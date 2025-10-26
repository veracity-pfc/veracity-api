from __future__ import annotations
import asyncio, json, logging, time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timezone
from app.domain.ai_model import AIResponse
from app.core.config import settings
from app.domain.analysis_model import Analysis
from app.domain.url_analysis_model import UrlAnalysis
from app.domain.enums import AnalysisType, AnalysisStatus, RiskLabel
from app.api.deps import ip_hash_from_request
from app.repositories.audit_repo import AuditRepository
from app.services.ai_service import AIService
from app.schemas.url_analysis import has_valid_tld

logger = logging.getLogger("veracity.link_analysis")
DNS_TIMEOUT = 1.2

def only_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()

async def dns_ok(host: str) -> bool:
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=DNS_TIMEOUT)
        return True
    except Exception:
        return False

def map_pt_label_to_enum(s: str) -> RiskLabel:
    s = (s or "").strip().lower()
    if s.startswith("segur"):   return RiskLabel.safe
    if s.startswith("suspe"):   return RiskLabel.suspicious
    if s.startswith("malic"):   return RiskLabel.malicious
    return RiskLabel.unknown

async def gsb_check(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    body = {
        "client": {"clientId": "veracity", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    t0 = time.perf_counter()
    r = await client.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.gsb_api_key}",
        json=body,
    )
    dt = round((time.perf_counter() - t0) * 1000, 1)
    logger.info("gsb.response", extra={"status": r.status_code, "ms": dt, "preview": r.text[:240].replace("\n","")})
    if r.status_code >= 400:
        return {"error": {"status": r.status_code, "text": r.text}}
    data = r.json() or {"matches": []}
    fm = (data.get("matches") or [None])[0]
    logger.info("gsb.matches", extra={
        "has_matches": bool(data.get("matches")),
        "count": len(data.get("matches", [])),
        "first_match_preview": json.dumps(fm, ensure_ascii=False)[:240] if fm else None
    })
    return data

class UrlAnalysisService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def _check_daily_limit(self, user_id: Optional[str], actor_hash: Optional[str]) -> None:
        if settings.disable_limits:
            return
        now = datetime.now(timezone.utc)
        start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        q = select(func.count(Analysis.id)).where(
            Analysis.analysis_type == AnalysisType.url,
            Analysis.created_at >= start,
        )
        if user_id:
            q = q.where(Analysis.user_id == user_id); limit = settings.user_url_limit
        else:
            q = q.where(Analysis.user_id.is_(None), Analysis.actor_ip_hash == actor_hash); limit = settings.anon_url_limit
        total = (await self.session.execute(q)).scalar_one()
        if total >= limit:
            raise ValueError("Limite diário de análises de link atingido.")

    async def analyze(self, *, url_in: str, request, user_id: Optional[str]) -> Tuple[Analysis, UrlAnalysis, Dict[str, Any]]:
        actor_hash = ip_hash_from_request(request)
        await self._check_daily_limit(user_id, actor_hash)

        analysis = Analysis(
            analysis_type=AnalysisType.url,
            status=AnalysisStatus.pending,
            label=RiskLabel.unknown,
            user_id=user_id,
            actor_ip_hash=actor_hash,
            source_url=url_in,
        )
        self.session.add(analysis)
        await self.session.flush()

        await AuditRepository(self.session).insert(
            table=__import__("app.domain.audit_model", fromlist=["AuditLog"]).AuditLog,
            user_id=user_id,
            actor_ip_hash=actor_hash,
            action="analysis.url.create",
            resource=str(analysis.id),
            success=True,
            details={"source_url": url_in},
        )

        host = only_host(url_in)
        _dns_ok = await dns_ok(host)
        _tld_ok = has_valid_tld(host)

        timeout = httpx.Timeout(settings.http_timeout)
        async with httpx.AsyncClient(timeout=timeout) as client:
            gsb_res = await gsb_check(url_in, client)
            ai_service = AIService(client)
            ai_json = await ai_service.generate_for_url(
                url=url_in,
                tld_ok=_tld_ok,     
                dns_ok=_dns_ok,
                gsb_json=gsb_res or {},
            )

        label_enum = map_pt_label_to_enum(ai_json.get("classification", ""))

        url_row = UrlAnalysis(
            analysis_id=analysis.id,
            user_id=user_id,
            actor_ip_hash=actor_hash,
            url=url_in,
            dns_ok=_dns_ok,
            gsb_json=gsb_res,
            ai_json=ai_json,
            risk_label=label_enum.value,
        )
        self.session.add(url_row)


        ai_resp = AIResponse(
            analysis_id=analysis.id,
            provider="hf-router",
            model=settings.hf_openai_model,
            content=json.dumps(ai_json, ensure_ascii=False),
        )
        self.session.add(ai_resp)
        await self.session.flush()

        analysis.ai_response_id = ai_resp.id
        analysis.status = AnalysisStatus.done
        analysis.label = label_enum
        analysis.completed_at = datetime.now(timezone.utc)

        await AuditRepository(self.session).insert(
            table=__import__("app.domain.audit_model", fromlist=["AuditLog"]).AuditLog,
            user_id=user_id,
            actor_ip_hash=actor_hash,
            action="analysis.url.finish",
            resource=str(analysis.id),
            success=True,
            details={
                "label": label_enum.value,
                "tld_ok": _tld_ok, 
                "dns_ok": _dns_ok,
                "gsb_has_match": bool(gsb_res and gsb_res.get("matches")),
            },
        )

        await self.session.commit()
        logger.info("analysis.done", extra={"analysis_id": str(analysis.id), "label": analysis.label.value})
        return analysis, url_row, ai_json
