from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.core.constants import DNS_TIMEOUT, GENERIC_ANALYSIS_ERROR
from app.domain.ai_model import AIResponse
from app.domain.analysis_model import Analysis
from app.domain.audit_model import AuditLog
from app.domain.enums import AnalysisStatus, AnalysisType, RiskLabel
from app.domain.url_analysis_model import UrlAnalysis
from app.repositories.audit_repository import AuditRepository
from app.schemas.url_analysis import has_valid_tld
from app.services.ai_service import AIService
from app.services.common import resolve_user_id
from app.services.utils.quota_utils import check_daily_limit

logger = logging.getLogger("veracity.link_analysis")


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
    if s.startswith("segur"):
        return RiskLabel.safe
    if s.startswith("suspe"):
        return RiskLabel.suspicious
    if s.startswith("malic"):
        return RiskLabel.malicious
    return RiskLabel.unknown


async def gsb_check(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    body = {
        "client": {"clientId": "veracity", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    t0 = time.perf_counter()
    
    try:
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find",
            headers={"X-Goog-Api-Key": settings.gsb_api_key},
            json=body,
        )
    except httpx.HTTPError as exc:
        logger.error(
            "gsb.request_error",
            extra={"error_type": type(exc).__name__},
        )
        raise ValueError(GENERIC_ANALYSIS_ERROR)

    dt = round((time.perf_counter() - t0) * 1000, 1)
    logger.info("gsb.response", extra={"status": r.status_code, "ms": dt})

    if r.status_code >= 400:
        logger.error(
            "gsb.status_error",
            extra={"status": r.status_code},
        )
        raise ValueError(GENERIC_ANALYSIS_ERROR)

    try:
        data = r.json() or {"matches": []}
    except ValueError:
        logger.error("gsb.json_error")
        raise ValueError(GENERIC_ANALYSIS_ERROR)

    first_match = (data.get("matches") or [None])[0]
    logger.info(
        "gsb.matches",
        extra={
            "has_matches": bool(data.get("matches")),
            "count": len(data.get("matches", [])),
            "first_match_preview": json.dumps(first_match, ensure_ascii=False)[:240]
            if first_match
            else None,
        },
    )
    return data


class UrlAnalysisService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def analyze(self, *, url_in: str, request, user_id: Optional[str]):
        actor_hash = ip_hash_from_request(request)
        resolved_user_id = resolve_user_id(request, user_id)

        used_today, limit, scope = await check_daily_limit(
            self.session,
            AnalysisType.url,
            user_id=resolved_user_id,
            actor_hash=actor_hash,
        )

        analysis = Analysis(
            analysis_type=AnalysisType.url,
            status=AnalysisStatus.pending,
            label=RiskLabel.unknown,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            source_url=url_in,
        )
        self.session.add(analysis)
        await self.session.flush()

        audit_repo = AuditRepository(self.session)

        await audit_repo.insert(
            table=AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.url.create",
            resource="/analyses/url",
            success=True,
            details={
                "source_url": url_in,
                "quota_used": used_today,
                "quota_limit": limit,
                "quota_scope": scope,
            },
        )

        host = only_host(url_in)
        dns_ok_flag = await dns_ok(host)
        tld_ok = has_valid_tld(host)

        timeout = httpx.Timeout(settings.http_timeout)
        try:
            logger.info(
                "analysis.url.start",
                extra={
                    "url": url_in,
                    "analysis_id": str(analysis.id),
                    "tld_ok": tld_ok,
                    "dns_ok": dns_ok_flag,
                },
            )

            async with httpx.AsyncClient(timeout=timeout) as client:
                gsb_res = await gsb_check(url_in, client)
                ai_service = AIService(client)
                ai_json = await ai_service.generate_for_url(
                    url=url_in,
                    tld_ok=tld_ok,
                    dns_ok=dns_ok_flag,
                    gsb_json=gsb_res or {},
                )

        except ValueError as exc:
            analysis.status = AnalysisStatus.error

            await audit_repo.insert(
                table=AuditLog,
                user_id=resolved_user_id,
                actor_ip_hash=actor_hash,
                action="analysis.url.error",
                resource=str(analysis.id),
                success=False,
                details={
                    "source_url": url_in,
                    "reason": "external_service_error",
                },
            )
            await self.session.commit()

            logger.exception(
                "analysis.url.failed",
                extra={
                    "analysis_id": str(analysis.id),
                    "error_type": type(exc).__name__,
                    "url": url_in,
                },
            )

            raise ValueError(GENERIC_ANALYSIS_ERROR) from exc

        except Exception as exc:
            analysis.status = AnalysisStatus.error

            await audit_repo.insert(
                table=AuditLog,
                user_id=resolved_user_id,
                actor_ip_hash=actor_hash,
                action="analysis.url.error",
                resource=str(analysis.id),
                success=False,
                details={
                    "source_url": url_in,
                    "reason": "unexpected_error",
                },
            )
            await self.session.commit()

            logger.exception(
                "analysis.url.unexpected_error",
                extra={
                    "analysis_id": str(analysis.id),
                    "error_type": type(exc).__name__,
                    "url": url_in,
                },
            )

            raise ValueError(GENERIC_ANALYSIS_ERROR) from exc


        label_enum = map_pt_label_to_enum(ai_json.get("classification", ""))

        url_row = UrlAnalysis(
            analysis_id=analysis.id,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            url=url_in,
            dns_ok=dns_ok_flag,
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

        await audit_repo.insert(
            table=AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.url.finish",
            resource=str(analysis.id),
            success=True,
            details={
                "label": label_enum.value,
                "tld_ok": tld_ok,
                "dns_ok": dns_ok_flag,
                "gsb_has_match": bool(gsb_res and gsb_res.get("matches")),
            },
        )

        await self.session.commit()

        used_after = used_today + 1
        remaining = max(0, (limit - used_after)) if limit else 0

        ai_json_out: Dict[str, Any] = dict(ai_json or {})
        ai_json_out["quota"] = {
            "scope": scope,
            "limit": limit,
            "used_today": used_after,
            "remaining_today": remaining,
        }

        logger.info(
            "analysis.url.done",
            extra={"analysis_id": str(analysis.id), "label": analysis.label.value},
        )
        return analysis, url_row, ai_json_out
