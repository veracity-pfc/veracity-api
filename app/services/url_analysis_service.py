from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_actor_identifier
from app.core.config import settings
from app.core.constants import DNS_TIMEOUT, GENERIC_ANALYSIS_ERROR, GSB_API_URL
from app.domain.ai_model import AIResponse
from app.domain.analysis_model import Analysis
from app.domain.audit_model import AuditLog
from app.domain.enums import AnalysisStatus, AnalysisType, RiskLabel
from app.domain.url_analysis_model import UrlAnalysis
from app.repositories.audit_repository import AuditRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.schemas.url_analysis import has_valid_tld
from app.services.ai_service import AIService
from app.services.common import resolve_user_id
from app.services.utils.quota_utils import check_daily_limit

logger = logging.getLogger("veracity.url_analysis_service")


def only_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


async def dns_ok(host: str) -> bool:
    loop = asyncio.get_running_loop()
    try:
        await asyncio.wait_for(loop.getaddrinfo(host, None), timeout=DNS_TIMEOUT)
        return True
    except Exception:
        logger.warning(f"DNS resolution failed for host: {host}")
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
            GSB_API_URL,
            headers={"X-Goog-Api-Key": settings.gsb_api_key},
            json=body,
        )
        duration = round((time.perf_counter() - t0) * 1000, 1)
        logger.info(f"GSB check finished. Status: {r.status_code}, Duration: {duration}ms")

    except httpx.HTTPError as e:
        logger.error(f"GSB connection error: {str(e)}")
        raise ValueError(GENERIC_ANALYSIS_ERROR)

    if r.status_code >= 400:
        logger.error(f"GSB API returned error status: {r.status_code}")
        raise ValueError(GENERIC_ANALYSIS_ERROR)

    try:
        data = r.json() or {"matches": []}
    except ValueError:
        logger.error("Failed to parse GSB response JSON")
        raise ValueError(GENERIC_ANALYSIS_ERROR)

    return data


class UrlAnalysisService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.audit = AuditRepository(session)
        self.analysis_repo = AnalysisRepository(session)

    async def run_analysis_with_validation(
        self, user_id: UUID, url: str, request: Request, token_id: Optional[UUID] = None
    ):
        return await self.analyze(
            url_in=url,
            request=request,
            user_id=str(user_id),
            api_token_id=str(token_id) if token_id else None,
        )

    async def analyze(
        self,
        *,
        url_in: str,
        request: Optional[Request] = None,
        user_id: Optional[str],
        api_token_id: Optional[str] = None,
    ):
        url = (url_in or "").strip()
        logger.info(f"Initiating URL analysis. UserID: {user_id}, TokenID: {api_token_id}")

        if not url:
            raise ValueError("A URL não pode estar vazia")
        if len(url) > 200:
            raise ValueError("A URL deve ter no máximo 200 caracteres.")
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("A URL deve começar com http:// ou https://")

        host = only_host(url)
        if not has_valid_tld(host):
            logger.warning(f"Invalid TLD detected for URL: {url}")
            raise ValueError("A URL deve possuir um TLD válido")

        actor_hash = get_actor_identifier(request) if request else None
        resolved_user_id = resolve_user_id(request, user_id) if request else user_id

        used_today, limit, scope = await check_daily_limit(
            self.session,
            AnalysisType.url,
            user_id=resolved_user_id,
            actor_hash=actor_hash,
            api_token_id=api_token_id,
        )

        analysis = Analysis(
            analysis_type=AnalysisType.url,
            status=AnalysisStatus.pending,
            label=RiskLabel.unknown,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            source_url=url,
            api_token_id=api_token_id,
        )
        self.session.add(analysis)
        await self.session.flush()
        logger.info(f"Analysis record created. ID: {analysis.id}")

        await self.audit.insert(
            table=AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.url.create",
            resource="/analyses/url",
            success=True,
            details={
                "source_url": url,
                "quota_used": used_today,
                "quota_limit": limit,
                "quota_scope": scope,
            },
        )

        dns_ok_flag = await dns_ok(host)
        tld_ok = True

        timeout = httpx.Timeout(settings.http_timeout)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                gsb_res = await gsb_check(url, client)
                ai_service = AIService(client)
                ai_json = await ai_service.generate_for_url(
                    url=url,
                    tld_ok=tld_ok,
                    dns_ok=dns_ok_flag,
                    gsb_json=gsb_res or {},
                )

        except Exception as exc:
            logger.exception(f"Error during URL analysis processing for ID: {analysis.id}")
            analysis.status = AnalysisStatus.error
            await self.audit.insert(
                table=AuditLog,
                user_id=resolved_user_id,
                actor_ip_hash=actor_hash,
                action="analysis.url.error",
                resource=str(analysis.id),
                success=False,
                details={"source_url": url, "reason": "service_error"},
            )
            await self.session.commit()
            raise ValueError(GENERIC_ANALYSIS_ERROR) from exc

        label_enum = map_pt_label_to_enum(ai_json.get("classification", ""))
        logger.info(f"Analysis classified. ID: {analysis.id}, Label: {label_enum.value}")

        url_row = UrlAnalysis(
            analysis_id=analysis.id,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            url=url,
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

        await self.audit.insert(
            table=AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.url.finish",
            resource=str(analysis.id),
            success=True,
            details={"label": label_enum.value},
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

        return analysis, url_row, ai_json_out