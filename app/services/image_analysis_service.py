from __future__ import annotations

import json
import logging
import mimetypes
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

import httpx
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_actor_identifier
from app.core.config import settings
from app.core.constants import GENERIC_ANALYSIS_ERROR, SIGHTENGINE_API_URL
from app.domain.ai_model import AIResponse
from app.domain.analysis_model import Analysis
from app.domain.audit_model import AuditLog
from app.domain.enums import AnalysisStatus, AnalysisType, RiskLabel
from app.domain.image_analysis_model import ImageAnalysis
from app.repositories.audit_repository import AuditRepository
from app.repositories.analysis_repository import AnalysisRepository
from app.services.ai_service import AIService
from app.services.common import resolve_user_id
from app.services.utils.quota_utils import check_daily_limit
from app.services.utils.validation_utils import detect_mime, validate_image_file

logger = logging.getLogger("veracity.image_analysis_service")


def _extract_ai_generated(se: Dict[str, Any]) -> float:
    candidates = []
    try:
        if isinstance(se, dict):
            t = se.get("type") or {}
            candidates.append(t.get("ai_generated"))
            candidates.append(t.get("ai-generated"))
            candidates.append((se.get("genai") or {}).get("ai_generated"))
            candidates.append(se.get("ai_generated"))
    except Exception:
        pass
    for v in candidates:
        try:
            if v is None:
                continue
            x = float(v)
            if x < 0:
                x = 0.0
            if x > 1:
                x = 1.0
            return x
        except Exception:
            continue
    return 0.0


def _decide(ai_gen: float) -> Tuple[RiskLabel, str]:
    if ai_gen >= 0.90:
        return RiskLabel.fake, "ai_generated"
    if ai_gen >= 0.60:
        return RiskLabel.suspicious, "ai_generated"
    return RiskLabel.safe, "real"


def _pt_label(label: RiskLabel) -> str:
    return {
        RiskLabel.safe: "Seguro",
        RiskLabel.suspicious: "Suspeito",
        RiskLabel.fake: "Falso",
        RiskLabel.unknown: "Desconhecido",
    }[label]


class ImageAnalysisService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.audit_repo = AuditRepository(session)
        self.analysis_repo = AnalysisRepository(session)

    async def _sightengine_check(self, img_bytes: bytes, filename: str) -> Dict[str, Any]:
        logger.debug(f"Calling Sightengine for file: {filename}")
        models = (
            "properties,type,quality,deepfake,"
            "faces,scam,text-content,face-attributes,text,genai"
        )
        data = {
            "models": models,
            "api_user": getattr(settings, "sight_engine_api_user"),
            "api_secret": getattr(settings, "sight_engine_api_secret"),
        }
        files = {"media": (filename, img_bytes, "application/octet-stream")}
        async with httpx.AsyncClient(timeout=settings.http_timeout) as client:
            try:
                r = await client.post(
                    SIGHTENGINE_API_URL,
                    data=data,
                    files=files,
                )
            except httpx.HTTPError as exc:
                logger.error(f"Sightengine HTTP error: {type(exc).__name__}")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            
            if r.status_code >= 400:
                logger.error(f"Sightengine returned error status: {r.status_code}")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            try:
                payload = r.json()
            except ValueError:
                logger.error("Sightengine returned invalid JSON")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            
            if isinstance(payload, dict) and payload.get("status") == "failure":
                error_detail = payload.get("error", {}).get("message", "unknown")
                logger.error(f"Sightengine API failure: {error_detail}")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            
            return payload

    async def run_analysis(self, user_id: UUID, file_content: bytes, request: Request):
        mime = detect_mime(file_content)
        ext = mimetypes.guess_extension(mime or "") or ".bin"
        filename = f"upload_{datetime.now().timestamp()}{ext}"

        return await self.analyze(
            upload_bytes=file_content,
            filename=filename,
            content_type=mime or "application/octet-stream",
            request=request,
            user_id=str(user_id),
        )

    async def run_analysis_with_validation(
        self,
        user_id: UUID,
        file_content: bytes,
        file_count: int,
        request: Request,
        token_id: Optional[UUID] = None,
        original_filename: Optional[str] = None, 
    ):
        if file_count > 1:
            logger.warning(f"Batch upload attempt rejected. UserID: {user_id}, Count: {file_count}")
            raise ValueError(
                "Envio em lote não suportado. Envie um arquivo por vez."
            )

        mime = detect_mime(file_content)
        
        if original_filename:
            filename = original_filename
        else:
            ext = mimetypes.guess_extension(mime or "") or ".bin"
            filename = f"token_{datetime.now().timestamp()}{ext}"

        return await self.analyze(
            upload_bytes=file_content,
            filename=filename,
            content_type=mime or "application/octet-stream",
            request=request,
            user_id=str(user_id),
            api_token_id=str(token_id) if token_id else None,
        )

    async def analyze(
        self,
        *,
        upload_bytes: bytes,
        filename: str,
        content_type: str,
        request: Optional[Request] = None,
        user_id: Optional[str],
        api_token_id: Optional[str] = None,
    ):
        logger.info(f"Initiating Image Analysis. UserID: {user_id}, TokenID: {api_token_id}, Size: {len(upload_bytes)} bytes")
        
        validate_image_file(upload_bytes, content_type)
        
        if request:
            actor_hash = get_actor_identifier(request)
            resolved_user_id = resolve_user_id(request, user_id)
        else:
            actor_hash = None
            resolved_user_id = user_id

        used_today, limit, scope = await check_daily_limit(
            self.session,
            AnalysisType.image,
            user_id=resolved_user_id,
            actor_hash=actor_hash,
            api_token_id=api_token_id,
        )

        analysis = Analysis(
            analysis_type=AnalysisType.image,
            status=AnalysisStatus.pending,
            label=RiskLabel.unknown,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            api_token_id=api_token_id,
        )
        self.session.add(analysis)
        await self.session.flush()

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.image.create",
            resource="/analyses/image",
            success=True,
            details={
                "filename": filename,
                "content_type": content_type,
                "size": len(upload_bytes),
                "quota_used": used_today,
                "quota_limit": limit,
                "quota_scope": scope,
            },
        )

        try:
            se_json = await self._sightengine_check(upload_bytes, filename)
            ai_generated = _extract_ai_generated(se_json)
            label_enum, type_hint = _decide(ai_generated)

            tech_meta = {
                "type_hint": type_hint,
                "ai_generated_score": ai_generated,
                "decision": label_enum.value,
                "notes": "Classificação baseada em type/genai.ai_generated do Sightengine.",
            }

            ai_service = AIService()
            ai_text = await ai_service.generate_for_image(
                filename=filename,
                mime=content_type,
                detection_json=se_json,
            )
        except ValueError as exc:
            analysis.status = AnalysisStatus.error
            await self.audit_repo.insert(
                table=AuditLog,
                user_id=resolved_user_id,
                actor_ip_hash=actor_hash,
                action="analysis.image.error",
                resource=str(analysis.id),
                success=False,
                details={
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(upload_bytes),
                    "reason": "external_service_error",
                },
            )
            await self.session.commit()
            logger.error(f"External service error during image analysis ID: {analysis.id}. Error: {type(exc).__name__}")
            raise ValueError(GENERIC_ANALYSIS_ERROR)
        except Exception as exc:
            analysis.status = AnalysisStatus.error
            await self.audit_repo.insert(
                table=AuditLog,
                user_id=resolved_user_id,
                actor_ip_hash=actor_hash,
                action="analysis.image.error",
                resource=str(analysis.id),
                success=False,
                details={
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(upload_bytes),
                    "reason": "unexpected_error",
                },
            )
            await self.session.commit()
            logger.exception(f"Unexpected error during image analysis ID: {analysis.id}")
            raise ValueError(GENERIC_ANALYSIS_ERROR)

        explanation = (ai_text.get("explanation") or "").strip()
        recommendations_raw = ai_text.get("recommendations") or []

        if isinstance(recommendations_raw, list):
            recommendations = [str(x).strip() for x in recommendations_raw if str(x).strip()]
        else:
            recommendations = [str(recommendations_raw).strip()] if recommendations_raw else []

        img_row = ImageAnalysis(
            analysis_id=analysis.id,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            meta={"filename": filename, "size": len(upload_bytes), "mime": content_type},
            sightengine_json=se_json,
            risk_label=label_enum.value,
            ai_json=tech_meta,
        )
        self.session.add(img_row)

        ai_json_std = {
            "explanation": explanation,
            "classification": _pt_label(label_enum),
            "recommendations": recommendations,
        }
        ai_resp = AIResponse(
            analysis_id=analysis.id,
            provider="hf-router",
            model=getattr(settings, "hf_openai_model", None) or "gpt-4o-mini",
            content=json.dumps(ai_json_std, ensure_ascii=False),
        )
        self.session.add(ai_resp)
        await self.session.flush()

        analysis.ai_response_id = ai_resp.id
        analysis.status = AnalysisStatus.done
        analysis.label = label_enum
        analysis.completed_at = datetime.now(timezone.utc)

        await self.audit_repo.insert(
            table=AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.image.finish",
            resource=str(analysis.id),
            success=True,
            details={
                "label": label_enum.value,
                "ai_generated": ai_generated,
                "type_hint": type_hint,
            },
        )

        await self.session.commit()

        used_after = used_today + 1
        remaining = max(0, (limit - used_after)) if limit else 0
        ai_json_std["quota"] = {
            "scope": scope,
            "limit": limit,
            "used_today": used_after,
            "remaining_today": remaining,
        }
        ai_json_std["label"] = label_enum.value

        logger.info(f"Image analysis finished. ID: {analysis.id}, Label: {label_enum.value}, AI Score: {ai_generated}")

        return analysis, img_row, ai_json_std