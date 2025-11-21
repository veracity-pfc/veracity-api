from __future__ import annotations

import json
import logging
import mimetypes
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

import filetype
import httpx
from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.core.constants import GENERIC_ANALYSIS_ERROR, ALLOWED_MIMES
from app.domain.ai_model import AIResponse
from app.domain.analysis_model import Analysis
from app.domain.audit_model import AuditLog
from app.domain.enums import AnalysisStatus, AnalysisType, RiskLabel
from app.domain.image_analysis_model import ImageAnalysis
from app.repositories.audit_repository import AuditRepository
from app.services.ai_service import AIService
from app.services.common import resolve_user_id
from app.services.utils.quota_utils import check_daily_limit

logger = logging.getLogger("veracity.image_analysis")


def _detect_mime(data: bytes) -> str | None:
    kind = filetype.guess(data)
    return (kind and kind.mime) or None


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

    async def _sightengine_check(self, img_bytes: bytes, filename: str) -> Dict[str, Any]:
        models = (
            "properties,type,quality,"
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
                    "https://api.sightengine.com/1.0/check.json",
                    data=data,
                    files=files,
                )
            except httpx.HTTPError as exc:
                logger.error(
                    "sightengine.request_error",
                    extra={"error_type": type(exc).__name__},
                )
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            if r.status_code >= 400:
                logger.error(
                    "sightengine.status_error",
                    extra={"status": r.status_code},
                )
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            try:
                payload = r.json()
            except ValueError:
                logger.error("sightengine.json_error")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            if isinstance(payload, dict) and payload.get("status") == "failure":
                logger.error("sightengine.api_error")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            return payload

    async def run_analysis(self, user_id: UUID, file_content: bytes, request: Request):
        mime = _detect_mime(file_content)
        ext = mimetypes.guess_extension(mime or "") or ".bin"
        filename = f"api_upload_{datetime.now().timestamp()}{ext}"

        return await self.analyze(
            upload_bytes=file_content,
            filename=filename,
            content_type=mime or "application/octet-stream",
            request=request, 
            user_id=str(user_id),
        )

    async def analyze(
        self,
        *,
        upload_bytes: bytes,
        filename: str,
        content_type: str,
        request: Optional[Request] = None,
        user_id: Optional[str],
    ):
        if not upload_bytes:
            raise ValueError("Arquivo vazio.")
        if len(upload_bytes) > 1_000_000:
            raise ValueError("A imagem não pode ultrapassar 1MB.")
        if content_type not in {"image/png", "image/jpeg", "image/jpg"}:
            raise ValueError("Formato inválido. Aceitos: png, jpeg ou jpg.")
        if (_detect_mime(upload_bytes) or "") not in ALLOWED_MIMES:
            raise ValueError("Conteúdo não reconhecido como PNG ou JPEG válido.")

        if request:
            actor_hash = ip_hash_from_request(request)
            resolved_user_id = resolve_user_id(request, user_id)
        else:
            actor_hash = None
            resolved_user_id = user_id

        used_today, limit, scope = await check_daily_limit(
            self.session,
            AnalysisType.image,
            user_id=resolved_user_id,
            actor_hash=actor_hash,
        )

        analysis = Analysis(
            analysis_type=AnalysisType.image,
            status=AnalysisStatus.pending,
            label=RiskLabel.unknown,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
        )
        self.session.add(analysis)
        await self.session.flush()

        audit_repo = AuditRepository(self.session)

        await audit_repo.insert(
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
            await audit_repo.insert(
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
            logger.error(
                "analysis.image.external_error",
                extra={"analysis_id": str(analysis.id), "error_type": type(exc).__name__},
            )
            raise ValueError(GENERIC_ANALYSIS_ERROR)
        except Exception as exc:
            analysis.status = AnalysisStatus.error
            await audit_repo.insert(
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
            logger.error(
                "analysis.image.unexpected_error",
                extra={"analysis_id": str(analysis.id), "error_type": type(exc).__name__},
            )
            raise ValueError(GENERIC_ANALYSIS_ERROR)

        pct = round(ai_generated * 100, 1)
        if label_enum == RiskLabel.fake:
            base_expl = (
                f"A imagem '{filename}' apresenta fortes indícios de geração por IA "
                f"(probabilidade {pct}%)."
            )
            base_recs = [
                "Não compartilhe esta imagem.",
                "Solicite a fonte original se necessário.",
                "Se for associada ao seu nome, publique um desmentido e guarde evidências.",
            ]
        elif label_enum == RiskLabel.suspicious:
            base_expl = (
                f"A imagem '{filename}' possui sinais de possível geração por IA "
                f"(probabilidade {pct}%)."
            )
            base_recs = [
                "Busque a fonte original (reverse image search).",
                "Evite conclusões sem validação independente.",
                "Se necessário, solicite verificação a um canal oficial.",
            ]
        else:
            base_expl = (
                f"A imagem '{filename}' não apresentou sinais relevantes de geração por IA "
                f"(probabilidade {pct}%)."
            )
            base_recs = [
                "Respeite a privacidade de pessoas retratadas.",
                "Verifique se não há dados sensíveis antes de publicar.",
            ]

        extra_expl = (ai_text.get("explanation") or "").strip()
        extra_recs_raw = ai_text.get("recommendations") or []
        if isinstance(extra_recs_raw, list):
            extra_recs = [str(x).strip() for x in extra_recs_raw if str(x).strip()]
        else:
            extra_recs = [str(extra_recs_raw).strip()] if extra_recs_raw else []

        explanation = base_expl
        if extra_expl:
            explanation = f"{base_expl}\n\nObservação do modelo: {extra_expl}"

        recs_set = set(base_recs)
        recommendations = base_recs + [r for r in extra_recs if r not in recs_set]

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

        await audit_repo.insert(
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

        logger.info(
            "analysis.image.done",
            extra={"analysis_id": str(analysis.id), "label": analysis.label.value},
        )

        return analysis, img_row, ai_json_std