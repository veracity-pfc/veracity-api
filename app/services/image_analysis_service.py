from __future__ import annotations
import logging
from typing import Any, Dict, Optional, Tuple
from datetime import datetime, timezone
import httpx
import filetype
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.core.config import settings
from app.api.deps import ip_hash_from_request
from app.repositories.audit_repo import AuditRepository
from app.domain.enums import AnalysisType, AnalysisStatus, RiskLabel
from app.domain.analysis_model import Analysis
from app.domain.image_analysis_model import ImageAnalysis
from app.domain.ai_model import AIResponse
from app.services.ai_service import AIService

logger = logging.getLogger("veracity.image_analysis")
ALLOWED_MIMES = {"image/png", "image/jpeg"}

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
            if x < 0: x = 0.0
            if x > 1: x = 1.0
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

    async def _check_daily_limit(self, user_id: Optional[str], actor_hash: Optional[str]) -> None:
        if getattr(settings, "disable_limits", False):
            return
        now = datetime.now(timezone.utc)
        start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
        q = select(func.count(Analysis.id)).where(
            Analysis.analysis_type == AnalysisType.image,
            Analysis.created_at >= start,
        )
        if user_id:
            q = q.where(Analysis.user_id == user_id); limit = settings.user_image_limit
        else:
            q = q.where(Analysis.user_id.is_(None), Analysis.actor_ip_hash == actor_hash); limit = settings.anon_image_limit
        total = (await self.session.execute(q)).scalar_one()
        if total >= limit:
            raise ValueError("Limite diário de análises de imagem atingido.")

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
            r = await client.post("https://api.sightengine.com/1.0/check.json", data=data, files=files)
            try:
                return r.json()
            except Exception:
                return {"status": "failure", "error": {"code": r.status_code, "text": r.text}}

    async def analyze(
        self,
        *,
        upload_bytes: bytes,
        filename: str,
        content_type: str,
        request,
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

        actor_hash = ip_hash_from_request(request)
        await self._check_daily_limit(user_id, actor_hash)

        analysis = Analysis(
            analysis_type=AnalysisType.image,
            status=AnalysisStatus.pending,
            label=RiskLabel.unknown,
            user_id=user_id,
            actor_ip_hash=actor_hash,
        )
        self.session.add(analysis)
        await self.session.flush()

        await AuditRepository(self.session).insert(
            table=__import__("app.domain.audit_model", fromlist=["AuditLog"]).AuditLog,
            user_id=user_id,
            actor_ip_hash=actor_hash,
            action="analysis.image.create",
            resource=str(analysis.id),
            success=True,
            details={"filename": filename, "content_type": content_type, "size": len(upload_bytes)},
        )

        se_json = await self._sightengine_check(upload_bytes, filename)
        ai_generated = _extract_ai_generated(se_json)
        label_enum, type_hint = _decide(ai_generated)

        tech_meta = {
            "type_hint": type_hint,
            "ai_generated_score": ai_generated,
            "decision": label_enum.value,
            "notes": "Classificação baseada somente em type.ai_generated do Sightengine.",
        }

        ai = AIService()
        ai_text = await ai.generate_for_image(
            filename=filename,
            mime=content_type,
            detection_json=se_json,  
        )

        img_row = ImageAnalysis(
            analysis_id=analysis.id,
            user_id=user_id,
            actor_ip_hash=actor_hash,
            meta={"filename": filename, "size": len(upload_bytes), "mime": content_type},
            sightengine_json=se_json,      
            risk_label=label_enum.value,    
            ai_json=tech_meta,           
        )
        self.session.add(img_row)

        ai_resp = AIResponse(
            analysis_id=analysis.id,
            provider="openai",
            model=getattr(settings, "hf_openai_model", None) or "gpt-4o-mini",
            content=ai_text.get("explanation", ""),
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
            action="analysis.image.finish",
            resource=str(analysis.id),
            success=True,
            details={"label": label_enum.value, "ai_generated": ai_generated, "type_hint": type_hint},
        )

        await self.session.commit()

        return analysis, img_row, {
            "classification": _pt_label(label_enum),      
            "label": label_enum.value,                   
            "explanation": ai_text.get("explanation", ""),
            "recommendations": ai_text.get("recommendations", []),
            "score_ai_generated": round(ai_generated, 3),
        }
