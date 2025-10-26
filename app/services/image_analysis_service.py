from __future__ import annotations
import httpx, json, logging
from typing import Any, Dict, Optional, Literal
from datetime import datetime, timezone
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
import filetype

logger = logging.getLogger("veracity.image_analysis")

ALLOWED_MIMES = {"image/png", "image/jpeg"} 
MODEL_DEEPFAKE = "prithivMLmods/Deep-Fake-Detector-v2-Model"
MODEL_VIT      = "google/vit-base-patch16-224"


def detect_image_mime(data: bytes) -> str | None:
    kind = filetype.guess(data)
    return kind.mime if kind else None

def _pt_to_enum(s: str) -> RiskLabel:
    s = (s or "").strip().lower()
    if s.startswith("fals"): return RiskLabel.fake       
    if s.startswith("segur"): return RiskLabel.safe
    if s.startswith("suspe"): return RiskLabel.suspicious
    if s.startswith("malic"): return RiskLabel.malicious
    return RiskLabel.unknown


async def _hf_image_classify(model: str, img_bytes: bytes, client: httpx.AsyncClient) -> Dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {getattr(settings, 'hf_token', '')}",
        "Accept": "application/json",
        "Content-Type": "application/octet-stream",
    }
    url = f"https://router.huggingface.co/hf-inference/models/{model}"
    r = await client.post(url, headers=headers, content=img_bytes, timeout=getattr(settings, "http_timeout", 30))
    logger.info("hf.inf", extra={"model": model, "status": r.status_code, "preview": r.text[:180].replace("\n"," ")})
    if r.status_code >= 400:
        try:
            return {"error": {"status": r.status_code, "text": r.text}}
        except Exception:
            return {"error": {"status": r.status_code}}
    try:
        return r.json()
    except Exception:
        return {}


def _risk_from_models(deepfake_json: Dict[str, Any]) -> RiskLabel:
    probs = []
    if isinstance(deepfake_json, list):
        for it in deepfake_json:
            lbl = str(it.get("label", "")).lower()
            scr = float(it.get("score", 0) or 0)
            probs.append((lbl, scr))
    elif isinstance(deepfake_json, dict):
        for lbl, scr in deepfake_json.items():
            try:
                probs.append((str(lbl).lower(), float(scr)))
            except Exception:
                pass

    fake_p = max((scr for (lbl, scr) in probs if "fake" in lbl), default=0.0)
    return RiskLabel.fake if fake_p >= 0.60 else RiskLabel.safe


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

    async def analyze(self, *, upload_bytes: bytes, filename: str, content_type: str, request, user_id: Optional[str]):
        
        if len(upload_bytes) == 0:
            raise ValueError("Arquivo vazio.")
        if len(upload_bytes) > 1_000_000:
            raise ValueError("A imagem não pode ultrapassar 1MB.")
        if content_type not in {"image/png", "image/jpeg", "image/jpg"}:
            raise ValueError("Formato inválido. Aceitos: png, jpeg ou jpg.")

        mime = detect_image_mime(upload_bytes)
        
        if mime not in ALLOWED_MIMES:
            raise ValueError("Conteúdo não reconhecido como PNG ou JPEG válido.")

        if content_type not in {"image/png", "image/jpeg", "image/jpg"}:
            raise ValueError("Formato inválido. Aceitos: png, jpeg ou jpg.")
 
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

        timeout = httpx.Timeout(getattr(settings, "http_timeout", 30))
        async with httpx.AsyncClient(timeout=timeout) as client:
            deepfake_json = await _hf_image_classify(MODEL_DEEPFAKE, upload_bytes, client)
            vit_json      = await _hf_image_classify(MODEL_VIT, upload_bytes, client)

            ai_service = AIService(client)
            ai_json = await ai_service.generate_for_image(
                filename=filename,
                mime=content_type,
                deepfake_json=deepfake_json or {},
                vit_json=vit_json or {},
            )

        label_enum = _pt_to_enum(ai_json.get("classification", "")) or _risk_from_models(deepfake_json)

        img_row = ImageAnalysis(
            analysis_id=analysis.id,
            user_id=user_id,
            actor_ip_hash=actor_hash,
            meta={"filename": filename, "size": len(upload_bytes), "mime": content_type},
            deepfake_json=deepfake_json,
            vit_json=vit_json,
            ai_json=ai_json,
            risk_label=label_enum.value,
        )
        self.session.add(img_row)

        ai_resp = AIResponse(
            analysis_id=analysis.id,
            provider="hf-inference",
            model=f"{MODEL_DEEPFAKE} + {MODEL_VIT}",
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
            action="analysis.image.finish",
            resource=str(analysis.id),
            success=True,
            details={"label": label_enum.value},
        )

        await self.session.commit()
        return analysis, img_row, ai_json
