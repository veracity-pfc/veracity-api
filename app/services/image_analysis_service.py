from __future__ import annotations
import logging, json
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

def _resolve_user_id(request, explicit_user_id: Optional[str]) -> Optional[str]:
    if explicit_user_id:
        return explicit_user_id
    try:
        st = getattr(request, "state", None)
        cand = None
        if st is not None:
            u = getattr(st, "user", None)
            if hasattr(u, "id") and u.id:
                cand = u.id
            if not cand:
                cand = getattr(st, "user_id", None)
        if not cand:
            u2 = getattr(request, "user", None)
            if hasattr(u2, "id") and u2.id:
                cand = u2.id
            elif isinstance(u2, str) and u2:
                cand = u2
        if cand:
            return str(cand)
    except Exception:
        pass
    return None

async def _count_today(session: AsyncSession, analysis_type: AnalysisType, *, user_id: Optional[str], actor_hash: Optional[str]) -> int:
    now = datetime.now(timezone.utc)
    start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
    q = select(func.count(Analysis.id)).where(
        Analysis.analysis_type == analysis_type,
        Analysis.created_at >= start,
    )
    if user_id:
        q = q.where(Analysis.user_id == user_id)
    else:
        q = q.where(Analysis.user_id.is_(None), Analysis.actor_ip_hash == actor_hash)
    return (await session.execute(q)).scalar_one()

async def _check_daily_limit(session: AsyncSession, analysis_type: AnalysisType, *, user_id: Optional[str], actor_hash: Optional[str]) -> Tuple[int, int, str]:
    if getattr(settings, "disable_limits", False):
        return (0, 0, "disabled")
    used = await _count_today(session, analysis_type, user_id=user_id, actor_hash=actor_hash)
    if user_id:
        limit = settings.user_image_limit if analysis_type == AnalysisType.image else settings.user_url_limit
        scope = "user"
    else:
        limit = settings.anon_image_limit if analysis_type == AnalysisType.image else settings.anon_url_limit
        scope = "anon"
    if used >= limit:
        raise ValueError("Limite diário de análises de imagem atingido.")
    return (used, limit, scope)

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
        resolved_user_id = _resolve_user_id(request, user_id)

        used_today, limit, scope = await _check_daily_limit(
            self.session, AnalysisType.image, user_id=resolved_user_id, actor_hash=actor_hash
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

        await AuditRepository(self.session).insert(
            table=__import__("app.domain.audit_model", fromlist=["AuditLog"]).AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.image.create",
            resource=str(analysis.id),
            success=True,
            details={"filename": filename, "content_type": content_type, "size": len(upload_bytes), "quota_used": used_today, "quota_limit": limit, "quota_scope": scope},
        )

        se_json = await self._sightengine_check(upload_bytes, filename)

        ai_generated = _extract_ai_generated(se_json)
        label_enum, type_hint = _decide(ai_generated)

        tech_meta = {
            "type_hint": type_hint,
            "ai_generated_score": ai_generated,
            "decision": label_enum.value,
            "notes": "Classificação baseada somente em type/genai.ai_generated do Sightengine.",
        }

        pct = round(ai_generated * 100, 1)
        if label_enum == RiskLabel.fake:
            base_expl = (
                f"A imagem '{filename}' apresenta fortes indícios de geração por IA "
                f"(probabilidade {pct}%)."
            )
        elif label_enum == RiskLabel.suspicious:
            base_expl = (
                f"A imagem '{filename}' possui sinais de possível geração por IA "
                f"(probabilidade {pct}%)."
            )
        else:
            base_expl = (
                f"A imagem '{filename}' não apresentou sinais relevantes de geração por IA "
                f"(probabilidade {pct}%)."
            )

        if label_enum == RiskLabel.fake:
            base_recs = [
                "Não compartilhe esta imagem.",
                "Solicite a fonte original se necessário.",
                "Se for associada ao seu nome, publique um desmentido e guarde evidências."
            ]
        elif label_enum == RiskLabel.suspicious:
            base_recs = [
                "Busque a fonte original (reverse image search).",
                "Evite conclusões sem validação independente.",
                "Se necessário, solicite verificação a um canal oficial."
            ]
        else:
            base_recs = [
                "Respeite a privacidade de pessoas retratadas.",
                "Verifique se não há dados sensíveis antes de publicar."
            ]

        extra_expl = ""
        extra_recs: list[str] = []
        try:
            ai = AIService()
            ai_text = await ai.generate_for_image(
                filename=filename,
                mime=content_type,
                detection_json=se_json,
            )
            extra_expl = (ai_text.get("explanation") or "").strip()
            rs = ai_text.get("recommendations") or []
            if isinstance(rs, list):
                extra_recs = [str(x).strip() for x in rs if str(x).strip()]
        except Exception as e:
            logger.warning("AIService.generate_for_image falhou: %s", e)

        explanation = base_expl if not extra_expl else f"{base_expl}\n\nObservação do modelo: {extra_expl}"
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

        await AuditRepository(self.session).insert(
            table=__import__("app.domain.audit_model", fromlist=["AuditLog"]).AuditLog,
            user_id=resolved_user_id,
            actor_ip_hash=actor_hash,
            action="analysis.image.finish",
            resource=str(analysis.id),
            success=True,
            details={"label": label_enum.value, "ai_generated": ai_generated, "type_hint": type_hint},
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

        return analysis, img_row, ai_json_std
