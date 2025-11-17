from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx

from app.core.config import settings
from app.core.constants import IANA_TTL_SEC, IANA_URL, GENERIC_ANALYSIS_ERROR, HAS_DIGIT_RE

logger = logging.getLogger("veracity.ai_service")

IANA_TLDS: set[str] | None = None
IANA_FETCH_TS: float | None = None

async def _load_iana_tlds(client: httpx.AsyncClient) -> set[str]:
    global IANA_TLDS, IANA_FETCH_TS
    now = time.time()
    if IANA_TLDS is not None and IANA_FETCH_TS and (now - IANA_FETCH_TS) < IANA_TTL_SEC:
        return IANA_TLDS

    t0 = time.perf_counter()
    r = await client.get(IANA_URL, timeout=settings.http_timeout)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    logger.info("iana.tlds.fetch", extra={"status": r.status_code, "ms": ms})
    r.raise_for_status()

    lines = r.text.splitlines()
    tlds = {ln.strip().lower() for ln in lines if ln and not ln.startswith("#")}
    IANA_TLDS, IANA_FETCH_TS = tlds, now
    logger.info("iana.tlds.loaded", extra={"count": len(tlds)})
    return tlds


@dataclass(slots=True)
class URLSignals:
    url: str
    host: str
    tld: str
    tld_in_iana: bool
    tld_ok_input: bool
    dns_ok: bool
    subdomain_count: int
    has_hyphen: bool
    has_digits: bool
    is_punycode: bool
    path_len: int
    query_len: int


def _compute_signals(
    url: str,
    tld_set: set[str],
    *,
    tld_ok_input: bool,
    dns_ok: bool,
) -> URLSignals:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    sub_count = max(0, host.count(".") - 1)
    return URLSignals(
        url=url,
        host=host,
        tld=tld,
        tld_in_iana=(tld in tld_set) if tld else False,
        tld_ok_input=tld_ok_input,
        dns_ok=dns_ok,
        subdomain_count=sub_count,
        has_hyphen=("-" in host) or ("_" in host),
        has_digits=bool(HAS_DIGIT_RE.search(host)),
        is_punycode=host.startswith("xn--"),
        path_len=len(parts.path or ""),
        query_len=len(parts.query or ""),
    )


def _build_prompt(gsb_json: Dict[str, Any], sig: URLSignals) -> str:
    gsb = json.dumps(gsb_json or {}, ensure_ascii=False)
    sig_json = json.dumps(asdict(sig), ensure_ascii=False)
    return (
        "Tarefa: você é um analista de segurança. Dada uma URL e sinais técnicos, "
        "classifique o risco e explique em linguagem simples.\n"
        f"URL: {sig.url}\n"
        f"Sinais: {sig_json}\n"
        f"Google Safe Browsing: {gsb}\n"
        "Instruções:\n"
        "- Avalie se o endereço tenta se passar por outro pela forma do domínio e subdomínios.\n"
        "- Mesmo sem alertas no GSB, considere: TLD desconhecido, punycode, muitos subdomínios, hífens/números e caminho longo.\n"
        "- Explique em UM parágrafo curto, SEM termos técnicos; foque no que o usuário leigo precisa saber e por quê.\n"
        "- Em seguida, traga 2 recomendações práticas e curtas.\n"
        "Responda SOMENTE com JSON válido no formato exato:\n"
        '{ "classification": "Seguro|Suspeito|Malicioso", '
        '"explanation": "um parágrafo claro e simples", '
        '"recommendations": ["recomendação 1", "recomendação 2"] }\n'
    )


async def _hf_chat(
    client: httpx.AsyncClient,
    prompt: str,
    *,
    temperature: float = 0.18,
    max_tokens: int = 360,
) -> Dict[str, Any]:
    url = f"{settings.hf_base_url}/chat/completions"
    headers = {"Authorization": f"Bearer {settings.hf_token}"}
    body = {
        "model": settings.hf_openai_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    t0 = time.perf_counter()
    r = await client.post(url, json=body, headers=headers, timeout=settings.http_timeout)
    logger.info(
        "hf.response",
        extra={
            "status": r.status_code,
            "ms": round((time.perf_counter() - t0) * 1000, 1),
        },
    )
    r.raise_for_status()

    jr = r.json()
    txt = jr.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
    s, e = txt.find("{"), txt.rfind("}")
    content = txt[s : e + 1] if s != -1 and e != -1 else "{}"
    out = json.loads(content)
    logger.info("hf.parsed_json", extra={"len": len(content)})
    return out


def _build_image_prompt_full(filename: str, mime: str, se_full: Dict[str, Any]) -> str:
    full_json = json.dumps(se_full or {}, ensure_ascii=False)
    return (
        "Tarefa: você é um analista de segurança de conteúdo visual. "
        "Com base no retorno TÉCNICO do detector Sightengine (considerado confiável), "
        "gere uma EXPLICAÇÃO DA CLASSIFICAÇÃO e RECOMENDAÇÕES para um usuário leigo.\n"
        f"Arquivo: {filename} ({mime})\n"
        f"Sightengine (JSON COMPLETO):\n{full_json}\n\n"
        "REGRAS DE INTERPRETAÇÃO (obrigatórias):\n"
        "- Leia os campos 'type.ai_generated' ou 'genai.ai_generated' (ou equivalentes).\n"
        "- Se o valor indicado for muito alto (≈ 0.90 ou maior), trate como FALSA (fake).\n"
        "- Se for intermediário (≈ 0.60 a 0.89), trate como SUSPEITA (suspicious).\n"
        "- Se for baixo (abaixo de ≈ 0.60), trate como SEGURA (safe).\n"
        "IMPORTANTE: a explicação DEVE refletir essa interpretação. Nunca diga que é 'segura' se a leitura indicar 'falsa' ou 'suspeita'.\n\n"
        "Instruções de estilo (obrigatórias):\n"
        "- NÃO reclassifique de forma independente; explique o porquê da leitura acima usando os sinais que aparecem no JSON.\n"
        "- A PRIMEIRA FRASE deve começar com: 'Foi classificada como <Falsa/Suspeita/Segura> porque...' e citar o(s) motivo(s) do Sightengine "
        "(ex.: 'o detector apontou geração por IA', 'não há sinais de geração por IA nem conteúdo proibido', etc.).\n"
        "- NÃO use números, porcentagens ou termos técnicos como 'score', 'probabilidade', 'confiança'.\n"
        "- NÃO descreva o conteúdo visual da foto; fale apenas dos sinais do detector.\n"
        "- Escreva a explicação em 3 a 5 frases, tom calmo e claro.\n"
        "- Se houver rosto(s) no JSON, inclua uma frase curta sobre privacidade/consentimento ao compartilhar.\n"
        "- Se houver texto sensível/ofensivo no JSON, mencione de forma simples.\n"
        "- Traga 2 a 4 recomendações práticas, curtas, no imperativo (ex.: 'Peça autorização antes de publicar').\n"
        "- Português do Brasil.\n\n"
        "Formato de saída (obrigatório): responda ESTRITAMENTE em JSON válido com as chaves:\n"
        '{ "explanation": "texto claro para leigos (3–5 frases)", '
        '"recommendations": ["recomendação 1", "recomendação 2"] }\n'
    )


class AIService:
    __slots__ = ("client",)

    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self.client = client

    async def generate_for_url(
        self,
        *,
        url: str,
        tld_ok: bool,
        dns_ok: bool,
        gsb_json: Dict[str, Any],
    ) -> Dict[str, Any]:
        client = self.client or httpx.AsyncClient(timeout=settings.http_timeout)
        close_client = self.client is None

        try:
            try:
                iana_tlds = await _load_iana_tlds(client)
            except Exception as exc:
                logger.exception(
                    "iana.tlds.error",
                    extra={
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    },
                )
                raise ValueError(GENERIC_ANALYSIS_ERROR) from exc

            sig = _compute_signals(url, iana_tlds, tld_ok_input=tld_ok, dns_ok=dns_ok)
            prompt = _build_prompt(gsb_json or {}, sig)
            
            try:
                out = await _hf_chat(
                    client,
                    prompt,
                    temperature=0.16,
                    max_tokens=360,
                )
            except Exception as exc:
                logger.exception(
                    "hf.chat.url.error",
                    extra={
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    },
                )
                raise ValueError(GENERIC_ANALYSIS_ERROR) from exc



            if not isinstance(out, dict) or not all(
                k in out for k in ("classification", "explanation", "recommendations")
            ):
                logger.error("hf.chat.url.invalid_payload")
                raise ValueError(GENERIC_ANALYSIS_ERROR)

            explanation = " ".join(str(out.get("explanation", "")).split())
            out["explanation"] = explanation
            return out
        finally:
            if close_client:
                await client.aclose()

    async def generate_for_image(
        self,
        *,
        filename: str,
        mime: str,
        detection_json: Dict[str, Any],
    ) -> Dict[str, Any]:
        se_full = detection_json or {}
        client = self.client or httpx.AsyncClient(timeout=settings.http_timeout)
        close_client = self.client is None

        try:
            prompt = _build_image_prompt_full(filename, mime, se_full)

            try:
                out = await _hf_chat(
                    client,
                    prompt,
                    temperature=0.16,
                    max_tokens=480,
                )
            except Exception as exc:
                logger.exception(
                    "hf.chat.image.error",
                    extra={
                        "error_type": type(exc).__name__,
                        "error_message": str(exc),
                    },
                )
                raise ValueError(GENERIC_ANALYSIS_ERROR) from exc


            if not isinstance(out, dict) or not all(
                k in out for k in ("explanation", "recommendations")
            ):
                logger.error(
                    "hf.chat.image.invalid_payload",
                    extra={"raw": str(out)[:500]},
                )
                raise ValueError(GENERIC_ANALYSIS_ERROR)


            explanation = " ".join(str(out.get("explanation", "")).split())
            out["explanation"] = explanation

            recs = out.get("recommendations") or []
            if isinstance(recs, list):
                out["recommendations"] = [str(r).strip() for r in recs if str(r).strip()]
            elif recs:
                out["recommendations"] = [str(recs).strip()]
            else:
                out["recommendations"] = []

            return out
        finally:
            if close_client:
                await client.aclose()
