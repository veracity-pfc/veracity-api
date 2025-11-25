from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from tld import get_tld

from app.core.config import settings
from app.core.constants import GENERIC_ANALYSIS_ERROR, HAS_DIGIT_RE

logger = logging.getLogger("veracity.ai_service")


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
    hosting_provider: str
    is_hosting_provider: bool


def _detect_hosting_provider(host: str) -> str:
    if not host:
        return ""
    h = host.lower()
    providers = {
        "vercel.app": "vercel",
        "onrender.com": "render",
        "render.com": "render",
        "netlify.app": "netlify",
        "web.app": "web_app",
        "firebaseapp.com": "firebase",
        "github.io": "github_pages",
        "herokuapp.com": "heroku",
        "glitch.me": "glitch",
    }
    for suffix, name in providers.items():
        if h.endswith(suffix):
            return name
    return ""


def _compute_signals(url: str, *, tld_ok_input: bool, dns_ok: bool) -> URLSignals:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()

    hosting_provider = _detect_hosting_provider(host)

    try:
        res = get_tld(url, as_object=True, fix_protocol=True)
        tld = str(res.tld)
        tld_valid = True
    except Exception:
        tld = ""
        tld_valid = False

    sub_count = max(0, host.count(".") - 1)

    return URLSignals(
        url=url,
        host=host,
        tld=tld,
        tld_in_iana=tld_valid,
        tld_ok_input=tld_ok_input,
        dns_ok=dns_ok,
        subdomain_count=sub_count,
        has_hyphen=("-" in host) or ("_" in host),
        has_digits=bool(HAS_DIGIT_RE.search(host)),
        is_punycode=host.startswith("xn--"),
        path_len=len(parts.path or ""),
        query_len=len(parts.query or ""),
        hosting_provider=hosting_provider,
        is_hosting_provider=bool(hosting_provider),
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
        "- Se o campo \"is_hosting_provider\" for verdadeiro, você DEVE classificar como \"Suspeito\", "
        "explicando que empresas legítimas normalmente usam domínios próprios (como \"empresa.com\" ou "
        "\"empresa.com.br\") em vez de subdomínios genéricos em provedores como Vercel, Render, Netlify, "
        "Firebase ou similares.\n"
        "- Explique em UM parágrafo curto, SEM termos técnicos; foque no que o usuário leigo precisa saber e por quê.\n"
        "- Em seguida, traga 2 recomendações práticas e curtas.\n"
        "Responda SOMENTE com JSON válido no formato exato:\n"
        '{ "classification": "Seguro|Suspeito|Malicioso", '
        '"explanation": "um parágrafo claro e simples", '
        '"recommendations": ["recomendação 1", "recomendação 2"] }\n"'
    )


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
        "- A PRIMEIRA FRASE deve começar com: 'Foi classificada como <Falsa/Suspeita/Segura> porque...' e citar o(s) motivo(s) do Sightengine.\n"
        "- NÃO use números, porcentagens ou termos técnicos como 'score', 'probabilidade', 'confiança'.\n"
        "- NÃO descreva o conteúdo visual da foto; fale apenas dos sinais do detector.\n"
        "- Escreva a explicação em 3 a 5 frases, tom calmo e claro.\n"
        "- Se houver rosto(s) no JSON, inclua uma frase curta sobre privacidade/consentimento ao compartilhar.\n"
        "- Se houver texto sensível/ofensivo no JSON, mencione de forma simples.\n"
        "- Traga 2 a 4 recomendações práticas, curtas, no imperativo.\n"
        "- Português do Brasil.\n\n"
        "Formato de saída (obrigatório): responda ESTRITAMENTE em JSON válido com as chaves:\n"
        '{ "explanation": "texto claro para leigos (3–5 frases)", '
        '"recommendations": ["recomendação 1", "recomendação 2"] }\n"'
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
    logger.debug("Sending request to HF Inference API")
    try:
        r = await client.post(
            url, json=body, headers=headers, timeout=settings.http_timeout
        )
    except httpx.HTTPError as e:
        logger.error(f"HF API connection error: {str(e)}")
        raise

    duration = round((time.perf_counter() - t0) * 1000, 1)
    logger.info(f"HF API response received. Status: {r.status_code}, Duration: {duration}ms")
    
    r.raise_for_status()

    jr = r.json()
    txt = jr.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
    s, e = txt.find("{"), txt.rfind("}")
    content = txt[s : e + 1] if s != -1 and e != -1 else "{}"
    return json.loads(content)


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
        logger.info(f"Generating AI analysis for URL: {url}")
        client = self.client or httpx.AsyncClient(timeout=settings.http_timeout)
        close_client = self.client is None

        try:
            sig = _compute_signals(url, tld_ok_input=tld_ok, dns_ok=dns_ok)
            prompt = _build_prompt(gsb_json or {}, sig)

            try:
                out = await _hf_chat(
                    client,
                    prompt,
                    temperature=0.16,
                    max_tokens=360,
                )
            except Exception as exc:
                logger.exception("Failed to query HF API for URL analysis")
                raise ValueError(GENERIC_ANALYSIS_ERROR) from exc

            if not isinstance(out, dict):
                out = {}

            classification = str(out.get("classification", "")).strip()
            explanation = str(out.get("explanation", "")).strip()
            recs = out.get("recommendations")

            if not classification:
                classification = "Suspeito" if sig.is_hosting_provider else "Desconhecido"

            if not explanation:
                if sig.is_hosting_provider:
                    explanation = (
                        "Esta URL está hospedada em um provedor genérico de aplicações, e "
                        "empresas e instituições legítimas normalmente utilizam domínios próprios "
                        "para seus sites oficiais."
                    )
                else:
                    explanation = (
                        "Não foi possível interpretar completamente os sinais técnicos desta URL, "
                        "então é recomendável manter cautela ao acessá-la."
                    )

            if not isinstance(recs, list):
                recs = []

            if not recs:
                recs = [
                    "Evite informar senhas ou dados pessoais antes de confirmar se o endereço é realmente oficial.",
                    "Quando estiver em dúvida, digite o endereço do site diretamente no navegador em vez de clicar em links recebidos por mensagens.",
                ]

            out = {
                "classification": classification,
                "explanation": explanation,
                "recommendations": recs,
            }

            if sig.is_hosting_provider:
                current_cls = str(out.get("classification", "")).strip()
                if not current_cls or current_cls.lower().startswith("segur"):
                    out["classification"] = "Suspeito"
                reason = (
                    "Esta URL está hospedada em um provedor genérico de aplicações, e "
                    "empresas e instituições legítimas normalmente utilizam domínios próprios "
                    "para seus sites oficiais."
                )
                current_exp = str(out.get("explanation") or "").strip()
                if current_exp:
                    out["explanation"] = f"{reason} {current_exp}"
                else:
                    out["explanation"] = reason

            out["explanation"] = " ".join(str(out.get("explanation", "")).split())
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
        logger.info(f"Generating AI analysis for Image: {filename}")
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
                logger.exception("Failed to query HF API for Image analysis")
                raise ValueError(GENERIC_ANALYSIS_ERROR) from exc

            if not isinstance(out, dict) or not all(
                k in out for k in ("explanation", "recommendations")
            ):
                raise ValueError(GENERIC_ANALYSIS_ERROR)

            out["explanation"] = " ".join(str(out.get("explanation", "")).split())

            recs = out.get("recommendations") or []
            if isinstance(recs, list):
                out["recommendations"] = [
                    str(r).strip() for r in recs if str(r).strip()
                ]
            elif recs:
                out["recommendations"] = [str(recs).strip()]
            else:
                out["recommendations"] = []

            return out
        finally:
            if close_client:
                await client.aclose()