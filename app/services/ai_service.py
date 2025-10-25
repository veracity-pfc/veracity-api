from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx

from app.core.config import settings

logger = logging.getLogger("veracity.ai_service")

_IANA_TLDS: set[str] | None = None
_IANA_FETCH_TS: float | None = None
_IANA_TTL_SEC = 24 * 60 * 60 
_IANA_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
_HAS_DIGIT_RE = re.compile(r"\d")


async def _load_iana_tlds(client: httpx.AsyncClient) -> set[str]:
    global _IANA_TLDS, _IANA_FETCH_TS
    now = time.time()
    if _IANA_TLDS is not None and _IANA_FETCH_TS and (now - _IANA_FETCH_TS) < _IANA_TTL_SEC:
        return _IANA_TLDS

    t0 = time.perf_counter()
    r = await client.get(_IANA_URL, timeout=settings.http_timeout)
    ms = round((time.perf_counter() - t0) * 1000, 1)
    logger.info("iana.tlds.fetch", extra={"status": r.status_code, "ms": ms})

    r.raise_for_status()
    lines = r.text.splitlines()
    tlds = {ln.strip().lower() for ln in lines if ln and not ln.startswith("#")}
    _IANA_TLDS, _IANA_FETCH_TS = tlds, now
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
        has_digits=bool(_HAS_DIGIT_RE.search(host)),
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
        "model": settings.hf_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    t0 = time.perf_counter()
    r = await client.post(url, json=body, headers=headers, timeout=settings.http_timeout)
    logger.info("hf.response", extra={
        "status": r.status_code,
        "ms": round((time.perf_counter() - t0) * 1000, 1),
        "preview": r.text[:240].replace("\n", ""),
    })
    if r.status_code >= 400:
        return {"error": {"status": r.status_code, "text": r.text}}

    jr = r.json()
    txt = jr.get("choices", [{}])[0].get("message", {}).get("content", "") or ""
    s, e = txt.find("{"), txt.rfind("}")
    content = txt[s:e + 1] if s != -1 and e != -1 else "{}"
    try:
        out = json.loads(content)
        logger.info("hf.parsed_json", extra={"ok": True, "len": len(content)})
        return out
    except Exception:
        logger.warning("hf.parse_failed", extra={"len": len(txt)})
        return {}


def _fallback_from_signals(sig: URLSignals, gsb_json: Dict[str, Any]) -> Dict[str, Any]:
    has_gsb = bool(gsb_json and gsb_json.get("matches"))

    hints = list(filter(None, [
        "o endereço já aparece em listas de alerta de segurança" if has_gsb else None,
        "a terminação do endereço (como .com) não é reconhecida" if not sig.tld_in_iana else None,
        "o nome do site usa caracteres pouco comuns que podem confundir" if sig.is_punycode else None,
        "há muitos pontos no endereço, algo comum em falsificações" if sig.subdomain_count >= 2 else None,
        "o nome do site tem hífens ou números, típico de imitações" if (sig.has_hyphen or sig.has_digits) else None,
        "o link é longo demais, o que pode esconder o destino real" if (sig.path_len > 20 or sig.query_len > 0) else None,
        "o endereço não está respondendo como um site ativo" if not sig.dns_ok else None,
    ]))

    strong = any([not sig.tld_in_iana, sig.is_punycode, sig.subdomain_count >= 2, not sig.dns_ok])
    weak   = any([sig.has_hyphen, sig.has_digits, sig.path_len > 20, sig.query_len > 0])

    classification = (
        "Malicioso" if has_gsb else
        ("Suspeito" if (strong or weak) else "Seguro")
    )

    if hints:
        expl = (
            f"Este link merece atenção porque {', '.join(hints[:-1])}"
            f"{(' e ' + hints[-1]) if len(hints) > 1 else ''}."
        )
    else:
        expl = "O endereço parece consistente para uso comum e não mostra sinais de fraude."

    tail = {
        "Malicioso": " Recomendamos tratá-lo como perigoso.",
        "Seguro": ".",
        "Suspeito": ". Se não for um site que você conhece, evite interagir.",
    }[classification]
    expl = expl.rstrip(".") + tail

    recommendations = {
        "Malicioso": ["Não clique nem insira dados", "Bloqueie ou reporte este endereço"],
        "Seguro": ["Verifique o cadeado do navegador", "Mantenha navegador e antivírus atualizados"],
        "Suspeito": ["Evite logins e downloads", "Confirme o site por um canal oficial"],
    }[classification]

    return {
        "classification": classification,
        "explanation": expl,
        "recommendations": recommendations,
    }

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
            iana_tlds = await _load_iana_tlds(client)
            sig = _compute_signals(url, iana_tlds, tld_ok_input=tld_ok, dns_ok=dns_ok)

            prompt = _build_prompt(gsb_json or {}, sig)
            for temperature, suffix in (
                (0.16, ""),
                (0.1, "\nResponda estritamente no JSON solicitado, sem texto fora do objeto."),
            ):
                out = await _hf_chat(client, prompt + suffix, temperature=temperature, max_tokens=360)
                if all(k in out for k in ("classification", "explanation", "recommendations")):
                    out["explanation"] = " ".join(str(out.get("explanation", "")).split())
                    return out

            fb = _fallback_from_signals(sig, gsb_json or {})
            logger.info("hf.dynamic_fallback", extra={"classification": fb["classification"]})
            return fb

        finally:
            if close_client:
                await client.aclose()
