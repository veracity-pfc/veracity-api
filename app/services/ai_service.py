from __future__ import annotations

import ast
import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlsplit

import httpx
from tld import get_tld

from app.core.config import settings
from app.core.constants import GENERIC_ANALYSIS_ERROR, HAS_DIGIT_RE, QUERY_DOMAIN_RE

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
    is_https: bool
    query_domain: str
    query_domain_mismatch: bool


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
    path = parts.path or ""
    query = parts.query or ""
    combined = f"{path}?{query}" if query or path else ""
    m = QUERY_DOMAIN_RE.search(combined)
    query_domain = m.group(1).lower() if m else ""
    query_domain_mismatch = bool(query_domain and query_domain not in host)
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
        path_len=len(path),
        query_len=len(query),
        hosting_provider=hosting_provider,
        is_hosting_provider=bool(hosting_provider),
        is_https=parts.scheme.lower() == "https",
        query_domain=query_domain,
        query_domain_mismatch=query_domain_mismatch,
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
        "- Mesmo sem alertas no GSB, considere: TLD desconhecido, punycode, muitos subdomínios, hífens/números, caminho longo e uso de HTTP sem HTTPS.\n"
        "- Se o campo \"is_hosting_provider\" for verdadeiro, avalie o host: se parecer o site ou painel oficial do próprio provedor "
        "(por exemplo, \"dashboard.render.com\", \"render.com\", \"vercel.com\", \"netlify.com\"), e não houver outros sinais claros de golpe, "
        "você pode classificar como \"Seguro\", apenas explicando que é um serviço de hospedagem.\n"
        "- Para subdomínios genéricos de hospedagem usados por projetos (como \"meusite.onrender.com\", \"app.netlify.app\", "
        "\"minhaapp.vercel.app\"), em geral classifique no mínimo como \"Suspeito\", explicando que criminosos costumam abusar desse tipo de endereço.\n"
        "- Se o campo \"query_domain_mismatch\" for verdadeiro, considere a URL no mínimo como \"Suspeito\", "
        "explicando que o endereço real é de um domínio estranho usando o nome de outro site dentro da URL.\n"
        "- Explique em UM parágrafo curto, SEM termos técnicos; foque no que o usuário leigo precisa saber e por quê.\n"
        "- Em seguida, traga 2 recomendações práticas e curtas.\n"
        "Responda SOMENTE com JSON válido no formato exato:\n"
        '{ "classification": "Seguro|Suspeito|Malicioso", '
        '"explanation": "um parágrafo claro e simples", '
        '"recommendations": ["recomendação 1", "recomendação 2"] }'
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
        "REGRAS IMPORTANTES DE SAÍDA:\n"
        "1. Retorne APENAS um objeto JSON válido.\n"
        "2. NÃO inclua campos como 'reasoning', 'thought' ou 'chain_of_thought'.\n"
        "3. NÃO use formatação markdown (como ```json).\n"
        "4. O JSON deve ter exatamente estas chaves: 'explanation', 'recommendations', 'classification'.\n"
        "5. A classificação deve ser uma destas: 'Seguro', 'Suspeito', 'Falso'.\n"
        "6. A explicação deve ser em Português, concisa e justificar a pontuação.\n"
        "7. 'recommendations' deve ser uma lista de strings em Português com dicas de segurança.\n"
    )


async def _hf_chat(
    client: httpx.AsyncClient,
    prompt: str,
    *,
    temperature: float = 0.18,
    max_tokens: int = 500,
) -> Dict[str, Any]:
    url = f"{settings.hf_base_url}/chat/completions"
    headers = {"Authorization": f"Bearer {settings.hf_token}"}
    body = {
        "model": settings.hf_openai_model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
    }
    t0 = time.perf_counter()
    logger.debug("Sending request to HF Inference API")
    try:
        r = await client.post(url, json=body, headers=headers, timeout=40.0)
        duration = round((time.perf_counter() - t0) * 1000, 1)
        raw_response = r.text
        logger.info(
            f"HF API response. Status: {r.status_code}, Duration: {duration}ms. Raw Body Snippet: {raw_response[:700]}"
        )
        if r.status_code >= 400:
            logger.error(f"HF API Error Body: {raw_response}")
            raise ValueError(GENERIC_ANALYSIS_ERROR)
        try:
            jr = r.json()
        except json.JSONDecodeError:
            logger.error(f"HF returned invalid JSON. Raw body: {raw_response}")
            raise ValueError(GENERIC_ANALYSIS_ERROR)
        choices = jr.get("choices", [])
        if not choices:
            logger.error(f"HF response has no 'choices'. Full JSON: {jr}")
            raise ValueError(GENERIC_ANALYSIS_ERROR)
        message_content = choices[0].get("message", {}).get("content", "")
        if not message_content:
            logger.error(f"HF message content is empty. Full JSON: {jr}")
            raise ValueError(GENERIC_ANALYSIS_ERROR)
        logger.debug(f"AI Content extracted: {message_content[:200]}...")
        s = message_content.find("{")
        e = message_content.rfind("}")
        if s == -1 or e == -1:
            logger.warning(f"No JSON brackets found in AI response. Content: {message_content}")
            raise ValueError(GENERIC_ANALYSIS_ERROR)
        json_str = message_content[s : e + 1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError as je:
            logger.warning(f"Failed to parse JSON. Trying literal eval. Error: {je}. Content: {json_str}")
            try:
                obj = ast.literal_eval(json_str)
                if isinstance(obj, dict):
                    return obj
                logger.error(f"Literal eval did not return dict. Type: {type(obj)}")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            except Exception as exc:
                logger.error(f"Failed to parse AI content with literal eval. Error: {exc}. Content: {json_str}")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
    except httpx.HTTPError as exc:
        logger.error(f"HF HTTP connection error: {type(exc).__name__} - {str(exc)}")
        raise ValueError("AI_SERVICE_UNAVAILABLE")


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
                    max_tokens=500,
                )
            except Exception as exc:
                logger.exception("Failed to query HF API for URL analysis")
                raise ValueError(GENERIC_ANALYSIS_ERROR) from exc
            if not isinstance(out, dict):
                logger.error(f"AI returned invalid type: {type(out)}")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            classification = str(out.get("classification", "")).strip()
            explanation = str(out.get("explanation", "")).strip()
            recs = out.get("recommendations")
            if not classification or not explanation:
                logger.error(
                    f"AI returned incomplete data. Class: '{classification}', Exp len: {len(explanation)}"
                )
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            if isinstance(recs, list):
                recommendations = [str(r).strip() for r in recs if str(r).strip()]
            elif recs:
                recommendations = [str(recs).strip()]
            else:
                recommendations = []
            out_clean = {
                "classification": classification,
                "explanation": " ".join(explanation.split()),
                "recommendations": recommendations,
            }
            official_hosts = {
                "render.com",
                "dashboard.render.com",
                "vercel.com",
                "netlify.com",
                "www.netlify.com",
            }
            is_official_host = sig.host in official_hosts
            if sig.is_hosting_provider and not is_official_host:
                current_cls = out_clean["classification"]
                if not current_cls or current_cls.lower().startswith("segur"):
                    out_clean["classification"] = "Suspeito"
            if sig.query_domain_mismatch:
                current_cls = out_clean["classification"]
                if not current_cls or current_cls.lower().startswith("segur"):
                    out_clean["classification"] = "Suspeito"
            return out_clean
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
                    max_tokens=500,
                )
            except Exception as exc:
                logger.exception("Failed to query HF API for Image analysis")
                raise ValueError(GENERIC_ANALYSIS_ERROR) from exc
            if not isinstance(out, dict):
                logger.error(f"HF Analysis failed: Output is not a dict. Type: {type(out)}")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            explanation = str(out.get("explanation", "")).strip()
            if not explanation:
                logger.error("HF Analysis returned empty explanation")
                raise ValueError(GENERIC_ANALYSIS_ERROR)
            recs = out.get("recommendations") or []
            if isinstance(recs, list):
                recommendations = [str(r).strip() for r in recs if str(r).strip()]
            elif recs:
                recommendations = [str(recs).strip()]
            else:
                recommendations = []
            classification = str(out.get("classification", "")).strip() or "Suspeito"
            return {
                "explanation": " ".join(explanation.split()),
                "recommendations": recommendations,
                "classification": classification,
            }
        finally:
            if close_client:
                await client.aclose()
