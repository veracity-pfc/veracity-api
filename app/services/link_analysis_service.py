import httpx
import asyncio
from urllib.parse import urlparse
from app.utils.validators import ensure_tld_cache, has_valid_tld, is_resolvable
from app.schemas.analysis_schema import LinkAnalysisResponse

from app.utils.constants import (
    IPQS_API_KEY, IPQS_API_URL, 
    IPQS_BASE_URL,
    GOOGLE_SAFE_BROWSING_API_KEY, 
    GOOGLE_SAFE_BROWSING_BASE_URL,
    HTTP_TIMEOUT, HTTP_USER_AGENT
)

def create_custom_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": HTTP_USER_AGENT})

async def check_ipqs(url: str) -> dict:
    if not IPQS_API_KEY:
        return {}
    try:
        async with create_custom_http_client() as client:
            response = await client.get(f"{IPQS_API_URL}/{IPQS_API_KEY}", params={"url": url})
            response.raise_for_status()
            data = response.json()
            return data
    except Exception as e:
        return {}

async def check_gsb(url: str) -> bool:
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return False

    payload = {
        "client": {"clientId": "veracity-pfc", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION", "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        async with create_custom_http_client() as client:
            response = await client.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}",
                json=payload
            )
            response.raise_for_status()
            data = response.json()
            return bool(data.get("matches"))
    except Exception as e:
        return False

def ipqs_classification(data: dict) -> str:
    if not data:
        return ""

    rules = {
        "Falso": any([
            data.get("phishing"),
            data.get("unsafe"),
            data.get("malware")
        ]),
        "Suspeito": any([
            data.get("suspicious"),
            data.get("risk_score") >= 70
        ]),
    }

    for label, condition in rules.items():
        if condition:
            return label

    return "Seguro"


def build_source_links(used_gsb: bool) -> list[str]:
    sources = []
    if IPQS_API_KEY:
        sources.append(IPQS_BASE_URL)
    if used_gsb:
        sources.append(GOOGLE_SAFE_BROWSING_BASE_URL)
    return sources


def build_recommendations(label: str) -> list[str]:
    return {
        "Falso": ["Não insira credenciais ou dados pessoais."],
        "Suspeito": ["Evite abrir em dispositivo pessoal."],
        "Seguro": ["Nenhuma ação necessária."],
    }[label]


async def analyze_link(url: str) -> LinkAnalysisResponse:
    await ensure_tld_cache()

    host = urlparse(url).hostname or ""
    tld_ok = has_valid_tld(host)
    host_ok = await is_resolvable(host)

    ipqs_task = asyncio.create_task(check_ipqs(url))
    gsb_task = asyncio.create_task(check_gsb(url))
    ipqs_data, gsb_data = await asyncio.gather(ipqs_task, gsb_task)

    notes = []

    if not tld_ok:
        label = "Falso"
        notes.append("TLD inválido.")
    elif gsb_data:
        label = "Falso"
        notes.append("Listagem no Google Safe Browsing.")
    elif not host_ok:
        label = "Falso"
        notes.append("Subdomínio ou host não resolve em DNS.")
    else:
        label = ipqs_classification(ipqs_data) or "Seguro"
        if label == "Suspeito":
            notes.append("Baixa reputação informada por fontes externas.")
        elif label == "Seguro":
            notes.append("Sem sinais de risco ou listagens em fontes consultadas.")

    response = LinkAnalysisResponse(
        classification=label,
        explanation=" ".join(notes) if notes else "Sem sinais relevantes.",
        sources=build_source_links(used_gsb=gsb_data),
        recommendations=build_recommendations(label),
    )

    return response
