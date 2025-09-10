import re
import httpx
import socket
import asyncio
from urllib.parse import urlparse
from datetime import datetime

from app.utils.constants import (
    IANA_TLD_URL, 
    TLD_CACHE_FILE, 
    TLD_CACHE_TTL, 
    HTTP_TIMEOUT, 
    HTTP_USER_AGENT,
    MAX_URL_LENGTH
)

from app.utils.error_message import (
    ERROR_MESSAGE_INVALID_PROTOCOL,
    ERROR_MESSAGE_INVALID_DOMAIN,
    ERROR_MESSAGE_EMPTY_URL,
    ERROR_MESSAGE_MAX_LENGTH,
    ERROR_MESSAGE_INVALID_CHARACTERS
)

_ALLOWED_CHARACTERS = re.compile(r'^[a-zA-Z0-9/:.\-]+$')

def is_valid_url(url: str) -> tuple[bool, str]:
    if not url:
        return False, ERROR_MESSAGE_EMPTY_URL

    if len(url) > MAX_URL_LENGTH:
        return False, ERROR_MESSAGE_MAX_LENGTH

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False, ERROR_MESSAGE_INVALID_PROTOCOL
    
    if not _ALLOWED_CHARACTERS.fullmatch(url):
        return False, ERROR_MESSAGE_INVALID_CHARACTERS

    host = parsed.hostname or ""
    if "." not in host:
        return False, ERROR_MESSAGE_INVALID_DOMAIN

    return True, ""

async def ensure_tld_cache():
    TLD_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        if TLD_CACHE_FILE.exists():
            last_modified = datetime.fromtimestamp(TLD_CACHE_FILE.stat().st_mtime)
            if datetime.now() - last_modified < TLD_CACHE_TTL:
                return

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, headers={"User-Agent": HTTP_USER_AGENT}) as client:
            response = await client.get(IANA_TLD_URL)
            response.raise_for_status()
            TLD_CACHE_FILE.write_text(response.text, encoding="utf-8")
    except Exception:
        pass

def _get_tlds_from_cache() -> set[str]:
    if TLD_CACHE_FILE.exists():
        return {
            line.strip().lower()
            for line in TLD_CACHE_FILE.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }

    return {
        "com", "br", "net", "org", "gov",
        "edu", "io", "app", "dev", "site", 
        "info", "biz", "online", "store"
    }

def has_valid_tld(host: str) -> bool:
    host = (host or "").strip(".").lower()
    if "." not in host:
        return False
    tld = host.rsplit(".", 1)[-1]
    return tld in _get_tlds_from_cache()

async def is_resolvable(host: str) -> bool:
    try:
        return await asyncio.to_thread(lambda: socket.getaddrinfo(host, None)) is not None
    except Exception:
        return False
