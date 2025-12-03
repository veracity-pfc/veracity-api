from __future__ import annotations

import html
import logging
from urllib.parse import urlsplit

import filetype
from app.core.constants import ALLOWED_MIMES, EMAIL_RE

logger = logging.getLogger("veracity.validation_utils")


def extract_host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def detect_mime(data: bytes) -> str | None:
    kind = filetype.guess(data)
    return (kind and kind.mime) or None


def validate_url_format(url: str) -> None:
    if not url:
        raise ValueError("A URL não pode estar vazia")
    if len(url) > 200:
        raise ValueError("A URL deve ter no máximo 200 caracteres.")
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("A URL deve começar com http:// ou https://")


def validate_image_file(file_content: bytes, content_type: str) -> None:
    if not file_content:
        raise ValueError("Arquivo vazio ou inválido.")
    if len(file_content) > 10_000_000:
        raise ValueError("A imagem deve ter no máximo 10MB.")
    if content_type not in ALLOWED_MIMES:
        logger.info(f"Invalid MIME type received: {content_type}")
        raise ValueError("Formato inválido. Aceitos: png, jpeg ou jpg")


def normalize_email(raw_email: str) -> str:
    email = html.unescape(raw_email or "").strip().lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("E-mail inválido.")
    return email


def validate_password_complexity(password: str) -> None:
    if len(password) < 8:
        raise ValueError("A nova senha deve ter pelo menos 8 caracteres.")
    
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    special = "!@#$%^&*()-_=+[]{};:,.<>/?"
    has_symbol = any(c in special or not c.isalnum() for c in password)
    has_lower = any(c.islower() for c in password)

    if not (has_upper and has_digit and (has_symbol or not password.isalnum())):
        raise ValueError(
            "A senha deve conter pelo menos 1 letra maiúscula, 1 número e 1 símbolo."
        )
    
    if not has_lower: 
         raise ValueError("Senha deve conter pelo menos uma letra minúscula.")


def validate_name_format(name: str) -> str:
    name = (name or "").strip()
    if len(name) < 3 or len(name) > 30:
        raise ValueError("Nome deve ter entre 3 e 30 caracteres.")
    return name

def anonymize_email(email: str | None) -> str:
    if not email:
        return ""
    email = email.strip()
    if not email:
        return ""
    if "@" not in email:
        return "***"
    local, domain = email.split("@", 1)
    if not local:
        masked_local = "***"
    elif len(local) == 1:
        masked_local = local + "***"
    elif len(local) == 2:
        masked_local = local[0] + "***"
    else:
        masked_local = local[0] + "***" + local[-1]
    return f"{masked_local}@{domain}"
