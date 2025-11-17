from __future__ import annotations

import logging
import re
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.core.constants import EMAIL_RE
from app.domain.audit_model import AuditLog
from app.repositories.audit_repo import AuditRepository
from app.services.email_service import EmailError, build_contact_email_html, send_email

logger = logging.getLogger("veracity.contact")


class ContactService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def send_contact_message(
        self,
        *,
        email: str,
        subject: str,
        message: str,
        request,
    ) -> None:

        email = (email or "").strip()
        message = (message or "").strip()

        if not email:
            raise ValueError("O e-mail deve ser preenchido.")

        if len(email) > 60:
            raise ValueError("O e-mail deve ter no máximo 60 caracteres.")

        if not EMAIL_RE.match(email):
            raise ValueError("O e-mail informado é inválido.")

        if not message:
            raise ValueError("A mensagem deve ser preenchida.")

        if len(message) > 4000:
            raise ValueError("A mensagem deve ter no máximo 4000 caracteres.")

        contact_to: Optional[str] = getattr(settings, "resend_from", None)
        if not contact_to:
            raise ValueError("Configuração de e-mail não encontrada.")

        actor_hash = ip_hash_from_request(request)
        html = build_contact_email_html(email=email, subject=subject, message=message)

        success = False
        try:
            await send_email(
                to=contact_to,
                subject=f"Nova mensagem recebida - {subject}",
                html_body=html,
            )
            success = True
        except EmailError:
            logger.error("contact.email_failed")
            raise ValueError(
                "Não foi possível enviar a mensagem agora. Tente novamente mais tarde."
            )
        finally:
            await AuditRepository(self.session).insert(
                table=AuditLog,
                user_id=None,
                actor_ip_hash=actor_hash,
                action="contact.send",
                resource="/contact-us",
                success=success,
                details={"from": email, "subject": subject},
            )
            await self.session.commit()
