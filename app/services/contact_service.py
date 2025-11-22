from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.core.constants import EMAIL_RE
from app.domain.api_token_model import ApiToken
from app.domain.api_token_request_model import ApiTokenRequest
from app.domain.audit_model import AuditLog
from app.domain.enums import ApiTokenStatus, ApiTokenRequestStatus
from app.domain.user_model import User
from app.repositories.audit_repository import AuditRepository
from app.schemas.contact import ALLOWED_SUBJECTS
from app.services.email_service import (
    EmailError,
    build_api_token_request_email_html,
    build_contact_email_html,
    send_email,
)

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
        subject = (subject or "").strip()
        message = (message or "").strip()

        if not email:
            raise ValueError("O e-mail deve ser preenchido.")

        if len(email) > 60:
            raise ValueError("O e-mail deve ter no máximo 60 caracteres.")

        if not EMAIL_RE.match(email):
            raise ValueError("O e-mail informado é inválido.")

        if not subject or subject not in ALLOWED_SUBJECTS:
            print(F"ASSUNTO {subject}")
            raise ValueError("Assunto inválido.")

        if not message:
            raise ValueError("A mensagem deve ser preenchida.")

        if len(message) > 4000:
            raise ValueError("A mensagem deve ter no máximo 4000 caracteres.")

        contact_to: Optional[str] = getattr(settings, "contact_email", None) or getattr(
            settings, "resend_from", None
        )
        if not contact_to:
            raise ValueError("Configuração de e-mail não encontrada.")

        actor_hash = ip_hash_from_request(request)
        lower_subject = subject.lower()
        is_token_request = "solicitação de token de api" in lower_subject

        token_request: Optional[ApiTokenRequest] = None
        token_request_user: Optional[User] = None
        token_request_created_at: Optional[datetime] = None
        token_request_id = None
        audit_user: Optional[User] = None

        if is_token_request:
            stmt_user = select(User).where(func.lower(User.email) == email.lower())
            result_user = await self.session.execute(stmt_user)
            token_request_user = result_user.scalar_one_or_none()
            if not token_request_user:
                raise ValueError(
                    "O e-mail fornecido não foi encontrado. Verifique e tente novamente."
                )

            audit_user = token_request_user

            stmt_has_token = select(func.count(ApiToken.id)).where(
                ApiToken.user_id == token_request_user.id,
                ApiToken.status == ApiTokenStatus.active,
            )
            result_token = await self.session.execute(stmt_has_token)
            if (result_token.scalar_one() or 0) > 0:
                raise ValueError("Você já possui um token de API ativo.")

            stmt_has_open_req = select(func.count(ApiTokenRequest.id)).where(
                ApiTokenRequest.user_id == token_request_user.id,
                ApiTokenRequest.status == ApiTokenRequestStatus.open,
            )
            result_open_req = await self.session.execute(stmt_has_open_req)
            if (result_open_req.scalar_one() or 0) > 0:
                raise ValueError("Você já possui uma solicitação de token em análise.")

            token_request_created_at = datetime.now(timezone.utc)
            token_request_id = uuid4()
            created_fmt = token_request_created_at.strftime("%d/%m/%Y %H:%M:%S")
            html = build_api_token_request_email_html(
                email=email,
                created_at=created_fmt,
                request_id=str(token_request_id),
            )
            email_subject = "Nova solicitação de token de API"
        else:
            stmt_user = select(User).where(func.lower(User.email) == email.lower())
            result_user = await self.session.execute(stmt_user)
            audit_user = result_user.scalar_one_or_none()

            html = build_contact_email_html(email=email, subject=subject, message=message)
            email_subject = f"Nova mensagem recebida - {subject}"

        success = False
        try:
            await send_email(
                to=contact_to,
                subject=email_subject,
                html_body=html,
            )
            success = True

            if (
                is_token_request
                and token_request_user
                and token_request_created_at
                and token_request_id
            ):
                token_request = ApiTokenRequest(
                    id=token_request_id,
                    user_id=token_request_user.id,
                    email=email,
                    message=message,
                    status=ApiTokenRequestStatus.open,
                    created_at=token_request_created_at,
                )
                self.session.add(token_request)
        except EmailError:
            logger.error("contact.email_failed")
            raise ValueError(
                "Não foi possível enviar a mensagem agora. Tente novamente mais tarde."
            )
        finally:
            audit_repo = AuditRepository(self.session)

            await audit_repo.insert(
                table=AuditLog,
                user_id=audit_user.id if audit_user else None,
                actor_ip_hash=actor_hash,
                action="contact.send",
                resource="/contact-us",
                success=success,
                details={"from": email, "subject": subject},
            )

            if is_token_request and success and token_request and token_request_user:
                await audit_repo.insert(
                    table=AuditLog,
                    user_id=token_request_user.id,
                    actor_ip_hash=actor_hash,
                    action="api_token_request.create",
                    resource="/contact-us",
                    success=True,
                    details={
                        "request_id": str(token_request.id),
                        "email": email,
                    },
                )

            await self.session.commit()