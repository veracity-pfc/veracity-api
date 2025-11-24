from __future__ import annotations

import logging
from datetime import datetime, timezone
from math import ceil
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.domain.audit_model import AuditLog
from app.domain.contact_request_model import ContactRequest
from app.domain.enums import ContactCategory, ContactStatus
from app.domain.user_model import User
from app.repositories.audit_repository import AuditRepository
from app.repositories.contact_repository import ContactRepository
from app.services.email_service import (
    EmailError,
    build_contact_reply_email_html,
    send_email,
)

logger = logging.getLogger("veracity.contact")


class ContactService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.audit = AuditRepository(session)
        self.repo = ContactRepository(session)

    async def list_requests(
        self,
        page: int,
        page_size: int,
        status: Optional[ContactStatus] = None,
        category: Optional[ContactCategory] = None,
        email: Optional[str] = None,
    ) -> Tuple[int, int, List[ContactRequest]]:
        total, rows = await self.repo.paginated(
            page=page,
            page_size=page_size,
            status=status,
            category=category,
            email=email,
        )
        total_pages = ceil(total / page_size) if page_size > 0 else 1
        return total, total_pages, rows

    async def _check_rate_limit(
        self, user_id: Optional[UUID], category: ContactCategory
    ):
        if not user_id:
            return

        count = await self.repo.count_by_user_and_category_status(
            user_id=user_id,
            category=category,
            status=ContactStatus.open,
        )
        if count > 0:
            cat_name = {
                ContactCategory.doubt: "dúvida",
                ContactCategory.complaint: "reclamação",
                ContactCategory.suggestion: "sugestão",
            }.get(category, "solicitação")

            raise ValueError(
                f"Você já possui uma {cat_name} em aberto. Aguarde a resposta."
            )

    async def process_contact_request(
        self,
        user: Optional[User],
        email: str,
        category: ContactCategory,
        subject: str,
        message: str,
        request_obj,
    ) -> None:
        ip_hash = ip_hash_from_request(request_obj)
        user_id = user.id if user else None

        await self._check_rate_limit(user_id, category)

        new_req = ContactRequest(
            user_id=user_id,
            email=email,
            category=category,
            subject=subject,
            message=message,
            status=ContactStatus.open,
        )
        await self.repo.create(new_req)

        await self.audit.insert(
            AuditLog,
            user_id=user_id,
            actor_ip_hash=ip_hash,
            action="contact.create",
            resource="/contact-us",
            success=True,
            details={"category": category.value, "subject": subject, "email": email},
        )
        await self.session.commit()

    async def reply_request(
        self, request_id: UUID, admin_user: User, reply_message: str
    ) -> ContactRequest:
        req = await self.repo.get(request_id)
        if not req:
            raise ValueError("Solicitação não encontrada.")

        if req.status != ContactStatus.open:
            raise ValueError("Esta solicitação já foi respondida.")

        now = datetime.now(timezone.utc)

        user_email = ""
        if req.user is not None and getattr(req.user, "email", None):
            user_email = req.user.email or ""

        is_deleted_user = "deleted.local" in user_email

        if is_deleted_user:
            req.status = ContactStatus.answered
            req.admin_reply = "Solicitação encerrada pois a conta foi excluída da plataforma."
            req.replied_at = now
            req.replied_by_admin_id = admin_user.id
        else:
            req.status = ContactStatus.answered
            req.admin_reply = reply_message
            req.replied_at = now
            req.replied_by_admin_id = admin_user.id

            try:
                html = build_contact_reply_email_html(
                    req.subject, req.message, reply_message
                )
                await send_email(req.email, f"Resposta: {req.subject}", html)
            except EmailError:
                logger.error(f"Falha ao enviar email de resposta para {req.id}")

        await self.audit.insert(
            AuditLog,
            user_id=req.user_id,
            actor_ip_hash=None,
            action="contact.reply",
            resource=f"/contact-requests/{request_id}",
            success=True,
            details={"admin_id": str(admin_user.id)},
        )

        await self.session.commit()
        return req

    async def get_request(self, request_id: UUID) -> Optional[ContactRequest]:
        return await self.repo.get(request_id)
