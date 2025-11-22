from __future__ import annotations
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, List
from uuid import uuid4
from math import ceil

from sqlalchemy import func, select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.domain.user_model import User
from app.domain.contact_request_model import ContactRequest
from app.domain.enums import ContactCategory, ContactStatus
from app.domain.audit_model import AuditLog
from app.repositories.audit_repository import AuditRepository
from app.services.email_service import (
    EmailError,
    send_email,
    build_contact_reply_email_html
)

logger = logging.getLogger("veracity.contact")

class ContactService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_requests(
        self,
        page: int,
        page_size: int,
        status: Optional[ContactStatus] = None,
        category: Optional[ContactCategory] = None,
        email: Optional[str] = None
    ) -> Tuple[int, int, List[ContactRequest]]:
        stmt = select(ContactRequest)
        
        if status:
            stmt = stmt.where(ContactRequest.status == status)
        if category:
            stmt = stmt.where(ContactRequest.category == category)
        if email:
            stmt = stmt.where(func.lower(ContactRequest.email).contains(email.lower()))
            
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.session.execute(count_stmt)).scalar() or 0
        
        stmt = stmt.order_by(desc(ContactRequest.created_at))
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        
        rows = (await self.session.execute(stmt)).scalars().all()
        total_pages = ceil(total / page_size) if page_size > 0 else 1
        
        return total, total_pages, list(rows)

    async def _check_rate_limit(self, user_id: Optional[uuid4], category: ContactCategory):
        if not user_id:
            return

        if category in [ContactCategory.doubt, ContactCategory.complaint]:
            stmt = select(func.count(ContactRequest.id)).where(
                ContactRequest.user_id == user_id,
                ContactRequest.category == category,
                ContactRequest.status == ContactStatus.open
            )
            res = await self.session.execute(stmt)
            count = res.scalar() or 0
            if count > 0:
                msg = "dúvida" if category == ContactCategory.doubt else "reclamação"
                raise ValueError(f"Você já possui uma {msg} em aberto. Aguarde a resposta antes de enviar outra.")
        
        elif category == ContactCategory.suggestion:
            now = datetime.now(timezone.utc)
            one_day_ago = now - timedelta(days=1)
            stmt = select(func.count(ContactRequest.id)).where(
                ContactRequest.user_id == user_id,
                ContactRequest.category == category,
                ContactRequest.created_at >= one_day_ago
            )
            res = await self.session.execute(stmt)
            count = res.scalar() or 0
            if count >= 3:
                raise ValueError("Você atingiu o limite de 3 sugestões por dia.")

    async def create_request(
        self,
        user: Optional[User],
        email: str,
        category: ContactCategory,
        subject: str,
        message: str,
        request_obj
    ) -> None:
        audit = AuditRepository(self.session)
        ip_hash = ip_hash_from_request(request_obj)
        
        user_id = user.id if user else None

        await self._check_rate_limit(user_id, category)

        new_req = ContactRequest(
            user_id=user_id, 
            email=email,
            category=category,
            subject=subject,
            message=message,
            status=ContactStatus.open
        )
        self.session.add(new_req)
        
        await audit.insert(
            AuditLog,
            user_id=user_id,
            actor_ip_hash=ip_hash,
            action="contact.create",
            resource="/contact-us",
            success=True,
            details={"category": category.value, "subject": subject, "email": email}
        )
        await self.session.commit()

    async def reply_request(
        self,
        request_id: uuid4,
        admin_user: User,
        reply_message: str
    ) -> ContactRequest:
        stmt = select(ContactRequest).where(ContactRequest.id == request_id)
        res = await self.session.execute(stmt)
        req = res.scalar_one_or_none()
        
        if not req:
            raise ValueError("Solicitação não encontrada.")
        
        if req.status != ContactStatus.open:
            raise ValueError("Esta solicitação já foi respondida.")

        now = datetime.now(timezone.utc)
        req.status = ContactStatus.answered
        req.admin_reply = reply_message
        req.replied_at = now
        req.replied_by_admin_id = admin_user.id
        
        try:
            html = build_contact_reply_email_html(req.subject, req.message, reply_message)
            await send_email(req.email, f"Resposta: {req.subject}", html)
        except EmailError:
            logger.error(f"Falha ao enviar email de resposta para {req.id}")

        audit = AuditRepository(self.session)
        await audit.insert(
            AuditLog,
            user_id=req.user_id, 
            actor_ip_hash=None,
            action="contact.reply",
            resource=f"/contact-requests/{request_id}",
            success=True,
            details={"admin_id": str(admin_user.id)}
        )

        await self.session.commit()
        return req
    
    async def get_request(self, request_id: uuid4) -> Optional[ContactRequest]:
        return await self.session.get(ContactRequest, request_id)