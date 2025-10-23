from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from app.core.config import settings
from app.api.deps import ip_hash_from_request
from app.domain.audit_model import AuditLog
from app.services.email_service import send_email, build_contact_email_html

class ContactService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def send_contact_message(
        self, *, email: str, subject: str, message: str, request
    ) -> None:
        
        contact_to: Optional[str] = getattr(settings, "resend_from", None)

        html = build_contact_email_html(email=email, subject=subject, message=message)

        await send_email(
            to=contact_to,
            subject=f"Nova mensagem recebida - {subject}",
            html_body=html,
        )

        await self.session.execute(
            AuditLog.__table__.insert().values(
                user_id=None,
                actor_ip_hash=ip_hash_from_request(request),
                action="contact.send",
                resource="/contact-us",
                success=True,
                details={"from": email, "subject": subject},
            )
        )
        await self.session.commit()
