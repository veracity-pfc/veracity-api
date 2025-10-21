from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.domain.pending_registration_model import PendingRegistration

class PendingRegistrationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_email(self, email: str) -> PendingRegistration | None:
        q = await self.session.execute(select(PendingRegistration).where(PendingRegistration.email == email.lower()))
        return q.scalar_one_or_none()
