from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.contact_request_model import ContactRequest
from app.domain.enums import ContactCategory, ContactStatus


class ContactRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, request: ContactRequest) -> ContactRequest:
        self.session.add(request)
        await self.session.flush()
        return request

    async def get(self, request_id: UUID) -> Optional[ContactRequest]:
        return await self.session.get(ContactRequest, request_id)

    async def paginated(
        self,
        *,
        page: int,
        page_size: int,
        status: Optional[ContactStatus] = None,
        category: Optional[ContactCategory] = None,
        email: Optional[str] = None,
    ) -> Tuple[int, List[ContactRequest]]:
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
        if page_size > 0:
            stmt = stmt.offset((page - 1) * page_size).limit(page_size)

        rows = (await self.session.execute(stmt)).scalars().all()
        return total, list(rows)

    async def count_by_user_and_category_status(
        self,
        user_id: UUID,
        category: ContactCategory,
        status: ContactStatus,
    ) -> int:
        stmt = select(func.count(ContactRequest.id)).where(
            ContactRequest.user_id == user_id,
            ContactRequest.category == category,
            ContactRequest.status == status,
        )
        return (await self.session.execute(stmt)).scalar() or 0

    async def count_recent_by_user_and_category(
        self,
        user_id: UUID,
        category: ContactCategory,
        since: datetime,
    ) -> int:
        stmt = select(func.count(ContactRequest.id)).where(
            ContactRequest.user_id == user_id,
            ContactRequest.category == category,
            ContactRequest.created_at >= since,
        )
        return (await self.session.execute(stmt)).scalar() or 0