from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.api_token_model import ApiToken
from app.domain.api_token_request_model import ApiTokenRequest
from app.domain.enums import ApiTokenRequestStatus, ApiTokenStatus
from app.domain.user_model import User


class ApiTokenRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def user_has_active_token(self, user_id: UUID) -> bool:
        stmt = select(func.count(ApiToken.id)).where(
            ApiToken.user_id == user_id,
            ApiToken.status == ApiTokenStatus.active,
        )
        res = await self.session.execute(stmt)
        return (res.scalar_one() or 0) > 0

    async def get_active_by_user(self, user_id: UUID) -> Optional[ApiToken]:
        stmt = select(ApiToken).where(
            ApiToken.user_id == user_id,
            ApiToken.status == ApiTokenStatus.active,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create(
        self,
        *,
        user_id: UUID,
        token_hash: str,
        token_prefix: str,
        expires_at: datetime,
        encrypted_token: str,
    ) -> ApiToken:
        token = ApiToken(
            user_id=user_id,
            token_hash=token_hash,
            token_prefix=token_prefix,
            expires_at=expires_at,
            encrypted_token=encrypted_token,
        )
        self.session.add(token)
        await self.session.flush()
        await self.session.refresh(token)
        return token

    async def get(self, token_id: UUID) -> Optional[ApiToken]:
        return await self.session.get(ApiToken, token_id)

    async def get_by_hash(self, token_hash: str) -> Optional[ApiToken]:
        stmt = select(ApiToken).where(ApiToken.token_hash == token_hash)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def mark_revealed(self, token: ApiToken, revealed_at: datetime) -> ApiToken:
        token.revealed_at = revealed_at
        self.session.add(token)
        await self.session.flush()
        return token

    async def revoke(
        self,
        token: ApiToken,
        reason: Optional[str],
        admin_id: Optional[UUID],
        now: datetime,
    ) -> ApiToken:
        token.status = ApiTokenStatus.revoked
        token.revoked_at = now
        token.revoked_reason = reason
        token.revoked_by_admin_id = admin_id
        self.session.add(token)
        await self.session.flush()
        return token

    async def get_expired_active_tokens(self, now: datetime) -> List[ApiToken]:
        stmt = select(ApiToken).where(
            ApiToken.status == ApiTokenStatus.active,
            ApiToken.expires_at < now,
        )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update(self, token: ApiToken) -> ApiToken:
        self.session.add(token)
        await self.session.flush()
        return token

    async def paginated(
        self,
        *,
        page: int,
        page_size: int,
        status: Optional[ApiTokenStatus],
        date_from: Optional[datetime],
        date_to: Optional[datetime],
        email: Optional[str],
    ) -> Tuple[int, List[ApiToken]]:
        conditions = []

        if status:
            conditions.append(ApiToken.status == status)
        if date_from:
            conditions.append(ApiToken.created_at >= date_from)
        if date_to:
            conditions.append(ApiToken.created_at < date_to)
        if email:
            conditions.append(func.lower(User.email).like(f"%{email.lower()}%"))

        count_stmt = (
            select(func.count(ApiToken.id))
            .select_from(ApiToken)
            .join(User, User.id == ApiToken.user_id)
        )
        if conditions:
            count_stmt = count_stmt.where(*conditions)

        res_count = await self.session.execute(count_stmt)
        total = res_count.scalar_one() or 0

        sort_expr = case(
            (ApiToken.status == ApiTokenStatus.active, 0),
            (ApiToken.status == ApiTokenStatus.expired, 1),
            (ApiToken.status == ApiTokenStatus.revoked, 2),
            else_=3,
        )

        stmt = select(ApiToken).join(User, User.id == ApiToken.user_id)
        if conditions:
            stmt = stmt.where(*conditions)

        stmt = (
            stmt.order_by(sort_expr, ApiToken.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )

        res_items = await self.session.execute(stmt)
        items = list(res_items.scalars().unique())
        return total, items


class ApiTokenRequestRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get(self, request_id: UUID) -> Optional[ApiTokenRequest]:
        return await self.session.get(ApiTokenRequest, request_id)

    async def get_open_by_user(self, user_id: UUID) -> Optional[ApiTokenRequest]:
        stmt = select(ApiTokenRequest).where(
            ApiTokenRequest.user_id == user_id,
            ApiTokenRequest.status == ApiTokenRequestStatus.open,
        )
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def create(
        self,
        *,
        user_id: UUID,
        email: str,
        message: str,
        status: ApiTokenRequestStatus = ApiTokenRequestStatus.open,
    ) -> ApiTokenRequest:
        req = ApiTokenRequest(
            user_id=user_id,
            email=email,
            message=message,
            status=status,
        )
        self.session.add(req)
        await self.session.flush()
        await self.session.refresh(req)
        return req

    async def paginated(
        self,
        *,
        page: int,
        page_size: int,
        status: Optional[ApiTokenRequestStatus],
        date_from: Optional[datetime],
        date_to: Optional[datetime],
        email: Optional[str],
    ) -> Tuple[int, List[ApiTokenRequest]]:
        conditions = []

        if status:
            conditions.append(ApiTokenRequest.status == status)
        if date_from:
            conditions.append(ApiTokenRequest.created_at >= date_from)
        if date_to:
            conditions.append(ApiTokenRequest.created_at < date_to)
        if email:
            conditions.append(
                func.lower(ApiTokenRequest.email).like(f"%{email.lower()}%")
            )

        count_stmt = select(func.count(ApiTokenRequest.id)).select_from(ApiTokenRequest)
        if conditions:
            count_stmt = count_stmt.where(*conditions)

        res_count = await self.session.execute(count_stmt)
        total = res_count.scalar_one() or 0

        sort_expr = case(
            (ApiTokenRequest.status == ApiTokenRequestStatus.open, 0),
            (ApiTokenRequest.status == ApiTokenRequestStatus.approved, 1),
            (ApiTokenRequest.status == ApiTokenRequestStatus.rejected, 2),
            else_=3,
        )

        stmt = select(ApiTokenRequest)
        if conditions:
            stmt = stmt.where(*conditions)

        stmt = (
            stmt.order_by(sort_expr, ApiTokenRequest.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )

        res_items = await self.session.execute(stmt)
        items = list(res_items.scalars().unique())
        return total, items