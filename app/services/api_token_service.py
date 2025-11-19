from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.api_token_model import ApiToken
from app.domain.api_token_request_model import ApiTokenRequest
from app.domain.enums import ApiTokenRequestStatus, ApiTokenStatus
from app.repositories.api_token_repository import (
    ApiTokenRepository,
    ApiTokenRequestRepository,
)
from app.services.history_service import normalize_date_range


DEFAULT_TOKEN_TTL_DAYS = 90


class ApiTokenService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.tokens = ApiTokenRepository(session)
        self.requests = ApiTokenRequestRepository(session)

    async def list_requests(
        self,
        *,
        page: int,
        page_size: int,
        status: Optional[ApiTokenRequestStatus],
        date_from: Optional[datetime],
        date_to: Optional[datetime],
        email: Optional[str],
    ) -> Tuple[int, int, List[ApiTokenRequest]]:
        start, end = normalize_date_range(date_from, date_to)
        total, rows = await self.requests.paginated(
            page=page,
            page_size=page_size,
            status=status,
            date_from=start,
            date_to=end,
            email=email,
        )
        total_pages = ceil(total / page_size) if page_size else 1
        return total, total_pages, rows

    async def get_request(self, request_id: UUID) -> Optional[ApiTokenRequest]:
        return await self.requests.get(request_id)

    async def list_tokens(
        self,
        *,
        page: int,
        page_size: int,
        status: Optional[ApiTokenStatus],
        date_from: Optional[datetime],
        date_to: Optional[datetime],
        email: Optional[str],
    ) -> Tuple[int, int, List[ApiToken]]:
        start, end = normalize_date_range(date_from, date_to)
        total, rows = await self.tokens.paginated(
            page=page,
            page_size=page_size,
            status=status,
            date_from=start,
            date_to=end,
            email=email,
        )
        total_pages = ceil(total / page_size) if page_size else 1
        return total, total_pages, rows

    async def approve_request(
        self,
        *,
        request_id: UUID,
        admin_id: UUID,
    ) -> Tuple[ApiTokenRequest, ApiToken, str]:
        req = await self.requests.get(request_id)
        if not req:
            raise ValueError("Solicitação não encontrada.")
        if req.status != ApiTokenRequestStatus.open:
            raise ValueError("A solicitação já foi processada.")

        has_active = await self.tokens.user_has_active_token(req.user_id)
        if has_active:
            raise ValueError("O usuário já possui um token ativo.")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=DEFAULT_TOKEN_TTL_DAYS)

        plain = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(plain.encode("utf-8")).hexdigest()
        token_prefix = plain[:16]

        token = await self.tokens.create(
            user_id=req.user_id,
            token_hash=token_hash,
            token_prefix=token_prefix,
            expires_at=expires_at,
        )

        req.status = ApiTokenRequestStatus.approved
        req.decided_at = now
        req.decided_by_admin_id = admin_id
        req.related_token_id = token.id

        await self.session.commit()
        await self.session.refresh(req)
        await self.session.refresh(token)

        return req, token, plain

    async def reject_request(
        self,
        *,
        request_id: UUID,
        admin_id: UUID,
        reason: str,
    ) -> ApiTokenRequest:
        req = await self.requests.get(request_id)
        if not req:
            raise ValueError("Solicitação não encontrada.")
        if req.status != ApiTokenRequestStatus.open:
            raise ValueError("A solicitação já foi processada.")

        now = datetime.now(timezone.utc)

        req.status = ApiTokenRequestStatus.rejected
        req.decided_at = now
        req.decided_by_admin_id = admin_id
        req.rejection_reason = reason

        await self.session.commit()
        await self.session.refresh(req)
        return req

    async def revoke_token(
        self,
        *,
        token_id: UUID,
        admin_id: UUID,
        reason: Optional[str],
    ) -> ApiToken:
        token = await self.tokens.get(token_id)
        if not token:
            raise ValueError("Token não encontrado.")

        now = datetime.now(timezone.utc)

        await self.tokens.revoke(
            token,
            reason=reason,
            admin_id=admin_id,
            now=now,
        )

        await self.session.commit()
        await self.session.refresh(token)
        return token
