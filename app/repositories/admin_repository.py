from __future__ import annotations

from datetime import date, datetime
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import (
    case,
    cast,
    desc,
    func,
    literal,
    select,
    String,
    text,
    union_all,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.api_token_model import ApiToken
from app.domain.api_token_request_model import ApiTokenRequest
from app.domain.contact_request_model import ContactRequest


class AdminRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def user_status_metrics(self, year: int, month: int) -> Dict[str, int]:
        start = date(year, month, 1)
        if month == 12:
            end = date(year + 1, 1, 1)
        else:
            end = date(year, month + 1, 1)

        query = text(
            """
            SELECT status, COUNT(*) AS total
            FROM users
            WHERE created_at < :end_date
            GROUP BY status
            """
        )

        result = await self._session.execute(query, {"end_date": end})
        rows = result.all()

        metrics = {"active": 0, "inactive": 0}
        for status, total in rows:
            if status in metrics:
                metrics[status] = int(total)

        return metrics

    async def token_metrics(self, year: int, month: int) -> Dict[str, int]:
        start_dt = datetime(year, month, 1)
        if month == 12:
            end_dt = datetime(year + 1, 1, 1)
        else:
            end_dt = datetime(year, month + 1, 1)

        stmt = (
            select(ApiToken.status, func.count(ApiToken.id))
            .where(ApiToken.created_at >= start_dt, ApiToken.created_at < end_dt)
            .group_by(ApiToken.status)
        )
        
        result = await self._session.execute(stmt)
        rows = result.all()
        
        data = {"active": 0, "expired": 0, "revoked": 0}
        for status_enum, count in rows:
            val = status_enum.value if hasattr(status_enum, "value") else str(status_enum)
            if val in data:
                data[val] = int(count)
        
        return data

    async def request_metrics(self, year: int, month: int) -> Dict[str, int]:
        start_dt = datetime(year, month, 1)
        if month == 12:
            end_dt = datetime(year + 1, 1, 1)
        else:
            end_dt = datetime(year, month + 1, 1)

        stmt_contacts = (
            select(ContactRequest.category, func.count(ContactRequest.id))
            .where(ContactRequest.created_at >= start_dt, ContactRequest.created_at < end_dt)
            .group_by(ContactRequest.category)
        )
        res_contacts = await self._session.execute(stmt_contacts)
        
        stmt_tokens = (
            select(func.count(ApiTokenRequest.id))
            .where(ApiTokenRequest.created_at >= start_dt, ApiTokenRequest.created_at < end_dt)
        )
        res_tokens = await self._session.execute(stmt_tokens)
        token_count = res_tokens.scalar() or 0

        data = {
            "doubt": 0,
            "suggestion": 0,
            "complaint": 0,
            "token_request": int(token_count)
        }

        for category_enum, count in res_contacts.all():
            val = category_enum.value if hasattr(category_enum, "value") else str(category_enum)
            if val in data:
                data[val] = int(count)
        
        return data

    async def list_unified_requests(
        self,
        *,
        page: int,
        page_size: int,
        status: Optional[str] = None,
        category: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Tuple[int, List[dict]]:
        
        q_contacts = select(
            ContactRequest.id,
            ContactRequest.seq_id,
            ContactRequest.email,
            cast(ContactRequest.category, String).label("category"),
            ContactRequest.subject,
            ContactRequest.message,
            cast(ContactRequest.status, String).label("status"),
            ContactRequest.created_at,
            literal("contact").label("type"),
        )

        q_tokens = select(
            ApiTokenRequest.id,
            ApiTokenRequest.seq_id, 
            ApiTokenRequest.email,
            literal("api_token").label("category"),
            literal("Solicitação de Token de API").label("subject"),
            ApiTokenRequest.message,
            cast(ApiTokenRequest.status, String).label("status"),
            ApiTokenRequest.created_at,
            literal("token").label("type"),
        )

        if status:
            q_contacts = q_contacts.where(cast(ContactRequest.status, String) == status)
            q_tokens = q_tokens.where(cast(ApiTokenRequest.status, String) == status)
        
        if email:
            term = f"%{email.lower()}%"
            q_contacts = q_contacts.where(func.lower(ContactRequest.email).like(term))
            q_tokens = q_tokens.where(func.lower(ApiTokenRequest.email).like(term))

        if category:
            if category == "api_token":
                q_contacts = q_contacts.where(literal(False))
            else:
                q_contacts = q_contacts.where(cast(ContactRequest.category, String) == category)
                q_tokens = q_tokens.where(literal(False))

        union_q = union_all(q_contacts, q_tokens)
        
        count_stmt = select(func.count()).select_from(union_q.subquery())
        total = (await self._session.execute(count_stmt)).scalar() or 0

        subq = union_q.subquery()

        status_priority = case(
            (subq.c.status == 'open', 0),
            else_=1
        )

        final_stmt = (
            select(subq)
            .order_by(status_priority, subq.c.created_at.desc())
            .limit(page_size)
            .offset((page - 1) * page_size)
        )

        result = await self._session.execute(final_stmt)
        rows = result.mappings().all()
        
        return total, [dict(row) for row in rows]

    async def get_unified_detail(self, request_id: UUID) -> Optional[dict]:
        contact = await self._session.get(ContactRequest, request_id)
        if contact:
            return {
                "id": contact.id,
                "seq_id": contact.seq_id,
                "type": "contact",
                "email": contact.email,
                "category": contact.category,
                "subject": contact.subject,
                "message": contact.message,
                "status": contact.status,
                "created_at": contact.created_at,
                "admin_reply": contact.admin_reply,
                "replied_at": contact.replied_at,
            }

        token_req = await self._session.get(ApiTokenRequest, request_id)
        if token_req:
            return {
                "id": token_req.id,
                "seq_id": token_req.seq_id,
                "type": "token",
                "email": token_req.email,
                "category": "Solicitação de token de API",
                "subject": "Solicitação de token de API",
                "message": token_req.message,
                "status": token_req.status,
                "created_at": token_req.created_at,
                "admin_reply": token_req.rejection_reason,
                "replied_at": token_req.decided_at,
            }

        return None