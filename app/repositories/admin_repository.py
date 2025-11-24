from __future__ import annotations

from datetime import date, datetime
from typing import Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import (
    case,
    cast,
    func,
    literal,
    select,
    String,
    text,
    union_all,
    or_,
)
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.api_token_model import ApiToken
from app.domain.api_token_request_model import ApiTokenRequest
from app.domain.contact_request_model import ContactRequest
from app.domain.user_model import User
from app.domain.enums import ContactStatus, ApiTokenRequestStatus


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
        
        q_contacts = (
            select(
                ContactRequest.id,
                ContactRequest.seq_id,
                ContactRequest.email,
                cast(ContactRequest.category, String).label("category"),
                ContactRequest.subject,
                ContactRequest.message,
                cast(ContactRequest.status, String).label("status"),
                ContactRequest.created_at,
                literal("contact").label("type"),
                User.email.label("user_email"),
            )
            .join(User, ContactRequest.user_id == User.id, isouter=True)
        )

        q_tokens = (
            select(
                ApiTokenRequest.id,
                ApiTokenRequest.seq_id,
                ApiTokenRequest.email,
                literal("Solicitação de token de API").label("category"),
                literal("Solicitação de Token de API").label("subject"),
                ApiTokenRequest.message,
                cast(ApiTokenRequest.status, String).label("status"),
                ApiTokenRequest.created_at,
                literal("token").label("type"),
                User.email.label("user_email"),
            )
            .join(User, ApiTokenRequest.user_id == User.id, isouter=True)
        )

        if status:
            q_contacts = q_contacts.where(cast(ContactRequest.status, String) == status)
            q_tokens = q_tokens.where(cast(ApiTokenRequest.status, String) == status)
        
        if email:
            term = f"%{email.lower()}%"
            q_contacts = q_contacts.where(
                or_(
                    func.lower(ContactRequest.email).like(term),
                    func.lower(User.email).like(term),
                )
            )
            q_tokens = q_tokens.where(
                or_(
                    func.lower(ApiTokenRequest.email).like(term),
                    func.lower(User.email).like(term),
                )
            )

        if category:
            if category == "Solicitação de token de API":
                q_contacts = q_contacts.where(literal(False))
            else:
                q_contacts = q_contacts.where(cast(ContactRequest.category, String) == category)
                q_tokens = q_tokens.where(literal(False))

        union_q = union_all(q_contacts, q_tokens)
        
        count_stmt = select(func.count()).select_from(union_q.subquery())
        total = (await self._session.execute(count_stmt)).scalar() or 0

        subq = union_q.subquery()

        status_priority = case(
            (subq.c.status == "open", 0),
            else_=1,
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
            status_value = contact.status
            status_str = status_value.value if hasattr(status_value, "value") else str(status_value)
            user_email = contact.user.email if contact.user else None
            return {
                "id": contact.id,
                "seq_id": contact.seq_id,
                "type": "contact",
                "email": contact.email,
                "user_email": user_email,
                "category": contact.category,
                "subject": contact.subject,
                "message": contact.message,
                "status": status_str,
                "created_at": contact.created_at,
                "admin_reply": contact.admin_reply,
                "replied_at": contact.replied_at,
            }

        token_req = await self._session.get(ApiTokenRequest, request_id)
        if token_req:
            status_value = token_req.status
            status_str = status_value.value if hasattr(status_value, "value") else str(status_value)
            user_email = token_req.user.email if token_req.user else None
            return {
                "id": token_req.id,
                "seq_id": token_req.seq_id,
                "type": "token",
                "email": token_req.email,
                "user_email": user_email,
                "category": "Solicitação de token de API",
                "subject": "Solicitação de token de API",
                "message": token_req.message,
                "status": status_str,
                "created_at": token_req.created_at,
                "admin_reply": token_req.rejection_reason,
                "replied_at": token_req.decided_at,
            }

        return None

    async def close_contact_request_for_deleted_user(
        self,
        request_id: UUID,
        closed_at: datetime,
    ) -> bool:
        contact = await self._session.get(ContactRequest, request_id)
        if not contact:
            return False
        user = contact.user
        email = user.email if user else None
        if not email or "deleted.local" not in email:
            return False
        if contact.status != ContactStatus.open:
            return False
        contact.status = ContactStatus.finished
        contact.admin_reply = "Solicitação encerrada pois a conta do usuário foi excluída."
        contact.replied_at = closed_at
        contact.replied_by_admin_id = None
        await self._session.flush()
        return True

    async def close_token_request_for_deleted_user(
        self,
        request_id: UUID,
        closed_at: datetime,
    ) -> bool:
        token_req = await self._session.get(ApiTokenRequest, request_id)
        if not token_req:
            return False
        user = token_req.user
        email = user.email if user else None
        if not email or "deleted.local" not in email:
            return False
        if token_req.status != ApiTokenRequestStatus.open:
            return False
        token_req.status = ApiTokenRequestStatus.rejected
        token_req.rejection_reason = "Solicitação encerrada pois a conta do usuário foi excluída."
        token_req.decided_at = closed_at
        token_req.decided_by_admin_id = None
        await self._session.flush()
        return True
