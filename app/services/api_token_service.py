from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import List, Optional, Tuple
from uuid import UUID

from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import ip_hash_from_request
from app.core.config import settings
from app.core.constants import TOKEN_PREFIX, DEFAULT_TOKEN_TTL_DAYS
from app.domain.api_token_model import ApiToken
from app.domain.api_token_request_model import ApiTokenRequest
from app.domain.audit_model import AuditLog
from app.domain.enums import ApiTokenRequestStatus, ApiTokenStatus
from app.repositories.api_token_repository import (
    ApiTokenRepository,
    ApiTokenRequestRepository,
)
from app.repositories.audit_repository import AuditRepository
from app.services.email_service import (
    EmailError,
    build_api_token_approved_email_html,
    build_api_token_rejected_email_html,
    build_api_token_revoked_email_html,
    build_api_token_expired_email_html,
    send_email,
)
from app.services.history_service import normalize_date_range


class ApiTokenService:
    def __init__(self, session: AsyncSession):
        self.session = session
        self.tokens = ApiTokenRepository(session)
        self.requests = ApiTokenRequestRepository(session)
        self.audit = AuditRepository(session)
        self._fernet = self._build_fernet()

    def _build_fernet(self) -> Fernet:
        secret = settings.jwt_secret.encode("utf-8")
        key = hashlib.sha256(secret).digest()
        return Fernet(base64.urlsafe_b64encode(key))

    def _encrypt_token(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("utf-8")

    def _decrypt_token(self, value: str) -> str:
        return self._fernet.decrypt(value.encode("utf-8")).decode("utf-8")

    async def get_token_details(self, token_id: UUID) -> Optional[dict]:
        stmt = (
            select(ApiToken)
            .options(selectinload(ApiToken.user))
            .where(ApiToken.id == token_id)
        )
        result = await self.session.execute(stmt)
        token = result.scalar_one_or_none()

        if not token:
            return None

        return {
            "id": str(token.id),
            "created_at": token.created_at,
            "status": token.status,
            "token_prefix": token.token_prefix,
            "expires_at": token.expires_at,
            "last_used_at": token.last_used_at,
            "revoked_at": token.revoked_at,
            "revoked_reason": token.revoked_reason,
            "user_email": token.user.email if token.user else None,
            "analysis_type": "token",
        }

    async def create_token_request_from_contact(
        self,
        *,
        user_id: UUID,
        email: str,
        message: str,
        request_obj,
    ) -> ApiTokenRequest:
        existing_open = await self.requests.get_open_by_user(user_id)
        if existing_open:
            raise ValueError("Você já possui uma solicitação de token em aberto. Aguarde a análise.")

        has_active = await self.tokens.user_has_active_token(user_id)
        if has_active:
            raise ValueError("Você já possui um token de API ativo. É necessário revogá-lo antes de solicitar um novo.")

        req = await self.requests.create(
            user_id=user_id,
            email=email,
            message=message,
            status=ApiTokenRequestStatus.open,
        )

        await self.audit.insert(
            table=AuditLog,
            user_id=user_id,
            actor_ip_hash=ip_hash_from_request(request_obj),
            action="api_token_request.create",
            resource="/v1/contact-us",
            success=True,
            details={"request_id": str(req.id), "email": email},
        )
        await self.session.commit()
        return req

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
    ):
        req = await self.requests.get(request_id)
        if not req:
            raise ValueError("Solicitação não encontrada.")
        if req.status != ApiTokenRequestStatus.open:
            raise ValueError("A solicitação já foi processada.")
        
        has_active = await self.tokens.user_has_active_token(req.user_id)
        if has_active:
            raise ValueError("O usuário já possui um token ativo.")
        
        plain, token = await self._generate_token(req.user_id)
        now = datetime.now(timezone.utc)
        req.status = ApiTokenRequestStatus.approved
        req.decided_at = now
        req.decided_by_admin_id = admin_id
        req.related_token_id = token.id
        
        await self.session.commit()
        await self.session.refresh(req)
        
        try:
            html = build_api_token_approved_email_html(token.expires_at)
            await send_email(req.email, "Token de API gerado com sucesso", html)
        except EmailError:
            pass

        await self.audit.insert(
            table=AuditLog,
            user_id=req.user_id,
            actor_ip_hash=None,
            action="api_token_request.approve",
            resource=f"/administration/api/token-requests/{req.id}",
            success=True,
            details={"token_id": str(token.id)},
        )
        await self.session.commit()
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

        email_sent = False
        try:
            html = build_api_token_rejected_email_html(reason=reason)
            await send_email(
                to=req.email,
                subject="Solicitação de token de API rejeitada",
                html_body=html,
            )
            email_sent = True
        except EmailError:
            email_sent = False

        await self.audit.insert(
            table=AuditLog,
            user_id=req.user_id,
            actor_ip_hash=None,
            action="api_token_request.reject",
            resource=f"/administration/api/token-requests/{req.id}",
            success=True,
            details={"request_id": str(req.id), "email_sent": email_sent},
        )
        await self.session.commit()

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
        await self.tokens.revoke(token, reason=reason, admin_id=admin_id, now=now)
        await self.session.commit()
        await self.session.refresh(token)

        try:
            html = build_api_token_revoked_email_html(token.expires_at, reason or "")
            await send_email(
                to=token.user.email,
                subject="Seu token de API foi revogado",
                html_body=html,
            )
        except EmailError:
            pass

        await self.audit.insert(
            table=AuditLog,
            user_id=token.user_id,
            actor_ip_hash=None,
            action="api_token.revoke_admin",
            resource=f"/administration/api/tokens/{token.id}/revoke",
            success=True,
            details={"reason": reason or "", "admin_id": str(admin_id)},
        )
        await self.session.commit()

        return token

    async def revoke_active_token_for_user(self, *, user_id: UUID) -> ApiToken:
        token = await self.tokens.get_active_by_user(user_id)
        if not token:
            raise ValueError("Nenhum token ativo para revogar.")

        now = datetime.now(timezone.utc)
        await self.tokens.revoke(token, reason="Revogado pelo usuário", admin_id=None, now=now)
        await self.session.commit()

        await self.audit.insert(
            table=AuditLog,
            user_id=user_id,
            actor_ip_hash=None,
            action="api_token.revoke_user",
            resource=f"/user/api-token/{token.id}/revoke",
            success=True,
            details={"reason": "Revogado pelo usuário"},
        )
        await self.session.commit()
        return token

    async def revoke_token_by_user(
        self,
        *,
        user_id: UUID,
        token_id: UUID,
        reason: Optional[str],
    ) -> ApiToken:
        token = await self.tokens.get(token_id)
        if not token or token.user_id != user_id or token.status != ApiTokenStatus.active:
            raise ValueError("Token não encontrado ou inválido.")

        now = datetime.now(timezone.utc)
        await self.tokens.revoke(token, reason=reason, admin_id=None, now=now)
        await self.session.commit()
        await self.session.refresh(token)

        await self.audit.insert(
            table=AuditLog,
            user_id=user_id,
            actor_ip_hash=None,
            action="api_token.revoke_user",
            resource=f"/user/api-token/{token.id}/revoke",
            success=True,
            details={"reason": reason or ""},
        )
        await self.session.commit()
        return token

    async def reveal_user_token(self, *, user_id: UUID) -> Tuple[ApiToken, str]:
        token = await self.tokens.get_active_by_user(user_id)
        if not token:
            raise ValueError("Nenhum token ativo encontrado.")

        now = datetime.now(timezone.utc)
        if token.expires_at < now:
            token.status = ApiTokenStatus.expired
            await self.session.commit()
            raise ValueError("Token expirado.")

        if token.revealed_at is not None or not token.encrypted_token:
            raise ValueError("Este token já foi revelado. Gere um novo.")

        plain = self._decrypt_token(token.encrypted_token)
        await self.tokens.mark_revealed(token, revealed_at=now)
        await self.session.commit()
        await self.session.refresh(token)

        await self.audit.insert(
            table=AuditLog,
            user_id=user_id,
            actor_ip_hash=None,
            action="api_token.reveal",
            resource="/user/api-token/reveal",
            success=True,
            details={"token_id": str(token.id)},
        )
        await self.session.commit()

        return token, plain

    async def expire_overdue_tokens(self) -> int:
        now = datetime.now(timezone.utc)
        tokens = await self.tokens.get_expired_active_tokens(now)
        
        if not tokens:
            return 0

        for token in tokens:
            token.status = ApiTokenStatus.expired
            try:
                html = build_api_token_expired_email_html(token.expires_at)
                await send_email(
                    to=token.user.email,
                    subject="Seu token de API expirou",
                    html_body=html,
                )
            except EmailError:
                pass
            
            await self.audit.insert(
                table=AuditLog,
                user_id=token.user_id,
                actor_ip_hash=None,
                action="api_token.expire",
                resource="/administration/api/tokens/expire",
                success=True,
                details={"token_id": str(token.id)},
            )

        await self.session.commit()
        return len(tokens)

    async def _generate_token(self, user_id: UUID) -> Tuple[str, ApiToken]:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=DEFAULT_TOKEN_TTL_DAYS)
        plain = f"{TOKEN_PREFIX}-{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(plain.encode("utf-8")).hexdigest()
        token_prefix = plain[:16]
        encrypted = self._encrypt_token(plain)
        
        token = await self.tokens.create(
            user_id=user_id,
            token_hash=token_hash,
            token_prefix=token_prefix,
            expires_at=expires_at,
            encrypted_token=encrypted,
        )
        return plain, token

    async def validate_token(self, token_plain: str) -> ApiToken:
        h = hashlib.sha256(token_plain.encode("utf-8")).hexdigest()
        token = await self.tokens.get_by_hash(h)
        if not token or token.status != ApiTokenStatus.active:
            raise ValueError("Token inválido.")
        
        if token.expires_at < datetime.now(timezone.utc):
            token.status = ApiTokenStatus.expired
            await self.session.commit()
            raise ValueError("Token expirado.")

        token.last_used_at = datetime.now(timezone.utc)
        await self.session.commit()

        return token