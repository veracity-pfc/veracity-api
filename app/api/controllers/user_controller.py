from __future__ import annotations

import logging

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_session
from app.domain.user_model import User
from app.schemas.user import ReactivateAccountPayload
from app.services.api_token_service import ApiTokenService
from app.services.user_service import UserService

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/users", tags=["user"])


@router.get("/profile")
async def get_profile(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    return await service.get_user_profile(user)


@router.post("/api-token/reveal")
async def reveal_api_token(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    service = ApiTokenService(session)
    token_obj, token_value = await service.reveal_user_token(user_id=user.id)

    expires_str = None
    if token_obj.expires_at:
        if hasattr(token_obj.expires_at, "isoformat"):
            expires_str = token_obj.expires_at.isoformat()
        else:
            expires_str = str(token_obj.expires_at)

    return {
        "token": token_value,
        "expires_at": expires_str,
    }


@router.post("/api-token/revoke")
async def revoke_api_token(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    service = ApiTokenService(session)
    await service.revoke_active_token_for_user(user_id=user.id)
    return {"ok": True}


@router.patch("/profile/name")
async def update_name(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    new_name = (payload.get("name") or "").strip()
    service = UserService(session)
    try:
        updated_name = await service.update_name(user.id, new_name)
        return {"ok": True, "name": updated_name}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.patch("/profile/name", name="validate_name")
async def validate_name_only(
    payload: dict = Body(...),
    validate_only: bool = Query(False),
):
    if not validate_only:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found",
        )

    new_name = (payload.get("name") or "").strip()
    if len(new_name) < 3 or len(new_name) > 30:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nome deve ter entre 3 e 30 caracteres.",
        )
    return {"ok": True}


@router.post("/profile/email-change/request")
async def request_email_change(
    request: Request,
    payload: ReactivateAccountPayload,
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
    validate_only: bool = Query(False),
):
    new_email = (payload.email or "").strip().lower()
    service = UserService(session)
    try:
        if validate_only:
            await service.validate_email_change(str(user.id), new_email)
            return {"ok": True, "requires_verification": True}
        await service.request_email_change(str(user.id), new_email, request)
        return {"ok": True, "requires_verification": True}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.post("/profile/email-change/confirm")
async def confirm_email_change(
    request: Request,
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    code = (payload.get("code") or "").strip()
    service = UserService(session)
    try:
        new_email = await service.confirm_email_change(str(user.id), code, request)
        return {"ok": True, "email": new_email}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception:
        logger.exception("Erro inesperado em confirm_email_change")
        raise


@router.patch("/account")
async def inactivate_account(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    try:
        await service.inactivate_account(str(user.id))
        return {"ok": True, "status": "inactive"}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.delete("/account")
async def delete_account(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    try:
        await service.delete_account(str(user.id))
        return {"ok": True}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

@router.post("/reactivate-account/validate")
async def validate_reactivate_account(
    payload: ReactivateAccountPayload,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    try:
        await service.validate_reactivation_email(payload.email, request)
        return {"ok": True}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.post("/reactivate-account/send-code")
async def send_reactivate_code(
    payload: ReactivateAccountPayload,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    try:
        await service.request_reactivation_code(payload.email, request)
        return {"detail": "Código de reativação enviado com sucesso."}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.post("/reactivate-account/confirm-code")
async def confirm_reactivate_code(
    request: Request,
    payload: dict = Body(...),
    session: AsyncSession = Depends(get_session),
):
    email = (payload.get("email") or "").strip().lower()
    code = (payload.get("code") or "").strip()

    service = UserService(session)
    try:
        await service.confirm_reactivation_code(
            email,
            code,
            request,
        )
        return {"detail": "Conta reativada com sucesso."}
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
