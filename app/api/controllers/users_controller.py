from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.database import get_session
from app.domain.user_model import User
from app.schemas.user import ReactivateAccountPayload, ReactivateConfirmPayload
from app.services.api_token_service import ApiTokenService
from app.services.user_service import UserService

router = APIRouter(prefix="/v1/user", tags=["user"])


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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.patch("/profile/name", name="validate_name")
async def validate_name_only(
    payload: dict = Body(...),
    validate_only: bool = Query(False),
):
    if not validate_only:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    new_name = (payload.get("name") or "").strip()
    if len(new_name) < 3 or len(new_name) > 30:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Nome deve ter entre 3 e 30 caracteres.",
        )
    return {"ok": True}


@router.post("/profile/email-change/request")
async def request_email_change(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    new_email = (payload.get("email") or "").strip().lower()
    service = UserService(session)
    try:
        await service.request_email_change(user.id, new_email)
        return {"ok": True, "requires_verification": True}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/profile/email-change/confirm")
async def confirm_email_change(
    payload: dict = Body(...),
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    code = (payload.get("code") or "").strip()
    email = (payload.get("email") or "").strip().lower()
    service = UserService(session)
    try:
        new_email = await service.confirm_email_change(user.id, email, code)
        return {"ok": True, "email": new_email}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.patch("/account")
async def inactivate_account(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    await service.inactivate_account(user.id)
    return {"ok": True, "status": "inactive"}


@router.delete("/account")
async def delete_account(
    user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    await service.delete_account(user.id)
    return {"ok": True}


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
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/reactivate-account/send-code")
async def send_reactivate_code(
    payload: ReactivateAccountPayload,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    try:
        await service.send_reactivation_code_flow(payload.email, request)
        return {"detail": "Código de reativação enviado com sucesso."}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post("/reactivate-account/confirm-code")
async def confirm_reactivate_code(
    payload: ReactivateConfirmPayload,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    service = UserService(session)
    try:
        await service.confirm_reactivation_code_flow(
            payload.email,
            payload.code,
            request,
        )
        return {"detail": "Conta reativada com sucesso."}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))