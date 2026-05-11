from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.core.security import create_access_token, create_refresh_token, decode_token, get_password_hash, verify_password
from app.db.database import get_db
from app.db.models import RefreshToken, Role, User
from app.schemas.auth import LoginRequest, RefreshRequest, RegisterRequest, TokenResponse, UserOut
from app.schemas.common import MessageResponse
from app.services.audit import write_audit_log
from app.services.password_policy import validate_password_policy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_tokens_for_user(user: User, db: Session) -> TokenResponse:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.add(user)
    db.commit()

    access_token = create_access_token(user_id=user.id, role=user.role.value)
    refresh_token, jti, refresh_expires_at = create_refresh_token(user.id)

    token_record = RefreshToken(user_id=user.id, jti=jti, expires_at=refresh_expires_at)
    db.add(token_record)
    db.commit()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


def _authenticate_user(username: str, password: str, request: Request, db: Session) -> User:
    user = db.scalar(select(User).where(User.username == username))

    now = datetime.now(timezone.utc)
    if user and user.locked_until and user.locked_until > now:
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account temporarily locked")

    if not user or not verify_password(password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.max_login_attempts:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
            db.add(user)
            db.commit()

        write_audit_log(
            db=db,
            action="LOGIN_FAILED",
            entity_type="User",
            entity_id=user.id if user else None,
            user_id=user.id if user else None,
            details={"username": username},
            request=request,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    return user


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> UserOut:
    # FIXED (CWE-521): Validate password policy
    validate_password_policy(payload.password)

    user_exists = db.scalar(
        select(User.id).where(or_(User.username == payload.username, User.email == payload.email))
    )
    if user_exists:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists")

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
        role=Role.ENGINEER,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    write_audit_log(
        db=db,
        action="REGISTER",
        entity_type="User",
        entity_id=user.id,
        user_id=user.id,
        details={"role": user.role.value},
        request=request,
    )

    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    user = _authenticate_user(payload.username, payload.password, request, db)
    tokens = _issue_tokens_for_user(user, db)

    write_audit_log(
        db=db,
        action="LOGIN_SUCCESS",
        entity_type="User",
        entity_id=user.id,
        user_id=user.id,
        details={"role": user.role.value},
        request=request,
    )

    return tokens


@router.post("/token", response_model=TokenResponse)
def oauth2_token_login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenResponse:
    user = _authenticate_user(form_data.username, form_data.password, request, db)
    tokens = _issue_tokens_for_user(user, db)

    write_audit_log(
        db=db,
        action="LOGIN_SUCCESS",
        entity_type="User",
        entity_id=user.id,
        user_id=user.id,
        details={"role": user.role.value, "via": "oauth2_password_flow"},
        request=request,
    )

    return tokens


@router.post("/refresh", response_model=TokenResponse)
def refresh_tokens(payload: RefreshRequest, db: Session = Depends(get_db)) -> TokenResponse:
    try:
        token_payload = decode_token(payload.refresh_token, expected_type="refresh")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized") from exc

    user_id = token_payload["sub"]
    jti = token_payload.get("jti")
    if not jti:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # FIXED (CWE-613): Enhance refresh token validation
    # Check token record exists, is not revoked, and hasn't expired
    token_record = db.scalar(select(RefreshToken).where(RefreshToken.jti == jti, RefreshToken.user_id == user_id))
    now = datetime.now(timezone.utc)
    
    if not token_record:
        logger.warning("Refresh token not found in database for user %s", user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    if token_record.revoked:
        logger.warning("Attempted refresh with revoked token for user %s (possible token reuse attack)", user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")
    
    if token_record.expires_at <= now:
        logger.warning("Refresh token expired for user %s", user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # Verify user still exists and is active
    user = db.get(User, user_id)
    if not user or not user.is_active:
        logger.warning("User %s inactive or deleted during token refresh", user_id)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    # Revoke old token before issuing new ones (atomic in single transaction)
    token_record.revoked = True
    new_access = create_access_token(user_id=user.id, role=user.role.value)
    new_refresh, new_jti, new_expires_at = create_refresh_token(user.id)

    db.add(RefreshToken(user_id=user.id, jti=new_jti, expires_at=new_expires_at))
    db.commit()

    write_audit_log(
        db=db,
        action="TOKEN_REFRESH",
        entity_type="User",
        entity_id=user.id,
        user_id=user.id,
        details={"old_jti": jti[:8] + "..."},  # Log token hint for audit, not full token
        request=None,
    )

    return TokenResponse(
        access_token=new_access,
        refresh_token=new_refresh,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    payload: RefreshRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> MessageResponse:
    try:
        token_payload = decode_token(payload.refresh_token, expected_type="refresh")
        if token_payload.get("sub") == current_user.id and token_payload.get("jti"):
            token_record = db.scalar(select(RefreshToken).where(RefreshToken.jti == token_payload["jti"]))
            if token_record and not token_record.revoked:
                token_record.revoked = True
                db.commit()
    except ValueError:
        # ИСПРАВЛЕНО (CWE-390): вместо pass логируем предупреждение — сессия могла не быть аннулирована
        logger.warning("Could not revoke refresh session during logout for user %s", current_user.id)

    write_audit_log(
        db=db,
        action="LOGOUT",
        entity_type="User",
        entity_id=current_user.id,
        user_id=current_user.id,
        details=None,
        request=request,
    )
    return MessageResponse(detail="Logged out")
