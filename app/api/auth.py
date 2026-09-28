from __future__ import annotations

import hashlib
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.dependencies import client_ip, get_current_user, get_db
from app.models import BrowserSession, User, utcnow
from app.schemas import LoginRequest, MessageResponse, RegisterRequest, UserResponse
from app.security import generate_csrf_token, generate_token, hash_password, hash_token, validate_password, verify_password

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.get("/csrf")
def issue_csrf(request: Request, response: Response) -> dict[str, str]:
    settings = request.app.state.settings
    raw_session = request.cookies.get(settings.session_cookie_name)
    binding = hash_token(raw_session, settings.session_secret) if raw_session else "anonymous"
    token = generate_csrf_token(settings.session_secret, binding)
    response.set_cookie(
        settings.csrf_cookie_name,
        token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
        max_age=settings.csrf_ttl_seconds,
    )
    return {"csrf_token": token}


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)) -> User:
    settings = request.app.state.settings
    if not request.app.state.rate_limiter.check(
        f"register:{client_ip(request)}", settings.register_rate_limit, settings.rate_limit_window_seconds
    ):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many requests")
    try:
        validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    email = str(payload.email).strip().lower()
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="unable to create account")
    user = User(email=email, password_hash=hash_password(payload.password))
    db.add(user)
    try:
        db.flush()
        record_audit(db, "REGISTER", actor_user_id=user.id)
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="unable to create account") from exc
    db.refresh(user)
    return user


@router.post("/login", response_model=UserResponse)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)) -> User:
    settings = request.app.state.settings
    email = str(payload.email).strip().lower()
    email_key = hashlib.sha256(email.encode()).hexdigest()[:16]
    key = f"login:{client_ip(request)}:{email_key}"
    if not request.app.state.rate_limiter.check(key, settings.login_rate_limit, settings.rate_limit_window_seconds):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many requests")
    user = db.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
    if not user or not verify_password(user.password_hash, payload.password):
        record_audit(db, "LOGIN_FAILURE", actor_user_id=user.id if user else None, details={"client": client_ip(request)})
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid email or password")
    raw_token = generate_token()
    now = utcnow()
    browser_session = BrowserSession(
        user_id=user.id,
        token_hash=hash_token(raw_token, settings.session_secret),
        created_at=now,
        expires_at=now + timedelta(seconds=settings.session_ttl_seconds),
        last_seen_at=now,
    )
    db.add(browser_session)
    record_audit(db, "LOGIN_SUCCESS", actor_user_id=user.id)
    db.commit()
    csrf_token = generate_csrf_token(settings.session_secret, browser_session.token_hash)
    response.set_cookie(
        settings.session_cookie_name,
        raw_token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
        max_age=settings.session_ttl_seconds,
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
        max_age=settings.csrf_ttl_seconds,
    )
    response.headers["X-CSRF-Token"] = csrf_token
    return user


@router.post("/logout", response_model=MessageResponse)
def logout(request: Request, response: Response, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    request.state.browser_session.revoked_at = utcnow()
    record_audit(db, "LOGOUT", actor_user_id=user.id)
    db.commit()
    settings = request.app.state.settings
    response.delete_cookie(settings.session_cookie_name, path="/")
    csrf_token = generate_csrf_token(settings.session_secret)
    response.set_cookie(
        settings.csrf_cookie_name,
        csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
        max_age=settings.csrf_ttl_seconds,
    )
    response.headers["X-CSRF-Token"] = csrf_token
    return {"message": "logged out"}


@router.get("/me", response_model=UserResponse)
def me(user: User = Depends(get_current_user)) -> User:
    return user
