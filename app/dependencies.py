from __future__ import annotations

from datetime import timedelta
from typing import Generator

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.models import BrowserSession, User, utcnow
from app.security import hash_token


def get_db(request: Request) -> Generator[Session, None, None]:
    db = request.app.state.SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    raw_token = request.cookies.get(request.app.state.settings.session_cookie_name)
    if not raw_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    token_hash = hash_token(raw_token, request.app.state.settings.session_secret)
    session = db.scalar(select(BrowserSession).where(BrowserSession.token_hash == token_hash))
    now = utcnow()
    if not session or session.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session")
    if session.expires_at <= now:
        session.revoked_at = now
        record_audit(db, "SESSION_EXPIRED", actor_user_id=session.user_id)
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session expired")
    user = db.scalar(select(User).where(User.id == session.user_id, User.is_active.is_(True)))
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid session")
    if session.last_seen_at <= now - timedelta(minutes=5):
        session.last_seen_at = now
        db.commit()
    request.state.browser_session = session
    return user


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
