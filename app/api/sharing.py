from __future__ import annotations

from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.authorization import get_owned_document
from app.dependencies import client_ip, get_current_user, get_db
from app.models import Document, DocumentShare, ShareLink, User, utcnow
from app.schemas import (
    DocumentResponse,
    LinkCreateRequest,
    LinkResponse,
    MessageResponse,
    NewLinkResponse,
    ShareCreateRequest,
    ShareResponse,
)
from app.security import generate_token, hash_token

router = APIRouter(tags=["sharing"])


def share_response(share: DocumentShare) -> ShareResponse:
    return ShareResponse(
        id=share.id,
        document_id=share.document_id,
        shared_with_user_id=share.shared_with_user_id,
        shared_with_email=share.recipient.email,
        created_at=share.created_at,
        revoked_at=share.revoked_at,
    )


def link_response(link: ShareLink) -> LinkResponse:
    return LinkResponse(
        id=link.id, document_id=link.document_id, created_at=link.created_at, expires_at=link.expires_at, revoked_at=link.revoked_at
    )


@router.post("/documents/{document_id}/shares", response_model=ShareResponse, status_code=status.HTTP_201_CREATED)
def create_share(
    document_id: int, payload: ShareCreateRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> ShareResponse:
    get_owned_document(db, document_id, user, "create_share")
    recipient = db.scalar(select(User).where(User.email == str(payload.email).lower(), User.is_active.is_(True)))
    if not recipient:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="recipient not found")
    if recipient.id == user.id:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="owner already has access")
    share = db.scalar(
        select(DocumentShare).where(DocumentShare.document_id == document_id, DocumentShare.shared_with_user_id == recipient.id)
    )
    if share and share.revoked_at is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="active share already exists")
    if share:
        share.revoked_at = None
        share.created_at = utcnow()
    else:
        share = DocumentShare(document_id=document_id, shared_with_user_id=recipient.id)
        db.add(share)
    db.flush()
    record_audit(db, "SHARE_CREATED", actor_user_id=user.id, document_id=document_id, target_user_id=recipient.id)
    db.commit()
    db.refresh(share)
    return share_response(share)


@router.get("/documents/{document_id}/shares", response_model=list[ShareResponse])
def list_shares(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[ShareResponse]:
    get_owned_document(db, document_id, user, "list_shares")
    shares = db.scalars(
        select(DocumentShare).where(DocumentShare.document_id == document_id).order_by(DocumentShare.created_at.desc())
    ).all()
    return [share_response(share) for share in shares]


@router.delete("/documents/{document_id}/shares/{share_id}", response_model=MessageResponse)
def revoke_share(document_id: int, share_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    get_owned_document(db, document_id, user, "revoke_share")
    share = db.scalar(select(DocumentShare).where(DocumentShare.id == share_id, DocumentShare.document_id == document_id))
    if not share:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="share not found")
    if share.revoked_at is None:
        share.revoked_at = utcnow()
        record_audit(db, "SHARE_REVOKED", actor_user_id=user.id, document_id=document_id, target_user_id=share.shared_with_user_id)
        db.commit()
    return {"message": "share revoked"}


@router.get("/shared-with-me", response_model=list[DocumentResponse])
def shared_with_me(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[DocumentResponse]:
    documents = db.scalars(
        select(Document)
        .join(DocumentShare)
        .where(
            DocumentShare.shared_with_user_id == user.id,
            DocumentShare.revoked_at.is_(None),
        )
        .order_by(Document.created_at.desc())
    ).all()
    return [
        DocumentResponse(
            id=d.id,
            owner_id=d.owner_id,
            original_filename=d.original_filename,
            content_type=d.content_type,
            file_size=d.file_size,
            created_at=d.created_at,
            access="shared",
        )
        for d in documents
    ]


@router.post("/documents/{document_id}/links", response_model=NewLinkResponse, status_code=status.HTTP_201_CREATED)
def create_link(
    document_id: int, payload: LinkCreateRequest, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> NewLinkResponse:
    get_owned_document(db, document_id, user, "create_link")
    raw_token = generate_token()
    expires_at = utcnow() + timedelta(seconds=payload.expires_in_seconds) if payload.expires_in_seconds else None
    link = ShareLink(
        document_id=document_id, token_hash=hash_token(raw_token, request.app.state.settings.session_secret), expires_at=expires_at
    )
    db.add(link)
    db.flush()
    record_audit(
        db,
        "SHARE_LINK_CREATED",
        actor_user_id=user.id,
        document_id=document_id,
        details={"link_id": link.id, "expires": expires_at is not None},
    )
    db.commit()
    db.refresh(link)
    url = str(request.url_for("shared_link_download", token=raw_token))
    return NewLinkResponse(**link_response(link).model_dump(), url=url)


@router.get("/documents/{document_id}/links", response_model=list[LinkResponse])
def list_links(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[LinkResponse]:
    get_owned_document(db, document_id, user, "list_links")
    links = db.scalars(select(ShareLink).where(ShareLink.document_id == document_id).order_by(ShareLink.created_at.desc())).all()
    return [link_response(link) for link in links]


@router.delete("/documents/{document_id}/links/{link_id}", response_model=MessageResponse)
def revoke_link(document_id: int, link_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    get_owned_document(db, document_id, user, "revoke_link")
    link = db.scalar(select(ShareLink).where(ShareLink.id == link_id, ShareLink.document_id == document_id))
    if not link:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="link not found")
    if link.revoked_at is None:
        link.revoked_at = utcnow()
        record_audit(db, "SHARE_LINK_REVOKED", actor_user_id=user.id, document_id=document_id, details={"link_id": link.id})
        db.commit()
    return {"message": "link revoked"}


@router.get("/shared/{token}", name="shared_link_download")
def shared_link_download(token: str, request: Request, db: Session = Depends(get_db)) -> FileResponse:
    settings = request.app.state.settings
    if not request.app.state.rate_limiter.check(
        f"public:{client_ip(request)}", settings.public_link_rate_limit, settings.rate_limit_window_seconds
    ):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="too many requests")
    link = db.scalar(select(ShareLink).where(ShareLink.token_hash == hash_token(token, settings.session_secret)))
    now = utcnow()
    if not link or link.revoked_at is not None or (link.expires_at is not None and link.expires_at <= now):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="share link not found")
    document = db.scalar(select(Document).where(Document.id == link.document_id))
    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="share link not found")
    storage_dir: Path = db.bind._secureshare_storage_dir  # type: ignore[attr-defined]
    path = storage_dir / document.storage_key
    if path.parent != storage_dir or not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="document content unavailable")
    record_audit(db, "DOWNLOAD", document_id=document.id, details={"access": "public_link", "link_id": link.id})
    db.commit()
    return FileResponse(path, media_type=document.content_type, filename=document.original_filename)
