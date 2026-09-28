from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.models import Document, DocumentShare, User


def get_document_for_view(db: Session, document_id: int, actor: User) -> tuple[Document, str]:
    document = db.scalar(select(Document).where(Document.id == document_id))
    if document and document.owner_id == actor.id:
        return document, "owner"
    if document:
        shared = db.scalar(
            select(
                exists().where(
                    DocumentShare.document_id == document_id,
                    DocumentShare.shared_with_user_id == actor.id,
                    DocumentShare.revoked_at.is_(None),
                )
            )
        )
        if shared:
            return document, "shared"
    record_audit(db, "ACCESS_DENIED", actor_user_id=actor.id, document_id=document_id, details={"operation": "view"})
    db.commit()
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="document not found")


def get_owned_document(db: Session, document_id: int, actor: User, operation: str) -> Document:
    document = db.scalar(select(Document).where(Document.id == document_id, Document.owner_id == actor.id))
    if document:
        return document
    record_audit(db, "ACCESS_DENIED", actor_user_id=actor.id, document_id=document_id, details={"operation": operation})
    db.commit()
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="document not found")
