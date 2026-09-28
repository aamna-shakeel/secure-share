from __future__ import annotations

import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import exists, or_, select
from sqlalchemy.orm import Session

from app.audit import record_audit
from app.authorization import get_document_for_view, get_owned_document
from app.dependencies import get_current_user, get_db
from app.models import Document, DocumentShare, User
from app.schemas import DocumentResponse, MessageResponse
from app.security import FileValidationError, validate_file

router = APIRouter(prefix="/documents", tags=["documents"])


def as_response(document: Document, access: str) -> DocumentResponse:
    return DocumentResponse(
        id=document.id,
        owner_id=document.owner_id,
        original_filename=document.original_filename,
        content_type=document.content_type,
        file_size=document.file_size,
        created_at=document.created_at,
        access=access,
    )


@router.post("", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> DocumentResponse:
    max_bytes = file.size if file.size is not None else None
    limit = request.app.state.settings.max_upload_bytes
    data = file.file.read(limit + 1)
    if len(data) > limit or (max_bytes is not None and max_bytes > limit):
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="file too large")
    filename = file.filename or ""
    try:
        content_type = validate_file(filename, file.content_type, data)
    except FileValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    storage_dir: Path = db.bind._secureshare_storage_dir  # type: ignore[attr-defined]
    storage_key = uuid.uuid4().hex
    destination = storage_dir / storage_key
    try:
        with destination.open("xb") as output:
            output.write(data)
        os.chmod(destination, 0o600)
        document = Document(
            owner_id=user.id,
            original_filename=filename,
            storage_key=storage_key,
            content_type=content_type,
            file_size=len(data),
        )
        db.add(document)
        db.flush()
        record_audit(db, "UPLOAD", actor_user_id=user.id, document_id=document.id, details={"size": len(data), "type": content_type})
        db.commit()
        db.refresh(document)
        return as_response(document, "owner")
    except Exception:
        db.rollback()
        destination.unlink(missing_ok=True)
        raise


@router.get("", response_model=list[DocumentResponse])
def list_documents(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[DocumentResponse]:
    shared = exists().where(
        DocumentShare.document_id == Document.id,
        DocumentShare.shared_with_user_id == user.id,
        DocumentShare.revoked_at.is_(None),
    )
    documents = db.scalars(select(Document).where(or_(Document.owner_id == user.id, shared)).order_by(Document.created_at.desc())).all()
    return [as_response(document, "owner" if document.owner_id == user.id else "shared") for document in documents]


@router.get("/{document_id}", response_model=DocumentResponse)
def get_document(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> DocumentResponse:
    document, access = get_document_for_view(db, document_id, user)
    return as_response(document, access)


@router.get("/{document_id}/download")
def download_document(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> FileResponse:
    document, access = get_document_for_view(db, document_id, user)
    storage_dir: Path = db.bind._secureshare_storage_dir  # type: ignore[attr-defined]
    path = storage_dir / document.storage_key
    if path.parent != storage_dir or not path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="document content unavailable")
    record_audit(db, "DOWNLOAD", actor_user_id=user.id, document_id=document.id, details={"access": access})
    db.commit()
    return FileResponse(path, media_type=document.content_type, filename=document.original_filename)


@router.delete("/{document_id}", response_model=MessageResponse)
def delete_document(document_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, str]:
    document = get_owned_document(db, document_id, user, "delete")
    storage_dir: Path = db.bind._secureshare_storage_dir  # type: ignore[attr-defined]
    source = storage_dir / document.storage_key
    quarantine = storage_dir / f".deleting-{uuid.uuid4().hex}"
    moved = False
    try:
        if source.is_file():
            source.replace(quarantine)
            moved = True
        record_audit(db, "DELETE", actor_user_id=user.id, document_id=document.id)
        db.delete(document)
        db.commit()
    except Exception:
        db.rollback()
        if moved and quarantine.exists():
            quarantine.replace(source)
        raise
    quarantine.unlink(missing_ok=True)
    return {"message": "document deleted"}
