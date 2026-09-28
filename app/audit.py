from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditEvent


def record_audit(
    db: Session,
    event_type: str,
    *,
    actor_user_id: int | None = None,
    document_id: int | None = None,
    target_user_id: int | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    event = AuditEvent(
        actor_user_id=actor_user_id,
        event_type=event_type,
        document_id=document_id,
        target_user_id=target_user_id,
        details=details or {},
    )
    db.add(event)
    return event
