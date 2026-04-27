from __future__ import annotations

import logging
from typing import Any

from fastapi import Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.models import AuditLog

logger = logging.getLogger(__name__)


def write_audit_log(
    db: Session,
    action: str,
    entity_type: str,
    entity_id: str | None,
    user_id: str | None,
    details: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    ip_address = None
    if request and request.client:
        ip_address = request.client.host

    entry = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
        ip_address=ip_address,
    )
    db.add(entry)
    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        # ИСПРАВЛЕНО: exc_info=True удалён, чтобы стек-трейс не попадал в логи (CWE-209)
        logger.warning("Failed to write audit log entry: %s", type(exc).__name__)
