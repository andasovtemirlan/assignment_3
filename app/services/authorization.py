from __future__ import annotations

from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Asset, MaintenanceRequest, Role, TaskStatus, User


VALID_TRANSITIONS: dict[TaskStatus, set[TaskStatus]] = {
    TaskStatus.CREATED: {TaskStatus.ASSIGNED, TaskStatus.CANCELLED},
    TaskStatus.ASSIGNED: {TaskStatus.IN_PROGRESS, TaskStatus.CANCELLED},
    TaskStatus.IN_PROGRESS: {TaskStatus.COMPLETED, TaskStatus.CANCELLED},
    TaskStatus.COMPLETED: set(),
    TaskStatus.CANCELLED: set(),
}


def require_roles(current_user: User, allowed: set[Role]) -> None:
    if current_user.role not in allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def get_asset_or_404(db: Session, asset_id: str) -> Asset:
    asset = db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


def get_request_or_404(db: Session, request_id: str) -> MaintenanceRequest:
    maintenance_request = db.get(MaintenanceRequest, request_id)
    if not maintenance_request:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Request not found")
    return maintenance_request


def ensure_asset_access(db: Session, current_user: User, asset: Asset) -> None:
    if current_user.role in {Role.ADMIN, Role.SUPERVISOR}:
        return

    if asset.owner_id == current_user.id:
        return

    request_exists = db.scalar(
        select(MaintenanceRequest.id).where(
            MaintenanceRequest.asset_id == asset.id,
            MaintenanceRequest.assigned_engineer_id == current_user.id,
        )
    )
    if request_exists:
        return

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def ensure_request_access(current_user: User, maintenance_request: MaintenanceRequest) -> None:
    if current_user.role in {Role.ADMIN, Role.SUPERVISOR}:
        return

    if maintenance_request.created_by_id == current_user.id:
        return

    if maintenance_request.assigned_engineer_id == current_user.id:
        return

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def validate_status_transition(
    current_user: User,
    maintenance_request: MaintenanceRequest,
    new_status: TaskStatus,
) -> None:
    if new_status == maintenance_request.status:
        return

    allowed_transitions = VALID_TRANSITIONS.get(maintenance_request.status, set())
    if new_status not in allowed_transitions:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid status transition")

    if current_user.role in {Role.ADMIN, Role.SUPERVISOR}:
        return

    if current_user.role != Role.ENGINEER:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    if maintenance_request.assigned_engineer_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    engineer_allowed = {
        (TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS),
        (TaskStatus.IN_PROGRESS, TaskStatus.COMPLETED),
    }
    if (maintenance_request.status, new_status) not in engineer_allowed:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")


def apply_status_fields(maintenance_request: MaintenanceRequest, new_status: TaskStatus) -> None:
    now = datetime.now(timezone.utc)
    if new_status == TaskStatus.IN_PROGRESS and maintenance_request.started_at is None:
        maintenance_request.started_at = now
    if new_status == TaskStatus.COMPLETED:
        maintenance_request.completed_at = now
