from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import MaintenanceRequest, Role, TaskStatus, User
from app.schemas.maintenance import AssignEngineerRequest, MaintenanceCreate, MaintenanceOut, StatusUpdateRequest
from app.services.audit import write_audit_log
from app.services.authorization import (
    apply_status_fields,
    ensure_asset_access,
    ensure_request_access,
    get_asset_or_404,
    get_request_or_404,
    validate_status_transition,
)

router = APIRouter(prefix="/maintenance", tags=["maintenance"])


@router.post("/requests", response_model=MaintenanceOut, status_code=status.HTTP_201_CREATED)
def create_maintenance_request(
    payload: MaintenanceCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MaintenanceOut:
    asset = get_asset_or_404(db, payload.asset_id)
    ensure_asset_access(db, current_user, asset)

    if payload.scheduled_date < datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scheduled date must be in the future")

    maintenance_request = MaintenanceRequest(
        asset_id=payload.asset_id,
        title=payload.title,
        description=payload.description,
        priority=payload.priority,
        scheduled_date=payload.scheduled_date,
        estimated_hours=payload.estimated_hours,
        status=TaskStatus.CREATED,
        created_by_id=current_user.id,
    )

    db.add(maintenance_request)
    db.commit()
    db.refresh(maintenance_request)

    write_audit_log(
        db=db,
        action="MAINTENANCE_REQUEST_CREATED",
        entity_type="MaintenanceRequest",
        entity_id=maintenance_request.id,
        user_id=current_user.id,
        details={"priority": maintenance_request.priority.value, "asset_id": maintenance_request.asset_id},
        request=request,
    )

    return MaintenanceOut.model_validate(maintenance_request)


@router.patch("/requests/{request_id}/assign", response_model=MaintenanceOut)
def assign_engineer(
    request_id: str,
    payload: AssignEngineerRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MaintenanceOut:
    if current_user.role not in {Role.ADMIN, Role.SUPERVISOR}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")

    maintenance_request = get_request_or_404(db, request_id)
    engineer = db.get(User, payload.engineer_id)
    if not engineer or engineer.role != Role.ENGINEER:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid engineer")

    if maintenance_request.status in {TaskStatus.COMPLETED, TaskStatus.CANCELLED}:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot assign closed request")

    previous_engineer_id = maintenance_request.assigned_engineer_id
    maintenance_request.assigned_engineer_id = engineer.id
    if maintenance_request.status == TaskStatus.CREATED:
        maintenance_request.status = TaskStatus.ASSIGNED

    db.add(maintenance_request)
    db.commit()
    db.refresh(maintenance_request)

    write_audit_log(
        db=db,
        action="MAINTENANCE_REQUEST_ASSIGNED",
        entity_type="MaintenanceRequest",
        entity_id=maintenance_request.id,
        user_id=current_user.id,
        details={
            "old_engineer_id": previous_engineer_id,
            "new_engineer_id": engineer.id,
            "status": maintenance_request.status.value,
        },
        request=request,
    )

    return MaintenanceOut.model_validate(maintenance_request)


@router.patch("/requests/{request_id}/status", response_model=MaintenanceOut)
def update_request_status(
    request_id: str,
    payload: StatusUpdateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MaintenanceOut:
    maintenance_request = get_request_or_404(db, request_id)
    ensure_request_access(current_user, maintenance_request)
    validate_status_transition(current_user, maintenance_request, payload.status)

    if payload.status == TaskStatus.COMPLETED and not payload.closed_note:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="closed_note is required for completion")

    old_status = maintenance_request.status
    maintenance_request.status = payload.status
    if payload.closed_note:
        maintenance_request.closed_note = payload.closed_note
    apply_status_fields(maintenance_request, payload.status)

    db.add(maintenance_request)
    db.commit()
    db.refresh(maintenance_request)

    write_audit_log(
        db=db,
        action="MAINTENANCE_STATUS_CHANGED",
        entity_type="MaintenanceRequest",
        entity_id=maintenance_request.id,
        user_id=current_user.id,
        details={"old_status": old_status.value, "new_status": payload.status.value},
        request=request,
    )

    return MaintenanceOut.model_validate(maintenance_request)


@router.get("/requests/{request_id}", response_model=MaintenanceOut)
def get_maintenance_request(
    request_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> MaintenanceOut:
    maintenance_request = get_request_or_404(db, request_id)
    ensure_request_access(current_user, maintenance_request)
    return MaintenanceOut.model_validate(maintenance_request)


@router.get("/requests", response_model=list[MaintenanceOut])
def list_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[MaintenanceOut]:
    if current_user.role in {Role.ADMIN, Role.SUPERVISOR}:
        requests = db.scalars(select(MaintenanceRequest).order_by(MaintenanceRequest.created_at.desc())).all()
    else:
        requests = db.scalars(
            select(MaintenanceRequest)
            .where(
                or_(
                    MaintenanceRequest.created_by_id == current_user.id,
                    MaintenanceRequest.assigned_engineer_id == current_user.id,
                )
            )
            .order_by(MaintenanceRequest.created_at.desc())
        ).all()

    return [MaintenanceOut.model_validate(item) for item in requests]
