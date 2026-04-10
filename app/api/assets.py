from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import distinct, or_, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import Asset, MaintenanceRequest, Role, User
from app.schemas.asset import AssetCreate, AssetOut
from app.services.audit import write_audit_log
from app.services.authorization import ensure_asset_access, get_asset_or_404

router = APIRouter(prefix="/assets", tags=["assets"])


@router.post("", response_model=AssetOut, status_code=status.HTTP_201_CREATED)
def create_asset(
    payload: AssetCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetOut:
    owner_id = current_user.id

    if payload.owner_id:
        if current_user.role not in {Role.ADMIN, Role.SUPERVISOR}:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
        owner = db.get(User, payload.owner_id)
        if not owner:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid owner")
        owner_id = owner.id

    existing_serial = db.scalar(select(Asset.id).where(Asset.serial_number == payload.serial_number))
    if existing_serial:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Serial number already exists")

    asset = Asset(
        name=payload.name,
        asset_type=payload.asset_type,
        location=payload.location,
        serial_number=payload.serial_number,
        owner_id=owner_id,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    write_audit_log(
        db=db,
        action="ASSET_CREATED",
        entity_type="Asset",
        entity_id=asset.id,
        user_id=current_user.id,
        details={"asset_type": asset.asset_type.value, "owner_id": asset.owner_id},
        request=request,
    )

    return AssetOut.model_validate(asset)


@router.get("", response_model=list[AssetOut])
def list_assets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AssetOut]:
    if current_user.role in {Role.ADMIN, Role.SUPERVISOR}:
        assets = db.scalars(select(Asset).order_by(Asset.created_at.desc())).all()
    else:
        assets = db.scalars(
            select(Asset)
            .join(MaintenanceRequest, MaintenanceRequest.asset_id == Asset.id, isouter=True)
            .where(
                or_(
                    Asset.owner_id == current_user.id,
                    MaintenanceRequest.assigned_engineer_id == current_user.id,
                )
            )
            .order_by(Asset.created_at.desc())
            .distinct()
        ).all()

    return [AssetOut.model_validate(asset) for asset in assets]


@router.get("/{asset_id}", response_model=AssetOut)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AssetOut:
    asset = get_asset_or_404(db, asset_id)
    ensure_asset_access(db, current_user, asset)
    return AssetOut.model_validate(asset)
