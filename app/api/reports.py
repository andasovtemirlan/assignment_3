from __future__ import annotations

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import Asset, MaintenanceRequest, Role, User
from app.services.authorization import require_roles

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/maintenance/export")
def export_maintenance_report(
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    require_roles(current_user, {Role.ADMIN, Role.SUPERVISOR})

    query = select(MaintenanceRequest, Asset).join(Asset, Asset.id == MaintenanceRequest.asset_id)
    if start_date:
        query = query.where(MaintenanceRequest.created_at >= start_date)
    if end_date:
        query = query.where(MaintenanceRequest.created_at <= end_date)

    rows = db.execute(query.limit(1000)).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "request_id",
            "asset_serial_number",
            "asset_type",
            "priority",
            "status",
            "scheduled_date",
            "started_at",
            "completed_at",
            "estimated_hours",
        ]
    )

    for request_row, asset_row in rows:
        writer.writerow(
            [
                request_row.id,
                asset_row.serial_number,
                asset_row.asset_type.value,
                request_row.priority.value,
                request_row.status.value,
                request_row.scheduled_date.isoformat(),
                request_row.started_at.isoformat() if request_row.started_at else "",
                request_row.completed_at.isoformat() if request_row.completed_at else "",
                request_row.estimated_hours,
            ]
        )

    csv_content = output.getvalue()
    output.close()

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=maintenance_report.csv"},
    )
