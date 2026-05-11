from __future__ import annotations

import csv
import io
import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from starlette.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import Asset, MaintenanceRequest, Role, User
from app.services.authorization import require_roles

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

# SECURITY: Sanitize CSV fields to prevent formula injection (CWE-1236)
def _sanitize_csv_field(value: str | None) -> str:
    """Prevent CSV injection by prefixing formula characters with single quote."""
    if value is None:
        return ""
    value_str = str(value)
    # FIXED (CWE-1236): Sanitize formula injection characters
    if value_str and value_str[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value_str
    return value_str


def _csv_row_generator(db: Session, query, max_rows: int = 1000):
    """Generate CSV rows as a streaming generator to prevent memory exhaustion."""
    # FIXED (CWE-400): Use generator to stream CSV instead of loading entire content in memory
    yield "request_id,asset_serial_number,asset_type,priority,status,scheduled_date,started_at,completed_at,estimated_hours\n"
    
    row_count = 0
    try:
        for request_row, asset_row in db.execute(query.limit(max_rows)).all():
            if row_count >= max_rows:
                logger.warning("CSV export reached max row limit (%d)", max_rows)
                break
            
            row_count += 1
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(
                [
                    _sanitize_csv_field(request_row.id),
                    _sanitize_csv_field(asset_row.serial_number),
                    _sanitize_csv_field(asset_row.asset_type.value),
                    _sanitize_csv_field(request_row.priority.value),
                    _sanitize_csv_field(request_row.status.value),
                    _sanitize_csv_field(request_row.scheduled_date.isoformat() if request_row.scheduled_date else ""),
                    _sanitize_csv_field(request_row.started_at.isoformat() if request_row.started_at else ""),
                    _sanitize_csv_field(request_row.completed_at.isoformat() if request_row.completed_at else ""),
                    _sanitize_csv_field(str(request_row.estimated_hours)),
                ]
            )
            yield output.getvalue()
            output.close()
    except Exception as e:
        logger.exception("Error during CSV export generation: %s", str(e))
        yield f"# Error during export: {str(e)}\n"


@router.get("/maintenance/export")
def export_maintenance_report(
    start_date: datetime | None = Query(default=None),
    end_date: datetime | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> StreamingResponse:
    require_roles(current_user, {Role.ADMIN, Role.SUPERVISOR})

    query = select(MaintenanceRequest, Asset).join(Asset, Asset.id == MaintenanceRequest.asset_id)
    if start_date:
        query = query.where(MaintenanceRequest.created_at >= start_date)
    if end_date:
        query = query.where(MaintenanceRequest.created_at <= end_date)

    # FIXED (CWE-400, CWE-1236): Stream CSV rows instead of loading entire content in memory
    # Prevents memory exhaustion and sanitizes for formula injection
    return StreamingResponse(
        _csv_row_generator(db, query),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=maintenance_report.csv"},
    )
