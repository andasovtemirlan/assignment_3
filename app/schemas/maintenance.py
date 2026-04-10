from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import TaskPriority, TaskStatus


class MaintenanceCreate(BaseModel):
    asset_id: str = Field(min_length=36, max_length=36)
    title: str = Field(min_length=3, max_length=120)
    description: str = Field(min_length=10, max_length=2000)
    priority: TaskPriority
    scheduled_date: datetime
    estimated_hours: float = Field(ge=0.25, le=720)


class AssignEngineerRequest(BaseModel):
    engineer_id: str = Field(min_length=36, max_length=36)


class StatusUpdateRequest(BaseModel):
    status: TaskStatus
    closed_note: str | None = Field(default=None, min_length=5, max_length=400)


class MaintenanceOut(BaseModel):
    id: str
    asset_id: str
    title: str
    description: str
    priority: TaskPriority
    status: TaskStatus
    scheduled_date: datetime
    started_at: datetime | None
    completed_at: datetime | None
    estimated_hours: float
    closed_note: str | None
    created_by_id: str
    assigned_engineer_id: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
