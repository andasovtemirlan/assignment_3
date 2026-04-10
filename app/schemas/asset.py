from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.db.models import AssetType

SERIAL_REGEX = re.compile(r"^[A-Z0-9-]{4,100}$")


class AssetCreate(BaseModel):
    name: str = Field(min_length=3, max_length=120)
    asset_type: AssetType
    location: str = Field(min_length=2, max_length=255)
    serial_number: str = Field(min_length=4, max_length=100)
    owner_id: str | None = Field(default=None, min_length=36, max_length=36)

    @field_validator("serial_number")
    @classmethod
    def validate_serial_number(cls, value: str) -> str:
        value = value.upper()
        if not SERIAL_REGEX.fullmatch(value):
            raise ValueError("Invalid serial number format")
        return value


class AssetOut(BaseModel):
    id: str
    name: str
    asset_type: AssetType
    location: str
    serial_number: str
    owner_id: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
