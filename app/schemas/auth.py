from __future__ import annotations

import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.db.models import Role

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.-]{3,50}$")


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if not USERNAME_REGEX.fullmatch(value):
            raise ValueError("Invalid username format")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        checks = [
            any(ch.isupper() for ch in value),
            any(ch.islower() for ch in value),
            any(ch.isdigit() for ch in value),
            any(not ch.isalnum() for ch in value),
        ]
        if not all(checks):
            raise ValueError("Password does not meet complexity requirements")
        return value


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=1, max_length=128)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=20, max_length=4000)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    id: str
    username: str
    email: EmailStr
    role: Role
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
