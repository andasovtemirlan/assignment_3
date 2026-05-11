"""Password policy validation service.

Provides validation of password strength requirements to ensure compliance
with security standards and prevent weak password usage.
"""
from __future__ import annotations

import re

from fastapi import HTTPException, status

from app.core.config import settings


class PasswordPolicyError(HTTPException):
    """Exception raised when password doesn't meet policy requirements."""

    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


def validate_password_policy(password: str) -> None:
    """Validate password against configured policy.

    FIXED (CWE-521): Enforce password complexity requirements
    - Minimum length
    - Uppercase letters (if enabled)
    - Digits (if enabled)
    - Special characters (if enabled)

    Args:
        password: The password to validate

    Raises:
        PasswordPolicyError: If password doesn't meet policy requirements
    """
    # Check minimum length
    if len(password) < settings.min_password_length:
        raise PasswordPolicyError(
            f"Password must be at least {settings.min_password_length} characters long"
        )

    # Check for uppercase letters
    if settings.require_password_uppercase and not re.search(r"[A-Z]", password):
        raise PasswordPolicyError("Password must contain at least one uppercase letter")

    # Check for digits
    if settings.require_password_digit and not re.search(r"\d", password):
        raise PasswordPolicyError("Password must contain at least one digit")

    # Check for special characters
    if settings.require_password_special_char and not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", password):
        raise PasswordPolicyError(
            "Password must contain at least one special character (!@#$%^&*()_+-=[]{}';:\"\\|,.<>/?)"
        )
