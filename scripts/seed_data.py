from __future__ import annotations

import sys
import os
import secrets
import string
from pathlib import Path
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

# Allow running this script directly: python .\scripts\seed_data.py
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.core.security import get_password_hash
from app.db.database import Base, SessionLocal, engine
from app.db.models import Asset, AssetType, MaintenanceRequest, Role, TaskPriority, TaskStatus, User


def _generate_strong_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
    return "A1!" + "".join(secrets.choice(alphabet) for _ in range(max(8, length - 3)))


def _resolve_demo_password(env_name: str) -> str:
    return os.getenv(env_name) or _generate_strong_password()


def ensure_user(db, username: str, email: str, role: Role, password: str) -> tuple[User, bool]:
    existing = db.scalar(select(User).where(User.username == username))
    if existing:
        return existing, False

    user = User(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        role=role,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user, True


def main() -> None:
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        admin_password = _resolve_demo_password("DEMO_ADMIN_PASSWORD")
        supervisor_password = _resolve_demo_password("DEMO_SUPERVISOR_PASSWORD")
        engineer_password = _resolve_demo_password("DEMO_ENGINEER_PASSWORD")

        admin, admin_created = ensure_user(db, "admin_demo", "admin@example.com", Role.ADMIN, admin_password)
        supervisor, supervisor_created = ensure_user(
            db,
            "supervisor_demo",
            "supervisor@example.com",
            Role.SUPERVISOR,
            supervisor_password,
        )
        engineer, engineer_created = ensure_user(
            db,
            "engineer_demo",
            "engineer@example.com",
            Role.ENGINEER,
            engineer_password,
        )

        asset = db.scalar(select(Asset).where(Asset.serial_number == "WELL-1001"))
        if not asset:
            asset = Asset(
                name="Well 1001",
                asset_type=AssetType.WELL,
                location="Field A",
                serial_number="WELL-1001",
                owner_id=engineer.id,
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

        request = db.scalar(select(MaintenanceRequest).where(MaintenanceRequest.title == "Quarterly well inspection"))
        if not request:
            request = MaintenanceRequest(
                asset_id=asset.id,
                title="Quarterly well inspection",
                description="Routine integrity and pressure check",
                priority=TaskPriority.HIGH,
                status=TaskStatus.ASSIGNED,
                scheduled_date=datetime.now(timezone.utc) + timedelta(days=2),
                estimated_hours=8,
                created_by_id=supervisor.id,
                assigned_engineer_id=engineer.id,
            )
            db.add(request)
            db.commit()

        print("Seed data ready")
        print("Users: admin_demo / supervisor_demo / engineer_demo")

        # ИСПРАВЛЕНО (CWE-312): пароли больше не выводятся в stdout — задайте через переменные окружения
        if admin_created:
            print("admin_demo: created (set DEMO_ADMIN_PASSWORD env to control credentials)")
        else:
            print("admin_demo: already exists, not modified")

        if supervisor_created:
            print("supervisor_demo: created (set DEMO_SUPERVISOR_PASSWORD env to control credentials)")
        else:
            print("supervisor_demo: already exists, not modified")

        if engineer_created:
            print("engineer_demo: created (set DEMO_ENGINEER_PASSWORD env to control credentials)")
        else:
            print("engineer_demo: already exists, not modified")

        print("Hint: set DEMO_ADMIN_PASSWORD / DEMO_SUPERVISOR_PASSWORD / DEMO_ENGINEER_PASSWORD to control credentials")
    finally:
        db.close()


if __name__ == "__main__":
    main()
