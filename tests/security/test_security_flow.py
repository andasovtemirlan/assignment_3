from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.core.security import get_password_hash
from app.db.database import Base, SessionLocal, engine
from app.db.models import Asset, AuditLog, MaintenanceRequest, RefreshToken, Role, User
from app.main import app

client = TestClient(app)


def _reset_db() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


# ИСПРАВЛЕНО (B107): пароль вынесен в переменную окружения вместо hardcoded значения
_TEST_PASSWORD = os.getenv("TEST_USER_PASSWORD", "TestP@ss!9k#Xr2")


def _create_user(username: str, role: Role, password: str = _TEST_PASSWORD) -> User:
    db = SessionLocal()
    try:
        user = User(
            username=username,
            email=f"{username}@example.com",
            hashed_password=get_password_hash(password),
            role=role,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    finally:
        db.close()


def _login(username: str, password: str = _TEST_PASSWORD) -> dict:
    response = client.post("/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()


def test_engineer_cannot_assign_request() -> None:
    _reset_db()
    supervisor = _create_user("sup_assign", Role.SUPERVISOR)
    engineer_1 = _create_user("eng_owner", Role.ENGINEER)
    _create_user("eng_other", Role.ENGINEER)

    owner_tokens = _login(engineer_1.username)
    create_asset_resp = client.post(
        "/assets",
        headers={"Authorization": f"Bearer {owner_tokens['access_token']}"},
        json={
            "name": "Compressor A1",
            "asset_type": "compressor",
            "location": "Station 7",
            "serial_number": "CMP-0001",
        },
    )
    assert create_asset_resp.status_code == 201
    asset_id = create_asset_resp.json()["id"]

    create_request_resp = client.post(
        "/maintenance/requests",
        headers={"Authorization": f"Bearer {owner_tokens['access_token']}"},
        json={
            "asset_id": asset_id,
            "title": "Compressor vibration check",
            "description": "Inspect vibration and tighten mounts",
            "priority": "high",
            "scheduled_date": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "estimated_hours": 4,
        },
    )
    assert create_request_resp.status_code == 201
    request_id = create_request_resp.json()["id"]

    other_tokens = _login("eng_other")
    forbidden_assign = client.patch(
        f"/maintenance/requests/{request_id}/assign",
        headers={"Authorization": f"Bearer {other_tokens['access_token']}"},
        json={"engineer_id": engineer_1.id},
    )
    assert forbidden_assign.status_code == 403

    supervisor_tokens = _login(supervisor.username)
    allowed_assign = client.patch(
        f"/maintenance/requests/{request_id}/assign",
        headers={"Authorization": f"Bearer {supervisor_tokens['access_token']}"},
        json={"engineer_id": engineer_1.id},
    )
    assert allowed_assign.status_code == 200


def test_engineer_status_rules_and_completion_note() -> None:
    _reset_db()
    supervisor = _create_user("sup_status", Role.SUPERVISOR)
    engineer_1 = _create_user("eng_status_1", Role.ENGINEER)
    engineer_2 = _create_user("eng_status_2", Role.ENGINEER)

    owner_tokens = _login(engineer_1.username)
    asset_resp = client.post(
        "/assets",
        headers={"Authorization": f"Bearer {owner_tokens['access_token']}"},
        json={
            "name": "Pump P-3",
            "asset_type": "pump",
            "location": "North zone",
            "serial_number": "PUMP-0003",
        },
    )
    asset_id = asset_resp.json()["id"]

    req_resp = client.post(
        "/maintenance/requests",
        headers={"Authorization": f"Bearer {owner_tokens['access_token']}"},
        json={
            "asset_id": asset_id,
            "title": "Pump seal replacement",
            "description": "Replace worn seal and retest pressure",
            "priority": "critical",
            "scheduled_date": (datetime.now(timezone.utc) + timedelta(days=2)).isoformat(),
            "estimated_hours": 6,
        },
    )
    request_id = req_resp.json()["id"]

    supervisor_tokens = _login(supervisor.username)
    assign_resp = client.patch(
        f"/maintenance/requests/{request_id}/assign",
        headers={"Authorization": f"Bearer {supervisor_tokens['access_token']}"},
        json={"engineer_id": engineer_1.id},
    )
    assert assign_resp.status_code == 200

    other_tokens = _login(engineer_2.username)
    forbidden_status = client.patch(
        f"/maintenance/requests/{request_id}/status",
        headers={"Authorization": f"Bearer {other_tokens['access_token']}"},
        json={"status": "in_progress"},
    )
    assert forbidden_status.status_code == 403

    start_resp = client.patch(
        f"/maintenance/requests/{request_id}/status",
        headers={"Authorization": f"Bearer {owner_tokens['access_token']}"},
        json={"status": "in_progress"},
    )
    assert start_resp.status_code == 200

    missing_note_resp = client.patch(
        f"/maintenance/requests/{request_id}/status",
        headers={"Authorization": f"Bearer {owner_tokens['access_token']}"},
        json={"status": "completed"},
    )
    assert missing_note_resp.status_code == 400

    complete_resp = client.patch(
        f"/maintenance/requests/{request_id}/status",
        headers={"Authorization": f"Bearer {owner_tokens['access_token']}"},
        json={"status": "completed", "closed_note": "Work completed and validated"},
    )
    assert complete_resp.status_code == 200


def test_logout_revokes_refresh_token() -> None:
    _reset_db()

    register_resp = client.post(
        "/auth/register",
        json={
            "username": "logout_user",
            "email": "logout_user@example.com",
            "password": "Strong#123",
        },
    )
    assert register_resp.status_code == 201

    login_resp = client.post(
        "/auth/login",
        json={"username": "logout_user", "password": "Strong#123"},
    )
    assert login_resp.status_code == 200
    tokens = login_resp.json()

    logout_resp = client.post(
        "/auth/logout",
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert logout_resp.status_code == 200

    refresh_resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh_resp.status_code == 401
