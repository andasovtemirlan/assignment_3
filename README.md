# Asset Maintenance MVP (Variant 2)

FastAPI MVP for oil and gas asset maintenance workflows with secure authentication, authorization, audit logging, and security analysis support.

## Quick start

1. Create and activate a virtual environment.
2. Install dependencies:
   - `pip install -r requirements.txt`
3. Copy environment file:
   - `copy .env.example .env`
4. Edit `.env` and set `SECRET_KEY`.
5. Run the app:
   - `uvicorn app.main:app --reload`

## Core features

- JWT auth with access and refresh tokens.
- Role-based and object-level authorization (admin, supervisor, engineer).
- SQLite database with SQLAlchemy.
- Password hashing with PBKDF2 (Passlib).
- Critical action audit logging.
- Input validation with Pydantic.
- Safe report export endpoint (restricted roles).

## Minimal demo data

- Create demo users and records:
   - `python scripts/seed_data.py`
   - or `python -m scripts.seed_data`

Demo users created by seed:

- admin_demo
- supervisor_demo
- engineer_demo

Credentials:

- Set optional environment variables before seed run:
   - `DEMO_ADMIN_PASSWORD`
   - `DEMO_SUPERVISOR_PASSWORD`
   - `DEMO_ENGINEER_PASSWORD`
- If variables are not set, strong random passwords are generated and printed once.

## Automated verification

- Tests:
   - `pytest -q`

## Security tooling

- SAST: `bandit -r app -f json -o reports/bandit.json`
- SCA: `pip-audit -r requirements.txt -f json -o reports/pip-audit.json`
