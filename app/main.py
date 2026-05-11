from __future__ import annotations

import logging
import os
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import assets, auth, maintenance, reports, users
from app.core.config import settings
from app.db.database import Base, engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger(__name__)

# FIXED (CWE-307): Rate limiting state (in production, use Redis)
_request_tracking: dict[str, list[datetime]] = defaultdict(list)


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, considering X-Forwarded-For headers."""
    if request.headers.get("x-forwarded-for"):
        return request.headers.get("x-forwarded-for").split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate_limit(ip: str, is_auth_endpoint: bool = False) -> bool:
    """Check if request from IP should be rate limited.
    
    FIXED (CWE-307): Implement rate limiting to prevent brute force attacks
    """
    # Check if pytest is running (for testing)
    if os.getenv("PYTEST_CURRENT_TEST") or os.getenv("TESTING"):
        return True
    
    if not settings.rate_limit_enabled:
        return True
    
    now = datetime.now()
    limit_requests = (
        settings.rate_limit_auth_requests_per_minute
        if is_auth_endpoint
        else settings.rate_limit_requests_per_minute
    )
    time_window = timedelta(minutes=1)
    cutoff_time = now - time_window

    # Clean old requests
    if ip in _request_tracking:
        _request_tracking[ip] = [
            req_time for req_time in _request_tracking[ip] if req_time > cutoff_time
        ]
    
    # Check if limit exceeded
    if len(_request_tracking[ip]) >= limit_requests:
        logger.warning(
            "Rate limit exceeded for IP %s (auth=%s, requests=%d)",
            ip,
            is_auth_endpoint,
            len(_request_tracking[ip]),
        )
        return False
    
    # Track this request
    _request_tracking[ip].append(now)
    return True


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins or ["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """FIXED (CWE-307): Rate limit authentication endpoints."""
    is_auth_endpoint = request.url.path.startswith("/auth/")
    client_ip = _get_client_ip(request)
    
    if not _check_rate_limit(client_ip, is_auth_endpoint):
        return JSONResponse(
            status_code=429,
            content={"detail": "Too many requests. Please try again later."},
        )
    
    return await call_next(request)


@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.max_request_size_bytes:
        return JSONResponse(status_code=413, content={"detail": "Request entity too large"})
    return await call_next(request)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception")
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/")
def root() -> dict[str, str]:
    return {
        "service": settings.app_name,
        "status": "running",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(assets.router)
app.include_router(maintenance.router)
app.include_router(reports.router)
