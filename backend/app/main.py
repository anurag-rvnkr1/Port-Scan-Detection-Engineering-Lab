from __future__ import annotations

from contextlib import asynccontextmanager
import csv
from datetime import datetime, timedelta, timezone
from collections import defaultdict, deque
import ipaddress
import io
import logging
import os
import secrets
import threading
import time
from typing import Annotated, Literal, cast
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse

from backend.app.auth import (
    ADMIN_ROLES,
    READ_ROLES,
    SESSION_COOKIE,
    SESSION_SECONDS,
    TEAM_ROLES,
    WRITE_ROLES,
    create_user,
    new_session,
    role_dependency,
    token_hash,
    verify_csrf,
    verify_password,
)
from backend.app.database import (
    AlertRow,
    AuditLogRow,
    AuthSessionRow,
    EventRow,
    IncidentRow,
    IntegrationDeliveryRow,
    NmapScanRow,
    SessionLocal,
    UserRow,
    create_tables,
)
from backend.app.generator import SCENARIOS, generate_events
from backend.app.integrations import (
    IntegrationName,
    deliver_records,
    integration_status,
    retry_delivery,
    send_test_event,
)
from backend.app.pipeline import DEFAULT_THRESHOLD, IPNetwork, detect_scans, parse_log, parse_source_allowlist
from backend.app.pcap import PcapFormatError, PcapRecordLimitError, parse_pcap
from backend.app.reports import ReportPeriod, generate_soc_pdf
from backend.app.scanner import (
    COMMON_PORTS,
    NmapConfigurationError,
    NmapExecutionError,
    NmapUnavailable,
    SCAN_LOCK,
    build_command,
    execute_command,
    load_configuration as load_nmap_configuration,
)
from backend.app.schemas import NetworkEvent


MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_REQUEST_BYTES = MAX_UPLOAD_BYTES + 128 * 1024
MAX_UPLOAD_RECORDS = 20_000
MAX_PARSE_ERRORS_RETURNED = 100
MAX_DETECTION_CONTEXT_EVENTS = 50_000
DETECTION_HISTORY_SECONDS = 60 * 60
_COOKIE_SECURE_SETTING = os.getenv("LAB_COOKIE_SECURE", "false").strip().lower()
if _COOKIE_SECURE_SETTING not in {"0", "1", "false", "true", "no", "yes"}:
    raise RuntimeError("LAB_COOKIE_SECURE must be true or false")
AUTH_COOKIE_SECURE = _COOKIE_SECURE_SETTING in {"1", "true", "yes"}
_API_HOST = os.getenv("LAB_HOST", "127.0.0.1").strip().strip("[]").lower()
try:
    _API_HOST_IS_LOOPBACK = _API_HOST == "localhost" or ipaddress.ip_address(_API_HOST).is_loopback
except ValueError:
    _API_HOST_IS_LOOPBACK = False
ALLOWED_ORIGINS = tuple(
    origin.strip()
    for origin in os.getenv("LAB_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")
    if origin.strip()
)
_TRUST_PROXY_SETTING = os.getenv("LAB_TRUSTED_LOOPBACK_PROXY", "false").strip().lower()
if _TRUST_PROXY_SETTING not in {"0", "1", "false", "true", "no", "yes"}:
    raise RuntimeError("LAB_TRUSTED_LOOPBACK_PROXY must be true or false")
TRUSTED_LOOPBACK_PROXY = _TRUST_PROXY_SETTING in {"1", "true", "yes"}


def _is_loopback_http_origin(origin: str) -> bool:
    try:
        parsed = urlsplit(origin)
        hostname = (parsed.hostname or "").lower()
        return (
            parsed.scheme == "http"
            and (hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback)
            and parsed.path in {"", "/"}
            and parsed.username is None
            and parsed.password is None
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


if not _API_HOST_IS_LOOPBACK and not AUTH_COOKIE_SECURE:
    if not TRUSTED_LOOPBACK_PROXY or not ALLOWED_ORIGINS or not all(
        _is_loopback_http_origin(origin) for origin in ALLOWED_ORIGINS
    ):
        raise RuntimeError(
            "Non-loopback HTTP cookies require LAB_TRUSTED_LOOPBACK_PROXY=true and loopback-only CORS origins, "
            "or set LAB_COOKIE_SECURE=true"
        )


class SlidingWindowLimiter:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._windows: dict[str, int] = {}
        self._lock = threading.Lock()

    def allow(self, scope: str, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        identity = (scope, key)
        with self._lock:
            self._windows[scope] = window_seconds
            if len(self._entries) >= 10_000:
                self._entries = defaultdict(
                    deque,
                    {
                        item: timestamps
                        for item, timestamps in self._entries.items()
                        if timestamps and timestamps[-1] > now - self._windows.get(item[0], window_seconds)
                    },
                )
            if identity not in self._entries and len(self._entries) >= 10_000:
                return False
            timestamps = self._entries[identity]
            while timestamps and timestamps[0] <= now - window_seconds:
                timestamps.popleft()
            if len(timestamps) >= limit:
                return False
            timestamps.append(now)
            return True


request_limiter = SlidingWindowLimiter()
LOGGER = logging.getLogger(__name__)


def _configured_detection_threshold() -> int:
    try:
        threshold = int(os.getenv("LAB_DETECTION_THRESHOLD", str(DEFAULT_THRESHOLD)))
    except ValueError as error:
        raise RuntimeError("LAB_DETECTION_THRESHOLD must be an integer from 3 to 65536") from error
    if not 3 <= threshold <= 65536:
        raise RuntimeError("LAB_DETECTION_THRESHOLD must be an integer from 3 to 65536")
    return threshold


def _configured_detection_source_allowlist() -> tuple[IPNetwork, ...]:
    try:
        return parse_source_allowlist(os.getenv("LAB_DETECTION_SOURCE_ALLOWLIST"))
    except ValueError as error:
        raise RuntimeError(f"Invalid LAB_DETECTION_SOURCE_ALLOWLIST: {error}") from error


DETECTION_SOURCE_ALLOWLIST = _configured_detection_source_allowlist()
DETECTION_THRESHOLD = _configured_detection_threshold()


class AlertUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["New", "Investigating", "Escalated", "Resolved", "Closed", "False Positive"] | None = None
    severity: Literal["Informational", "Low", "Medium", "High", "Critical"] | None = None
    assigned_to: str | None = Field(default=None, max_length=120)
    note: str | None = Field(default=None, max_length=4000)


class IncidentCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    assigned_to: str | None = Field(default=None, max_length=120)


class IncidentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["New", "Investigating", "Escalated", "Resolved", "Closed"] | None = None
    assigned_to: str | None = Field(default=None, max_length=120)
    resolution: str | None = Field(default=None, max_length=4000)
    note: str | None = Field(default=None, max_length=4000)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    password: str = Field(min_length=12, max_length=1024)
    role: Literal["security_admin", "soc_manager", "soc_analyst", "read_only_viewer"]


class UserActiveUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    is_active: bool


NmapPort = Annotated[int, Field(strict=True, ge=1, le=65535)]


class NmapScanCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str = Field(min_length=2, max_length=45)
    profile: Literal["common_ports", "selected_ports", "host_discovery"] = "common_ports"
    scan_type: Literal["tcp_connect", "syn"] = "tcp_connect"
    ports: list[NmapPort] | None = Field(default=None, min_length=1, max_length=256)
    service_detection: bool = False
    timeout_seconds: int = Field(default=60, ge=5, le=300)
    confirm_authorized: Literal[True]


def _record_audit(session: Session, entity_type: str, entity_id: str, action: str, actor: str, details: dict) -> None:
    session.add(
        AuditLogRow(
            id=str(uuid4()),
            entity_type=entity_type,
            entity_id=entity_id,
            action=action,
            actor=actor,
            details=details,
            created_at=datetime.now(timezone.utc),
        )
    )


def _incident_payload(row: IncidentRow) -> dict:
    return {
        "incident_id": row.id,
        "title": row.title,
        "description": row.description,
        "status": row.status,
        "assigned_to": row.assigned_to,
        "alert_ids": row.alert_ids,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
        "resolution": row.resolution,
    }


def _nmap_scan_payload(row: NmapScanRow, *, include_result: bool = True) -> dict:
    payload = {
        "scan_id": row.id,
        "target": row.target,
        "profile": row.profile,
        "scan_type": row.scan_type,
        "ports": row.ports,
        "service_detection": row.service_detection,
        "status": row.status,
        "started_at": row.started_at.isoformat(),
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "initiated_by": row.initiated_by,
        "error": row.error,
    }
    if include_result:
        payload["result"] = row.result
    return payload


def _validate_assignee(session: Session, username: str | None) -> None:
    if username is None:
        return
    normalized = username.strip().lower()
    user = session.scalar(select(UserRow).where(UserRow.username == normalized, UserRow.is_active.is_(True)))
    if user is None:
        raise HTTPException(status_code=422, detail="Assignee must be an active analyst account")


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_tables()
    yield


app = FastAPI(title="Port Scan Detection Lab API", version="0.1.0", description="Offline-first local SOC telemetry and detection API.", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(ALLOWED_ORIGINS),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


@app.middleware("http")
async def bound_ingestion_requests(request: Request, call_next):
    if request.url.path in {"/api/ingest/upload", "/api/ingest/pcap"} and request.method == "POST":
        if not request_limiter.allow("log-upload", _client_key(request), 10, 60):
            return JSONResponse(status_code=429, content={"detail": "Upload rate limit exceeded"})
        length = request.headers.get("content-length")
        if length is None:
            return JSONResponse(status_code=411, content={"detail": "Content-Length is required for log uploads"})
        try:
            request_length = int(length)
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
        if request_length > MAX_UPLOAD_REQUEST_BYTES:
            return JSONResponse(status_code=413, content={"detail": "Upload request exceeds the configured size limit"})
    return await call_next(request)


def get_db():
    with SessionLocal() as session:
        yield session


def get_current_user(
    request: Request,
    session: Annotated[Session, Depends(get_db)],
) -> UserRow:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    auth_session = session.get(AuthSessionRow, token_hash(token))
    now = datetime.now(timezone.utc)
    expires_at = auth_session.expires_at if auth_session is not None else None
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if auth_session is None or expires_at <= now:
        if auth_session is not None:
            session.delete(auth_session)
            session.commit()
        raise HTTPException(status_code=401, detail="Session is invalid or expired")
    user = session.get(UserRow, auth_session.user_id)
    if user is None or not user.is_active:
        session.delete(auth_session)
        session.commit()
        raise HTTPException(status_code=401, detail="Session is invalid or expired")
    origin = request.headers.get("origin")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if origin is not None and origin not in ALLOWED_ORIGINS:
            raise HTTPException(status_code=403, detail="Untrusted request origin")
        if not verify_csrf(auth_session, request.headers.get("X-CSRF-Token")):
            raise HTTPException(status_code=403, detail="CSRF token missing or invalid")
    return user


require_read = role_dependency(get_current_user, *READ_ROLES)
require_write = role_dependency(get_current_user, *WRITE_ROLES)
require_admin = role_dependency(get_current_user, *ADMIN_ROLES)
require_team_admin = role_dependency(get_current_user, *TEAM_ROLES)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _persist(session: Session, events: list[NetworkEvent]) -> tuple[int, list[dict]]:
    event_ids = {event.event_id for event in events}
    existing_ids: set[str] = set()
    all_ids = sorted(event_ids)
    for offset in range(0, len(all_ids), 500):
        existing_ids.update(
            session.scalars(
                select(EventRow.id).where(EventRow.id.in_(all_ids[offset : offset + 500]))
            ).all()
        )
    fresh: list[NetworkEvent] = []
    added_ids: set[str] = set()
    for event in events:
        identifier = event.event_id
        if identifier in added_ids or identifier in existing_ids:
            continue
        added_ids.add(identifier)
        fresh.append(event)
        session.add(
            EventRow(
                id=identifier,
                timestamp=event.timestamp,
                source_ip=str(event.source_ip),
                destination_ip=str(event.destination_ip),
                destination_port=event.destination_port,
                protocol=event.protocol,
                scenario_id=event.scenario_id,
                payload=event.model_dump(mode="json"),
            )
        )
    if not fresh:
        session.commit()
        return 0, []

    source_ips = {str(event.source_ip) for event in fresh}
    earliest = min(event.timestamp for event in fresh)
    latest = max(event.timestamp for event in fresh)
    context_rows: list[EventRow] = []
    sources = sorted(source_ips)
    for offset in range(0, len(sources), 500):
        context_rows.extend(
            session.scalars(
                select(EventRow).where(
                    EventRow.source_ip.in_(sources[offset : offset + 500]),
                    EventRow.timestamp >= earliest - timedelta(seconds=DETECTION_HISTORY_SECONDS),
                    EventRow.timestamp <= latest,
                )
                .order_by(EventRow.timestamp.desc())
                .limit(MAX_DETECTION_CONTEXT_EVENTS)
            ).all()
        )
    existing_events = [
        NetworkEvent.model_validate(row.payload)
        for row in context_rows
        if row.id not in added_ids
    ]
    alerts = detect_scans(
        [*existing_events, *fresh],
        threshold=DETECTION_THRESHOLD,
        allowlisted_sources=DETECTION_SOURCE_ALLOWLIST,
    )
    alert_rows = session.scalars(
        select(AlertRow)
        .where(AlertRow.source_ip.in_(source_ips))
        .order_by(AlertRow.timestamp.desc())
        .limit(MAX_DETECTION_CONTEXT_EVENTS)
    ).all()
    existing_by_key: dict[tuple[str, str, str], list[AlertRow]] = {}
    for row in alert_rows:
        key = (row.payload.get("rule_id", ""), row.payload.get("source_ip", ""), row.payload.get("destination_ip", ""))
        existing_by_key.setdefault(key, []).append(row)

    returned_alerts = []
    for alert in alerts:
        key = (alert.rule_id, alert.source_ip, alert.destination_ip)
        evidence = set(alert.evidence)
        matching_row = next(
            (
                row
                for row in existing_by_key.get(key, [])
                if evidence.intersection(row.payload.get("evidence", []))
            ),
            None,
        )
        payload = alert.model_dump(mode="json")
        if matching_row is not None:
            payload["alert_id"] = matching_row.id
            payload["status"] = matching_row.payload.get("status", alert.status)
            for preserved_field in ("assigned_to",):
                if preserved_field in matching_row.payload:
                    payload[preserved_field] = matching_row.payload[preserved_field]
            matching_row.payload = payload
            matching_row.severity = alert.severity
            matching_row.status = payload["status"]
            matching_row.timestamp = alert.last_seen
        else:
            matching_row = AlertRow(
                id=alert.alert_id,
                severity=alert.severity,
                status=alert.status,
                timestamp=alert.last_seen,
                source_ip=alert.source_ip,
                payload=payload,
            )
            session.add(matching_row)
            existing_by_key.setdefault(key, []).append(matching_row)
        returned_alerts.append(payload)
    session.commit()
    for integration_name in ("splunk", "elasticsearch"):
        deliver_records(
            session,
            integration_name,
            "network_event",
            [event.model_dump(mode="json") for event in fresh],
        )
        if returned_alerts:
            deliver_records(
                session,
                integration_name,
                "security_alert",
                returned_alerts,
            )
    return len(fresh), returned_alerts


@app.get("/health")
def health() -> dict:
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Database health check failed") from error
    return {"status": "ok", "mode": "offline-demo", "database": "connected"}


@app.post("/api/auth/login")
def login(credentials: LoginRequest, request: Request, response: Response, session: Annotated[Session, Depends(get_db)]) -> dict:
    if not request_limiter.allow("login-ip", _client_key(request), 10, 15 * 60):
        raise HTTPException(status_code=429, detail="Too many login attempts; try again later")
    username = credentials.username.strip().lower()
    if not request_limiter.allow("login-user", username, 8, 15 * 60):
        raise HTTPException(status_code=429, detail="Too many login attempts; try again later")
    origin = request.headers.get("origin")
    if origin is not None and origin not in ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Untrusted request origin")
    user = session.scalar(select(UserRow).where(UserRow.username == username))
    if user is None or not user.is_active or not verify_password(
        credentials.password,
        user.password_hash if user is not None else "$invalid$0$0$0$$",
    ):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token, csrf_token, _ = new_session(session, user)
    _record_audit(session, "user", user.id, "login", user.username, {})
    session.commit()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_SECONDS,
        httponly=True,
        secure=AUTH_COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    return {"user": {"username": user.username, "role": user.role}, "csrf_token": csrf_token}


@app.get("/api/auth/me")
def current_user(user: Annotated[UserRow, Depends(get_current_user)]) -> dict:
    return {"username": user.username, "role": user.role}


@app.get("/api/auth/csrf")
def rotate_csrf(
    request: Request,
    user: Annotated[UserRow, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    token = request.cookies.get(SESSION_COOKIE)
    auth_session = session.get(AuthSessionRow, token_hash(token or ""))
    if auth_session is None or auth_session.user_id != user.id:
        raise HTTPException(status_code=401, detail="Session is invalid or expired")
    csrf_token = secrets.token_urlsafe(32)
    auth_session.csrf_hash = token_hash(csrf_token)
    session.commit()
    return {"csrf_token": csrf_token}


@app.post("/api/auth/logout")
def logout(
    request: Request,
    response: Response,
    user: Annotated[UserRow, Depends(get_current_user)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        auth_session = session.get(AuthSessionRow, token_hash(token))
        if auth_session is not None:
            session.delete(auth_session)
    _record_audit(session, "user", user.id, "logout", user.username, {})
    session.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=AUTH_COOKIE_SECURE, samesite="strict")
    return {"status": "logged_out"}


@app.get("/api/users")
def list_users(
    _: Annotated[UserRow, Depends(require_admin)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    users = session.scalars(select(UserRow).order_by(UserRow.username)).all()
    return {
        "items": [
            {"user_id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active}
            for user in users
        ]
    }


@app.get("/api/analysts")
def list_analysts(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    analysts = session.scalars(
        select(UserRow)
        .where(UserRow.role.in_(["soc_analyst", "soc_manager"]), UserRow.is_active.is_(True))
        .order_by(UserRow.username)
    ).all()
    return {"items": [{"username": user.username, "role": user.role} for user in analysts]}


@app.post("/api/users", status_code=201)
def add_user(
    user_data: UserCreate,
    actor: Annotated[UserRow, Depends(require_team_admin)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    if actor.role == "soc_manager" and user_data.role not in {"soc_analyst", "read_only_viewer"}:
        raise HTTPException(status_code=403, detail="SOC managers may only create analyst and viewer accounts")
    try:
        user = create_user(session, user_data.username, user_data.password, user_data.role)
    except ValueError as error:
        raise HTTPException(status_code=409 if "already exists" in str(error) else 422, detail=str(error)) from error
    _record_audit(session, "user", user.id, "created", actor.username, {"role": user.role})
    session.commit()
    return {"user_id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active}


@app.patch("/api/users/{user_id}")
def set_user_active(
    user_id: str,
    update: UserActiveUpdate,
    actor: Annotated[UserRow, Depends(require_admin)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    user = session.get(UserRow, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not update.is_active and user.id == actor.id:
        raise HTTPException(status_code=422, detail="You cannot deactivate your own account")
    if not update.is_active and user.role in ADMIN_ROLES:
        active_admins = session.scalar(
            select(func.count()).select_from(UserRow).where(UserRow.role.in_(ADMIN_ROLES), UserRow.is_active.is_(True))
        ) or 0
        if active_admins <= 1:
            raise HTTPException(status_code=422, detail="Cannot deactivate the last active administrator")
    user.is_active = update.is_active
    if not user.is_active:
        session.execute(delete(AuthSessionRow).where(AuthSessionRow.user_id == user.id))
    _record_audit(session, "user", user.id, "active_status_changed", actor.username, {"is_active": user.is_active})
    session.commit()
    return {"user_id": user.id, "username": user.username, "role": user.role, "is_active": user.is_active}


@app.get("/api/dashboard/summary")
def dashboard_summary(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    return _dashboard_summary(session)


def _dashboard_summary(session: Session) -> dict:
    event_count = session.scalar(select(func.count()).select_from(EventRow)) or 0
    alert_count = session.scalar(select(func.count()).select_from(AlertRow)) or 0
    severity_rows = session.execute(select(AlertRow.severity, func.count()).group_by(AlertRow.severity)).all()
    severities = dict(severity_rows)
    distinct_source_ips = session.scalar(select(func.count(func.distinct(EventRow.source_ip)))) or 0
    distinct_destinations = session.scalar(select(func.count(func.distinct(EventRow.destination_ip)))) or 0
    distinct_ports = session.scalar(select(func.count(func.distinct(EventRow.destination_port))).where(EventRow.destination_port.is_not(None))) or 0
    simulated_count = session.scalar(
        select(func.count()).select_from(EventRow).where(EventRow.payload["sensor_type"].as_string() == "simulator")
    ) or 0
    active_incidents = session.scalar(
        select(func.count()).select_from(IncidentRow).where(IncidentRow.status.not_in(["Resolved", "Closed"]))
    ) or 0
    return {
        "total_events": event_count,
        "total_alerts": alert_count,
        "critical_alerts": severities.get("Critical", 0),
        "high_alerts": severities.get("High", 0),
        "unique_source_ips": distinct_source_ips,
        "targeted_hosts": distinct_destinations,
        "unique_destination_ports": distinct_ports,
        "simulated_events": simulated_count,
        "active_incidents": active_incidents,
        "severity_distribution": severities,
        "data_mode": "simulated and offline ingested telemetry",
    }


@app.get("/api/events")
def list_events(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    source_ip: str | None = None,
    protocol: Literal["tcp", "udp", "icmp", "other"] | None = None,
) -> dict:
    filters = []
    if source_ip:
        filters.append(EventRow.source_ip == source_ip)
    if protocol:
        filters.append(EventRow.protocol == protocol)
    query = select(EventRow).where(*filters).order_by(EventRow.timestamp.desc()).limit(limit).offset(offset)
    rows = session.scalars(query).all()
    total = session.scalar(select(func.count()).select_from(EventRow).where(*filters)) or 0
    return {"items": [row.payload for row in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/alerts")
def list_alerts(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    rows = session.scalars(select(AlertRow).order_by(AlertRow.timestamp.desc()).limit(limit).offset(offset)).all()
    total = session.scalar(select(func.count()).select_from(AlertRow)) or 0
    return {"items": [row.payload for row in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/alerts/{alert_id}")
def get_alert(
    alert_id: str,
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    row = session.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    evidence_ids = row.payload.get("evidence", [])
    evidence = session.scalars(select(EventRow).where(EventRow.id.in_(evidence_ids))).all() if evidence_ids else []
    audit = session.scalars(
        select(AuditLogRow).where(AuditLogRow.entity_type == "alert", AuditLogRow.entity_id == alert_id).order_by(AuditLogRow.created_at)
    ).all()
    return {
        "alert": row.payload,
        "evidence": [event.payload for event in evidence],
        "audit_trail": [
            {"action": item.action, "actor": item.actor, "details": item.details, "created_at": item.created_at.isoformat()}
            for item in audit
        ],
    }


@app.patch("/api/alerts/{alert_id}")
def update_alert(
    alert_id: str,
    update: AlertUpdate,
    actor: Annotated[UserRow, Depends(require_write)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    row = session.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one alert field must be updated")
    note = changes.pop("note", None)
    if "assigned_to" in changes:
        _validate_assignee(session, changes["assigned_to"])
    payload = dict(row.payload)
    payload.update(changes)
    row.payload = payload
    row.status = payload.get("status", row.status)
    row.severity = payload.get("severity", row.severity)
    _record_audit(session, "alert", alert_id, "updated", actor.username, {"changes": changes, "note": note})
    session.commit()
    return payload


@app.post("/api/incidents", status_code=201)
def create_incident(
    request: IncidentCreate,
    actor: Annotated[UserRow, Depends(require_write)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    alert = session.get(AlertRow, request.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    _validate_assignee(session, request.assigned_to)
    now = datetime.now(timezone.utc)
    incident = IncidentRow(
        id=str(uuid4()),
        title=request.title.strip(),
        description=request.description,
        status="New",
        assigned_to=request.assigned_to,
        alert_ids=[request.alert_id],
        created_at=now,
        updated_at=now,
    )
    if not incident.title:
        raise HTTPException(status_code=422, detail="Incident title must not be blank")
    session.add(incident)
    _record_audit(session, "incident", incident.id, "created", actor.username, {"alert_id": request.alert_id})
    session.commit()
    return _incident_payload(incident)


@app.get("/api/incidents")
def list_incidents(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    rows = session.scalars(select(IncidentRow).order_by(IncidentRow.updated_at.desc()).limit(limit).offset(offset)).all()
    total = session.scalar(select(func.count()).select_from(IncidentRow)) or 0
    return {"items": [_incident_payload(row) for row in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    row = session.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    alerts = session.scalars(select(AlertRow).where(AlertRow.id.in_(row.alert_ids))).all() if row.alert_ids else []
    audit = session.scalars(
        select(AuditLogRow).where(AuditLogRow.entity_type == "incident", AuditLogRow.entity_id == incident_id).order_by(AuditLogRow.created_at)
    ).all()
    return {
        "incident": _incident_payload(row),
        "alerts": [alert.payload for alert in alerts],
        "audit_trail": [
            {"action": item.action, "actor": item.actor, "details": item.details, "created_at": item.created_at.isoformat()}
            for item in audit
        ],
    }


@app.patch("/api/incidents/{incident_id}")
def update_incident(
    incident_id: str,
    update: IncidentUpdate,
    actor: Annotated[UserRow, Depends(require_write)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    row = session.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one incident field must be updated")
    if changes.get("resolution", "not-supplied") is None:
        changes.pop("resolution")
    if "assigned_to" in changes:
        _validate_assignee(session, changes["assigned_to"])
    resolution = changes.get("resolution", row.resolution)
    if changes.get("status") in {"Resolved", "Closed"} and not (resolution and resolution.strip()):
        raise HTTPException(status_code=422, detail="A resolution is required before resolving or closing an incident")
    note = changes.pop("note", None)
    previous_status = row.status
    for key, value in changes.items():
        setattr(row, key, value)
    row.updated_at = datetime.now(timezone.utc)
    _record_audit(
        session,
        "incident",
        incident_id,
        "status_changed" if row.status != previous_status else "updated",
        actor.username,
        {"changes": changes, "note": note},
    )
    session.commit()
    return _incident_payload(row)


@app.get("/api/nmap/status")
def nmap_status(_: Annotated[UserRow, Depends(require_admin)]) -> dict:
    try:
        configuration = load_nmap_configuration()
    except NmapConfigurationError:
        return {
            "available": False,
            "enabled": False,
            "authorized_network_count": 0,
            "status": "invalid_authorization_configuration",
        }
    if configuration.executable is None:
        status = "nmap_not_installed"
    elif not configuration.authorized_networks:
        status = "authorized_targets_not_configured"
    else:
        status = "ready"
    return {
        "available": configuration.executable is not None,
        "enabled": configuration.enabled,
        "authorized_network_count": len(configuration.authorized_networks),
        "status": status,
    }


@app.get("/api/scans")
def list_nmap_scans(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict:
    scans = session.scalars(
        select(NmapScanRow)
        .order_by(NmapScanRow.started_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {"items": [_nmap_scan_payload(scan, include_result=False) for scan in scans]}


@app.get("/api/scans/{scan_id}")
def get_nmap_scan(
    scan_id: str,
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    scan = session.get(NmapScanRow, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _nmap_scan_payload(scan)


@app.post("/api/scans", status_code=201)
def create_nmap_scan(
    scan_request: NmapScanCreate,
    request: Request,
    actor: Annotated[UserRow, Depends(require_admin)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    if not request_limiter.allow("nmap-scan", actor.id, 3, 60 * 60):
        raise HTTPException(status_code=429, detail="Nmap scan rate limit exceeded")
    try:
        configuration = load_nmap_configuration()
    except NmapConfigurationError as error:
        raise HTTPException(status_code=503, detail="Nmap authorization configuration is invalid") from error
    if not configuration.enabled:
        raise HTTPException(
            status_code=503,
            detail="Active scanning is disabled until Nmap is installed and authorized lab CIDRs are configured",
        )
    try:
        command = build_command(
            target=scan_request.target,
            profile=scan_request.profile,
            scan_type=scan_request.scan_type,
            ports=scan_request.ports,
            service_detection=scan_request.service_detection,
            configuration=configuration,
        )
    except NmapConfigurationError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if not SCAN_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Another Nmap scan is already running")

    scan_ports = (
        list(COMMON_PORTS)
        if scan_request.profile == "common_ports"
        else sorted(scan_request.ports or [])
        if scan_request.profile == "selected_ports"
        else []
    )
    now = datetime.now(timezone.utc)
    row = NmapScanRow(
        id=str(uuid4()),
        target=command[-1],
        profile=scan_request.profile,
        scan_type=scan_request.scan_type,
        ports=scan_ports,
        service_detection=scan_request.service_detection,
        status="running",
        started_at=now,
        completed_at=None,
        initiated_by=actor.username,
        result=None,
        error=None,
    )
    session.add(row)
    _record_audit(
        session,
        "nmap_scan",
        row.id,
        "started",
        actor.username,
        {"target": row.target, "profile": row.profile, "scan_type": row.scan_type},
    )
    session.commit()
    try:
        try:
            row.result = execute_command(command, scan_request.timeout_seconds)
            row.status = "completed"
        except (NmapExecutionError, NmapUnavailable) as error:
            row.status = "failed"
            row.error = str(error)[:240]
        row.completed_at = datetime.now(timezone.utc)
        _record_audit(
            session,
            "nmap_scan",
            row.id,
            row.status,
            actor.username,
            {"target": row.target, "status": row.status},
        )
        session.commit()
        return _nmap_scan_payload(row)
    finally:
        SCAN_LOCK.release()


@app.get("/api/reports/summary")
def summary_report(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    summary = _dashboard_summary(session)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "period": "all retained local records",
        "summary": summary,
        "recent_alerts": [
            row.payload
            for row in session.scalars(select(AlertRow).order_by(AlertRow.timestamp.desc()).limit(100)).all()
        ],
        "incidents": [
            _incident_payload(row)
            for row in session.scalars(select(IncidentRow).order_by(IncidentRow.updated_at.desc()).limit(100)).all()
        ],
    }


@app.get("/api/reports/summary.csv")
def summary_report_csv(
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
) -> Response:
    summary = _dashboard_summary(session)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["metric", "value"])
    for key, value in summary.items():
        if isinstance(value, dict):
            for subkey, subvalue in value.items():
                writer.writerow([f"{key}.{subkey}", subvalue])
        else:
            writer.writerow([key, value])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc-summary.csv"'},
    )


@app.get("/api/integrations")
def list_integrations(
    _: Annotated[UserRow, Depends(require_admin)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    deliveries = session.scalars(
        select(IntegrationDeliveryRow)
        .order_by(IntegrationDeliveryRow.updated_at.desc())
        .limit(50)
    ).all()
    return {
        "integrations": integration_status(),
        "recent_deliveries": [
            {
                "delivery_id": item.id,
                "integration": item.integration,
                "record_type": item.record_type,
                "record_count": len(item.record_ids),
                "status": item.status,
                "attempts": item.attempts,
                "http_status": item.http_status,
                "error": item.error,
                "created_at": item.created_at.isoformat(),
                "updated_at": item.updated_at.isoformat(),
            }
            for item in deliveries
        ],
    }


@app.post("/api/integrations/{integration_name}/test")
def test_integration(
    integration_name: str,
    request: Request,
    actor: Annotated[UserRow, Depends(require_admin)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    if integration_name not in {"splunk", "elasticsearch"}:
        raise HTTPException(status_code=404, detail="Integration not found")
    if not request_limiter.allow("integration-test", actor.id, 5, 60 * 60):
        raise HTTPException(status_code=429, detail="Integration test rate limit exceeded")
    try:
        delivery = send_test_event(session, cast(IntegrationName, integration_name))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    _record_audit(
        session,
        "integration",
        delivery.id,
        "test_delivery",
        actor.username,
        {
            "integration": integration_name,
            "status": delivery.status,
            "http_status": delivery.http_status,
        },
    )
    session.commit()
    return {
        "integration": integration_name,
        "status": delivery.status,
        "attempts": delivery.attempts,
        "http_status": delivery.http_status,
        "error": delivery.error,
    }


@app.post("/api/integrations/deliveries/{delivery_id}/retry")
def retry_integration_delivery(
    delivery_id: str,
    request: Request,
    actor: Annotated[UserRow, Depends(require_admin)],
    session: Annotated[Session, Depends(get_db)],
) -> dict:
    if not request_limiter.allow("integration-retry", actor.id, 10, 60 * 60):
        raise HTTPException(status_code=429, detail="Integration retry rate limit exceeded")
    try:
        delivery = retry_delivery(session, delivery_id)
    except LookupError as error:
        raise HTTPException(status_code=404, detail=str(error)) from error
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    _record_audit(
        session,
        "integration",
        delivery.id,
        "delivery_retry",
        actor.username,
        {
            "integration": delivery.integration,
            "status": delivery.status,
            "http_status": delivery.http_status,
        },
    )
    session.commit()
    return {
        "integration": delivery.integration,
        "status": delivery.status,
        "attempts": delivery.attempts,
        "http_status": delivery.http_status,
        "error": delivery.error,
    }


@app.get("/api/reports/summary.pdf")
def summary_report_pdf(
    request: Request,
    _: Annotated[UserRow, Depends(require_read)],
    session: Annotated[Session, Depends(get_db)],
    period: ReportPeriod = Query(default="all"),
    download: bool = Query(default=True),
) -> Response:
    if not request_limiter.allow("pdf-report", _client_key(request), 20, 60):
        raise HTTPException(status_code=429, detail="Report generation rate limit exceeded")
    content = generate_soc_pdf(session, period)
    disposition = "attachment" if download else "inline"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'{disposition}; filename="sentinelsoc-{period}-report.pdf"'},
    )


@app.post("/api/demo/generate")
def generate_demo(
    _: Annotated[UserRow, Depends(require_write)],
    session: Annotated[Session, Depends(get_db)],
    scenario: str = Query(default="syn"),
    count: int = Query(default=40, ge=1, le=5000),
    seed: int | None = Query(default=None, ge=0, le=4294967295),
) -> dict:
    if scenario not in SCENARIOS:
        raise HTTPException(status_code=422, detail=f"scenario must be one of: {', '.join(sorted(SCENARIOS))}")
    seed = seed if seed is not None else secrets.randbelow(2**32)
    events = generate_events(count=count, scenario=scenario, seed=seed)
    ingested, alerts = _persist(session, events)
    return {"accepted": ingested, "scenario": scenario, "seed": seed, "simulated": True, "alerts": alerts}


@app.post("/api/ingest/upload")
async def ingest_upload(
    _: Annotated[UserRow, Depends(require_write)],
    session: Annotated[Session, Depends(get_db)],
    file: Annotated[UploadFile, File()],
    format_name: Annotated[Literal["zeek", "suricata", "firewall"], Query(alias="format")],
) -> dict:
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 5 MiB limit")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=400, detail="Log file must be UTF-8 text") from error
    record_count = len(text.splitlines())
    if record_count > MAX_UPLOAD_RECORDS:
        raise HTTPException(status_code=413, detail=f"Upload exceeds the {MAX_UPLOAD_RECORDS} record limit")
    events, errors = parse_log(text, format_name, source_file=(file.filename or "upload").replace("\\", "/").split("/")[-1][:255])
    if not events and errors:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "No valid records found",
                "errors": errors[:MAX_PARSE_ERRORS_RETURNED],
                "error_count": len(errors),
                "errors_truncated": len(errors) > MAX_PARSE_ERRORS_RETURNED,
            },
        )
    ingested, alerts = _persist(session, events)
    return {
        "accepted": ingested,
        "parsed": len(events),
        "duplicates": len(events) - ingested,
        "parse_errors": errors[:MAX_PARSE_ERRORS_RETURNED],
        "parse_error_count": len(errors),
        "parse_errors_truncated": len(errors) > MAX_PARSE_ERRORS_RETURNED,
        "alerts": alerts,
    }


@app.post("/api/ingest/pcap")
async def ingest_pcap(
    _: Annotated[UserRow, Depends(require_write)],
    session: Annotated[Session, Depends(get_db)],
    file: Annotated[UploadFile, File()],
) -> dict:
    try:
        content = await file.read(MAX_UPLOAD_BYTES + 1)
    finally:
        await file.close()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Capture exceeds the 5 MiB limit")
    filename = (file.filename or "upload.pcap").replace("\\", "/").split("/")[-1][:255]
    try:
        events, malformed = parse_pcap(content, filename)
    except PcapRecordLimitError as error:
        raise HTTPException(status_code=413, detail=str(error)) from error
    except PcapFormatError as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
    if not events and malformed:
        raise HTTPException(status_code=422, detail="Capture contained no supported valid network packets")
    ingested, alerts = _persist(session, events)
    return {
        "accepted": ingested,
        "parsed": len(events),
        "duplicates": len(events) - ingested,
        "malformed_packets": malformed,
        "alerts": alerts,
    }