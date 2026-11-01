from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import BigInteger, JSON, DateTime, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


DATABASE_URL = os.getenv("LAB_DATABASE_URL", "sqlite:///./data/soc_lab.db")
_MIGRATIONS_SETTING = os.getenv("LAB_USE_MIGRATIONS", "false").strip().lower()
if _MIGRATIONS_SETTING not in {"0", "1", "false", "true", "no", "yes"}:
    raise RuntimeError("LAB_USE_MIGRATIONS must be true or false")
USE_DATABASE_MIGRATIONS = _MIGRATIONS_SETTING in {"1", "true", "yes"}
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)
if DATABASE_URL.startswith("sqlite:///"):
    Path(DATABASE_URL.removeprefix("sqlite:///" )).parent.mkdir(parents=True, exist_ok=True)

engine_options = {"connect_args": {"check_same_thread": False}} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, **engine_options)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "network_events"

    id: Mapped[str] = mapped_column(String(128), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_ip: Mapped[str] = mapped_column(String(45), index=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    protocol: Mapped[str] = mapped_column(String(12), index=True)
    scenario_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON)


class AlertRow(Base):
    __tablename__ = "security_alerts"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    severity: Mapped[str] = mapped_column(String(20), index=True)
    status: Mapped[str] = mapped_column(String(24), default="New", index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class IncidentRow(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(4000), default="")
    status: Mapped[str] = mapped_column(String(24), default="New", index=True)
    assigned_to: Mapped[str | None] = mapped_column(String(120), nullable=True)
    alert_ids: Mapped[list[str]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    resolution: Mapped[str | None] = mapped_column(String(4000), nullable=True)


class AuditLogRow(Base):
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    entity_type: Mapped[str] = mapped_column(String(24), index=True)
    entity_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(80))
    actor: Mapped[str] = mapped_column(String(120))
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class UserRow(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[str] = mapped_column(String(32), index=True)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class AuthSessionRow(Base):
    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class IntegrationDeliveryRow(Base):
    __tablename__ = "integration_deliveries"
    __table_args__ = (UniqueConstraint("batch_key", name="uq_integration_delivery_batch_key"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    integration: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    record_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    record_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(String(240), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


class NmapScanRow(Base):
    __tablename__ = "nmap_scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(45), index=True)
    profile: Mapped[str] = mapped_column(String(24))
    scan_type: Mapped[str] = mapped_column(String(24))
    ports: Mapped[list[int]] = mapped_column(JSON)
    service_detection: Mapped[bool]
    status: Mapped[str] = mapped_column(String(16), index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(64), index=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(String(240), nullable=True)


class SensorRow(Base):
    __tablename__ = "sensors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    sensor_type: Mapped[str] = mapped_column(String(16), index=True)
    log_path: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(16), index=True)
    cursor_offset: Mapped[int] = mapped_column(BigInteger, default=0)
    file_identity: Mapped[str | None] = mapped_column(String(128), nullable=True)
    pending_line: Mapped[str] = mapped_column(Text, default="")
    zeek_header: Mapped[str | None] = mapped_column(Text, nullable=True)
    processed_records: Mapped[int] = mapped_column(Integer, default=0)
    parse_error_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(240), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


def create_tables() -> None:
    if not USE_DATABASE_MIGRATIONS:
        Base.metadata.create_all(bind=engine)
