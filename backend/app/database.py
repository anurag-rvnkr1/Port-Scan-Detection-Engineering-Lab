from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import JSON, DateTime, Float, Integer, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


DATABASE_URL = os.getenv("LAB_DATABASE_URL", "sqlite:///./data/soc_lab.db")
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
    timestamp: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
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
    timestamp: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str] = mapped_column(String(45), index=True)
    payload: Mapped[dict] = mapped_column(JSON)


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)
