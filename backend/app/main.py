from __future__ import annotations

from contextlib import asynccontextmanager
from collections import Counter
import os
import secrets
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.database import AlertRow, EventRow, SessionLocal, create_tables
from backend.app.generator import SCENARIOS, generate_events
from backend.app.pipeline import detect_scans, parse_log
from backend.app.schemas import NetworkEvent


MAX_UPLOAD_BYTES = 5 * 1024 * 1024


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_tables()
    yield


app = FastAPI(title="Port Scan Detection Lab API", version="0.1.0", description="Offline-first local SOC telemetry and detection API.", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("LAB_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


def get_db():
    with SessionLocal() as session:
        yield session


def _persist(session: Session, events: list[NetworkEvent]) -> tuple[int, list[dict]]:
    fresh: list[NetworkEvent] = []
    added_ids: set[str] = set()
    for event in events:
        identifier = event.event_id
        if identifier in added_ids or session.get(EventRow, identifier) is not None:
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
    alerts = detect_scans(fresh)
    for alert in alerts:
        if session.get(AlertRow, alert.alert_id) is None:
            session.add(AlertRow(id=alert.alert_id, severity=alert.severity, status=alert.status, timestamp=alert.last_seen, source_ip=alert.source_ip, payload=alert.model_dump(mode="json")))
    session.commit()
    return len(fresh), [alert.model_dump(mode="json") for alert in alerts]


@app.get("/health")
def health() -> dict:
    try:
        with SessionLocal() as session:
            session.execute(text("SELECT 1"))
    except SQLAlchemyError as error:
        raise HTTPException(status_code=503, detail="Database health check failed") from error
    return {"status": "ok", "mode": "offline-demo", "database": "connected"}


@app.get("/api/dashboard/summary")
def dashboard_summary(session: Annotated[Session, Depends(get_db)]) -> dict:
    event_count = session.scalar(select(func.count()).select_from(EventRow)) or 0
    alert_rows = session.scalars(select(AlertRow)).all()
    event_rows = session.scalars(select(EventRow)).all()
    severities = Counter(row.severity for row in alert_rows)
    return {
        "total_events": event_count,
        "total_alerts": len(alert_rows),
        "critical_alerts": severities.get("Critical", 0),
        "high_alerts": severities.get("High", 0),
        "unique_source_ips": len({row.source_ip for row in event_rows}),
        "targeted_hosts": len({row.destination_ip for row in event_rows}),
        "unique_destination_ports": len({row.destination_port for row in event_rows if row.destination_port is not None}),
        "simulated_events": sum(1 for row in event_rows if row.payload.get("sensor_type") == "simulator"),
        "severity_distribution": dict(severities),
        "data_mode": "simulated and offline ingested telemetry",
    }


@app.get("/api/events")
def list_events(
    session: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    source_ip: str | None = None,
    protocol: Literal["tcp", "udp", "icmp", "other"] | None = None,
) -> dict:
    query = select(EventRow).order_by(EventRow.timestamp.desc()).limit(limit).offset(offset)
    if source_ip:
        query = query.where(EventRow.source_ip == source_ip)
    if protocol:
        query = query.where(EventRow.protocol == protocol)
    rows = session.scalars(query).all()
    return {"items": [row.payload for row in rows], "limit": limit, "offset": offset}


@app.get("/api/alerts")
def list_alerts(session: Annotated[Session, Depends(get_db)], limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)) -> dict:
    rows = session.scalars(select(AlertRow).order_by(AlertRow.timestamp.desc()).limit(limit).offset(offset)).all()
    return {"items": [row.payload for row in rows], "limit": limit, "offset": offset}


@app.post("/api/demo/generate")
def generate_demo(
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
    session: Annotated[Session, Depends(get_db)],
    file: Annotated[UploadFile, File()],
    format_name: Annotated[Literal["zeek", "suricata", "firewall"], Query(alias="format")],
) -> dict:
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="Upload exceeds the 5 MiB limit")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=400, detail="Log file must be UTF-8 text") from error
    events, errors = parse_log(text, format_name, source_file=(file.filename or "upload").replace("\\", "/").split("/")[-1][:255])
    if not events and errors:
        raise HTTPException(status_code=422, detail={"message": "No valid records found", "errors": errors[:20], "error_count": len(errors)})
    ingested, alerts = _persist(session, events)
    return {"accepted": ingested, "parsed": len(events), "duplicates": len(events) - ingested, "parse_errors": errors, "alerts": alerts}