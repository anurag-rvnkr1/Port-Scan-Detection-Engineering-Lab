from __future__ import annotations

from contextlib import asynccontextmanager
import csv
from datetime import datetime, timedelta, timezone
import io
import os
import secrets
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, File, HTTPException, Query, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.database import AlertRow, AuditLogRow, EventRow, IncidentRow, SessionLocal, create_tables
from backend.app.generator import SCENARIOS, generate_events
from backend.app.pipeline import detect_scans, parse_log
from backend.app.schemas import NetworkEvent


MAX_UPLOAD_BYTES = 5 * 1024 * 1024
DETECTION_HISTORY_SECONDS = 60 * 60


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


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_tables()
    yield


app = FastAPI(title="Port Scan Detection Lab API", version="0.1.0", description="Offline-first local SOC telemetry and detection API.", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("LAB_CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",") if origin.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
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
            ).all()
        )
    existing_events = [
        NetworkEvent.model_validate(row.payload)
        for row in context_rows
        if row.id not in added_ids
    ]
    alerts = detect_scans([*existing_events, *fresh])
    alert_rows = session.scalars(select(AlertRow).where(AlertRow.source_ip.in_(source_ips))).all()
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
    return len(fresh), returned_alerts


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
def list_alerts(session: Annotated[Session, Depends(get_db)], limit: int = Query(default=100, ge=1, le=500), offset: int = Query(default=0, ge=0)) -> dict:
    rows = session.scalars(select(AlertRow).order_by(AlertRow.timestamp.desc()).limit(limit).offset(offset)).all()
    total = session.scalar(select(func.count()).select_from(AlertRow)) or 0
    return {"items": [row.payload for row in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str, session: Annotated[Session, Depends(get_db)]) -> dict:
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
def update_alert(alert_id: str, update: AlertUpdate, session: Annotated[Session, Depends(get_db)]) -> dict:
    row = session.get(AlertRow, alert_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one alert field must be updated")
    note = changes.pop("note", None)
    payload = dict(row.payload)
    payload.update({key: value for key, value in changes.items() if key != "assigned_to"})
    if "assigned_to" in changes:
        payload["assigned_to"] = changes["assigned_to"]
    row.payload = payload
    row.status = payload.get("status", row.status)
    row.severity = payload.get("severity", row.severity)
    _record_audit(session, "alert", alert_id, "updated", "local-analyst", {"changes": changes, "note": note})
    session.commit()
    return payload


@app.post("/api/incidents", status_code=201)
def create_incident(request: IncidentCreate, session: Annotated[Session, Depends(get_db)]) -> dict:
    alert = session.get(AlertRow, request.alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
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
    _record_audit(session, "incident", incident.id, "created", "local-analyst", {"alert_id": request.alert_id})
    session.commit()
    return _incident_payload(incident)


@app.get("/api/incidents")
def list_incidents(
    session: Annotated[Session, Depends(get_db)],
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> dict:
    rows = session.scalars(select(IncidentRow).order_by(IncidentRow.updated_at.desc()).limit(limit).offset(offset)).all()
    total = session.scalar(select(func.count()).select_from(IncidentRow)) or 0
    return {"items": [_incident_payload(row) for row in rows], "total": total, "limit": limit, "offset": offset}


@app.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str, session: Annotated[Session, Depends(get_db)]) -> dict:
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
def update_incident(incident_id: str, update: IncidentUpdate, session: Annotated[Session, Depends(get_db)]) -> dict:
    row = session.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    changes = update.model_dump(exclude_unset=True)
    if not changes:
        raise HTTPException(status_code=422, detail="At least one incident field must be updated")
    if changes.get("resolution", "not-supplied") is None:
        changes.pop("resolution")
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
        "local-analyst",
        {"changes": changes, "note": note},
    )
    session.commit()
    return _incident_payload(row)


@app.get("/api/reports/summary")
def summary_report(session: Annotated[Session, Depends(get_db)]) -> dict:
    summary = dashboard_summary(session)
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
def summary_report_csv(session: Annotated[Session, Depends(get_db)]) -> Response:
    summary = dashboard_summary(session)
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
    events, errors = parse_log(text, format_name, source_file=(file.filename or "upload").replace("\\", "/").split("/")[-1][:255])
    if not events and errors:
        raise HTTPException(status_code=422, detail={"message": "No valid records found", "errors": errors[:20], "error_count": len(errors)})
    ingested, alerts = _persist(session, events)
    return {"accepted": ingested, "parsed": len(events), "duplicates": len(events) - ingested, "parse_errors": errors, "alerts": alerts}