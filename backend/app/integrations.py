from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database import IntegrationDeliveryRow


LOGGER = logging.getLogger(__name__)
IntegrationName = Literal["splunk", "elasticsearch"]
RecordType = Literal["network_event", "security_alert", "test_event"]
MAX_BATCH_RECORDS = 250
MAX_RETRIES = 3
REQUEST_TIMEOUT_SECONDS = 5.0
INDEX_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")


@dataclass(frozen=True)
class IntegrationConfig:
    name: IntegrationName
    endpoint: str
    secret: str
    index: str | None = None


@dataclass(frozen=True)
class DeliveryResult:
    status: Literal["delivered", "failed", "skipped"]
    attempts: int
    http_status: int | None
    error: str | None


def _validate_endpoint(value: str, *, allow_path: bool) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("Integration endpoint must be an absolute HTTPS URL")
    if parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment:
        raise ValueError("Integration endpoint must not contain credentials, query, or fragment")
    if parsed.scheme == "http":
        hostname = parsed.hostname.lower()
        try:
            is_loopback = hostname == "localhost" or ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = False
        if not is_loopback:
            raise ValueError("Unencrypted integration endpoints are allowed only on loopback")
    if not allow_path and parsed.path not in {"", "/"}:
        raise ValueError("Elasticsearch URL must be an origin without a path")
    return value.rstrip("/")


def load_config(name: IntegrationName) -> IntegrationConfig | None:
    if name == "splunk":
        endpoint = os.getenv("SENTINELSOC_SPLUNK_HEC_URL", "").strip()
        secret = os.getenv("SENTINELSOC_SPLUNK_HEC_TOKEN", "").strip()
        if not endpoint and not secret:
            return None
        if not endpoint or not secret:
            raise ValueError("Splunk HEC URL and token must both be configured")
        endpoint = _validate_endpoint(endpoint, allow_path=True)
        if not urlsplit(endpoint).path.rstrip("/").endswith("/services/collector/event"):
            raise ValueError("Splunk HEC URL must end in /services/collector/event")
        return IntegrationConfig(name=name, endpoint=endpoint, secret=secret)

    endpoint = os.getenv("SENTINELSOC_ELASTICSEARCH_URL", "").strip()
    secret = os.getenv("SENTINELSOC_ELASTICSEARCH_API_KEY", "").strip()
    index = os.getenv("SENTINELSOC_ELASTICSEARCH_INDEX", "sentinelsoc-events").strip()
    if not endpoint and not secret:
        return None
    if not endpoint or not secret:
        raise ValueError("Elasticsearch URL and API key must both be configured")
    endpoint = _validate_endpoint(endpoint, allow_path=False)
    if not INDEX_PATTERN.fullmatch(index):
        raise ValueError("Elasticsearch index must be lowercase and contain only letters, digits, dot, underscore, or hyphen")
    return IntegrationConfig(name=name, endpoint=endpoint, secret=secret, index=index)


def integration_status() -> dict[str, dict[str, str | bool]]:
    status: dict[str, dict[str, str | bool]] = {}
    for name in ("splunk", "elasticsearch"):
        try:
            configured = load_config(name) is not None
            status[name] = {"configured": configured, "status": "configured" if configured else "disabled"}
        except ValueError:
            status[name] = {"configured": False, "status": "invalid_configuration"}
    return status


def _batch_key(name: IntegrationName, kind: RecordType, records: list[dict]) -> str:
    identifiers = sorted(str(record.get("event_id") or record.get("alert_id")) for record in records)
    value = f"{name}:{kind}:{','.join(identifiers)}"
    return hashlib.sha256(value.encode()).hexdigest()


def _splunk_body(kind: RecordType, records: list[dict]) -> bytes:
    source = f"sentinelsoc:{kind}"
    lines = [
        json.dumps(
            {
                "time": _timestamp(record),
                "host": "sentinelsoc",
                "source": source,
                "sourcetype": "_json",
                "event": record,
            },
            separators=(",", ":"),
        )
        for record in records
    ]
    return ("\n".join(lines) + "\n").encode()


def _timestamp(record: dict) -> float:
    raw_timestamp = record.get("timestamp") or record.get("last_seen") or record.get("first_seen")
    if isinstance(raw_timestamp, (float, int)):
        return float(raw_timestamp)
    if isinstance(raw_timestamp, str):
        return datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00")).timestamp()
    return datetime.now(timezone.utc).timestamp()


def _elasticsearch_body(config: IntegrationConfig, records: list[dict]) -> bytes:
    assert config.index is not None
    lines: list[str] = []
    for record in records:
        identifier = record.get("event_id") or record.get("alert_id")
        lines.append(json.dumps({"index": {"_index": config.index, "_id": identifier}}, separators=(",", ":")))
        lines.append(json.dumps(record, separators=(",", ":")))
    return ("\n".join(lines) + "\n").encode()


def _post(config: IntegrationConfig, kind: RecordType, records: list[dict]) -> DeliveryResult:
    if not records:
        return DeliveryResult("skipped", 0, None, None)
    if len(records) > MAX_BATCH_RECORDS:
        raise ValueError(f"Integration batch exceeds the {MAX_BATCH_RECORDS} record limit")
    if config.name == "splunk":
        url = config.endpoint
        headers = {
            "Authorization": f"Splunk {config.secret}",
            "Content-Type": "application/json",
        }
        content = _splunk_body(kind, records)
    else:
        url = f"{config.endpoint}/_bulk"
        headers = {
            "Authorization": f"ApiKey {config.secret}",
            "Content-Type": "application/x-ndjson",
        }
        content = _elasticsearch_body(config, records)

    last_error = "delivery failed"
    last_status: int | None = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with httpx.Client(timeout=REQUEST_TIMEOUT_SECONDS, verify=True, trust_env=False) as client:
                response = client.post(url, headers=headers, content=content)
            last_status = response.status_code
            if response.is_success:
                if config.name == "splunk":
                    try:
                        accepted = response.json().get("code") == 0
                    except (ValueError, AttributeError):
                        accepted = False
                    if not accepted:
                        last_error = "Splunk HEC did not acknowledge the submitted batch"
                    else:
                        return DeliveryResult("delivered", attempt, last_status, None)
                else:
                    try:
                        payload = response.json()
                        items = payload.get("items", [])
                        accepted = (
                            not payload.get("errors", True)
                            and len(items) == len(records)
                            and all(
                                item.get("index", {}).get("status", 500) in {200, 201}
                                for item in items
                            )
                        )
                    except (ValueError, AttributeError):
                        accepted = False
                    if accepted:
                        return DeliveryResult("delivered", attempt, last_status, None)
                    last_error = "Elasticsearch bulk response reported one or more failed records"
            else:
                last_error = f"remote service returned HTTP {last_status}"
        except httpx.TimeoutException:
            last_error = "integration request timed out"
        except httpx.RequestError as error:
            last_error = f"integration connection failed ({type(error).__name__})"
        if attempt < MAX_RETRIES:
            time.sleep(0.1 * (2 ** (attempt - 1)))

    LOGGER.warning(
        "SIEM delivery failed",
        extra={"integration": config.name, "record_type": kind, "http_status": last_status, "error": last_error},
    )
    return DeliveryResult("failed", MAX_RETRIES, last_status, last_error)


def deliver_records(
    session: Session,
    name: IntegrationName,
    kind: RecordType,
    records: list[dict],
) -> list[IntegrationDeliveryRow]:
    try:
        config = load_config(name)
    except ValueError as error:
        LOGGER.warning(
            "SIEM integration configuration is invalid",
            extra={"integration": name, "record_type": kind, "error": str(error)},
        )
        return _record_failed_batches(session, name, kind, records, str(error))
    if config is None:
        return []
    batches: list[list[dict]] = [
        records[offset : offset + MAX_BATCH_RECORDS]
        for offset in range(0, len(records), MAX_BATCH_RECORDS)
    ]
    deliveries: list[IntegrationDeliveryRow] = []
    for batch in batches:
        batch_key = _batch_key(name, kind, batch)
        existing = session.scalar(
            select(IntegrationDeliveryRow).where(IntegrationDeliveryRow.batch_key == batch_key)
        )
        if existing is not None and existing.status == "delivered":
            deliveries.append(existing)
            continue
        result = _post(config, kind, batch)
        now = datetime.now(timezone.utc)
        if existing is None:
            existing = IntegrationDeliveryRow(
                id=str(uuid4()),
                batch_key=batch_key,
                integration=name,
                record_type=kind,
                record_ids=[
                    str(record.get("event_id") or record.get("alert_id"))
                    for record in batch
                ],
                status=result.status,
                attempts=result.attempts,
                http_status=result.http_status,
                error=result.error,
                created_at=now,
                updated_at=now,
            )
            session.add(existing)
        else:
            existing.status = result.status
            existing.attempts += result.attempts
            existing.http_status = result.http_status
            existing.error = result.error
            existing.updated_at = now
        deliveries.append(existing)
    session.commit()
    return deliveries


def _record_failed_batches(
    session: Session,
    name: IntegrationName,
    kind: RecordType,
    records: list[dict],
    reason: str,
) -> list[IntegrationDeliveryRow]:
    batches = [
        records[offset : offset + MAX_BATCH_RECORDS]
        for offset in range(0, len(records), MAX_BATCH_RECORDS)
    ]
    deliveries: list[IntegrationDeliveryRow] = []
    now = datetime.now(timezone.utc)
    for batch in batches:
        batch_key = _batch_key(name, kind, batch)
        existing = session.scalar(
            select(IntegrationDeliveryRow).where(IntegrationDeliveryRow.batch_key == batch_key)
        )
        if existing is None:
            existing = IntegrationDeliveryRow(
                id=str(uuid4()),
                batch_key=batch_key,
                integration=name,
                record_type=kind,
                record_ids=[
                    str(record.get("event_id") or record.get("alert_id"))
                    for record in batch
                ],
                status="failed",
                attempts=0,
                http_status=None,
                error=reason[:240],
                created_at=now,
                updated_at=now,
            )
            session.add(existing)
        else:
            existing.status = "failed"
            existing.error = reason[:240]
            existing.updated_at = now
        deliveries.append(existing)
    session.commit()
    return deliveries


def send_test_event(session: Session, name: IntegrationName) -> IntegrationDeliveryRow:
    config = load_config(name)
    if config is None:
        raise ValueError(f"{name} is not configured")
    event = {
        "event_id": f"sentinelsoc-test-{uuid4()}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "integration_test",
        "sensor_type": "sentinelsoc",
        "message": "SentinelSOC integration connectivity test",
    }
    return deliver_records(session, name, "test_event", [event])[0]
