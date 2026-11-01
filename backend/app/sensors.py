from __future__ import annotations

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import stat
import threading
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from backend.app.database import SensorRow, SessionLocal
from backend.app.pipeline import parse_log


LOGGER = logging.getLogger(__name__)
MAX_SENSOR_COUNT = 16
MAX_ACTIVE_SENSORS = 4
MAX_SENSOR_READ_BYTES = 256 * 1024
MAX_SENSOR_RECORDS_PER_POLL = 250
MAX_SENSOR_LINE_BYTES = 64 * 1024
SENSOR_POLL_INTERVAL_SECONDS = 1.0
ALLOWED_SENSOR_TYPES = {"zeek", "suricata"}


class EventIngestor(Protocol):
    def __call__(self, session: Session, events: list) -> tuple[int, list[dict]]: ...


class SensorConfigurationError(ValueError):
    pass


def allowed_sensor_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    for raw_path in os.getenv("LAB_SENSOR_LOG_DIRS", "").split(os.pathsep):
        candidate = raw_path.strip()
        if not candidate:
            continue
        path = Path(candidate)
        try:
            root = path.resolve(strict=True)
        except OSError as error:
            raise SensorConfigurationError("A configured sensor log directory does not exist") from error
        if not root.is_dir():
            raise SensorConfigurationError("Configured sensor log paths must be directories")
        if root not in roots:
            roots.append(root)
    return tuple(roots)


def validate_log_path(raw_path: str, sensor_type: str) -> Path:
    if sensor_type not in ALLOWED_SENSOR_TYPES:
        raise SensorConfigurationError("Sensor type must be zeek or suricata")
    if not raw_path or len(raw_path) > 1024 or "\x00" in raw_path:
        raise SensorConfigurationError("Log path is invalid")
    path = Path(raw_path)
    try:
        resolved = path.resolve(strict=True)
        roots = allowed_sensor_roots()
    except SensorConfigurationError:
        raise
    except OSError as error:
        raise SensorConfigurationError("Sensor path or configured log directory could not be accessed") from error
    if not roots:
        raise SensorConfigurationError("Set LAB_SENSOR_LOG_DIRS to explicitly authorize sensor log directories")
    if path.is_symlink() or not resolved.is_file():
        raise SensorConfigurationError("Sensor log path must be a regular, non-symlink file")
    if not any(resolved.is_relative_to(root) for root in roots):
        raise SensorConfigurationError("Sensor log file is outside the configured authorized directories")
    return resolved


def sensor_payload(row: SensorRow) -> dict:
    return {
        "sensor_id": row.id,
        "name": row.name,
        "sensor_type": row.sensor_type,
        "status": row.status,
        "processed_records": row.processed_records,
        "parse_error_count": row.parse_error_count,
        "last_error": row.last_error,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


def open_authorized_log(path: Path) -> tuple[int, os.stat_result]:
    roots = allowed_sensor_roots()
    root = next((candidate for candidate in roots if path.is_relative_to(candidate)), None)
    if root is None:
        raise SensorConfigurationError("Sensor log file is outside the configured authorized directories")
    relative = path.relative_to(root)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    directory_fd = os.open(root, directory_flags)
    try:
        for component in relative.parts[:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        descriptor = os.open(relative.parts[-1], file_flags, dir_fd=directory_fd)
        try:
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                raise SensorConfigurationError("Sensor source is not a regular file")
            return descriptor, file_stat
        except Exception:
            os.close(descriptor)
            raise
    finally:
        os.close(directory_fd)


class SensorManager:
    def __init__(
        self,
        session_factory: sessionmaker = SessionLocal,
        ingest: EventIngestor | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._ingest = ingest
        self._workers: dict[str, tuple[threading.Event, threading.Thread]] = {}
        self._lock = threading.Lock()

    def set_ingestor(self, ingest: EventIngestor) -> None:
        self._ingest = ingest

    def start(self, sensor_id: str) -> SensorRow:
        with self._lock:
            with self._session_factory() as session:
                row = session.get(SensorRow, sensor_id)
                if row is None:
                    raise LookupError("Sensor not found")
                existing = self._workers.get(sensor_id)
                if existing and existing[1].is_alive():
                    if row.status != "running":
                        row.status = "running"
                        row.last_error = None
                        row.updated_at = datetime.now(timezone.utc)
                        session.commit()
                        session.refresh(row)
                    return row
                self._workers.pop(sensor_id, None)
                if len(self._workers) >= MAX_ACTIVE_SENSORS:
                    raise SensorConfigurationError("At most four sensors may monitor files concurrently")
                validate_log_path(row.log_path, row.sensor_type)
                row.status = "running"
                row.last_error = None
                row.updated_at = datetime.now(timezone.utc)
                session.commit()
                session.refresh(row)
                detached = row
            stop_event = threading.Event()
            worker = threading.Thread(
                target=self._run,
                args=(sensor_id, stop_event),
                name=f"sentinelsoc-sensor-{sensor_id}",
                daemon=True,
            )
            self._workers[sensor_id] = (stop_event, worker)
            worker.start()
            return detached

    def stop(self, sensor_id: str) -> SensorRow:
        with self._lock:
            with self._session_factory() as session:
                row = session.get(SensorRow, sensor_id)
                if row is None:
                    raise LookupError("Sensor not found")
                worker_pair = self._workers.get(sensor_id)
                row.status = "stopping" if worker_pair else "stopped"
                row.updated_at = datetime.now(timezone.utc)
                session.commit()
            if worker_pair:
                stop_event, worker = worker_pair
                stop_event.set()
                worker.join(timeout=3)
                if worker.is_alive():
                    raise RuntimeError("Sensor worker did not stop within the timeout")
                self._workers.pop(sensor_id, None)
            with self._session_factory() as session:
                row = session.get(SensorRow, sensor_id)
                if row is None:
                    raise LookupError("Sensor not found")
                row.status = "stopped"
                row.updated_at = datetime.now(timezone.utc)
                session.commit()
                session.refresh(row)
                return row

    def stop_all(self) -> None:
        with self._lock:
            workers = list(self._workers.items())
            self._workers.clear()
        for sensor_id, (stop_event, worker) in workers:
            stop_event.set()
            worker.join(timeout=3)
            with self._session_factory() as session:
                row = session.get(SensorRow, sensor_id)
                if row is not None:
                    row.status = "stopped"
                    row.updated_at = datetime.now(timezone.utc)
                    session.commit()

    def start_persisted_sensors(self) -> None:
        with self._session_factory() as session:
            sensor_ids = session.scalars(
                select(SensorRow.id).where(SensorRow.status.in_(["running", "degraded"]))
            ).all()
        for sensor_id in sensor_ids[:MAX_ACTIVE_SENSORS]:
            try:
                self.start(sensor_id)
            except (LookupError, SensorConfigurationError) as error:
                LOGGER.warning("Could not resume network sensor %s: %s", sensor_id, error)
                with self._session_factory() as session:
                    row = session.get(SensorRow, sensor_id)
                    if row is not None:
                        row.status = "degraded"
                        row.last_error = str(error)[:240]
                        row.updated_at = datetime.now(timezone.utc)
                        session.commit()

    def poll_once(self, sensor_id: str) -> dict[str, int]:
        if self._ingest is None:
            raise RuntimeError("Sensor event ingestor is not configured")
        with self._session_factory() as session:
            row = session.get(SensorRow, sensor_id)
            if row is None:
                raise LookupError("Sensor not found")
            path = validate_log_path(row.log_path, row.sensor_type)
            try:
                descriptor, file_stat = open_authorized_log(path)
                try:
                    identity = f"{file_stat.st_dev}:{file_stat.st_ino}"
                    if row.file_identity != identity or row.cursor_offset > file_stat.st_size:
                        row.cursor_offset = 0
                        row.pending_line = ""
                        row.zeek_header = None
                        row.file_identity = identity
                    pending = row.pending_line.encode("utf-8")
                    pending_complete_lines = sum(1 for line in pending.splitlines(keepends=True) if line.endswith(b"\n"))
                    if pending_complete_lines >= MAX_SENSOR_RECORDS_PER_POLL:
                        data = pending
                    else:
                        os.lseek(descriptor, row.cursor_offset, os.SEEK_SET)
                        chunk = os.read(descriptor, max(0, MAX_SENSOR_READ_BYTES - len(pending)))
                        row.cursor_offset += len(chunk)
                        data = pending + chunk
                finally:
                    os.close(descriptor)

                if not data:
                    row.status = "running"
                    row.last_error = None
                    row.updated_at = datetime.now(timezone.utc)
                    session.commit()
                    return {"read": 0, "accepted": 0, "parse_errors": 0}

                physical_lines = data.splitlines(keepends=True)
                complete_count = sum(1 for line in physical_lines if line.endswith(b"\n"))
                take_count = min(complete_count, MAX_SENSOR_RECORDS_PER_POLL)
                consumed = physical_lines[:take_count]
                remaining = b"".join(physical_lines[take_count:])
                if not complete_count and len(data) <= MAX_SENSOR_LINE_BYTES:
                    row.pending_line = data.decode("utf-8", errors="replace")
                    row.updated_at = datetime.now(timezone.utc)
                    session.commit()
                    return {"read": 0, "accepted": 0, "parse_errors": 0}
                oversized_lines = sum(
                    1
                    for line in consumed
                    if len(line.rstrip(b"\r\n")) > MAX_SENSOR_LINE_BYTES
                )
                remaining_lines = remaining.splitlines(keepends=True)
                if (
                    remaining_lines
                    and not remaining_lines[-1].endswith(b"\n")
                    and len(remaining_lines[-1]) > MAX_SENSOR_LINE_BYTES
                ):
                    oversized_lines += 1
                    remaining = b"".join(remaining_lines[:-1])
                row.pending_line = remaining.decode("utf-8", errors="replace")

                lines = [
                    line.rstrip(b"\r\n").decode("utf-8", errors="replace")
                    for line in consumed
                    if len(line.rstrip(b"\r\n")) <= MAX_SENSOR_LINE_BYTES
                ]
                if row.sensor_type == "zeek":
                    for line in lines:
                        if line.startswith("#fields\t"):
                            row.zeek_header = line
                    if row.zeek_header and not any(line.startswith("#fields\t") for line in lines):
                        lines.insert(0, row.zeek_header)
                source_file = f"{row.name}.{row.sensor_type}"
                events, errors = parse_log(
                    "\n".join(lines),
                    row.sensor_type,
                    source_file=source_file,
                    line_offset=row.processed_records,
                )
                accepted, _ = self._ingest(session, events)
                error_count = len(errors) + oversized_lines
                row.processed_records += len(consumed)
                row.parse_error_count += error_count
                row.status = "running"
                row.last_error = f"{error_count} malformed log record(s)" if error_count else None
                row.updated_at = datetime.now(timezone.utc)
                session.commit()
                return {
                    "read": len(consumed),
                    "accepted": accepted,
                    "parse_errors": error_count,
                }
            except (OSError, UnicodeError, SensorConfigurationError) as error:
                row.status = "degraded"
                row.last_error = (
                    "Sensor log file is unavailable or unreadable"
                    if isinstance(error, OSError)
                    else str(error)[:240]
                )
                row.updated_at = datetime.now(timezone.utc)
                session.commit()
                raise
            except Exception as error:
                session.rollback()
                row = session.get(SensorRow, sensor_id)
                if row is not None:
                    row.status = "degraded"
                    row.last_error = "Sensor event ingestion failed"
                    row.updated_at = datetime.now(timezone.utc)
                    session.commit()
                LOGGER.error("Network sensor %s poll failed (%s)", sensor_id, type(error).__name__)
                raise

    def _run(self, sensor_id: str, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                self.poll_once(sensor_id)
            except LookupError:
                LOGGER.error("Configured network sensor %s was removed", sensor_id)
                return
            except Exception as error:
                LOGGER.error("Network sensor %s polling failed (%s)", sensor_id, type(error).__name__)
            stop_event.wait(SENSOR_POLL_INTERVAL_SECONDS)
