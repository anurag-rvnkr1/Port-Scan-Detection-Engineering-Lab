from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import main
from backend.app.auth import create_user
from backend.app.database import Base, EventRow, SensorRow
from backend.app.sensors import SensorConfigurationError, SensorManager, validate_log_path


@pytest.fixture
def api_client(monkeypatch) -> Iterator[TestClient]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        with test_sessions() as session:
            yield session

    with test_sessions() as session:
        create_user(session, "sensor-admin", "test-password-for-sensor-admin", "super_admin")
        session.commit()
    monkeypatch.setattr(main, "request_limiter", main.SlidingWindowLimiter())
    monkeypatch.setattr(main, "sensor_manager", SensorManager(test_sessions, main._persist))
    monkeypatch.setattr(main, "create_tables", lambda: None)
    main.app.dependency_overrides[main.get_db] = override_db
    try:
        with TestClient(main.app) as client:
            login = client.post(
                "/api/auth/login",
                json={"username": "sensor-admin", "password": "test-password-for-sensor-admin"},
            )
            assert login.status_code == 200
            client.headers.update({"X-CSRF-Token": login.json()["csrf_token"]})
            yield client
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()


@pytest.fixture
def sensor_store(tmp_path: Path):
    database_path = tmp_path / "sensors.db"
    engine = create_engine(f"sqlite:///{database_path}")
    Base.metadata.create_all(bind=engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        yield sessions
    finally:
        engine.dispose()


def _suricata_record(destination_port: int = 443) -> str:
    record = {
        "timestamp": "2026-11-01T17:00:00.000000+0000",
        "event_type": "flow",
        "src_ip": "192.168.56.25",
        "src_port": 51000,
        "dest_ip": "192.168.56.10",
        "dest_port": destination_port,
        "proto": "TCP",
        "flow_id": f"flow-{destination_port}",
        "tcp": {"tcp_flags": "02"},
    }
    return json.dumps(record)


def _make_sensor(
    sessions: sessionmaker,
    path: Path,
    *,
    sensor_type: str = "suricata",
    name: str = "lab-sensor",
) -> str:
    with sessions() as session:
        row = SensorRow(
            id="sensor-1",
            name=name,
            sensor_type=sensor_type,
            log_path=str(path),
            status="running",
            cursor_offset=0,
            file_identity=None,
            pending_line="",
            zeek_header=None,
            processed_records=0,
            parse_error_count=0,
            last_error=None,
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        session.add(row)
        session.commit()
        return row.id


def test_sensor_paths_require_explicit_directory_allowlist_and_regular_file(tmp_path, monkeypatch) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    sensor_log = allowed / "eve.json"
    sensor_log.write_text("", encoding="utf-8")
    (allowed / "linked.json").symlink_to(outside / "not-allowed.json")
    (allowed / "linked-directory").symlink_to(outside, target_is_directory=True)
    (outside / "not-allowed.json").write_text("", encoding="utf-8")
    (outside / "nested.json").write_text("", encoding="utf-8")
    monkeypatch.setenv("LAB_SENSOR_LOG_DIRS", str(allowed))

    assert validate_log_path(str(sensor_log), "suricata") == sensor_log.resolve()
    with pytest.raises(SensorConfigurationError, match="outside"):
        validate_log_path(str(outside / "not-allowed.json"), "suricata")
    with pytest.raises(SensorConfigurationError, match="non-symlink"):
        validate_log_path(str(allowed / "linked.json"), "suricata")
    with pytest.raises(SensorConfigurationError, match="outside"):
        validate_log_path(str(allowed / "linked-directory" / "nested.json"), "suricata")
    missing = allowed / "missing.json"
    with pytest.raises(SensorConfigurationError, match="could not be accessed") as error:
        validate_log_path(str(missing), "suricata")
    assert str(missing) not in str(error.value)


def test_suricata_sensor_tails_incrementally_persists_and_deduplicates(tmp_path, monkeypatch, sensor_store) -> None:
    log_path = tmp_path / "eve.json"
    log_path.write_text(_suricata_record() + "\n", encoding="utf-8")
    monkeypatch.setenv("LAB_SENSOR_LOG_DIRS", str(tmp_path))
    sensor_id = _make_sensor(sensor_store, log_path)
    manager = SensorManager(sensor_store, main._persist)

    first = manager.poll_once(sensor_id)
    second = manager.poll_once(sensor_id)
    assert first == {"read": 1, "accepted": 1, "parse_errors": 0}
    assert second == {"read": 0, "accepted": 0, "parse_errors": 0}
    with sensor_store() as session:
        events = session.scalars(select(EventRow)).all()
        sensor = session.get(SensorRow, sensor_id)
        assert len(events) == 1
        assert events[0].payload["sensor_type"] == "suricata"
        assert events[0].payload["destination_port"] == 443
        assert sensor is not None
        assert sensor.processed_records == 1
        assert sensor.parse_error_count == 0


def test_sensor_event_ids_remain_distinct_for_identical_log_lines(tmp_path, monkeypatch, sensor_store) -> None:
    record = _suricata_record(destination_port=5353)
    log_path = tmp_path / "eve.json"
    log_path.write_text(f"{record}\n{record}\n", encoding="utf-8")
    monkeypatch.setenv("LAB_SENSOR_LOG_DIRS", str(tmp_path))
    sensor_id = _make_sensor(sensor_store, log_path)
    manager = SensorManager(sensor_store, main._persist)

    result = manager.poll_once(sensor_id)
    assert result == {"read": 2, "accepted": 2, "parse_errors": 0}
    with sensor_store() as session:
        event_ids = session.scalars(select(EventRow.id)).all()
        assert len(event_ids) == 2
        assert len(set(event_ids)) == 2


def test_sensor_record_cap_preserves_backlog_and_oversized_lines_are_skipped(
    tmp_path,
    monkeypatch,
    sensor_store,
) -> None:
    log_path = tmp_path / "eve.json"
    records = [_suricata_record(destination_port=1000 + index) for index in range(500)]
    oversized = "x" * (64 * 1024 + 1)
    log_path.write_text(oversized + "\n" + "\n".join(records) + "\n", encoding="utf-8")
    monkeypatch.setenv("LAB_SENSOR_LOG_DIRS", str(tmp_path))
    sensor_id = _make_sensor(sensor_store, log_path)
    manager = SensorManager(sensor_store, main._persist)

    first = manager.poll_once(sensor_id)
    second = manager.poll_once(sensor_id)
    third = manager.poll_once(sensor_id)
    assert first == {"read": 250, "accepted": 249, "parse_errors": 1}
    assert second == {"read": 250, "accepted": 250, "parse_errors": 0}
    assert third == {"read": 1, "accepted": 1, "parse_errors": 0}
    with sensor_store() as session:
        assert len(session.scalars(select(EventRow.id)).all()) == 500
        sensor = session.get(SensorRow, sensor_id)
        assert sensor is not None
        assert sensor.processed_records == 501
        assert sensor.parse_error_count == 1


def test_sensor_buffers_partial_lines_and_records_parse_errors(tmp_path, monkeypatch, sensor_store) -> None:
    log_path = tmp_path / "eve.json"
    full_record = _suricata_record(destination_port=8443)
    log_path.write_text(full_record[:35], encoding="utf-8")
    monkeypatch.setenv("LAB_SENSOR_LOG_DIRS", str(tmp_path))
    sensor_id = _make_sensor(sensor_store, log_path)
    manager = SensorManager(sensor_store, main._persist)

    partial = manager.poll_once(sensor_id)
    assert partial == {"read": 0, "accepted": 0, "parse_errors": 0}
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(full_record[35:] + "\nnot-json\n")

    result = manager.poll_once(sensor_id)
    assert result == {"read": 2, "accepted": 1, "parse_errors": 1}
    with sensor_store() as session:
        sensor = session.get(SensorRow, sensor_id)
        assert sensor is not None
        assert sensor.processed_records == 2
        assert sensor.parse_error_count == 1
        assert "malformed" in (sensor.last_error or "")


def test_zeek_sensor_retains_fields_header_across_poll_cycles(tmp_path, monkeypatch, sensor_store) -> None:
    log_path = tmp_path / "conn.log"
    header = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tconn_state\n"
    row = "1793552400.0\tCabc123\t192.168.56.20\t50000\t192.168.56.10\t22\ttcp\tS0\n"
    log_path.write_text(header + row, encoding="utf-8")
    monkeypatch.setenv("LAB_SENSOR_LOG_DIRS", str(tmp_path))
    sensor_id = _make_sensor(sensor_store, log_path, sensor_type="zeek", name="zeek-lab")
    manager = SensorManager(sensor_store, main._persist)

    result = manager.poll_once(sensor_id)
    assert result == {"read": 2, "accepted": 1, "parse_errors": 0}
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write("1793552401.0\tCabc124\t192.168.56.20\t50001\t192.168.56.10\t443\ttcp\tS0\n")
    appended = manager.poll_once(sensor_id)
    assert appended == {"read": 1, "accepted": 1, "parse_errors": 0}
    with sensor_store() as session:
        events = session.scalars(select(EventRow).order_by(EventRow.timestamp)).all()
        assert len(events) == 2
        assert events[1].payload["sensor_type"] == "zeek"
        assert events[1].payload["destination_port"] == 443


def test_sensor_api_validates_admin_and_logs_configuration_changes(
    api_client: TestClient,
    tmp_path: Path,
    monkeypatch,
) -> None:
    allowed = tmp_path / "authorized"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    log_path = allowed / "eve.json"
    log_path.write_text("", encoding="utf-8")
    external_path = outside / "eve.json"
    external_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("LAB_SENSOR_LOG_DIRS", str(allowed))

    response = api_client.post(
        "/api/sensors",
        json={"name": "suricata-lab", "sensor_type": "suricata", "log_path": str(log_path)},
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "stopped"
    sensor_id = response.json()["sensor_id"]
    started = api_client.post(f"/api/sensors/{sensor_id}/start")
    assert started.status_code == 200, started.text
    stopped = api_client.post(f"/api/sensors/{sensor_id}/stop")
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["status"] == "stopped"

    rejected = api_client.post(
        "/api/sensors",
        json={"name": "outside-lab", "sensor_type": "suricata", "log_path": str(external_path)},
    )
    assert rejected.status_code == 422
    assert api_client.get("/api/sensors").json()["items"][0]["sensor_type"] == "suricata"
