from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import main
from backend.app.database import Base


@pytest.fixture
def api_client(monkeypatch) -> Iterator[TestClient]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        with test_sessions() as session:
            yield session

    monkeypatch.setattr(main, "create_tables", lambda: None)
    main.app.dependency_overrides[main.get_db] = override_db
    try:
        with TestClient(main.app) as client:
            yield client
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()


def test_demo_api_persists_events_alerts_and_real_metrics(monkeypatch) -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        with test_sessions() as session:
            yield session

    monkeypatch.setattr(main, "create_tables", lambda: None)
    main.app.dependency_overrides[main.get_db] = override_db
    try:
        with TestClient(main.app) as client:
            generated = client.post("/api/demo/generate?scenario=syn&count=12")
            generated_again = client.post("/api/demo/generate?scenario=syn&count=12")
            assert generated.status_code == 200
            assert generated.json()["accepted"] == 12
            assert generated.json()["simulated"] is True
            assert generated_again.json()["accepted"] == 12

            summary = client.get("/api/dashboard/summary").json()
            assert summary["total_events"] == 24
            assert summary["total_alerts"] >= 1
            assert summary["simulated_events"] == 24

            events = client.get("/api/events?limit=5").json()
            alerts = client.get("/api/alerts").json()
            assert len(events["items"]) == 5
            assert alerts["items"]
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()


def test_upload_is_idempotent_for_same_file_and_filename(monkeypatch) -> None:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        with test_sessions() as session:
            yield session

    monkeypatch.setattr(main, "create_tables", lambda: None)
    main.app.dependency_overrides[main.get_db] = override_db
    sample = Path(__file__).resolve().parents[1] / "port_scan_detection_lab/logs/zeek_conn.log"
    payload = sample.read_bytes()
    try:
        with TestClient(main.app) as client:
            first = client.post("/api/ingest/upload?format=zeek", files={"file": ("conn.log", payload, "text/plain")})
            second = client.post("/api/ingest/upload?format=zeek", files={"file": ("conn.log", payload, "text/plain")})

            assert first.status_code == 200
            assert first.json()["accepted"] > 0
            assert second.json()["accepted"] == 0
            assert second.json()["duplicates"] == first.json()["parsed"]
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()


def test_health_checks_the_database() -> None:
    with TestClient(main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def test_upload_rejects_files_over_size_limit() -> None:
    with TestClient(main.app) as client:
        response = client.post(
            "/api/ingest/upload?format=suricata",
            files={"file": ("large.json", b"x" * (main.MAX_UPLOAD_BYTES + 1), "application/json")},
        )

    assert response.status_code == 413


def test_cors_allows_local_dashboard_and_rejects_unlisted_origin() -> None:
    with TestClient(main.app) as client:
        local = client.options(
            "/api/dashboard/summary",
            headers={"Origin": "http://localhost:3000", "Access-Control-Request-Method": "GET"},
        )
        remote = client.options(
            "/api/dashboard/summary",
            headers={"Origin": "https://untrusted.example", "Access-Control-Request-Method": "GET"},
        )

    assert local.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-origin" not in remote.headers


def test_end_to_end_labelled_ingestion_investigation_incident_and_reports(api_client: TestClient) -> None:
    benign_response = api_client.post("/api/demo/generate?scenario=benign&count=40&seed=300")
    malicious_response = api_client.post("/api/demo/generate?scenario=syn&count=40&seed=301")

    assert benign_response.status_code == 200
    assert malicious_response.status_code == 200
    assert benign_response.json()["accepted"] == 40
    assert benign_response.json()["alerts"] == []
    assert malicious_response.json()["accepted"] == 40
    assert {event["ground_truth"] for event in api_client.get("/api/events?limit=100").json()["items"]} == {"benign", "malicious"}

    alerts = api_client.get("/api/alerts?limit=100").json()
    assert alerts["total"] >= 2
    alert = next(item for item in alerts["items"] if item["rule_id"] == "tcp_syn_scan")
    investigated = api_client.get(f"/api/alerts/{alert['alert_id']}")
    assert investigated.status_code == 200
    detail = investigated.json()
    assert len(detail["evidence"]) == alert["event_count"]
    assert {event["event_id"] for event in detail["evidence"]} == set(alert["evidence"])
    assert {event["ground_truth"] for event in detail["evidence"]} == {"malicious"}

    update = api_client.patch(
        f"/api/alerts/{alert['alert_id']}",
        json={"status": "Investigating", "assigned_to": "analyst-1", "note": "Reviewing source ownership."},
    )
    assert update.status_code == 200
    assert update.json()["status"] == "Investigating"
    assert update.json()["assigned_to"] == "analyst-1"
    assert api_client.get(f"/api/alerts/{alert['alert_id']}").json()["audit_trail"][0]["action"] == "updated"

    created = api_client.post(
        "/api/incidents",
        json={"alert_id": alert["alert_id"], "title": "Synthetic scan investigation", "assigned_to": "analyst-1"},
    )
    assert created.status_code == 201
    incident_id = created.json()["incident_id"]
    assert api_client.patch(f"/api/incidents/{incident_id}", json={"status": "Resolved"}).status_code == 422
    for status in ("Investigating", "Escalated", "Resolved", "Closed"):
        changed = api_client.patch(
            f"/api/incidents/{incident_id}",
            json={"status": status, "resolution": "Controlled synthetic test completed." if status == "Resolved" else None},
        )
        assert changed.status_code == 200
        assert changed.json()["status"] == status

    incident_detail = api_client.get(f"/api/incidents/{incident_id}").json()
    assert incident_detail["incident"]["status"] == "Closed"
    assert len(incident_detail["alerts"]) == 1
    assert len(incident_detail["audit_trail"]) == 5

    report = api_client.get("/api/reports/summary").json()
    assert report["summary"]["total_events"] == 80
    assert report["summary"]["total_alerts"] == alerts["total"]
    assert report["summary"]["active_incidents"] == 0
    csv_report = api_client.get("/api/reports/summary.csv")
    assert csv_report.status_code == 200
    assert 'attachment; filename="soc-summary.csv"' in csv_report.headers["content-disposition"]
    assert "total_events,80" in csv_report.text


def test_incident_and_alert_validation_and_not_found_paths(api_client: TestClient) -> None:
    assert api_client.get("/api/alerts/missing").status_code == 404
    assert api_client.get("/api/incidents/missing").status_code == 404
    assert api_client.post("/api/incidents", json={"alert_id": "missing", "title": "Test"}).status_code == 404
    assert api_client.patch("/api/incidents/missing", json={"status": "Closed"}).status_code == 404
    assert api_client.patch("/api/incidents/anything", json={"status": "invalid"}).status_code == 422
    assert api_client.patch("/api/alerts/anything", json={"status": "invalid"}).status_code == 422


def test_events_filter_total_and_pagination_match_database(api_client: TestClient) -> None:
    api_client.post("/api/demo/generate?scenario=benign&count=12&seed=400")
    page = api_client.get("/api/events?limit=5&offset=0&protocol=tcp")
    udp_page = api_client.get("/api/events?limit=5&offset=0&protocol=udp")
    assert page.status_code == 200
    assert len(page.json()["items"]) == 5
    assert page.json()["total"] + udp_page.json()["total"] == 12


def test_cors_preflight_allows_alert_mutation(api_client: TestClient) -> None:
    response = api_client.options(
        "/api/alerts/example",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "PATCH",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.headers["access-control-allow-methods"]
    assert "PATCH" in response.headers["access-control-allow-methods"]


def test_empty_database_reports_have_zero_metrics_and_valid_csv(api_client: TestClient) -> None:
    report = api_client.get("/api/reports/summary")
    assert report.status_code == 200
    assert report.json()["summary"]["total_events"] == 0
    assert report.json()["summary"]["total_alerts"] == 0
    assert report.json()["recent_alerts"] == []
    assert report.json()["incidents"] == []

    csv_report = api_client.get("/api/reports/summary.csv")
    assert csv_report.status_code == 200
    assert "total_events,0" in csv_report.text
    assert "total_alerts,0" in csv_report.text


def test_detection_correlates_split_ingestion_batches_and_merges_alerts(api_client: TestClient) -> None:
    timestamp = datetime.now(timezone.utc)

    def upload(start: int, stop: int, filename: str) -> dict:
        rows = [
            {
                "event_id": f"split-scan-{port}",
                "timestamp": (timestamp + timedelta(seconds=port)).isoformat(),
                "src_ip": "198.51.100.77",
                "src_port": 45000 + port,
                "dest_ip": "192.0.2.77",
                "dest_port": port,
                "proto": "TCP",
                "event_type": "flow",
                "tcp": {"flags": "SYN", "state": "new"},
            }
            for port in range(start, stop)
        ]
        response = api_client.post(
            "/api/ingest/upload?format=suricata",
            files={"file": (filename, "\n".join(json.dumps(row) for row in rows), "application/json")},
        )
        assert response.status_code == 200
        return response.json()

    first = upload(20, 24, "batch-1.json")
    assert first["accepted"] == 4
    assert first["alerts"] == []

    second = upload(24, 28, "batch-2.json")
    assert second["accepted"] == 4
    syn_alert = next(alert for alert in second["alerts"] if alert["rule_id"] == "tcp_syn_scan")
    assert syn_alert["event_count"] == 8
    original_alert_id = syn_alert["alert_id"]
    api_client.patch(f"/api/alerts/{original_alert_id}", json={"status": "Investigating"})

    third = upload(28, 32, "batch-3.json")
    merged_alert = next(alert for alert in third["alerts"] if alert["rule_id"] == "tcp_syn_scan")
    assert merged_alert["alert_id"] == original_alert_id
    assert merged_alert["event_count"] == 12
    assert merged_alert["status"] == "Investigating"
    assert len(merged_alert["evidence"]) == 12
    assert api_client.get("/api/alerts").json()["total"] == 2