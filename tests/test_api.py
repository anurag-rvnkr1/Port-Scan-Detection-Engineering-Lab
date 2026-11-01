from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
from pathlib import Path
import re
import socket

import dpkt
import pytest
from fastapi.testclient import TestClient
from pypdf import PdfReader
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import main
from backend.app.auth import create_user
from backend.app.database import Base
from backend.app.sensors import SensorManager


@pytest.fixture
def api_client(monkeypatch) -> Iterator[TestClient]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    test_sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        with test_sessions() as session:
            yield session

    with test_sessions() as session:
        create_user(session, "soc-admin", "test-password-for-admin-123", "super_admin")
        create_user(session, "analyst-1", "test-password-for-analyst-123", "soc_analyst")
        session.commit()
    monkeypatch.setattr(main, "request_limiter", main.SlidingWindowLimiter())
    monkeypatch.setattr(main, "sensor_manager", SensorManager(test_sessions, main._persist))
    monkeypatch.setattr(main, "create_tables", lambda: None)
    main.app.dependency_overrides[main.get_db] = override_db
    try:
        with TestClient(main.app) as client:
            login = client.post(
                "/api/auth/login",
                json={"username": "soc-admin", "password": "test-password-for-admin-123"},
            )
            assert login.status_code == 200
            client.headers.update({"X-CSRF-Token": login.json()["csrf_token"]})
            yield client
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()


def test_demo_api_persists_events_alerts_and_real_metrics(api_client: TestClient) -> None:
    generated = api_client.post("/api/demo/generate?scenario=syn&count=12")
    generated_again = api_client.post("/api/demo/generate?scenario=syn&count=12")
    assert generated.status_code == 200, generated.text
    assert generated.json()["accepted"] == 12
    assert generated.json()["simulated"] is True
    assert generated_again.json()["accepted"] == 12

    summary = api_client.get("/api/dashboard/summary").json()
    assert summary["total_events"] == 24
    assert summary["total_alerts"] >= 1
    assert summary["simulated_events"] == 24

    events = api_client.get("/api/events?limit=5").json()
    alerts = api_client.get("/api/alerts").json()
    assert len(events["items"]) == 5
    assert alerts["items"]


def test_allowlisted_demo_events_are_persisted_without_creating_alerts(api_client: TestClient, monkeypatch) -> None:
    from backend.app.pipeline import parse_source_allowlist

    monkeypatch.setattr(main, "DETECTION_SOURCE_ALLOWLIST", parse_source_allowlist("198.51.100.0/24"))

    generated = api_client.post("/api/demo/generate?scenario=syn&count=12")
    summary = api_client.get("/api/dashboard/summary").json()

    assert generated.status_code == 200
    assert generated.json()["accepted"] == 12
    assert generated.json()["alerts"] == []
    assert summary["total_events"] == 12
    assert summary["total_alerts"] == 0


def test_configured_detection_threshold_is_applied_by_api(api_client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(main, "DETECTION_THRESHOLD", 13)

    generated = api_client.post("/api/demo/generate?scenario=syn&count=12")

    assert generated.status_code == 200
    assert generated.json()["accepted"] == 12
    assert generated.json()["alerts"] == []


def test_api_requires_login_csrf_and_enforces_read_only_role(api_client: TestClient) -> None:
    unauthenticated = TestClient(main.app)
    assert unauthenticated.get("/api/events").status_code == 401
    assert unauthenticated.get("/api/reports/summary.pdf").status_code == 401
    assert unauthenticated.post("/api/demo/generate?count=1").status_code == 401

    created = api_client.post(
        "/api/users",
        json={"username": "viewer-1", "password": "viewer-password-long-123", "role": "read_only_viewer"},
    )
    assert created.status_code == 201

    viewer = TestClient(main.app)
    login = viewer.post("/api/auth/login", json={"username": "viewer-1", "password": "viewer-password-long-123"})
    assert login.status_code == 200
    viewer.headers.update({"X-CSRF-Token": login.json()["csrf_token"]})
    assert viewer.get("/api/events").status_code == 200
    assert viewer.post("/api/demo/generate?count=1").status_code == 403
    assert viewer.post("/api/auth/logout").status_code == 200
    assert viewer.get("/api/auth/me").status_code == 401


def test_authenticated_writes_require_csrf_and_audit_real_username(api_client: TestClient) -> None:
    assert api_client.post("/api/auth/logout", headers={"X-CSRF-Token": "invalid"}).status_code == 403
    untrusted = api_client.post(
        "/api/demo/generate?count=1",
        headers={"Origin": "https://untrusted.example"},
    )
    assert untrusted.status_code == 403
    result = api_client.post("/api/demo/generate?count=12")
    assert result.status_code == 200
    alert_id = next(item["alert_id"] for item in result.json()["alerts"] if item["rule_id"] == "tcp_syn_scan")
    api_client.patch(
        f"/api/alerts/{alert_id}",
        json={"status": "Investigating"},
    )
    detail = api_client.get(f"/api/alerts/{alert_id}").json()
    assert detail["audit_trail"][0]["actor"] == "soc-admin"


def test_login_sets_http_only_same_site_cookie(api_client: TestClient) -> None:
    response = api_client.post(
        "/api/auth/login",
        json={"username": "soc-admin", "password": "test-password-for-admin-123"},
    )
    cookie_header = response.headers["set-cookie"].lower()

    assert response.status_code == 200
    assert "httponly" in cookie_header
    assert "samesite=strict" in cookie_header
    assert api_client.cookies.get(main.SESSION_COOKIE)
    assert api_client.get("/api/auth/me").json() == {"username": "soc-admin", "role": "super_admin"}
    assert api_client.get("/api/auth/csrf").status_code == 200


@pytest.mark.parametrize("configured", ["not-a-number", "2", "65537"])
def test_detection_threshold_configuration_rejects_invalid_values(monkeypatch, configured: str) -> None:
    monkeypatch.setenv("LAB_DETECTION_THRESHOLD", configured)

    with pytest.raises(RuntimeError, match="LAB_DETECTION_THRESHOLD must be an integer"):
        main._configured_detection_threshold()


def test_detection_allowlist_configuration_is_validated(monkeypatch) -> None:
    monkeypatch.setenv("LAB_DETECTION_SOURCE_ALLOWLIST", "192.0.2.1,2001:db8::/32")
    networks = main._configured_detection_source_allowlist()
    assert len(networks) == 2

    monkeypatch.setenv("LAB_DETECTION_SOURCE_ALLOWLIST", "not-an-address")
    with pytest.raises(RuntimeError, match="Invalid LAB_DETECTION_SOURCE_ALLOWLIST"):
        main._configured_detection_source_allowlist()


def test_upload_is_idempotent_for_same_file_and_filename(api_client: TestClient) -> None:
    sample = Path(__file__).resolve().parents[1] / "port_scan_detection_lab/logs/zeek_conn.log"
    payload = sample.read_bytes()
    first = api_client.post("/api/ingest/upload?format=zeek", files={"file": ("conn.log", payload, "text/plain")})
    second = api_client.post("/api/ingest/upload?format=zeek", files={"file": ("conn.log", payload, "text/plain")})

    assert first.status_code == 200
    assert first.json()["accepted"] > 0
    assert second.json()["accepted"] == 0
    assert second.json()["duplicates"] == first.json()["parsed"]


def test_health_checks_the_database() -> None:
    with TestClient(main.app) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["database"] == "connected"


def test_upload_rejects_files_over_size_limit(api_client: TestClient) -> None:
    response = api_client.post(
        "/api/ingest/upload?format=suricata",
        files={"file": ("large.json", b"x" * (main.MAX_UPLOAD_BYTES + 1), "application/json")},
    )

    assert response.status_code == 413


def test_upload_rejects_record_count_over_limit(api_client: TestClient) -> None:
    content = b'{"bad":true}\n' * (main.MAX_UPLOAD_RECORDS + 1)
    response = api_client.post(
        "/api/ingest/upload?format=suricata",
        files={"file": ("large.jsonl", content, "application/json")},
    )

    assert response.status_code == 413
    assert "record limit" in response.json()["detail"]


def test_upload_rate_limit_and_parse_error_response_are_bounded(api_client: TestClient) -> None:
    for _ in range(10):
        response = api_client.post(
            "/api/ingest/upload?format=suricata",
            files={"file": ("empty.jsonl", b"", "application/json")},
        )
        assert response.status_code == 200
    throttled = api_client.post(
        "/api/ingest/upload?format=suricata",
        files={"file": ("empty.jsonl", b"", "application/json")},
    )
    assert throttled.status_code == 429
    main.request_limiter = main.SlidingWindowLimiter()

    limited = TestClient(main.app)
    created = api_client.post(
        "/api/users",
        json={"username": "error-reviewer", "password": "error-reviewer-password-123", "role": "soc_analyst"},
    )
    assert created.status_code == 201
    login = limited.post(
        "/api/auth/login",
        json={"username": "error-reviewer", "password": "error-reviewer-password-123"},
    )
    assert login.status_code == 200
    limited.headers.update({"X-CSRF-Token": login.json()["csrf_token"]})
    bad_lines = b"not-json\n" * 101
    response = limited.post(
        "/api/ingest/upload?format=suricata",
        files={"file": ("bad.jsonl", bad_lines, "application/json")},
    )
    detail = response.json()["detail"]
    assert response.status_code == 422
    assert detail["error_count"] == 101
    assert len(detail["errors"]) == main.MAX_PARSE_ERRORS_RETURNED
    assert detail["errors_truncated"] is True


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


def test_pdf_report_uses_persisted_metrics_and_supports_preview(api_client: TestClient) -> None:
    generated = api_client.post("/api/demo/generate?scenario=syn&count=12")
    assert generated.status_code == 200

    report = api_client.get("/api/reports/summary.pdf?period=weekly&download=false")

    assert report.status_code == 200
    assert report.headers["content-type"] == "application/pdf"
    assert 'inline; filename="sentinelsoc-weekly-report.pdf"' in report.headers["content-disposition"]
    reader = PdfReader(BytesIO(report.content))
    assert len(reader.pages) >= 1
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert "SentinelSOC" in text
    assert "Weekly" in text
    assert re.search(r"Network events\s+12", text)
    assert "Security alerts" in text
    assert "TCP SYN" in text
    assert "Methodology and limitations" in text
    assert api_client.get("/api/reports/summary.pdf?period=invalid").status_code == 422


def test_pcap_upload_normalizes_persists_and_deduplicates_packets(api_client: TestClient) -> None:
    tcp = dpkt.tcp.TCP(sport=45555, dport=443, flags=dpkt.tcp.TH_SYN)
    ip = dpkt.ip.IP(
        src=socket.inet_aton("192.0.2.50"),
        dst=socket.inet_aton("198.51.100.50"),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    ip.len = len(ip)
    frame = bytes(
        dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP,
            data=ip,
        )
    )
    capture = BytesIO()
    writer = dpkt.pcap.Writer(capture)
    writer.writepkt(frame, ts=1_700_000_000)
    content = capture.getvalue()

    uploaded = api_client.post(
        "/api/ingest/pcap",
        files={"file": ("sample.pcap", content, "application/vnd.tcpdump.pcap")},
    )
    duplicate = api_client.post(
        "/api/ingest/pcap",
        files={"file": ("sample.pcap", content, "application/vnd.tcpdump.pcap")},
    )

    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()["accepted"] == 1
    assert uploaded.json()["parsed"] == 1
    assert uploaded.json()["malformed_packets"] == 0
    assert duplicate.json()["accepted"] == 0
    assert duplicate.json()["duplicates"] == 1
    events = api_client.get("/api/events?limit=500").json()["items"]
    event = next(item for item in events if item["sensor_type"] == "pcap")
    assert event["source_ip"] == "192.0.2.50"
    assert event["destination_ip"] == "198.51.100.50"
    assert event["destination_port"] == 443
    assert event["tcp_flags"] == ["SYN"]

    invalid = api_client.post(
        "/api/ingest/pcap",
        files={"file": ("bad.pcap", b"not a capture", "application/octet-stream")},
    )
    assert invalid.status_code == 422


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