from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timezone
import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import integrations, main
from backend.app.auth import create_user
from backend.app.database import Base, IntegrationDeliveryRow
from backend.app.sensors import SensorManager


class MockResponse:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self.is_success = 200 <= status_code < 300
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class MockClient:
    def __init__(self, response_factory, requests: list[dict]) -> None:
        self.response_factory = response_factory
        self.requests = requests

    def __enter__(self) -> MockClient:
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def post(self, url: str, *, headers: dict, content: bytes) -> MockResponse:
        self.requests.append({"url": url, "headers": headers, "content": content})
        return self.response_factory()


@pytest.fixture
def delivery_session() -> Iterator[Session]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with factory() as session:
        yield session
    engine.dispose()


@pytest.fixture
def api_client(monkeypatch) -> Iterator[TestClient]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        with factory() as session:
            yield session

    with factory() as session:
        create_user(session, "siem-admin", "test-password-for-siem-admin", "super_admin")
        session.commit()
    monkeypatch.setattr(main, "request_limiter", main.SlidingWindowLimiter())
    monkeypatch.setattr(main, "sensor_manager", SensorManager(factory, main._persist))
    main.app.dependency_overrides[main.get_db] = override_db
    try:
        with TestClient(main.app) as client:
            login = client.post(
                "/api/auth/login",
                json={"username": "siem-admin", "password": "test-password-for-siem-admin"},
            )
            assert login.status_code == 200
            client.headers.update({"X-CSRF-Token": login.json()["csrf_token"]})
            yield client
    finally:
        main.app.dependency_overrides.clear()
        engine.dispose()


def install_mock_client(monkeypatch, response_factory, requests: list[dict]) -> None:
    monkeypatch.setattr(
        integrations.httpx,
        "Client",
        lambda **_: MockClient(response_factory, requests),
    )
    monkeypatch.setattr(integrations.time, "sleep", lambda _: None)


def test_splunk_hec_receives_structured_event_and_ack(delivery_session, monkeypatch) -> None:
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_URL", "https://splunk.example/services/collector/event")
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_TOKEN", "test-token-do-not-log")
    requests: list[dict] = []
    install_mock_client(monkeypatch, lambda: MockResponse(200, {"code": 0, "text": "Success"}), requests)
    event = {
        "event_id": "event-1",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "destination_port": 443,
        "protocol": "tcp",
    }

    result = integrations.deliver_records(delivery_session, "splunk", "network_event", [event])

    assert len(result) == 1
    assert result[0].status == "delivered"
    assert result[0].attempts == 1
    assert requests[0]["headers"]["Authorization"] == "Splunk test-token-do-not-log"
    content = requests[0]["content"]
    assert isinstance(content, bytes)
    body = json.loads(content.decode().strip())
    assert body["sourcetype"] == "_json"
    assert body["event"] == event
    assert result[0].error is None


def test_elasticsearch_bulk_uses_api_key_and_stable_document_id(delivery_session, monkeypatch) -> None:
    monkeypatch.setenv("SENTINELSOC_ELASTICSEARCH_URL", "https://elastic.example:9200")
    monkeypatch.setenv("SENTINELSOC_ELASTICSEARCH_API_KEY", "encoded-api-key")
    monkeypatch.setenv("SENTINELSOC_ELASTICSEARCH_INDEX", "soc-events")
    requests: list[dict] = []
    install_mock_client(
        monkeypatch,
        lambda: MockResponse(200, {"errors": False, "items": [{"index": {"status": 201}}]}),
        requests,
    )

    result = integrations.deliver_records(
        delivery_session,
        "elasticsearch",
        "network_event",
        [{"event_id": "event-42", "timestamp": "2026-11-01T00:00:00+00:00"}],
    )

    content = requests[0]["content"]
    assert isinstance(content, bytes)
    lines = content.decode().splitlines()
    assert result[0].status == "delivered"
    assert requests[0]["url"] == "https://elastic.example:9200/_bulk"
    assert requests[0]["headers"]["Authorization"] == "ApiKey encoded-api-key"
    assert json.loads(lines[0])["index"] == {"_index": "soc-events", "_id": "event-42"}


def test_delivery_retries_are_bounded_and_do_not_persist_remote_body(delivery_session, monkeypatch) -> None:
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_URL", "https://splunk.example/services/collector/event")
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_TOKEN", "secret-value")
    requests: list[dict] = []
    install_mock_client(
        monkeypatch,
        lambda: MockResponse(503, {"message": "secret-value and internal detail"}),
        requests,
    )

    result = integrations.deliver_records(
        delivery_session,
        "splunk",
        "network_event",
        [{"event_id": "event-fail", "timestamp": "2026-11-01T00:00:00+00:00"}],
    )

    assert len(requests) == integrations.MAX_RETRIES
    assert result[0].status == "failed"
    assert result[0].attempts == integrations.MAX_RETRIES
    assert result[0].error == "remote service returned HTTP 503"
    assert "secret-value" not in result[0].error


def test_successful_batch_delivery_is_idempotent(delivery_session, monkeypatch) -> None:
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_URL", "https://splunk.example/services/collector/event")
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_TOKEN", "token")
    requests: list[dict] = []
    install_mock_client(monkeypatch, lambda: MockResponse(200, {"code": 0}), requests)
    event = {"event_id": "unique-id", "timestamp": "2026-11-01T00:00:00+00:00"}

    first = integrations.deliver_records(delivery_session, "splunk", "network_event", [event])
    second = integrations.deliver_records(delivery_session, "splunk", "network_event", [event])

    assert len(requests) == 1
    assert first[0].id == second[0].id
    assert len(delivery_session.scalars(select(IntegrationDeliveryRow)).all()) == 1


@pytest.mark.parametrize(
    ("name", "url_environment", "secret_environment", "url"),
    [
        ("splunk", "SENTINELSOC_SPLUNK_HEC_URL", "SENTINELSOC_SPLUNK_HEC_TOKEN", "http://192.0.2.10/services/collector/event"),
        ("elasticsearch", "SENTINELSOC_ELASTICSEARCH_URL", "SENTINELSOC_ELASTICSEARCH_API_KEY", "http://elastic.example:9200"),
        ("elasticsearch", "SENTINELSOC_ELASTICSEARCH_URL", "SENTINELSOC_ELASTICSEARCH_API_KEY", "https://elastic.example/path"),
    ],
)
def test_rejects_unsafe_endpoint_configuration(monkeypatch, name, url_environment, secret_environment, url) -> None:
    monkeypatch.setenv(url_environment, url)
    monkeypatch.setenv(secret_environment, "not-a-real-secret")

    with pytest.raises(ValueError):
        integrations.load_config(name)


def test_ingestion_dispatches_events_to_configured_integration(api_client, monkeypatch) -> None:
    monkeypatch.delenv("SENTINELSOC_ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("SENTINELSOC_ELASTICSEARCH_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_URL", "https://splunk.example/services/collector/event")
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_TOKEN", "api-test-token")
    requests: list[dict] = []
    install_mock_client(monkeypatch, lambda: MockResponse(200, {"code": 0}), requests)

    response = api_client.post("/api/demo/generate?scenario=benign&count=2")

    assert response.status_code == 200
    assert response.json()["accepted"] == 2
    assert len(requests) == 1
    content = requests[0]["content"]
    assert isinstance(content, bytes)
    batch = [json.loads(line) for line in content.decode().splitlines()]
    assert len(batch) == 2
    assert all(item["source"] == "sentinelsoc:network_event" for item in batch)
    status = api_client.get("/api/integrations")
    assert status.status_code == 200
    assert status.json()["integrations"]["splunk"]["configured"] is True
    assert status.json()["recent_deliveries"][0]["status"] == "delivered"
    assert "api-test-token" not in status.text


def test_admin_can_send_a_controlled_integration_test_event(api_client, monkeypatch) -> None:
    monkeypatch.delenv("SENTINELSOC_ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("SENTINELSOC_ELASTICSEARCH_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_URL", "https://splunk.example/services/collector/event")
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_TOKEN", "test-token")
    requests: list[dict] = []
    install_mock_client(monkeypatch, lambda: MockResponse(200, {"code": 0}), requests)

    response = api_client.post("/api/integrations/splunk/test")

    assert response.status_code == 200
    assert response.json()["status"] == "delivered"
    assert "test-token" not in response.text
    payload = json.loads(requests[0]["content"].decode().strip())
    assert payload["event"]["event_type"] == "integration_test"
    assert api_client.get("/api/integrations").json()["recent_deliveries"][0]["record_type"] == "test_event"


def test_admin_can_retry_failed_delivery_from_persisted_records(api_client, monkeypatch) -> None:
    monkeypatch.delenv("SENTINELSOC_ELASTICSEARCH_URL", raising=False)
    monkeypatch.delenv("SENTINELSOC_ELASTICSEARCH_API_KEY", raising=False)
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_URL", "https://splunk.example/services/collector/event")
    monkeypatch.setenv("SENTINELSOC_SPLUNK_HEC_TOKEN", "test-token")
    requests: list[dict] = []
    response_count = 0

    def response_factory() -> MockResponse:
        nonlocal response_count
        response_count += 1
        if response_count <= integrations.MAX_RETRIES:
            return MockResponse(503, {"text": "not accepted"})
        return MockResponse(200, {"code": 0})

    install_mock_client(monkeypatch, response_factory, requests)
    ingest = api_client.post("/api/demo/generate?scenario=benign&count=2")
    failed_delivery = api_client.get("/api/integrations").json()["recent_deliveries"][0]

    assert ingest.status_code == 200
    assert failed_delivery["status"] == "failed"
    retried = api_client.post(f"/api/integrations/deliveries/{failed_delivery['delivery_id']}/retry")

    assert retried.status_code == 200
    assert retried.json()["status"] == "delivered"
    assert retried.json()["attempts"] == integrations.MAX_RETRIES + 1
    assert response_count == integrations.MAX_RETRIES + 1


def test_integration_settings_are_admin_only(api_client) -> None:
    created = api_client.post(
        "/api/users",
        json={"username": "integration-viewer", "password": "viewer-password-long-123", "role": "read_only_viewer"},
    )
    assert created.status_code == 201
    viewer = TestClient(main.app)
    login = viewer.post(
        "/api/auth/login",
        json={"username": "integration-viewer", "password": "viewer-password-long-123"},
    )
    assert login.status_code == 200
    assert api_client.get("/api/integrations").status_code == 200
    assert viewer.get("/api/integrations").status_code == 403
