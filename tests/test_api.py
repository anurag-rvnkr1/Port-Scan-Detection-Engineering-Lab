from collections.abc import Iterator
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import main
from backend.app.database import Base


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