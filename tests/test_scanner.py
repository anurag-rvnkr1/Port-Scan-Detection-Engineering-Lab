from __future__ import annotations

from collections.abc import Iterator
import ipaddress
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app import main, scanner
from backend.app.auth import create_user
from backend.app.database import Base


@pytest.fixture
def api_client(monkeypatch) -> Iterator[TestClient]:
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Iterator[Session]:
        with sessions() as session:
            yield session

    with sessions() as session:
        create_user(session, "soc-admin", "test-password-for-admin-123", "super_admin")
        session.commit()
    monkeypatch.setattr(main, "request_limiter", main.SlidingWindowLimiter())
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


NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" />
    <ports>
      <port protocol="tcp" portid="443"><state state="open" /><service name="https" product="Example" version="1.2" /></port>
      <port protocol="tcp" portid="22"><state state="closed" /></port>
    </ports>
  </host>
</nmaprun>
"""


def test_authorized_cidr_configuration_is_opt_in_and_private_only(monkeypatch) -> None:
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "/usr/bin/nmap")
    monkeypatch.delenv("LAB_NMAP_ALLOWED_CIDRS", raising=False)
    assert scanner.load_configuration().enabled is False

    monkeypatch.setenv("LAB_NMAP_ALLOWED_CIDRS", "192.168.56.0/24,fd00:1234::/48")
    configuration = scanner.load_configuration()
    assert configuration.enabled is True
    assert len(configuration.authorized_networks) == 2

    monkeypatch.setenv("LAB_NMAP_ALLOWED_CIDRS", "0.0.0.0/0")
    with pytest.raises(scanner.NmapConfigurationError):
        scanner.load_configuration()


@pytest.mark.parametrize("target", ["scan.example", "192.168.56.5;id", "203.0.113.12", "192.168.57.5"])
def test_authorization_rejects_hostnames_injection_public_and_unlisted_targets(target: str) -> None:
    allowed = (ipaddress.ip_network("192.168.56.0/24"),)
    with pytest.raises(scanner.NmapConfigurationError):
        scanner.authorize_target(target, allowed)


def test_command_uses_fixed_arguments_and_parses_open_service_output(monkeypatch) -> None:
    configuration = scanner.ScanConfiguration(
        executable="/usr/bin/nmap",
        authorized_networks=(ipaddress.ip_network("192.168.56.0/24"),),
    )
    arguments = scanner.build_command(
        target="192.168.56.15",
        profile="selected_ports",
        scan_type="tcp_connect",
        ports=[443, 22],
        service_detection=True,
        configuration=configuration,
    )
    assert arguments == [
        "/usr/bin/nmap", "-n", "-T3", "--reason", "-oX", "-",
        "-sT", "-p", "22,443", "-sV", "192.168.56.15",
    ]

    observed: dict = {}

    def fake_run(command: list[str], **kwargs) -> SimpleNamespace:
        observed["command"] = command
        observed["kwargs"] = kwargs
        return SimpleNamespace(returncode=0, stdout=NMAP_XML)

    monkeypatch.setattr(scanner.subprocess, "run", fake_run)
    result = scanner.execute_command(arguments, timeout_seconds=30)
    assert result == {
        "host_status": "up",
        "open_ports": [
            {"protocol": "tcp", "port": 443, "service": "https", "product": "Example", "version": "1.2"}
        ],
    }
    assert observed["kwargs"]["timeout"] == 30
    assert "shell" not in observed["kwargs"]


def test_scan_profiles_reject_unsafe_or_ambiguous_options() -> None:
    configuration = scanner.ScanConfiguration(
        executable="/usr/bin/nmap",
        authorized_networks=(ipaddress.ip_network("127.0.0.1/32"),),
    )
    with pytest.raises(scanner.NmapConfigurationError, match="require at least one port"):
        scanner.build_command(
            target="127.0.0.1",
            profile="selected_ports",
            scan_type="tcp_connect",
            ports=None,
            service_detection=False,
            configuration=configuration,
        )
    with pytest.raises(scanner.NmapConfigurationError, match="does not accept"):
        scanner.build_command(
            target="127.0.0.1",
            profile="host_discovery",
            scan_type="tcp_connect",
            ports=[80],
            service_detection=False,
            configuration=configuration,
        )


def test_nmap_api_requires_admin_and_persists_authenticated_scan_history(api_client, monkeypatch) -> None:
    configuration = scanner.ScanConfiguration(
        executable="/usr/bin/nmap",
        authorized_networks=(ipaddress.ip_network("192.168.56.0/24"),),
    )
    monkeypatch.setattr("backend.app.main.load_nmap_configuration", lambda: configuration)
    executed: dict = {}

    def fake_execute(command: list[str], timeout_seconds: int) -> dict:
        executed["command"] = command
        executed["timeout"] = timeout_seconds
        return {"host_status": "up", "open_ports": [{"protocol": "tcp", "port": 443}]}

    monkeypatch.setattr("backend.app.main.execute_command", fake_execute)
    response = api_client.post(
        "/api/scans",
        json={
            "target": "192.168.56.12",
            "profile": "selected_ports",
            "scan_type": "tcp_connect",
            "ports": [443, 22],
            "service_detection": True,
            "timeout_seconds": 30,
            "confirm_authorized": True,
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["initiated_by"] == "soc-admin"
    assert payload["result"]["open_ports"] == [{"protocol": "tcp", "port": 443}]
    assert executed["timeout"] == 30
    assert executed["command"][-1] == "192.168.56.12"
    assert "192.168.56.12" not in executed["command"][:-1]

    history = api_client.get("/api/scans")
    assert history.status_code == 200
    assert history.json()["items"][0]["scan_id"] == payload["scan_id"]
    detail = api_client.get(f"/api/scans/{payload['scan_id']}")
    assert detail.json()["initiated_by"] == "soc-admin"


def test_nmap_api_disables_scanning_without_explicit_allowlist(api_client, monkeypatch) -> None:
    monkeypatch.setattr(
        "backend.app.main.load_nmap_configuration",
        lambda: scanner.ScanConfiguration(executable="/usr/bin/nmap", authorized_networks=()),
    )
    response = api_client.post(
        "/api/scans",
        json={
            "target": "192.168.56.12",
            "confirm_authorized": True,
        },
    )
    assert response.status_code == 503


def test_nmap_api_rejects_external_targets_before_execution(api_client, monkeypatch) -> None:
    configuration = scanner.ScanConfiguration(
        executable="/usr/bin/nmap",
        authorized_networks=(ipaddress.ip_network("192.168.56.0/24"),),
    )
    monkeypatch.setattr("backend.app.main.load_nmap_configuration", lambda: configuration)
    response = api_client.post(
        "/api/scans",
        json={"target": "198.51.100.25", "confirm_authorized": True},
    )
    assert response.status_code == 422
