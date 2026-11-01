from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from sqlalchemy import create_engine, inspect


ROOT = Path(__file__).resolve().parents[1]


def test_postgres_urls_select_psycopg_driver_without_connecting() -> None:
    environment = os.environ | {
        "LAB_DATABASE_URL": "postgresql://soc:test-only@localhost:5432/sentinelsoc"
    }
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from backend.app.database import DATABASE_URL; print(DATABASE_URL)",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == "postgresql+psycopg://soc:test-only@localhost:5432/sentinelsoc"


def test_insecure_cookie_proxy_mode_rejects_non_loopback_origins() -> None:
    environment = os.environ | {
        "LAB_HOST": "0.0.0.0",
        "LAB_COOKIE_SECURE": "false",
        "LAB_TRUSTED_LOOPBACK_PROXY": "true",
        "LAB_CORS_ORIGINS": "https://soc.example.com",
    }
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from backend.app.main import app",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "loopback-only CORS origins" in result.stderr


def test_initial_migration_creates_current_sqlite_schema(tmp_path: Path) -> None:
    database_path = tmp_path / "migration-test.db"
    database_url = f"sqlite:///{database_path}"
    environment = os.environ | {"LAB_DATABASE_URL": database_url}

    subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(ROOT / "alembic.ini"),
            "upgrade",
            "head",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            sys.executable,
            "-m",
            "alembic",
            "-c",
            str(ROOT / "alembic.ini"),
            "check",
        ],
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    engine = create_engine(database_url)
    try:
        tables = set(inspect(engine).get_table_names())
        assert {
            "alembic_version",
            "audit_log",
            "auth_sessions",
            "incidents",
            "network_events",
            "security_alerts",
            "users",
        } <= tables
    finally:
        engine.dispose()
