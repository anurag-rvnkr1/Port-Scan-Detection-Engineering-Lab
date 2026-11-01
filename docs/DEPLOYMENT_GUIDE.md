# Deployment Guide

## Supported Deployment

This checkout supports local development only: Next.js frontend, FastAPI backend, and SQLite. The API binds to loopback by default and enforces authenticated sessions and roles. It is not yet a production SOC deployment.

PostgreSQL and Alembic have local integration coverage, but Docker deployment, Redis, worker processes, TLS termination, production secrets management, and production health/backup procedures are not implemented. PDF reports are available locally but are not yet separately tested in a deployed production environment. Do not infer deployment support from the desired architecture.

## Local Setup

Requirements: Python 3.10+, Node.js 20+, and npm.

```bash
./install.sh
```

In one terminal, run the API:

```bash
./run_lab.sh
```

Create the first administrator interactively before logging in:

```bash
.venv/bin/python -m backend.app.admin create-admin
```

In a second terminal, run the frontend:

```bash
npm run dev
```

Browse to <http://localhost:3000>. API health is <http://localhost:8000/health>; interactive route documentation is <http://localhost:8000/docs>.

## Local Configuration

The runner supports `LAB_HOST`, `LAB_PORT`, `LAB_DATABASE_URL`, `LAB_CORS_ORIGINS`, and `LAB_COOKIE_SECURE`. Keep `LAB_HOST=127.0.0.1`. Set `LAB_COOKIE_SECURE=true` only when HTTPS is terminated by a trusted reverse proxy; use an HTTPS same-site frontend/API deployment and configure exact frontend origins. SQLite data is stored at `data/soc_lab.db` by default. Detection behavior can be configured at API startup:

```bash
LAB_DETECTION_THRESHOLD=8 \
LAB_DETECTION_SOURCE_ALLOWLIST="198.51.100.27,2001:db8:1234::/48" \
./run_lab.sh
```

`LAB_DETECTION_SOURCE_ALLOWLIST` suppresses alert generation for matching *source events*; it does not permit active network scanning. Invalid settings cause startup failure.

An initial Alembic migration is available. To prepare a database before starting the API, run:

```bash
.venv/bin/alembic upgrade head
```

`LAB_DATABASE_URL` selects the migration target; for PostgreSQL, use a `postgresql://` URL (the app selects psycopg 3). The initial migration and API database health check were verified against PostgreSQL 17 in an isolated temporary container; this does not establish a supported production deployment.

## Data Backup and Restore

For this local SQLite prototype, stop the API before copying `data/soc_lab.db` to a protected backup location. Restore by stopping the API and replacing that single database file with a known-good copy. This is a manual local procedure, not a tested production backup system. Protect backups because event payloads may contain sensitive network metadata and raw records.

## Pending Production Work

Although API authentication and role checks are implemented, do not expose the app until HTTPS proxy behavior, production secret management, multi-worker rate limiting, backups, and security tests are implemented. Current upload rate limiting is process-local and is not a distributed limiter. Docker/Compose and optional SIEM/sensor profiles still require service health checks and end-to-end verification.
