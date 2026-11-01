# Deployment Guide

## Supported Deployment

This checkout supports local development only: Next.js frontend, FastAPI backend, and SQLite. The API binds to loopback by default. It has no authentication or RBAC and is not suitable for a shared network, internet-facing host, or production SOC deployment.

Docker, PostgreSQL, Redis, worker processes, migrations, TLS termination, production secrets management, and production health/backup procedures are not implemented. Do not infer deployment support from the desired architecture.

## Local Setup

Requirements: Python 3.10+, Node.js 20+, and npm.

```bash
./install.sh
```

In one terminal, run the API:

```bash
./run_lab.sh
```

In a second terminal, run the frontend:

```bash
npm run dev
```

Browse to <http://localhost:3000>. API health is <http://localhost:8000/health>; interactive route documentation is <http://localhost:8000/docs>.

## Local Configuration

The runner supports `LAB_HOST`, `LAB_PORT`, `LAB_DATABASE_URL`, and `LAB_CORS_ORIGINS`. Keep `LAB_HOST=127.0.0.1`. SQLite data is stored at `data/soc_lab.db` by default. Detection behavior can be configured at API startup:

```bash
LAB_DETECTION_THRESHOLD=8 \
LAB_DETECTION_SOURCE_ALLOWLIST="198.51.100.27,2001:db8:1234::/48" \
./run_lab.sh
```

`LAB_DETECTION_SOURCE_ALLOWLIST` suppresses alert generation for matching *source events*; it does not permit active network scanning. Invalid settings cause startup failure.

## Data Backup and Restore

For this local SQLite prototype, stop the API before copying `data/soc_lab.db` to a protected backup location. Restore by stopping the API and replacing that single database file with a known-good copy. This is a manual local procedure, not a tested production backup system. Protect backups because event payloads may contain sensitive network metadata and raw records.

## Pending Production Work

Do not expose the app until authentication, RBAC, bounded ingestion and rate limiting, deployment secrets, TLS, migrations, and security tests are implemented. Add Docker/Compose and optional SIEM/sensor profiles only with service health checks and end-to-end verification.
