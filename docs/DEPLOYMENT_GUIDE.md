# Deployment Guide

## Supported Deployment

The repository supports local development with SQLite and a loopback-only Docker Compose demo stack using PostgreSQL. The Compose stack binds only the frontend to `127.0.0.1`; the API and database have no published host ports and communicate on an internal Docker network. The frontend is attached to a separate bridge network to receive the local published port. Compose runs Alembic migrations before starting the API. This is not a production deployment: there is no TLS termination, Redis/worker, automated backup, sensor/SIEM service, distributed rate limiter, or production secrets management.

## Local Setup

Requirements for local development: Python 3.10+, Node.js 20+, and npm. Requirements for Docker: Docker Engine and the Docker Compose plugin.

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

### Authorized Nmap use

Nmap is included in the backend container. In a local Python setup, install Nmap using your operating system's package manager and verify `nmap --version`. To enable scans, set `LAB_NMAP_ALLOWED_CIDRS` to a private or loopback CIDR for an isolated lab that you are authorized to test; it is empty by default. Example `.env` entry: `LAB_NMAP_ALLOWED_CIDRS=192.168.56.0/24`. Do not add public or third-party ranges. Restart the API after changing this setting. Admins can check `GET /api/nmap/status`, submit a scan through `POST /api/scans`, and review `GET /api/scans` and `/api/scans/{scan_id}`. Requests require explicit confirmation and are bounded by a fixed one-target scope, 256 ports, a 5–300 second timeout, a one-scan process lock, and three scans per admin per hour. This route executes synchronously and cannot be cancelled; a durable worker and cancellation remain pending. SYN scans may require privileges unavailable to the non-root container.

### Zeek and Suricata log sensors

The API can tail existing Zeek `conn.log` TSV or Suricata `eve.json` JSONL files. It does not install or launch either sensor and does not capture packets. For Docker Compose, set `LAB_SENSOR_LOG_MOUNT` to a host directory containing logs; the directory is mounted read-only at `/var/lib/sentinelsoc/sensors`, the only directory allowed by the service. In a local Python run, set `LAB_SENSOR_LOG_DIRS` to one or more explicitly trusted directories separated by the platform path separator. Do not authorize broad system directories or logs from networks you do not administer.

After starting the app, create a sensor with the admin-only `POST /api/sensors` endpoint using `name`, `sensor_type` (`zeek` or `suricata`), and the absolute mounted `log_path`. Start and stop it through `POST /api/sensors/{sensor_id}/start` and `/stop`; `GET /api/sensors` shows status and ingestion counters. Logs are tailed incrementally, including partial lines and file rotation/truncation. Each polling cycle is capped at 256 KiB and 250 records; no historical retention policy is applied to normalized event records. At most 16 sensor definitions and four active tailers are allowed. The tailers run inside the API process and require a single API worker/replica; multi-instance leases and a durable worker are not implemented. Automated tests use temporary fixture files; external Zeek/Suricata processes have not been verified.

An initial Alembic migration is available. To prepare a database before starting the API, run:

```bash
.venv/bin/alembic upgrade head
```

`LAB_DATABASE_URL` selects the migration target; for PostgreSQL, use a `postgresql://` URL (the app selects psycopg 3). The initial migration and API database health check were verified against PostgreSQL 17 in an isolated temporary container; this does not establish a supported production deployment.

## Local Docker Compose Demo

Copy `.env.example` to `.env` and replace the example database password with a locally generated URL-safe value. For example, `openssl rand -hex 32` produces a hexadecimal password that can be pasted into `POSTGRES_PASSWORD`. Never commit `.env`.

```bash
docker compose up --build --wait
```

The dashboard is available at <http://localhost:3000>. Only this loopback address is published; the API is proxied by the frontend and is not exposed as a host port. To provision the initial administrator, run:

```bash
docker compose exec api python -m backend.app.admin create-admin
```

Stop the stack with `docker compose down`; named database volumes remain in place. `docker compose down --volumes` permanently deletes the Compose database and backend volumes, so use it only when intentionally discarding local demo data. The example uses HTTP and is for local demonstration only; do not expose it on an untrusted network.

The frontend API proxy target is supplied as a build argument (`http://api:8000` in Compose) and is internal to the Docker network. If changing this target, rebuild the frontend image. Do not put credentials in this value.

### Optional SIEM delivery

The backend accepts these variables through `.env`; keep tokens out of source control and use a local-only file with restricted permissions:

- Splunk: `SENTINELSOC_SPLUNK_HEC_URL` must be the full `https://.../services/collector/event` URL; set `SENTINELSOC_SPLUNK_HEC_TOKEN`.
- Elasticsearch: set `SENTINELSOC_ELASTICSEARCH_URL` to an HTTPS origin, `SENTINELSOC_ELASTICSEARCH_API_KEY`, and optionally `SENTINELSOC_ELASTICSEARCH_INDEX` (defaults to `sentinelsoc-events`).

Unencrypted HTTP is accepted only for loopback integration testing. TLS certificate verification remains enabled. Leave values blank for offline-only operation. Recreate the API service after changing environment values. Admins can inspect `GET /api/integrations`, send a controlled test event with `POST /api/integrations/{splunk|elasticsearch}/test`, and retry a failed event/alert batch using `POST /api/integrations/deliveries/{delivery_id}/retry`. New ingested events and generated alerts are delivered to enabled integrations; outcomes are recorded in PostgreSQL. Delivery and retry requests are synchronous, and live service ingestion/search was not verified.

## Data Backup and Restore

For this local SQLite prototype, stop the API before copying `data/soc_lab.db` to a protected backup location. Restore by stopping the API and replacing that single database file with a known-good copy. This is a manual local procedure, not a tested production backup system. Protect backups because event payloads may contain sensitive network metadata and raw records.

## Pending Production Work

Although API authentication and role checks are implemented, do not expose the app until HTTPS proxy behavior, production secret management, multi-worker rate limiting, backups, and security tests are implemented. Current upload rate limiting is process-local and is not a distributed limiter. Docker/Compose and optional SIEM/sensor profiles still require service health checks and end-to-end verification.
