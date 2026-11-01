# Testing Report

Date: 2026-11-01

## Executed Checks

| Command | Result | Scope |
|---|---|---|
| `.venv/bin/python -m pytest -q` (before change) | 36 passed | Backend baseline. |
| `.venv/bin/python -m pytest -q` (current) | 57 passed | Backend unit/API suite, including PDF endpoint/content, PostgreSQL URL normalization, isolated SQLite migration checks, and unsafe reverse-proxy origin rejection. |
| `npm run lint` (current) | Passed | ESLint configured for `app/`; includes account-management UI correction. |
| `npm run typecheck` (current) | Passed | `tsc --noEmit`. |
| `npm run build` (current) | Passed | Next.js production build, including TypeScript phase. |
| `.venv/bin/ruff check --select E4,E7,E9,F backend tests` | Passed | Same Ruff correctness rules configured in CI. |
| `.venv/bin/pip check` | Passed | Installed Python dependency consistency. |
| `npm run test:e2e` | 1 passed | Chromium browser workflow: administrator sign-in, create analyst, generate detections, investigate and assign alert, create/update incident, verify audit actor, download PDF. |
| PostgreSQL 17 Docker integration check | Passed | Fresh container, Alembic upgrade/check, and FastAPI `/health` database connectivity; temporary container was stopped and removed. |
| `docker compose --env-file .env.example config --quiet` | Passed | Compose schema/interpolation validation; no containers started. |
| `docker compose build` | Passed | Backend and Next.js frontend images built locally. |
| Docker Compose deployment smoke test | Passed | PostgreSQL, migration-before-API startup, API/frontend health, and database connectivity succeeded. Through the frontend proxy, unauthenticated access returned 401, admin login issued an HttpOnly session, a write without CSRF returned 403, and a CSRF-protected write succeeded. API port was not published; frontend bound to `127.0.0.1:3010` because local port 3000 was already in use. The test stack and its temporary volumes were removed afterward. |

The current backend and frontend checks were rerun after implementation changes.

## New Regression Coverage

- CIDR allowlisting suppresses detections for matching sources while non-allowlisted events in the same batch can still alert.
- Threshold boundary is exercised with events below the default and at a configured threshold.
- IPv4 and IPv6 allowlist parsing and invalid-entry rejection are covered.
- Startup configuration parsing and invalid threshold/allowlist rejection are covered.
- API-level check verifies allowlisted synthetic events persist and count in event metrics while creating no alerts.
- PDF endpoint creates valid parseable PDFs from persisted records; tests check expected report labels, severity/rule content, metric text, response disposition, and invalid period validation.
- The frontend exposes the weekly PDF report endpoint.
- Alembic migration applies to a fresh isolated SQLite database and creates all expected application tables. `alembic check` reports no schema drift after upgrade.
- PostgreSQL 17: initial migration and schema check completed; API health returned `{"status":"ok","mode":"offline-demo","database":"connected"}`.
- PostgreSQL URL normalization selects psycopg 3.
- An API configured for non-loopback HTTP cookies with the loopback-proxy opt-in rejects non-loopback CORS origins.

## Not Executed / Not Established

- No load/performance test, clean-environment installation, or production deployment was verified in this pass. The local Compose demo stack was built and started, but is not a production deployment. Browser E2E covers one local administrator workflow, not all pages or roles.
- No live Nmap, packet capture, Zeek/Suricata process, Splunk HEC, or Elasticsearch service was available or exercised.
- No security scanner, dependency audit, formal type checker for Python, or detection-quality benchmark was run in this pass.
- GitHub Actions workflow files were added, but no remote Actions execution was available; Gitleaks, dependency review, and container scanning are not claimed as executed.
- The labeled synthetic tests do not establish precision, recall, false-positive rate, or field accuracy.

Only the results in the executed-check table are claimed as successful.
