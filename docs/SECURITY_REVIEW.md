# Security Review

Date: 2026-11-01  
Scope: static review of the local FastAPI endpoints, upload handling, event/detection pipeline, runtime scripts, and exposed configuration paths. This is a bounded source review, not a penetration test, dependency audit, or production security certification.

## Previous Findings and Remediation Status

| # | Previous severity | Status | Remediation |
|---|------------------|--------|-------------|
| 1 | HIGH | Mitigated for the local prototype | All data endpoints require an authenticated active user; reads/writes are role-gated; writes require CSRF token and allowed-origin validation. Opaque sessions are stored hashed server-side and expire after eight hours. The runner defaults to loopback. HTTPS reverse-proxy production operation is not verified. |
| 2 | MEDIUM | Fixed in application paths | Audit actions now use the authenticated username. Admin/manager account provisioning replaces public registration; password values are not included in audit details. |
| 3 | MEDIUM | Mitigated with explicit resource ceilings | Upload request size is bounded, content length is required, uploads are capped at 5 MiB/20,000 lines, response parse errors are capped at 100, upload requests are rate limited, and detection history queries are capped. The rate limiter is process-local; multi-worker deployments require Redis/shared limiting. |

This review covers the current local scanner controls and optional SIEM client code; it is not a penetration test. The scanner has not been run against a live lab target.

## Existing Protections and Boundaries

- `run_lab.sh` defaults the backend host to `127.0.0.1`; this is the safe local mode.
- CORS origins default to local development URLs. CORS is not authentication and does not prevent non-browser clients from calling the API.
- Upload reads at most 5 MiB + 1 byte, checks UTF-8, restricts parser formats, closes the upload, and reports malformed records.
- SQLAlchemy parameterization is used for application queries; no string-built SQL was identified in reviewed routes.
- Event schemas validate IP addresses and ports, and ingestion deduplicates IDs.
- `LAB_DETECTION_SOURCE_ALLOWLIST` is for excluding detection noise. It is not an authorized-target allowlist and must not be used to authorize scanning.
- Active Nmap scans are disabled by default. The separate `LAB_NMAP_ALLOWED_CIDRS` setting accepts only explicit private or loopback CIDRs; requests must target one IP inside that list and require an authenticated administrator plus a confirmation field. Nmap receives a fixed argv list without a shell, with service/script options restricted, a one-process lock, per-admin rate limit, port ceiling, and timeout. The current API call is synchronous, so request workers can be occupied until the bounded timeout; use a durable isolated worker before expanding scope.
- Zeek/Suricata log tailers are admin-configured and restricted to regular files beneath `LAB_SENSOR_LOG_DIRS`; paths are opened component-by-component with `O_NOFOLLOW` where supported, reads and lines/records per poll are bounded, and the Compose mount is read-only. Tailers are single-process/in-memory workers backed by persisted cursors; use a shared worker/lease model before deploying multiple API replicas.
- In the local Compose stack, the API and PostgreSQL are on an internal network with no published host ports; the frontend alone is published on host loopback. The Next.js server-side proxy forwards same-origin API traffic, caps request bodies at 6 MiB, and uses no-store responses. This topology has a local smoke test; it is not a substitute for production TLS, proxy identity verification, and network-policy review.
- Pinned Python dependencies were audited and vulnerable AnyIO, Starlette, and pytest versions were upgraded; the current lock reports no known Python dependency vulnerabilities. Production npm dependencies also report none. The complete npm tree retains 16 moderate advisories in development lint tooling (`minimatch`); the suggested forced remediation downgrades ESLint to a breaking major, so it was not applied. CI audits npm at a high/critical threshold and includes Trivy high/critical image scans, but the remote workflow has not yet run.
- SIEM URLs and tokens are environment-configured, never returned by status endpoints or stored in delivery rows. TLS certificate verification is enabled, ambient proxy use is disabled, cleartext HTTP is restricted to loopback, endpoint paths and index names are validated, and request timeouts/retries/batch sizes are bounded. Live service verification and asynchronous delivery controls remain outstanding.

## Remaining Before Shared or Production Use

1. Replace process-local rate limiting with a shared backend before adding workers/replicas.
2. Verify secure-cookie behavior behind the chosen HTTPS reverse proxy and deploy frontend/API on a compatible same-site origin.
3. Execute the dependency/container scans in remote CI and keep resolving development-tool advisories through compatible upstream releases.
4. Review PostgreSQL, TLS, secret handling, migrations, audit retention, and backup controls before production deployment.

This update is a code-level mitigation and test pass, not an external penetration test or production security certification. Continue to use the app as a local prototype.
