# Security Review

Date: 2026-11-01  
Scope: static review of the local FastAPI endpoints, upload handling, event/detection pipeline, runtime scripts, and exposed configuration paths. This is a bounded source review, not a penetration test, dependency audit, or production security certification.

## Previous Findings and Remediation Status

| # | Previous severity | Status | Remediation |
|---|------------------|--------|-------------|
| 1 | HIGH | Mitigated for the local prototype | All data endpoints require an authenticated active user; reads/writes are role-gated; writes require CSRF token and allowed-origin validation. Opaque sessions are stored hashed server-side and expire after eight hours. The runner defaults to loopback. HTTPS reverse-proxy production operation is not verified. |
| 2 | MEDIUM | Fixed in application paths | Audit actions now use the authenticated username. Admin/manager account provisioning replaces public registration; password values are not included in audit details. |
| 3 | MEDIUM | Mitigated with explicit resource ceilings | Upload request size is bounded, content length is required, uploads are capped at 5 MiB/20,000 lines, response parse errors are capped at 100, upload requests are rate limited, and detection history queries are capped. The rate limiter is process-local; multi-worker deployments require Redis/shared limiting. |

No evidence of shell-based command execution, a Nmap runner, PCAP parsing, or SIEM credential handling was found because those integrations are not implemented. They are not security-reviewed integrations.

## Existing Protections and Boundaries

- `run_lab.sh` defaults the backend host to `127.0.0.1`; this is the safe local mode.
- CORS origins default to local development URLs. CORS is not authentication and does not prevent non-browser clients from calling the API.
- Upload reads at most 5 MiB + 1 byte, checks UTF-8, restricts parser formats, closes the upload, and reports malformed records.
- SQLAlchemy parameterization is used for application queries; no string-built SQL was identified in reviewed routes.
- Event schemas validate IP addresses and ports, and ingestion deduplicates IDs.
- `LAB_DETECTION_SOURCE_ALLOWLIST` is for excluding detection noise. It is not an authorized-target allowlist and must not be used to authorize scanning.

## Remaining Before Shared or Production Use

1. Replace process-local rate limiting with a shared backend before adding workers/replicas.
2. Verify secure-cookie behavior behind the chosen HTTPS reverse proxy and deploy frontend/API on a compatible same-site origin.
3. Add dependency/container scanning and security-focused API tests in CI.
4. Review PostgreSQL, TLS, secret handling, migrations, audit retention, and backup controls before production deployment.

This update is a code-level mitigation and test pass, not an external penetration test or production security certification. Continue to use the app as a local prototype.
