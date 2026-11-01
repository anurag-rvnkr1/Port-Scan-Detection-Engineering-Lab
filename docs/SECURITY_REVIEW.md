# Security Review

Date: 2026-11-01  
Scope: static review of the local FastAPI endpoints, upload handling, event/detection pipeline, runtime scripts, and exposed configuration paths. This is a bounded source review, not a penetration test, dependency audit, or production security certification.

## Findings

| # | Severity | File | Lines | Vulnerability | Confidence |
|---|----------|------|-------|---------------|------------|
| 1 | 🟠 HIGH | `backend/app/main.py` | 150-477 | API routes have no authentication or backend-enforced authorization. If the API is bound to a reachable interface, unauthenticated callers can read telemetry and change alert/incident state or submit data. Default runner binding is loopback, but `LAB_HOST` is configurable. | 9/10 |
| 2 | 🟡 MEDIUM | `backend/app/main.py` | 76-82, 320-402 | Audit actor is a fixed `local-analyst` label rather than a verified identity; records do not provide trustworthy multi-user attribution. | 9/10 |
| 3 | 🟡 MEDIUM | `backend/app/main.py`, `backend/app/pipeline.py` | 465-484, 111-156 | Upload bytes are bounded at 5 MiB, but parsing and accepted/error record lists are accumulated in memory without a record-count limit or request rate limit. Repeated/high-line-count uploads can consume CPU and memory on the local service. | 8/10 |

No evidence of shell-based command execution, a Nmap runner, PCAP parsing, or SIEM credential handling was found because those integrations are not implemented. They are not security-reviewed integrations.

## Existing Protections and Boundaries

- `run_lab.sh` defaults the backend host to `127.0.0.1`; this is the safe local mode.
- CORS origins default to local development URLs. CORS is not authentication and does not prevent non-browser clients from calling the API.
- Upload reads at most 5 MiB + 1 byte, checks UTF-8, restricts parser formats, closes the upload, and reports malformed records.
- SQLAlchemy parameterization is used for application queries; no string-built SQL was identified in reviewed routes.
- Event schemas validate IP addresses and ports, and ingestion deduplicates IDs.
- `LAB_DETECTION_SOURCE_ALLOWLIST` is for excluding detection noise. It is not an authorized-target allowlist and must not be used to authorize scanning.

## Required Before Shared or Production Use

1. Implement and test authentication, server-side RBAC, secure sessions, and rate limiting before binding to a non-loopback interface.
2. Derive audit actors from authenticated identities; make audit records append-only and define retention.
3. Bound parsed record counts, parse-error response sizes, and request frequency in addition to the byte upload limit.
4. Add dependency/container scanning and security-focused API tests in CI.
5. Review PostgreSQL, reverse-proxy, TLS, secret handling, and backup controls before a production deployment.

No remediation for the unauthenticated API or identity model is claimed in this increment. Continue to run the app only as a local single-user prototype.
