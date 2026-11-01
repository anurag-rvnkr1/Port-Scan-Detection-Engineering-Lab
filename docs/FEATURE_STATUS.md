# SentinelSOC Feature Status

Status reflects code and checks available in this repository as of 2026-11-01. "Implemented" means the local application code exists and focused tests or build checks passed; it does not imply production readiness or real-world detection efficacy.

| Capability | Status | Evidence / limitation |
|---|---|---|
| FastAPI REST API | Implemented | Health, events, alerts, incidents, ingestion, demo generation, and summary report routes; see OpenAPI at `/docs` when running locally. |
| Canonical event normalization | Implemented | Pydantic validation, UTC timestamps, IPv4/IPv6 addresses, TCP flags, and raw input retention. |
| Offline log ingestion | Implemented | Zeek TSV, Suricata EVE JSONL, and supported UFW-style syslog; UTF-8 upload capped at 5 MiB. No live sensors. |
| Synthetic scenarios | Implemented | Deterministic, labeled benign/SYN/connect/sweep/FIN/NULL/XMAS/low-and-slow scenarios. These do not generate network traffic. |
| Scan detections | Implemented in part | Explainable horizontal, vertical, connect, low-and-slow, SYN, FIN, NULL, and XMAS heuristics. Threshold and source IP/CIDR allowlist are configurable at process start. No tuning UI, broad correlation, calibrated confidence, or production quality claims. |
| Event/alert persistence | Implemented | SQLite persistence, duplicate event IDs skipped, bounded one-hour event lookback for detection. |
| Alert and incident workflow | Partial | Local status/assignment/note endpoints, incident lifecycle, and audit records exist. No authenticated actor, analyst accounts, teams, or RBAC. |
| SOC dashboard | Partial | API-backed overview, events, alerts, incidents, ingestion, loading/error handling, periodic refresh, and CSV export. No login, responsive-accessibility audit, full page suite, or browser-driven E2E verification. |
| Summary reporting | Partial | Database-backed JSON and CSV summary reports. No PDF, date-range/report permissions, charts, or full analyst-note report. |
| Authentication / RBAC | Not implemented | API is unauthenticated. Keep backend bound to loopback; CORS is not an authorization boundary. |
| Nmap integration | Not implemented | The reference shell commands are not an app-mediated scanner. No target allowlist, job queue, cancellation, or scan verification. |
| Live capture / Zeek / Suricata sensors | Not implemented | Parsers handle offline files only; packet capture and sensor health are not present. |
| PCAP processing | Not implemented | No PCAP upload/parser workflow. |
| Splunk HEC | Not implemented | Checked-in SPL/dashboard artifacts are reference material only; no event delivery/search verification. |
| Elasticsearch | Not implemented | Query artifacts are not connected to an indexing/search client. |
| PDF reports | Not implemented | No PDF library or generation endpoint. |
| PostgreSQL / migrations | Not implemented | SQLite is the only validated configuration; schema uses `create_all`, not Alembic. |
| Redis / background worker | Not implemented | Work is synchronous in the API process. |
| Docker / deployment profiles | Not implemented | No Dockerfiles or Compose stack. |
| CI/CD | Not implemented | No GitHub Actions workflow. |
| Detection quality / performance evaluation | Not implemented | Synthetic fixture tests are regression checks, not independent accuracy or production-performance measurements. |

## Recent Verified Increment

The API reads `LAB_DETECTION_THRESHOLD` (3–65536; default 8) and `LAB_DETECTION_SOURCE_ALLOWLIST` (comma-separated IPv4/IPv6 addresses or CIDRs) at startup. Invalid values stop startup with an explicit error. Matching source events continue to be ingested and queryable but are omitted from scan alert generation. Unit and API tests cover the behavior.

See [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) for phase gates and [TESTING_REPORT.md](./TESTING_REPORT.md) for executed checks.
