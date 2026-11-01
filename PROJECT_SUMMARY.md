# SentinelSOC Project Status Summary

## Current Status: Offline Detection Engineering Prototype

The repository contains a functioning local FastAPI + SQLite backend and Next.js dashboard for synthetic and offline network telemetry. It is not production-ready and must not be presented as a fully deployed SOC platform.

## Implemented and Verified

- Canonical Pydantic event schema, UTC normalization, IPv4/IPv6 support, protocol and TCP flag normalization.
- Deterministic labeled synthetic scenarios that do not send network traffic.
- Zeek TSV, Suricata EVE JSONL, and supported UFW-style log ingestion.
- SQLite persistence and event deduplication.
- Explainable heuristic horizontal/vertical, connect, low-and-slow, SYN, FIN, NULL, and XMAS detections.
- Process-start configurable detection threshold and IPv4/IPv6 source address/CIDR exclusions. Excluded events remain ingested.
- API-backed dashboard, alert evidence and workflow, incident statuses/audit entries, and JSON/CSV summary reporting.
- Backend suite: 44 tests passed on 2026-11-01. ESLint, TypeScript checking, and Next.js production build passed in the same implementation pass.

## Not Implemented or Verified

- Authentication, RBAC, analyst identity, and trustworthy multi-user audit attribution.
- Controlled Nmap scanning, live packet capture, Zeek/Suricata sensor processes, and PCAP analysis.
- Splunk HEC and Elasticsearch delivery/search integrations.
- PDF reports, PostgreSQL, Alembic migrations, Redis/background workers, and real-time push.
- Docker deployment, GitHub Actions CI, Playwright workflows, load/performance testing, and independent detection-quality evaluation.

The unauthenticated API must remain loopback-bound. Synthetic fixture behavior is not a real-world precision/recall claim. See [docs/FEATURE_STATUS.md](docs/FEATURE_STATUS.md), [docs/TESTING_REPORT.md](docs/TESTING_REPORT.md), and [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) for precise status and limitations.
