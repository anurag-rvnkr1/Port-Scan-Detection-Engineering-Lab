# Project Status Summary

## Current Status: Functional Local Detection Prototype

This repository now has a tested offline backend pipeline and an API-backed SOC dashboard. It is not production-ready and does not implement all originally proposed capabilities. Do not represent optional SIEM integrations, live traffic capture, Nmap execution, incident management, PDF reporting, authentication, or CI/CD as completed.

## Implemented and Locally Verified

- FastAPI API with a database health check and local SQLite persistence.
- Pydantic canonical event schema with IPv4/IPv6 validation, UTC timestamp normalization, protocol/flag normalization, and raw-event preservation.
- Deterministic synthetic scenarios: SYN, Connect-like, sweep, FIN, NULL, XMAS, and benign TCP records.
- Parsers for included Zeek TSV, Suricata EVE JSON Lines, and UFW-style firewall sample logs.
- Evidence-backed horizontal, vertical, TCP connect, low-and-slow, SYN, FIN, NULL, and XMAS detections.
- API-backed dashboard views for metrics, events, alerts, offline ingestion, generation, and CSV export.
- Regression tests for schema, samples, malformed records, negative cases, persistence, and deduplication.
- Root-relative non-root installer and loopback-bound local API runner.

Verification evidence at implementation time: `21 passed` in the focused pytest suite; `npm run lint` succeeds; `npm run build` succeeds with TypeScript checks enabled; shell syntax checks pass. Production npm audit reports zero vulnerabilities after the frontend dependency upgrades. See the current implementation plan for remaining gates.

## Not Yet Implemented or Verified

- Splunk HEC and Elasticsearch delivery/search verification.
- Restricted Nmap execution or live network sensor collection.
- Incident/analyst workflow, API authentication, audit log, PDF reporting, low-and-slow detection, and automated detection-quality metrics.
- Docker Compose, GitHub Actions, production benchmark, and live service integration.