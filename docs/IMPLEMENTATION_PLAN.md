# Implementation Plan

Each phase has a concrete exit check. A phase is not considered complete when only documentation or interface scaffolding exists.

| Phase | Deliverable | Exit check | Status |
| --- | --- | --- | --- |
| 1. Audit and plan | Repository audit and sequenced implementation plan | Findings trace to files or verified missing paths; current changes preserved | Implemented; see dated audit history and current snapshot |
| 2. Script and structure repair | One root-relative offline run path; non-root installation; no placeholder SIEM success | Shell syntax passes; installer and launch workflow pass end-to-end | Implemented and locally verified; script binds loopback by default |
| 3. Backend and storage | FastAPI app, versioned event model, SQLite/PostgreSQL adapters, health and event APIs | App imports/starts; API tests prove persistence, validation, and error behavior; migrations upgrade cleanly | SQLite and PostgreSQL 17 migration plus database-health checks verified; background processing and production orchestration remain pending |
| 4. Generation and ingestion | Synthetic scenarios plus parsers for checked-in Zeek, Suricata, and supported firewall samples | Deterministic fixtures parse; malformed records are counted and isolated | Implemented and tested for listed formats |
| 5. Detection | Multi-event horizontal/vertical scan rules, flag indicators only with flag telemetry, explainable alerts | Positive and benign labeled fixtures exercise thresholds, evidence, and deduplication | Implemented in part; process-start threshold and IPv4/IPv6 source allowlists are configured and tested; advanced windows, distributed correlation, and evaluation pending |
| 6. SOC dashboard | Functional frontend backed by actual API data | Build/typecheck pass; empty/loading/error states and live API data demonstrated | Implemented with API-backed data; one administrator-to-incident/report browser E2E workflow passes, while other pages/roles remain uncovered |
| 7. Investigation | Alert workflow, analyst assignment/notes, incident lifecycle, audit history | API/UI integration tests verify durable state transitions and actor history | Partially implemented; authenticated local account workflow and API tests pass; team workflows remain limited |
| 8. Reporting | CSV and PDF summary exports based on persisted records | Export tests cover empty data, representative records, PDF structure/content, and period validation | Partially implemented; JSON/CSV plus daily/weekly/monthly/all PDF with metrics, ranked tables, severity chart, and available notes; long-running reports remain synchronous |
| 9. SIEM integrations | Optional HEC and Elasticsearch clients, bounded retries, verification status | Mocked contract tests pass; live checks remain explicitly unverified without service credentials | Not started |
| 10. Quality and security | Unit/integration/security tests, static checks, reproducible benchmark harness | Tests report actual counts; unsafe target/path/secret cases rejected; benchmark metadata recorded | Partial: bounded static source review and local tests documented; automated security scanning, load tests, and formal benchmark pending |
| 11. Deployment and CI | Docker/Compose, health checks, CI workflow and dependency lock | Clean documented compose/test/build workflow passes in available environment | Partial: backend/frontend images and local PostgreSQL Compose workflow passed health, migration, and authenticated-proxy smoke checks; CI workflow includes tests and container builds, but remote workflow execution, dependency/container scans, and production deployment remain pending |
| 12. Documentation and release readiness | Accurate README and beginner operator guides | Commands run as written; every acceptance item has evidence or a clear incomplete status | Partial: current-state guides and feature/test/security status added; full portfolio evidence, screenshots, and clean-environment install verification pending |

## Scope and Safety Boundaries

- The default demonstration uses synthetic or explicitly supplied offline logs; it does not claim live packet capture.
- Nmap execution, if added, remains opt-in, requires explicit confirmation, and validates every target against loopback or configured authorized lab networks before process launch.
- Splunk and Elasticsearch remain optional. No secrets are committed, logged, or shown in API responses.
- Detection limitations are surfaced: flag-based scan classification requires telemetry that includes TCP flags, and a single event is not a confirmed scan.
- Real-world performance and accuracy are not inferred from synthetic fixtures.

## Current Delivery Gate

The current verified increment includes authentication/RBAC, bounded offline ingestion, analyst account operations, configurable detection filtering, and database-backed PDF reports. This is not completion of the full platform roadmap. Feature-by-feature state and known constraints are in [FEATURE_STATUS.md](./FEATURE_STATUS.md); current test execution is in [TESTING_REPORT.md](./TESTING_REPORT.md). Do not advance to externally exposed deployment, active scanning, or live packet capture until authentication/authorization and lab-bound safety controls exist and are tested.