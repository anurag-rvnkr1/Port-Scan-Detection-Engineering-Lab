# Implementation Plan

Each phase has a concrete exit check. A phase is not considered complete when only documentation or interface scaffolding exists.

| Phase | Deliverable | Exit check | Status |
| --- | --- | --- | --- |
| 1. Audit and plan | Repository audit and sequenced implementation plan | Findings trace to files or verified missing paths; current changes preserved | Implemented and verified |
| 2. Script and structure repair | One root-relative offline run path; non-root installation; no placeholder SIEM success | Shell syntax passes; installer and launch workflow pass end-to-end | Implemented and locally verified; script binds loopback by default |
| 3. Backend and storage | FastAPI app, versioned event model, SQLite persistence, health and event APIs | App imports/starts; API tests prove persistence, validation, and error behavior | Implemented and live HTTP-verified |
| 4. Generation and ingestion | Synthetic scenarios plus parsers for checked-in Zeek, Suricata, and supported firewall samples | Deterministic fixtures parse; malformed records are counted and isolated | Implemented and tested for listed formats |
| 5. Detection | Multi-event horizontal/vertical scan rules, flag indicators only with flag telemetry, explainable alerts | Positive and benign labeled fixtures exercise thresholds, evidence, and deduplication | Implemented in part; distributed correlation, allowlists, configurable windows, tuning, and evaluation pending |
| 6. SOC dashboard | Functional frontend backed by actual API data | Build/typecheck pass; empty/loading/error states and live API data demonstrated | Implemented and HTTP-smoke-verified; full browser interaction review pending |
| 7. Investigation | Alert workflow, analyst assignment/notes, incident lifecycle, audit history | API/UI integration tests verify durable state transitions and actor history | Partially implemented; local single-user workflow and API tests pass; no auth |
| 8. Reporting | CSV and investigation summary exports based on persisted records | Export tests cover empty data, escaping, and representative records | Partially implemented; JSON and CSV SOC summaries; no PDF/period filtering |
| 9. SIEM integrations | Optional HEC and Elasticsearch clients, bounded retries, verification status | Mocked contract tests pass; live checks remain explicitly unverified without service credentials | Planned |
| 10. Quality and security | Unit/integration/security tests, static checks, reproducible benchmark harness | Tests report actual counts; unsafe target/path/secret cases rejected; benchmark metadata recorded | Planned |
| 11. Deployment and CI | Docker/Compose, health checks, CI workflow and dependency lock | Clean documented compose/test/build workflow passes in available environment | Planned |
| 12. Documentation and release readiness | Accurate README and beginner operator guides | Commands run as written; every acceptance item has evidence or a clear incomplete status | Planned |

## Scope and Safety Boundaries

- The default demonstration uses synthetic or explicitly supplied offline logs; it does not claim live packet capture.
- Nmap execution, if added, remains opt-in, requires explicit confirmation, and validates every target against loopback or configured authorized lab networks before process launch.
- Splunk and Elasticsearch remain optional. No secrets are committed, logged, or shown in API responses.
- Detection limitations are surfaced: flag-based scan classification requires telemetry that includes TCP flags, and a single event is not a confirmed scan.
- Real-world performance and accuracy are not inferred from synthetic fixtures.