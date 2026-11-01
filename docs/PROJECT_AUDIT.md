# Project Audit

## Audit Scope

This audit describes the checked-out workspace as inspected on 2026-11-01. It covers tracked project files, the existing frontend entrypoint and package configuration, root scripts, sample telemetry, SIEM query/dashboard artifacts, and the repository status. Existing user changes to `tsconfig.json`, `next-env.d.ts`, and `package-lock.json` were observed and are not part of this audit's proposed changes. No Python implementation or automated test source exists in the checkout.

## Existing Architecture

- A Next.js 16 / React 19 / TypeScript frontend shell exists at the repository root, with Tailwind CSS and a collection of shadcn-style UI components.
- The app has a root layout and global styles, but no `app/page.tsx`, API routes, frontend tests, or application workflows.
- `port_scan_detection_lab/` contains markdown scenarios, sample auth/syslog/Zeek/Suricata logs, SPL/KQL/Elasticsearch DSL query artifacts, dashboard examples, and manual testing instructions.
- Root-level `run_lab.sh`, `install.sh`, and `nmap_commands.sh` operate separately from the nested lab directory. There is no backend, event schema, database, generator, parser, detection runtime, SIEM client, or report implementation.

## Existing Features

- Reference Nmap command examples and scan scenario documentation.
- Static sample telemetry for Zeek, Suricata, syslog, and authentication activity.
- SIEM query and dashboard reference artifacts.
- A Next.js scaffold and reusable UI component library.

These are reference materials, not an end-to-end running detection platform. No real-time traffic capture or successful SIEM ingestion was verified.

## Missing Features

- No Python modules, FastAPI application, canonical event model, database, tests, Docker configuration, CI workflow, or reproducible dependency lock for Python.
- No safe synthetic event generator, controlled Nmap execution path, ingestion/parser pipeline, alert persistence, incident workflow, reporting, or dashboard data API.
- No functioning SOC page or application navigation; the frontend package is scaffold-only.
- No configured or verified Splunk/Elasticsearch client. The query files do not establish that their fields match normalized events or a real index mapping.
- No documented authorization/authentication boundary for state-changing API operations (there is no API yet).

## Verified Bugs and Root Causes

| Finding | Root cause | Evidence / impact |
| --- | --- | --- |
| `run_lab.sh` cannot generate its advertised logs | It invokes root-level `log_generator.py`, which is absent. | Direct path check reports missing. Failures are hidden by `|| true` or warning fallbacks, after which the script continues. |
| Installation creates a contradictory layout | `install.sh` creates root-level `logs/`, `detections/`, and `attack_simulation/` although the useful artifacts are nested under `port_scan_detection_lab/`. | The nested `attack_simulation/nmap_commands.sh` target does not exist; its `chmod` is fatal under `set -e`. |
| Installation requires unnecessary root and broad system changes | The script insists on root and runs apt installation of multiple optional services and sensors. | Local simulation/documentation does not need these packages or elevated privileges. Package availability also varies by distro. |
| SIEM checks overstate health | The runner embeds a placeholder HEC token and hardcodes endpoints; `curl -s` does not enforce HTTP success, and no event is submitted/searched. | Reachability is not authentication, ingestion, indexing, or search verification. |
| User-facing claims exceed implementation | README and `PROJECT_SUMMARY.md` describe production readiness, automated validation, live monitoring, and completion. | No application backend, generator, test implementation, or live integration exists to support these claims. |
| Dashboard/query schema is unverified | Static artifacts use varying fields and query syntax; there is no canonical schema or ingestion mapping. | No pipeline exists to make the sources or dashboard fields consistent. |
| Frontend build can conceal type errors | Next config sets `typescript.ignoreBuildErrors: true`; package metadata still uses a generic scaffold name and layout metadata. | A production build can succeed despite type errors; application functionality is absent. |
| Dependency claims are stale and broad | `requirements.txt` claims Python 3.6+ while requiring modern optional integrations and several unused data libraries. | No Python entrypoint imports or test requirements justify the full set; compatibility has not been validated. |

No hardcoded live credential was found; the visible HEC value is an obvious placeholder, but must still be removed from execution defaults. There is no evidence of an implemented Nmap runner, so the existing command reference is not an application-mediated scanner. Actual exploitability findings cannot be established for functionality that does not exist.

## Proposed Architecture

Retain the current root-level Next.js project and reference materials; add a small `backend/` FastAPI application as the owner of event normalization, local SQLite persistence, detections, and REST endpoints. Keep synthetic generation offline and deterministic by default. Keep SIEM integrations optional and disabled until configured. The frontend should consume backend APIs and make the simulated/demo nature of locally generated records explicit. Do not introduce live sensor capture, unrestricted scanning, or external services as prerequisites.

Initial canonical event fields should include UTC timestamp, stable event ID, source/destination addresses and ports, protocol, flags, event type, connection state, sensor, source file, scenario ID, and preserved raw record. Initial detections should require multi-event evidence, use configurable thresholds, and expose their explanation and evidence. SQLite and local sample files should provide the zero-configuration path.

## Implementation Roadmap

1. Establish this audit and the independently testable phase plan; preserve existing user changes.
2. Replace broken shell behavior with project-root-relative, non-root-safe commands and a deterministic offline generator.
3. Add validated event schema, parsers for the formats actually present, SQLite persistence, and a FastAPI health/ingest/events API.
4. Add explainable, configurable multi-event scan detections and alert persistence with positive and benign fixtures.
5. Connect a usable dashboard to real backend metrics and alert/event APIs; show loading, empty, and error states.
6. Add alert status/notes and incidents with audit history, then CSV/report exports.
7. Add optional, secret-safe Splunk HEC and Elasticsearch clients with mocked tests and explicit live-verification status.
8. Add Docker/Compose and CI only after local install, tests, and service health checks are reproducible.
9. Expand security, performance, documentation, and end-to-end validation. Only report measured benchmarks and verified integrations.

## Verification Strategy

- Unit test canonical schema validation, timestamp/IP/protocol normalization, every supported parser, generator determinism, each implemented detection, allowlisting, deduplication, and SIEM payloads.
- Use checked-in fixtures for positive and negative detections; verify API persistence and filtering with a temporary SQLite database and FastAPI's test client.
- Run shell syntax checks and the documented offline workflow from the repository root without root privileges or network access.
- Run Python tests, frontend lint/typecheck/build, and Docker/CI validation only where tooling is installed; record unavailable gates rather than implying success.
- Mock external SIEM services. Mark live status unverified unless authenticated event submission and subsequent search are both observed.
- Benchmark only with a recorded host, dataset, repetitions, timing, and memory method. Synthetic results are not production accuracy claims.

## Audit Status

The audit documents verified current-state defects and a proposed sequence. The current checkout does not meet the stated production/recruiter acceptance criteria. Completion status must be updated as implementation and verification proceed.

## Remediation Update

The first implementation added the local FastAPI/SQLite pipeline, sample parsing, synthetic event generation, detections, and dashboard. Its verification was narrower than the original acceptance list; incident workflows and reports were still missing at that point.

## Independent Second Audit — 2026-11-01

The current source was independently inspected and executed rather than relying on earlier completion reports. The audit found and corrected these concrete gaps:

- Alert investigation was display-only; there were no alert detail/update, incident lifecycle, audit history, or report routes. Added these API paths, persisted tables, regression tests, and dashboard controls.
- Suricata TCP flags were not consistently normalized. The code now handles named flags and hexadecimal bitmasks, including both `tcp.flags` and `tcp.tcp_flags`; regression tests verify SYN detections and malformed encodings.
- Synthetic data had scenario metadata but no explicit ground-truth label and no directly generated low-and-slow case. Added `ground_truth` and a labeled `low_slow` scenario.
- Dashboard KPI aggregation loaded every event and alert row into Python. Replaced that with database aggregate queries; independently compared returned metrics with direct SQLite queries in the live test.
- CORS permitted only GET/POST, preventing browser alert/incident updates. PATCH is now allowed for explicitly configured local origins and preflight-tested.
- Documentation incorrectly claimed there was no incident/report workflow and understated supported scenarios. Updated the operator guides and limitations.
- Frontend CSV exports did not neutralize spreadsheet formula prefixes. Values are now escaped before CSV serialization.
- Running a production build alongside the dev server reused `.next` and disrupted the existing dev cache. Added configurable `NEXT_BUILD_DIR`, verified an isolated production build and server, and excluded generated alternate build directories.
- The inherited dev listener on port 3000 remains in a stale compile-failure state (`tw-animate-css` resolution) even though a clean isolated dev server and production build both compile successfully. It was not terminated because it predated this audit. The `npm run dev` script now uses an isolated `.next-dev` cache to avoid future dev/build collisions.

Verification on this audit run:

- Backend: 36 tests passed, including malformed parser records, detection, API persistence, split-batch correlation, labeled benign/malicious cases, alert evidence, status changes, incident transitions/audit history, reports, pagination, and CORS.
- Frontend: ESLint, TypeScript, isolated Next.js production build, and a separate interactive dev server passed. The isolated page returned HTTP 200; production HTML and all seven referenced JavaScript assets returned HTTP 200. No browser automation binary was available, so interactive click-through was not independently browser-tested.
- Live API: `/health`, all 14 OpenAPI operations, event generation, Zeek/Suricata/firewall upload, alert detail/update, incident create/list/detail/status updates, JSON/CSV reports, duplicate upload behavior, cross-batch scan correlation, and PATCH preflight were exercised.
- Clean live dataset: 405 events (320 labeled synthetic + 12 split-batch Suricata + 73 sample logs), 24 alerts, 1 incident moved through New → Investigating → Escalated → Resolved → Closed, and five audit entries. The generated synthetic rules produced TP=280, FP=0, TN=40, FN=0 (precision/recall/F1=1.0; FPR=0.0) against only these 320 labeled events. Every alert evidence ID resolved to a stored event, and all dashboard KPI values matched direct SQLite aggregate queries.
- These synthetic results are narrow fixture checks, not calibrated detection quality or real-world performance. The source-separated synthetic scenarios avoid cross-label contamination; the 12 split-batch events were intentionally unlabeled and excluded from the confusion matrix.
- Production npm audit reports zero production dependency vulnerabilities. Development tooling still reports moderate npm advisories; no forced breaking dependency upgrade was applied.

Remaining gaps: no Splunk/Elasticsearch client, live sensor, safe Nmap runner, formal rule correlation/allowlisting/tuning, auth/RBAC, multi-user analyst identity, PDF reporting, benchmark harness, CI workflow, or Docker deployment. Detection thresholds and confidence remain simple heuristics. The API is a local single-user demo and must stay loopback-bound. No real-world detection accuracy or performance claim is supported.