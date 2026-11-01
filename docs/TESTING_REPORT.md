# Testing Report

Date: 2026-11-01

## Executed Checks

| Command | Result | Scope |
|---|---|---|
| `.venv/bin/python -m pytest -q` (before change) | 36 passed | Backend baseline. |
| `.venv/bin/python -m pytest -q` (after change) | 44 passed | Full backend unit/API suite, including new allowlist and threshold coverage. |
| `npm run lint` | Passed | ESLint configured for `app/`. |
| `npm run typecheck` | Passed | `tsc --noEmit`. |
| `npm run build` | Passed | Next.js production build, including TypeScript phase. |

The final backend and frontend checks were run after implementation changes. No frontend source code changed in this increment; frontend checks confirm the existing app still passes its configured lint, type, and build gates.

## New Regression Coverage

- CIDR allowlisting suppresses detections for matching sources while non-allowlisted events in the same batch can still alert.
- Threshold boundary is exercised with events below the default and at a configured threshold.
- IPv4 and IPv6 allowlist parsing and invalid-entry rejection are covered.
- Startup configuration parsing and invalid threshold/allowlist rejection are covered.
- API-level check verifies allowlisted synthetic events persist and count in event metrics while creating no alerts.

## Not Executed / Not Established

- No browser automation, Playwright, load/performance test, migration test, container build, or clean-environment installation was run in this pass.
- No live Nmap, packet capture, Zeek/Suricata process, Splunk HEC, or Elasticsearch service was available or exercised.
- No security scanner, dependency audit, formal type checker for Python, or detection-quality benchmark was run in this pass.
- The labeled synthetic tests do not establish precision, recall, false-positive rate, or field accuracy.

Only the results in the executed-check table are claimed as successful.
