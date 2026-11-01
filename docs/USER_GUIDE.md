# Local User Guide

SentinelSOC in this repository is an offline-first analyst workflow prototype. Generated events are marked simulated and do not send packets. Uploaded telemetry is parsed from local files and stored in the configured SQLite database.

## Start the Application

Follow [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md). Create the initial administrator with the CLI command before logging in. Registration is disabled; administrators/managers create accounts.

## Dashboard Workflow

1. Select **Generate demo events** to create a labeled synthetic SYN-scan dataset. Verify the simulated event and alert counts.
2. Open **Network events** to search and inspect persisted normalized telemetry. Export the visible rows as CSV.
3. Open **Security alerts** and choose an alert to inspect its evidence and detection rationale.
4. Update the alert status or assign an active SOC Analyst account. The authenticated username is recorded in the audit history.
5. Create an incident from an alert and update its status. A resolution is required before setting the incident to Resolved or Closed.
6. Use **Incidents** to inspect open work and download a summary CSV.
7. Open **Log ingestion**, choose the matching source format, select an offline Zeek, Suricata, supported UFW-style log, or PCAP/PCAPNG file, and run parsing. Uploads are limited to 5 MiB and 20,000 records/packets. PCAP support extracts metadata only from Ethernet or raw IPv4/IPv6 captures; it does not store/replay packet payloads or start live capture. Duplicate event IDs are skipped; malformed records are reported.
8. Use **Analyst management** (administrator or manager) to create a SOC Analyst or Read-only Viewer account. Passwords must be at least 12 characters.
9. Select **Weekly PDF** to download a database-backed report. The API also supports `daily`, `weekly`, `monthly`, and `all` periods; append `&download=false` to preview inline in a browser. Reports include persisted metrics, alert severity distribution, top source/destination addresses and ports, rule and incident distributions, and investigation notes when available.
10. Administrators may use the interactive API docs at `/docs` for the restricted Nmap API. Scanning is disabled unless Nmap is installed and `LAB_NMAP_ALLOWED_CIDRS` names an authorized private/loopback lab network. Requests target one IP, require explicit confirmation, are synchronous and rate-limited, and create audited scan history. No dashboard scan page or cancellation control is available.

## Detection Configuration

Set `LAB_DETECTION_THRESHOLD` and/or `LAB_DETECTION_SOURCE_ALLOWLIST` before starting `run_lab.sh`. The threshold defaults to 8, with a supported range of 3–65536. The allowlist accepts comma-separated IPv4/IPv6 addresses and CIDRs. Matching events remain in the database, but do not participate in detections.

## Data and Limitations

The application stores data in `data/soc_lab.db` by default. There is no automatic retention policy. The UI refreshes persisted API data periodically; it is not a live sensor stream. Confidence and severity are heuristic. Results from synthetic samples are not a measure of real-world detection accuracy. PDF reports describe these limitations and are not an independent accuracy assessment.

Nmap execution is available only through the restricted API and has not been live-scan verified. Live capture and sensor processes are unavailable. PCAP upload parses metadata only; Splunk/Elasticsearch delivery is implemented but externally unverified. Production deployment is not supported.
