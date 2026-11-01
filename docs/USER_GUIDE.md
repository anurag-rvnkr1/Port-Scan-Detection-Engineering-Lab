# Local User Guide

SentinelSOC in this repository is an offline-first analyst workflow prototype. Generated events are marked simulated and do not send packets. Uploaded telemetry is parsed from local files and stored in the configured SQLite database.

## Start the Application

Follow [DEPLOYMENT_GUIDE.md](./DEPLOYMENT_GUIDE.md). Keep the API bound to loopback; there are no user accounts or roles.

## Dashboard Workflow

1. Select **Generate demo events** to create a labeled synthetic SYN-scan dataset. Verify the simulated event and alert counts.
2. Open **Network events** to search and inspect persisted normalized telemetry. Export the visible rows as CSV.
3. Open **Security alerts** and choose an alert to inspect its evidence and detection rationale.
4. Update the alert status or analyst label. The current actor is a fixed local label, not an authenticated user.
5. Create an incident from an alert and update its status. A resolution is required before setting the incident to Resolved or Closed.
6. Use **Incidents** to inspect open work and download a summary CSV.
7. Open **Log ingestion**, choose the matching source format, select an offline Zeek, Suricata, or supported UFW-style log, and run parsing. The upload is limited to 5 MiB. Duplicate IDs are skipped; malformed records are reported.

## Detection Configuration

Set `LAB_DETECTION_THRESHOLD` and/or `LAB_DETECTION_SOURCE_ALLOWLIST` before starting `run_lab.sh`. The threshold defaults to 8, with a supported range of 3–65536. The allowlist accepts comma-separated IPv4/IPv6 addresses and CIDRs. Matching events remain in the database, but do not participate in detections.

## Data and Limitations

The application stores data in `data/soc_lab.db` by default. There is no automatic retention policy. The UI refreshes persisted API data periodically; it is not a live sensor stream. Confidence and severity are heuristic. Results from synthetic samples are not a measure of real-world detection accuracy.

Nmap execution, live capture, PCAP investigation, analyst login/RBAC, Splunk/Elasticsearch delivery, PDFs, and production deployment are unavailable; do not rely on controls or buttons for those features.
