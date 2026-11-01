# Beginner Installation Guide

## Windows With an Ubuntu or Kali Virtual Machine

Install VirtualBox or VMware on Windows, then install an Ubuntu or Kali Linux VM. Run the project commands inside the VM's Linux terminal, not PowerShell, unless the repository itself is checked out inside Windows and a Linux shell is being used. The application only uses local simulated or offline log data; it does not require the VM network adapter to reach a target network.

Install Python 3.10+, Node.js 20+, and Git using the VM's package manager or the official language installers. Do not run these project scripts with `sudo`.

In the VM terminal:

```bash
git clone https://github.com/anurag-rvnkr1/Port-Scan-Detection-Engineering-Lab.git
cd Port-Scan-Detection-Engineering-Lab
./install.sh
```

Start the backend and frontend in two terminal windows, both in the repository directory:

```bash
./run_lab.sh
```

```bash
npm run dev
```

Open `http://localhost:3000` in the VM browser. To open it from the Windows host, configure the VM's network port forwarding for TCP ports 3000 and 8000, then set the frontend API URL and backend CORS origin to the host-reachable addresses. The default configuration intentionally binds the API to loopback and allows only local development origins.

## Generate a Demonstration

1. In the browser, choose **Generate demo events**.
2. Confirm that the event count and alert count change. The events are synthetic and remain local.
3. Choose **Security alerts**, select an alert, and inspect its detection reason and event evidence IDs.
4. Choose **Network events** to inspect normalized records; use the search field and **Export CSV**.
5. Choose **Log ingestion**, select `Zeek conn.log`, choose `port_scan_detection_lab/logs/zeek_conn.log`, and start ingestion. The parser shows accepted records, duplicates, and malformed lines.
6. Repeat with the Suricata JSON Lines or UFW syslog sample by changing the source format.

## Run Tests and Troubleshoot

```bash
.venv/bin/python -m pytest -q
npm run build
```

- If installation says Python is missing, install Python 3.10 or newer and ensure `python3` is on `PATH`.
- If it says Node.js is missing, install Node.js 20 or newer and npm.
- If the dashboard reports an API connection error, keep `./run_lab.sh` running and check <http://localhost:8000/health>.
- If the API cannot bind its port, set `LAB_PORT=8001` for the backend and update `NEXT_PUBLIC_API_BASE_URL=http://localhost:8001` before starting Next.js.
- Local SQLite data is stored in `data/soc_lab.db`. Deleting that file removes local events and alerts; stop the API before doing so.
- API schema and request errors are available at <http://localhost:8000/docs>.

No live network traffic is captured. Splunk and Elasticsearch setup is not currently connected to the application.