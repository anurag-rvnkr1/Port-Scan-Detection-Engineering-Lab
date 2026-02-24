# Port Scan Detection Lab - Attack Scenarios

## Scenario Overview

This document describes realistic attack scenarios for port scanning reconnaissance, including the techniques used, expected log patterns, and detection strategies.

---

## Scenario 1: Internal Network Reconnaissance (SYN Scan)

### Attacker Profile
- Internal user with compromised credentials
- Probing internal network for vulnerable services
- Using stealth scanning to avoid detection

### Attack Sequence

```
Time: T+0 sec → Attacker gains access to compromised workstation (10.1.1.50)
                Executes: nmap -sS 192.168.1.0/24 -p 22,80,443,3306,5432

Time: T+1-2 sec → SYN packets sent to gateway (192.168.1.1)
                  probing ports 22, 80, 443 across 255 hosts

Time: T+2-4 sec → SYN packets sent to file server (192.168.1.50)
                  probing database ports 3306, 5432

Time: T+4-6 sec → SYN packets sent to web servers (192.168.1.51-60)
                  probing http(s) ports
```

### Expected Logs

```
Firewall/Syslog:
[UFW BLOCK] SRC=10.1.1.50 DST=192.168.1.1 DPT=22 SYN
[UFW BLOCK] SRC=10.1.1.50 DST=192.168.1.1 DPT=80 SYN
[UFW BLOCK] SRC=10.1.1.50 DST=192.168.1.1 DPT=443 SYN
[UFW BLOCK] SRC=10.1.1.50 DST=192.168.1.2 DPT=22 SYN
...

IDS/Suricata:
Classification: [Reconnaissance activity] Possible SYN scan
Priority: 3
src_ip: 10.1.1.50, dst_ip: 192.168.1.0/24
```

### Detection Query (Splunk)

```spl
index=firewall sourcetype=syslog "SYN" src_ip=10.1.1.50 
| stats count as syn_count, dc(DPT) as unique_ports 
    by src_ip, dest_ip 
| where unique_ports > 15
```

### Expected Results

| Metric | Value |
|--------|-------|
| Source IP | 10.1.1.50 |
| Unique Ports | 20+ |
| Attack Duration | ~6 seconds |
| Log Events | 500+ |
| Severity | HIGH |

### Remediation

1. Block source IP (10.1.1.50) at firewall
2. Isolate compromised workstation
3. Force password reset for user account
4. Scan for malware/compromise
5. Review user's recent activity

---

## Scenario 2: External Port Sweep (Multiple Targets, Same Port)

### Attacker Profile
- External attacker (IP: 203.0.113.42)
- Searching for hosts running SSH with weak credentials
- Using automated tools to find targets

### Attack Sequence

```
Time: T+0 sec → External attacker begins port 22 sweep
                Probes: 192.168.1.1-192.168.1.254 on port 22

Time: T+0-2 sec → 254 SYN packets to port 22
                  Waiting for responses to identify open ports

Time: T+2-4 sec → For open ports, attempt SSH connections
                  Using common default credentials
```

### Expected Logs

```
Firewall:
[UFW BLOCK] SRC=203.0.113.42 DST=192.168.1.1 DPT=22 SYN
[UFW BLOCK] SRC=203.0.113.42 DST=192.168.1.2 DPT=22 SYN
[UFW BLOCK] SRC=203.0.113.42 DST=192.168.1.3 DPT=22 SYN
...

SSH Auth logs (on responsive hosts):
Invalid user admin from 203.0.113.42
Invalid user root from 203.0.113.42
Invalid user ubuntu from 203.0.113.42
```

### Detection Query (Splunk)

```spl
index=firewall sourcetype=syslog "SYN" 
    src_ip!=127.0.0.1 
    src_ip!="10.0.0.1" 
| stats count, dc(DPT) as port_count by src_ip, DPT 
| where port_count < 3 AND count > 50
```

This detects horizontal port sweeps (many targets, same port).

### Expected Results

| Metric | Value |
|--------|-------|
| Source IP | 203.0.113.42 |
| Target Hosts | 254 |
| Target Port | 22 (SSH) |
| Attack Duration | ~2 seconds |
| Log Events | 254+ |
| Severity | HIGH |

---

## Scenario 3: Stealth Reconnaissance (FIN Scan)

### Attacker Profile
- Advanced attacker with IDS/firewall evasion knowledge
- Using stealth techniques to avoid detection
- Targeting specific high-value hosts

### Attack Sequence

```
Time: T+0 sec → Attacker identifies high-value target (Database server)
                Executes: nmap -sF 192.168.1.50 -p 1-1000

Time: T+0-30 sec → FIN packets sent to 1000 ports
                   FIN flag in closed ports triggers RST response
                   Open ports typically ignore FIN packets
```

### Expected Logs

```
Firewall:
[UFW BLOCK] SRC=203.0.113.100 DST=192.168.1.50 DPT=22 FIN
[UFW BLOCK] SRC=203.0.113.100 DST=192.168.1.50 DPT=80 FIN
[UFW BLOCK] SRC=203.0.113.100 DST=192.168.1.50 DPT=443 FIN

IDS/Suricata Alert:
Classification: [Reconnaissance activity] Possible FIN scan
signature: "Possible FIN scan"
signature_id: 2210033
```

### Detection Query (ELK)

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "tcp.flags": "FIN" } },
        { "range": { "destination.port": { "gte": 1, "lte": 1000 } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip" },
      "aggs": {
        "unique_ports": { "cardinality": { "field": "destination.port" } }
      }
    }
  }
}
```

### Expected Results

| Metric | Value |
|--------|-------|
| Source IP | 203.0.113.100 |
| Unique Ports Probed | 50+ |
| Scan Type | FIN |
| Attack Duration | ~30 seconds |
| Severity | MEDIUM-HIGH |

---

## Scenario 4: Advanced Multi-Technique Scan

### Attacker Profile
- Sophisticated threat actor (APT-like behavior)
- Using multiple techniques to avoid signature-based detection
- Systematically identifying weaknesses

### Attack Sequence

```
Phase 1 (SYN Scan): T+0-5 sec
  nmap -sS 192.168.1.0/24 -p 22,80,443

Phase 2 (Service Detection): T+5-10 sec
  nmap -sV -p 22,80,443 192.168.1.1-50

Phase 3 (Stealth FIN Scan): T+10-20 sec
  nmap -sF -p 1-65535 192.168.1.50

Phase 4 (OS Fingerprinting): T+20-30 sec
  nmap -O -p 22,80,443 192.168.1.1-50
```

### Expected Logs (Mixed Patterns)

```
[UFW BLOCK] SRC=203.0.113.200 DST=192.168.1.* DPT=22 SYN (100+ events)
[UFW BLOCK] SRC=203.0.113.200 DST=192.168.1.* DPT=80 SYN (100+ events)
[UFW BLOCK] SRC=203.0.113.200 DST=192.168.1.50 DPT=* FIN (1000+ events)
[UFW BLOCK] SRC=203.0.113.200 DST=192.168.1.* DPT=22 ACK (variable)
```

### Detection Query (Splunk)

```spl
index=firewall sourcetype=syslog src_ip="203.0.113.200" 
| stats values(tcp_flags) as techniques 
    by src_ip, span=5m 
| search techniques="*SYN*" techniques="*FIN*" techniques="*ACK*"
| eval severity="CRITICAL", alert="MULTI_TECHNIQUE_SCAN"
```

### Expected Results

| Metric | Value |
|--------|-------|
| Source IP | 203.0.113.200 |
| Techniques Detected | 3+ (SYN, FIN, ACK, etc.) |
| Total Events | 1500+ |
| Duration | ~30 seconds |
| Severity | CRITICAL |
| Confidence | VERY HIGH |

---

## Scenario 5: Low-and-Slow Reconnaissance

### Attacker Profile
- Patient attacker avoiding detection
- Distributing scans over extended period
- Targeting specific vulnerability class

### Attack Sequence

```
T+0 min → Scan port 22 on host 1
T+2 min → Scan port 22 on host 2
T+4 min → Scan port 22 on host 3
T+6 min → Scan port 22 on host 4
T+8 min → Scan port 22 on host 5
... (continues over 1-2 hours)
```

### Expected Logs

```
Distributed over time:
Feb 23 10:00:00 firewall kernel: [UFW BLOCK] SRC=203.0.113.50 DST=192.168.1.10 DPT=22 SYN
Feb 23 10:02:00 firewall kernel: [UFW BLOCK] SRC=203.0.113.50 DST=192.168.1.11 DPT=22 SYN
Feb 23 10:04:00 firewall kernel: [UFW BLOCK] SRC=203.0.113.50 DST=192.168.1.12 DPT=22 SYN
```

### Detection Query (Splunk)

```spl
index=firewall sourcetype=syslog 
| timechart count by src_ip, span=10m 
| where count > 5
| stats sum(count) as total_activity by src_ip 
| where total_activity > 30
```

### Expected Results

| Metric | Value |
|--------|-------|
| Source IP | 203.0.113.50 |
| Events per 10 min | 5-10 |
| Total Duration | 60-120 minutes |
| Total Events | 50+ |
| Severity | MEDIUM |

---

## Scenario 6: False Positive Test Case - Legitimate Scan

### Legitimate User Profile
- Network administrator (192.168.1.100)
- Performing authorized vulnerability scan
- Using Nessus professional
- During change window

### Activity Pattern

```
Time: T+0 → Authorization received for maintenance window
       Nessus scanner begins comprehensive network scan
       Scanning: 192.168.1.0/24 on ports 1-1000

Time: T+10-30 min → Scan completes
       Multiple scan techniques (SYN, service detection, etc.)
       High volume of connection attempts
```

### Expected Logs

```
[UFW ACCEPT] SRC=192.168.1.100 DST=192.168.1.* DPT=* SYN
[Nessus] Scanning host 192.168.1.10, port 22, SSH Server
[Nessus] Scanning host 192.168.1.11, port 80, HTTP Server
```

### Expected Detection Behavior

**Without Whitelist:**
- Would trigger HIGH severity alert
- Multiple technique detection
- Port sweep detection

**With Whitelist (Correct Configuration):**
- Detection query EXCLUDES 192.168.1.100
- NO alert generated
- Logged as authorized activity

### Query with Whitelist

```spl
index=firewall sourcetype=syslog 
    src_ip!="192.168.1.100"
    src_ip!="10.0.0.1"
    src_ip!="10.50.0.0/16" 
| stats dc(DPT) as unique_ports by src_ip 
| where unique_ports > 20
```

---

## Scenario 7: Outbound Data Exfiltration Scanning

### Attacker Profile
- Attacker with command and control (C2) access
- Compromised internal host attempting to reach external systems
- Probing multiple external IPs for C2 communication

### Attack Sequence

```
Compromised Host: 10.1.1.50
C2 Infrastructure: 10.20.30.0/24 (attacker's network)

T+0 sec → Host attempts outbound connections to multiple C2 IPs
         Probing port 443 (HTTPS disguise)
         Testing port 80 (HTTP fallback)
         Testing port 8080 (Alternative)
```

### Expected Logs

```
Firewall (Outbound):
SRC=10.1.1.50 DST=10.20.30.1 DPT=443 (OUTBOUND)
SRC=10.1.1.50 DST=10.20.30.2 DPT=443 (OUTBOUND)
SRC=10.1.1.50 DST=10.20.30.3 DPT=443 (OUTBOUND)
[... repeat for multiple external IPs ...]
```

### Detection Query (ELK)

```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "network.traffic_direction": "outbound" } }
      ],
      "filter": [
        { "range": { "source.ip": { "gte": "10.0.0.0", "lte": "10.255.255.255" } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip" },
      "aggs": {
        "unique_external_ips": { "cardinality": { "field": "destination.ip" } }
      }
    }
  }
}
```

### Expected Results

| Metric | Value |
|--------|-------|
| Source IP (Internal) | 10.1.1.50 |
| Destination IPs | 10+ external |
| Severity | CRITICAL |
| Indicator | Data exfiltration attempt |

---

## Scenario 8: Vulnerability-Specific Scanning

### Attacker Profile
- Attacker searching for specific vulnerability (e.g., Apache Struts)
- Only scanning port 8080 (common application port)
- Across entire network range

### Attack Pattern

```
nmap -sV -p 8080 192.168.1.0/24

Targeting: Specific service port
Technique: Version detection
Duration: Quick scan
Port-specific behavior detected
```

### Detection Query

```spl
index=firewall sourcetype=syslog 
    DPT=8080 
    tcp_flags="SYN" 
| stats dc(DST) as unique_hosts 
    by SRC 
| where unique_hosts > 50
```

### IoC Detection

- Single port probed across many hosts
- Suggests vulnerability/service-specific targeting
- Indicates sophisticated attacker knowledge

---

## Scenario Execution Guide

### For Lab Testing

1. **Choose Scenario:** Select from 8 scenarios above
2. **Generate Logs:** Use log_generator.py with scenario parameters
3. **Ingest Logs:** Use run_lab.sh or manual ingest
4. **Execute Queries:** Run corresponding detection query
5. **Validate Results:** Compare with expected results
6. **Document:** Record test execution and findings

### Example Command

```bash
# Scenario 1: Internal SYN Scan
python3 log_generator.py \
  --scenario syn_scan \
  --source-ip 10.1.1.50 \
  --target-network 192.168.1.0/24 \
  --port-range 22,80,443,3306,5432 \
  --count 100

# Ingest into Splunk
bash run_lab.sh

# Execute detection query
splunk search 'index=firewall ... (from scenario above)'
```

---

## Scenario Coverage Matrix

| Scenario | Technique | Detection Method | Confidence |
|----------|-----------|-----------------|-----------|
| 1 - Internal Recon | SYN Sweep | Multiple ports, time window | HIGH |
| 2 - Port Sweep | Port Sweep | Multiple hosts, same port | HIGH |
| 3 - Stealth | FIN Scan | Anomalous flags | VERY HIGH |
| 4 - Multi-Technique | Mixed | Technique correlation | CRITICAL |
| 5 - Low-and-Slow | Distributed | Temporal aggregation | MEDIUM |
| 6 - False Positive | Legitimate | Whitelist exclusion | PASS |
| 7 - C2 Scanning | Outbound | Direction + volume | CRITICAL |
| 8 - Vuln-Specific | Service Port | Single port focus | HIGH |

---

## Real-World Implications

### Typical APT Reconnaissance Pattern

```
Week 1: External reconnaissance (DNS enumeration, WHOIS)
Week 2: External network scanning (Shodan, CENSYS)
Week 3: Port and service scanning (Nmap)
Week 4: Vulnerability assessment (Nessus, Qualys)
Week 5: Credential acquisition (Phishing, password spray)
Week 6: Initial access (Exploit vulnerable service)
Week 7+: Lateral movement, persistence, data exfiltration
```

This lab focuses on **Week 3: Port and service scanning**, a critical detection point.

---

**Last Updated:** February 23, 2024
