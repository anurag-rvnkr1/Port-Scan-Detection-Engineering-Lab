# Port Scan Detection Lab - Test Cases

## Test Case Summary

This document provides comprehensive test cases for validating port scan detection engineering queries and dashboards.

---

## Test Case 1: SYN Scan Detection

### Objective
Verify detection of TCP SYN scans (stealth scans)

### Test Log Example
```
Feb 23 10:15:32 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.105 DST=192.168.1.100 PROTO=TCP SPT=52341 DPT=22 SYN
Feb 23 10:15:33 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.105 DST=192.168.1.100 PROTO=TCP SPT=52342 DPT=23 SYN
Feb 23 10:15:34 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.105 DST=192.168.1.100 PROTO=TCP SPT=52343 DPT=25 SYN
[... continue until 20+ unique ports in 60 seconds ...]
```

### Expected Behavior
- **Splunk:** Query returns `unique_ports >= 20`, severity set to HIGH
- **ELK/Kibana:** KQL query returns documents grouped by source IP with `cardinality > 20`
- **Alert:** Triggers when threshold exceeded

### Test Step-by-Step

1. **Inject Test Logs:**
   ```bash
   # For Splunk
   curl -X POST "http://splunk:8088/services/collector" \
     -H "Authorization: Splunk your-hec-token" \
     -d @test_logs/syn_scan.log
   
   # For ELK
   curl -X POST "http://elasticsearch:9200/firewall-logs/_doc" \
     -H "Content-Type: application/json" \
     -d @test_logs/syn_scan.json
   ```

2. **Execute Query:**
   ```splunk
   index=firewall sourcetype=syslog "SYN" 
   | stats dc(DPT) as unique_ports by src_ip 
   | where unique_ports >= 20
   ```

3. **Validate Results:**
   - Source IP `192.168.1.105` should appear
   - `unique_ports` field should show >= 20
   - Timestamp should match injection time

4. **Expected Output:**
   | src_ip | unique_ports | count |
   |--------|------------|-------|
   | 192.168.1.105 | 22 | 22 |

### Pass/Fail Criteria
- ✅ PASS: Detection triggered with correct source IP and port count
- ❌ FAIL: Detection did not trigger or incorrect values

---

## Test Case 2: FIN Scan Detection

### Objective
Verify detection of FIN flag scans (stealth technique)

### Test Log
```
Feb 23 10:16:01 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.105 DST=192.168.1.100 PROTO=TCP DPT=22 FIN
Feb 23 10:16:02 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.105 DST=192.168.1.100 PROTO=TCP DPT=23 FIN
Feb 23 10:16:03 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.105 DST=192.168.1.100 PROTO=TCP DPT=25 FIN
```

### Expected Behavior
- Detection triggers when >= 3 FIN packets from same source
- Severity: MEDIUM

### Query (Splunk)
```splunk
index=firewall sourcetype=syslog "FIN" 
| stats count as fin_count, dc(DPT) as unique_fin_ports by src_ip 
| where unique_fin_ports >= 3
```

### Validation
1. Inject 5+ FIN packets from 192.168.1.105
2. Query should return source IP with count >= 3
3. Check severity is set to "MEDIUM"

---

## Test Case 3: NULL Scan Detection

### Objective
Verify detection of NULL packets (no TCP flags set)

### Test Log
```
Feb 23 10:16:10 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.110 DST=192.168.1.100 PROTO=TCP DPT=22 NONE
Feb 23 10:16:11 firewall kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.110 DST=192.168.1.100 PROTO=TCP DPT=80 NONE
```

### Expected Behavior
- Detection triggers on ANY NULL packets (highly anomalous)
- Severity: HIGH

### Test Procedure
1. Inject 2+ logs with tcp.flags = "NONE"
2. Query should return results immediately
3. Verify severity = HIGH

### Query Validation
```splunk
index=firewall sourcetype=syslog "NONE" 
| stats count as null_count by src_ip 
| where null_count >= 2
```

---

## Test Case 4: Port Sweep Detection

### Objective
Verify detection of horizontal port sweeps

### Test Log
```
Feb 23 10:17:10 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DST=192.168.1.101 DPT=22 SYN
Feb 23 10:17:11 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DST=192.168.1.102 DPT=22 SYN
Feb 23 10:17:12 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DST=192.168.1.103 DPT=22 SYN
[... scan 15+ unique destination IPs on port 22 ...]
```

### Expected Behavior
- Detection triggers when single source probes > 15 unique IPs on same port
- Severity: HIGH
- Indicates reconnaissance of entire subnet

### Test Steps
1. Inject logs showing 16+ unique destination IPs from single source, same port
2. Execute query
3. Validate `unique_targets >= 15`

### Sample Query Results
| src_ip | dest_port | unique_targets | attempts |
|--------|-----------|----------------|----------|
| 192.168.1.105 | 22 | 16 | 16 |

---

## Test Case 5: XMAS Scan Detection

### Objective
Verify detection of XMAS scans (FIN+PSH+URG flags)

### Test Log
```
Feb 23 10:16:30 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DST=192.168.1.100 DPT=139 FIN,PSH,URG
Feb 23 10:16:31 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DST=192.168.1.100 DPT=445 FIN,PSH,URG
```

### Expected Behavior
- Detection triggers on ANY XMAS packet detection
- Severity: HIGH (extremely rare in legitimate traffic)

### Query (Splunk)
```splunk
index=firewall sourcetype=syslog "FIN,PSH,URG" 
| stats count by src_ip
```

---

## Test Case 6: Multi-Technique Detection

### Objective
Verify detection of sophisticated attacks using multiple techniques

### Test Log
```
[SYN scan packets from 192.168.1.105]
[FIN scan packets from 192.168.1.105]
```

### Expected Behavior
- Detection triggers when same source uses multiple techniques
- Indicates advanced attacker
- Severity: CRITICAL

### Test Procedure
1. Inject SYN packets: 192.168.1.105 → 192.168.1.100 (ports 22, 80, 443)
2. Inject FIN packets: 192.168.1.105 → 192.168.1.100 (ports 22, 23)
3. Execute multi-technique query
4. Verify both techniques appear in results

---

## Test Case 7: False Positive Test - Whitelist

### Objective
Verify legitimate traffic is NOT detected

### Test Scenario
Administrator connects from trusted IP (192.168.1.50) and establishes multiple legitimate connections

### Test Log
```
Feb 23 10:18:05 firewall kernel: [UFW ACCEPT] SRC=192.168.1.50 DST=192.168.1.100 DPT=22 SYN,ACK
Feb 23 10:18:06 firewall kernel: [UFW ACCEPT] SRC=192.168.1.50 DST=192.168.1.100 DPT=22 ACK
```

### Expected Behavior
- NO detection triggered
- Whitelist correctly excludes 192.168.1.50
- Action: ACCEPT (not BLOCK)

### Validation
```splunk
index=firewall sourcetype=syslog src_ip!=127.0.0.1 src_ip!="192.168.1.50" 
| stats dc(DPT) as unique_ports by src_ip 
| where unique_ports > 20
```

Result should NOT include 192.168.1.50

---

## Test Case 8: Low-and-Slow Scan Detection

### Objective
Verify detection of distributed scanning over extended time

### Test Log (Spread over 10 minutes)
```
[Few connection attempts spread evenly across 10 minutes]
Feb 23 10:15:00 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DPT=22 SYN
Feb 23 10:17:00 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DPT=23 SYN
Feb 23 10:19:00 firewall kernel: [UFW BLOCK] SRC=192.168.1.105 DPT=25 SYN
[... 20+ attempts over 10 minute window ...]
```

### Expected Behavior
- Detection triggers on aggregated activity over 5-10 minute window
- Detects slow, distributed reconnaissance
- Severity: MEDIUM

### Test Steps
1. Inject logs with 60-second intervals
2. Use time-based aggregation (5-10 minute windows)
3. Verify count >= 20 over longer time period

---

## Test Case 9: Outbound Scan Detection

### Objective
Verify detection of data exfiltration/outbound scanning

### Test Log
```
[Outbound connection attempts from internal host]
SRC=10.1.1.50 DST=8.8.8.8 DPT=22
SRC=10.1.1.50 DST=8.8.8.9 DPT=22
SRC=10.1.1.50 DST=8.8.8.10 DPT=22
[... 15+ unique external IPs ...]
```

### Expected Behavior
- Detection triggers on outbound scanning
- Indicates compromised internal host
- Severity: CRITICAL

### Query Filter
```
network.traffic_direction : "outbound"
AND source.ip : 10.0.0.0/8
```

---

## Test Case 10: Performance and Scalability Test

### Objective
Verify detection system performs under load

### Test Scenario
Inject 100,000 firewall log entries across multiple source IPs

### Expected Behavior
- Query completes within < 5 seconds
- Correctly identifies all scanning patterns
- Dashboard loads within acceptable time

### Test Procedure
```bash
# Generate large test dataset
python3 generate_large_test_dataset.py --events 100000 --output test_logs/large_dataset.json

# Ingest into Elasticsearch/Splunk
# Execute queries and measure response time
```

### Success Criteria
- Query response time < 5 seconds
- All 23 high-risk IPs identified
- No memory errors or timeouts

---

## Test Case 11: Baseline Traffic Pattern Test

### Objective
Establish normal traffic baseline to tune thresholds

### Test Data
Normal corporate traffic:
- User web browsing (port 80, 443)
- Email activity (port 25, 587)
- File transfer (port 21, 22)
- Database queries (port 3306, 5432)

### Expected Behavior
- NO false positives generated
- Thresholds correctly exclude normal patterns
- Alert only on anomalous activity

### Baseline Collection Period
- Capture 7-14 days of normal traffic
- Analyze distribution of connection attempts
- Set thresholds at 95th percentile

---

## Test Case 12: Alert Validation

### Objective
Verify alerts trigger correctly and escalate appropriately

### Test Alert Configuration
```
Trigger: unique_ports > 30 (Critical)
Trigger: unique_ports > 20 (High)
Trigger: unique_ports > 10 (Medium)
```

### Test Steps
1. Inject SYN scan with 25 unique ports
   - Expected: High alert triggered
2. Inject SYN scan with 35 unique ports
   - Expected: Critical alert triggered
3. Inject SYN scan with 5 unique ports
   - Expected: No alert

### Validation Points
- Alert message contains correct severity
- Timestamp matches injection time
- Source IP correctly identified
- Notification channel receives alert

---

## Test Case 13: Dashboard Data Freshness

### Objective
Verify dashboards display real-time or near-real-time data

### Test Procedure
1. Inject test log at T=0
2. View Splunk/Kibana dashboard at T+5 seconds
3. Verify data appears within 5-10 seconds

### Expected Behavior
- Data appears in dashboard within 10 seconds
- All panels update with fresh data
- Timestamps reflect recent activity

---

## Test Case 14: Query Syntax Validation

### Objective
Verify all queries have correct syntax and are executable

### Validation Checklist
- [ ] All Splunk SPL queries execute without syntax errors
- [ ] All Elasticsearch DSL JSON is valid JSON
- [ ] All KQL queries parse correctly in Kibana
- [ ] Field names match actual log field names
- [ ] Date range filters use correct syntax
- [ ] Aggregations are properly formatted

### Execution
```bash
# Test Splunk queries
splunk show saved-searches | grep port_scan

# Test Elasticsearch DSL
curl -X POST "localhost:9200/firewall-logs/_validate/query?pretty" \
  -H "Content-Type: application/json" \
  -d @query.json

# Test KQL
# Use Kibana Dev Tools Console
```

---

## Test Case 15: Logging and Audit Trail

### Objective
Verify detection events are logged for compliance

### Expected Logs
```
2024-02-23 10:15:32 DETECTION: SYN_SCAN_HIGH_RISK src_ip=192.168.1.105 unique_ports=22 severity=HIGH
2024-02-23 10:16:10 DETECTION: FIN_SCAN_MEDIUM src_ip=192.168.1.110 fin_count=4 severity=MEDIUM
2024-02-23 10:17:10 DETECTION: PORT_SWEEP_HIGH src_ip=192.168.1.105 unique_targets=16 severity=HIGH
```

### Audit Log Verification
1. Check Splunk `_internal` index for search executions
2. Verify Elasticsearch audit logs contain detection events
3. Confirm timestamp accuracy
4. Validate immutability (logs cannot be deleted)

---

## Test Execution Summary Table

| Test Case | Input | Expected Output | Status |
|-----------|-------|-----------------|--------|
| 1 - SYN Scan | 22 SYN packets | unique_ports >= 20, HIGH | ⬜ |
| 2 - FIN Scan | 5 FIN packets | fin_count >= 3, MEDIUM | ⬜ |
| 3 - NULL Scan | 2 NONE packets | null_count >= 2, HIGH | ⬜ |
| 4 - Port Sweep | 16 unique IPs | unique_targets >= 15, HIGH | ⬜ |
| 5 - XMAS Scan | 2 XMAS packets | xmas_count >= 1, HIGH | ⬜ |
| 6 - Multi-Tech | SYN + FIN | Both techniques detected | ⬜ |
| 7 - Whitelist | Trusted IP | NO detection | ⬜ |
| 8 - Slow Scan | 20 spread events | Aggregated detection | ⬜ |
| 9 - Outbound | 15 external IPs | outbound_ports >= 15 | ⬜ |
| 10 - Scale Test | 100K events | Response < 5 sec | ⬜ |
| 11 - Baseline | Normal traffic | NO false positives | ⬜ |
| 12 - Alert | Multiple thresholds | Correct severity | ⬜ |
| 13 - Freshness | Injection + 5s | Data visible in 10s | ⬜ |
| 14 - Syntax | All queries | No errors, executable | ⬜ |
| 15 - Audit | All detections | Events logged | ⬜ |

---

## Test Automation Script

```python
#!/usr/bin/env python3
# test_automation.py

import requests
import json
import time
from datetime import datetime, timedelta

class PortScanDetectionTester:
    def __init__(self, splunk_url, elasticsearch_url):
        self.splunk_url = splunk_url
        self.elasticsearch_url = elasticsearch_url
        
    def test_syn_scan(self):
        """Test Case 1: SYN Scan Detection"""
        test_logs = self._generate_syn_scan_logs(25)
        self._ingest_logs(test_logs)
        results = self._query_splunk("unique_ports >= 20")
        assert len(results) > 0, "SYN scan detection failed"
        print("✓ Test Case 1: SYN Scan Detection PASSED")
    
    def test_fin_scan(self):
        """Test Case 2: FIN Scan Detection"""
        test_logs = self._generate_fin_scan_logs(5)
        self._ingest_logs(test_logs)
        results = self._query_elasticsearch("tcp.flags:FIN")
        assert len(results) >= 3, "FIN scan detection failed"
        print("✓ Test Case 2: FIN Scan Detection PASSED")
    
    def test_null_scan(self):
        """Test Case 3: NULL Scan Detection"""
        test_logs = self._generate_null_scan_logs(2)
        self._ingest_logs(test_logs)
        results = self._query_elasticsearch("tcp.flags:NONE")
        assert len(results) >= 2, "NULL scan detection failed"
        print("✓ Test Case 3: NULL Scan Detection PASSED")
    
    def run_all_tests(self):
        """Execute all test cases"""
        tests = [
            self.test_syn_scan,
            self.test_fin_scan,
            self.test_null_scan,
        ]
        
        passed = 0
        failed = 0
        
        for test in tests:
            try:
                test()
                passed += 1
            except AssertionError as e:
                print(f"✗ {test.__name__} FAILED: {e}")
                failed += 1
        
        print(f"\nTest Results: {passed} passed, {failed} failed")
        return failed == 0
```

---

## Documentation

- For additional query testing, see `detections/splunk_queries.spl`
- For ELK-specific tests, see `detections/elastic_dsl_queries.json`
- For validation steps, see `testing/validation_steps.md`

---

**Test Suite Version:** 1.0  
**Last Updated:** 2024-02-23
