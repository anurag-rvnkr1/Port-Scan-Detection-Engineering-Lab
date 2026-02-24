# Port Scan Detection Lab - Validation & Testing Steps

## Quick Start Validation (5 minutes)

### Step 1: Verify Installation
```bash
# Check all files present
ls -la port_scan_detection_lab/
# Expected output: attack_simulation/, logs/, detections/, dashboards/, testing/

# Verify scripts are executable
ls -l attack_simulation/nmap_commands.sh run_lab.sh install.sh

# Check dependencies
nmap --version
python3 --version
```

### Step 2: Verify Log Format
```bash
# Check sample logs were generated
wc -l logs/sample_*.log

# Expected output: ~30-50 lines per log file

# Inspect log structure
head -5 logs/sample_syslog.log
head -5 logs/sample_auth.log
```

### Step 3: Verify Query Syntax
```bash
# Splunk query syntax check
grep -c "stats" detections/splunk_queries.spl
# Expected: > 10 valid queries

# Validate JSON files
python3 -m json.tool detections/elastic_dsl_queries.json > /dev/null && echo "Valid JSON"

# Check ELK KQL format
grep -c "bool" detections/elk_kql_queries.txt
# Expected: Multiple KQL query examples
```

---

## Detailed Validation Procedures

### Splunk Integration Validation

#### 1. Splunk Connectivity Test
```bash
# Test HEC endpoint connectivity
curl -k https://localhost:8088/services/collector \
  -H "Authorization: Splunk your-hec-token" \
  -d '{"event":"test"}'

# Expected response: {"text":"Success","code":0}
```

#### 2. Index Creation Verification
```spl
# In Splunk UI - Search & Reporting
| rest /services/data/indexes | stats count
# Should list all indices including "firewall" or similar
```

#### 3. Sample Log Ingestion
```bash
# Send sample logs to Splunk
for log in logs/sample_*.log; do
  curl -k https://localhost:8088/services/collector \
    -H "Authorization: Splunk your-hec-token" \
    --data-binary @$log
done
```

#### 4. Query Validation (Splunk)
```spl
# Test basic query functionality
index=firewall 
| stats count

# Expected: Returns count of ingested events

# Test field extraction
index=firewall 
| stats count by SRC
# Expected: Shows source IPs from sample logs
```

#### 5. SYN Scan Detection Query Test
```spl
# Execute SYN scan detection query
index=firewall sourcetype=syslog "SYN" 
| stats count as syn_count, dc(DPT) as unique_ports by src_ip 
| where unique_ports > 20

# Expected results:
# src_ip=192.168.1.105, unique_ports=12, syn_count=12
# (from sample_syslog.log data)
```

#### 6. FIN Scan Detection Query Test
```spl
index=firewall sourcetype=syslog "FIN" 
| where DPT NOT IN (22, 80, 443) 
| stats count as fin_count, dc(DPT) as unique_fin_ports by src_ip 
| where unique_fin_ports >= 3

# Expected: src_ip=192.168.1.105 with fin_count >= 3
```

#### 7. Dashboard Import
1. Navigate to: **Settings** > **Dashboards**
2. Click **New Dashboard**
3. From toolbar: **Edit** > **Import** JSON
4. Select `dashboards/splunk_dashboard.json`
5. Verify all panels load without errors

#### 8. Dashboard Data Validation
```spl
# In dashboard - verify each panel
# Panel: "Total Blocked Connections (Last 1h)"
# Expected: Count > 0

# Panel: "Top Scanning Source IPs"
# Expected: 192.168.1.105 appears as top source

# Panel: "Most Targeted Ports"
# Expected: Ports 22, 80, 443, etc. appear with high counts
```

---

### Elasticsearch/Kibana Integration Validation

#### 1. Elasticsearch Connectivity Test
```bash
# Test cluster health
curl http://localhost:9200/_cluster/health

# Expected response: "status":"green" or "yellow"
```

#### 2. Index Pattern Verification
```bash
# List all indices
curl http://localhost:9200/_cat/indices?v

# Should show indices like:
# firewall-logs-2024.02.23
# logs-firewall*
```

#### 3. Sample Data Ingestion (Elasticsearch)
```bash
# Create index with mappings
curl -X PUT http://localhost:9200/firewall-logs \
  -H "Content-Type: application/json" \
  -d '{
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "source.ip": { "type": "ip" },
        "destination.port": { "type": "integer" },
        "tcp.flags": { "type": "keyword" },
        "firewall.action": { "type": "keyword" }
      }
    }
  }'

# Ingest sample log
curl -X POST http://localhost:9200/firewall-logs/_doc \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "2024-02-23T10:15:32Z",
    "source.ip": "192.168.1.105",
    "destination.ip": "192.168.1.100",
    "destination.port": 22,
    "tcp.flags": "SYN",
    "firewall.action": "BLOCK"
  }'
```

#### 4. KQL Query Test (Kibana)
```
# In Kibana > Discover
firewall.action : "BLOCK" AND tcp.flags : "SYN"

# Expected: Returns documents with matching criteria
```

#### 5. SYN Scan Detection Query Test (Elasticsearch)
```bash
curl -X POST http://localhost:9200/firewall-logs/_search \
  -H "Content-Type: application/json" \
  -d '{
    "query": {
      "bool": {
        "must": [
          { "match": { "tcp.flags": "SYN" } },
          { "match": { "firewall.action": "BLOCK" } }
        ]
      }
    },
    "aggs": {
      "by_source": {
        "terms": { "field": "source.ip", "size": 100 },
        "aggs": {
          "unique_ports": {
            "cardinality": { "field": "destination.port" }
          }
        }
      }
    }
  }'

# Expected: Returns aggregation showing source IPs with port count
```

#### 6. Kibana Dashboard Creation
1. Navigate: **Kibana** > **Dashboards**
2. Click **Create Dashboard**
3. Add visualization: **Metric** for total blocked connections
4. Add visualization: **Bar chart** for top source IPs
5. Add visualization: **Line chart** for activity timeline

#### 7. Alert Rule Creation (Kibana)
1. Go: **Stack Management** > **Rules and Connectors**
2. Click **Create Rule**
3. Choose **Search Threshold** rule type
4. Add query: `firewall.action : "BLOCK" AND tcp.flags : "SYN"`
5. Set threshold: `cardinality(destination.port) > 20`
6. Set notification: Email or Slack
7. Click **Create and enable rule**

---

## End-to-End Validation Workflow

### Workflow: Complete Detection Testing (30 minutes)

**Objective:** Validate entire detection pipeline from logs to alerts

#### Phase 1: Setup (5 min)
```bash
1. Start Splunk/Elasticsearch services
2. Verify connectivity from curl commands above
3. Create necessary indices/indexes
```

#### Phase 2: Log Injection (5 min)
```bash
# Option A: Splunk
bash run_lab.sh

# Option B: Elasticsearch
python3 scripts/ingest_logs.py logs/sample_syslog.log
```

#### Phase 3: Query Execution (5 min)
```bash
# Splunk: Execute from Search page
# ELK: Use Dev Tools or Kibana Discover
# Results should match expected outputs from test cases
```

#### Phase 4: Dashboard Validation (10 min)
```bash
1. Import dashboard JSON
2. Verify all panels load
3. Check data freshness (< 10 second delay)
4. Validate calculated fields match test data
```

#### Phase 5: Alert Testing (5 min)
```bash
1. Create alert rule for SYN scan detection
2. Set threshold to > 20 ports
3. Trigger alert by injecting test data
4. Verify notification received
```

---

## Automated Validation Script

Create `validation_script.sh`:

```bash
#!/bin/bash

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "Port Scan Detection Lab - Validation"
echo "=========================================="
echo ""

# Test 1: File Structure
echo -n "Test 1: Checking file structure... "
if [ -d "logs" ] && [ -d "detections" ] && [ -d "dashboards" ] && [ -d "testing" ]; then
    echo -e "${GREEN}PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}FAIL${NC}"
    ((FAIL++))
fi

# Test 2: Splunk Query Syntax
echo -n "Test 2: Validating Splunk query syntax... "
QUERY_COUNT=$(grep -c "^index=" detections/splunk_queries.spl)
if [ "$QUERY_COUNT" -gt 10 ]; then
    echo -e "${GREEN}PASS${NC} ($QUERY_COUNT queries found)"
    ((PASS++))
else
    echo -e "${RED}FAIL${NC}"
    ((FAIL++))
fi

# Test 3: JSON Validity
echo -n "Test 3: Validating Elastic DSL JSON... "
if python3 -m json.tool detections/elastic_dsl_queries.json > /dev/null 2>&1; then
    echo -e "${GREEN}PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}FAIL${NC}"
    ((FAIL++))
fi

# Test 4: Sample Logs
echo -n "Test 4: Checking sample logs... "
LOG_COUNT=$(ls logs/sample_*.log 2>/dev/null | wc -l)
if [ "$LOG_COUNT" -ge 3 ]; then
    echo -e "${GREEN}PASS${NC} ($LOG_COUNT log files)"
    ((PASS++))
else
    echo -e "${RED}FAIL${NC}"
    ((FAIL++))
fi

# Test 5: Test Cases Documentation
echo -n "Test 5: Checking test cases... "
if grep -q "Test Case 1" testing/test_cases.md; then
    echo -e "${GREEN}PASS${NC}"
    ((PASS++))
else
    echo -e "${RED}FAIL${NC}"
    ((FAIL++))
fi

# Test 6: Splunk HEC Connectivity
echo -n "Test 6: Testing Splunk HEC connectivity... "
if command -v curl &> /dev/null; then
    RESPONSE=$(curl -s -k https://localhost:8088/services/collector/health 2>/dev/null)
    if echo "$RESPONSE" | grep -q "\"status\""; then
        echo -e "${GREEN}PASS${NC}"
        ((PASS++))
    else
        echo -e "${YELLOW}SKIP${NC} (Splunk not running)"
        ((SKIP++))
    fi
else
    echo -e "${YELLOW}SKIP${NC} (curl not available)"
    ((SKIP++))
fi

# Test 7: Elasticsearch Connectivity
echo -n "Test 7: Testing Elasticsearch connectivity... "
if curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q "status"; then
    echo -e "${GREEN}PASS${NC}"
    ((PASS++))
else
    echo -e "${YELLOW}SKIP${NC} (Elasticsearch not running)"
    ((SKIP++))
fi

# Summary
echo ""
echo "=========================================="
echo "Validation Results"
echo "=========================================="
echo -e "${GREEN}Passed: $PASS${NC}"
[ $FAIL -gt 0 ] && echo -e "${RED}Failed: $FAIL${NC}"
[ $SKIP -gt 0 ] && echo -e "${YELLOW}Skipped: $SKIP${NC}"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All critical tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Please review.${NC}"
    exit 1
fi
```

### Run validation:
```bash
chmod +x validation_script.sh
./validation_script.sh
```

---

## Performance Benchmark

### Expected Metrics

| Metric | Target | Acceptable | Poor |
|--------|--------|-----------|------|
| Query Response Time | < 2s | < 5s | > 10s |
| Dashboard Load Time | < 3s | < 10s | > 20s |
| Log Ingestion Rate | > 10K/sec | > 5K/sec | < 1K/sec |
| Alert Latency | < 1 min | < 5 min | > 10 min |
| Detection Accuracy | > 95% | > 85% | < 75% |

### Performance Test
```bash
# Measure query response time
time splunk search 'index=firewall | stats count'

# Measure ingestion rate
# Count: rows per second from `run_lab.sh`
```

---

## Production Readiness Checklist

- [ ] All 15 test cases pass
- [ ] Query response time < 5 seconds
- [ ] Dashboard loads in < 10 seconds
- [ ] No false positives in baseline traffic
- [ ] Alerts configured and tested
- [ ] Escalation paths documented
- [ ] Runbooks created for each alert
- [ ] Backup/recovery procedures defined
- [ ] Access controls implemented
- [ ] Audit logging enabled
- [ ] Documentation complete
- [ ] Team trained on procedures

---

## Troubleshooting

### Query Returns No Results
```
Cause: Logs not ingested or field names don't match
Solution:
1. Verify logs were ingested: index=firewall | stats count
2. Check field names: index=firewall | head 1 | fields *
3. Adjust query field names to match actual data
```

### Slow Query Performance
```
Cause: Too many events or complex aggregations
Solution:
1. Limit time range: earliest=-1h latest=now
2. Add filters to reduce dataset: firewall.action="BLOCK"
3. Use summary indexing for frequent queries
4. Enable field acceleration on frequently searched fields
```

### Dashboard Visualization Errors
```
Cause: Incorrect field types or missing data
Solution:
1. Check field data type (keyword vs. text)
2. Verify field exists in index
3. Use field rename if naming differs
4. Check visualization query in JSON
```

---

## References

- **Test Cases Documentation:** `testing/test_cases.md`
- **Splunk Query Guide:** `detections/splunk_queries.spl`
- **ELK Query Guide:** `detections/elastic_dsl_queries.json`
- **Main Documentation:** `README.md`

---

**Validation Guide Version:** 1.0  
**Last Updated:** 2024-02-23
