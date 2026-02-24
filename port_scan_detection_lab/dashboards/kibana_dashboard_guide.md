# Kibana Dashboard Setup Guide - Port Scan Detection Lab

## Overview
This guide provides step-by-step instructions for setting up a comprehensive Kibana dashboard for port scan detection and reconnaissance monitoring.

## Prerequisites
- Elasticsearch 8.0+ with Kibana 8.0+
- Firewall logs ingested with Filebeat, Logstash, or direct API
- Index pattern created (e.g., `firewall-logs*`)
- KQL queries from `elk_kql_queries.txt` and Elasticsearch DSL queries available

---

## Step 1: Create Index Pattern

### In Kibana UI:
1. Navigate to **Stack Management** → **Index Patterns**
2. Click **Create index pattern**
3. Index pattern name: `firewall-logs*`
4. Timestamp field: `@timestamp`
5. Click **Create index pattern**

### Field Mapping (verify these exist):
- `source.ip` or `src_ip`
- `destination.ip` or `dest_ip`
- `destination.port` or `dest_port`
- `network.protocol`
- `firewall.action`
- `tcp.flags`
- `@timestamp`

---

## Step 2: Create Dashboards

### Dashboard 1: Port Scan Detection Overview

#### Panel 1: Total Blocked Connections (Single Stat)
```json
{
  "title": "Total Blocked Connections (Last 1h)",
  "visualization": {
    "type": "metric"
  },
  "query": {
    "bool": {
      "must": [
        { "match": { "firewall.action": "BLOCK" } }
      ],
      "filter": [
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}
```

#### Panel 2: Unique Source IPs (Single Stat)
```json
{
  "title": "Unique Scanning Source IPs (Last 1h)",
  "visualization": {
    "type": "metric"
  },
  "aggregations": {
    "unique_sources": {
      "cardinality": { "field": "source.ip" }
    }
  }
}
```

#### Panel 3: High Risk Alert Count (Single Stat)
```json
{
  "title": "High Risk Alerts (SYN > 20 ports)",
  "visualization": {
    "type": "metric"
  },
  "query": {
    "bool": {
      "must": [
        { "match": { "tcp.flags": "SYN" } }
      ]
    }
  },
  "aggregations": {
    "by_source": {
      "terms": { "field": "source.ip" },
      "aggs": {
        "unique_ports": {
          "cardinality": { "field": "destination.port" }
        }
      }
    }
  }
}
```

#### Panel 4: Top Scanning Source IPs (Bar Chart)
```
Visualization: Vertical Bar Chart
X-axis: source.ip (terms aggregation, top 10)
Y-axis: count
Query: 
{
  "bool": {
    "must": [
      { "match": { "firewall.action": "BLOCK" } }
    ],
    "filter": [
      { "range": { "@timestamp": { "gte": "now-24h" } } }
    ]
  }
}
```

#### Panel 5: Scan Type Distribution (Pie Chart)
```
Visualization: Pie Chart
Segments: tcp.flags (terms aggregation)
Size: count of documents
Query:
{
  "bool": {
    "must": [
      { "match": { "firewall.action": "BLOCK" } }
    ]
  }
}
```

#### Panel 6: Most Targeted Ports (Horizontal Bar)
```
Visualization: Horizontal Bar Chart
Y-axis: destination.port (terms, top 15)
X-axis: count
Query:
{
  "bool": {
    "must": [
      { "match": { "firewall.action": "BLOCK" } }
    ]
  }
}
```

#### Panel 7: Scan Activity Timeline (Line Chart)
```
Visualization: Line Chart
X-axis: @timestamp (date histogram, 5m interval)
Y-axis: count
Colored by: source.ip (top 5)
Query:
{
  "bool": {
    "must": [
      { "match": { "firewall.action": "BLOCK" } }
    ],
    "filter": [
      { "range": { "@timestamp": { "gte": "now-24h" } } }
    ]
  }
}
```

---

### Dashboard 2: Detailed Threat Investigation

#### Panel 1: SYN Scan High Risk Detections (Data Table)
```
Visualization: Data Table
Columns: source.ip, unique_ports, attempt_count, severity, @timestamp
Query:
{
  "bool": {
    "must": [
      { "match": { "tcp.flags": "SYN" } },
      { "match": { "firewall.action": "BLOCK" } }
    ]
  }
}
Aggregations:
{
  "by_source": {
    "terms": { "field": "source.ip", "size": 100 },
    "aggs": {
      "unique_ports": { "cardinality": { "field": "destination.port" } },
      "attempts": { "value_count": { "field": "destination.port" } }
    }
  }
}
Filter: unique_ports > 20
```

#### Panel 2: Stealth Scan Techniques (Data Table)
```
Visualization: Data Table
Columns: source.ip, tcp.flags, unique_ports, @timestamp
Query:
{
  "bool": {
    "must": [
      {
        "terms": {
          "tcp.flags": ["FIN", "NONE", "FIN,PSH,URG"]
        }
      }
    ]
  }
}
```

#### Panel 3: Port Sweep Attacks (Data Table)
```
Visualization: Data Table
Columns: source.ip, destination.port, unique_targets, attempts
Query:
{
  "bool": {
    "must": [
      { "match": { "firewall.action": "BLOCK" } }
    ]
  }
}
Aggregations:
{
  "by_source_port": {
    "composite": {
      "sources": [
        { "source_ip": { "terms": { "field": "source.ip" } } },
        { "dest_port": { "terms": { "field": "destination.port" } } }
      ]
    },
    "aggs": {
      "unique_targets": {
        "cardinality": { "field": "destination.ip" }
      }
    }
  }
}
Filter: unique_targets > 15
```

#### Panel 4: Raw Firewall Events (Data Table)
```
Visualization: Data Table
Columns: @timestamp, source.ip, destination.ip, destination.port, tcp.flags, firewall.action
Query: All firewall logs
Sort: @timestamp descending
Limit: 500 rows
```

---

### Dashboard 3: Operational Metrics & Alerts

#### Panel 1: Alert Severity Breakdown (Stacked Bar)
```
Visualization: Stacked Horizontal Bar
X-axis: count
Y-axis: severity (critical, high, medium, low)
Query: Aggregated by severity level
```

#### Panel 2: Attack Sources by Country (Map)
```
Visualization: Maps (Elasticsearch Maps)
Location data: source.geo.location
Color intensity: count of events
Query:
{
  "bool": {
    "must": [
      { "match": { "firewall.action": "BLOCK" } }
    ]
  }
}
```

#### Panel 3: Detection Effectiveness (Metric)
```
Visualization: Metric
KPI: Number of alerts generated
Threshold: > 50 alerts/day = good detection
```

#### Panel 4: Mean Time Between Scans (Metric)
```
Visualization: Metric
Formula: Avg time between detection events
Indicates: How frequently scanning occurs
```

---

## Step 3: Create Alerts

### Alert 1: Critical SYN Scan Detected

**Trigger Condition:**
- Single source IP with > 30 unique ports in 5 minutes
- Action: HIGH severity

**Configuration:**
1. Kibana UI → **Stack Management** → **Rules and Connectors**
2. Click **Create Rule**
3. Rule type: **Search Threshold**
4. Query:
```json
{
  "bool": {
    "must": [
      { "match": { "tcp.flags": "SYN" } },
      { "match": { "firewall.action": "BLOCK" } }
    ],
    "filter": [
      { "range": { "@timestamp": { "gte": "now-5m" } } }
    ]
  }
}
```
5. Aggregation: `cardinality` of `destination.port` by `source.ip`
6. Threshold: unique_ports > 30
7. Notification: Email, Slack, webhook

### Alert 2: Stealth Scan Technique Detected

**Trigger Condition:**
- Any FIN, NULL, or XMAS scan detected
- Action: MEDIUM severity

**Configuration:**
Same as above but query includes:
```json
{
  "terms": {
    "tcp.flags": ["FIN", "NONE", "FIN,PSH,URG"]
  }
}
```
Threshold: count > 0

### Alert 3: Port Sweep in Progress

**Trigger Condition:**
- Single source scanning > 15 unique destinations on same port
- Action: HIGH severity

---

## Step 4: Create Canvas Report

For executive reporting, create a Canvas visualization:

1. **Kibana** → **Canvas**
2. Create new workpad
3. Add elements:
   - Map of attack sources
   - Timeline of attacks
   - Top 10 scanning IPs
   - Severity distribution pie chart
   - Attack technique breakdown

---

## Step 5: Configure Scheduled Reports

### Daily Threat Report

**Schedule:** 9:00 AM UTC daily

**Content:**
- Summary of yesterday's scanning activity
- Top 5 attacking IPs
- Most targeted ports
- Number of high-risk detections
- Geographical distribution

**Steps:**
1. Create a saved search dashboard
2. Stack Management → **Reporting**
3. Schedule PDF generation and email

---

## Step 6: Data Enrichment & Lookups

### Enrich Source IP with Threat Intelligence

```json
{
  "processor": {
    "enrich": {
      "policy_name": "threat_intel_enrichment",
      "field": "source.ip",
      "target_field": "source.threat_intel"
    }
  }
}
```

### Create Lookup Tables for:
- Known vulnerability scanners (Nessus, Qualys, etc.)
- Internal IP ranges
- VPN concentrators
- Approved testing IPs

---

## Step 7: ML-Based Anomaly Detection

### Use Kibana ML for:

1. **Anomaly Detection Job:**
   - Field: Source IP connection attempts
   - Detect abnormal increase in scanning activity
   - Baseline: Normal traffic patterns

2. **Forecast:**
   - Predict when next major scan might occur
   - Identify patterns in attacker behavior

**Configuration:**
1. **Machine Learning** → **Anomaly Detection**
2. Select index pattern: `firewall-logs*`
3. Metric: `count` of `firewall.action:BLOCK`
4. Time interval: 5 minutes
5. View anomalies in dedicated dashboard

---

## Step 8: Export & Version Control

### Export Dashboards:
```bash
# Using Kibana API
curl -X GET "localhost:5601/api/saved_objects/dashboard/dashboard-id" \
  -H "kbn-xsrf: true" > dashboard.json

# Import dashboard
curl -X POST "localhost:5601/api/saved_objects/dashboard" \
  -H "kbn-xsrf: true" \
  -d @dashboard.json
```

### Git integration:
- Store dashboard JSON in Git repo
- Version control all queries and alerts
- Use Infrastructure as Code (IaC) for Elasticsearch

---

## Performance Optimization

### Index Settings:
```json
{
  "settings": {
    "number_of_shards": 3,
    "number_of_replicas": 1,
    "refresh_interval": "5s"
  },
  "mappings": {
    "properties": {
      "source.ip": { "type": "ip" },
      "destination.port": { "type": "integer" },
      "tcp.flags": { "type": "keyword" },
      "firewall.action": { "type": "keyword" }
    }
  }
}
```

### ILM Policy (Index Lifecycle Management):
```json
{
  "policy": "firewall-logs-policy",
  "phases": {
    "hot": {
      "min_age": "0d",
      "actions": {
        "rollover": { "max_primary_shard_size": "50GB" }
      }
    },
    "warm": {
      "min_age": "30d",
      "actions": {
        "set_priority": { "priority": 50 }
      }
    },
    "delete": {
      "min_age": "90d",
      "actions": {
        "delete": {}
      }
    }
  }
}
```

---

## Troubleshooting

### Dashboard Slow to Load:
- Check query performance in Dev Tools
- Use Kibana alerting for background processing
- Implement aggregation-based visualization instead of raw data

### Missing Data:
- Verify index pattern includes firewall logs
- Check field mappings match actual log format
- Use Index Management to inspect indices

### Alerts Not Triggering:
- Check rule connector configuration
- Verify threshold values
- Review rule execution logs in Stack Management

---

## Best Practices

1. **Query Optimization:**
   - Use filters instead of queries where possible
   - Limit time range to necessary periods
   - Pre-filter at ingest time with Logstash/Filebeat

2. **Dashboard Design:**
   - Group related panels together
   - Use consistent color schemes
   - Provide clear labels and descriptions

3. **Alert Management:**
   - Set appropriate thresholds for your environment
   - Create escalation paths
   - Document alert runbooks

4. **Data Retention:**
   - Keep hot logs for 30 days
   - Warm logs for 60 days
   - Archive logs beyond 90 days

---

## Maintenance Schedule

- **Daily:** Review high-risk alerts
- **Weekly:** Analyze trend data, tune thresholds
- **Monthly:** Review dashboard effectiveness
- **Quarterly:** Update lookups and threat intel

---

## References

- [Elasticsearch Documentation](https://www.elastic.co/guide/en/elasticsearch/reference/current/)
- [Kibana Alerts Guide](https://www.elastic.co/guide/en/kibana/current/alerting-getting-started.html)
- [Filebeat Prospector Configuration](https://www.elastic.co/guide/en/beats/filebeat/current/)

---

**Dashboard Version:** 1.0  
**Last Updated:** 2024-02-23  
**Author:** SOC Detection Engineer
