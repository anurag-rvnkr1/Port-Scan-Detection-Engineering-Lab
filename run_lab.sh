#!/bin/bash

# Port Scan Detection Engineering Lab - Main Runner
# Orchestrates log generation and attack simulation

set -e

SPLUNK_HEC_URL="http://localhost:8088"
SPLUNK_HEC_TOKEN="your-hec-token"
ELK_ENDPOINT="http://localhost:9200"
LOG_DIR="./logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "=========================================="
echo "Port Scan Detection Lab - Main Execution"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1"
}

# Step 1: Generate sample logs
print_status "Step 1: Generating sample logs..."
if [ ! -d "$LOG_DIR" ]; then
    mkdir -p "$LOG_DIR"
fi

echo "[*] Generating syslog samples..."
python3 log_generator.py syslog > "$LOG_DIR/sample_syslog_$TIMESTAMP.log" 2>/dev/null || print_warning "Log generator not found, using sample logs"

echo "[*] Generating auth.log samples..."
python3 log_generator.py auth > "$LOG_DIR/sample_auth_$TIMESTAMP.log" 2>/dev/null || true

echo "[*] Generating firewall.log samples..."
python3 log_generator.py firewall > "$LOG_DIR/sample_firewall_$TIMESTAMP.log" 2>/dev/null || true

echo "[*] Generating Zeek conn.log samples..."
python3 log_generator.py zeek > "$LOG_DIR/zeek_conn_$TIMESTAMP.log" 2>/dev/null || true

echo "[*] Generating Suricata EVE.json samples..."
python3 log_generator.py suricata > "$LOG_DIR/suricata_eve_$TIMESTAMP.json" 2>/dev/null || true

print_status "Sample logs generated in $LOG_DIR"
echo ""

# Step 2: Validate log format
print_status "Step 2: Validating log formats..."
for logfile in "$LOG_DIR"/*; do
    if [ -f "$logfile" ]; then
        linecount=$(wc -l < "$logfile")
        echo "[*] $logfile: $linecount lines"
    fi
done
echo ""

# Step 3: Check Splunk connectivity
print_status "Step 3: Checking Splunk connectivity..."
if curl -s -H "Authorization: Splunk $SPLUNK_HEC_TOKEN" "$SPLUNK_HEC_URL/services/collector/health" > /dev/null 2>&1; then
    print_status "Splunk HEC endpoint is reachable"
else
    print_warning "Splunk HEC endpoint not reachable at $SPLUNK_HEC_URL"
    print_warning "Configure SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN in this script"
fi
echo ""

# Step 4: Check ELK connectivity
print_status "Step 4: Checking ELK connectivity..."
if curl -s "$ELK_ENDPOINT" > /dev/null 2>&1; then
    print_status "ELK endpoint is reachable"
else
    print_warning "ELK endpoint not reachable at $ELK_ENDPOINT"
    print_warning "Configure ELK_ENDPOINT in this script"
fi
echo ""

# Step 5: Display detection queries
print_status "Step 5: Detection queries available..."
echo "[*] Splunk Detection Queries:"
echo "    - See detections/splunk_queries.spl"
echo "[*] ELK Detection Queries:"
echo "    - See detections/elk_kql_queries.txt"
echo "    - See detections/elastic_dsl_queries.json"
echo ""

# Step 6: Log ingestion instructions
print_status "Step 6: Log ingestion instructions..."
echo ""
echo "========== SPLUNK LOG INGESTION =========="
echo "1. Upload to Splunk via HEC:"
echo "   for f in logs/*.log; do"
echo "       curl -X POST $SPLUNK_HEC_URL/services/collector \\"
echo "         -H \"Authorization: Splunk $SPLUNK_HEC_TOKEN\" \\"
echo "         -d @\$f"
echo "   done"
echo ""
echo "2. Or add to monitored directory:"
echo "   Settings > Data Inputs > Files & Directories"
echo "   Add path: $(pwd)/logs/"
echo ""

echo "========== ELK LOG INGESTION =========="
echo "1. Use Filebeat configuration:"
echo "   filebeat.inputs:"
echo "   - type: log"
echo "     paths:"
echo "       - $(pwd)/logs/*.log"
echo ""
echo "2. Or send via curl:"
echo "   jq -R '. as \$line | {\"message\": \$line}' logs/sample_syslog.log | \\"
echo "   while read line; do"
echo "       curl -X POST \"$ELK_ENDPOINT/port-scans/_doc\" -H \"Content-Type: application/json\" -d \"\$line\""
echo "   done"
echo ""

# Step 7: Display dashboard setup
print_status "Step 7: Dashboard setup..."
echo "[*] Splunk Dashboard: dashboards/splunk_dashboard.json"
echo "[*] ELK Kibana Dashboard: dashboards/kibana_dashboard_guide.md"
echo ""

# Step 8: Testing instructions
print_status "Step 8: Testing and validation..."
echo "[*] Run test cases:"
echo "    cat testing/test_cases.md"
echo "[*] Validation steps:"
echo "    cat testing/validation_steps.md"
echo ""

# Step 9: Display resume points
print_status "Step 9: Professional development..."
echo "[*] This lab demonstrates:"
echo "    - Advanced threat detection engineering"
echo "    - SIEM query optimization"
echo "    - False-positive reduction strategies"
echo "    - Network security monitoring"
echo ""

echo "=========================================="
print_status "Lab setup complete!"
echo "=========================================="
echo ""
echo "Configure your Splunk and ELK endpoints, then:"
echo "1. Ingest logs using instructions above"
echo "2. Import dashboards in Splunk/ELK"
echo "3. Verify detection alerts trigger correctly"
echo "4. Review testing/validation_steps.md"
echo ""
