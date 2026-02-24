#!/bin/bash

# Port Scan Detection Engineering Lab - Nmap Attack Simulation
# This script demonstrates various Nmap scanning techniques
# for cybersecurity lab and detection engineering purposes

TARGET_HOST="192.168.1.100"
TARGET_NETWORK="192.168.1.0/24"

echo "[*] Port Scan Detection Lab - Attack Simulation"
echo "[*] Target Host: $TARGET_HOST"
echo "[*] Target Network: $TARGET_NETWORK"
echo ""

# Function to display scan information
display_scan_info() {
    echo "=========================================="
    echo "Scan Type: $1"
    echo "Nmap Command: $2"
    echo "=========================================="
    echo ""
}

# 1. TCP SYN Scan (Stealth Scan)
display_scan_info "TCP SYN Scan (-sS)" "nmap -sS $TARGET_HOST"
# nmap -sS --reason --packet-trace $TARGET_HOST

# 2. TCP Connect Scan (Full Connection)
display_scan_info "TCP Connect Scan (-sT)" "nmap -sT $TARGET_HOST"
# nmap -sT $TARGET_HOST

# 3. FIN Scan (Stealth)
display_scan_info "FIN Scan (-sF)" "nmap -sF $TARGET_HOST"
# nmap -sF --packet-trace $TARGET_HOST

# 4. NULL Scan (Stealth)
display_scan_info "NULL Scan (-sN)" "nmap -sN $TARGET_HOST"
# nmap -sN --packet-trace $TARGET_HOST

# 5. XMAS Scan (Stealth)
display_scan_info "XMAS Scan (-sX)" "nmap -sX $TARGET_HOST"
# nmap -sX --packet-trace $TARGET_HOST

# 6. ACK Scan (Firewall Mapping)
display_scan_info "ACK Scan (-sA)" "nmap -sA $TARGET_HOST"
# nmap -sA $TARGET_HOST

# 7. Version Detection Scan
display_scan_info "Version Detection Scan (-sV)" "nmap -sV $TARGET_HOST"
# nmap -sV $TARGET_HOST

# 8. Aggressive Scan
display_scan_info "Aggressive Scan (-A)" "nmap -A $TARGET_HOST"
# nmap -A $TARGET_HOST

# 9. Port Sweep (Multiple Hosts)
display_scan_info "Port Sweep (-p 80,443,22)" "nmap -p 80,443,22 $TARGET_NETWORK"
# nmap -p 80,443,22 $TARGET_NETWORK

# 10. UDP Scan
display_scan_info "UDP Scan (-sU)" "nmap -sU $TARGET_HOST"
# nmap -sU $TARGET_HOST

# 11. Slow Scan (IDS Evasion)
display_scan_info "Slow Scan (--scan-delay 10s)" "nmap -sS --scan-delay 10s --max-parallelism 1 $TARGET_HOST"
# nmap -sS --scan-delay 10s --max-parallelism 1 $TARGET_HOST

# 12. Range Scan (Multiple Hosts, Common Ports)
display_scan_info "Range Scan (-p 1-1000)" "nmap -p 1-1000 -sS $TARGET_NETWORK"
# nmap -p 1-1000 -sS $TARGET_NETWORK

echo ""
echo "[+] Scan simulation guide created."
echo "[+] To execute actual scans (requires proper authorization):"
echo "    1. Uncomment desired nmap command"
echo "    2. Replace target host/network with authorized target"
echo "    3. Ensure network logs are being captured"
echo "    4. Monitor Splunk/ELK dashboards for detections"
echo ""

# Tcpdump example for capturing raw network traffic
echo "[*] Network Traffic Capture Commands:"
echo "=========================================="
echo "Capture all traffic:"
echo "  sudo tcpdump -i any -n -w capture.pcap"
echo ""
echo "Capture SYN packets:"
echo "  sudo tcpdump -i any 'tcp[tcpflags] & tcp-syn != 0' -w syn_capture.pcap"
echo ""
echo "Capture specific port scans:"
echo "  sudo tcpdump -i any 'dst port 1:1000' -w port_scan.pcap"
echo ""
