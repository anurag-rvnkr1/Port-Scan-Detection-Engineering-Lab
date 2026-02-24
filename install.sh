#!/bin/bash

# Port Scan Detection Engineering Lab - Installation Script
# Sets up the complete lab environment

set -e

echo "=========================================="
echo "Port Scan Detection Lab - Installation"
echo "=========================================="
echo ""

# Check if running on Linux
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo "[!] This lab is designed for Linux (Kali Linux preferred)"
    exit 1
fi

# Check if running as root or with sudo
if [[ $EUID -ne 0 ]]; then
   echo "[!] This script must be run as root"
   exit 1
fi

echo "[*] Step 1: Installing system dependencies..."
apt-get update
apt-get install -y \
    nmap \
    tcpdump \
    wireshark \
    zeek \
    suricata \
    python3 \
    python3-pip \
    python3-venv \
    git \
    jq \
    curl \
    wget

echo "[+] System dependencies installed"
echo ""

echo "[*] Step 2: Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip3 install -r requirements.txt
    echo "[+] Python dependencies installed"
else
    echo "[!] requirements.txt not found"
fi
echo ""

echo "[*] Step 3: Creating directory structure..."
mkdir -p logs
mkdir -p detections
mkdir -p dashboards
mkdir -p testing
mkdir -p attack_simulation
echo "[+] Directory structure created"
echo ""

echo "[*] Step 4: Setting permissions..."
chmod +x attack_simulation/nmap_commands.sh
chmod +x run_lab.sh
echo "[+] Permissions set"
echo ""

echo "[*] Step 5: Verifying installations..."
echo "[*] Checking Nmap version:"
nmap --version || echo "[!] Nmap not found"

echo "[*] Checking Python version:"
python3 --version || echo "[!] Python3 not found"

echo ""
echo "=========================================="
echo "[+] Installation Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Review the README.md for lab overview"
echo "2. Configure Splunk and ELK endpoints in run_lab.sh"
echo "3. Run './run_lab.sh' to start the lab"
echo "4. Monitor detections in Splunk/ELK dashboards"
echo ""
