#!/bin/bash
# ═══════════════════════════════════════════════════════════
# NOCTIS — Dependency installer
# ═══════════════════════════════════════════════════════════

set -e

echo "[*] Installing system tools..."
sudo apt update
sudo apt install -y nmap dnsutils curl whois jq python3-pip golang-go

echo "[*] Installing ProjectDiscovery tools (Go)..."
export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "[*] Installing Python packages..."
pip3 install --user -r requirements.txt

echo "[+] Done. Run: python3 noctis.py -d example.com"
