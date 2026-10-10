# NOCTIS v2

Recon pipeline for authorized security testing only.

## Features

- OpSec validation (public IP, DNS leak, VPN detection, shell history)
- Passive recon (subfinder, crt.sh, DNS records, WHOIS)
- Subdomain resolution (async, concurrent)
- HTTP probing (httpx with requests fallback)
- Active recon (nmap with service/version detection)
- HTML + JSON reports
- Safe subprocess handling (no shell injection)

## Installation

```bash
git clone https://github.com/kurobykuro/noctis
cd noctis
chmod +x install.sh
./install.sh
