#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════
#   NOCTIS v2.1 — Recon Pipeline
#   Passive + Active Recon with OpSec Validation
#   Offline-first. Silent by default.
#   Authorized testing only.
# ═══════════════════════════════════════════════════════════

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FTimeout
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
    import dns.resolver
    import requests
    import whois as whois_lib
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from jinja2 import Template
except ImportError as e:
    print(f"[-] Missing dependency: {e.name}")
    print("[*] Run: pip3 install -r requirements.txt")
    sys.exit(1)

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────
# SETUP
# ─────────────────────────────────────────────
CONSOLE = Console()

BANNER = r"""
[bold magenta]
   ███╗   ██╗ ██████╗  ██████╗████████╗██╗███████╗
   ████╗  ██║██╔═══██╗██╔════╝╚══██╔══╝██║██╔════╝
   ██╔██╗ ██║██║   ██║██║        ██║   ██║███████╗
   ██║╚██╗██║██║   ██║██║        ██║   ██║╚════██║
   ██║ ╚████║╚██████╔╝╚██████╗   ██║   ██║███████║
   ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝   ╚═╝   ╚═╝╚══════╝
[/bold magenta]
[dim]   recon pipeline  ·  v2.1  ·  silent operations[/dim]
"""


# ─────────────────────────────────────────────
# CAPABILITY DETECTION
# ─────────────────────────────────────────────
def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def resolve_nmap_flags(base_flags: str, has_root: bool) -> tuple[str, bool]:
    """Downgrade -sS to -sT if not root. Returns (flags, downgraded)."""
    if not has_root and "-sS" in base_flags:
        return base_flags.replace("-sS", "-sT"), True
    return base_flags, False


# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
def load_config(path: Path) -> dict:
    defaults = {
        "opsec": {
            "enabled": True,
            "min_score": 5,
            "offline": True,
        },
        "passive": {
            "subfinder": True,
            "crt_sh": True,
            "whois": True,
            "dns_records": True,
            "max_subdomains": 500,
        },
        "active": {
            "profile": "phantom",
            "profiles": {
                "phantom": {
                    "nmap_flags": "-sS -T2 -Pn -f --data-length 24",
                    "ports": "custom",
                    "custom_ports": "22,80,443,445,3389,5985,5986",
                    "service_detection": False,
                    "default_scripts": False,
                    "os_detection": False,
                },
                "standard": {
                    "nmap_flags": "-sS -T3 -Pn",
                    "ports": "top-1000",
                    "custom_ports": "",
                    "service_detection": True,
                    "default_scripts": False,
                    "os_detection": False,
                },
                "full": {
                    "nmap_flags": "-sS -T4 -Pn",
                    "ports": "all",
                    "custom_ports": "",
                    "service_detection": True,
                    "default_scripts": True,
                    "os_detection": True,
                },
            },
            "timeout": 600,
        },
        "resolve": {"enabled": True, "concurrency": 50},
        "http": {"enabled": True, "concurrency": 50, "timeout": 10},
        "output": {
            "dir": "~/.noctis/recon",
            "formats": ["json", "html"],
            "keep_raw": True,
        },
    }
    if path.exists():
        with open(path) as f:
            user_cfg = yaml.safe_load(f) or {}
        for k, v in user_cfg.items():
            if isinstance(v, dict) and k in defaults and isinstance(defaults[k], dict):
                defaults[k].update(v)
            else:
                defaults[k] = v
    return defaults


# ─────────────────────────────────────────────
# UTILS
# ─────────────────────────────────────────────
def log(msg: str, level: str = "info"):
    styles = {
        "info": "[cyan][*][/cyan]",
        "ok":   "[green][+][/green]",
        "warn": "[yellow][!][/yellow]",
        "err":  "[red][-][/red]",
        "step": "[magenta][>][/magenta]",
    }
    CONSOLE.print(f"{styles.get(level, '[*]')} {msg}")


def run(cmd, timeout=60):
    """Run a command safely. Lists only — never shell=True."""
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, shell=False,
        )
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        log(f"Timeout: {' '.join(cmd) if isinstance(cmd, list) else cmd}", "warn")
        return ""
    except FileNotFoundError:
        log(f"Command not found: {cmd[0]}", "warn")
        return ""
    except Exception as e:
        log(f"Execution error: {e}", "warn")
        return ""


def which(tool: str) -> bool:
    return shutil.which(tool) is not None


def save(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, (dict, list)):
        path.write_text(json.dumps(data, indent=2, default=str))
    else:
        path.write_text(str(data))
    return path


# ─────────────────────────────────────────────
# PHASE 0 — OPSEC CHECK
# ─────────────────────────────────────────────
def check_public_ip_offline() -> tuple[str, bool]:
    """Local fallback — no external calls. Returns (ip, has_vpn_like)."""
    out = run(["bash", "-c",
        "ip -4 addr show scope global | grep inet | awk '{print $2}' | cut -d/ -f1"],
        timeout=5)
    if not out:
        return "", False

    ips = out.splitlines()
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                        "172.29.", "172.30.", "172.31.")

    for ip in ips:
        if not any(ip.startswith(p) for p in private_prefixes):
            return ip, False  # public IP directly visible
    return ips[0], True  # only private IPs = likely tunneled


def check_public_ip_online() -> tuple[str, bool]:
    """External lookup. Sends your IP to 3 third parties. Use only if you want."""
    sources = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    ips = []
    for url in sources:
        try:
            r = requests.get(url, timeout=5)
            if r.ok:
                ips.append(r.text.strip())
        except Exception:
            continue
    if not ips:
        return "", False
    unique = set(ips)
    return list(unique)[0], len(unique) == 1


def check_dns_leak() -> tuple[bool, str]:
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        return True, "resolv.conf not found"
    content = resolv.read_text()
    if "127.0.0.53" in content or "127.0.0.1" in content:
        upstream = run(["resolvectl", "status"], timeout=5)
        if "DNS Servers" in upstream:
            return True, "systemd-resolved active"
        return False, "local stub resolver - potential leak"
    return True, "direct DNS"


def check_vpn() -> tuple[bool, str]:
    ifaces = run(["ip", "-o", "link", "show"], timeout=5)
    vpn_keywords = ["tun", "tap", "wg", "ppp", "utun", "tailscale", "zerotier"]
    detected = []
    for line in ifaces.splitlines():
        for kw in vpn_keywords:
            if kw in line:
                parts = line.split(":")
                if len(parts) > 1:
                    detected.append(parts[1].strip())

    if not detected:
        return False, "no VPN interface detected"

    routes = run(["ip", "route", "show", "default"], timeout=5)
    default_iface = ""
    if routes:
        m = re.search(r"dev\s+(\S+)", routes)
        if m:
            default_iface = m.group(1)

    if default_iface and default_iface in detected:
        return True, f"VPN active ({default_iface}) - default route confirmed"
    return True, f"VPN interface up ({', '.join(detected)}) - route unverified"


def opsec_check(cfg: dict, offline: bool = True) -> int:
    log("PHASE 0 - OpSec validation", "step")
    if offline:
        log("Offline mode - no external IP lookups", "info")

    score = 10
    issues = []

    if offline:
        ip, tunneled = check_public_ip_offline()
        if ip:
            log(f"Local IP: {ip}", "info")
            if not tunneled:
                score -= 1
                issues.append("Public IP visible directly - no tunnel detected")
        else:
            score -= 2
            issues.append("No global IP found")
    else:
        ip, consistent = check_public_ip_online()
        if not ip:
            score -= 2
            issues.append("Public IP unreachable")
        else:
            log(f"Public IP: {ip}", "info")
            if not consistent:
                score -= 1
                issues.append("IP sources disagree - possible proxy")

    dns_ok, dns_msg = check_dns_leak()
    if not dns_ok:
        score -= 1
        issues.append(dns_msg)

    vpn_ok, vpn_msg = check_vpn()
    if vpn_ok:
        log(f"VPN: {vpn_msg}", "ok")
    else:
        score -= 1
        issues.append("No VPN detected - traffic may be exposed")

    hist = Path.home() / ".bash_history"
    if hist.exists():
        try:
            lines = len(hist.read_text(errors="ignore").splitlines())
            if lines > 100:
                score -= 2
                issues.append(f"Shell history has {lines} lines - clear before ops")
        except Exception:
            pass

    conns = run(["bash", "-c",
        "ss -tun | grep -v 127.0.0.1 | tail -n +2 | wc -l"], timeout=5)
    try:
        n = int(conns)
        if n > 5:
            score -= 1
            issues.append(f"{n} active external connections")
    except ValueError:
        pass

    score = max(0, score)
    color = "ok" if score >= 7 else "warn"
    log(f"OpSec Score: {score}/10", color)

    for issue in issues:
        log(issue, "warn")

    if score < cfg["opsec"]["min_score"]:
        log(f"Score below threshold ({cfg['opsec']['min_score']}). Aborting.", "err")
        sys.exit(1)

    return score


# ─────────────────────────────────────────────
# PHASE 1 — PASSIVE RECON
# ─────────────────────────────────────────────
def run_subfinder(domain: str) -> list[str]:
    if not which("subfinder"):
        log("subfinder not installed - skipping", "warn")
        return []
    log("Running subfinder...", "info")
    try:
        out = run(["subfinder", "-d", domain, "-silent"], timeout=120)
    except Exception as e:
        log(f"subfinder failed: {e}", "warn")
        return []
    if not out:
        log("subfinder returned no results", "warn")
        return []
    return sorted(set(out.splitlines()))


def run_crtsh(domain: str) -> list[str]:
    log("Querying crt.sh...", "info")
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=30,
        )
        if not r.ok:
            return []
        data = r.json()
        subs = set()
        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().replace("*.", "")
                if name and (name == domain or name.endswith("." + domain)):
                    subs.add(name)
        return sorted(subs)
    except Exception as e:
        log(f"crt.sh error: {e}", "warn")
        return []


def get_dns_records(domain: str) -> dict:
    log("Resolving DNS records...", "info")
    records = {}
    for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=10)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            records[rtype] = []
    return records


def get_whois(domain: str) -> dict:
    log("Querying WHOIS...", "info")
    try:
        with ThreadPoolExecutor(max_workers=1) as ex:
            fut = ex.submit(whois_lib.whois, domain)
            w = fut.result(timeout=15)

        def _s(v):
            return str(v) if v else None

        cd = w.creation_date
        ed = w.expiration_date
        if isinstance(cd, list):
            cd = cd[0] if cd else None
        if isinstance(ed, list):
            ed = ed[0] if ed else None

        return {
            "registrar": _s(w.registrar),
            "creation_date": _s(cd),
            "expiration_date": _s(ed),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "org": _s(w.org),
            "country": _s(w.country),
        }
    except FTimeout:
        log("WHOIS timed out - skipping", "warn")
        return {}
    except Exception as e:
        log(f"WHOIS error: {e}", "warn")
        return {}


def passive_recon(domain: str, cfg: dict) -> dict:
    log(f"PHASE 1 - Passive recon on {domain}", "step")

    results = {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "subdomains": [],
        "dns": {},
        "whois": {},
    }

    subs = set()
    if cfg["passive"]["subfinder"]:
        subs.update(run_subfinder(domain))
    if cfg["passive"]["crt_sh"]:
        subs.update(run_crtsh(domain))

    results["subdomains"] = sorted(subs)[:cfg["passive"]["max_subdomains"]]
    log(f"Found {len(results['subdomains'])} unique subdomains", "ok")

    if cfg["passive"]["dns_records"]:
        results["dns"] = get_dns_records(domain)

    if cfg["passive"]["whois"]:
        results["whois"] = get_whois(domain)

    return results


# ─────────────────────────────────────────────
# PHASE 2 — RESOLVE & HTTP PROBE
# ─────────────────────────────────────────────
def resolve_subdomains(subs: list[str], concurrency: int = 50) -> dict:
    log(f"Resolving {len(subs)} subdomains...", "info")
    resolved = {}

    def _resolve(sub):
        try:
            answers = dns.resolver.resolve(sub, "A", lifetime=5)
            return sub, [str(r) for r in answers]
        except Exception:
            return sub, []

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(_resolve, s): s for s in subs}
        with Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            console=CONSOLE,
        ) as prog:
            task = prog.add_task("Resolving...", total=len(futures))
            for fut in as_completed(futures):
                sub, ips = fut.result()
                if ips:
                    resolved[sub] = ips
                prog.advance(task)

    log(f"Resolved {len(resolved)}/{len(subs)} subdomains", "ok")
    return resolved


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    return m.group(1).strip()[:100] if m else ""


def http_probe(subdomains: list[str], concurrency: int = 50) -> list[dict]:
    if which("httpx"):
        log("Running httpx...", "info")
        tmp = Path("/tmp/_noctis_subs.txt")
        tmp.write_text("\n".join(subdomains))
        out = run([
            "httpx", "-l", str(tmp),
            "-silent", "-json", "-status-code", "-title", "-tech-detect",
            "-timeout", "10",
        ], timeout=300)
        results = []
        for line in out.splitlines():
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        log(f"httpx found {len(results)} live hosts", "ok")
        return results

    log("httpx not found - using requests fallback", "warn")
    results = []

    def _probe(host):
        for scheme in ["https", "http"]:
            try:
                r = requests.get(
                    f"{scheme}://{host}",
                    timeout=10,
                    verify=False,
                    allow_redirects=True,
                )
                return {
                    "input": host,
                    "url": r.url,
                    "status_code": r.status_code,
                    "title": _extract_title(r.text),
                    "scheme": scheme,
                }
            except Exception:
                continue
        return None

    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for res in ex.map(_probe, subdomains):
            if res:
                results.append(res)

    log(f"Found {len(results)} live hosts", "ok")
    return results


# ─────────────────────────────────────────────
# PHASE 3 — ACTIVE RECON (NMAP)
# ─────────────────────────────────────────────
def parse_nmap_xml(xml: str) -> list[dict]:
    if not xml.strip():
        return []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as e:
        log(f"XML parse error: {e}", "warn")
        return []

    hosts = []
    for host in root.iter("host"):
        addr_el = host.find("address")
        if addr_el is None:
            continue

        host_data = {
            "ip": addr_el.get("addr"),
            "hostnames": [h.get("name") for h in host.iter("hostname")],
            "ports": [],
            "os": [],
        }

        for port in host.iter("port"):
            state_el = port.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port.find("service")
            host_data["ports"].append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": service_el.get("name", "") if service_el is not None else "",
                "product": service_el.get("product", "") if service_el is not None else "",
                "version": service_el.get("version", "") if service_el is not None else "",
            })

        for osmatch in host.iter("osmatch"):
            host_data["os"].append({
                "name": osmatch.get("name"),
                "accuracy": osmatch.get("accuracy"),
            })

        hosts.append(host_data)

    return hosts


def active_recon(target: str, cfg: dict, profile: str = "phantom",
                 dry_run: bool = False) -> dict:
    log(f"PHASE 3 - Active recon on {target} [{profile}]", "step")

    if not which("nmap"):
        log("nmap not installed", "err")
        return {"target": target, "hosts": [], "raw_xml": "",
                "error": "nmap_missing", "profile": profile}

    profiles = cfg["active"]["profiles"]
    if profile not in profiles:
        log(f"Unknown profile '{profile}', using phantom", "warn")
        profile = "phantom"

    p = profiles[profile]
    has_root = is_root()

    flags_str, downgraded = resolve_nmap_flags(p["nmap_flags"], has_root)
    flags = flags_str.split()

    if downgraded:
        log("Not root - using -sT (TCP connect) instead of -sS", "warn")

    if p["service_detection"]:
        flags.append("-sV")
    if p["default_scripts"]:
        flags.append("-sC")
    if p["os_detection"]:
        if has_root:
            flags.append("-O")
        else:
            log("OS detection requires root - skipping", "warn")

    if p["ports"] == "all":
        flags.append("-p-")
    elif p["ports"].startswith("top-"):
        flags.extend(["--top-ports", p["ports"].split("-")[1]])
    else:
        ports = p["custom_ports"] or "22,80,443,445,3389,5985,5986"
        flags.extend(["-p", ports])

    flags.extend(["-oX", "-", target])
    full_cmd = ["nmap"] + flags

    log(f"Command: {' '.join(full_cmd)}", "info")

    if dry_run:
        log("Dry run - not executing", "warn")
        return {
            "target": target,
            "profile": profile,
            "command": " ".join(full_cmd),
            "dry_run": True,
        }

    xml = run(full_cmd, timeout=cfg["active"]["timeout"])

    if not xml:
        log("nmap returned nothing", "warn")
        return {"target": target, "hosts": [], "raw_xml": "",
                "profile": profile, "root": has_root}

    hosts = parse_nmap_xml(xml)
    total_ports = sum(len(h["ports"]) for h in hosts)
    log(f"Found {len(hosts)} hosts, {total_ports} open ports", "ok")

    return {
        "target": target,
        "profile": profile,
        "root": has_root,
        "hosts": hosts,
        "raw_xml": xml if cfg["output"]["keep_raw"] else "",
    }


# ─────────────────────────────────────────────
# PHASE 4 — REPORTING
# ─────────────────────────────────────────────
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>NOCTIS Report - {{ domain or target }}</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; padding: 2rem; }
  h1 { color: #58a6ff; border-bottom: 2px solid #30363d; padding-bottom: .5rem; }
  h2 { color: #79c0ff; margin-top: 2rem; }
  h3 { color: #79c0ff; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin: 1rem 0; }
  .stat { display: inline-block; margin: 0 .5rem; padding: .5rem 1rem; background: #21262d; border-radius: 6px; }
  .stat b { color: #58a6ff; font-size: 1.4rem; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { text-align: left; padding: .5rem; border-bottom: 1px solid #30363d; }
  th { color: #79c0ff; background: #161b22; }
  .port { color: #7ee787; font-weight: bold; }
  .warn { color: #f0883e; }
  code { background: #21262d; padding: .2rem .4rem; border-radius: 4px; }
</style>
</head>
<body>
<h1>NOCTIS Recon Report</h1>
<p><b>Generated:</b> {{ timestamp }}</p>

{% if opsec %}
<div class="card">
  <h2>OpSec Score</h2>
  <div class="stat"><b>{{ opsec }}</b>/10</div>
</div>
{% endif %}

{% if passive %}
<h2>Passive Recon - {{ passive.domain }}</h2>
<div class="card">
  <div class="stat">Subdomains <b>{{ passive.subdomains|length }}</b></div>
  <div class="stat">DNS Records <b>{{ passive.dns|length }}</b></div>
</div>

{% if passive.subdomains %}
<h3>Subdomains</h3>
<table>
  <tr><th>#</th><th>Subdomain</th></tr>
  {% for s in passive.subdomains[:200] %}
  <tr><td>{{ loop.index }}</td><td><code>{{ s }}</code></td></tr>
  {% endfor %}
</table>
{% if passive.subdomains|length > 200 %}
<p class="warn">... and {{ passive.subdomains|length - 200 }} more (see full JSON)</p>
{% endif %}
{% endif %}

{% if passive.whois %}
<h3>WHOIS</h3>
<div class="card">
  <p><b>Registrar:</b> {{ passive.whois.registrar }}</p>
  <p><b>Created:</b> {{ passive.whois.creation_date }}</p>
  <p><b>Expires:</b> {{ passive.whois.expiration_date }}</p>
  <p><b>Org:</b> {{ passive.whois.org }}</p>
</div>
{% endif %}
{% endif %}

{% if resolved %}
<h2>Resolved Hosts</h2>
<div class="card">
  <div class="stat">Resolved <b>{{ resolved|length }}</b></div>
</div>
{% endif %}

{% if http_hosts %}
<h2>Live HTTP Hosts</h2>
<table>
  <tr><th>URL</th><th>Status</th><th>Title</th></tr>
  {% for h in http_hosts %}
  <tr>
    <td><code>{{ h.url or h.input }}</code></td>
    <td>{{ h.status_code }}</td>
    <td>{{ h.title or '' }}</td>
  </tr>
  {% endfor %}
</table>
{% endif %}

{% if active %}
<h2>Active Recon - {{ active.target }}</h2>
{% if active.profile %}<p>Profile: <b>{{ active.profile }}</b></p>{% endif %}
{% for host in active.hosts %}
<div class="card">
  <h3>{{ host.ip }}</h3>
  {% if host.hostnames %}<p>Hostnames: {{ host.hostnames|join(', ') }}</p>{% endif %}
  {% if host.ports %}
  <table>
    <tr><th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th></tr>
    {% for p in host.ports %}
    <tr>
      <td class="port">{{ p.port }}</td>
      <td>{{ p.protocol }}</td>
      <td>{{ p.service }}</td>
      <td>{{ p.product }}</td>
      <td>{{ p.version }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="warn">No open ports found</p>
  {% endif %}
</div>
{% endfor %}
{% endif %}

<hr>
<p style="color:#8b949e;text-align:center">NOCTIS v2.1 - Map the terrain. Move once.</p>
</body>
</html>
"""


def render_html(data: dict) -> str:
    return Template(HTML_TEMPLATE).render(**data)


def print_summary(results: dict):
    log("PHASE 5 - Summary", "step")
    CONSOLE.print()

    table = Table(title="NOCTIS RECON REPORT", show_header=False, border_style="magenta")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")

    if results.get("opsec") is not None:
        table.add_row("OpSec Score", f"{results['opsec']}/10")

    if results.get("passive"):
        p = results["passive"]
        table.add_row("Domain", p["domain"])
        table.add_row("Subdomains", str(len(p["subdomains"])))
        table.add_row("DNS Records", str(sum(len(v) for v in p["dns"].values())))
        if p["whois"].get("registrar"):
            table.add_row("Registrar", p["whois"]["registrar"])

    if results.get("resolved"):
        table.add_row("Resolved Hosts", str(len(results["resolved"])))

    if results.get("http_hosts"):
        table.add_row("Live HTTP", str(len(results["http_hosts"])))

    if results.get("active"):
        a = results["active"]
        if a.get("dry_run"):
            table.add_row("Target", a["target"])
            table.add_row("Command", a.get("command", ""))
            table.add_row("Mode", "DRY RUN")
        else:
            total_ports = sum(len(h["ports"]) for h in a.get("hosts", []))
            table.add_row("Target", a["target"])
            table.add_row("Profile", a.get("profile", ""))
            table.add_row("Hosts", str(len(a.get("hosts", []))))
            table.add_row("Open Ports", str(total_ports))

    table.add_row("Output", str(results.get("output_dir", "")))
    CONSOLE.print(table)
    CONSOLE.print()


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    CONSOLE.print(BANNER)

    parser = argparse.ArgumentParser(
        description="NOCTIS v2.1 - Recon pipeline"
    )
    parser.add_argument("-d", "--domain", help="Domain for passive recon")
    parser.add_argument("-t", "--target", help="Target IP/CIDR for active recon")
    parser.add_argument("-c", "--config", default="config.yaml",
                        help="Config file path")
    parser.add_argument("--profile", default="phantom",
                        choices=["phantom", "standard", "full"],
                        help="Nmap profile (default: phantom)")
    parser.add_argument("--fast", action="store_true",
                        help="Alias for --profile standard")
    parser.add_argument("--skip-opsec", action="store_true",
                        help="Skip OpSec check")
    parser.add_argument("--online-opsec", action="store_true",
                        help="Allow external IP lookups (default: offline)")
    parser.add_argument("--no-active", action="store_true",
                        help="Skip active recon")
    parser.add_argument("--no-http", action="store_true",
                        help="Skip HTTP probe")
    parser.add_argument("--ports",
                        help="Override ports (top-100|top-1000|all|custom)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show commands without executing")
    parser.add_argument("-o", "--output", help="Output directory")

    args = parser.parse_args()

    if not args.domain and not args.target:
        parser.print_help()
        print()
        CONSOLE.print("[yellow]Examples:[/yellow]")
        CONSOLE.print("  python3 noctis.py -d example.com")
        CONSOLE.print("  python3 noctis.py -t 192.168.1.1 --profile standard")
        CONSOLE.print("  python3 noctis.py -d example.com -t 10.0.0.0/24")
        sys.exit(0)

    # Resolve effective profile
    profile = args.profile
    if args.fast and profile == "phantom":
        profile = "standard"

    cfg = load_config(Path(args.config))
    if args.ports:
        cfg["active"]["profiles"][profile]["ports"] = args.ports
    if args.output:
        cfg["output"]["dir"] = args.output

    out_dir = Path(os.path.expanduser(cfg["output"]["dir"]))
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "output_dir": str(out_dir),
    }

    # Phase 0
    if not args.skip_opsec and cfg["opsec"]["enabled"]:
        offline = not args.online_opsec
        results["opsec"] = opsec_check(cfg, offline=offline)
    else:
        log("Skipping OpSec check", "warn")

    # Phase 1
    if args.domain:
        results["passive"] = passive_recon(args.domain, cfg)
        save(out_dir / f"{stamp}_{args.domain}_passive.json", results["passive"])

    # Phase 2
    if (args.domain
            and cfg["resolve"]["enabled"]
            and results.get("passive", {}).get("subdomains")):
        subs = results["passive"]["subdomains"]
        results["resolved"] = resolve_subdomains(
            subs, cfg["resolve"]["concurrency"]
        )
        save(out_dir / f"{stamp}_{args.domain}_resolved.json", results["resolved"])

        if (not args.no_http
                and cfg["http"]["enabled"]
                and results["resolved"]):
            results["http_hosts"] = http_probe(
                list(results["resolved"].keys()),
                cfg["http"]["concurrency"],
            )
            save(out_dir / f"{stamp}_{args.domain}_http.json",
                 results["http_hosts"])

    # Phase 3
    if args.target and not args.no_active:
        results["active"] = active_recon(
            args.target, cfg, profile=profile, dry_run=args.dry_run
        )
        save(
            out_dir / f"{stamp}_{args.target.replace('/', '_')}_active.json",
            results["active"],
        )

    # Phase 4
    html = render_html(results)
    html_path = out_dir / f"{stamp}_report.html"
    html_path.write_text(html)
    log(f"HTML report: {html_path}", "ok")

    # Phase 5
    print_summary(results)

    CONSOLE.print("[magenta]  -- NOCTIS --[/magenta]")
    CONSOLE.print("[dim]  Map the terrain. Move once.[/dim]\n")


if __name__ == "__main__":
    main()