<!-- © VampSecure Studios — VampSecure Labs Security Research Division -->

  <img src="https://github.com/Vampsecure-Labs/vamp-easm/actions/workflows/ci.yml/badge.svg" alt="CI"/>
# vamp-easm

**Continuous External Attack Surface Management with daily diff tracking**

Part of the [VampSecure Labs](https://github.com/Vampsecure-Labs) security toolkit.

---

## Overview

`vamp-easm` is a lightweight EASM engine designed to run continuously (via cron or CI/CD) against one or more external domains. Unlike point-in-time scanners, its core value is **delta detection**: each run is compared against the previous snapshot stored in a local SQLite database, surfacing only what changed.

### Key Features

- **Subdomain enumeration** — queries crt.sh (Certificate Transparency) and HackerTarget via standard urllib (no external dependencies for this layer)
- **Port scanning** — async TCP connect scan over the top-100 most common ports using `asyncio` + stdlib `socket`; optional `nmap` backend for accuracy
- **TLS certificate inspection** — hostname, issuer, expiration date, SANs, self-signed detection and SHA-256 fingerprint via stdlib `ssl`
- **SQLite history** — every scan is stored; diffs are computed against the last completed scan for the same target
- **Structured findings** — diffs are normalized as VSL findings (prefix `EASM-NNN`) compatible with `vamp-penreport`
- **Webhook alerts** — POSTs a JSON payload (Slack/Discord/Mattermost compatible) when CRITICAL or HIGH diffs are found
- **Exit codes** — machine-friendly: `0` clean, `1` HIGH diffs, `2` CRITICAL diffs (CI/CD and monitoring ready)
- **Shodan enrichment** — queries Shodan by IP to surface sensitive ports, CVEs and alternative hostnames (`--shodan-key`)
- **Censys enrichment** — discovers shadow hosts not found by crt.sh/HackerTarget using Censys API v2 (`--censys-id` / `--censys-secret`)
- **Shodan Monitor integration** — creates persistent Monitor alerts that detect new open ports and CVEs automatically; `monitor` subcommand for full lifecycle management (v1.5)

---

## Diff Types and Severities

| Category | Severity | Description |
|---|---|---|
| `NUEVO_SUBDOMINIO` | HIGH | A subdomain not seen in the previous scan has appeared |
| `NUEVO_PUERTO` | MEDIUM | A TCP port is open that was closed in the previous scan |
| `CERT_EXPIRADO` | HIGH / CRITICAL | TLS certificate expires within 30 days (HIGH) or is already expired (CRITICAL) |
| `CERT_CAMBIADO` | CRITICAL | TLS fingerprint changed since the last scan — possible re-issue or MitM |
| `SERVICIO_DESAPARECIDO` | LOW | A previously open port is no longer reachable |
| `IP_CAMBIADA` | MEDIUM | DNS resolution for a known subdomain returned a different IP |

---

## Installation


```bash
pip install vamp-easm
# o con Homebrew:
brew install vampsecure-labs/labs/vamp-easm
```

```bash
# 1. Clone and enter the directory
git clone https://github.com/Vampsecure-Labs/vamp-easm.git
cd vamp-easm

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **Optional:** install `nmap` on your system and use `--nmap` for more reliable port scanning.

---

## Usage

### Scan a target

```bash
# Default: top-100 ports, stdlib async scanner
python vamp_easm.py scan --target example.com

# Custom port list
python vamp_easm.py scan --target example.com --ports 22,80,443,8080,8443

# Use nmap as port-scan backend (requires nmap in PATH)
python vamp_easm.py scan --target example.com --nmap

# Export findings as HTML and JSON reports
python vamp_easm.py scan --target example.com --html --json

# Send alerts to a webhook on CRITICAL/HIGH diffs
python vamp_easm.py scan --target example.com --alert-webhook https://hooks.slack.com/...

# Full example
python vamp_easm.py scan \
  --target example.com \
  --ports top100 \
  --html \
  --alert-webhook "$SLACK_WEBHOOK" \
  --client "AcmeCorp" \
  --engagement "Q3-2026-EASM"
```

### View scan history

```bash
python vamp_easm.py history --target example.com
python vamp_easm.py history --target example.com --limit 20
```

### List known assets

```bash
python vamp_easm.py assets --target example.com
```

### Export a snapshot

```bash
# Export last scan as both JSON and HTML
python vamp_easm.py export --target example.com

# JSON only
python vamp_easm.py export --target example.com --json
```

---

## Cron Example

Run a daily EASM scan with Slack alerts and log output:

```bash
0 6 * * * cd /opt/vamp-easm && .venv/bin/python vamp_easm.py scan --target midominio.com --alert-webhook $SLACK_URL >> /var/log/vamp-easm.log 2>&1
```

For CI/CD, use the exit code to gate pipelines:

```bash
python vamp_easm.py scan --target example.com
EXIT=$?
if [ $EXIT -eq 2 ]; then
  echo "CRITICAL diffs detected — blocking pipeline"
  exit 1
elif [ $EXIT -eq 1 ]; then
  echo "HIGH diffs detected — review required"
fi
```

---

### Shodan Monitor (v1.5)

```bash
# Step 1: run a scan first to populate IPs
python vamp_easm.py scan --target example.com

# Step 2: create a Shodan Monitor alert for those IPs
python vamp_easm.py monitor --target example.com --shodan-key $SHODAN_KEY --setup

# Step 3: check for new findings (new ports / CVEs since last check)
python vamp_easm.py monitor --target example.com --shodan-key $SHODAN_KEY --check

# Integrate Monitor check into every scan run
python vamp_easm.py scan --target example.com --shodan-key $SHODAN_KEY --shodan-monitor

# Manage alerts
python vamp_easm.py monitor --shodan-key $SHODAN_KEY --list
python vamp_easm.py monitor --target example.com --shodan-key $SHODAN_KEY --remove
```

State is persisted in `~/.config/vampsec/easm_shodan_monitor.json`. Each `--check` diffs against the previous run and emits `EASM-MON-NNN` findings.

| Event | Severity |
|---|---|
| New sensitive port (21/23/3389/6379…) | HIGH |
| New non-sensitive port | MEDIUM |
| 3+ new CVEs on a single IP | CRITICAL |
| 1–2 new CVEs | HIGH |
| IP with no active matches | INFO |

---

## Environment Variables

| Variable | Description |
|---|---|
| `EASM_ALERT_WEBHOOK` | Webhook URL for alerts (alternative to `--alert-webhook`) |
| `SHODAN_API_KEY` | Shodan API key (alternative to `--shodan-key`) |
| `CENSYS_API_ID` | Censys API ID (alternative to `--censys-id`) |
| `CENSYS_API_SECRET` | Censys API secret (alternative to `--censys-secret`) |

---

## Database

The SQLite database `vamp_easm.db` is created automatically in the working directory. It contains three tables:

- **`scans`** — one row per scan run (UUID, target, timestamps, asset/diff counts)
- **`assets`** — discovered hosts, subdomains, open ports and services with first/last-seen timestamps
- **`certs`** — TLS certificate snapshots (issuer, expiration, SANs, SHA-256 fingerprint)

The database file is excluded from version control (`.gitignore`). Back it up if you want to preserve historical data.

---

## Integration with vamp-penreport

`vamp-easm` exports findings in the VSL standard format used across all VampSecure Labs tools. To include EASM findings in a pentest report:

```bash
# 1. Generate JSON snapshot from the last scan
python vamp_easm.py export --target example.com --json

# 2. Merge with vamp-penreport (pass the JSON as an additional findings source)
python ../vamp-penreport/vamp_penreport.py \
  --findings easm_export_example.com_*.json \
  --client "AcmeCorp" \
  --engagement "Pentest-2026-Q3" \
  --html report_acmecorp.html
```

The `EASM-NNN` finding IDs are stable within a single scan run and can be referenced in report narratives.

---

## Dependencies

| Package | Purpose |
|---|---|
| `aiohttp>=3.9.0` | Async HTTP client for subdomain source queries |
| `rich>=13.7.0` | Terminal output tables and panels |
| stdlib only | Port scanning, TLS inspection, DNS queries, alerts |

---

## License

AGPL-3.0 License — see [LICENSE](LICENSE) for details.

© VampSecure Studios — VampSecure Labs Security Research Division  
For authorized penetration testing use only.

---

## Sample Output

```
$ python vamp_easm.py scan --target example.com --html

 vamp-easm v1.6 — VampSecure Labs
 Target: example.com  |  Previous scan: 2026-10-01 06:14 UTC  |  Δ diff mode ON

 [Phase 1] Subdomain enumeration
  crt.sh       →  14 results
  HackerTarget →  11 results
  Union        →  16 unique subdomains

 [Phase 2] TCP scan  (top-100 ports, async)
  Scanning 16 hosts ... done in 4.2 s

 [Phase 3] TLS inspection
  16 certificates analysed

 [Phase 4] GreyNoise enrichment
  IPs queried: 9  |  Malicious: 1 (192.168.45.12 — see EASM-005)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ DIFFS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  EASM-001  HIGH      NUEVO_SUBDOMINIO  dev-internal.example.com → 192.168.20.14
  EASM-002  MEDIUM    NUEVO_PUERTO      api.example.com:8080 opened (was closed)
  EASM-003  HIGH      CERT_EXPIRADO     mail.example.com — expires in 11 days
  EASM-004  CRITICAL  CERT_CAMBIADO     www.example.com — fingerprint changed
                                        prev: sha256:3b2e...  now: sha256:f9a1...
  EASM-005  HIGH      IP_GREYNOISE      192.168.45.12 classified malicious by GreyNoise
  EASM-006  MEDIUM    IP_CAMBIADA       cdn.example.com  10.0.2.5 → 10.0.18.91
  EASM-007  LOW       SERVICIO_DESAP.   ftp.example.com:21 no longer reachable

 Summary: 1 CRITICAL · 3 HIGH · 2 MEDIUM · 1 LOW
 HTML report: easm_example.com_20261008.html
 Exit code: 2
```

## Why vamp-easm vs. Netlas · Censys · Shodan Monitor nativo

| Capability | vamp-easm | Netlas | Censys | Shodan Monitor |
|---|---|---|---|---|
| Self-hosted — no data sent to third parties | ✅ | ❌ cloud | ❌ cloud | ❌ cloud |
| Delta diff against your own historical baseline | ✅ SQLite | ❌ | ❌ | ⚠️ alert only |
| crt.sh + HackerTarget enumeration (free) | ✅ | ❌ API credit | ⚠️ paid tier | ❌ |
| GreyNoise reputation enrichment (free tier) | ✅ | ❌ | ❌ | ❌ |
| Shodan Monitor integration (persistent alerts) | ✅ | ❌ | ❌ | ✅ |
| VSL findings format (EASM-NNN) for penreport | ✅ | ❌ | ❌ | ❌ |
| CI/CD machine-readable exit codes | ✅ | ❌ | ❌ | ❌ |
| Webhook alerts (Slack/Discord/Mattermost) | ✅ | ⚠️ email only | ⚠️ email only | ⚠️ email only |

- **Zero external data residency**: all scan results stay in a local SQLite file — no domain, IP, or certificate data leaves your perimeter.
- **Continuous delta tracking**: knowing that `dev-internal.example.com` appeared *this week* is more actionable than a full asset inventory; the diff engine surfaces only what changed since the last run.
- **Multi-source corroboration**: crt.sh catches newly issued certificates; HackerTarget catches DNS records; Censys catches shadow infrastructure not yet in CT logs — combining all three reduces blind spots.
- **GreyNoise reputation at zero cost**: the free-tier `/v3/context/{ip}` call flags IPs already associated with malicious activity without requiring a paid API key.

## Check Coverage

| Check ID | Description | Standard | Severity |
|---|---|---|---|
| EASM-001 | New subdomain not seen in previous scan | CIS Control 1 (Asset Inventory) | HIGH |
| EASM-002 | New TCP port open since last scan | NIST CSF Identify (ID.AM-1) | MEDIUM |
| EASM-003 | TLS certificate expiring within 30 days | CIS Control 9.4 | HIGH |
| EASM-004 | TLS certificate already expired | CIS Control 9.4 | CRITICAL |
| EASM-005 | TLS certificate fingerprint changed — possible re-issue or MitM | NIST CSF PR.DS-2 | CRITICAL |
| EASM-006 | DNS resolution for known subdomain returned different IP | NIST CSF ID.AM-1 | MEDIUM |
| EASM-007 | Previously open port is no longer reachable | NIST CSF ID.AM-1 | LOW |
| EASM-008 | IP flagged as malicious by GreyNoise free API | NIST CSF DE.CM-1 | HIGH |
| EASM-009 | TLS certificate is self-signed (no trusted CA chain) | CIS Control 9.4 | HIGH |
| EASM-010 | Sensitive port newly opened (21/23/3389/5900/6379) | CIS Control 4 | HIGH |
| EASM-MON-001 | Shodan Monitor — 1–2 new CVEs detected on monitored IP | NIST CSF ID.RA-1 | HIGH |
| EASM-MON-002 | Shodan Monitor — 3 or more new CVEs on single IP | NIST CSF ID.RA-1 | CRITICAL |

## Historial de versiones

| Versión | Cambios principales |
|---------|---------------------|
| v1.6 | Enriquecimiento GreyNoise free API (`/v3/context/{ip}`) — activo por defecto, sin clave; `--no-greynoise` para desactivar; hallazgos HIGH para IPs maliciosas conocidas |
| v1.5 | Shodan Monitor integration — alertas persistentes con `monitor` subcommand |
| v1.4 | Enriquecimiento Censys v2 (`--censys-id` / `--censys-secret`) |
