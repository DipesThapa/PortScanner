# Port Scanner with Advanced Nmap Features

Modern, Python-driven wrapper around **Nmap** that brings together aggressive scanning, friendly reporting, and an optional kid-proof interactive helper. Run targeted one-offs, batch jobs across many hosts, or simply re-process existing XML reports—everything now lives in a modular `portscanner/` package.

**Key Features**
- **Flexible Targeting:** Scan single hosts, lists, or files of targets with optional concurrency.
- **Configurable Scans:** Tune port ranges, timing templates, NSE script sets, and raw Nmap flags from the CLI or JSON config files.
- **Service Intelligence:** Add banner/title/TLS checks, risk-ranked findings, and curated remediation advice per service with `--intel`.
- **Plugin Ecosystem:** Enable optional plugins for threat intel, automated responders, and deep-dive command staging via `--plugins`.
- **Rich Reporting:** Highlight vulnerable findings with severity/CVE metadata, render human-readable reports, capture deltas vs baselines, or export structured JSON for automation.
- **Per-Target Artifacts:** Save XML and vulnerability summaries per host (via `--output-dir`) or aggregate everything into combined reports.
- **Interactive Wizard:** A guided helper keeps beginners on the rails while still using the same parsing and reporting engine under the hood.
- **Offline Review:** Re-open any saved XML report and regenerate the summaries without re-running Nmap.
- **Asset Awareness:** Attach owners, environments, and tags from an asset catalog so findings carry business context.
- **Historical Baselines:** Persist every run to a baseline store and print quick trends across the most recent scans.
- **Job Scheduler Scaffolding:** Queue multiple scan definitions in a JSON job file and execute them back-to-back with a single flag.
- **Credential-Aware Deep Dives:** Feed per-service credentials so automated follow-up commands embed the right secrets for authenticated checks.
- **Secrets & Orchestration:** Centralize credentials via env/files and inspect distributed worker status before dispatching scans.
- **REST API (optional):** Expose live summary/diff/trend data over HTTP for dashboards or integrations.

## Prerequisites

- **Python 3.x**
- **FastAPI + Uvicorn + SQLModel** if you plan to run the web API: `pip install fastapi uvicorn sqlmodel`
- **Node 18+ / npm** to build and run the React dashboard under `webapp/frontend`
- **Nmap Installed**:  
  - On Debian/Ubuntu: `sudo apt-get install nmap`  
  - On Fedora/CentOS: `sudo yum install nmap`  
  - On macOS (with Homebrew): `brew install nmap`  
- **Git (Optional)** if you want to clone the repository directly.

## Installation

1. **Clone the Repository (Optional):**
   ```bash
   git clone https://github.com/DipesThapa/PortScanner.git
   cd PortScanner
   ```

## Usage

Run the scanner directly with Python (single target):

```bash
python3 port_scanner.py --target example.com --ports 1-1024
```

### Batch Scans & Concurrency

Scan multiple hosts at once (two in parallel), keeping XML/vuln summaries in a dedicated directory and a combined JSON artifact:

```bash
python3 port_scanner.py \
  --targets 192.168.1.10 192.168.1.11 \
  --ports 1-65535 \
  --concurrency 2 \
  --output-dir scans/ \
  --output-json combined.json
```

### Guided Interactive Mode

```bash
python3 port_scanner.py --interactive
```

Launching `python3 port_scanner.py` with no arguments automatically starts the helper. It walks through target selection, port range presets, file saving, and reviewing existing XML reports.

### Service Intelligence Enrichment

Pull extra service insight (banners, titles, certificates) and get remediation hints. Results include risk-ranked findings, observations, and recommended next steps in both CLI reports and the web dashboard:

```bash
python3 port_scanner.py --target web.example.com --intel --intel-scripts banner,http-title,ssl-cert
```

### Plugins & Automation

Run with built-in plugins for threat intelligence, automated responders, and deep-dive command staging:

```bash
python3 port_scanner.py \
  --target 192.168.1.42 \
  --intel \
  --plugins threat-intel auto-responder deep-dive \
  --plugin-config plugin-options.json
```

Example `plugin-options.json`:

```json
{
  "auto-responder": {
    "min_severity": "critical",
    "forbidden_ports": ["23", "3389"]
  },
  "deep-dive": {
    "commands": {
      "http": ["nuclei -target {target}:{port}"]
    }
  }
}
```

### Working From Saved XML

```bash
python3 port_scanner.py --xml-file scan.xml --save-report recap.txt --save-vulns recap.json
```

### Differential Reports

Compare a fresh scan against a stored baseline and emit a delta report:

```bash
python3 port_scanner.py \
  --targets 192.168.1.10 192.168.1.11 \
  --baseline-json baselines/latest.json \
  --diff-report diffs/2024-04-18.json \
  --output-json reports/2024-04-18.json
```

### Credential Store

Provide per-service credentials (used by plugins and deep-dive command templates):

```json
{
  "ssh": {"username": "audit", "password": "Sup3rSecret"},
  "snmp": {"community": "private"}
}
```

Run with:

```bash
python3 port_scanner.py --target core-switch.local --credential-file creds.json --plugins deep-dive
```

### Configuration Files

Provide defaults in JSON (values still overridable via CLI flags):

```json
{
  "targets": ["192.168.1.10", "192.168.1.11"],
  "ports": "1-2000",
  "concurrency": 3,
  "scripts": ["vuln", "auth"],
  "intel": true,
  "intel_scripts": ["banner", "http-title"],
  "timing_template": 4,
  "output_dir": "scans/",
  "output_json": "latest.json",
  "asset_file": "assets.json",
  "baseline_json": "reports/latest.json",
  "baseline_store": "baseline-history/",
  "credential_file": "creds.json",
  "plugins": ["threat-intel", "auto-responder"],
  "plugin_options": {
    "auto-responder": {"min_severity": "high"}
  }
}
```

Run with:

```bash
python3 port_scanner.py --config scan-config.json
```

### Asset Catalogs

Build a JSON catalog so scan output carries ownership context:

```json
{
  "assets": [
    {
      "name": "Prod Web Tier",
      "target": "web.example.com",
      "addresses": ["192.168.1.10"],
      "owner": "Platform Team",
      "environment": "production",
      "criticality": "high",
      "tags": ["web", "frontend"]
    }
  ]
}
```

Use it on any run:

```bash
python3 port_scanner.py --target web.example.com --intel --asset-file assets.json
```

### Highlights & Output Options

- `--save-xml PATH`: Raw XML (for multiple hosts, use a directory).
- `--save-vulns PATH`: Aggregated vulnerability findings (JSON).
- `--save-report PATH`: Combined human-readable text report.
- `--output-json PATH`: Structured summary with targets, findings, and settings.
- `--output-dir DIR`: Per-target `*.xml` and `*.vulns.json` outputs.
- `--intel`: Turn on service intelligence (add banner/title/TLS scripts and hints).
- `--baseline-json PATH`: Compare results with a stored JSON baseline.
- `--diff-report PATH`: Write the new-vs-old delta to JSON.
- `--asset-file PATH`: Attach ownership/metadata from an asset catalog.
- `--baseline-store DIR`: Persist run results and print most recent trends.
- `--plugins ...`: Enable built-in or custom plugins; combine with `--plugin-config` for options.
- `--credential-file PATH`: Provide per-service credentials to plugins and deep-dive commands.
- `--secret-file PATH`: Resolve `secret://` placeholders in credential files; combine with `--secret-prefix` for env lookups.
- `--job-file PATH`: Execute multiple queued scans described in a JSON job list.
- `--orchestrator-config PATH`: List worker nodes and verify their reachability before dispatching heavy jobs.
- `--api-listen HOST:PORT`: Start a simple read-only API exposing the latest summary/diff/trend.
- `--exporters ...`: Emit run data via stdout/jsonl (or custom exporters) using `--exporter-config`.

Check `python3 port_scanner.py --help` for the full option list.

### Scheduler Job File Example

```json
{
  "jobs": [
    {
      "name": "Internal quick sweep",
      "args": [
        "--targets", "192.168.1.10", "192.168.1.11",
        "--ports", "1-1024",
        "--intel",
        "--plugins", "threat-intel"
      ]
    },
    {
      "name": "External baseline",
      "args": [
        "--target", "vpn.example.com",
        "--ports", "1-2000",
        "--baseline-store", "baseline-history/"
      ]
    }
  ]
}
```

Run the whole queue with:

```bash
python3 port_scanner.py --job-file jobs.json
```

### Distributed Worker Inventory

Check remote worker reachability before dispatching heavy jobs:

```json
{
  "workers": [
    {"name": "east", "address": "10.10.0.10:22", "capabilities": {"bandwidth": "high"}},
    {"name": "west", "address": "10.20.0.10:22"}
  ]
}
```

```bash
python3 port_scanner.py --orchestrator-config workers.json --target 10.0.0.5
```

### REST API Endpoint

Serve the latest summary/diff/trend data for dashboards:

```bash
python3 port_scanner.py --target 10.0.0.5 --baseline-store baseline-history --api-listen 0.0.0.0:8080
```

Endpoints:

- `GET /health` – simple status check.
- `GET /summary` – most recent summary payload.
- `GET /diff` – new vs resolved findings when a baseline is available.
- `GET /trend` – text version of the baseline trend.

### Web API & UI Scaffolding

Run everything as a FastAPI service (auto-starts background scans using the same engine):

```bash
uvicorn webapp.main:app --reload
```

Endpoints include:

- `POST /scans` – submit a scan job (JSON body accepts the same options as the CLI).
- `GET /scans` – list jobs with status, summaries, plugin output.
- `GET /scans/{id}` – inspect a specific job, logs, diff, artifacts.
- `GET /scans/{id}/artifacts/{path}` – download generated reports/XML/JSON files.

Combine with `--plugins`, `--exporters`, `--baseline-store`, `--orchestrator-config`, and credential/secret files for full parity with the CLI experience.

#### Frontend Dev Server

The `webapp/frontend` directory contains a Vite + React UI that consumes the REST API:

```bash
# (from repo root)
cd webapp/frontend
npm install
npm run dev
```

The dev server proxies API calls to `http://127.0.0.1:8000` (configure in `vite.config.js`). Visit http://127.0.0.1:5173 to see the dashboard, trigger new scans, and drill into job results. Build artifacts with `npm run build`.
### Exporters

Dump combined run data via built-in exporters (stdout/jsonl) or add your own:

```bash
python3 port_scanner.py \
  --targets 10.0.0.5 10.0.0.6 \
  --exporters stdout jsonl \
  --exporter-config exporter-options.json
```

`exporter-options.json` example:

```json
{
  "jsonl": {"path": "exports/latest.jsonl"}
}
```
