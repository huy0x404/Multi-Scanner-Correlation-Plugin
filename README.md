# Multi-Scanner Correlation Plugin

A practical plugin-style security analytics project that extends scanner outputs from:

- Nmap
- Nikto
- OpenVAS
- Wireshark (tshark JSON export)

This project does not replace scanners. It ingests their outputs, correlates findings, computes risk, detects changes between scans, and sends smart alerts.

## What You Get

- Unified asset/finding model across tools
- Correlation engine (port + service + vuln + CVE)
- Deterministic risk scoring (no AI)
- Diff mode to compare two scan snapshots
- Smart alerting for high risk findings
- Scheduler mode that only alerts when results changed
- Telegram integration
- AI-style remediation suggestions per asset
- Local web dashboard for operations view

## Supported Input Formats

- Nmap: XML
- Nikto: JSON, TXT
- OpenVAS: JSON, XML
- Wireshark/tshark: JSON, PCAP, PCAPNG (via tshark)

## Install

```powershell
py -3 -m pip install -r requirements.txt
```

Create `.env` for Telegram (optional but recommended):

```env
TELEGRAM_BOT_TOKEN=123456:ABCDEF...
TELEGRAM_CHAT_ID=123456789
```

You can also copy from `.env.example`:

```powershell
Copy-Item .env.example .env
```

Then update values in `.env`.

## Quick Start

Run interactive mode:

```powershell
py -3 -m mscp.cli
```

Generate a report:

```powershell
py -3 -m mscp.cli report \
  --nmap .\sample_data\nmap.xml \
  --nikto .\sample_data\nikto.txt \
  --openvas .\sample_data\openvas.xml \
  --wireshark .\sample_data\wireshark.json \
  --risk-config .\config\risk_weights.json \
  --out .\out\report.json
```

Analysis modes (for practical workflows):

- `--analysis-mode auto`: use all provided sources
- `--analysis-mode 1`: analyze first 1 source (priority: nmap -> nikto -> openvas -> wireshark)
- `--analysis-mode 2`: analyze first 2 sources
- `--analysis-mode 3`: analyze first 3 sources
- `--analysis-mode 4`: analyze all 4 sources

Examples:

```powershell
py -3 -m mscp.cli report --nmap .\data\nmap.xml --analysis-mode 1 --out .\out\report-nmap-only.json
py -3 -m mscp.cli report --nmap .\data\nmap.xml --wireshark .\data\wireshark.json --analysis-mode 2 --out .\out\report-dual.json
```

Run directly from Wireshark capture file:

```powershell
py -3 -m mscp.cli report \
  --nmap .\data\nmap.xml \
  --nikto .\data\nikto.txt \
  --openvas .\data\openvas.xml \
  --wireshark .\data\capture.pcapng \
  --risk-config .\config\risk_weights.yaml \
  --out .\out\report.json
```

Compare with baseline:

```powershell
py -3 -m mscp.cli report \
  --nmap .\sample_data\nmap.xml \
  --nikto .\sample_data\nikto.txt \
  --openvas .\sample_data\openvas.xml \
  --wireshark .\sample_data\wireshark.json \
  --baseline .\out\report.json \
  --out .\out\report-with-diff.json
```

Enable Telegram alert:

```powershell
py -3 -m mscp.cli report \
  --nmap .\sample_data\nmap.xml \
  --nikto .\sample_data\nikto.txt \
  --openvas .\sample_data\openvas.xml \
  --telegram-bot-token <token> \
  --telegram-chat-id <chat_id> \
  --alert-min-risk HIGH
```

`--alert-min-risk` accepts: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

## Web Dashboard

Start dashboard from latest report:

```powershell
py -3 -m mscp.cli dashboard --report .\out\report.json --host 127.0.0.1 --port 8787
```

Use `--no-browser` if running on server/SSH terminal.
If the selected port is busy, dashboard automatically tries next ports.

Live dashboard with source files (switch mode 1/2/3/4 directly on web):

```powershell
py -3 -m mscp.cli dashboard \
  --report .\out\report-live.json \
  --nmap .\Save\data_test\192_168.1.5_1st.xml \
  --wireshark .\Save\data_test\wireshark_json_1.json \
  --risk-config .\config\risk_weights.json \
  --dotenv .\.env \
  --analysis-mode 2 \
  --host 127.0.0.1 --port 8787
```

Then open `http://127.0.0.1:8787` and change Analysis Mode on the page.

On dashboard page:

- You can input any source file paths (any folder) for nmap/nikto/openvas/wireshark.
- Click `Analyze` to re-run analysis.
- Click `Send Telegram Alert` to send alert using `.env` credentials.
- Use mode selector `auto/1/2/3/4` directly in the web UI.

Important:

- Dashboard is not forced to one folder. You can analyze files from any absolute path.
- Dashboard is not forced to all scanners. You can run with 1 source, 2 sources, or 4 sources.

## Scheduler (Only Alert On New Changes)

```powershell
py -3 -m mscp.cli schedule \
  --nmap .\data\nmap.xml \
  --nikto .\data\nikto.txt \
  --openvas .\data\openvas.xml \
  --wireshark .\data\wireshark.json \
  --risk-config .\config\risk_weights.yaml \
  --telegram-bot-token <token> \
  --telegram-chat-id <chat_id> \
  --alert-min-risk HIGH \
  --interval 300 \
  --state-file .\out\last-schedule-report.json
```

Behavior:

- Run every `interval` seconds
- Compare against last report stored in `state-file`
- Send alert only when scan results changed and risk level meets threshold

For one cycle test:

```powershell
py -3 -m mscp.cli schedule \
  --nmap .\sample_data\nmap.xml \
  --nikto .\sample_data\nikto.txt \
  --openvas .\sample_data\openvas.xml \
  --wireshark .\sample_data\wireshark.json \
  --once
```

## Risk Weight Config

Example JSON config in `config/risk_weights.json`:

```json
{
  "weights": {
    "open_port": 1,
    "web_vuln": 3,
    "cve": 5,
    "exploit": 10,
    "traffic_signal": 2
  }
}
```

Example YAML config in `config/risk_weights.yaml`:

```yaml
weights:
  open_port: 1
  web_vuln: 3
  cve: 5
  exploit: 10
  traffic_signal: 2
```

## Real Data Collection (Run Actual Tools)

Nmap XML:

```powershell
nmap -sV -oX .\data\nmap.xml <target>
```

Nikto TXT:

```powershell
nikto -h <target> -output .\data\nikto.txt
```

OpenVAS XML:

- Export report as XML from OpenVAS/GVM UI and save to `.\data\openvas.xml`

Wireshark/tshark JSON (example):

```powershell
tshark -r .\capture.pcapng -T json > .\data\wireshark.json
```

If you pass `.pcap` or `.pcapng` directly to `--wireshark`, the plugin will call `tshark` automatically. Ensure `tshark` is installed and available in PATH.

## Output Shape

```json
{
  "generated_at": "2026-04-10T11:22:33Z",
  "assets": [
    {
      "host": "192.168.1.10",
      "port": 80,
      "service": "http",
      "findings": ["Nikto: XSS /admin"],
      "cves": ["CVE-2021-41773"],
      "evidence": ["open_port", "web_vuln", "cve"],
      "score": 19,
      "score_details": {"open_port": 1, "web_vuln": 3, "cve": 5, "exploit": 10},
      "risk": "HIGH",
      "reason": "Web service exposed with vulnerability and CVE",
      "ai_suggestions": ["Server nay co the bi SQL Injection..."]
    }
  ]
}
```

## Notes

- Parsing logic is conservative and format-tolerant.
- Adapt parser mappings to your scanner export format if needed.
- Add more scanner plugins by implementing `ScannerPlugin` in `mscp/plugins.py`.
- Detailed implementation notes for the latest major feature set: `COMMIT_003618B_DETAILS.md`.
