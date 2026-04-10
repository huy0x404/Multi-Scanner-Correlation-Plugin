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

## Supported Input Formats

- Nmap: XML
- Nikto: JSON, TXT
- OpenVAS: JSON, XML
- Wireshark/tshark: JSON

## Install

```powershell
py -3 -m pip install -r requirements.txt
```

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
      "risk": "HIGH",
      "reason": "Web service exposed with vulnerability and CVE"
    }
  ]
}
```

## Notes

- Parsing logic is conservative and format-tolerant.
- Adapt parser mappings to your scanner export format if needed.
- Add more scanner plugins by implementing `ScannerPlugin` in `mscp/plugins.py`.
