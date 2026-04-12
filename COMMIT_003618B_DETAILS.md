# Detailed Notes for Commit 003618b

This document expands the implementation details for commit `003618b` without changing git history.

## Scope Summary

Commit `003618b` introduced a production-ready workflow around the correlation engine:

- Live web dashboard with real-time analysis trigger
- Telegram alert integration via `.env`
- Transparent scoring details (`score_details`) per asset
- Multi-source analysis modes (`auto`, `1`, `2`, `3`, `4`)
- Actionable analysis insights and AI-style remediation hints

## Feature Breakdown

## 1) Live Dashboard

Primary module: `mscp/dashboard.py`

Capabilities:

- Runs local web server for operations view
- Accepts paths for Nmap/Nikto/OpenVAS/Wireshark from UI
- Supports mode switching from UI (`auto`, `1`, `2`, `3`, `4`)
- Supports report JSON download endpoint (`/report.json`)
- Has explicit action buttons:
  - `Analyze`
  - `Send Telegram Alert`

Runtime command example:

```powershell
py -3 -m mscp.cli dashboard \
  --report .\out\report-live-any.json \
  --dotenv .\.env \
  --host 127.0.0.1 \
  --port 8787
```

## 2) Telegram via .env

Modules:

- `mscp/env_config.py` (dotenv parsing)
- `mscp/cli.py` (credential resolution and alert dispatch)
- `mscp/alerts/telegram.py` (Telegram API call)

Resolution order:

1. CLI args (`--telegram-bot-token`, `--telegram-chat-id`)
2. `.env` values (`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`)

## 3) Transparent Weights / Scoring

Modules:

- `mscp/engine/risk.py`
- `mscp/models.py`

Output now includes:

- `score`: total risk score
- `score_details`: per-evidence score contribution

Example:

```json
{
  "score": 19,
  "score_details": {
    "open_port": 1,
    "web_vuln": 3,
    "cve": 5,
    "exploit": 10
  }
}
```

## 4) Analysis Modes (1/2/3/4 + auto)

Module: `mscp/cli.py`

Mode behavior:

- `auto`: use all provided sources
- `1`/`2`/`3`/`4`: use first N provided sources by priority:
  - `nmap -> nikto -> openvas -> wireshark`

## 5) Actionable Insights Layer

Module: `mscp/analysis.py`

Adds report-level section:

- `risk_counts`
- `top_assets`
- `top_traffic`
- `exposed_with_traffic`
- `public_hosts`
- `recommendations`

## 6) AI-style Suggestions

Module: `mscp/advisor.py`

Per-asset `ai_suggestions` are generated from deterministic security heuristics.

## Test Coverage Added/Updated

- `tests/test_advisor.py`
- `tests/test_analysis.py`
- `tests/test_env_config.py`
- plus updates in parser/engine/cli tests

Expected run:

```powershell
D:/Python312/python.exe -m unittest discover -s tests -p "test_*.py" -v
```

## Operational Notes

- Keep `.env` out of git.
- Keep runtime output files under `out/` out of commits.
- Keep real scan data under `Save/data_test/` out of commits unless intentionally versioned.

## Why a separate details document?

To keep commit `003618b` unchanged (as requested), while still providing detailed traceability for reviewers and future maintenance.
