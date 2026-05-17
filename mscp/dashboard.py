from __future__ import annotations

import html
import json
import smtplib
import webbrowser
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import cgi
import tempfile
from pathlib import Path
from typing import Any, Callable
from mscp.analysis_modules import analyze_path_by_type, validate_input_for_type
from mscp.analysis import build_analysis_insights
from mscp.engine.risk import resolve_weights_for_mode, score_assets, normalize_assets_to_100
from mscp.advisor import enrich_assets_with_ai
from mscp.ai_integration import analyze_asset_with_ai
from mscp.alerts.telegram import send_telegram_alert
from urllib.parse import parse_qs, urlparse

from mscp.modes import RISK_MODE_META


HTML_TEMPLATE = """<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <title>MSCP Dashboard</title>
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
    <link rel=\"preconnect\" href=\"https://fonts.googleapis.com\" />
    <link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin />
    <link href=\"https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=IBM+Plex+Mono:wght@400;500&display=swap\" rel=\"stylesheet\" />
  <style>
        :root {
            --bg-top:#061423;
            --bg-mid:#0e2138;
            --bg-bottom:#111319;
            --card:#111a29cc;
            --card-border:#ffffff22;
            --fg:#eff6ff;
            --muted:#a6bad8;
            --accent:#4cc9f0;
            --accent-2:#2a9d8f;
            --critical:#ff4d6d;
            --high:#ff9f1c;
            --medium:#ffd166;
            --low:#2ec4b6;
            --mono:'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
            --sans:'Space Grotesk', 'Segoe UI', system-ui, sans-serif;
        }
        * { box-sizing:border-box; }
        body {
            margin:0;
            font-family:var(--sans);
            background:
                radial-gradient(1200px 700px at -10% -20%, #2a9d8f33, transparent 60%),
                radial-gradient(1000px 700px at 110% -30%, #4cc9f044, transparent 60%),
                linear-gradient(150deg, var(--bg-top), var(--bg-mid) 48%, var(--bg-bottom));
            color:var(--fg);
            min-height:100vh;
        }
        .wrap { max-width:1300px; margin:0 auto; padding:28px 20px 40px; }
        h1 { margin:0 0 14px; letter-spacing:.3px; font-size:30px; }
        .grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; }
        .card {
            background:var(--card);
            border-radius:14px;
            padding:14px;
            border:1px solid var(--card-border);
            backdrop-filter: blur(8px);
            box-shadow: 0 8px 30px #0000001f;
        }
        .k { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.8px; font-weight:600; }
        .v { font-size:28px; font-weight:700; margin-top:6px; }
        .toolbar-grid { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:10px; margin-top:10px; }
        .toolbar-row { margin-top:10px; display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
        input, select, button {
            background:#0d1725;
            color:var(--fg);
            border:1px solid #ffffff2b;
            border-radius:10px;
            padding:10px 12px;
            font-family:var(--sans);
            font-size:13px;
        }
        input::placeholder { color:#9eb2ce; }
        button {
            cursor:pointer;
            border-color:#4cc9f066;
            background:linear-gradient(120deg,#153a4f,#1b5960);
            font-weight:600;
            transition:transform .15s ease, box-shadow .15s ease;
        }
        button:hover { transform:translateY(-1px); box-shadow:0 8px 18px #00000033; }
        .secondary-btn { background:linear-gradient(120deg,#46381a,#664a1f); border-color:#ffb70366; }
        table {
            width:100%;
            border-collapse:collapse;
            margin-top:14px;
            background:var(--card);
            border-radius:14px;
            overflow:hidden;
            border:1px solid var(--card-border);
        }
        th, td { padding:11px 10px; border-bottom:1px solid #ffffff17; text-align:left; vertical-align:top; font-size:13px; }
        th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.7px; }
        tr:hover td { background:#ffffff08; }
        .risk-badge { border-radius:999px; padding:3px 8px; font-size:11px; font-weight:700; display:inline-block; }
        .risk-CRITICAL { color:#ffd9df; background:#ff4d6d3a; border:1px solid #ff4d6d85; }
        .risk-HIGH { color:#fff0d8; background:#ff9f1c33; border:1px solid #ff9f1c80; }
        .risk-MEDIUM { color:#fff7dd; background:#ffd1662e; border:1px solid #ffd16675; }
        .risk-LOW { color:#dbfff9; background:#2ec4b638; border:1px solid #2ec4b675; }
        .hint { color:#c7d9f3; font-size:13px; max-width:360px; }
        .mono { font-family:var(--mono); font-size:12px; color:#d2e4ff; }
        .foot { color:var(--muted); margin-top:12px; font-size:12px; }
        .banner-ok { border-color:#06d6a06e; color:#d2ffe8; }
        .banner-err { border-color:#ef476f8a; color:#ffd6df; }
        a { color:#9fd8ff; }
        ul { margin:8px 0 0; padding-left:20px; }
        @media (max-width:1024px) {
            .grid { grid-template-columns:repeat(2,minmax(0,1fr)); }
            .toolbar-grid { grid-template-columns:1fr; }
        }
        @media (max-width:640px) {
            .grid { grid-template-columns:1fr; }
            .wrap { padding:16px 12px 24px; }
            h1 { font-size:24px; }
        }
  </style>
</head>
<body>
    <div class=\"wrap\">__CONTENT__</div>
</body>
</html>
"""


def _load_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"generated_at": "n/a", "assets": []}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _q(values: dict[str, str], key: str, default: str = "") -> str:
    return str(values.get(key, default))


def _send_email_alert(settings: dict[str, Any], subject: str, body: str) -> str:
    host = str(settings.get("smtp_host", "")).strip()
    port = int(settings.get("smtp_port", 587) or 587)
    user = str(settings.get("smtp_user", "")).strip()
    password = str(settings.get("smtp_pass", "")).strip()
    sender = str(settings.get("email_from", "")).strip()
    recipients_raw = str(settings.get("email_to", "")).strip()
    use_tls = bool(settings.get("smtp_use_tls", True))

    recipients = [x.strip() for x in recipients_raw.split(",") if x.strip()]
    if not (host and sender and recipients):
        raise RuntimeError("Email settings incomplete")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    with smtplib.SMTP(host, port, timeout=12) as smtp:
        if use_tls:
            smtp.starttls()
        if user:
            smtp.login(user, password)
        smtp.send_message(msg)
    return f"Email sent to {len(recipients)} recipient(s)"


def _build_notification_text(assets: list[dict[str, Any]]) -> str:
    critical = sum(1 for a in assets if a.get("risk") == "CRITICAL")
    high = sum(1 for a in assets if a.get("risk") == "HIGH")
    top = sorted(assets, key=lambda a: int(a.get("score", 0)), reverse=True)[:3]
    lines = [
        "MSCP Aggregate Risk Alert",
        f"Critical: {critical}",
        f"High: {high}",
    ]
    for t in top:
        lines.append(f"- {t.get('host')}:{t.get('port')} {t.get('risk')} score={t.get('score')}")
        hints = t.get("ai_suggestions") or []
        if hints:
            lines.append(f"  Suggestion: {hints[0]}")
    return "\n".join(lines)


def _get_effective_settings(report: dict[str, Any], defaults: dict[str, Any]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    merged.update(defaults.get("settings", {}))
    merged.update(report.get("settings", {}))
    return merged


def _render(
    report: dict[str, Any],
    report_path: Path,
    params: dict[str, str],
    session_data: dict[str, Any],
    error: str | None = None,
    notice: str | None = None,
) -> str:
    lang = str(params.get("lang", "en")).lower()
    tr = {
        "en": {
            "title": "MSCP Dashboard",
            "upload_title": "Upload / Drag & Drop",
            "upload_btn": "Upload & Analyze Files",
            "aggregate_btn": "Aggregate Analysis",
            "download": "Download current report JSON",
            "mode_defs": "Mode Definitions",
            "risk": "Risk",
            "best_for": "Best for",
            "sources": "Sources",
            "assets": "Assets",
            "critical": "Critical",
            "high": "High",
            "medium_low": "Medium/Low",
            "recommendations": "Recommendations",
            "top_traffic": "Top Traffic Endpoints",
            "per_input": "Per-input Analysis Results",
            "filename": "Filename",
            "scanner": "Scanner",
            "status": "Status",
            "errors": "Errors",
            "host": "Host",
            "port": "Port",
            "service": "Service",
            "risk_col": "Risk",
            "score": "Score",
            "findings": "Findings",
            "score_details": "Score Details",
            "ai": "AI Suggestion",
            "generated": "Generated at",
            "source": "Source",
        },
        "vi": {
            "title": "Bang Dieu Khien MSCP",
            "upload_title": "Tai len / Keo tha",
            "upload_btn": "Tai len va Phan tich",
            "aggregate_btn": "Phan tich tong hop",
            "download": "Tai report JSON hien tai",
            "mode_defs": "Dinh nghia che do",
            "risk": "Rui ro",
            "best_for": "Phu hop",
            "sources": "Nguon",
            "assets": "Tai san",
            "critical": "Nghiem trong",
            "high": "Cao",
            "medium_low": "Trung binh/Thap",
            "recommendations": "Khuyen nghi",
            "top_traffic": "Diem luong truy cap cao",
            "per_input": "Ket qua phan tich theo input",
            "filename": "Ten file",
            "scanner": "Cong cu",
            "status": "Trang thai",
            "errors": "Loi",
            "host": "Host",
            "port": "Port",
            "service": "Dich vu",
            "risk_col": "Rui ro",
            "score": "Diem",
            "findings": "Phat hien",
            "score_details": "Chi tiet diem",
            "ai": "Goi y AI",
            "generated": "Thoi gian tao",
            "source": "Nguon",
        },
    }.get(lang, {})

    def t(key: str) -> str:
        return tr.get(key, key)

    assets = report.get("assets", [])
    current_risk_mode = str(params.get("risk_mode") or report.get("risk_mode", "realistic"))
    critical = sum(1 for a in assets if a.get("risk") == "CRITICAL")
    high = sum(1 for a in assets if a.get("risk") == "HIGH")
    medium = sum(1 for a in assets if a.get("risk") == "MEDIUM")
    low = sum(1 for a in assets if a.get("risk") == "LOW")

    top_assets = sorted(assets, key=lambda x: int(x.get("score", 0)), reverse=True)[:30]
    analysis = report.get("analysis", {})
    recs = analysis.get("recommendations", [])
    top_traffic = analysis.get("top_traffic", [])[:5]

    risk_mode_options = []
    for m in ("realistic", "capability", "balanced", "dos"):
        selected = " selected" if m == current_risk_mode else ""
        label = RISK_MODE_META.get(m, {}).get("label", m)
        risk_mode_options.append(f"<option value='{m}'{selected}>{html.escape(label)}</option>")

    rows = []
    for a in top_assets:
        suggestions = a.get("ai_suggestions", [])
        first_hint = html.escape(suggestions[0] if suggestions else "-")
        findings = ", ".join(a.get("findings", [])[:3])
        score_details = ", ".join(f"{k}:{v}" for k, v in sorted((a.get("score_details") or {}).items()))
        risk = html.escape(str(a.get("risk")))
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(a.get('host')))}</td>"
            f"<td>{html.escape(str(a.get('port')))}</td>"
            f"<td>{html.escape(str(a.get('service')))}</td>"
            f"<td><span class='risk-badge risk-{risk}'>{risk}</span></td>"
            f"<td>{html.escape(str(a.get('score')))}</td>"
            f"<td>{html.escape(findings)}</td><td class='mono'>{html.escape(score_details)}</td>"
            f"<td class='hint'>{first_hint}</td>"
            "</tr>"
        )

    rec_html = "".join(f"<li>{html.escape(str(r))}</li>" for r in recs)
    traffic_html = "".join(
        f"<li>{html.escape(str(x.get('host')))}:{html.escape(str(x.get('port')))} -> {html.escape(str(x.get('traffic_events')))} events</li>"
        for x in top_traffic
    )

    settings = _get_effective_settings(report, params)
    current_lang = str(params.get("lang") or settings.get("lang") or lang)
    current_engine = str(settings.get("analysis_engine", "system"))

    # Per-scanner analyze slots (one file per scanner)
    form = (
        "<div class='card' style='margin-bottom:12px'>"
        f"<div class='k'>Analyze Files (One Slot Per Scanner)</div>"
        "<div class='toolbar-grid' style='grid-template-columns:repeat(4,1fr)'>"
        "<form method='post' enctype='multipart/form-data' action='/analyze' style='display:flex;flex-direction:column;gap:6px;'>"
        "<input type='hidden' name='scanner' value='nikto'/>"
        f"<input type='hidden' name='lang' value='{html.escape(current_lang)}'/>"
        "<input type='file' name='file' />"
        f"<button type='submit'>Analyze Nikto</button>"
        "</form>"
        "<form method='post' enctype='multipart/form-data' action='/analyze' style='display:flex;flex-direction:column;gap:6px;'>"
        "<input type='hidden' name='scanner' value='nmap'/>"
        f"<input type='hidden' name='lang' value='{html.escape(current_lang)}'/>"
        "<input type='file' name='file' />"
        f"<button type='submit'>Analyze Nmap</button>"
        "</form>"
        "<form method='post' enctype='multipart/form-data' action='/analyze' style='display:flex;flex-direction:column;gap:6px;'>"
        "<input type='hidden' name='scanner' value='openvas'/>"
        f"<input type='hidden' name='lang' value='{html.escape(current_lang)}'/>"
        "<input type='file' name='file' />"
        f"<button type='submit'>Analyze OpenVAS</button>"
        "</form>"
        "<form method='post' enctype='multipart/form-data' action='/analyze' style='display:flex;flex-direction:column;gap:6px;'>"
        "<input type='hidden' name='scanner' value='wireshark'/>"
        f"<input type='hidden' name='lang' value='{html.escape(current_lang)}'/>"
        "<input type='file' name='file' />"
        f"<button type='submit'>Analyze Wireshark</button>"
        "</form>"
        "</div>"
        "</div>"
    )

    input_states = report.get("per_inputs", session_data.get("inputs", []))
    can_aggregate = bool(input_states) and all(x.get("status") == "done" for x in input_states)
    aggregate_disabled = "" if can_aggregate else " disabled"
    aggregate_form = (
        "<form method='post' action='/aggregate' class='card' style='margin-bottom:12px'>"
        f"<input type='hidden' name='lang' value='{html.escape(lang)}' />"
        f"<button type='submit'{aggregate_disabled}>{html.escape(t('aggregate_btn'))}</button>"
        "</form>"
    )

    # Settings are loaded from .env and shown as read-only on dashboard.
    path_form = (
        "<div class='card' style='margin-bottom:12px'>"
        "<div class='k'>Runtime Settings (.env)</div>"
        "<div class='toolbar-grid' style='grid-template-columns:1fr 1fr 1fr'>"
        f"<div><div class='k'>Language</div><div>{html.escape(current_lang)}</div><div class='k'>Risk Mode</div><div>{html.escape(str(settings.get('risk_mode', current_risk_mode)))}</div><div class='k'>Analysis Engine</div><div>{html.escape(current_engine)}</div><div class='k'>AI Enabled</div><div>{html.escape(str(settings.get('ai_enabled', True)))}</div></div>"
        f"<div><div class='k'>Telegram Enabled</div><div>{html.escape(str(settings.get('telegram_enabled', False)))}</div><div class='k'>Telegram Chat</div><div>{html.escape(str(settings.get('telegram_chat_id', '')) or '-')}</div></div>"
        f"<div><div class='k'>Email Enabled</div><div>{html.escape(str(settings.get('email_enabled', False)))}</div><div class='k'>SMTP Host</div><div>{html.escape(str(settings.get('smtp_host', '')) or '-')}</div><div class='k'>Email To</div><div>{html.escape(str(settings.get('email_to', '')) or '-')}</div></div>"
        "</div>"
        "<div class='foot'>Edit .env to change these settings, then restart dashboard.</div>"
        "<div class='foot'><a href='/?lang=en'>English</a> | <a href='/?lang=vi'>Vietnamese</a></div>"
        "</div>"
    )

    risk_mode_meta = RISK_MODE_META.get(str(report.get("risk_mode", "realistic")), RISK_MODE_META["realistic"])

    per_inputs = report.get("per_inputs", [])
    scanner_counts: dict[str, dict[str, int]] = {}
    for it in per_inputs:
        name = str(it.get("declared_type", "unknown"))
        if name not in scanner_counts:
            scanner_counts[name] = {"done": 0, "error": 0}
        scanner_counts[name]["done" if it.get("status") == "done" else "error"] += 1

    scanner_rows = []
    for scanner_name, cnt in sorted(scanner_counts.items()):
        scanner_rows.append(
            "<tr>"
            f"<td>{html.escape(scanner_name)}</td>"
            f"<td>{cnt.get('done', 0)}</td>"
            f"<td>{cnt.get('error', 0)}</td>"
            "</tr>"
        )

    total_errors = sum(len(it.get("errors", [])) for it in per_inputs)
    total_findings = sum(len(a.get("findings", [])) for a in assets)
    input_rows = []
    for it in per_inputs:
        errs = "; ".join(it.get("errors", [])[:3])
        input_rows.append(
            "<tr>"
            f"<td>{html.escape(str(it.get('filename', '-')))}</td>"
            f"<td>{html.escape(str(it.get('declared_type', '-')))}</td>"
            f"<td>{html.escape(str(it.get('status', '-')))}</td>"
            f"<td>{html.escape(errs or '-')}</td>"
            "</tr>"
        )

    content = (
        f"<h1>{html.escape(t('title'))}</h1>"
        f"{form}"
        f"{path_form}"
        f"{aggregate_form}"
        f"<div class='card' style='margin-bottom:12px'>"
        f"<a href='/report.json'>{html.escape(t('download'))}</a>"
        f"<div class='foot'>This JSON contains: settings, per-input results, aggregated assets, and analysis summary.</div>"
        f"</div>"
        f"<div class='card' style='margin-bottom:12px'>"
        f"<div class='k'>{html.escape(t('mode_defs'))}</div>"
        f"<div style='margin-top:6px'><strong>{html.escape(t('risk'))}</strong>: {html.escape(str(report.get('risk_mode', 'realistic')))} - {html.escape(risk_mode_meta.get('description', ''))}</div>"
        f"<div class='foot'>{html.escape(t('best_for'))}: {html.escape(risk_mode_meta.get('best_for', ''))}</div>"
        f"</div>"
        f"<div class='foot'>{html.escape(t('sources'))}: {html.escape(', '.join(report.get('selected_sources', [])))}</div>"
        f"<div class='grid'>"
        f"<div class='card'><div class='k'>{html.escape(t('assets'))}</div><div class='v'>{len(assets)}</div></div>"
        f"<div class='card'><div class='k'>{html.escape(t('critical'))}</div><div class='v'>{critical}</div></div>"
        f"<div class='card'><div class='k'>{html.escape(t('high'))}</div><div class='v'>{high}</div></div>"
        f"<div class='card'><div class='k'>{html.escape(t('medium_low'))}</div><div class='v'>{medium + low}</div></div>"
        f"<div class='card'><div class='k'>Vulnerabilities/Findings</div><div class='v'>{total_findings}</div></div>"
        f"<div class='card'><div class='k'>Input Errors</div><div class='v'>{total_errors}</div></div>"
        f"</div>"
        f"<div class='card' style='margin-top:12px'>"
        f"<div class='k'>Per-Scanner Evaluation</div>"
        f"<table><thead><tr><th>Scanner</th><th>Done</th><th>Error</th></tr></thead><tbody>{''.join(scanner_rows) or '<tr><td colspan=3>-</td></tr>'}</tbody></table>"
        f"</div>"
        f"<div class='card' style='margin-top:12px'>"
        f"<div class='k'>{html.escape(t('recommendations'))}</div>"
        f"<ul>{rec_html}</ul>"
        f"</div>"
        f"<div class='card' style='margin-top:12px'>"
        f"<div class='k'>{html.escape(t('top_traffic'))}</div>"
        f"<ul>{traffic_html}</ul>"
        f"</div>"
        f"<div class='card' style='margin-top:12px'>"
        f"<div class='k'>{html.escape(t('per_input'))}</div>"
        f"<table><thead><tr><th>{html.escape(t('filename'))}</th><th>{html.escape(t('scanner'))}</th><th>{html.escape(t('status'))}</th><th>{html.escape(t('errors'))}</th></tr></thead><tbody>{''.join(input_rows)}</tbody></table>"
        f"</div>"
        f"<table>"
        f"<thead><tr><th>{html.escape(t('host'))}</th><th>{html.escape(t('port'))}</th><th>{html.escape(t('service'))}</th><th>{html.escape(t('risk_col'))}</th><th>{html.escape(t('score'))}</th><th>{html.escape(t('findings'))}</th><th>{html.escape(t('score_details'))}</th><th>{html.escape(t('ai'))}</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        f"</table>"
        f"<div class='foot'>{html.escape(t('generated'))}: {html.escape(str(report.get('generated_at', 'n/a')))} | {html.escape(t('source'))}: {html.escape(str(report_path))}</div>"
    )
    if notice:
        content = f"<div class='card banner-ok' style='margin-bottom:12px'>{html.escape(notice)}</div>" + content
    if error:
        content = f"<div class='card banner-err' style='margin-bottom:12px'>Error: {html.escape(error)}</div>" + content
    return HTML_TEMPLATE.replace("__CONTENT__", content)


def run_dashboard(
    report_file: str,
    host: str = "127.0.0.1",
    port: int = 8787,
    open_browser_flag: bool = True,
    report_loader: Callable[[str, dict[str, str]], dict[str, Any]] | None = None,
    alert_sender: Callable[[dict[str, Any], str], str] | None = None,
    initial_params: dict[str, str] | None = None,
    default_mode: str = "auto",
) -> int:
    report_path = Path(report_file)
    defaults = initial_params or {}

    class Handler(BaseHTTPRequestHandler):
        # session_data keeps per-upload analysis state in memory and persists to report file
        session_data: dict[str, Any] = {"inputs": [], "aggregated": None}

        def do_POST(self) -> None:  # noqa: N802
            try:
                parsed = urlparse(self.path)
                if parsed.path == "/analyze":
                    self._handle_analyze()
                    return
                if parsed.path == "/aggregate":
                    self._handle_aggregate()
                    return
                self.send_response(404)
                self.end_headers()
            except Exception as exc:
                body = (
                    f"<html><body><p>POST error: {html.escape(str(exc))}</p>"
                    "<p><a href='/'>Back</a></p></body></html>"
                ).encode("utf-8")
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def _record_single_input(self, filename: str, tmp_path: str, declared_type: str, risk_mode: str) -> dict[str, Any]:
            validation_errors = validate_input_for_type(tmp_path, declared_type, original_name=filename)

            assets = []
            errors: list[str] = []
            if validation_errors:
                errors.extend(validation_errors)
            else:
                assets, errors = analyze_path_by_type(tmp_path, declared_type)
                # enrich per-input assets with AI suggestions for immediate feedback
                try:
                    enrich_assets_with_ai(assets)
                except Exception:
                    # non-fatal: AI enrichment shouldn't block upload recording
                    pass

            status = 'done' if not errors else 'error'
            entry = {
                'filename': filename,
                'path': tmp_path,
                'declared_type': declared_type,
                'status': status,
                'errors': errors,
                'assets': [a.to_dict() for a in assets],
            }
            Handler.session_data['inputs'].append(entry)

            report = _load_report(report_path)
            report['risk_mode'] = risk_mode
            report['selected_sources'] = sorted(
                {
                    x.get('declared_type', '')
                    for x in Handler.session_data['inputs']
                    if x.get('status') == 'done'
                }
            )
            report.setdefault('per_inputs', [])
            report['per_inputs'].append(entry)
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            return entry

        def _handle_analyze(self) -> None:
            # single-file per-scanner analyze
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'})
            scanner = str(form.getfirst('scanner', 'nikto'))
            lang = form.getfirst('lang', 'en')
            settings_from_defaults = defaults.get('settings', {})
            risk_mode = str(settings_from_defaults.get('risk_mode', defaults.get('risk_mode', 'realistic')))

            file_field = form['file'] if 'file' in form else None
            if file_field is None or not getattr(file_field, 'filename', None):
                self._respond_and_redirect('No file provided for analyze', lang=lang)
                return

            with tempfile.NamedTemporaryFile(delete=False, prefix='mscp_upload_', suffix='') as tmp:
                data = file_field.file.read()
                tmp.write(data)
                tmp.flush()
                tmp_path = tmp.name

            self._record_single_input(
                filename=file_field.filename,
                tmp_path=tmp_path,
                declared_type=scanner,
                risk_mode=str(risk_mode),
            )
            self._respond_and_redirect(f'Analyzed {file_field.filename} as {scanner}', lang=lang)

        def _handle_aggregate(self) -> None:
            # Only aggregate if all inputs are done
            if any(i.get('status') != 'done' for i in Handler.session_data.get('inputs', [])):
                self._respond_and_redirect('All individual analyses must be completed before aggregation')
                return

            if not Handler.session_data.get('inputs'):
                self._respond_and_redirect('No individual analysis results found')
                return

            combined_map: dict[tuple[str, int], dict] = {}
            for entry in Handler.session_data.get('inputs', []):
                for a in entry.get('assets', []):
                    key = (a.get('host'), int(a.get('port') or 0))
                    acc = combined_map.get(key) or {'host': key[0], 'port': key[1], 'findings': [], 'cves': set(), 'evidence': set()}
                    acc['findings'].extend(a.get('findings', []))
                    for c in a.get('cves', []):
                        acc['cves'].add(c)
                    for ev in a.get('evidence', []):
                        acc['evidence'].add(ev)
                    combined_map[key] = acc

            from mscp.models import CorrelatedAsset

            assets = []
            for k, v in combined_map.items():
                ca = CorrelatedAsset(host=v['host'], port=v['port'])
                ca.findings = v['findings']
                ca.cves = set(v['cves'])
                ca.evidence = set(v['evidence'])
                assets.append(ca)

            report_for_weights = _load_report(report_path)
            settings = _get_effective_settings(report_for_weights, defaults)
            risk_mode_for_agg = str(settings.get('risk_mode') or report_for_weights.get('risk_mode') or defaults.get('risk_mode') or 'realistic')
            weights = resolve_weights_for_mode(risk_mode_for_agg)
            scored = score_assets(assets, weights=weights)
            scored = normalize_assets_to_100(scored)
            # attach AI suggestions to aggregated assets
            try:
                enrich_assets_with_ai(scored)
            except Exception:
                pass

            ai_enabled = bool(settings.get('ai_enabled', True))
            analysis_engine = str(settings.get('analysis_engine', 'system')).lower()
            hf_key = str(settings.get('hf_api_key', '')).strip()
            if ai_enabled and analysis_engine in {'ai', 'hybrid'}:
                for a in scored:
                    asset_text = (
                        f"host={a.host} port={a.port} risk={a.risk} "
                        f"findings={'; '.join(a.findings[:5])}"
                    )
                    ai_text = analyze_asset_with_ai(asset_text, hf_api_key=hf_key)
                    if not ai_text:
                        continue
                    ai_text = ai_text.strip()
                    if analysis_engine == 'ai':
                        a.ai_suggestions = [ai_text]
                    else:
                        a.ai_suggestions = [ai_text] + list(a.ai_suggestions)

            Handler.session_data['aggregated'] = [a.to_dict() for a in scored]

            # persist aggregated to report file
            report = _load_report(report_path)
            report['risk_mode'] = risk_mode_for_agg
            report['settings'] = settings
            report['aggregated'] = Handler.session_data['aggregated']
            report['assets'] = Handler.session_data['aggregated']
            report['analysis'] = build_analysis_insights(report)
            notice_parts: list[str] = []

            msg = _build_notification_text(report['assets'])
            try:
                if bool(settings.get('telegram_enabled')):
                    token = str(settings.get('telegram_bot_token', '')).strip()
                    chat_id = str(settings.get('telegram_chat_id', '')).strip()
                    if token and chat_id:
                        send_telegram_alert(token, chat_id, msg)
                        notice_parts.append('Telegram sent')
            except Exception as exc:
                notice_parts.append(f'Telegram failed: {exc}')

            try:
                if bool(settings.get('email_enabled')):
                    email_notice = _send_email_alert(settings, 'MSCP Aggregate Risk Alert', msg)
                    notice_parts.append(email_notice)
            except Exception as exc:
                notice_parts.append(f'Email failed: {exc}')

            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)

            suffix = f" ({'; '.join(notice_parts)})" if notice_parts else ''
            self._respond_and_redirect(f'Aggregated analysis complete{suffix}', lang=str(settings.get('lang', 'en')))

        def _respond_and_redirect(self, message: str, lang: str = 'en') -> None:
            # simple response page with link back to dashboard
            body = (
                f"<html><body><p>{html.escape(message)}</p>"
                f"<p><a href='/?lang={html.escape(lang)}'>Back</a></p></body></html>"
            ).encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            params = {
                "nmap": qs.get("nmap", [defaults.get("nmap", "")])[0],
                "nikto": qs.get("nikto", [defaults.get("nikto", "")])[0],
                "openvas": qs.get("openvas", [defaults.get("openvas", "")])[0],
                "wireshark": qs.get("wireshark", [defaults.get("wireshark", "")])[0],
                "risk_config": qs.get("risk_config", [defaults.get("risk_config", "")])[0],
                "risk_mode": qs.get("risk_mode", [defaults.get("risk_mode", "realistic")])[0],
                "alert_min_risk": qs.get("alert_min_risk", [defaults.get("alert_min_risk", "HIGH")])[0],
                "lang": qs.get("lang", [defaults.get("lang", "en")])[0],
                "settings": defaults.get("settings", {}),
            }
            action = qs.get("action", ["analyze"])[0]

            error = None
            notice = None
            has_paths = any(params.get(k) for k in ("nmap", "nikto", "openvas", "wireshark"))
            if report_loader is not None and has_paths:
                try:
                    report = report_loader(default_mode, params)
                    with open(report_path, "w", encoding="utf-8") as f:
                        json.dump(report, f, indent=2)
                    if action == "alert" and alert_sender is not None:
                        notice = alert_sender(report, params.get("alert_min_risk", "HIGH"))
                except Exception as exc:
                    report = _load_report(report_path)
                    error = str(exc)
            else:
                report = _load_report(report_path)

            report_settings = _get_effective_settings(report, defaults)
            report['settings'] = report_settings

            if not qs.get("lang"):
                settings_lang = str(report_settings.get("lang", "")).strip().lower()
                if settings_lang in {"en", "vi"}:
                    params["lang"] = settings_lang

            if parsed.path == "/report.json":
                payload = json.dumps(report, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return

            body = _render(
                report,
                report_path,
                params=params,
                session_data=Handler.session_data,
                error=error,
                notice=notice,
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            return

    bind_port = port
    server = None
    for p in range(port, port + 20):
        try:
            server = ThreadingHTTPServer((host, p), Handler)
            bind_port = p
            break
        except OSError:
            continue

    if server is None:
        raise RuntimeError("No available port for dashboard in range 20 ports")

    url = f"http://{host}:{bind_port}"
    print(f"Dashboard running at {url}")
    if open_browser_flag:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

    return 0
