from __future__ import annotations

import html
import json
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, urlparse

from mscp.modes import ANALYSIS_MODES, RISK_MODE_META


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


def _render(
    report: dict[str, Any],
    report_path: Path,
    current_mode: str,
    params: dict[str, str],
    error: str | None = None,
    notice: str | None = None,
) -> str:
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

    mode_options = []
    for m in ("auto", "1", "2", "3", "4"):
        selected = " selected" if m == current_mode else ""
        label = ANALYSIS_MODES.get(m, {}).get("label", m)
        mode_options.append(f"<option value='{m}'{selected}>{html.escape(m)} - {html.escape(label)}</option>")

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

    form = (
        "<form method='get' class='card' style='margin-bottom:12px'>"
        "<div class='k'>Live Inputs</div>"
        f"<div class='toolbar-grid'>"
        f"<input name='nmap' placeholder='Nmap XML path' value='{html.escape(_q(params, 'nmap'))}' />"
        f"<input name='nikto' placeholder='Nikto path' value='{html.escape(_q(params, 'nikto'))}' />"
        f"<input name='openvas' placeholder='OpenVAS path' value='{html.escape(_q(params, 'openvas'))}' />"
        f"<input name='wireshark' placeholder='Wireshark path' value='{html.escape(_q(params, 'wireshark'))}' />"
        f"<input name='risk_config' placeholder='Risk config path' value='{html.escape(_q(params, 'risk_config'))}' />"
        f"<select name='risk_mode'>{''.join(risk_mode_options)}</select>"
        f"<input name='alert_min_risk' placeholder='Alert min risk (HIGH)' value='{html.escape(_q(params, 'alert_min_risk', 'HIGH'))}' />"
        "</div>"
        f"<div class='toolbar-row'>"
        "<label for='mode'>Analysis Mode</label>"
        f"<select id='mode' name='mode'>{''.join(mode_options)}</select>"
        "<button type='submit' name='action' value='analyze'>Analyze</button>"
        "<button type='submit' name='action' value='alert' class='secondary-btn'>Send Telegram Alert</button>"
        "</div>"
        "</form>"
    )

    analysis_mode_meta = ANALYSIS_MODES.get(str(report.get("analysis_mode", "auto")), ANALYSIS_MODES["auto"])
    risk_mode_meta = RISK_MODE_META.get(str(report.get("risk_mode", "realistic")), RISK_MODE_META["realistic"])

    content = (
        f"<h1>MSCP Dashboard</h1>"
        f"{form}"
        f"<div class='card' style='margin-bottom:12px'>"
        f"<a href='/report.json?mode={html.escape(current_mode)}'>Download current report JSON</a>"
        f"</div>"
        f"<div class='card' style='margin-bottom:12px'>"
        f"<div class='k'>Mode Definitions</div>"
        f"<div><strong>Analysis</strong>: {html.escape(str(report.get('analysis_mode', 'auto')))} - {html.escape(analysis_mode_meta.get('description', ''))}</div>"
        f"<div class='foot'>{html.escape(analysis_mode_meta.get('behavior', ''))}</div>"
        f"<div style='margin-top:6px'><strong>Risk</strong>: {html.escape(str(report.get('risk_mode', 'realistic')))} - {html.escape(risk_mode_meta.get('description', ''))}</div>"
        f"<div class='foot'>Best for: {html.escape(risk_mode_meta.get('best_for', ''))}</div>"
        f"</div>"
        f"<div class='foot'>Sources: {html.escape(', '.join(report.get('selected_sources', [])))}</div>"
        f"<div class='grid'>"
        f"<div class='card'><div class='k'>Assets</div><div class='v'>{len(assets)}</div></div>"
        f"<div class='card'><div class='k'>Critical</div><div class='v'>{critical}</div></div>"
        f"<div class='card'><div class='k'>High</div><div class='v'>{high}</div></div>"
        f"<div class='card'><div class='k'>Medium/Low</div><div class='v'>{medium + low}</div></div>"
        f"</div>"
        f"<div class='card' style='margin-top:12px'>"
        f"<div class='k'>Recommendations</div>"
        f"<ul>{rec_html}</ul>"
        f"</div>"
        f"<div class='card' style='margin-top:12px'>"
        f"<div class='k'>Top Traffic Endpoints</div>"
        f"<ul>{traffic_html}</ul>"
        f"</div>"
        f"<table>"
        f"<thead><tr><th>Host</th><th>Port</th><th>Service</th><th>Risk</th><th>Score</th><th>Findings</th><th>Score Details</th><th>AI Goi Y</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        f"</table>"
        f"<div class='foot'>Generated at: {html.escape(str(report.get('generated_at', 'n/a')))} | Source: {html.escape(str(report_path))}</div>"
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
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            mode = qs.get("mode", [default_mode])[0]
            params = {
                "nmap": qs.get("nmap", [defaults.get("nmap", "")])[0],
                "nikto": qs.get("nikto", [defaults.get("nikto", "")])[0],
                "openvas": qs.get("openvas", [defaults.get("openvas", "")])[0],
                "wireshark": qs.get("wireshark", [defaults.get("wireshark", "")])[0],
                "risk_config": qs.get("risk_config", [defaults.get("risk_config", "")])[0],
                "risk_mode": qs.get("risk_mode", [defaults.get("risk_mode", "realistic")])[0],
                "alert_min_risk": qs.get("alert_min_risk", [defaults.get("alert_min_risk", "HIGH")])[0],
            }
            action = qs.get("action", ["analyze"])[0]

            error = None
            notice = None
            if report_loader is not None:
                try:
                    report = report_loader(mode, params)
                    with open(report_path, "w", encoding="utf-8") as f:
                        json.dump(report, f, indent=2)
                    if action == "alert" and alert_sender is not None:
                        notice = alert_sender(report, params.get("alert_min_risk", "HIGH"))
                except Exception as exc:
                    report = _load_report(report_path)
                    error = str(exc)
            else:
                report = _load_report(report_path)

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
                current_mode=mode,
                params=params,
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
