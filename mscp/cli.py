from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from mscp.alerts.telegram import send_telegram_alert
from mscp.config import load_weights
from mscp.engine.correlation import correlate
from mscp.engine.diff import diff_reports
from mscp.engine.risk import score_assets
from mscp.plugins import PluginRegistry


def _load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _risk_rank(level: str) -> int:
    order = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    return order.get(str(level).upper(), 0)


def _is_at_least(level: str, min_level: str) -> bool:
    return _risk_rank(level) >= _risk_rank(min_level)


def _should_alert(report: dict, diff: dict | None, min_risk: str) -> bool:
    high_or_critical = any(_is_at_least(str(a.get("risk", "LOW")), min_risk) for a in report.get("assets", []))
    if diff is None:
        return high_or_critical

    changed_high = any(_is_at_least(str(x.get("new_risk", "LOW")), min_risk) for x in diff.get("risk_changed", []))
    added_high = any(_is_at_least(str(a.get("risk", "LOW")), min_risk) for a in diff.get("added", []))
    return changed_high or added_high


def _build_alert_text(report: dict, diff: dict | None) -> str:
    critical = [a for a in report.get("assets", []) if a.get("risk") == "CRITICAL"]
    high = [a for a in report.get("assets", []) if a.get("risk") == "HIGH"]

    lines = [
        "[MSCP] Security Risk Alert",
        f"Critical: {len(critical)}",
        f"High: {len(high)}",
    ]

    top = sorted(report.get("assets", []), key=lambda a: int(a.get("score", 0)), reverse=True)[:3]
    for asset in top:
        lines.append(
            f"- {asset.get('host')}:{asset.get('port')} {asset.get('risk')} score={asset.get('score')}"
        )

    if diff is not None:
        lines.append(
            f"Diff -> added: {len(diff.get('added', []))}, removed: {len(diff.get('removed', []))}, risk_changed: {len(diff.get('risk_changed', []))}"
        )

    return "\n".join(lines)


def _has_input_sources(args: argparse.Namespace) -> bool:
    return any([args.nmap, args.nikto, args.openvas, args.wireshark])


def _assets_fingerprint(report: dict) -> str:
    return json.dumps(report.get("assets", []), sort_keys=True)


def _has_any_diff(diff_payload: dict | None) -> bool:
    if diff_payload is None:
        return False
    return any(len(diff_payload.get(key, [])) > 0 for key in ("added", "removed", "risk_changed"))


def build_report(args: argparse.Namespace) -> dict:
    registry = PluginRegistry.default()
    weights = load_weights(getattr(args, "risk_config", None))

    nmap_data = registry.run("nmap", args.nmap) if args.nmap else []
    nikto_data = registry.run("nikto", args.nikto) if args.nikto else []
    openvas_data = registry.run("openvas", args.openvas) if args.openvas else []
    wireshark_data = registry.run("wireshark", args.wireshark) if args.wireshark else []

    assets = correlate(
        nmap=nmap_data,
        nikto=nikto_data,
        openvas=openvas_data,
        wireshark=wireshark_data,
    )
    scored = score_assets(assets, weights=weights)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "assets": [x.to_dict() for x in scored],
    }
    return report


def handle_report(args: argparse.Namespace) -> int:
    if not _has_input_sources(args):
        print("No scanner input provided.")
        print("Provide at least one of: --nmap, --nikto, --openvas, --wireshark")
        return 2

    report = build_report(args)
    diff_payload = None

    if args.baseline:
        old_report = _load_json(Path(args.baseline))
        diff_payload = diff_reports(old_report=old_report, new_report=report)
        report["diff"] = diff_payload

    if args.out:
        _save_json(Path(args.out), report)

    print(json.dumps(report, indent=2))

    if args.telegram_bot_token and args.telegram_chat_id:
        if _should_alert(report, diff_payload, args.alert_min_risk):
            message = _build_alert_text(report, diff_payload)
            send_telegram_alert(
                bot_token=args.telegram_bot_token,
                chat_id=args.telegram_chat_id,
                message=message,
            )
            print("Telegram alert sent")
        else:
            print("No alert-level risk detected, alert suppressed")

    return 0


def _run_alert_if_needed(args: argparse.Namespace, report: dict, diff_payload: dict | None) -> None:
    if not (args.telegram_bot_token and args.telegram_chat_id):
        return

    if _should_alert(report, diff_payload, args.alert_min_risk):
        message = _build_alert_text(report, diff_payload)
        send_telegram_alert(
            bot_token=args.telegram_bot_token,
            chat_id=args.telegram_chat_id,
            message=message,
        )
        print("Telegram alert sent")
    else:
        print("No alert-level risk detected, alert suppressed")


def handle_schedule(args: argparse.Namespace) -> int:
    if not _has_input_sources(args):
        print("No scanner input provided.")
        print("Provide at least one of: --nmap, --nikto, --openvas, --wireshark")
        return 2

    state_path = Path(args.state_file)
    previous_report = _load_json(state_path) if state_path.exists() else None

    print(f"Schedule started. Interval: {args.interval}s. State: {state_path}")
    try:
        while True:
            report = build_report(args)
            diff_payload = None

            if previous_report is not None:
                diff_payload = diff_reports(old_report=previous_report, new_report=report)
                report["diff"] = diff_payload

            changed = previous_report is None
            if previous_report is not None:
                changed = _has_any_diff(diff_payload) or (
                    _assets_fingerprint(previous_report) != _assets_fingerprint(report)
                )

            if args.out:
                _save_json(Path(args.out), report)

            if changed:
                print("Change detected in scan results")
                _run_alert_if_needed(args, report, diff_payload)
            else:
                print("No change detected; alert skipped")

            _save_json(state_path, report)
            previous_report = report

            if args.once:
                return 0

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Scheduler stopped by user")
        return 130


def _prompt_value(label: str, default: str | None = None) -> str | None:
    suffix = f" [{default}]" if default else ""
    raw = input(f"{label}{suffix}: ").strip()
    if raw:
        return raw
    return default


def _run_interactive() -> int:
    print("MSCP interactive mode")
    print("Leave empty if a scanner file is not available.")

    nmap = _prompt_value("Nmap XML path")
    nikto = _prompt_value("Nikto JSON/TXT path")
    openvas = _prompt_value("OpenVAS JSON/XML path")
    wireshark = _prompt_value("Wireshark JSON path")
    baseline = _prompt_value("Baseline report JSON path")
    out = _prompt_value("Output JSON path", default="out/report-interactive.json")
    risk_config = _prompt_value("Risk config path (.json/.yaml)", default="config/risk_weights.json")

    bot_token = _prompt_value("Telegram bot token")
    chat_id = _prompt_value("Telegram chat id")
    min_risk = (_prompt_value("Alert min risk (LOW|MEDIUM|HIGH|CRITICAL)", default="HIGH") or "HIGH").upper()
    if min_risk not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        min_risk = "HIGH"

    args = argparse.Namespace(
        command="report",
        nmap=nmap,
        nikto=nikto,
        openvas=openvas,
        wireshark=wireshark,
        baseline=baseline,
        out=out,
        risk_config=risk_config,
        telegram_bot_token=bot_token,
        telegram_chat_id=chat_id,
        alert_min_risk=min_risk,
        handler=handle_report,
    )
    return handle_report(args)


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mscp", description="Multi-Scanner Correlation Plugin")

    sub = parser.add_subparsers(dest="command", required=True)

    report_cmd = sub.add_parser("report", help="Build correlated risk report")
    report_cmd.add_argument("--nmap", help="Path to Nmap XML report")
    report_cmd.add_argument("--nikto", help="Path to Nikto JSON or TXT report")
    report_cmd.add_argument("--openvas", help="Path to OpenVAS JSON or XML report")
    report_cmd.add_argument("--wireshark", help="Path to tshark/Wireshark JSON report")
    report_cmd.add_argument("--baseline", help="Old report JSON for diff mode")
    report_cmd.add_argument("--out", help="Output JSON path")
    report_cmd.add_argument("--risk-config", help="Risk config file (.json/.yaml)")

    report_cmd.add_argument("--telegram-bot-token", help="Telegram bot token")
    report_cmd.add_argument("--telegram-chat-id", help="Telegram chat id")
    report_cmd.add_argument(
        "--alert-min-risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum risk level that can trigger Telegram alert (default: HIGH)",
    )

    report_cmd.set_defaults(handler=handle_report)

    schedule_cmd = sub.add_parser("schedule", help="Run periodic scans and alert only on changes")
    schedule_cmd.add_argument("--nmap", help="Path to Nmap XML report")
    schedule_cmd.add_argument("--nikto", help="Path to Nikto JSON or TXT report")
    schedule_cmd.add_argument("--openvas", help="Path to OpenVAS JSON or XML report")
    schedule_cmd.add_argument("--wireshark", help="Path to tshark/Wireshark JSON report")
    schedule_cmd.add_argument("--out", help="Output JSON path")
    schedule_cmd.add_argument("--risk-config", help="Risk config file (.json/.yaml)")

    schedule_cmd.add_argument("--telegram-bot-token", help="Telegram bot token")
    schedule_cmd.add_argument("--telegram-chat-id", help="Telegram chat id")
    schedule_cmd.add_argument(
        "--alert-min-risk",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="HIGH",
        help="Minimum risk level that can trigger Telegram alert (default: HIGH)",
    )
    schedule_cmd.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Scheduler interval in seconds (default: 300)",
    )
    schedule_cmd.add_argument(
        "--state-file",
        default="out/last-schedule-report.json",
        help="State file used to detect changes between runs",
    )
    schedule_cmd.add_argument(
        "--once",
        action="store_true",
        help="Run only one scheduler cycle (useful for testing)",
    )
    schedule_cmd.set_defaults(handler=handle_schedule)

    return parser


def main(argv: List[str] | None = None) -> int:
    parser = make_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    if not raw_argv:
        return _run_interactive()

    args = parser.parse_args(raw_argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
