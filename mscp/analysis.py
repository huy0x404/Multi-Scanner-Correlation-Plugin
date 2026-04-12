from __future__ import annotations

import ipaddress
from typing import Any


def _traffic_count(findings: list[str]) -> int:
    total = 0
    for f in findings:
        if not f.startswith("Traffic:"):
            continue
        if " x" in f:
            try:
                total += int(f.rsplit(" x", 1)[1])
                continue
            except ValueError:
                pass
        total += 1
    return total


def _is_public_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def build_analysis_insights(report: dict[str, Any]) -> dict[str, Any]:
    assets = report.get("assets", [])
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for a in assets:
        risk = str(a.get("risk", "LOW")).upper()
        if risk in risk_counts:
            risk_counts[risk] += 1

    top_assets = sorted(assets, key=lambda a: int(a.get("score", 0)), reverse=True)[:10]

    traffic_assets = []
    for a in assets:
        count = _traffic_count(a.get("findings", []))
        if count > 0:
            traffic_assets.append(
                {
                    "host": a.get("host"),
                    "port": a.get("port"),
                    "risk": a.get("risk"),
                    "score": a.get("score"),
                    "traffic_events": count,
                }
            )

    traffic_assets.sort(key=lambda x: int(x["traffic_events"]), reverse=True)

    exposed_and_traffic = [
        {
            "host": a.get("host"),
            "port": a.get("port"),
            "risk": a.get("risk"),
            "score": a.get("score"),
        }
        for a in assets
        if "open_port" in a.get("evidence", []) and "traffic_signal" in a.get("evidence", [])
    ]

    public_hosts = sorted({str(a.get("host", "")) for a in assets if _is_public_ip(str(a.get("host", "")))})

    recommendations: list[str] = []
    if risk_counts["CRITICAL"] > 0:
        recommendations.append("Patch ngay cac asset CRITICAL va kiem tra exposure tren Internet.")
    if len(exposed_and_traffic) > 0:
        recommendations.append("Uu tien dieu tra asset vua open port vua co traffic bat thuong.")
    if len(public_hosts) > 0:
        recommendations.append("Raf soat ket noi ra ngoai doi voi host public va gioi han egress neu can.")
    if not recommendations:
        recommendations.append("Khong co chi bao nghiem trong. Tiep tuc theo doi diff theo chu ky.")

    return {
        "risk_counts": risk_counts,
        "top_assets": top_assets,
        "top_traffic": traffic_assets[:10],
        "exposed_with_traffic": exposed_and_traffic,
        "public_hosts": public_hosts,
        "recommendations": recommendations,
    }
