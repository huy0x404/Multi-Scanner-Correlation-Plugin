from __future__ import annotations

from typing import Dict, List

from mscp.models import CorrelatedAsset


RISK_PROFILES: dict[str, dict[str, int]] = {
    # Practical default profile for real-world mixed scanner signals.
    "realistic": {
        "open_port": 1,
        "web_vuln": 4,
        "cve": 6,
        "exploit": 9,
        "traffic_signal": 2,
        "traffic_anomaly": 4,
        "dos_indicator": 7,
    },
    # Legacy profile kept for backward compatibility.
    "balanced": {
        "open_port": 1,
        "web_vuln": 3,
        "cve": 5,
        "exploit": 10,
        "traffic_signal": 2,
        "traffic_anomaly": 5,
        "dos_indicator": 10,
    },
    # Capability-based profile: each scanner weight follows its practical detection strength.
    "capability": {
        "open_port": 1,
        "web_vuln": 4,
        "cve": 7,
        "exploit": 12,
        "traffic_signal": 2,
        "traffic_anomaly": 6,
        "dos_indicator": 12,
    },
    # Traffic/DoS-focused operations mode.
    "dos": {
        "open_port": 1,
        "web_vuln": 3,
        "cve": 5,
        "exploit": 10,
        "traffic_signal": 3,
        "traffic_anomaly": 8,
        "dos_indicator": 14,
    },
}

DEFAULT_RISK_MODE = "realistic"
DEFAULT_WEIGHTS = dict(RISK_PROFILES[DEFAULT_RISK_MODE])


def resolve_weights_for_mode(mode: str | None) -> Dict[str, int]:
    selected = str(mode or DEFAULT_RISK_MODE).strip().lower()
    if selected not in RISK_PROFILES:
        selected = DEFAULT_RISK_MODE
    return dict(RISK_PROFILES[selected])


def classify(score: int) -> str:
    if score >= 20:
        return "CRITICAL"
    if score >= 12:
        return "HIGH"
    if score >= 6:
        return "MEDIUM"
    return "LOW"


def _interaction_bonus(asset: CorrelatedAsset) -> int:
    ev = asset.evidence
    bonus = 0

    if "open_port" in ev and "cve" in ev:
        bonus += 2
    if "cve" in ev and "exploit" in ev:
        bonus += 4
    if "web_vuln" in ev and "open_port" in ev:
        bonus += 1
    if "traffic_anomaly" in ev and ("open_port" in ev or "web_vuln" in ev or "cve" in ev):
        bonus += 2
    if "dos_indicator" in ev and "traffic_anomaly" in ev:
        bonus += 3

    return bonus


def explain(asset: CorrelatedAsset) -> str:
    web_service = asset.service.lower() in {"http", "https", "http-proxy"} or asset.port in {80, 443, 8080, 8443}
    has_vuln = "web_vuln" in asset.evidence
    has_cve = "cve" in asset.evidence
    has_exploit = "exploit" in asset.evidence
    has_traffic_anomaly = "traffic_anomaly" in asset.evidence
    has_dos = "dos_indicator" in asset.evidence

    if has_dos:
        return "Possible DoS behavior detected from sustained high-volume traffic"
    if has_traffic_anomaly:
        return "Traffic volume anomaly detected on this endpoint"

    if web_service and has_vuln and has_cve:
        return "Web service exposed with vulnerability and CVE"
    if has_exploit and has_cve:
        return "Exploit hint detected for known CVE"
    if has_cve:
        return "CVE detected on exposed service"
    if has_vuln:
        return "Application vulnerability detected"
    if "open_port" in asset.evidence:
        return "Open service exposed"
    return "Low-confidence security signal"


def score_assets(assets: List[CorrelatedAsset], weights: Dict[str, int] | None = None) -> List[CorrelatedAsset]:
    active_weights = weights or DEFAULT_WEIGHTS

    for asset in assets:
        score = 0
        details: Dict[str, int] = {}
        for ev in asset.evidence:
            val = int(active_weights.get(ev, 0))
            score += val
            details[ev] = val

        bonus = _interaction_bonus(asset)
        if bonus > 0:
            score += bonus
            details["interaction_bonus"] = bonus

        asset.score = score
        asset.score_details = dict(sorted(details.items()))
        asset.risk = classify(score)
        asset.reason = explain(asset)

    return assets
