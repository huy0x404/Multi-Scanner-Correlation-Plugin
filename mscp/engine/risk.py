from __future__ import annotations

from typing import Dict, List

from mscp.models import CorrelatedAsset

DEFAULT_WEIGHTS = {
    "open_port": 1,
    "web_vuln": 3,
    "cve": 5,
    "exploit": 10,
    "traffic_signal": 2,
    "traffic_anomaly": 5,
    "dos_indicator": 10,
}


def classify(score: int) -> str:
    if score >= 18:
        return "CRITICAL"
    if score >= 10:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


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

        asset.score = score
        asset.score_details = dict(sorted(details.items()))
        asset.risk = classify(score)
        asset.reason = explain(asset)

    return assets
