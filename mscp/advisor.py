from __future__ import annotations

from typing import List

from mscp.models import CorrelatedAsset


def suggest_actions(asset: CorrelatedAsset) -> List[str]:
    suggestions: List[str] = []
    findings_text = " ".join(asset.findings).lower()

    if "sql" in findings_text and "inject" in findings_text:
        suggestions.append("Potential SQL Injection. Validate inputs and enforce prepared statements.")

    if "xss" in findings_text:
        suggestions.append("Possible XSS behavior detected. Start with output encoding and a strict CSP.")

    if "cve" in asset.evidence and "exploit" in asset.evidence:
        suggestions.append("CVE with exploit hint detected. Prioritize emergency patching and reduce exposure.")

    if asset.port in {22, 3389} and "open_port" in asset.evidence:
        suggestions.append("Administrative port is exposed. Enforce IP allowlist and MFA.")

    if "traffic_signal" in asset.evidence and asset.risk in {"HIGH", "CRITICAL"}:
        suggestions.append("High-risk traffic anomaly detected. Capture short-window packets for investigation.")

    if not suggestions:
        suggestions.append("No clear attack indicator yet. Keep monitoring diffs in the next scan cycle.")

    return suggestions


def enrich_assets_with_ai(assets: List[CorrelatedAsset]) -> List[CorrelatedAsset]:
    for asset in assets:
        asset.ai_suggestions = suggest_actions(asset)
    return assets
