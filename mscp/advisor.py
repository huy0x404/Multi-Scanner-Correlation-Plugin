from __future__ import annotations

from typing import List

from mscp.models import CorrelatedAsset


def suggest_actions(asset: CorrelatedAsset) -> List[str]:
    suggestions: List[str] = []
    findings_text = " ".join(asset.findings).lower()

    if "sql" in findings_text and "inject" in findings_text:
        suggestions.append("Server nay co the bi SQL Injection. Kiem tra input validation va prepared statements.")

    if "xss" in findings_text:
        suggestions.append("Co dau hieu XSS. Bat dau voi output encoding va CSP.")

    if "cve" in asset.evidence and "exploit" in asset.evidence:
        suggestions.append("Co CVE kem exploit hint. Uu tien patch khan cap va giam exposure.")

    if asset.port in {22, 3389} and "open_port" in asset.evidence:
        suggestions.append("Cong quan tri dang mo. Kiem tra allowlist IP va MFA.")

    if "traffic_signal" in asset.evidence and asset.risk in {"HIGH", "CRITICAL"}:
        suggestions.append("Luu luong bat thuong ket hop risk cao. Nen bat packet capture theo cua so thoi gian ngan de dieu tra.")

    if not suggestions:
        suggestions.append("Chua thay chi bao tan cong ro rang. Tiep tuc theo doi diff o lan scan tiep theo.")

    return suggestions


def enrich_assets_with_ai(assets: List[CorrelatedAsset]) -> List[CorrelatedAsset]:
    for asset in assets:
        asset.ai_suggestions = suggest_actions(asset)
    return assets
