from __future__ import annotations

from typing import Dict, List, Tuple


def build_index(report: dict) -> Dict[Tuple[str, int], dict]:
    idx: Dict[Tuple[str, int], dict] = {}
    for asset in report.get("assets", []):
        key = (str(asset.get("host", "unknown")), int(asset.get("port", 0)))
        idx[key] = asset
    return idx


def diff_reports(old_report: dict, new_report: dict) -> dict:
    old_idx = build_index(old_report)
    new_idx = build_index(new_report)

    added: List[dict] = []
    removed: List[dict] = []
    risk_changed: List[dict] = []

    for key, asset in new_idx.items():
        if key not in old_idx:
            added.append(asset)
        else:
            old_risk = old_idx[key].get("risk")
            new_risk = asset.get("risk")
            if old_risk != new_risk:
                risk_changed.append(
                    {
                        "host": key[0],
                        "port": key[1],
                        "old_risk": old_risk,
                        "new_risk": new_risk,
                    }
                )

    for key, asset in old_idx.items():
        if key not in new_idx:
            removed.append(asset)

    return {
        "added": added,
        "removed": removed,
        "risk_changed": risk_changed,
    }
