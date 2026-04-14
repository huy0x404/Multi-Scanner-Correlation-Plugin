from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from mscp.engine.risk import DEFAULT_RISK_MODE, resolve_weights_for_mode


def _normalize_weights(raw: dict, base: Dict[str, int]) -> Dict[str, int]:
    merged = dict(base)
    for key, value in raw.items():
        try:
            merged[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return merged


def load_weights(path: str | None, mode: str | None = None) -> Dict[str, int]:
    base = resolve_weights_for_mode(mode)
    if not path:
        return base

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Risk config file not found: {p}")

    suffix = p.suffix.lower()
    if suffix == ".json":
        with open(p, "r", encoding="utf-8") as f:
            payload = json.load(f)
    elif suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore
        except ImportError as exc:
            raise RuntimeError("YAML config requires PyYAML. Install with: pip install pyyaml") from exc
        with open(p, "r", encoding="utf-8") as f:
            payload = yaml.safe_load(f)
    else:
        raise ValueError("Risk config must be .json, .yaml, or .yml")

    if not isinstance(payload, dict):
        raise ValueError("Risk config root must be an object")

    cfg_mode = payload.get("mode") if isinstance(payload, dict) else None
    effective_mode = str(cfg_mode).strip().lower() if cfg_mode else (mode or DEFAULT_RISK_MODE)
    base = resolve_weights_for_mode(effective_mode)

    weights_obj = payload.get("weights", payload)
    if not isinstance(weights_obj, dict):
        raise ValueError("Risk config must contain an object field 'weights' or be a key/value object")

    return _normalize_weights(weights_obj, base=base)
