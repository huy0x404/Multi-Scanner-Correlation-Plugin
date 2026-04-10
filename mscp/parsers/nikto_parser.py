from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from mscp.models import NiktoVuln

_TARGET_IP_RE = re.compile(r"^\+\s*Target\s+IP:\s*(.+)$", re.IGNORECASE)
_TARGET_HOST_RE = re.compile(r"^\+\s*Target\s+Hostname:\s*(.+)$", re.IGNORECASE)
_TARGET_PORT_RE = re.compile(r"^\+\s*Target\s+Port:\s*(\d+)", re.IGNORECASE)
_OSVDB_LINE_RE = re.compile(r"OSVDB-(\d+)", re.IGNORECASE)
_META_PREFIXES = (
    "+ Target IP:",
    "+ Target Hostname:",
    "+ Target Port:",
    "+ Start Time:",
    "+ End Time:",
    "+ Server:",
)


def parse_nikto_json(path: str | Path) -> List[NiktoVuln]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulns: List[NiktoVuln] = []

    if isinstance(data, dict) and "vulnerabilities" in data:
        entries = data["vulnerabilities"]
    elif isinstance(data, list):
        entries = data
    else:
        entries = []

    for item in entries:
        host = str(item.get("host", "unknown"))
        port = int(item.get("port", 80))
        detail = str(item.get("msg") or item.get("description") or "Nikto finding")
        osvdb = item.get("osvdb")

        vulns.append(NiktoVuln(host=host, port=port, item=detail, osvdb=str(osvdb) if osvdb else None))

    return vulns


def parse_nikto_txt(path: str | Path) -> List[NiktoVuln]:
    vulns: List[NiktoVuln] = []
    current_host = "unknown"
    current_port = 80

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue

            ip_match = _TARGET_IP_RE.match(line)
            if ip_match:
                current_host = ip_match.group(1).strip()
                continue

            host_match = _TARGET_HOST_RE.match(line)
            if host_match and current_host == "unknown":
                current_host = host_match.group(1).strip()
                continue

            port_match = _TARGET_PORT_RE.match(line)
            if port_match:
                current_port = int(port_match.group(1))
                continue

            if not line.startswith("+"):
                continue

            if line.startswith(_META_PREFIXES):
                continue

            if "OSVDB-" not in line and ":" not in line:
                continue

            osvdb_match = _OSVDB_LINE_RE.search(line)
            osvdb = osvdb_match.group(1) if osvdb_match else None
            message = line.lstrip("+").strip()
            vulns.append(NiktoVuln(host=current_host, port=current_port, item=message, osvdb=osvdb))

    return vulns


def parse_nikto(path: str | Path) -> List[NiktoVuln]:
    suffix = Path(path).suffix.lower()
    if suffix in {".txt", ".log"}:
        return parse_nikto_txt(path)
    return parse_nikto_json(path)
