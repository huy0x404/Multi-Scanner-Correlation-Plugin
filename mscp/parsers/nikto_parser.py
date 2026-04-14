from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, List

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
_NIKTOSCAN_BLOCK_RE = re.compile(r"<niktoscan\b[\s\S]*?</niktoscan>", re.IGNORECASE)


def _to_int(value: Any, default: int = 80) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _normalize_host(value: Any) -> str:
    host = str(value or "").strip()
    return host if host else "unknown"


def _extract_osvdb(message: str) -> str | None:
    match = _OSVDB_LINE_RE.search(message)
    if match:
        return match.group(1)
    return None


def _normalize_message(item: dict[str, Any]) -> str:
    msg = str(item.get("msg") or item.get("description") or item.get("item") or "").strip()
    if msg:
        return msg

    # Some Nikto JSON variants provide URI + method + summary instead of msg.
    uri = str(item.get("uri") or item.get("path") or "").strip()
    method = str(item.get("method") or "").strip().upper()
    summary = str(item.get("summary") or item.get("title") or "Nikto finding").strip()

    if uri and method:
        return f"{method} {uri} - {summary}"
    if uri:
        return f"{uri} - {summary}"
    return summary


def _append_nikto_vuln(vulns: List[NiktoVuln], seen: set[tuple[str, int, str, str | None]], item: dict[str, Any]) -> None:
    host = _normalize_host(item.get("host") or item.get("ip") or item.get("hostname"))
    port = _to_int(item.get("port") or item.get("target_port") or item.get("targetport"), default=80)
    detail = _normalize_message(item)

    osvdb_raw = item.get("osvdb")
    osvdb = str(osvdb_raw).strip() if osvdb_raw is not None else None
    if osvdb in {"", "0", "None", "none"}:
        osvdb = None
    if osvdb is None:
        osvdb = _extract_osvdb(detail)

    key = (host, port, detail, osvdb)
    if key in seen:
        return

    seen.add(key)
    vulns.append(NiktoVuln(host=host, port=port, item=detail, osvdb=osvdb))


def _coerce_json_entries(data: Any) -> List[dict[str, Any]]:
    # Supported shapes:
    # 1) {"vulnerabilities": [{...}]}
    # 2) [{...}] simple list
    # 3) {"hosts": [{"ip":..., "port":..., "vulnerabilities": [...]}, ...]}
    # 4) {"results": [...]} or {"findings": [...]} variants
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]

    if not isinstance(data, dict):
        return []

    entries: List[dict[str, Any]] = []

    top_level = data.get("vulnerabilities") or data.get("results") or data.get("findings")
    if isinstance(top_level, list):
        entries.extend([x for x in top_level if isinstance(x, dict)])

    hosts = data.get("hosts")
    if isinstance(hosts, list):
        for host_item in hosts:
            if not isinstance(host_item, dict):
                continue
            host = host_item.get("host") or host_item.get("ip") or host_item.get("hostname")
            port = host_item.get("port") or host_item.get("target_port") or host_item.get("targetport")

            host_findings = (
                host_item.get("vulnerabilities")
                or host_item.get("findings")
                or host_item.get("items")
                or host_item.get("results")
                or []
            )
            if not isinstance(host_findings, list):
                continue

            for f in host_findings:
                if not isinstance(f, dict):
                    continue
                merged = dict(f)
                merged.setdefault("host", host)
                merged.setdefault("port", port)
                entries.append(merged)

    return entries


def parse_nikto_json(path: str | Path) -> List[NiktoVuln]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    vulns: List[NiktoVuln] = []
    seen: set[tuple[str, int, str, str | None]] = set()
    entries = _coerce_json_entries(data)

    for item in entries:
        _append_nikto_vuln(vulns, seen, item)

    return vulns


def parse_nikto_txt(path: str | Path) -> List[NiktoVuln]:
    vulns: List[NiktoVuln] = []
    seen: set[tuple[str, int, str, str | None]] = set()
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

            message = line.lstrip("+").strip()
            _append_nikto_vuln(
                vulns,
                seen,
                {
                    "host": current_host,
                    "port": current_port,
                    "msg": message,
                },
            )

    return vulns


def _iter_nikto_xml_roots(raw: str) -> List[ET.Element]:
    roots: List[ET.Element] = []

    blocks = _NIKTOSCAN_BLOCK_RE.findall(raw)
    if blocks:
        for block in blocks:
            try:
                roots.append(ET.fromstring(block))
            except ET.ParseError:
                continue
        return roots

    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return []

    return [root]


def parse_nikto_xml(path: str | Path) -> List[NiktoVuln]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    vulns: List[NiktoVuln] = []
    seen: set[tuple[str, int, str, str | None]] = set()

    for root in _iter_nikto_xml_roots(raw):
        for details in root.findall(".//scandetails"):
            host = details.attrib.get("targetip") or details.attrib.get("targethostname") or "unknown"
            port = _to_int(details.attrib.get("targetport"), default=80)

            for item in details.findall("item"):
                description = (item.findtext("description") or "").strip()
                uri = (item.findtext("uri") or "").strip()
                method = str(item.attrib.get("method") or "").strip().upper()
                osvdb = str(item.attrib.get("osvdbid") or "").strip()

                _append_nikto_vuln(
                    vulns,
                    seen,
                    {
                        "host": host,
                        "port": port,
                        "msg": description,
                        "uri": uri,
                        "method": method,
                        "osvdb": osvdb,
                    },
                )

    return vulns


def parse_nikto(path: str | Path) -> List[NiktoVuln]:
    suffix = Path(path).suffix.lower()
    if suffix in {".txt", ".log"}:
        return parse_nikto_txt(path)
    if suffix == ".xml":
        return parse_nikto_xml(path)
    return parse_nikto_json(path)
