from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

from mscp.models import CorrelatedAsset
from mscp.parsers.nikto_parser import parse_nikto
from mscp.parsers.nmap_parser import parse_nmap_xml
from mscp.parsers.openvas_parser import parse_openvas
from mscp.parsers.wireshark_parser import parse_wireshark


def _asset_key(host: str, port: int) -> tuple[str, int]:
    return (host or "unknown", int(port or 0))


def analyze_nikto_path(path: str) -> Tuple[List[CorrelatedAsset], List[str]]:
    errors: List[str] = []
    assets_map: Dict[tuple[str, int], CorrelatedAsset] = {}
    try:
        vulns = parse_nikto(path)
    except Exception as exc:  # pragma: no cover - defensive for uploads
        return [], [str(exc)]

    for v in vulns:
        key = _asset_key(v.host, v.port)
        a = assets_map.get(key) or CorrelatedAsset(host=v.host, port=v.port, service="http")
        a.findings.append(v.item)
        a.evidence.add("web_vuln")
        assets_map[key] = a

    return list(assets_map.values()), errors


def analyze_nmap_path(path: str) -> Tuple[List[CorrelatedAsset], List[str]]:
    try:
        services = parse_nmap_xml(path)
    except Exception as exc:
        return [], [str(exc)]

    assets_map: Dict[tuple[str, int], CorrelatedAsset] = {}
    for s in services:
        key = _asset_key(s.host, s.port)
        a = assets_map.get(key) or CorrelatedAsset(host=s.host, port=s.port, service=s.service)
        a.evidence.add("open_port")
        assets_map[key] = a

    return list(assets_map.values()), []


def analyze_openvas_path(path: str) -> Tuple[List[CorrelatedAsset], List[str]]:
    try:
        findings = parse_openvas(path)
    except Exception as exc:
        return [], [str(exc)]

    assets_map: Dict[tuple[str, int], CorrelatedAsset] = {}
    for f in findings:
        key = _asset_key(f.host, f.port)
        a = assets_map.get(key) or CorrelatedAsset(host=f.host, port=f.port)
        a.cves.add(f.cve)
        a.findings.append(f.cve)
        a.evidence.add("cve")
        if f.has_exploit_hint:
            a.evidence.add("exploit")
        assets_map[key] = a

    return list(assets_map.values()), []


def analyze_wireshark_path(path: str) -> Tuple[List[CorrelatedAsset], List[str]]:
    try:
        signals = parse_wireshark(path)
    except Exception as exc:
        return [], [str(exc)]

    assets_map: Dict[tuple[str, int], CorrelatedAsset] = {}
    counts: Dict[tuple[str, int], int] = defaultdict(int)
    for s in signals:
        key = _asset_key(s.host, s.port)
        counts[key] += 1
        a = assets_map.get(key) or CorrelatedAsset(host=s.host, port=s.port)
        a.findings.append(s.signal)
        a.evidence.add("traffic_signal")
        if s.signal in {"many_http_500_responses", "tcp_rst_seen", "suspicious_traffic"}:
            # treat higher-severity traffic observations as anomalies
            a.evidence.add("traffic_anomaly")
        assets_map[key] = a

    # mark dos_indicator if sustained high count
    for key, cnt in counts.items():
        if cnt > 50:
            assets_map[key].evidence.add("dos_indicator")

    return list(assets_map.values()), []


def analyze_path_by_type(path: str, declared_type: str) -> Tuple[List[CorrelatedAsset], List[str]]:
    dt = (declared_type or "").strip().lower()
    if dt in {"nikto", "nikto_xml", "nikto.txt", "nikto.json"}:
        return analyze_nikto_path(path)
    if dt in {"nmap", "nmap_xml"}:
        return analyze_nmap_path(path)
    if dt in {"openvas", "openvas_xml"}:
        return analyze_openvas_path(path)
    if dt in {"wireshark", "tshark", "pcap", "pcapng"}:
        return analyze_wireshark_path(path)
    return [], [f"Unknown declared type: {declared_type}"]


def validate_input_for_type(path: str, declared_type: str, original_name: str = "") -> List[str]:
    """Validate file extension/header against selected scanner type."""
    errs: List[str] = []
    dt = (declared_type or "").strip().lower()
    ext = Path(original_name or path).suffix.lower()

    allowed_exts = {
        "nmap": {".xml"},
        "nikto": {".xml", ".json", ".txt", ".log"},
        "openvas": {".xml", ".json"},
        "wireshark": {".json", ".pcap", ".pcapng"},
    }

    if dt not in allowed_exts:
        return [f"Unsupported scanner type: {declared_type}"]

    if ext and ext not in allowed_exts[dt]:
        errs.append(f"Invalid file extension '{ext}' for scanner '{declared_type}'")

    try:
        with open(path, "rb") as f:
            head = f.read(4096)
    except OSError as exc:
        return [f"Cannot read file: {exc}"]

    sniff = head.decode("utf-8", errors="ignore").lower()

    if dt == "nmap" and "<nmaprun" not in sniff:
        errs.append("File content does not look like Nmap XML (<nmaprun> missing)")
    if dt == "nikto" and ext == ".xml" and "<niktoscan" not in sniff:
        errs.append("File content does not look like Nikto XML (<niktoscan> missing)")
    if dt == "openvas" and ext == ".xml" and "<report" not in sniff and "<result" not in sniff:
        errs.append("File content does not look like OpenVAS XML")
    if dt == "wireshark" and ext == ".json" and "_source" not in sniff and "packets" not in sniff:
        errs.append("File content does not look like Wireshark/tshark JSON")

    return errs
