from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from mscp.models import OpenVASCve

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def parse_openvas_json(path: str | Path) -> List[OpenVASCve]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        entries = data.get("results", [])
    elif isinstance(data, list):
        entries = data
    else:
        entries = []

    findings: List[OpenVASCve] = []

    for row in entries:
        host = str(row.get("host", "unknown"))
        port = int(row.get("port", 0))

        text_blob = " ".join(
            [
                str(row.get("name", "")),
                str(row.get("description", "")),
                str(row.get("nvt", "")),
                str(row.get("cve", "")),
            ]
        )

        has_exploit_hint = any(
            kw in text_blob.lower()
            for kw in ("exploit available", "metasploit", "remote code execution", "weaponized")
        )

        cves = set(match.upper() for match in _CVE_RE.findall(text_blob))
        for cve in cves:
            findings.append(OpenVASCve(host=host, port=port, cve=cve, has_exploit_hint=has_exploit_hint))

    return findings


def _parse_port(value: str) -> int:
    if not value:
        return 0
    token = value.split("/")[0].strip()
    try:
        return int(token)
    except ValueError:
        return 0


def parse_openvas_xml(path: str | Path) -> List[OpenVASCve]:
    findings: List[OpenVASCve] = []
    tree = ET.parse(str(path))
    root = tree.getroot()

    for result in root.findall(".//result"):
        host = (result.findtext("host") or "unknown").strip()
        port = _parse_port((result.findtext("port") or "0").strip())

        nvt = result.find("nvt")
        nvt_name = nvt.findtext("name", default="") if nvt is not None else ""
        nvt_cve = nvt.findtext("cve", default="") if nvt is not None else ""
        nvt_tags = nvt.findtext("tags", default="") if nvt is not None else ""

        ref_cves: List[str] = []
        if nvt is not None:
            for ref in nvt.findall(".//ref"):
                if str(ref.attrib.get("type", "")).lower() == "cve":
                    rid = ref.attrib.get("id", "")
                    if rid:
                        ref_cves.append(rid)

        description = result.findtext("description", default="")
        text_blob = " ".join([nvt_name, nvt_cve, nvt_tags, description, " ".join(ref_cves)])

        has_exploit_hint = any(
            kw in text_blob.lower()
            for kw in ("exploit available", "metasploit", "remote code execution", "weaponized")
        )

        cves = set(match.upper() for match in _CVE_RE.findall(text_blob))
        for cve in cves:
            findings.append(OpenVASCve(host=host, port=port, cve=cve, has_exploit_hint=has_exploit_hint))

    return findings


def parse_openvas(path: str | Path) -> List[OpenVASCve]:
    suffix = Path(path).suffix.lower()
    if suffix == ".xml":
        return parse_openvas_xml(path)
    return parse_openvas_json(path)
