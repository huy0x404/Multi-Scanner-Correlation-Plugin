from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from mscp.models import CorrelatedAsset, NiktoVuln, NmapService, OpenVASCve, WiresharkSignal


def correlate(
    nmap: List[NmapService],
    nikto: List[NiktoVuln],
    openvas: List[OpenVASCve],
    wireshark: List[WiresharkSignal],
) -> List[CorrelatedAsset]:
    assets: Dict[Tuple[str, int], CorrelatedAsset] = {}

    for svc in nmap:
        key = (svc.host, svc.port)
        assets[key] = CorrelatedAsset(host=svc.host, port=svc.port, service=svc.service)
        assets[key].evidence.add("open_port")

    for finding in nikto:
        key = (finding.host, finding.port)
        if key not in assets:
            assets[key] = CorrelatedAsset(host=finding.host, port=finding.port)
        assets[key].findings.append(f"Nikto: {finding.item}")
        assets[key].evidence.add("web_vuln")

    for cve in openvas:
        key = (cve.host, cve.port)
        if key not in assets:
            assets[key] = CorrelatedAsset(host=cve.host, port=cve.port)
        assets[key].cves.add(cve.cve)
        assets[key].evidence.add("cve")
        if cve.has_exploit_hint:
            assets[key].evidence.add("exploit")

    grouped_signals = defaultdict(list)
    for sig in wireshark:
        grouped_signals[(sig.host, sig.port)].append(sig.signal)

    for key, signals in grouped_signals.items():
        if key not in assets:
            assets[key] = CorrelatedAsset(host=key[0], port=key[1])
        for sig in signals:
            assets[key].findings.append(f"Traffic: {sig}")
        assets[key].evidence.add("traffic_signal")

    return sorted(assets.values(), key=lambda x: (x.host, x.port))
