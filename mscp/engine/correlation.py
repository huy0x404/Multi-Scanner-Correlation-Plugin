from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Tuple

from mscp.models import CorrelatedAsset, NiktoVuln, NmapService, OpenVASCve, WiresharkSignal


_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_LOW_VALUE_SIGNALS = {"suspicious_traffic", "udp_traffic", "tcp_rst_seen"}
_WEB_PORTS = {80, 443, 8080, 8443}


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
        host, port = key
        counts = Counter(signals)
        total_events = sum(counts.values())

        # Skip noisy local loopback chatter unless volume is very high.
        if host in _LOOPBACK_HOSTS and set(counts).issubset(_LOW_VALUE_SIGNALS) and total_events < 1000:
            continue

        if key not in assets:
            assets[key] = CorrelatedAsset(host=host, port=port)

        # Summarize repeated traffic patterns into actionable counts.
        for sig, count in sorted(counts.items()):
            if count > 1:
                assets[key].findings.append(f"Traffic: {sig} x{count}")
            else:
                assets[key].findings.append(f"Traffic: {sig}")

        assets[key].evidence.add("traffic_signal")

        # Elevate risk when traffic volume indicates endpoint stress or DoS-like pressure.
        if total_events >= 300:
            assets[key].findings.append(f"Traffic: high_volume x{total_events}")
            assets[key].evidence.add("traffic_anomaly")
        if total_events >= 3000:
            assets[key].findings.append(f"Traffic: potential_dos x{total_events}")
            assets[key].evidence.add("dos_indicator")

        # Web endpoints under sustained heavy load are treated as DoS candidates earlier.
        if port in _WEB_PORTS and total_events >= 1000:
            assets[key].findings.append(f"Traffic: web_dos_candidate x{total_events}")
            assets[key].evidence.add("dos_indicator")

    return sorted(assets.values(), key=lambda x: (x.host, x.port))
