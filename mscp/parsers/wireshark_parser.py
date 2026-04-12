from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, List

from mscp.models import WiresharkSignal


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _extract_from_tshark_packet(pkt: dict) -> WiresharkSignal | None:
    layers = pkt.get("_source", {}).get("layers", {})
    if not isinstance(layers, dict):
        return None

    ip_layer = layers.get("ip", {})
    ipv6_layer = layers.get("ipv6", {})

    host = "unknown"
    if isinstance(ip_layer, dict):
        host = str(ip_layer.get("ip.dst", ip_layer.get("ip.src", host)))
    elif isinstance(ipv6_layer, dict):
        host = str(ipv6_layer.get("ipv6.dst", ipv6_layer.get("ipv6.src", host)))

    port = 0
    signal = "suspicious_traffic"

    tcp_layer = layers.get("tcp", {})
    if isinstance(tcp_layer, dict):
        port = _to_int(tcp_layer.get("tcp.dstport", tcp_layer.get("tcp.srcport", 0)))
        flags = str(tcp_layer.get("tcp.flags.str", "")).upper()
        if "RST" in flags:
            signal = "tcp_rst_seen"

    udp_layer = layers.get("udp", {})
    if port == 0 and isinstance(udp_layer, dict):
        port = _to_int(udp_layer.get("udp.dstport", udp_layer.get("udp.srcport", 0)))
        signal = "udp_traffic"

    http_layer = layers.get("http", {})
    if isinstance(http_layer, dict):
        status_code = _to_int(http_layer.get("http.response.code", 0))
        if status_code >= 500:
            signal = "many_http_500_responses"

    if host == "unknown" and port == 0:
        return None

    return WiresharkSignal(host=host, port=port, signal=signal)


def _parse_packets(data: Any) -> List[WiresharkSignal]:
    if isinstance(data, dict):
        packets = data.get("packets", [])
    elif isinstance(data, list):
        packets = data
    else:
        packets = []

    signals: List[WiresharkSignal] = []
    for pkt in packets:
        if isinstance(pkt, dict) and "_source" in pkt:
            parsed = _extract_from_tshark_packet(pkt)
            if parsed is not None:
                signals.append(parsed)
                continue

        if not isinstance(pkt, dict):
            continue

        host = str(pkt.get("host", pkt.get("dst", "unknown")))
        port = _to_int(pkt.get("port", pkt.get("dst_port", 0)))
        flag = str(pkt.get("signal", "suspicious_traffic"))

        if host == "unknown" and port == 0:
            continue

        signals.append(WiresharkSignal(host=host, port=port, signal=flag))

    return signals


def parse_wireshark_json(path: str | Path) -> List[WiresharkSignal]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return _parse_packets(data)


def parse_wireshark_pcap(path: str | Path) -> List[WiresharkSignal]:
    try:
        proc = subprocess.run(
            ["tshark", "-r", str(path), "-T", "json"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("tshark not found. Install Wireshark/tshark and ensure tshark is in PATH.") from exc
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() if exc.stderr else "unknown error"
        raise RuntimeError(f"tshark failed: {stderr}") from exc

    data = json.loads(proc.stdout or "[]")
    return _parse_packets(data)


def parse_wireshark(path: str | Path) -> List[WiresharkSignal]:
    suffix = Path(path).suffix.lower()
    if suffix in {".pcap", ".pcapng"}:
        return parse_wireshark_pcap(path)
    return parse_wireshark_json(path)
