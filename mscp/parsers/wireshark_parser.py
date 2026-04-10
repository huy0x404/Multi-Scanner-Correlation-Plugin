from __future__ import annotations

import json
from pathlib import Path
from typing import List

from mscp.models import WiresharkSignal


# Input is expected from tshark JSON export (possibly simplified by user script).
def parse_wireshark_json(path: str | Path) -> List[WiresharkSignal]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        packets = data.get("packets", [])
    elif isinstance(data, list):
        packets = data
    else:
        packets = []

    signals: List[WiresharkSignal] = []
    for pkt in packets:
        host = str(pkt.get("host", pkt.get("dst", "unknown")))
        port = int(pkt.get("port", pkt.get("dst_port", 0)))
        flag = str(pkt.get("signal", "suspicious_traffic"))
        signals.append(WiresharkSignal(host=host, port=port, signal=flag))

    return signals
