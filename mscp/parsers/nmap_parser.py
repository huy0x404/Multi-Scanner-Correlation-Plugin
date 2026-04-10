from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List

from mscp.models import NmapService


def parse_nmap_xml(path: str | Path) -> List[NmapService]:
    services: List[NmapService] = []
    tree = ET.parse(str(path))
    root = tree.getroot()

    for host in root.findall("host"):
        addr_node = host.find("address")
        if addr_node is None:
            continue
        ip = addr_node.attrib.get("addr", "unknown")

        ports_node = host.find("ports")
        if ports_node is None:
            continue

        for port in ports_node.findall("port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            try:
                port_id = int(port.attrib.get("portid", "0"))
            except ValueError:
                continue

            svc_node = port.find("service")
            service_name = "unknown"
            if svc_node is not None:
                service_name = svc_node.attrib.get("name", "unknown")

            services.append(NmapService(host=ip, port=port_id, service=service_name))

    return services
