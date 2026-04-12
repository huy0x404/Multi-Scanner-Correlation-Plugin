from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict

from mscp.parsers.nikto_parser import parse_nikto
from mscp.parsers.nmap_parser import parse_nmap_xml
from mscp.parsers.openvas_parser import parse_openvas
from mscp.parsers.wireshark_parser import parse_wireshark


@dataclass
class ScannerPlugin:
    name: str
    parser: Callable[[str | Path], Any]


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: Dict[str, ScannerPlugin] = {}

    def register(self, plugin: ScannerPlugin) -> None:
        self._plugins[plugin.name] = plugin

    def run(self, plugin_name: str, input_path: str | Path) -> Any:
        plugin = self._plugins.get(plugin_name)
        if plugin is None:
            raise ValueError(f"Unknown plugin: {plugin_name}")
        return plugin.parser(input_path)

    @classmethod
    def default(cls) -> "PluginRegistry":
        registry = cls()
        registry.register(ScannerPlugin(name="nmap", parser=parse_nmap_xml))
        registry.register(ScannerPlugin(name="nikto", parser=parse_nikto))
        registry.register(ScannerPlugin(name="openvas", parser=parse_openvas))
        registry.register(ScannerPlugin(name="wireshark", parser=parse_wireshark))
        return registry
