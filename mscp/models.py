from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class NmapService:
    host: str
    port: int
    service: str


@dataclass
class NiktoVuln:
    host: str
    port: int
    item: str
    osvdb: str | None = None


@dataclass
class OpenVASCve:
    host: str
    port: int
    cve: str
    has_exploit_hint: bool = False


@dataclass
class WiresharkSignal:
    host: str
    port: int
    signal: str


@dataclass
class CorrelatedAsset:
    host: str
    port: int
    service: str = "unknown"
    findings: List[str] = field(default_factory=list)
    cves: Set[str] = field(default_factory=set)
    evidence: Set[str] = field(default_factory=set)
    score: int = 0
    risk: str = "LOW"
    reason: str = ""

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "findings": self.findings,
            "cves": sorted(self.cves),
            "evidence": sorted(self.evidence),
            "score": self.score,
            "risk": self.risk,
            "reason": self.reason,
        }
