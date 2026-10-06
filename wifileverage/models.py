"""Data models shared across modules and the reporter."""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


class Severity(enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class Finding:
    """A single observation produced by a module.

    Findings are the assessment output. For a segmentation engagement, a
    *reachable* path that should have been isolated is the interesting
    finding; an isolated boundary is recorded as INFO evidence that the
    control works.
    """

    module: str
    title: str
    severity: Severity
    description: str
    target: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class AccessPoint:
    """An observed wireless access point / BSS."""

    ssid: str
    bssid: str
    channel: Optional[int] = None
    frequency_mhz: Optional[int] = None
    signal_dbm: Optional[float] = None
    security: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Segment:
    """A network segment the tester currently has a foothold on."""

    interface: str
    ip_address: Optional[str] = None
    cidr: Optional[str] = None
    gateway: Optional[str] = None
    dns: List[str] = field(default_factory=list)
    dhcp_server: Optional[str] = None
    ssid: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Host:
    """A host discovered during reachability assessment."""

    address: str
    reachable: bool = False
    rtt_ms: Optional[float] = None
    open_ports: List[int] = field(default_factory=list)
    mac: Optional[str] = None
    via: Optional[str] = None  # which segment/interface observed it

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    """Everything a module produced in one run."""

    module: str
    ok: bool = True
    skipped_reason: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "ok": self.ok,
            "skipped_reason": self.skipped_reason,
            "findings": [f.to_dict() for f in self.findings],
            "data": self.data,
        }
