"""Shared run context passed to every module."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .models import AccessPoint, Segment
from .scope import Scope


@dataclass
class Context:
    """Everything a module needs, plus the running state of the engagement."""

    scope: Scope
    interface: Optional[str] = None
    active: bool = False
    port_list: List[int] = field(default_factory=lambda: [22, 80, 443, 445, 3389, 8080])
    timeout: float = 1.5
    host_limit: int = 256
    workers: int = 64  # concurrent host probes

    # Populated as earlier modules run, read by later ones.
    access_points: List[AccessPoint] = field(default_factory=list)
    segments: List[Segment] = field(default_factory=list)

    @property
    def current_segment(self) -> Optional[Segment]:
        return self.segments[0] if self.segments else None
