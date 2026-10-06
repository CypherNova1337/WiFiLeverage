"""Assessment modules.

Each module is a self-contained unit of work that takes the shared
:class:`~wifileverage.context.Context` and returns a
:class:`~wifileverage.models.ModuleResult`.
"""

from .base import Module, PASSIVE, ACTIVE
from .wireless_recon import WirelessRecon
from .segment_discovery import SegmentDiscovery
from .reachability import Reachability
from .isolation import StationIsolation

# Registry keyed by the short name used on the CLI (``--only``, ``--phases``).
REGISTRY = {
    m.name: m
    for m in (WirelessRecon, SegmentDiscovery, Reachability, StationIsolation)
}

__all__ = [
    "Module",
    "PASSIVE",
    "ACTIVE",
    "WirelessRecon",
    "SegmentDiscovery",
    "Reachability",
    "StationIsolation",
    "REGISTRY",
]
