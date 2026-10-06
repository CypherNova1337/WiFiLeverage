"""Optional engagement scope — keeps a run inside its targets.

Scope is a convenience, not a gate: WiFiLeverage runs fine without one. When
you *do* supply a scope file (``-S scope.yaml``) or inline include/exclude
rules, every active probe is filtered through it so the tool stays inside the
networks and SSIDs you listed and never touches an excluded one. This mirrors
the rules-of-engagement discipline of a real assessment and is the same
scope-aware behaviour used across the rest of the toolkit.

With no scope loaded, an empty :class:`Scope` is used: nothing is excluded and
membership checks fall back to "whatever you explicitly targeted on the command
line is in scope".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

from .utils import netaddr

log = logging.getLogger(__name__)


class ScopeError(Exception):
    """Raised when a scope file is missing or malformed."""


@dataclass
class Scope:
    """Targets and exclusions for one assessment. All fields are optional."""

    engagement: str = ""
    client: str = ""
    ssids: List[str] = field(default_factory=list)
    target_cidrs: List[str] = field(default_factory=list)
    exclude_cidrs: List[str] = field(default_factory=list)
    notes: str = ""

    # ---- construction -------------------------------------------------
    @classmethod
    def empty(cls) -> "Scope":
        """A permissive scope: nothing excluded, no target restriction."""
        return cls()

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        p = Path(path)
        if not p.is_file():
            raise ScopeError(f"scope file not found: {p}")
        try:
            raw = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:
            raise ScopeError(f"could not parse scope file: {exc}") from exc
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict) -> "Scope":
        if not isinstance(raw, dict):
            raise ScopeError("scope file must be a mapping")
        scope = cls(
            engagement=str(raw.get("engagement", "")),
            client=str(raw.get("client", "")),
            ssids=[str(s) for s in (raw.get("ssids") or [])],
            target_cidrs=[str(c) for c in (raw.get("target_cidrs") or [])],
            exclude_cidrs=[str(c) for c in (raw.get("exclude_cidrs") or [])],
            notes=str(raw.get("notes", "")),
        )
        # Validate CIDRs eagerly so a typo fails loudly at load time.
        netaddr.parse_networks(scope.target_cidrs)
        netaddr.parse_networks(scope.exclude_cidrs)
        return scope

    # ---- derived ------------------------------------------------------
    @property
    def restricts_targets(self) -> bool:
        """True if the scope narrows targets (has any include rules)."""
        return bool(self.target_cidrs or self.ssids)

    def merge_inline(
        self,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        ssids: Optional[List[str]] = None,
    ) -> "Scope":
        """Return a copy with inline CLI include/exclude/ssid rules merged in."""
        new = Scope(
            engagement=self.engagement,
            client=self.client,
            ssids=list(self.ssids),
            target_cidrs=list(self.target_cidrs),
            exclude_cidrs=list(self.exclude_cidrs),
            notes=self.notes,
        )
        if include:
            new.target_cidrs.extend(include)
        if exclude:
            new.exclude_cidrs.extend(exclude)
        if ssids:
            new.ssids.extend(ssids)
        netaddr.parse_networks(new.target_cidrs)
        netaddr.parse_networks(new.exclude_cidrs)
        return new

    # ---- membership tests --------------------------------------------
    def ssid_in_scope(self, ssid: str) -> bool:
        """SSID is in scope if no SSID list is set, or it is listed."""
        if not self.ssids:
            return True
        return ssid in self.ssids

    def address_in_scope(self, address: str) -> bool:
        """An address is in scope unless excluded; if include rules exist it
        must also match one of them."""
        if netaddr.address_in_networks(address, netaddr.parse_networks(self.exclude_cidrs)):
            return False
        if not self.target_cidrs:
            return True
        return netaddr.address_in_networks(address, netaddr.parse_networks(self.target_cidrs))

    def network_in_scope(self, cidr: str) -> bool:
        net = netaddr.parse_network(cidr)
        if any(netaddr.networks_overlap(net, ex) for ex in netaddr.parse_networks(self.exclude_cidrs)):
            return False
        if not self.target_cidrs:
            return True
        return any(netaddr.networks_overlap(net, t) for t in netaddr.parse_networks(self.target_cidrs))

    def summary(self) -> str:
        label = self.engagement or "(unnamed)"
        return (
            f"engagement={label!r} client={self.client or '-'!r} "
            f"ssids={len(self.ssids)} target_cidrs={len(self.target_cidrs)} "
            f"exclude_cidrs={len(self.exclude_cidrs)} "
            f"restricts_targets={self.restricts_targets}"
        )
