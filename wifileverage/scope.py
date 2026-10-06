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
from typing import Dict, List, Optional, Tuple

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

    # Named security zones (zone name -> list of CIDRs) and the intended
    # isolation policy. By default every cross-zone flow is expected to be
    # DENIED (isolated); `policy_allow` lists the (from_zone, to_zone) flows
    # that are permitted. The policy engine flags any observed reachability
    # that is not permitted as a segmentation violation.
    zones: Dict[str, List[str]] = field(default_factory=dict)
    policy_allow: List[Tuple[str, str]] = field(default_factory=list)
    # True once a `policy:` block is present. When set, every cross-zone flow
    # not in `policy_allow` is a violation (default-deny / full isolation),
    # even if the allow-list is empty. Without a policy block, nothing is
    # asserted as a violation.
    policy_defined: bool = False

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
        zones_raw = raw.get("zones") or {}
        if not isinstance(zones_raw, dict):
            raise ScopeError("'zones' must be a mapping of zone-name -> list of CIDRs")
        zones = {str(name): [str(c) for c in (cidrs or [])] for name, cidrs in zones_raw.items()}

        scope = cls(
            engagement=str(raw.get("engagement", "")),
            client=str(raw.get("client", "")),
            ssids=[str(s) for s in (raw.get("ssids") or [])],
            target_cidrs=[str(c) for c in (raw.get("target_cidrs") or [])],
            exclude_cidrs=[str(c) for c in (raw.get("exclude_cidrs") or [])],
            notes=str(raw.get("notes", "")),
            zones=zones,
            policy_allow=cls._parse_policy(raw.get("policy")),
            policy_defined="policy" in raw and raw.get("policy") is not None,
        )
        # Validate CIDRs eagerly so a typo fails loudly (as a ScopeError) at
        # load time rather than deep inside a probe later.
        scope._validate_cidrs()
        return scope

    def _validate_cidrs(self) -> None:
        def _check(label: str, cidrs: List[str]) -> None:
            try:
                netaddr.parse_networks(cidrs)
            except ValueError as exc:
                raise ScopeError(f"invalid CIDR in {label}: {exc}") from exc

        _check("target_cidrs", self.target_cidrs)
        _check("exclude_cidrs", self.exclude_cidrs)
        for name, cidrs in self.zones.items():
            _check(f"zone {name!r}", cidrs)

    @staticmethod
    def _parse_policy(policy_raw) -> List[Tuple[str, str]]:
        """Parse the optional ``policy.allow`` list of permitted flows."""
        if not policy_raw:
            return []
        if not isinstance(policy_raw, dict):
            raise ScopeError("'policy' must be a mapping with an 'allow' list")
        allow: List[Tuple[str, str]] = []
        for rule in policy_raw.get("allow") or []:
            if not isinstance(rule, dict) or "from" not in rule or "to" not in rule:
                raise ScopeError("each policy.allow rule needs 'from' and 'to' zone names")
            allow.append((str(rule["from"]), str(rule["to"])))
        return allow

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
            zones={k: list(v) for k, v in self.zones.items()},
            policy_allow=list(self.policy_allow),
            policy_defined=self.policy_defined,
        )
        if include:
            new.target_cidrs.extend(include)
        if exclude:
            new.exclude_cidrs.extend(exclude)
        if ssids:
            new.ssids.extend(ssids)
        new._validate_cidrs()
        return new

    # ---- zones & policy ----------------------------------------------
    @property
    def has_zones(self) -> bool:
        return bool(self.zones)

    def probe_cidrs(self) -> List[str]:
        """CIDRs eligible for active probing.

        Explicit ``target_cidrs`` win; otherwise the union of all zone CIDRs is
        used, so declaring zones is enough to make them testable without
        repeating the ranges under ``target_cidrs``.
        """
        if self.target_cidrs:
            return list(self.target_cidrs)
        cidrs: List[str] = []
        for zone_cidrs in self.zones.values():
            cidrs.extend(zone_cidrs)
        return cidrs

    def zone_of(self, address: str) -> Optional[str]:
        """Return the name of the zone *address* belongs to, if any.

        The most specific (longest-prefix) matching zone wins, so overlapping
        zone definitions resolve deterministically.
        """
        best_zone = None
        best_prefix = -1
        for name, cidrs in self.zones.items():
            for net in netaddr.parse_networks(cidrs):
                try:
                    if netaddr.address_in_networks(address, [net]) and net.prefixlen > best_prefix:
                        best_zone = name
                        best_prefix = net.prefixlen
                except ValueError:
                    continue
        return best_zone

    def flow_allowed(self, from_zone: str, to_zone: str) -> bool:
        """Return True if traffic from *from_zone* to *to_zone* is permitted.

        Same-zone traffic is always allowed; otherwise the flow must appear in
        the policy allow-list. With no policy defined at all, nothing is
        asserted as a violation (``flow_allowed`` returns True).
        """
        if from_zone == to_zone:
            return True
        if not self.policy_defined:
            return True
        return (from_zone, to_zone) in self.policy_allow

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
            f"zones={len(self.zones)} policy_allow={len(self.policy_allow)} "
            f"restricts_targets={self.restricts_targets}"
        )
