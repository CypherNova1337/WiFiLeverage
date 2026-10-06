"""Discover the network segment the tester currently has a foothold on.

Reads the local interface addressing, default gateway, DNS and visible ARP
neighbours using ``ip``. This establishes *where you are* before any
cross-segment reachability testing: the subnet you were handed by DHCP, the
gateway that fronts it, and the neighbours already in the ARP cache.

All of this is local host introspection — no traffic is generated.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional

from ..context import Context
from ..models import Finding, ModuleResult, Segment, Severity
from ..utils import shell
from .base import Module, PASSIVE


class SegmentDiscovery(Module):
    name = "segment"
    phase = PASSIVE
    description = "Map the local subnet, gateway, DNS and ARP neighbours"

    def run(self, ctx: Context) -> ModuleResult:
        result = self.new_result()

        if not shell.tool_available("ip"):
            result.ok = False
            result.skipped_reason = "the 'ip' command is required but was not found on PATH"
            self.log.warning(result.skipped_reason)
            return result

        iface = ctx.interface or self._default_iface()
        if not iface:
            result.ok = False
            result.skipped_reason = "could not determine an interface to inspect"
            return result

        seg = Segment(interface=iface)
        addr_res = shell.run(["ip", "-o", "-4", "addr", "show", "dev", iface])
        if addr_res.ok:
            ip, cidr = self.parse_ip_addr(addr_res.stdout)
            seg.ip_address, seg.cidr = ip, cidr

        route_res = shell.run(["ip", "-4", "route", "show", "default"])
        if route_res.ok:
            seg.gateway = self.parse_default_gateway(route_res.stdout)

        seg.dns = self._read_resolvers()

        neigh_res = shell.run(["ip", "-4", "neigh", "show"])
        neighbours: List[str] = []
        if neigh_res.ok:
            neighbours = self.parse_neighbours(neigh_res.stdout, seg.cidr)

        ctx.segments.append(seg)
        result.data["segment"] = seg.to_dict()
        result.data["neighbours"] = neighbours

        if seg.cidr:
            self.log.info("foothold on %s via %s (gw %s)", seg.cidr, iface, seg.gateway or "?")
            result.add(
                Finding(
                    module=self.name,
                    title=f"Foothold established on {seg.cidr}",
                    severity=Severity.INFO,
                    description=(
                        f"Associated on interface {iface} with address {seg.ip_address}. "
                        f"Gateway {seg.gateway or 'unknown'}, {len(neighbours)} neighbour(s) "
                        "already visible in the ARP cache."
                    ),
                    target=seg.cidr,
                    evidence={"segment": seg.to_dict(), "neighbours": neighbours},
                )
            )
        else:
            result.ok = False
            result.skipped_reason = f"interface {iface} has no IPv4 address (are you associated?)"
        return result

    # ---- helpers ------------------------------------------------------
    def _default_iface(self) -> Optional[str]:
        res = shell.run(["ip", "-4", "route", "show", "default"])
        if not res.ok:
            return None
        m = re.search(r"\bdev\s+(\S+)", res.stdout)
        return m.group(1) if m else None

    def _read_resolvers(self) -> List[str]:
        path = Path("/etc/resolv.conf")
        if not path.is_file():
            return []
        servers = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    servers.append(parts[1])
        return servers

    # ---- parsers (pure, unit-tested) ---------------------------------
    @staticmethod
    def parse_ip_addr(output: str):
        """Return ``(ip, cidr)`` from ``ip -o -4 addr show`` output."""
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", output)
        if not m:
            return None, None
        ip = m.group(1)
        prefix = m.group(2)
        # Normalise to network/prefix.
        import ipaddress

        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        return ip, str(net)

    @staticmethod
    def parse_default_gateway(output: str) -> Optional[str]:
        m = re.search(r"default\s+via\s+(\d+\.\d+\.\d+\.\d+)", output)
        return m.group(1) if m else None

    @staticmethod
    def parse_neighbours(output: str, cidr: Optional[str]) -> List[str]:
        import ipaddress

        net = None
        if cidr:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                net = None
        out: List[str] = []
        for line in output.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s", line.strip())
            if not m:
                continue
            addr = m.group(1)
            if "FAILED" in line or "INCOMPLETE" in line:
                continue
            if net is not None:
                try:
                    if ipaddress.ip_address(addr) not in net:
                        continue
                except ValueError:
                    continue
            out.append(addr)
        return sorted(set(out))
