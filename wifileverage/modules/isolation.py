"""Station (client) isolation assessment.

Many access points offer "client isolation" / "AP isolation" so that two
devices associated to the *same* SSID cannot talk to each other — important
for guest and public Wi-Fi. This module tests that control directly: from the
current foothold it looks for peer stations on the same subnet (via the ARP
cache and a bounded sweep) and probes whether they are reachable.

A reachable peer on an SSID that is supposed to isolate clients is the
finding. Runs only with ``active=True`` and stays within scope.
"""

from __future__ import annotations

from typing import List

from ..context import Context
from ..models import Finding, Host, ModuleResult, Severity
from ..utils import netaddr
from .base import Module, ACTIVE
from .reachability import Reachability


class StationIsolation(Module):
    name = "isolation"
    phase = ACTIVE
    description = "Test whether same-SSID peer stations can reach each other"

    def run(self, ctx: Context) -> ModuleResult:
        result = self.new_result()

        if not ctx.active:
            result.ok = False
            result.skipped_reason = "active probing disabled (pass --active to enable)"
            return result

        seg = ctx.current_segment
        if not seg or not seg.cidr:
            result.ok = False
            result.skipped_reason = "no local segment mapped; run the 'segment' module first"
            return result

        peers = self.select_peers(ctx)
        if not peers:
            result.ok = False
            result.skipped_reason = "no candidate peer stations found on the local segment"
            return result

        self.log.info("probing %d peer station(s) on %s", len(peers), seg.cidr)
        prober = Reachability()
        reachable: List[Host] = []
        for addr in peers:
            host = prober._probe_host(addr, ctx.port_list, ctx.timeout)
            host.via = seg.interface
            if host.reachable:
                reachable.append(host)

        result.data["peers_probed"] = len(peers)
        result.data["peers_reachable"] = [h.to_dict() for h in reachable]

        if reachable:
            addrs = ", ".join(h.address for h in reachable)
            result.add(
                Finding(
                    module=self.name,
                    title=f"Client isolation not enforced on {seg.ssid or seg.cidr}",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(reachable)} peer station(s) on the same segment are reachable "
                        f"from this client ({addrs}). Stations associated to this network can "
                        "reach one another; client/AP isolation is off or ineffective."
                    ),
                    target=seg.ssid or seg.cidr,
                    evidence={"reachable_peers": [h.to_dict() for h in reachable]},
                    recommendation="Enable client/AP isolation on the SSID, especially for guest and public networks.",
                )
            )
        else:
            result.add(
                Finding(
                    module=self.name,
                    title=f"Client isolation appears enforced on {seg.ssid or seg.cidr}",
                    severity=Severity.INFO,
                    description=(
                        f"None of the {len(peers)} candidate peer station(s) were reachable. "
                        "Consistent with working client isolation."
                    ),
                    target=seg.ssid or seg.cidr,
                )
            )
        return result

    @staticmethod
    def select_peers(ctx: Context) -> List[str]:
        """Candidate peers = in-scope hosts on the current subnet, minus self."""
        seg = ctx.current_segment
        if not seg or not seg.cidr:
            return []
        net = netaddr.parse_network(seg.cidr)
        peers: List[str] = []
        for host in netaddr.hosts(net, limit=ctx.host_limit):
            if host in (seg.ip_address, seg.gateway):
                continue
            if ctx.scope.address_in_scope(host):
                peers.append(host)
        return peers
