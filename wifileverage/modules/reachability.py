"""Cross-segment reachability assessment — the core of the toolkit.

Segmentation is a control: a guest SSID is supposed to be walled off from the
corporate VLAN, an IoT network from the workstations, one tenant from another.
This module *validates that wall* from the foothold established by the
``segment`` module.

For every in-scope target that lives **outside** the current segment, it
performs an unprivileged TCP connect probe against a small, configurable port
list (and an ICMP echo where ``ping`` is available). A successful connection
to a host on the far side of a boundary that is meant to be isolated is the
finding that matters: the segmentation does not hold. A boundary that refuses
every probe is recorded as INFO evidence that the control works.

Only runs when the engagement was started with ``active=True``. Every probe is
filtered through the scope first, so excluded networks are never touched.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from ..context import Context
from ..models import Finding, Host, ModuleResult, Severity
from ..utils import netaddr, shell
from .base import Module, ACTIVE


class Reachability(Module):
    name = "reach"
    phase = ACTIVE
    description = "Probe reachability to in-scope hosts across segment boundaries"

    def run(self, ctx: Context) -> ModuleResult:
        result = self.new_result()

        if not ctx.active:
            result.ok = False
            result.skipped_reason = "active probing disabled (pass --active to enable)"
            return result

        targets = self.select_targets(ctx)
        if not targets:
            result.ok = False
            result.skipped_reason = (
                "no out-of-segment targets to probe. Add target_cidrs to your scope "
                "(or -i) that lie outside the current foothold subnet."
            )
            return result

        self.log.info(
            "probing %d host(s) across segment boundaries (%d workers)", len(targets), ctx.workers
        )
        hosts = self.probe_many(targets, ctx.port_list, ctx.timeout, ctx.workers)
        for host in hosts:
            if host.reachable:
                self._record_reach(result, ctx, host)

        reachable = [h for h in hosts if h.reachable]
        result.data["probed"] = len(hosts)
        result.data["reachable"] = [h.to_dict() for h in reachable]

        if not reachable:
            result.add(
                Finding(
                    module=self.name,
                    title="Segment boundary held against all probes",
                    severity=Severity.INFO,
                    description=(
                        f"None of the {len(hosts)} out-of-segment host(s) responded to ICMP or "
                        "TCP connect probes from the current foothold. Consistent with enforced "
                        "segmentation (or host-level filtering)."
                    ),
                    evidence={"probed": len(hosts)},
                )
            )
        return result

    # ---- target selection (pure, unit-tested) ------------------------
    @staticmethod
    def select_targets(ctx: Context) -> List[str]:
        """Choose host addresses outside the current segment but in scope.

        If the scope names target CIDRs, enumerate their hosts (minus the
        current foothold subnet and minus exclusions). With no target CIDRs,
        fall back to probing the current gateway only, which at least shows
        whether the gateway exposes services to the segment.
        """
        seg = ctx.current_segment
        current_net = netaddr.parse_network(seg.cidr) if (seg and seg.cidr) else None

        probe_cidrs = ctx.scope.probe_cidrs()
        if not probe_cidrs:
            if seg and seg.gateway:
                return [seg.gateway]
            return []

        targets: List[str] = []
        for cidr in probe_cidrs:
            net = netaddr.parse_network(cidr)
            # Skip the segment we're already on — we want *cross*-segment reach.
            if current_net is not None and net.overlaps(current_net):
                continue
            for host in netaddr.hosts(net, limit=ctx.host_limit):
                if ctx.scope.address_in_scope(host):
                    targets.append(host)
        # De-duplicate preserving order.
        seen = set()
        ordered = []
        for t in targets:
            if t not in seen:
                seen.add(t)
                ordered.append(t)
        return ordered[: ctx.host_limit]

    # ---- probing ------------------------------------------------------
    def probe_many(self, addrs: List[str], ports: List[int], timeout: float, workers: int = 64) -> List[Host]:
        """Probe many hosts concurrently; results preserve input order."""
        if not addrs:
            return []
        workers = max(1, min(workers, len(addrs)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(lambda a: self._probe_host(a, ports, timeout), addrs))

    def _probe_host(self, addr: str, ports: List[int], timeout: float) -> Host:
        host = Host(address=addr)
        rtt = self._icmp(addr, timeout)
        if rtt is not None:
            host.reachable = True
            host.rtt_ms = rtt
        open_ports = []
        for port in ports:
            if self._tcp_connect(addr, port, timeout):
                open_ports.append(port)
        if open_ports:
            host.reachable = True
            host.open_ports = open_ports
        return host

    @staticmethod
    def _tcp_connect(addr: str, port: int, timeout: float) -> bool:
        """Unprivileged TCP connect probe (no raw sockets, no root)."""
        try:
            with socket.create_connection((addr, port), timeout=timeout):
                return True
        except (OSError, ValueError):
            return False

    @staticmethod
    def _icmp(addr: str, timeout: float) -> Optional[float]:
        """ICMP echo via the system ``ping`` if present; returns RTT in ms."""
        if not shell.tool_available("ping"):
            return None
        res = shell.run(
            ["ping", "-n", "-c", "1", "-W", str(max(1, int(timeout))), addr],
            timeout=timeout + 2,
        )
        if not res.ok:
            return None
        import re

        m = re.search(r"time[=<]([\d.]+)\s*ms", res.stdout)
        if m:
            try:
                return float(m.group(1))
            except ValueError:
                return None
        return 0.0

    # ---- findings -----------------------------------------------------
    def _record_reach(self, result: ModuleResult, ctx: Context, host: Host) -> None:
        seg = ctx.current_segment
        from_desc = seg.cidr if (seg and seg.cidr) else (ctx.interface or "current segment")
        ports = ", ".join(str(p) for p in host.open_ports) if host.open_ports else "ICMP only"
        result.add(
            Finding(
                module=self.name,
                title=f"Cross-segment reachability to {host.address}",
                severity=Severity.HIGH,
                description=(
                    f"Host {host.address} is reachable from the {from_desc} foothold "
                    f"({ports}). If these segments are intended to be isolated, the "
                    "segmentation control is not being enforced for this path."
                ),
                target=host.address,
                evidence=host.to_dict(),
                recommendation=(
                    "Confirm the intended segmentation policy, then restrict inter-segment "
                    "traffic at the gateway/firewall or enable client isolation for the SSID."
                ),
            )
        )
