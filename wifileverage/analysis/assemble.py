"""Turn raw module results into the analysis block (zones, matrix, graph).

This is the glue between the probing modules and the intelligence layer. It
derives the foothold zone, collects every cross-boundary reachability
observation, evaluates the policy matrix (when zones are declared) and builds
the segmentation graph with multi-hop leverage paths.

When no explicit zones are declared it still produces a graph by synthesising
pseudo-zones from the target CIDRs (or a /24 fallback), so the visual map and
path analysis work out of the box.
"""

from __future__ import annotations

import ipaddress
from typing import List, Optional

from ..models import ModuleResult, Segment
from ..scope import Scope
from .graph import Edge, SegmentGraph
from .policy import Observation, PolicyMatrix


def _fallback_zone(scope: Scope, address: str) -> str:
    """Zone label when no explicit zones are defined."""
    for cidr in scope.target_cidrs:
        try:
            if ipaddress.ip_address(address) in ipaddress.ip_network(cidr, strict=False):
                return cidr
        except ValueError:
            continue
    try:
        ip = ipaddress.ip_address(address)
        if ip.version == 4:
            return str(ipaddress.ip_network(f"{address}/24", strict=False))
    except ValueError:
        pass
    return address


def zone_label(scope: Scope, address: Optional[str]) -> Optional[str]:
    if not address:
        return None
    if scope.has_zones:
        return scope.zone_of(address) or "unzoned"
    return _fallback_zone(scope, address)


def collect_observations(
    scope: Scope, results: List[ModuleResult], segment: Optional[Segment]
) -> List[Observation]:
    """Gather cross-boundary reachability observations from module output."""
    foothold_addr = segment.ip_address if segment else None
    from_zone = zone_label(scope, foothold_addr) or "foothold"

    obs: List[Observation] = []
    for result in results:
        if result.module not in ("reach", "isolation"):
            continue
        key = "reachable" if result.module == "reach" else "peers_reachable"
        for host in result.data.get(key, []):
            addr = host.get("address")
            if not addr:
                continue
            obs.append(
                Observation(
                    from_zone=from_zone,
                    address=addr,
                    ports=tuple(host.get("open_ports", []) or []),
                )
            )
    return obs


def assemble(
    scope: Scope, results: List[ModuleResult], segment: Optional[Segment]
) -> dict:
    """Build the full analysis block to attach to a report."""
    observations = collect_observations(scope, results, segment)
    foothold_zone = zone_label(scope, segment.ip_address if segment else None) or "foothold"

    if scope.has_zones:
        matrix = PolicyMatrix.evaluate(scope, observations)
        graph = matrix.graph
        for z in scope.zones:
            graph.add_node(z)
        matrix_dict = matrix.to_dict()
        matrix_ascii = matrix.to_ascii()
        policy_findings = [f.to_dict() for f in matrix.findings()]
    else:
        # No zones: synthesise a graph straight from observations.
        graph = SegmentGraph()
        graph.add_node(foothold_zone)
        for o in observations:
            dst = zone_label(scope, o.address) or o.address
            graph.add_edge(Edge(src=o.from_zone, dst=dst, via=o.address, ports=o.ports, allowed=None))
        matrix_dict = None
        matrix_ascii = None
        policy_findings = []

    paths = {
        start: graph.leverage_paths(start)
        for start in sorted(graph.nodes)
        if graph.leverage_paths(start)
    }

    return {
        "foothold_zone": foothold_zone,
        "zones": sorted(graph.nodes),
        "edges": graph.to_dict()["edges"],
        "graph_mermaid": graph.to_mermaid(),
        "graph_dot": graph.to_dot(),
        "graph_ascii": graph.to_ascii(),
        "leverage_paths": {k: v for k, v in paths.items()},
        "matrix": matrix_dict,
        "matrix_ascii": matrix_ascii,
        "policy_findings": policy_findings,
    }
