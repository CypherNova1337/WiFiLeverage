"""Segmentation policy matrix — observed reality vs. intended isolation.

You declare the isolation you *intend* in the scope (named zones, and a
``policy.allow`` list of the cross-zone flows that are permitted). This engine
takes the reachability WiFiLeverage actually observed and renders a matrix:

                 ┌ to ─────────────────────────┐
         from    guest     corp      iot
         guest    self      !!       ok
         corp      -        self      -
         iot       -        ok       self

where each cell is one of:

* ``self``      — same zone (not evaluated)
* ``ok``        — reachable **and** permitted by policy, or correctly isolated
* ``!!``        — VIOLATION: reachable but policy says it should be isolated
* ``-``         — untested (no observation either way)

The violations are the product: concrete, reportable proof that a segmentation
control is not holding, mapped back to the policy the client signed off on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from ..models import Finding, Severity
from ..scope import Scope
from .graph import Edge, SegmentGraph


class CellState(Enum):
    SELF = "self"
    OK = "ok"
    VIOLATION = "violation"
    UNTESTED = "untested"


@dataclass
class MatrixCell:
    from_zone: str
    to_zone: str
    state: CellState
    ports: Tuple[int, ...] = ()
    example: str = ""


@dataclass
class Observation:
    """One reachability fact: from a foothold in *from_zone*, *address* answered."""

    from_zone: str
    address: str
    ports: Tuple[int, ...] = ()


@dataclass
class PolicyMatrix:
    scope: Scope
    cells: Dict[Tuple[str, str], MatrixCell] = field(default_factory=dict)
    graph: SegmentGraph = field(default_factory=SegmentGraph)

    @classmethod
    def evaluate(cls, scope: Scope, observations: List[Observation]) -> "PolicyMatrix":
        pm = cls(scope=scope)
        zones = sorted(scope.zones.keys())
        for z in zones:
            pm.graph.add_node(z)

        # Seed every zone pair as untested.
        for a in zones:
            for b in zones:
                state = CellState.SELF if a == b else CellState.UNTESTED
                pm.cells[(a, b)] = MatrixCell(a, b, state)

        for obs in observations:
            to_zone = scope.zone_of(obs.address)
            if to_zone is None or obs.from_zone is None:
                continue
            if obs.from_zone == to_zone:
                continue
            permitted = scope.flow_allowed(obs.from_zone, to_zone)
            state = CellState.OK if permitted else CellState.VIOLATION
            cell = pm.cells.get((obs.from_zone, to_zone))
            ports = tuple(sorted(set(obs.ports) | (set(cell.ports) if cell else set())))
            # A violation sticks even if a later observation on the same pair is permitted.
            if cell and cell.state == CellState.VIOLATION:
                state = CellState.VIOLATION
            pm.cells[(obs.from_zone, to_zone)] = MatrixCell(
                obs.from_zone, to_zone, state, ports=ports, example=obs.address
            )
            pm.graph.add_edge(
                Edge(src=obs.from_zone, dst=to_zone, via=obs.address, ports=ports, allowed=permitted)
            )
        return pm

    # ---- outputs ------------------------------------------------------
    def violations(self) -> List[MatrixCell]:
        return [c for c in self.cells.values() if c.state == CellState.VIOLATION]

    def findings(self) -> List[Finding]:
        out: List[Finding] = []
        for cell in self.violations():
            ports = ", ".join(str(p) for p in cell.ports) or "ICMP"
            out.append(
                Finding(
                    module="policy",
                    title=f"Segmentation policy violation: {cell.from_zone} → {cell.to_zone}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Policy requires the '{cell.from_zone}' zone to be isolated from "
                        f"'{cell.to_zone}', but a host in '{cell.to_zone}' ({cell.example}) was "
                        f"reachable from a '{cell.from_zone}' foothold on {ports}. The intended "
                        "segmentation is not being enforced for this flow."
                    ),
                    target=f"{cell.from_zone}->{cell.to_zone}",
                    evidence={"example_host": cell.example, "ports": list(cell.ports)},
                    recommendation=(
                        f"Block {cell.from_zone}->{cell.to_zone} traffic at the gateway/firewall "
                        "or VLAN ACL, then re-test to confirm the boundary holds."
                    ),
                )
            )
        return out

    def to_ascii(self) -> str:
        zones = sorted(self.scope.zones.keys())
        if not zones:
            return "(no zones defined; add a 'zones:' block to the scope to get a matrix)"
        glyph = {
            CellState.SELF: "·",
            CellState.OK: "ok",
            CellState.VIOLATION: "!!",
            CellState.UNTESTED: "-",
        }
        width = max([len(z) for z in zones] + [5])
        header = " " * (width + 3) + "".join(z.center(width + 2) for z in zones)
        lines = ["Segmentation matrix  (rows = from, cols = to)", header]
        for a in zones:
            row = [a.rjust(width) + "  "]
            for b in zones:
                row.append(glyph[self.cells[(a, b)].state].center(width + 2))
            lines.append("".join(row))
        lines.append("")
        lines.append("legend: ok = reachable+permitted or isolated   !! = VIOLATION   - = untested   · = self")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "zones": sorted(self.scope.zones.keys()),
            "cells": [
                {
                    "from": c.from_zone,
                    "to": c.to_zone,
                    "state": c.state.value,
                    "ports": list(c.ports),
                    "example": c.example,
                }
                for c in self.cells.values()
            ],
            "violations": len(self.violations()),
        }
