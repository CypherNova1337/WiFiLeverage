"""Compare two WiFiLeverage reports — what changed in the segmentation.

Baseline an engagement, run it again after remediation (or next quarter), and
this tells you which reachable paths are *new* (regressions), which closed
(fixed), and how the policy-violation count moved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


def _edge_set(report: dict) -> Dict[Tuple[str, str], dict]:
    edges = ((report or {}).get("analysis") or {}).get("edges", [])
    return {(e["src"], e["dst"]): e for e in edges}


def _violation_set(report: dict) -> Set[Tuple[str, str]]:
    return {k for k, e in _edge_set(report).items() if e.get("allowed") is False}


@dataclass
class Diff:
    new_edges: List[Tuple[str, str]] = field(default_factory=list)
    removed_edges: List[Tuple[str, str]] = field(default_factory=list)
    new_violations: List[Tuple[str, str]] = field(default_factory=list)
    resolved_violations: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def regressed(self) -> bool:
        return bool(self.new_edges or self.new_violations)

    def to_text(self) -> str:
        def fmt(pairs):
            return [f"{s} -> {d}" for s, d in pairs] or ["(none)"]

        lines = ["Segmentation diff (baseline -> current)", ""]
        lines.append("New reachable paths (regressions):")
        lines += [f"  + {x}" for x in fmt(self.new_edges)]
        lines.append("")
        lines.append("Closed paths (fixed):")
        lines += [f"  - {x}" for x in fmt(self.removed_edges)]
        lines.append("")
        lines.append("New policy violations:")
        lines += [f"  !! {x}" for x in fmt(self.new_violations)]
        lines.append("")
        lines.append("Resolved policy violations:")
        lines += [f"  ok {x}" for x in fmt(self.resolved_violations)]
        return "\n".join(lines)


def diff_reports(baseline: dict, current: dict) -> Diff:
    base_edges = set(_edge_set(baseline))
    cur_edges = set(_edge_set(current))
    base_viol = _violation_set(baseline)
    cur_viol = _violation_set(current)
    return Diff(
        new_edges=sorted(cur_edges - base_edges),
        removed_edges=sorted(base_edges - cur_edges),
        new_violations=sorted(cur_viol - base_viol),
        resolved_violations=sorted(base_viol - cur_viol),
    )
