"""Segmentation graph and multi-hop leverage-path analysis.

The graph models security *zones* as nodes and observed *reachability* as
directed edges (A -> B means: from a foothold in zone A, a host in zone B was
reachable). A single run from one foothold produces the edges leaving that
foothold's zone; merging the JSON of several runs — one per foothold — yields
the full picture, and that is where the interesting result lives:

    guest ──▶ dmz ──▶ corp

No single run proves guest can reach corp, but chaining the edges does. The
:meth:`SegmentGraph.leverage_paths` method walks those chains (BFS) to surface
multi-hop pivots an attacker could use to cross boundaries that look isolated
one hop at a time.

Pure data-structure code — no network, no I/O — so it is fully unit-testable
and deterministic.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple


@dataclass(frozen=True)
class Edge:
    """A directed reachability edge between two zones."""

    src: str
    dst: str
    via: str = ""          # example host that demonstrated the edge
    ports: Tuple[int, ...] = ()
    allowed: Optional[bool] = None  # per policy: True=permitted, False=violation, None=unknown

    def key(self) -> Tuple[str, str]:
        return (self.src, self.dst)


@dataclass
class SegmentGraph:
    nodes: Set[str] = field(default_factory=set)
    edges: Dict[Tuple[str, str], Edge] = field(default_factory=dict)

    # ---- construction -------------------------------------------------
    def add_node(self, name: str) -> None:
        if name:
            self.nodes.add(name)

    def add_edge(self, edge: Edge) -> None:
        self.add_node(edge.src)
        self.add_node(edge.dst)
        existing = self.edges.get(edge.key())
        if existing is None:
            self.edges[edge.key()] = edge
            return
        # Merge: union the demonstrated ports, keep the stricter policy verdict.
        ports = tuple(sorted(set(existing.ports) | set(edge.ports)))
        allowed = existing.allowed
        if edge.allowed is False or existing.allowed is False:
            allowed = False
        elif allowed is None:
            allowed = edge.allowed
        self.edges[edge.key()] = Edge(
            src=edge.src,
            dst=edge.dst,
            via=existing.via or edge.via,
            ports=ports,
            allowed=allowed,
        )

    @classmethod
    def from_reports(cls, reports: Iterable[dict]) -> "SegmentGraph":
        """Build a graph from one or more WiFiLeverage report dicts.

        Reads the ``reach``/``isolation`` module data and the per-report
        ``analysis.edges`` block (when a report was already zone-annotated).
        Falls back gracefully when zone data is absent.
        """
        g = cls()
        for report in reports:
            analysis = (report or {}).get("analysis") or {}
            for raw in analysis.get("edges", []):
                g.add_edge(
                    Edge(
                        src=raw.get("src", "?"),
                        dst=raw.get("dst", "?"),
                        via=raw.get("via", ""),
                        ports=tuple(raw.get("ports", []) or []),
                        allowed=raw.get("allowed"),
                    )
                )
            for z in analysis.get("zones", []):
                g.add_node(z)
        return g

    # ---- adjacency ----------------------------------------------------
    def _adjacency(self) -> Dict[str, List[str]]:
        adj: Dict[str, List[str]] = defaultdict(list)
        for (src, dst) in self.edges:
            adj[src].append(dst)
        return adj

    def neighbors(self, node: str) -> List[str]:
        return self._adjacency().get(node, [])

    # ---- reachability -------------------------------------------------
    def reachable_from(self, start: str) -> Set[str]:
        """All zones transitively reachable from *start* (excluding itself)."""
        adj = self._adjacency()
        seen: Set[str] = set()
        q = deque(adj.get(start, []))
        while q:
            n = q.popleft()
            if n in seen or n == start:
                continue
            seen.add(n)
            q.extend(adj.get(n, []))
        return seen

    def leverage_paths(self, start: str, max_depth: int = 6) -> List[List[str]]:
        """Return shortest reachability paths from *start* to every other zone.

        Each path is a list of zone names ``[start, ..., target]``. Only the
        shortest path to each target is returned (BFS), which is what an
        operator wants: the fewest pivots needed to cross a boundary.
        """
        adj = self._adjacency()
        paths: Dict[str, List[str]] = {}
        q: deque[List[str]] = deque([[start]])
        while q:
            path = q.popleft()
            # A path of N nodes represents N-1 hops; stop expanding once we
            # would exceed max_depth hops so returned paths never run longer.
            if len(path) - 1 >= max_depth:
                continue
            tail = path[-1]
            for nxt in adj.get(tail, []):
                if nxt in path:  # avoid cycles
                    continue
                if nxt not in paths:
                    paths[nxt] = path + [nxt]
                    q.append(path + [nxt])
        return [p for _, p in sorted(paths.items())]

    def violations(self) -> List[Edge]:
        """Edges the policy marks as not-permitted (segmentation violations)."""
        return [e for e in self.edges.values() if e.allowed is False]

    # ---- rendering ----------------------------------------------------
    def to_mermaid(self) -> str:
        """Render as a Mermaid flowchart (great in Markdown/HTML)."""
        lines = ["flowchart LR"]
        for node in sorted(self.nodes):
            nid = _mid(node)
            lines.append(f'    {nid}["{node}"]')
        for edge in self.edges.values():
            style = ""
            label = ",".join(str(p) for p in edge.ports) or "reach"
            if edge.allowed is False:
                style = ":::violation"
                label = f"VIOLATION ({label})"
            lines.append(f'    {_mid(edge.src)} -->|{label}| {_mid(edge.dst)}{style}')
        lines.append("    classDef violation stroke:#d00,stroke-width:3px,color:#d00;")
        return "\n".join(lines)

    def to_dot(self) -> str:
        """Render as Graphviz DOT."""
        lines = ["digraph segmentation {", '    rankdir=LR;', '    node [shape=box];']
        for node in sorted(self.nodes):
            lines.append(f'    "{node}";')
        for edge in self.edges.values():
            label = ",".join(str(p) for p in edge.ports) or "reach"
            color = "red" if edge.allowed is False else "black"
            lines.append(f'    "{edge.src}" -> "{edge.dst}" [label="{label}", color={color}];')
        lines.append("}")
        return "\n".join(lines)

    def to_ascii(self) -> str:
        """A compact text rendering for the terminal."""
        if not self.edges:
            return "(no reachability edges observed)"
        out = []
        for edge in sorted(self.edges.values(), key=lambda e: (e.src, e.dst)):
            marker = "  !! VIOLATION" if edge.allowed is False else ""
            ports = ",".join(str(p) for p in edge.ports) or "icmp"
            out.append(f"  {edge.src:>12}  ──[{ports}]──▶  {edge.dst}{marker}")
        return "\n".join(out)

    def to_dict(self) -> dict:
        return {
            "nodes": sorted(self.nodes),
            "edges": [
                {"src": e.src, "dst": e.dst, "via": e.via, "ports": list(e.ports), "allowed": e.allowed}
                for e in self.edges.values()
            ],
        }


def _mid(name: str) -> str:
    """A Mermaid-safe node id."""
    return "z_" + "".join(c if c.isalnum() else "_" for c in name)
