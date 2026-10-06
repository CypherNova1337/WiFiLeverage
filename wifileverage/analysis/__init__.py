"""Analysis layer: turn raw reachability observations into segmentation
intelligence — a graph, multi-hop leverage paths, and a policy matrix."""

from .graph import SegmentGraph, Edge
from .policy import PolicyMatrix, MatrixCell

__all__ = ["SegmentGraph", "Edge", "PolicyMatrix", "MatrixCell"]
