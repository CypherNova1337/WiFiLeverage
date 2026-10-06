"""Regression tests distilled from the adversarial stress harness."""

import pytest

from wifileverage.analysis.graph import Edge, SegmentGraph
from wifileverage.models import Finding, ModuleResult, Segment, Severity
from wifileverage.modules.wireless_recon import WirelessRecon
from wifileverage.modules.segment_discovery import SegmentDiscovery
from wifileverage.report import Report
from wifileverage.scope import Scope, ScopeError


def test_bad_cidr_raises_scopeerror_not_valueerror():
    # A malformed CIDR anywhere must surface as ScopeError (the CLI catches it).
    with pytest.raises(ScopeError):
        Scope.from_dict({"target_cidrs": ["10.0.0.0/33"]})
    with pytest.raises(ScopeError):
        Scope.from_dict({"zones": {"z": ["nope/16"]}})
    with pytest.raises(ScopeError):
        Scope.empty().merge_inline(include=["not-a-cidr"])


def test_iw_parser_never_raises_on_garbage():
    for junk in ["", "BSS zz\nSSID:", "\x00\x00 freq: x signal: y", "BSS \nSSID: ‮evil"]:
        WirelessRecon.parse_iw_scan(junk)  # must not raise


def test_ip_parsers_tolerate_garbage():
    assert SegmentDiscovery.parse_ip_addr("garbage") == (None, None)
    assert SegmentDiscovery.parse_default_gateway("nothing here") is None
    assert SegmentDiscovery.parse_neighbours("junk", "bogus/99") == []


def test_leverage_paths_respects_max_depth():
    g = SegmentGraph()
    for i in range(50):
        g.add_edge(Edge(f"c{i}", f"c{i+1}"))
    for p in g.leverage_paths("c0", max_depth=6):
        assert len(p) - 1 <= 6  # hops never exceed max_depth


def test_graph_terminates_on_cycles():
    g = SegmentGraph()
    g.add_edge(Edge("a", "b"))
    g.add_edge(Edge("b", "c"))
    g.add_edge(Edge("c", "a"))
    for p in g.leverage_paths("a"):
        assert len(set(p)) == len(p)  # no node repeats


def test_html_report_escapes_hostile_content():
    rep = Report(scope=Scope.from_dict({"engagement": "<script>x</script>"}), interface="w", active=True)
    r = ModuleResult(module="reach")
    r.add(Finding(module="reach", title="<img src=x onerror=y>", severity=Severity.HIGH, description="&<b>"))
    rep.add(r)
    html = rep.to_html()
    assert "<script>x</script>" not in html
    assert "onerror=y>" not in html
    assert "&lt;img" in html


def test_concurrent_probe_preserves_order_and_handles_empty():
    from wifileverage.modules.reachability import Reachability

    assert Reachability().probe_many([], [80], 0.1) == []
    hosts = Reachability().probe_many(["203.0.113.1", "203.0.113.2"], [9], 0.2, workers=8)
    assert [h.address for h in hosts] == ["203.0.113.1", "203.0.113.2"]
