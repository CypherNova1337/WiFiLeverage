from wifileverage.analysis.assemble import assemble, zone_label
from wifileverage.analysis.diff import diff_reports
from wifileverage.analysis.graph import Edge, SegmentGraph
from wifileverage.analysis.policy import CellState, Observation, PolicyMatrix
from wifileverage.models import ModuleResult, Segment
from wifileverage.scope import Scope

ZONED = Scope.from_dict(
    {
        "zones": {
            "guest": ["192.168.50.0/24"],
            "corp": ["10.20.0.0/16"],
            "iot": ["192.168.60.0/24"],
        },
        "policy": {"allow": [{"from": "corp", "to": "iot"}]},
    }
)


# ---- scope zones/policy ----
def test_zone_of_longest_prefix_wins():
    s = Scope.from_dict({"zones": {"big": ["10.0.0.0/8"], "small": ["10.20.0.0/16"]}})
    assert s.zone_of("10.20.0.5") == "small"
    assert s.zone_of("10.99.0.5") == "big"
    assert s.zone_of("172.16.0.1") is None


def test_flow_allowed():
    assert ZONED.flow_allowed("corp", "iot")
    assert not ZONED.flow_allowed("guest", "corp")
    assert ZONED.flow_allowed("guest", "guest")  # same zone always ok


def test_empty_policy_block_means_full_isolation():
    # A present-but-empty policy block = default-deny (nothing allowed).
    strict = Scope.from_dict({"zones": {"a": ["10.0.0.0/8"], "b": ["192.168.0.0/16"]}, "policy": {"allow": []}})
    assert strict.policy_defined
    assert not strict.flow_allowed("a", "b")
    # No policy block at all = assert nothing.
    loose = Scope.from_dict({"zones": {"a": ["10.0.0.0/8"], "b": ["192.168.0.0/16"]}})
    assert not loose.policy_defined
    assert loose.flow_allowed("a", "b")


# ---- policy matrix ----
def test_matrix_flags_violation():
    obs = [Observation(from_zone="guest", address="10.20.0.5", ports=(445,))]
    pm = PolicyMatrix.evaluate(ZONED, obs)
    assert pm.cells[("guest", "corp")].state == CellState.VIOLATION
    assert len(pm.violations()) == 1
    f = pm.findings()[0]
    assert f.severity.value == "critical"
    assert "guest" in f.title and "corp" in f.title


def test_matrix_permitted_flow_is_ok():
    obs = [Observation(from_zone="corp", address="192.168.60.9", ports=(22,))]
    pm = PolicyMatrix.evaluate(ZONED, obs)
    assert pm.cells[("corp", "iot")].state == CellState.OK
    assert pm.violations() == []


def test_matrix_ascii_renders():
    pm = PolicyMatrix.evaluate(ZONED, [])
    text = pm.to_ascii()
    assert "guest" in text and "corp" in text and "legend" in text


# ---- graph ----
def test_graph_multi_hop_paths():
    g = SegmentGraph()
    g.add_edge(Edge("guest", "dmz", ports=(443,)))
    g.add_edge(Edge("dmz", "corp", ports=(445,)))
    assert g.reachable_from("guest") == {"dmz", "corp"}
    paths = g.leverage_paths("guest")
    assert ["guest", "dmz", "corp"] in paths


def test_graph_handles_cycles():
    g = SegmentGraph()
    g.add_edge(Edge("a", "b"))
    g.add_edge(Edge("b", "a"))
    # Must terminate and not loop forever.
    assert g.reachable_from("a") == {"b", "a"} or g.reachable_from("a") == {"b"}
    paths = g.leverage_paths("a")
    assert all(len(set(p)) == len(p) for p in paths)  # no node repeats in a path


def test_graph_edge_merge_keeps_violation():
    g = SegmentGraph()
    g.add_edge(Edge("a", "b", ports=(80,), allowed=True))
    g.add_edge(Edge("a", "b", ports=(443,), allowed=False))
    e = g.edges[("a", "b")]
    assert e.allowed is False
    assert set(e.ports) == {80, 443}


def test_graph_renderers():
    g = SegmentGraph()
    g.add_edge(Edge("guest", "corp", via="10.20.0.5", ports=(445,), allowed=False))
    assert "flowchart" in g.to_mermaid()
    assert "digraph" in g.to_dot()
    assert "VIOLATION" in g.to_mermaid()
    assert "guest" in g.to_ascii()


def test_graph_from_reports_merges_footholds():
    r1 = {"analysis": {"edges": [{"src": "guest", "dst": "dmz", "ports": [443]}], "zones": ["guest", "dmz"]}}
    r2 = {"analysis": {"edges": [{"src": "dmz", "dst": "corp", "ports": [445]}], "zones": ["corp"]}}
    g = SegmentGraph.from_reports([r1, r2])
    assert ["guest", "dmz", "corp"] in g.leverage_paths("guest")


# ---- assemble ----
def _reach_result(hosts):
    r = ModuleResult(module="reach")
    r.data["reachable"] = hosts
    return r


def test_assemble_with_zones_produces_matrix_and_violation():
    seg = Segment(interface="wlan0", ip_address="192.168.50.10", cidr="192.168.50.0/24")
    results = [_reach_result([{"address": "10.20.0.5", "open_ports": [445]}])]
    a = assemble(ZONED, results, seg)
    assert a["foothold_zone"] == "guest"
    assert a["matrix"]["violations"] == 1
    assert a["policy_findings"][0]["severity"] == "critical"
    assert "flowchart" in a["graph_mermaid"]


def test_assemble_without_zones_still_builds_graph():
    s = Scope.from_dict({"target_cidrs": ["10.20.0.0/16"]})
    seg = Segment(interface="wlan0", ip_address="192.168.50.10", cidr="192.168.50.0/24")
    results = [_reach_result([{"address": "10.20.0.5", "open_ports": [445]}])]
    a = assemble(s, results, seg)
    assert a["matrix"] is None
    assert a["edges"]  # graph still has an edge


def test_zone_label_fallback():
    s = Scope.empty()
    assert zone_label(s, "10.1.2.3") == "10.1.2.0/24"
    assert zone_label(s, None) is None


# ---- diff ----
def test_diff_detects_regression_and_fix():
    base = {"analysis": {"edges": [{"src": "guest", "dst": "iot", "allowed": True}]}}
    cur = {
        "analysis": {
            "edges": [
                {"src": "guest", "dst": "corp", "allowed": False},  # new violation
            ]
        }
    }
    d = diff_reports(base, cur)
    assert ("guest", "corp") in d.new_edges
    assert ("guest", "iot") in d.removed_edges
    assert ("guest", "corp") in d.new_violations
    assert d.regressed
