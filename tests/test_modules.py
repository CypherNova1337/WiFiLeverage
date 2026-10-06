from wifileverage.context import Context
from wifileverage.models import Segment
from wifileverage.modules.isolation import StationIsolation
from wifileverage.modules.reachability import Reachability
from wifileverage.modules.segment_discovery import SegmentDiscovery
from wifileverage.modules.wireless_recon import WirelessRecon
from wifileverage.scope import Scope

IW_SCAN = """
BSS aa:bb:cc:dd:ee:ff(on wlan0)
	freq: 2437
	signal: -42.00 dBm
	SSID: CorpNet
	DS Parameter set: channel 6
	RSN:	 * Version: 1
BSS 11:22:33:44:55:66(on wlan0)
	freq: 5180
	signal: -70.00 dBm
	SSID: GuestNet
	DS Parameter set: channel 36
"""


def test_parse_iw_scan():
    aps = WirelessRecon.parse_iw_scan(IW_SCAN)
    assert len(aps) == 2
    corp = aps[0]
    assert corp.ssid == "CorpNet"
    assert corp.bssid == "aa:bb:cc:dd:ee:ff"
    assert corp.channel == 6
    assert corp.security == "WPA2"
    guest = aps[1]
    assert guest.ssid == "GuestNet"
    assert guest.security == "open"


def test_parse_ip_addr():
    out = "2: wlan0    inet 192.168.50.23/24 brd 192.168.50.255 scope global wlan0\\       valid_lft forever"
    ip, cidr = SegmentDiscovery.parse_ip_addr(out)
    assert ip == "192.168.50.23"
    assert cidr == "192.168.50.0/24"


def test_parse_default_gateway():
    out = "default via 192.168.50.1 dev wlan0 proto dhcp metric 600"
    assert SegmentDiscovery.parse_default_gateway(out) == "192.168.50.1"


def test_parse_neighbours_filters_to_subnet():
    out = (
        "192.168.50.1 dev wlan0 lladdr aa:bb:cc:dd:ee:01 REACHABLE\n"
        "192.168.50.77 dev wlan0 lladdr aa:bb:cc:dd:ee:02 STALE\n"
        "192.168.50.90 dev wlan0  FAILED\n"
        "10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:03 REACHABLE\n"
    )
    neigh = SegmentDiscovery.parse_neighbours(out, "192.168.50.0/24")
    assert neigh == ["192.168.50.1", "192.168.50.77"]


def _ctx(scope, seg=None, active=True):
    ctx = Context(scope=scope, interface="wlan0", active=active, host_limit=16)
    if seg:
        ctx.segments.append(seg)
    return ctx


def test_select_targets_excludes_current_segment():
    scope = Scope.from_dict({"target_cidrs": ["192.168.50.0/24", "10.20.0.0/29"]})
    seg = Segment(interface="wlan0", ip_address="192.168.50.10", cidr="192.168.50.0/24", gateway="192.168.50.1")
    ctx = _ctx(scope, seg)
    targets = Reachability.select_targets(ctx)
    # None of the targets should be in the current /24; all in the corp /29.
    assert targets
    assert all(t.startswith("10.20.0.") for t in targets)


def test_select_targets_falls_back_to_gateway():
    scope = Scope.empty()
    seg = Segment(interface="wlan0", ip_address="192.168.50.10", cidr="192.168.50.0/24", gateway="192.168.50.1")
    ctx = _ctx(scope, seg)
    assert Reachability.select_targets(ctx) == ["192.168.50.1"]


def test_select_targets_respects_exclusions():
    scope = Scope.from_dict({"target_cidrs": ["10.20.0.0/29"], "exclude_cidrs": ["10.20.0.0/31"]})
    seg = Segment(interface="wlan0", ip_address="192.168.50.10", cidr="192.168.50.0/24")
    ctx = _ctx(scope, seg)
    targets = Reachability.select_targets(ctx)
    assert "10.20.0.1" not in targets
    assert "10.20.0.2" in targets


def test_select_peers_excludes_self_and_gateway():
    scope = Scope.empty()
    seg = Segment(interface="wlan0", ip_address="192.168.50.10", cidr="192.168.50.0/28", gateway="192.168.50.1")
    ctx = _ctx(scope, seg)
    peers = StationIsolation.select_peers(ctx)
    assert "192.168.50.10" not in peers
    assert "192.168.50.1" not in peers
    assert "192.168.50.2" in peers


def test_reach_skips_when_not_active():
    scope = Scope.from_dict({"target_cidrs": ["10.20.0.0/29"]})
    seg = Segment(interface="wlan0", ip_address="192.168.50.10", cidr="192.168.50.0/24")
    ctx = _ctx(scope, seg, active=False)
    result = Reachability().run(ctx)
    assert not result.ok
    assert "active" in result.skipped_reason
