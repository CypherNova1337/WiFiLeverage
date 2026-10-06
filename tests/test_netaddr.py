from wifileverage.utils import netaddr


def test_parse_network_clears_host_bits():
    net = netaddr.parse_network("192.168.1.42/24")
    assert str(net) == "192.168.1.0/24"


def test_address_in_networks():
    nets = netaddr.parse_networks(["10.0.0.0/8", "192.168.0.0/16"])
    assert netaddr.address_in_networks("10.5.5.5", nets)
    assert netaddr.address_in_networks("192.168.1.1", nets)
    assert not netaddr.address_in_networks("172.16.0.1", nets)


def test_address_in_networks_rejects_garbage():
    nets = netaddr.parse_networks(["10.0.0.0/8"])
    assert not netaddr.address_in_networks("not-an-ip", nets)


def test_networks_overlap():
    a = netaddr.parse_network("10.0.0.0/8")
    b = netaddr.parse_network("10.20.0.0/16")
    c = netaddr.parse_network("192.168.0.0/16")
    assert netaddr.networks_overlap(a, b)
    assert not netaddr.networks_overlap(a, c)


def test_hosts_respects_limit():
    net = netaddr.parse_network("10.0.0.0/16")
    hosts = list(netaddr.hosts(net, limit=5))
    assert len(hosts) == 5
    assert hosts[0] == "10.0.0.1"


def test_same_subnet():
    assert netaddr.same_subnet("192.168.1.10", "192.168.1.200", 24)
    assert not netaddr.same_subnet("192.168.1.10", "192.168.2.200", 24)
