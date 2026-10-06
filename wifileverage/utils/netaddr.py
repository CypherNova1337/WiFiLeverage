"""Pure-Python network-address helpers built on the stdlib ``ipaddress``.

Kept dependency-free and side-effect-free so the segmentation logic can be
unit-tested without any network access or privileges.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Iterator, List, Union

IPv4 = ipaddress.IPv4Address
Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_network(value: str) -> Network:
    """Parse a CIDR or bare address into a network (host bits cleared)."""
    return ipaddress.ip_network(value.strip(), strict=False)


def parse_networks(values: Iterable[str]) -> List[Network]:
    return [parse_network(v) for v in values]


def address_in_networks(addr: str, networks: Iterable[Network]) -> bool:
    """Return ``True`` if *addr* falls inside any of *networks*."""
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        return False
    return any(ip in net for net in networks)


def networks_overlap(a: Network, b: Network) -> bool:
    """Return ``True`` if two networks share any address space."""
    return a.overlaps(b)


def hosts(network: Network, limit: int = 1024) -> Iterator[str]:
    """Yield usable host addresses in *network*, capped at *limit*.

    The cap keeps an accidental ``/8`` in a scope file from trying to
    enumerate 16 million hosts.
    """
    count = 0
    for host in network.hosts():
        if count >= limit:
            return
        yield str(host)
        count += 1


def same_subnet(a: str, b: str, prefixlen: int) -> bool:
    """Return ``True`` if addresses *a* and *b* share a /prefixlen network."""
    try:
        net_a = ipaddress.ip_network(f"{a}/{prefixlen}", strict=False)
        ip_b = ipaddress.ip_address(b)
    except ValueError:
        return False
    return ip_b in net_a
