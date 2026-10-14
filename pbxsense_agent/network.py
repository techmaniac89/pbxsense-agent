from __future__ import annotations

import ipaddress


def is_private_or_loopback_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() == "localhost"
    return address.is_private or address.is_loopback or address.is_link_local


def is_loopback_host(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host.lower() == "localhost"


def is_trusted_lan_host(host: str) -> bool:
    """Explicit LAN ranges, not Python's broader private/reserved classification."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in ipaddress.ip_network(network) for network in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
