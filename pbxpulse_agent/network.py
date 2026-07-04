from __future__ import annotations

import ipaddress


def is_private_or_loopback_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() == "localhost"
    return address.is_private or address.is_loopback or address.is_link_local
