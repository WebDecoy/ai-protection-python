"""Resolve only explicitly trusted forwarding chains from an original socket peer."""

import ipaddress
from collections.abc import Mapping, Sequence


def resolve_client_ip(
    peer: str | None,
    headers: Mapping[str, str],
    *,
    trusted_proxy_cidrs: Sequence[str] = (),
) -> str | None:
    networks = tuple(ipaddress.ip_network(cidr) for cidr in trusted_proxy_cidrs)
    if any(network.prefixlen == 0 for network in networks) or len(networks) > 32:
        raise ValueError("trust specific ingress networks, not all addresses")

    def parse(raw: str | None):
        try:
            address = ipaddress.ip_address(raw or "")
            if getattr(address, "scope_id", None):
                return None
            return getattr(address, "ipv4_mapped", None) or address
        except ValueError:
            return None

    def trusted(address) -> bool:
        return any(address in network for network in networks)

    address = parse(peer)
    if address is None:
        return None
    forwarded = {key.lower(): value for key, value in headers.items()}
    chain = forwarded.get("x-forwarded-for", "")
    if not trusted(address):
        # Forwarding claims from an unconfigured ingress cannot identify the end user.
        return (
            None if chain or "forwarded" in forwarded or "x-real-ip" in forwarded else str(address)
        )
    if not chain or len(chain) > 8192 or len(chain.split(",")) > 32:
        return None
    for raw in reversed(chain.split(",")):
        address = parse(raw.strip())
        if address is None:
            return None
        if not trusted(address):
            return str(address)
    return None
