"""Security utilities for validating Safaricom webhook ingress IP addresses and headers."""

import ipaddress
from typing import Iterable, List, Optional, Set, Union


# Standard Safaricom Daraja public gateway IP ranges (Production and Sandbox pools)
DEFAULT_SAFARICOM_CIDRS: List[str] = [
    "196.201.214.0/24",
    "196.201.213.0/24",
    "196.19.140.0/24",
    "196.19.141.0/24",
]


class IngressSecurityError(Exception):
    """Raised when an ingress request fails origin validation."""


class IPValidator:
    """Validates remote IP addresses against configured trusted CIDR blocks."""

    def __init__(
        self,
        allowed_cidrs: Optional[Iterable[str]] = None,
        allow_loopback: bool = False,
    ):
        raw_cidrs = list(allowed_cidrs) if allowed_cidrs is not None else DEFAULT_SAFARICOM_CIDRS
        self.allow_loopback = allow_loopback
        self.networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []

        for cidr in raw_cidrs:
            try:
                self.networks.append(ipaddress.ip_network(cidr.strip(), strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR block provided '{cidr}': {exc}") from exc

    def is_authorized(self, client_ip: str) -> bool:
        """
        Evaluate if an IP address belongs to allowed CIDR networks.

        Returns:
            bool: True if authorized, False otherwise.
        """
        if not client_ip or not isinstance(client_ip, str):
            return False

        try:
            parsed_ip = ipaddress.ip_address(client_ip.strip())
        except ValueError:
            return False

        if self.allow_loopback and parsed_ip.is_loopback:
            return True

        return any(parsed_ip in network for network in self.networks)

    def enforce_authorized(self, client_ip: str) -> None:
        """Raise IngressSecurityError if the client IP is not within trusted ranges."""
        if not self.is_authorized(client_ip):
            raise IngressSecurityError(
                f"Ingress rejected: IP '{client_ip}' does not match authorized gateway ranges."
            )


def extract_client_ip(
    headers: dict,
    remote_addr: Optional[str] = None,
    trusted_proxy_count: int = 1,
) -> str:
    """
    Extract the real client IP from incoming HTTP request headers safely.

    Handles X-Forwarded-For headers with reverse proxy topology awareness.
    If trusted_proxy_count is 1, the immediate client IP before the last proxy is used.
    """
    # Normalize header keys to lowercase
    normalized = {k.lower(): v for k, v in headers.items()}
    x_forwarded_for = normalized.get("x-forwarded-for")

    if x_forwarded_for:
        # Split and clean all IPs in the forwarding chain
        ip_list = [ip.strip() for ip in x_forwarded_for.split(",") if ip.strip()]
        if ip_list:
            # Taking the client IP from the right side relative to trusted proxy depth
            if len(ip_list) >= trusted_proxy_count:
                target_ip = ip_list[-trusted_proxy_count]
            else:
                target_ip = ip_list[0]
            try:
                ipaddress.ip_address(target_ip)
                return target_ip
            except ValueError:
                pass

    if remote_addr and remote_addr.strip():
        try:
            ipaddress.ip_address(remote_addr.strip())
            return remote_addr.strip()
        except ValueError:
            pass

    return "0.0.0.0"