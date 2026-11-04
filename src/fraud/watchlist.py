"""Multi-vector entity watchlist, sanctions, and denylist screening engine."""

from dataclasses import dataclass, field
from enum import Enum
import ipaddress
import threading
import time
from typing import Any, Dict, List, Optional, Union

from src.models.contracts import normalize_msisdn


class WatchlistType(str, Enum):
    """Classification tiers for entity watchlist screening."""
    BLACKLIST = "BLACKLIST"   # Immediate block / intercept
    GREYLIST = "GREYLIST"     # Enhanced scrutiny / step-up auth
    WHITELIST = "WHITELIST"   # Trusted / bypass standard rules


class WatchlistEntityType(str, Enum):
    """Supported entity identifier vectors."""
    MSISDN = "MSISDN"
    IP_ADDRESS = "IP_ADDRESS"
    DEVICE_ID = "DEVICE_ID"
    MERCHANT_ID = "MERCHANT_ID"


@dataclass(frozen=True)
class WatchlistEntry:
    """Record defining an entity's status on a watchlist."""
    entity_value: str
    entity_type: WatchlistEntityType
    list_type: WatchlistType
    reason: str
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        if self.expires_at is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at


@dataclass(frozen=True)
class WatchlistMatch:
    """Outcome of an entity screening evaluation."""
    matched: bool
    list_type: Optional[WatchlistType] = None
    entry: Optional[WatchlistEntry] = None


class WatchlistEngine:
    """Thread-safe multi-vector watchlist registry and real-time screening filter."""

    def __init__(self):
        # Exact-match index: {(entity_type, normalized_value): WatchlistEntry}
        self._entries: Dict[tuple[WatchlistEntityType, str], WatchlistEntry] = {}
        # Subnet-match index for IP ranges: list of (IPv4Network/IPv6Network, WatchlistEntry)
        self._ip_subnets: List[tuple[Union[ipaddress.IPv4Network, ipaddress.IPv6Network], WatchlistEntry]] = []
        self._lock = threading.RLock()

    def _normalize_value(self, entity_type: WatchlistEntityType, raw_val: str) -> str:
        val = raw_val.strip()
        if entity_type == WatchlistEntityType.MSISDN:
            return normalize_msisdn(val)
        elif entity_type in (WatchlistEntityType.DEVICE_ID, WatchlistEntityType.MERCHANT_ID):
            return val.upper()
        return val

    def add_entry(
        self,
        entity_value: str,
        entity_type: WatchlistEntityType,
        list_type: WatchlistType,
        reason: str,
        ttl_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        created_at: Optional[float] = None,
    ) -> WatchlistEntry:
        """
        Register an entity on a target watchlist.

        Supports single IP addresses or CIDR ranges (e.g., '196.201.214.0/24').
        """
        if not entity_value or not entity_value.strip():
            raise ValueError("Entity value cannot be empty.")
        if not reason or not reason.strip():
            raise ValueError("Reason cannot be empty.")

        now = created_at if created_at is not None else time.time()
        expires_at = (now + ttl_seconds) if ttl_seconds is not None else None
        meta = metadata or {}

        with self._lock:
            # Handle IP CIDR notation
            if entity_type == WatchlistEntityType.IP_ADDRESS and "/" in entity_value:
                try:
                    network = ipaddress.ip_network(entity_value.strip(), strict=False)
                except ValueError as exc:
                    raise ValueError(f"Invalid IP CIDR range: '{entity_value}'") from exc

                entry = WatchlistEntry(
                    entity_value=str(network),
                    entity_type=entity_type,
                    list_type=list_type,
                    reason=reason,
                    created_at=now,
                    expires_at=expires_at,
                    metadata=meta,
                )
                # Overwrite existing if identical subnet
                self._ip_subnets = [
                    (net, ent) for net, ent in self._ip_subnets if net != network
                ]
                self._ip_subnets.append((network, entry))
                return entry

            # Standard point identifier
            clean_val = self._normalize_value(entity_type, entity_value)
            entry = WatchlistEntry(
                entity_value=clean_val,
                entity_type=entity_type,
                list_type=list_type,
                reason=reason,
                created_at=now,
                expires_at=expires_at,
                metadata=meta,
            )
            self._entries[(entity_type, clean_val)] = entry
            return entry

    def remove_entry(self, entity_value: str, entity_type: WatchlistEntityType) -> bool:
        """Remove an entry from the registry. Returns True if found and removed."""
        with self._lock:
            if entity_type == WatchlistEntityType.IP_ADDRESS and "/" in entity_value:
                try:
                    network = ipaddress.ip_network(entity_value.strip(), strict=False)
                    initial_len = len(self._ip_subnets)
                    self._ip_subnets = [
                        (net, ent) for net, ent in self._ip_subnets if net != network
                    ]
                    return len(self._ip_subnets) < initial_len
                except ValueError:
                    return False

            try:
                clean_val = self._normalize_value(entity_type, entity_value)
            except ValueError:
                return False

            key = (entity_type, clean_val)
            if key in self._entries:
                del self._entries[key]
                return True
            return False

    def screen(
        self,
        entity_value: str,
        entity_type: WatchlistEntityType,
        current_time: Optional[float] = None,
    ) -> WatchlistMatch:
        """
        Screen an entity against registered lists.

        Returns WatchlistMatch with matched=True if an active, non-expired entry exists.
        """
        if not entity_value or not entity_value.strip():
            return WatchlistMatch(matched=False)

        now = current_time if current_time is not None else time.time()

        with self._lock:
            # 1. Exact match lookup
            try:
                clean_val = self._normalize_value(entity_type, entity_value)
                key = (entity_type, clean_val)
                entry = self._entries.get(key)
                if entry:
                    if entry.is_expired(now):
                        del self._entries[key]
                    else:
                        return WatchlistMatch(matched=True, list_type=entry.list_type, entry=entry)
            except ValueError:
                # Invalid format (e.g. malformed MSISDN string)
                pass

            # 2. IP Subnet sweep (if IP screening)
            if entity_type == WatchlistEntityType.IP_ADDRESS:
                try:
                    ip_obj = ipaddress.ip_address(entity_value.strip())
                    for network, subnet_entry in list(self._ip_subnets):
                        if subnet_entry.is_expired(now):
                            self._ip_subnets.remove((network, subnet_entry))
                            continue
                        if ip_obj in network:
                            return WatchlistMatch(
                                matched=True,
                                list_type=subnet_entry.list_type,
                                entry=subnet_entry,
                            )
                except ValueError:
                    pass

        return WatchlistMatch(matched=False)

    def prune_expired(self, current_time: Optional[float] = None) -> int:
        """Prune all expired watchlist entries. Returns number of purged items."""
        now = current_time if current_time is not None else time.time()
        purged = 0

        with self._lock:
            expired_keys = [
                key for key, entry in self._entries.items() if entry.is_expired(now)
            ]
            for key in expired_keys:
                del self._entries[key]
                purged += 1

            active_subnets = []
            for network, entry in self._ip_subnets:
                if entry.is_expired(now):
                    purged += 1
                else:
                    active_subnets.append((network, entry))
            self._ip_subnets = active_subnets

        return purged
    