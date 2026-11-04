"""Tests for entity watchlist screening, normalization, CIDR matching, and TTL rules."""

import concurrent.futures
import time
import pytest

from src.fraud.watchlist import (
    WatchlistEngine,
    WatchlistEntityType,
    WatchlistType,
)


def test_add_entry_input_validation():
    engine = WatchlistEngine()
    with pytest.raises(ValueError, match="Entity value cannot be empty"):
        engine.add_entry("", WatchlistEntityType.MSISDN, WatchlistType.BLACKLIST, "Fraud")

    with pytest.raises(ValueError, match="Reason cannot be empty"):
        engine.add_entry("0712345678", WatchlistEntityType.MSISDN, WatchlistType.BLACKLIST, "")


def test_msisdn_screening_with_normalization():
    engine = WatchlistEngine()
    # Add as local Kenyan format
    engine.add_entry(
        entity_value="0712345678",
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.BLACKLIST,
        reason="Reported SIM swap syndicate",
    )

    # Screen using international E.164 format
    match_int = engine.screen("+254712345678", WatchlistEntityType.MSISDN)
    assert match_int.matched is True
    assert match_int.list_type == WatchlistType.BLACKLIST
    assert match_int.entry is not None
    assert match_int.entry.entity_value == "254712345678"

    # Unlisted number returns clean
    clean_match = engine.screen("0722000000", WatchlistEntityType.MSISDN)
    assert clean_match.matched is False
    assert clean_match.list_type is None


def test_ip_cidr_subnet_screening():
    engine = WatchlistEngine()
    # Blacklist an entire /24 botnet subnet
    engine.add_entry(
        entity_value="196.201.214.0/24",
        entity_type=WatchlistEntityType.IP_ADDRESS,
        list_type=WatchlistType.BLACKLIST,
        reason="Compromised data-center proxy pool",
    )

    # Any IP inside that range must trigger a match
    match_sub = engine.screen("196.201.214.55", WatchlistEntityType.IP_ADDRESS)
    assert match_sub.matched is True
    assert match_sub.list_type == WatchlistType.BLACKLIST

    # IP outside range passes
    match_out = engine.screen("196.201.215.1", WatchlistEntityType.IP_ADDRESS)
    assert match_out.matched is False


def test_device_and_merchant_case_insensitivity():
    engine = WatchlistEngine()
    engine.add_entry(
        entity_value="dev-uuid-abcdef",
        entity_type=WatchlistEntityType.DEVICE_ID,
        list_type=WatchlistType.GREYLIST,
        reason="Rooted device emulator",
    )

    match = engine.screen("DEV-UUID-ABCDEF", WatchlistEntityType.DEVICE_ID)
    assert match.matched is True
    assert match.list_type == WatchlistType.GREYLIST


def test_ttl_expiration_behavior():
    engine = WatchlistEngine()
    t0 = 1000.0

    # Pass created_at=t0 so expires_at calculates to 1005.0 deterministically
    engine.add_entry(
        entity_value="0711111111",
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.BLACKLIST,
        reason="Temporary rate lock",
        ttl_seconds=5,
        created_at=t0,
    )

    # Screening at t0 + 2s (1002.0) -> active
    assert engine.screen("0711111111", WatchlistEntityType.MSISDN, current_time=t0 + 2.0).matched is True

    # Screening at t0 + 6s (1006.0) -> expired
    assert engine.screen("0711111111", WatchlistEntityType.MSISDN, current_time=t0 + 6.0).matched is False


def test_removal_and_pruning():
    engine = WatchlistEngine()
    engine.add_entry("0722222222", WatchlistEntityType.MSISDN, WatchlistType.WHITELIST, "VIP")
    assert engine.screen("0722222222", WatchlistEntityType.MSISDN).matched is True

    removed = engine.remove_entry("0722222222", WatchlistEntityType.MSISDN)
    assert removed is True
    assert engine.screen("0722222222", WatchlistEntityType.MSISDN).matched is False

    # Prune expired test
    engine.add_entry(
        "10.0.0.0/24",
        WatchlistEntityType.IP_ADDRESS,
        WatchlistType.BLACKLIST,
        "Temp ban",
        ttl_seconds=1,
    )
    time.sleep(1.1)
    purged = engine.prune_expired()
    assert purged >= 1


def test_concurrent_screening_and_mutation():
    engine = WatchlistEngine()

    def worker(i: int):
        phone = f"0712345{i:03d}"
        engine.add_entry(phone, WatchlistEntityType.MSISDN, WatchlistType.BLACKLIST, "Batch")
        res = engine.screen(phone, WatchlistEntityType.MSISDN)
        return res.matched

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(worker, range(50)))

    assert all(results)
    