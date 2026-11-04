"""Tests for sliding-window velocity profiling, threshold limits, and concurrency safety."""

import concurrent.futures
from decimal import Decimal
import time
import pytest

from src.fraud.velocity import VelocityProfiler, VelocityWindow


def test_velocity_input_validation():
    profiler = VelocityProfiler()
    with pytest.raises(ValueError, match="Entity key cannot be empty"):
        profiler.record_event("", Decimal("100.00"))

    with pytest.raises(ValueError, match="Amount must be positive"):
        profiler.record_event("254712345678", Decimal("0.00"))


def test_velocity_count_threshold_breach():
    # Allow 2 transactions per 60 seconds
    window = VelocityWindow(window_seconds=60, max_count=2)
    profiler = VelocityProfiler(default_windows=[window])
    msisdn = "254712345678"

    # Transaction 1: allowed
    res1 = profiler.evaluate_and_record(msisdn, Decimal("500.00"))
    assert res1.is_allowed is True
    assert len(res1.violations) == 0

    # Transaction 2: allowed
    res2 = profiler.evaluate_and_record(msisdn, Decimal("500.00"))
    assert res2.is_allowed is True

    # Transaction 3: exceeds count of 2 in 60s
    res3 = profiler.evaluate(msisdn, Decimal("500.00"))
    assert res3.is_allowed is False
    assert len(res3.violations) == 1
    assert res3.violations[0].metric == "COUNT"
    assert res3.violations[0].observed == Decimal("3")


def test_velocity_volume_threshold_breach():
    # Allow max 1,000 KES within 60 seconds
    window = VelocityWindow(window_seconds=60, max_count=10, max_volume=Decimal("1000.00"))
    profiler = VelocityProfiler(default_windows=[window])
    msisdn = "254700000001"

    profiler.record_event(msisdn, Decimal("600.00"))
    profiler.record_event(msisdn, Decimal("300.00"))

    # Next 150.00 brings volume to 1050.00 -> violation
    res = profiler.evaluate(msisdn, Decimal("150.00"))
    assert res.is_allowed is False
    assert len(res.violations) == 1
    assert res.violations[0].metric == "VOLUME"
    assert res.violations[0].observed == Decimal("1050.00")
    assert res.violations[0].limit == Decimal("1000.00")


def test_sliding_window_time_eviction():
    window = VelocityWindow(window_seconds=2, max_count=1)
    profiler = VelocityProfiler(default_windows=[window])
    msisdn = "254722222222"

    t0 = 1000.0
    profiler.record_event(msisdn, Decimal("100.00"), timestamp=t0)

    # Within 2 seconds (t0 + 1s) -> should breach
    eval_soon = profiler.evaluate(msisdn, Decimal("100.00"), timestamp=t0 + 1.0)
    assert eval_soon.is_allowed is False

    # After window passes (t0 + 3s) -> should be allowed
    eval_later = profiler.evaluate(msisdn, Decimal("100.00"), timestamp=t0 + 3.0)
    assert eval_later.is_allowed is True


def test_concurrent_velocity_evaluations_thread_safety():
    # Allow 10 transactions max across 50 competing threads
    window = VelocityWindow(window_seconds=60, max_count=10)
    profiler = VelocityProfiler(default_windows=[window])
    msisdn = "254799999999"

    def worker():
        res = profiler.evaluate_and_record(msisdn, Decimal("50.00"))
        return res.is_allowed

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        outcomes = list(executor.map(lambda _: worker(), range(50)))

    # Exactly 10 should succeed, 40 should be rejected
    assert outcomes.count(True) == 10
    assert outcomes.count(False) == 40


def test_prune_stale_events():
    profiler = VelocityProfiler()
    msisdn = "254711111111"
    now = time.time()

    # Event 2 days ago
    profiler.record_event(msisdn, Decimal("100.00"), timestamp=now - 172800)
    # Event 1 hour ago
    profiler.record_event(msisdn, Decimal("200.00"), timestamp=now - 3600)

    # Prune older than 24 hours (86400s)
    purged = profiler.prune_stale_events(max_retention_seconds=86400)
    assert purged == 1

    # Remaining event in memory must be the 1 hour ago entry
    assert len(profiler._events[msisdn]) == 1
    