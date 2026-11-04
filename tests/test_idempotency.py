"""Tests for the webhook idempotency cache engine."""

import concurrent.futures
import time
import pytest

from src.webhook.idempotency import IdempotencyEngine, IdempotencyStatus


def test_idempotency_empty_key_validation():
    engine = IdempotencyEngine()
    with pytest.raises(ValueError, match="Idempotency key cannot be empty"):
        engine.acquire("", '{"ResultCode": 0}')


def test_idempotency_acquire_and_complete_lifecycle():
    engine = IdempotencyEngine(default_ttl_seconds=300)
    key = "ws_CO_04112026190000001"
    raw_payload = '{"ResultCode": 0, "Amount": 1500}'

    # First acquisition: successful
    acquired, record = engine.acquire(key, raw_payload)
    assert acquired is True
    assert record.status == IdempotencyStatus.PROCESSING
    assert len(record.payload_hash) == 64

    # Second acquisition: must be detected as duplicate in-flight
    dup_acquired, dup_record = engine.acquire(key, raw_payload)
    assert dup_acquired is False
    assert dup_record.status == IdempotencyStatus.PROCESSING

    # Complete the transaction
    response_data = {"status": "ACK", "receipt": "TK32XYZ123"}
    engine.complete(key, response_data)

    # Check status transition
    completed_record = engine.get_record(key)
    assert completed_record is not None
    assert completed_record.status == IdempotencyStatus.COMPLETED
    assert completed_record.response_payload == response_data


def test_idempotency_failure_state_handling():
    engine = IdempotencyEngine()
    key = "ws_CO_FAILED_001"
    engine.acquire(key, '{"error": true}')
    engine.fail(key)

    record = engine.get_record(key)
    assert record is not None
    assert record.status == IdempotencyStatus.FAILED


def test_idempotency_ttl_expiration_and_cleanup():
    # 1 second TTL
    engine = IdempotencyEngine(default_ttl_seconds=1)
    key = "ws_CO_EXPIRE_001"
    engine.acquire(key, '{"amount": 100}')

    # Verify present immediately
    assert engine.get_record(key) is not None

    # Sleep past expiration
    time.sleep(1.1)

    # get_record should lazily evict
    assert engine.get_record(key) is None

    # Manual cleanup
    engine.acquire("ws_CO_EXPIRE_002", '{"amount": 200}', ttl_seconds=1)
    time.sleep(1.1)
    purged_count = engine.cleanup_expired()
    assert purged_count >= 1


def test_idempotency_concurrency_race_condition():
    """Simulate 20 simultaneous webhook requests arriving at the exact same millisecond."""
    engine = IdempotencyEngine(default_ttl_seconds=60)
    key = "ws_CO_RACE_CONDITION_KEY"
    raw_payload = '{"TransactionID": "QK99XYZ"}'

    def worker():
        acquired, _ = engine.acquire(key, raw_payload)
        return acquired

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(lambda _: worker(), range(20)))

    # Exactly ONE thread must acquire successfully; 19 must be rejected as duplicates
    assert results.count(True) == 1
    assert results.count(False) == 19
    