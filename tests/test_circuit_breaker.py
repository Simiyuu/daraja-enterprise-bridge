"""Tests for circuit breaker lifecycle states, probe recovery, and exponential backoff retries."""

from unittest.mock import MagicMock
import pytest

from src.resilience.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    RetryPolicy,
)


class MockClock:
    """Controllable clock for instantaneous testing without sleeping."""

    def __init__(self, initial_time: float = 1000.0):
        self.current_time = initial_time

    def time(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


def test_circuit_breaker_init_validation():
    with pytest.raises(ValueError, match="failure_threshold must be greater than zero"):
        CircuitBreaker(failure_threshold=0)

    with pytest.raises(ValueError, match="recovery_timeout_seconds must be greater than zero"):
        CircuitBreaker(recovery_timeout_seconds=-1.0)


def test_circuit_breaker_closed_state_success():
    clock = MockClock()
    cb = CircuitBreaker(failure_threshold=3, time_func=clock.time)

    mock_func = MagicMock(return_value="OK")
    res = cb.call(mock_func)

    assert res == "OK"
    assert cb.state == CircuitState.CLOSED
    metrics = cb.metrics()
    assert metrics.success_count == 1
    assert metrics.failure_count == 0


def test_circuit_breaker_trips_to_open_after_threshold_breach():
    clock = MockClock()
    cb = CircuitBreaker(
        failure_threshold=3,
        recovery_timeout_seconds=30.0,
        expected_exceptions=(RuntimeError,),
        time_func=clock.time,
    )

    def failing_func():
        raise RuntimeError("Gateway connection dropped")

    # Failures 1 and 2: still CLOSED
    for _ in range(2):
        with pytest.raises(RuntimeError):
            cb.call(failing_func)
        assert cb.state == CircuitState.CLOSED

    # Failure 3: reaches threshold -> trips to OPEN
    with pytest.raises(RuntimeError):
        cb.call(failing_func)
    assert cb.state == CircuitState.OPEN

    # Subsequent call fast-fails with CircuitBreakerOpenError without calling target
    probe_mock = MagicMock()
    with pytest.raises(CircuitBreakerOpenError, match="is OPEN. Fast-failing"):
        cb.call(probe_mock)
    probe_mock.assert_not_called()


def test_circuit_breaker_recovery_to_half_open_and_closed():
    clock = MockClock()
    cb = CircuitBreaker(
        failure_threshold=2,
        recovery_timeout_seconds=20.0,
        half_open_success_threshold=2,
        expected_exceptions=(RuntimeError,),
        time_func=clock.time,
    )

    def faulty():
        raise RuntimeError("Outage")

    # Trip to OPEN
    with pytest.raises(RuntimeError):
        cb.call(faulty)
    with pytest.raises(RuntimeError):
        cb.call(faulty)
    assert cb.state == CircuitState.OPEN

    # 10s elapsed -> still OPEN
    clock.advance(10.0)
    assert cb.state == CircuitState.OPEN

    # 25s elapsed (total > 20s recovery timeout) -> transitions to HALF_OPEN
    clock.advance(15.0)
    assert cb.state == CircuitState.HALF_OPEN

    # First successful probe
    success_mock = MagicMock(return_value="RECOVERED")
    cb.call(success_mock)
    assert cb.state == CircuitState.HALF_OPEN

    # Second successful probe meets half_open_success_threshold -> transitions back to CLOSED
    cb.call(success_mock)
    assert cb.state == CircuitState.CLOSED

    metrics = cb.metrics()
    assert metrics.state == CircuitState.CLOSED
    assert metrics.failure_count == 0


def test_circuit_breaker_half_open_relapses_on_failure():
    clock = MockClock()
    cb = CircuitBreaker(
        failure_threshold=2,
        recovery_timeout_seconds=20.0,
        expected_exceptions=(RuntimeError,),
        time_func=clock.time,
    )

    # Trip to OPEN
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("1")))
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("2")))
    assert cb.state == CircuitState.OPEN

    # Advance past recovery window -> HALF_OPEN
    clock.advance(25.0)
    assert cb.state == CircuitState.HALF_OPEN

    # Single failure while in HALF_OPEN immediately trips back to OPEN
    with pytest.raises(RuntimeError):
        cb.call(lambda: (_ for _ in ()).throw(RuntimeError("Probe failed")))
    assert cb.state == CircuitState.OPEN


def test_retry_policy_eventual_success():
    sleep_calls: list[float] = []
    retry = RetryPolicy(
        max_retries=3,
        base_delay_seconds=1.0,
        enable_jitter=False,
        sleep_func=lambda d: sleep_calls.append(d),
    )

    attempts = 0

    def flaky():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ConnectionError("Transient network failure")
        return "SUCCESS"

    result = retry.execute(flaky, retry_exceptions=(ConnectionError,))

    assert result == "SUCCESS"
    assert attempts == 3
    # Attempt 0: delay 1.0, Attempt 1: delay 2.0
    assert sleep_calls == [1.0, 2.0]


def test_retry_policy_exhaustion_raises():
    sleep_calls: list[float] = []
    retry = RetryPolicy(
        max_retries=2,
        base_delay_seconds=0.5,
        enable_jitter=False,
        sleep_func=lambda d: sleep_calls.append(d),
    )

    def perpetually_failing():
        raise TimeoutError("Endpoint timeout")

    with pytest.raises(TimeoutError, match="Endpoint timeout"):
        retry.execute(perpetually_failing, retry_exceptions=(TimeoutError,))

    assert len(sleep_calls) == 2
    