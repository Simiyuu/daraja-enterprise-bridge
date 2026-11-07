"""Resilient circuit breaker and exponential backoff retry engine for external API calls."""

from dataclasses import dataclass, field
from enum import Enum
import random
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, TypeVar

T = TypeVar("T")


class CircuitState(str, Enum):
    """Lifecycle states of the circuit breaker."""
    CLOSED = "CLOSED"        # Normal operations: calls pass through
    OPEN = "OPEN"            # Outage detected: fail fast, calls blocked
    HALF_OPEN = "HALF_OPEN"  # Testing recovery: trial probe traffic allowed


class CircuitBreakerOpenError(Exception):
    """Raised when an execution attempt is rejected because the circuit is OPEN."""

    def __init__(self, message: str, opened_at: float, recovery_timeout: float):
        super().__init__(message)
        self.opened_at = opened_at
        self.recovery_timeout = recovery_timeout


@dataclass(frozen=True)
class CircuitBreakerMetrics:
    """Operational telemetry snapshot of the circuit breaker."""
    state: CircuitState
    failure_count: int
    success_count: int
    consecutive_successes: int
    last_failure_time: Optional[float]
    last_state_change: float


class CircuitBreaker:
    """
    Thread-safe three-state circuit breaker for external service integration.

    Transitions:
        - CLOSED -> OPEN: When failure_count >= failure_threshold within window.
        - OPEN -> HALF_OPEN: When current_time >= opened_at + recovery_timeout_seconds.
        - HALF_OPEN -> CLOSED: When consecutive_successes >= half_open_success_threshold.
        - HALF_OPEN -> OPEN: On any failure while probing.
    """

    def __init__(
        self,
        name: str = "daraja-gateway-breaker",
        failure_threshold: int = 5,
        recovery_timeout_seconds: float = 30.0,
        half_open_success_threshold: int = 2,
        expected_exceptions: Optional[Tuple[Type[Exception], ...]] = None,
        time_func: Optional[Callable[[], float]] = None,
    ):
        if failure_threshold <= 0:
            raise ValueError("failure_threshold must be greater than zero.")
        if recovery_timeout_seconds <= 0.0:
            raise ValueError("recovery_timeout_seconds must be greater than zero.")
        if half_open_success_threshold <= 0:
            raise ValueError("half_open_success_threshold must be greater than zero.")

        self.name = name
        self.failure_threshold = failure_threshold
        self.recovery_timeout_seconds = recovery_timeout_seconds
        self.half_open_success_threshold = half_open_success_threshold
        self.expected_exceptions = expected_exceptions or (Exception,)
        self._time_func = time_func or time.time

        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._consecutive_successes = 0
        self._total_successes = 0
        self._last_failure_time: Optional[float] = None
        self._last_state_change: float = self._time_func()
        self._opened_at: Optional[float] = None
        self._lock = threading.RLock()

    @property
    def state(self) -> CircuitState:
        """Inspect current state with automatic OPEN -> HALF_OPEN evaluation."""
        with self._lock:
            now = self._time_func()
            if self._state == CircuitState.OPEN and self._opened_at is not None:
                if now - self._opened_at >= self.recovery_timeout_seconds:
                    self._state = CircuitState.HALF_OPEN
                    self._consecutive_successes = 0
                    self._last_state_change = now
            return self._state

    def call(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        Execute callable through the circuit breaker guard.

        Raises:
            CircuitBreakerOpenError: If the circuit is currently OPEN.
            Exception: Re-raises the target function's exception upon failure.
        """
        with self._lock:
            current_state = self.state

            if current_state == CircuitState.OPEN:
                raise CircuitBreakerOpenError(
                    f"Circuit breaker '{self.name}' is OPEN. Fast-failing downstream request.",
                    opened_at=self._opened_at or self._last_state_change,
                    recovery_timeout=self.recovery_timeout_seconds,
                )

        # Execute target callable outside lock to avoid blocking other threads during network I/O
        try:
            result = func(*args, **kwargs)
        except self.expected_exceptions:
            with self._lock:
                self._record_failure()
            raise

        with self._lock:
            self._record_success()

        return result

    def _record_success(self) -> None:
        """Record successful invocation."""
        now = self._time_func()
        self._total_successes += 1

        if self._state == CircuitState.HALF_OPEN:
            self._consecutive_successes += 1
            if self._consecutive_successes >= self.half_open_success_threshold:
                self._state = CircuitState.CLOSED
                self._failure_count = 0
                self._consecutive_successes = 0
                self._opened_at = None
                self._last_state_change = now
        elif self._state == CircuitState.CLOSED:
            self._failure_count = 0

    def _record_failure(self) -> None:
        """Record failed invocation and trip breaker if threshold breached."""
        now = self._time_func()
        self._last_failure_time = now

        if self._state == CircuitState.HALF_OPEN:
            # Immediate relapse to OPEN on any probe failure
            self._state = CircuitState.OPEN
            self._opened_at = now
            self._last_state_change = now
            self._consecutive_successes = 0
        elif self._state == CircuitState.CLOSED:
            self._failure_count += 1
            if self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = now
                self._last_state_change = now

    def reset(self) -> None:
        """Force manual reset back to clean CLOSED state."""
        with self._lock:
            now = self._time_func()
            self._state = CircuitState.CLOSED
            self._failure_count = 0
            self._consecutive_successes = 0
            self._opened_at = None
            self._last_state_change = now

    def metrics(self) -> CircuitBreakerMetrics:
        """Snapshot current operational metrics."""
        with self._lock:
            return CircuitBreakerMetrics(
                state=self.state,
                failure_count=self._failure_count,
                success_count=self._total_successes,
                consecutive_successes=self._consecutive_successes,
                last_failure_time=self._last_failure_time,
                last_state_change=self._last_state_change,
            )


class RetryPolicy:
    """Configurable jittered exponential backoff retry executor."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay_seconds: float = 0.5,
        max_delay_seconds: float = 8.0,
        backoff_multiplier: float = 2.0,
        enable_jitter: bool = True,
        sleep_func: Optional[Callable[[float], None]] = None,
    ):
        if max_retries < 0:
            raise ValueError("max_retries cannot be negative.")
        if base_delay_seconds <= 0:
            raise ValueError("base_delay_seconds must be positive.")
        if max_delay_seconds < base_delay_seconds:
            raise ValueError("max_delay_seconds must be >= base_delay_seconds.")

        self.max_retries = max_retries
        self.base_delay_seconds = base_delay_seconds
        self.max_delay_seconds = max_delay_seconds
        self.backoff_multiplier = backoff_multiplier
        self.enable_jitter = enable_jitter
        self._sleep_func = sleep_func or time.sleep

    def compute_delay(self, attempt: int) -> float:
        """Compute backoff delay with full jitter."""
        delay = min(self.max_delay_seconds, self.base_delay_seconds * (self.backoff_multiplier ** attempt))
        if self.enable_jitter:
            delay = random.uniform(0.0, delay)
        return delay

    def execute(
        self,
        func: Callable[..., T],
        retry_exceptions: Tuple[Type[Exception], ...],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """
        Execute callable with automatic retries on recognized transient errors.
        """
        last_exception: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except retry_exceptions as exc:
                last_exception = exc
                if attempt == self.max_retries:
                    raise last_exception
                delay = self.compute_delay(attempt)
                self._sleep_func(delay)

        assert last_exception is not None
        raise last_exception
    