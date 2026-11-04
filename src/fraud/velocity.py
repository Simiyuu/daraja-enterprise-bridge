"""Sliding-window velocity profiling and rate anomaly detection engine."""

from dataclasses import dataclass, field
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
import threading
import time


@dataclass(frozen=True)
class VelocityWindow:
    """Configurable evaluation window for rate and volume bounds."""
    window_seconds: int
    max_count: int
    max_volume: Optional[Decimal] = None


@dataclass(frozen=True)
class VelocityViolation:
    """Detailed audit of a breached velocity threshold."""
    window_seconds: int
    metric: str  # "COUNT" or "VOLUME"
    limit: Decimal
    observed: Decimal


@dataclass(frozen=True)
class VelocityEvaluation:
    """Evaluation decision payload returned to the transaction gatekeeper."""
    key: str
    is_allowed: bool
    violations: List[VelocityViolation] = field(default_factory=list)
    evaluated_at: float = field(default_factory=time.time)


class VelocityProfiler:
    """Thread-safe sliding-window event recorder and velocity rate evaluator."""

    def __init__(self, default_windows: Optional[List[VelocityWindow]] = None):
        self.default_windows = default_windows or [
            VelocityWindow(window_seconds=60, max_count=5, max_volume=Decimal("150000.00")),
            VelocityWindow(window_seconds=3600, max_count=30, max_volume=Decimal("500000.00")),
            VelocityWindow(window_seconds=86400, max_count=100, max_volume=Decimal("1000000.00")),
        ]
        # In-memory store: {entity_key: [(timestamp, amount), ...]}
        self._events: Dict[str, List[Tuple[float, Decimal]]] = {}
        self._lock = threading.RLock()

    def record_event(
        self,
        key: str,
        amount: Decimal,
        timestamp: Optional[float] = None,
    ) -> None:
        """Register a confirmed or in-flight transaction event for an entity key."""
        if not key or not key.strip():
            raise ValueError("Entity key cannot be empty.")
        if amount <= Decimal("0.00"):
            raise ValueError(f"Amount must be positive. Received: {amount}")

        event_time = timestamp if timestamp is not None else time.time()
        clean_key = key.strip()

        with self._lock:
            if clean_key not in self._events:
                self._events[clean_key] = []
            self._events[clean_key].append((event_time, amount))

    def evaluate(
        self,
        key: str,
        amount: Decimal,
        windows: Optional[List[VelocityWindow]] = None,
        timestamp: Optional[float] = None,
    ) -> VelocityEvaluation:
        """
        Evaluate if a proposed transaction violates any sliding-window velocity thresholds.

        Does not register the event; purely evaluates projected metrics.
        """
        if not key or not key.strip():
            raise ValueError("Entity key cannot be empty.")
        if amount <= Decimal("0.00"):
            raise ValueError(f"Amount must be positive. Received: {amount}")

        eval_time = timestamp if timestamp is not None else time.time()
        active_windows = windows or self.default_windows
        clean_key = key.strip()
        violations: List[VelocityViolation] = []

        with self._lock:
            events = self._events.get(clean_key, [])

            for window in active_windows:
                cutoff_time = eval_time - window.window_seconds
                # Extract events within the sliding window
                window_events = [e for e in events if e[0] >= cutoff_time]

                # Project count and volume including current transaction
                projected_count = len(window_events) + 1
                projected_volume = sum((e[1] for e in window_events), Decimal("0.00")) + amount

                if projected_count > window.max_count:
                    violations.append(
                        VelocityViolation(
                            window_seconds=window.window_seconds,
                            metric="COUNT",
                            limit=Decimal(str(window.max_count)),
                            observed=Decimal(str(projected_count)),
                        )
                    )

                if window.max_volume is not None and projected_volume > window.max_volume:
                    violations.append(
                        VelocityViolation(
                            window_seconds=window.window_seconds,
                            metric="VOLUME",
                            limit=window.max_volume,
                            observed=projected_volume,
                        )
                    )

        is_allowed = len(violations) == 0
        return VelocityEvaluation(
            key=clean_key,
            is_allowed=is_allowed,
            violations=violations,
            evaluated_at=eval_time,
        )

    def evaluate_and_record(
        self,
        key: str,
        amount: Decimal,
        windows: Optional[List[VelocityWindow]] = None,
        timestamp: Optional[float] = None,
    ) -> VelocityEvaluation:
        """Atomic check-and-record operation under concurrency lock."""
        with self._lock:
            decision = self.evaluate(key, amount, windows=windows, timestamp=timestamp)
            if decision.is_allowed:
                self.record_event(key, amount, timestamp=timestamp)
            return decision

    def prune_stale_events(self, max_retention_seconds: int = 86400) -> int:
        """Purge historical entries older than the longest retention horizon."""
        now = time.time()
        cutoff = now - max_retention_seconds
        purged_count = 0

        with self._lock:
            keys_to_delete = []
            for key, event_list in self._events.items():
                fresh_events = [e for e in event_list if e[0] >= cutoff]
                purged_count += len(event_list) - len(fresh_events)
                if fresh_events:
                    self._events[key] = fresh_events
                else:
                    keys_to_delete.append(key)

            for key in keys_to_delete:
                del self._events[key]

        return purged_count


        