"""Thread-safe idempotency cache engine for M-Pesa webhook deduplication."""

import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple

from src.daraja.crypto import compute_payload_sha256


class IdempotencyStatus(str, Enum):
    """Lifecycle states of an in-flight or completed transaction webhook."""
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class IdempotencyRecord:
    key: str
    payload_hash: str
    status: IdempotencyStatus
    created_at: float
    expires_at: float
    response_payload: Optional[Dict[str, Any]] = None

    def is_expired(self) -> bool:
        return time.time() >= self.expires_at


class IdempotencyEngine:
    """In-memory thread-safe registry tracking transaction idempotency keys."""

    def __init__(self, default_ttl_seconds: int = 86400):
        self.default_ttl_seconds = default_ttl_seconds
        self._store: Dict[str, IdempotencyRecord] = {}
        self._lock = threading.RLock()

    def acquire(
        self,
        key: str,
        raw_payload: str | bytes,
        ttl_seconds: Optional[int] = None,
    ) -> Tuple[bool, Optional[IdempotencyRecord]]:
        """
        Attempt to register an idempotency key atomically.

        Returns:
            Tuple[bool, Optional[IdempotencyRecord]]:
                - (True, record) if the request is fresh and acquired for processing.
                - (False, record) if the request is a duplicate or currently in-flight.
        """
        if not key or not key.strip():
            raise ValueError("Idempotency key cannot be empty.")

        payload_hash = compute_payload_sha256(raw_payload)
        now = time.time()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        expires_at = now + ttl

        with self._lock:
            existing = self._store.get(key)
            if existing:
                if existing.is_expired():
                    # Evict expired record and allow fresh ingestion
                    del self._store[key]
                else:
                    return False, existing

            # Key is fresh: initialize record in PROCESSING state
            record = IdempotencyRecord(
                key=key,
                payload_hash=payload_hash,
                status=IdempotencyStatus.PROCESSING,
                created_at=now,
                expires_at=expires_at,
            )
            self._store[key] = record
            return True, record

    def complete(self, key: str, response_payload: Dict[str, Any]) -> None:
        """Mark an in-flight idempotency record as COMPLETED with its cached response."""
        with self._lock:
            record = self._store.get(key)
            if not record:
                raise KeyError(f"No active idempotency record found for key '{key}'.")
            record.status = IdempotencyStatus.COMPLETED
            record.response_payload = response_payload

    def fail(self, key: str) -> None:
        """Mark an in-flight idempotency record as FAILED or release it."""
        with self._lock:
            record = self._store.get(key)
            if record:
                record.status = IdempotencyStatus.FAILED

    def get_record(self, key: str) -> Optional[IdempotencyRecord]:
        """Inspect the current record for an idempotency key."""
        with self._lock:
            record = self._store.get(key)
            if record and record.is_expired():
                del self._store[key]
                return None
            return record

    def cleanup_expired(self) -> int:
        """Purge all expired records from memory. Returns count of purged keys."""
        with self._lock:
            now = time.time()
            expired_keys = [k for k, r in self._store.items() if now >= r.expires_at]
            for k in expired_keys:
                del self._store[k]
            return len(expired_keys)
        