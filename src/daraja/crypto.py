"""Cryptographic utilities for Daraja password synthesis and payload verification."""

import base64
import hashlib
import hmac
from datetime import datetime, timezone
from typing import Optional, Union


def get_current_timestamp() -> str:
    """Generate a 14-character UTC timestamp in canonical YYYYMMDDHHmmss format."""
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


def generate_stk_password(
    business_short_code: str,
    passkey: str,
    timestamp: Optional[str] = None
) -> tuple[str, str]:
    """
    Compile the dynamic Base64 password required for Daraja STK Push requests.

    Formula: Base64(BusinessShortCode + Passkey + Timestamp)
    Returns: Tuple of (base64_encoded_password, timestamp_used)
    """
    if not business_short_code or not business_short_code.strip():
        raise ValueError("business_short_code cannot be empty.")
    if not passkey or not passkey.strip():
        raise ValueError("passkey cannot be empty.")

    ts = timestamp if timestamp else get_current_timestamp()

    # Validate timestamp format
    try:
        datetime.strptime(ts, "%Y%m%d%H%M%S")
    except ValueError:
        raise ValueError(f"Invalid timestamp '{ts}'. Expected format: YYYYMMDDHHmmss.")

    raw_concatenation = f"{business_short_code.strip()}{passkey.strip()}{ts}"
    encoded_bytes = base64.b64encode(raw_concatenation.encode("utf-8"))
    return encoded_bytes.decode("utf-8"), ts


def compute_payload_sha256(payload: Union[str, bytes]) -> str:
    """Compute the hexadecimal SHA-256 digest of a payload for deduplication and idempotency."""
    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise TypeError("Payload must be of type str or bytes.")

    return hashlib.sha256(payload_bytes).hexdigest()


def compute_hmac_sha256(payload: Union[str, bytes], secret: str) -> str:
    """Compute HMAC-SHA256 hex digest using a shared secret key."""
    if not secret:
        raise ValueError("Secret key cannot be empty.")

    if isinstance(payload, str):
        payload_bytes = payload.encode("utf-8")
    elif isinstance(payload, bytes):
        payload_bytes = payload
    else:
        raise TypeError("Payload must be of type str or bytes.")

    return hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def verify_hmac_sha256(
    payload: Union[str, bytes],
    secret: str,
    expected_signature: str
) -> bool:
    """Timing-attack-resistant verification of HMAC-SHA256 signatures."""
    if not expected_signature:
        return False
    computed_signature = compute_hmac_sha256(payload, secret)
    return hmac.compare_digest(computed_signature, expected_signature)
    