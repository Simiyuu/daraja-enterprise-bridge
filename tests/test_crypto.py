"""Tests for dynamic password compilation, SHA-256 digests, and HMAC verification."""

import base64
import pytest
from src.daraja.crypto import (
    compute_hmac_sha256,
    compute_payload_sha256,
    generate_stk_password,
    get_current_timestamp,
    verify_hmac_sha256,
)


def test_get_current_timestamp_format():
    ts = get_current_timestamp()
    assert len(ts) == 14
    assert ts.isdigit()


def test_generate_stk_password_deterministic():
    # Canonical Daraja test values
    shortcode = "174379"
    passkey = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
    timestamp = "20160216165627"

    password, used_ts = generate_stk_password(shortcode, passkey, timestamp)
    assert used_ts == timestamp

    # Validate Base64 decoding matches the concatenated plain string
    decoded = base64.b64decode(password).decode("utf-8")
    assert decoded == f"{shortcode}{passkey}{timestamp}"


def test_generate_stk_password_auto_timestamp():
    shortcode = "174379"
    passkey = "dummy-passkey"

    password, ts = generate_stk_password(shortcode, passkey)
    assert len(ts) == 14
    decoded = base64.b64decode(password).decode("utf-8")
    assert decoded == f"{shortcode}{passkey}{ts}"


def test_generate_stk_password_validation_errors():
    with pytest.raises(ValueError, match="business_short_code cannot be empty"):
        generate_stk_password("", "passkey")

    with pytest.raises(ValueError, match="passkey cannot be empty"):
        generate_stk_password("174379", "   ")

    with pytest.raises(ValueError, match="Invalid timestamp"):
        generate_stk_password("174379", "passkey", timestamp="2026-11-03")


def test_compute_payload_sha256():
    sample_json = '{"ResultCode":0,"Amount":1500}'
    digest = compute_payload_sha256(sample_json)
    assert len(digest) == 64
    # Deterministic check
    assert digest == compute_payload_sha256(sample_json.encode("utf-8"))


def test_compute_and_verify_hmac():
    payload = "TransactionPayloadData"
    secret = "production-super-secret-key"

    signature = compute_hmac_sha256(payload, secret)
    assert len(signature) == 64

    # Valid signature
    assert verify_hmac_sha256(payload, secret, signature) is True

    # Tampered payload
    assert verify_hmac_sha256("TamperedPayloadData", secret, signature) is False

    # Tampered secret
    assert verify_hmac_sha256(payload, "wrong-secret", signature) is False

    # Empty signature
    assert verify_hmac_sha256(payload, secret, "") is False
    