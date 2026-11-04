"""Tests for Safaricom IP ingress validation and proxy header parsing."""

import pytest
from src.webhook.security import (
    DEFAULT_SAFARICOM_CIDRS,
    IPValidator,
    IngressSecurityError,
    extract_client_ip,
)


def test_validator_initialization_with_custom_cidrs():
    validator = IPValidator(allowed_cidrs=["10.0.0.0/8", "192.168.1.0/24"])
    assert len(validator.networks) == 2


def test_validator_invalid_cidr_raises():
    with pytest.raises(ValueError, match="Invalid CIDR block"):
        IPValidator(allowed_cidrs=["not-an-ip-range"])


def test_authorized_safaricom_ips():
    validator = IPValidator()
    # 196.201.214.200 is inside 196.201.214.0/24
    assert validator.is_authorized("196.201.214.200") is True
    # 196.201.213.15 is inside 196.201.213.0/24
    assert validator.is_authorized("196.201.213.15") is True
    # 196.19.140.50 is inside 196.19.140.0/24
    assert validator.is_authorized("196.19.140.50") is True


def test_unauthorized_external_ips():
    validator = IPValidator()
    # Public internet arbitrary IP
    assert validator.is_authorized("8.8.8.8") is False
    assert validator.is_authorized("102.134.12.5") is False
    assert validator.is_authorized("1.1.1.1") is False


def test_loopback_handling():
    strict_validator = IPValidator(allow_loopback=False)
    assert strict_validator.is_authorized("127.0.0.1") is False

    dev_validator = IPValidator(allow_loopback=True)
    assert dev_validator.is_authorized("127.0.0.1") is True
    assert dev_validator.is_authorized("::1") is True


def test_enforce_authorized_raises_security_error():
    validator = IPValidator()
    # Valid should pass silently
    validator.enforce_authorized("196.201.214.5")

    # Unauthorized must raise IngressSecurityError
    with pytest.raises(IngressSecurityError, match="Ingress rejected: IP '8.8.8.8'"):
        validator.enforce_authorized("8.8.8.8")


def test_invalid_ip_formats():
    validator = IPValidator()
    assert validator.is_authorized("invalid-ip") is False
    assert validator.is_authorized("") is False
    assert validator.is_authorized(None) is False  # type: ignore


def test_extract_client_ip_from_direct_remote_addr():
    headers = {}
    ip = extract_client_ip(headers, remote_addr="196.201.214.200")
    assert ip == "196.201.214.200"


def test_extract_client_ip_with_x_forwarded_for():
    # Scenario: Client -> Cloudflare/ALB -> Application
    headers = {"X-Forwarded-For": "196.201.214.200, 10.0.0.1"}
    # Default trusted_proxy_count = 1 takes rightmost forwarded IP before proxy
    ip = extract_client_ip(headers, remote_addr="10.0.0.1", trusted_proxy_count=1)
    assert ip == "10.0.0.1"

    # With proxy count 2, it picks the real upstream IP
    ip_upstream = extract_client_ip(headers, remote_addr="127.0.0.1", trusted_proxy_count=2)
    assert ip_upstream == "196.201.214.200"


def test_extract_client_ip_fallback():
    headers = {"X-Forwarded-For": "invalid-ip"}
    ip = extract_client_ip(headers, remote_addr="also-invalid")
    assert ip == "0.0.0.0"
    