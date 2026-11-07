"""Tests for configuration validation, endpoint resolution, and environment parsing."""

from decimal import Decimal
import pytest
from pydantic import ValidationError

from src.config import BridgeConfig, DARAJA_BASE_URLS
from src.models.enums import Environment


@pytest.fixture
def valid_config_dict() -> dict:
    return {
        "DARAJA_ENVIRONMENT": "SANDBOX",
        "DARAJA_CONSUMER_KEY": "sample_consumer_key_12345",
        "DARAJA_CONSUMER_SECRET": "sample_consumer_secret_12345",
        "DARAJA_PASSKEY": "sample_passkey_abcdef0123456789",
        "DARAJA_SHORTCODE": "174379",
        "DARAJA_CALLBACK_URL": "https://bridge.enterprise.co.ke/v1/webhook",
        "DARAJA_ENFORCE_IP_WHITELIST": "true",
        "DARAJA_TIMEOUT_SECONDS": "45.0",
        "DARAJA_MAX_RETRIES": "5",
        "DARAJA_DEFAULT_FLAT_FEE": "10.00",
        "DARAJA_DEFAULT_FEE_RATE": "0.015",
    }


def test_bridge_config_direct_instantiation():
    cfg = BridgeConfig(
        environment=Environment.PRODUCTION,
        consumer_key="prod_consumer_key_xyz",
        consumer_secret="prod_consumer_secret_xyz",
        passkey="prod_passkey_0123456789abcdef",
        shortcode="600123",
        callback_url="https://api.merchant.com/webhook",
    )

    assert cfg.environment == Environment.PRODUCTION
    assert cfg.base_url == "https://api.safaricom.co.ke"
    assert cfg.oauth_url.startswith("https://api.safaricom.co.ke/oauth/v1")
    assert cfg.stk_push_url.startswith("https://api.safaricom.co.ke/mpesa/stkpush/v1")
    assert cfg.enforce_ip_whitelist is True
    assert cfg.default_flat_fee == Decimal("0.00")


def test_bridge_config_shortcode_validation():
    # Non-digit shortcode must fail
    with pytest.raises(ValidationError, match="Shortcode must contain only numeric digits"):
        BridgeConfig(
            consumer_key="valid_consumer_key",
            consumer_secret="valid_consumer_secret",
            passkey="valid_passkey_12345678",
            shortcode="PAYBILL-01",
            callback_url="https://example.com/callback",
        )


def test_bridge_config_callback_url_validation():
    # Invalid URL scheme
    with pytest.raises(ValidationError, match="Callback URL must be a valid HTTP/HTTPS URL"):
        BridgeConfig(
            consumer_key="valid_consumer_key",
            consumer_secret="valid_consumer_secret",
            passkey="valid_passkey_12345678",
            shortcode="174379",
            callback_url="ftp://invalid-url.com",
        )


def test_bridge_config_from_env_parser(valid_config_dict):
    cfg = BridgeConfig.from_env(valid_config_dict)

    assert cfg.environment == Environment.SANDBOX
    assert cfg.consumer_key == "sample_consumer_key_12345"
    assert cfg.shortcode == "174379"
    assert cfg.api_timeout_seconds == 45.0
    assert cfg.max_retries == 5
    assert cfg.default_flat_fee == Decimal("10.00")
    assert cfg.default_fee_rate == Decimal("0.015")
    assert cfg.base_url == DARAJA_BASE_URLS[Environment.SANDBOX]


def test_bridge_config_from_env_invalid_environment(valid_config_dict):
    valid_config_dict["DARAJA_ENVIRONMENT"] = "STAGING_INVALID"
    with pytest.raises(ValueError, match="Invalid DARAJA_ENVIRONMENT"):
        BridgeConfig.from_env(valid_config_dict)


def test_bridge_config_boundary_checks():
    # Negative timeout must fail validation
    with pytest.raises(ValidationError):
        BridgeConfig(
            consumer_key="valid_key_12345",
            consumer_secret="valid_secret_12345",
            passkey="valid_passkey_12345678",
            shortcode="174379",
            callback_url="https://example.com/cb",
            api_timeout_seconds=-5.0,
        )

    # Fee rate > 100% (1.00) must fail validation
    with pytest.raises(ValidationError):
        BridgeConfig(
            consumer_key="valid_key_12345",
            consumer_secret="valid_secret_12345",
            passkey="valid_passkey_12345678",
            shortcode="174379",
            callback_url="https://example.com/cb",
            default_fee_rate=Decimal("1.50"),
        )
        