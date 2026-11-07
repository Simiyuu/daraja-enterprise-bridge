"""Tests for the unified DarajaEnterpriseBridge facade."""

from decimal import Decimal
import json
from unittest.mock import MagicMock
import pytest

from src.bridge import DarajaEnterpriseBridge
from src.config import BridgeConfig
from src.fraud.interceptor import FraudInterceptionError
from src.fraud.watchlist import WatchlistEntityType, WatchlistType
from src.models.contracts import STKPushResponse
from src.models.enums import Environment, TransactionStatus
from src.resilience.circuit_breaker import CircuitBreakerOpenError


@pytest.fixture
def sample_config() -> BridgeConfig:
    return BridgeConfig(
        environment=Environment.SANDBOX,
        consumer_key="test_consumer_key_12345",
        consumer_secret="test_consumer_secret_12345",
        passkey="test_passkey_abcdef0123456789",
        shortcode="174379",
        callback_url="https://example.com/callback",
        enforce_ip_whitelist=False,
        default_flat_fee=Decimal("10.00"),
        default_fee_rate=Decimal("0.01"),
    )


@pytest.fixture
def mock_client() -> MagicMock:
    client = MagicMock()
    client.initiate_stk_push.return_value = STKPushResponse(
        merchant_request_id="29115-34620561-1",
        checkout_request_id="ws_CO_19122026102030123",
        response_code="0",
        response_description="Success. Request accepted for processing",
        customer_message="Success. Request accepted for processing",
    )
    return client


def test_bridge_initialization_defaults(sample_config, mock_client):
    bridge = DarajaEnterpriseBridge(config=sample_config, client=mock_client)

    assert bridge.default_escrow_account.code == "1010-ESCROW"
    assert bridge.default_merchant_account.code == "2010-MERCHANT-PAYABLE"
    assert bridge.default_fee_revenue_account.code == "4010-FEE-REVENUE"
    assert bridge.get_trial_balance().is_balanced is True


def test_bridge_initiate_payment_success(sample_config, mock_client):
    bridge = DarajaEnterpriseBridge(config=sample_config, client=mock_client)

    response = bridge.initiate_payment(
        phone_number="0712345678",
        amount=1500.00,
        account_reference="INV-9988",
    )

    assert response.response_code == "0"
    assert response.checkout_request_id == "ws_CO_19122026102030123"
    assert mock_client.initiate_stk_push.call_count == 1


def test_bridge_initiate_payment_fraud_blocked(sample_config, mock_client):
    bridge = DarajaEnterpriseBridge(config=sample_config, client=mock_client)
    blacklisted_phone = "0799999999"

    bridge.fraud_interceptor.watchlist_engine.add_entry(
        entity_value=blacklisted_phone,
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.BLACKLIST,
        reason="Known fraudulent number",
    )

    with pytest.raises(FraudInterceptionError, match="blocked by fraud interceptor"):
        bridge.initiate_payment(
            phone_number=blacklisted_phone,
            amount=5000.00,
            account_reference="FRAUD-TEST",
        )

    # Client must never be called if fraud check intercepts
    mock_client.initiate_stk_push.assert_not_called()


def test_bridge_initiate_payment_circuit_breaker_open(sample_config, mock_client):
    bridge = DarajaEnterpriseBridge(config=sample_config, client=mock_client)
    bridge.circuit_breaker._state = bridge.circuit_breaker._state.OPEN
    bridge.circuit_breaker._opened_at = 9999999999.0

    with pytest.raises(CircuitBreakerOpenError):
        bridge.initiate_payment(
            phone_number="0712345678",
            amount=500.00,
            account_reference="CB-TEST",
        )


def test_bridge_handle_webhook_and_auto_settle(sample_config, mock_client):
    bridge = DarajaEnterpriseBridge(config=sample_config, client=mock_client)

    # Sample successful Safaricom callback payload
    payload = {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "MR-5544",
                "CheckoutRequestID": "ws_CO_001_SETTLE",
                "ResultCode": 0,
                "ResultDesc": "The service was accepted successfully",
                "CallbackMetadata": {
                    "Item": [
                        {"Name": "Amount", "Value": 5000.0},
                        {"Name": "MpesaReceiptNumber", "Value": "QA12XYZ888"},
                        {"Name": "TransactionDate", "Value": 20261104120000},
                        {"Name": "PhoneNumber", "Value": 254712345678},
                    ]
                },
            }
        }
    }
    raw_body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}

    callback = bridge.handle_webhook(headers=headers, raw_body=raw_body, auto_settle=True)

    assert callback.status == TransactionStatus.COMPLETED
    assert callback.receipt_number == "QA12XYZ888"

    # Verify atomic settlement in ledger
    # Gross: 5000.00 -> Fee: 10 + (5000 * 0.01) = 60.00 -> Merchant Net: 4940.00
    escrow_id = bridge.default_escrow_account.id
    merchant_id = bridge.default_merchant_account.id
    fee_id = bridge.default_fee_revenue_account.id

    assert bridge.ledger_engine.calculate_balance(escrow_id) == Decimal("5000.00")
    assert bridge.ledger_engine.calculate_balance(merchant_id) == Decimal("4940.00")
    assert bridge.ledger_engine.calculate_balance(fee_id) == Decimal("60.00")

    # Trial balance must be strictly balanced
    tb = bridge.get_trial_balance()
    assert tb.is_balanced is True
    assert tb.discrepancy == Decimal("0.00")


def test_bridge_reversal_lifecycle(sample_config, mock_client):
    bridge = DarajaEnterpriseBridge(config=sample_config, client=mock_client)

    # Post an initial settlement directly
    bridge.settlement_service.settle_stk_payment(
        reference_id="TX-REV-TEST",
        gross_amount=Decimal("1000.00"),
        merchant_account_id=bridge.default_merchant_account.id,
        escrow_account_id=bridge.default_escrow_account.id,
    )

    # Execute full reversal through facade
    rev_res = bridge.reverse_payment(
        original_reference_id="TX-REV-TEST",
        reversal_reference_id="REV-TX-REV-TEST",
        reason="Defective goods returned",
    )

    assert rev_res.is_full_reversal is True
    assert rev_res.amount_reversed == Decimal("1000.00")

    # Integrity check must confirm clean state
    integrity = bridge.verify_ledger_integrity()
    assert integrity.is_sound is True


def test_bridge_inspect_risk_dry_run(sample_config, mock_client):
    bridge = DarajaEnterpriseBridge(config=sample_config, client=mock_client)

    decision = bridge.inspect_risk(
        phone_number="0722000000",
        amount=1000.00,
    )

    assert decision.is_cleared is True
    # Ensure nothing was recorded in velocity events during dry-run inspection
    assert len(bridge.fraud_interceptor.velocity_profiler._events) == 0
    