"""End-to-End Integration Suite & Concurrency Benchmark Harness for Daraja Enterprise Bridge."""

import concurrent.futures
from decimal import Decimal
import json
import time
from unittest.mock import MagicMock
import pytest

from src.bridge import DarajaEnterpriseBridge
from src.config import BridgeConfig
from src.fraud.interceptor import FraudInterceptionError
from src.fraud.watchlist import WatchlistEntityType, WatchlistType
from src.models.contracts import STKPushResponse
from src.models.enums import Environment, TransactionStatus


def build_stk_callback_payload(
    checkout_id: str,
    receipt_no: str,
    amount: float,
    phone: str = "254712345678",
) -> bytes:
    """Helper to synthesize valid Safaricom Daraja STK callback JSON payloads."""
    payload = {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": f"MR-{checkout_id}",
                "CheckoutRequestID": checkout_id,
                "ResultCode": 0,
                "ResultDesc": "The service was accepted successfully",
                "CallbackMetadata": {
                    "Item": [
                        {"Name": "Amount", "Value": amount},
                        {"Name": "MpesaReceiptNumber", "Value": receipt_no},
                        {"Name": "TransactionDate", "Value": 20261107120000},
                        {"Name": "PhoneNumber", "Value": int(phone)},
                    ]
                },
            }
        }
    }
    return json.dumps(payload).encode("utf-8")


@pytest.fixture
def e2e_config() -> BridgeConfig:
    return BridgeConfig(
        environment=Environment.SANDBOX,
        consumer_key="e2e_consumer_key_sandbox",
        consumer_secret="e2e_consumer_secret_sandbox",
        passkey="e2e_passkey_0123456789abcdef0123456789",
        shortcode="174379",
        callback_url="https://api.enterprise.co.ke/v1/callbacks",
        enforce_ip_whitelist=False,
        default_flat_fee=Decimal("15.00"),
        default_fee_rate=Decimal("0.015"),  # 1.5%
    )


@pytest.fixture
def mock_telco_client() -> MagicMock:
    client = MagicMock()
    client.initiate_stk_push.return_value = STKPushResponse(
        merchant_request_id="MR-E2E-99001",
        checkout_request_id="ws_CO_E2E_000123",
        response_code="0",
        response_description="Success. Request accepted for processing",
        customer_message="Success. Request accepted for processing",
    )
    return client


def test_e2e_full_payment_settlement_lifecycle(e2e_config, mock_telco_client):
    """
    Validate complete happy-path lifecycle:
    Payment Outbound -> Callback Ingress -> Settle Ledger -> Audit Equilibrium.
    """
    bridge = DarajaEnterpriseBridge(config=e2e_config, client=mock_telco_client)

    # 1. Outbound Checkout Dispatch
    stk_response = bridge.initiate_payment(
        phone_number="0712345678",
        amount=10000.00,
        account_reference="ORD-E2E-77",
    )
    assert stk_response.response_code == "0"
    assert stk_response.checkout_request_id == "ws_CO_E2E_000123"

    # 2. Inbound Callback Receipt from Safaricom
    raw_body = build_stk_callback_payload(
        checkout_id="ws_CO_E2E_000123",
        receipt_no="QA99E2E001",
        amount=10000.0,
    )
    headers = {"Content-Type": "application/json"}
    callback = bridge.handle_webhook(headers=headers, raw_body=raw_body, auto_settle=True)

    assert callback is not None
    assert callback.status == TransactionStatus.COMPLETED
    assert callback.receipt_number == "QA99E2E001"

    # 3. Double-Entry Verification
    # Gross: 10,000.00
    # Fee: 15.00 + (10,000 * 0.015) = 15.00 + 150.00 = 165.00
    # Net Merchant Payable: 10,000.00 - 165.00 = 9,835.00
    escrow = bridge.default_escrow_account
    merchant = bridge.default_merchant_account
    fee_rev = bridge.default_fee_revenue_account

    assert bridge.ledger_engine.calculate_balance(escrow.id) == Decimal("10000.00")
    assert bridge.ledger_engine.calculate_balance(merchant.id) == Decimal("9835.00")
    assert bridge.ledger_engine.calculate_balance(fee_rev.id) == Decimal("165.00")

    # 4. Audit equilibrium
    trial_balance = bridge.get_trial_balance()
    assert trial_balance.is_balanced is True
    assert trial_balance.total_debits == Decimal("10000.00")
    assert trial_balance.total_credits == Decimal("10000.00")
    assert trial_balance.discrepancy == Decimal("0.00")

    integrity = bridge.verify_ledger_integrity()
    assert integrity.is_sound is True


def test_e2e_idempotency_webhook_storm(e2e_config, mock_telco_client):
    """
    Validate that identical webhook callbacks arriving in a rapid duplicate burst
    are deduplicated without double-crediting balances or corrupting journals.
    """
    bridge = DarajaEnterpriseBridge(config=e2e_config, client=mock_telco_client)

    raw_body = build_stk_callback_payload(
        checkout_id="ws_CO_STORM_001",
        receipt_no="QA_STORM_999",
        amount=5000.0,
    )
    headers = {"Content-Type": "application/json"}

    # First delivery: processed and settled
    cb_first = bridge.handle_webhook(headers=headers, raw_body=raw_body, auto_settle=True)
    assert cb_first is not None
    assert cb_first.status == TransactionStatus.COMPLETED

    # Subsequent 4 duplicate deliveries: recognized as duplicates and ignored
    for _ in range(4):
        cb_duplicate = bridge.handle_webhook(headers=headers, raw_body=raw_body, auto_settle=True)
        assert cb_duplicate is None

    # Ledger must contain exactly ONE settlement journal of KES 5,000
    escrow_balance = bridge.ledger_engine.calculate_balance(bridge.default_escrow_account.id)
    assert escrow_balance == Decimal("5000.00")  # Never 25,000.00

    tb = bridge.get_trial_balance()
    assert tb.is_balanced is True
    assert tb.total_debits == Decimal("5000.00")
    assert tb.discrepancy == Decimal("0.00")


def test_e2e_fraud_blocked_pre_flight(e2e_config, mock_telco_client):
    """
    Validate that a blacklisted entity is halted before network egress,
    protecting external quota and maintaining a pristine ledger.
    """
    bridge = DarajaEnterpriseBridge(config=e2e_config, client=mock_telco_client)
    compromised_phone = "0711999888"

    # Register entity on active blacklist
    bridge.fraud_interceptor.watchlist_engine.add_entry(
        entity_value=compromised_phone,
        entity_type=WatchlistEntityType.MSISDN,
        list_type=WatchlistType.BLACKLIST,
        reason="Sanctioned SIM-box attack node",
    )

    # Attempt payment dispatch
    with pytest.raises(FraudInterceptionError, match="blocked by fraud interceptor"):
        bridge.initiate_payment(
            phone_number=compromised_phone,
            amount=5000.00,
            account_reference="MALICIOUS-RUN",
        )

    # Assert outbound network client was never invoked
    mock_telco_client.initiate_stk_push.assert_not_called()

    # Assert ledger remains untouched
    assert bridge.get_trial_balance().total_debits == Decimal("0.00")


def test_e2e_payment_settlement_and_compensating_reversal(mock_telco_client):
    """
    Validate complete settlement followed by compensating reversal,
    asserting balanced books throughout both phases.
    """
    zero_fee_cfg = BridgeConfig(
        environment=Environment.SANDBOX,
        consumer_key="e2e_consumer_key_sandbox",
        consumer_secret="e2e_consumer_secret_sandbox",
        passkey="e2e_passkey_0123456789abcdef0123456789",
        shortcode="174379",
        callback_url="https://api.enterprise.co.ke/v1/callbacks",
        enforce_ip_whitelist=False,
        default_flat_fee=Decimal("0.00"),
        default_fee_rate=Decimal("0.00"),
    )
    bridge = DarajaEnterpriseBridge(config=zero_fee_cfg, client=mock_telco_client)

    # 1. Settle Payment of KES 2,000
    raw_body = build_stk_callback_payload(
        checkout_id="ws_CO_REV_001",
        receipt_no="QA_REV_111",
        amount=2000.0,
    )
    bridge.handle_webhook(headers={"Content-Type": "application/json"}, raw_body=raw_body, auto_settle=True)

    # Pre-reversal equilibrium check
    tb_pre = bridge.get_trial_balance()
    assert tb_pre.is_balanced is True
    assert tb_pre.total_debits == Decimal("2000.00")

    # 2. Execute Full Reversal
    rev_res = bridge.reverse_payment(
        original_reference_id="QA_REV_111",
        reversal_reference_id="REV-QA_REV-111",
        reason="Customer dispute - non-delivery",
    )

    assert rev_res.is_full_reversal is True
    assert rev_res.amount_reversed == Decimal("2000.00")

    # Post-reversal equilibrium check
    tb_post = bridge.get_trial_balance()
    assert tb_post.is_balanced is True
    assert tb_post.discrepancy == Decimal("0.00")

    # Balances must return to zero net liability
    assert bridge.ledger_engine.calculate_balance(bridge.default_escrow_account.id) == Decimal("0.00")
    assert bridge.ledger_engine.calculate_balance(bridge.default_merchant_account.id) == Decimal("0.00")
    assert bridge.ledger_engine.calculate_balance(bridge.default_fee_revenue_account.id) == Decimal("0.00")


def test_e2e_concurrent_burst_benchmark(e2e_config, mock_telco_client):
    """
    Concurrency benchmark: Process 25 concurrent independent settlements across worker threads.
    Validates atomic balance updates under load with zero mathematical discrepancy.
    """
    bridge = DarajaEnterpriseBridge(config=e2e_config, client=mock_telco_client)
    total_txns = 25
    gross_per_txn = Decimal("1000.00")

    def process_transaction(i: int):
        body = build_stk_callback_payload(
            checkout_id=f"ws_CO_BURST_{i:03d}",
            receipt_no=f"QA_BURST_{i:03d}",
            amount=float(gross_per_txn),
            phone=f"254700000{i:03d}",
        )
        return bridge.handle_webhook(
            headers={"Content-Type": "application/json"},
            raw_body=body,
            auto_settle=True,
        )

    start_time = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(process_transaction, range(total_txns)))
    duration = time.perf_counter() - start_time

    assert len(results) == total_txns
    assert all(r is not None and r.status == TransactionStatus.COMPLETED for r in results)

    # Total gross settled = 25 * 1000 = 25,000.00
    expected_gross = gross_per_txn * total_txns
    escrow_bal = bridge.ledger_engine.calculate_balance(bridge.default_escrow_account.id)
    assert escrow_bal == expected_gross

    # Systemic equilibrium check
    tb = bridge.get_trial_balance()
    assert tb.is_balanced is True
    assert tb.total_debits == expected_gross
    assert tb.total_credits == expected_gross
    assert tb.discrepancy == Decimal("0.00")

    # Assert performance threshold: 25 end-to-end settlements complete under 6 seconds
    assert duration < 6.0
    