"""Tests for the webhook ingress handler and callback normalization."""

import json
import pytest

from src.models.enums import ResultCode, TransactionStatus
from src.webhook.handler import WebhookHandler, WebhookResponse
from src.webhook.idempotency import IdempotencyEngine
from src.webhook.security import IPValidator


@pytest.fixture
def mock_safaricom_success_payload() -> str:
    return json.dumps({
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "29115-34620561-1",
                "CheckoutRequestID": "ws_CO_04112026190000001",
                "ResultCode": 0,
                "ResultDesc": "The service request is processed successfully.",
                "CallbackMetadata": {
                    "Item": [
                        {"Name": "Amount", "Value": 2500.0},
                        {"Name": "MpesaReceiptNumber", "Value": "UL41XYZ999"},
                        {"Name": "Balance"},
                        {"Name": "TransactionDate", "Value": 20261104200000},
                        {"Name": "PhoneNumber", "Value": 254712345678},
                    ]
                },
            }
        }
    })


@pytest.fixture
def mock_safaricom_cancelled_payload() -> str:
    return json.dumps({
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "29115-34620561-2",
                "CheckoutRequestID": "ws_CO_04112026190000002",
                "ResultCode": 1032,
                "ResultDesc": "Request cancelled by user.",
            }
        }
    })


def test_webhook_handler_unauthorized_ip(mock_safaricom_success_payload):
    handler = WebhookHandler(enforce_ip_whitelist=True)
    headers = {"X-Forwarded-For": "8.8.8.8"}
    resp = handler.process_callback(mock_safaricom_success_payload, headers=headers)

    assert resp.status_code == 403
    assert "Unauthorized ingress source IP" in resp.payload["error"]
    assert resp.normalized_callback is None


def test_webhook_handler_successful_processing(mock_safaricom_success_payload):
    handler = WebhookHandler(enforce_ip_whitelist=False)
    headers = {}
    resp = handler.process_callback(mock_safaricom_success_payload, headers=headers)

    assert resp.status_code == 200
    assert resp.payload == {"ResultCode": 0, "ResultDesc": "Accepted"}
    assert resp.is_duplicate is False

    cb = resp.normalized_callback
    assert cb is not None
    assert cb.is_successful is True
    assert cb.receipt_number == "UL41XYZ999"
    assert cb.amount == 2500.0
    assert cb.phone_number == "254712345678"
    assert cb.status == TransactionStatus.COMPLETED


def test_webhook_handler_cancelled_processing(mock_safaricom_cancelled_payload):
    handler = WebhookHandler(enforce_ip_whitelist=False)
    headers = {}
    resp = handler.process_callback(mock_safaricom_cancelled_payload, headers=headers)

    assert resp.status_code == 200
    cb = resp.normalized_callback
    assert cb is not None
    assert cb.is_successful is False
    assert cb.result_code == 1032
    assert cb.status == TransactionStatus.FAILED
    assert cb.receipt_number is None
    assert cb.amount is None


def test_webhook_handler_idempotency_deduplication(mock_safaricom_success_payload):
    idempotency_engine = IdempotencyEngine()
    handler = WebhookHandler(idempotency_engine=idempotency_engine, enforce_ip_whitelist=False)

    # First delivery
    first_resp = handler.process_callback(mock_safaricom_success_payload, headers={})
    assert first_resp.status_code == 200
    assert first_resp.is_duplicate is False
    assert first_resp.normalized_callback is not None

    # Immediate second delivery of identical callback (Safaricom network retry)
    second_resp = handler.process_callback(mock_safaricom_success_payload, headers={})
    assert second_resp.status_code == 200
    assert second_resp.is_duplicate is True
    assert second_resp.payload == {"ResultCode": 0, "ResultDesc": "Accepted"}
    # Must not recreate normalized callback on duplicate
    assert second_resp.normalized_callback is None


def test_webhook_handler_malformed_json():
    handler = WebhookHandler(enforce_ip_whitelist=False)
    resp = handler.process_callback("not-a-valid-json", headers={})

    assert resp.status_code == 400
    assert "Invalid or malformed callback payload" in resp.payload["error"]
    