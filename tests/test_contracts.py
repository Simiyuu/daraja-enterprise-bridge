"""Tests for Pydantic data contracts, phone normalization, and callback parsing."""

import pytest
from pydantic import ValidationError
from src.models.contracts import (
    STKPushRequest,
    STKPushResponse,
    STKCallbackPayload,
    normalize_msisdn,
)
from src.models.enums import TransactionType


def test_normalize_msisdn_valid_inputs():
    assert normalize_msisdn("0712345678") == "254712345678"
    assert normalize_msisdn("+254712345678") == "254712345678"
    assert normalize_msisdn("254712345678") == "254712345678"
    assert normalize_msisdn("0112345678") == "254112345678"
    assert normalize_msisdn("712345678") == "254712345678"


def test_normalize_msisdn_invalid_inputs():
    with pytest.raises(ValueError, match="Invalid Kenyan MSISDN"):
        normalize_msisdn("12345")
    with pytest.raises(ValueError, match="Invalid Kenyan MSISDN"):
        normalize_msisdn("0201234567")  # Landline format


def test_stk_push_request_validation():
    req = STKPushRequest(
        BusinessShortCode="174379",
        Password="mock-base64-password",
        Timestamp="20261103143000",
        Amount=500,
        PartyA="0712345678",
        PartyB="174379",
        PhoneNumber="0712345678",
        CallBackURL="https://api.example.com/callback",
        AccountReference="INV-001",
        TransactionDesc="Order Payment",
    )
    assert req.phone_number == "254712345678"
    assert req.party_a == "254712345678"
    assert req.amount == 500
    assert req.transaction_type == TransactionType.CUSTOMER_PAYBILL_ONLINE


def test_stk_push_request_invalid_amount_or_timestamp():
    with pytest.raises(ValidationError):
        STKPushRequest(
            BusinessShortCode="174379",
            Password="mock-pass",
            Timestamp="invalid-timestamp",
            Amount=0,  # Must be > 0
            PartyA="0712345678",
            PartyB="174379",
            PhoneNumber="0712345678",
            CallBackURL="https://api.example.com/callback",
            AccountReference="INV-001",
            TransactionDesc="Payment",
        )


def test_stk_push_response_parsing():
    raw_response = {
        "MerchantRequestID": "29115-34620561-1",
        "CheckoutRequestID": "ws_CO_031120261430001234",
        "ResponseCode": "0",
        "ResponseDescription": "Success. Request accepted for processing",
        "CustomerMessage": "Success. Request accepted for processing",
    }
    resp = STKPushResponse(**raw_response)
    assert resp.is_successful is True
    assert resp.merchant_request_id == "29115-34620561-1"


def test_successful_stk_callback_payload_parsing():
    raw_callback = {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "29115-34620561-1",
                "CheckoutRequestID": "ws_CO_031120261430001234",
                "ResultCode": 0,
                "ResultDesc": "The service request is processed successfully.",
                "CallbackMetadata": {
                    "Item": [
                        {"Name": "Amount", "Value": 1500.0},
                        {"Name": "MpesaReceiptNumber", "Value": "TK32XYZ123"},
                        {"Name": "Balance"},
                        {"Name": "TransactionDate", "Value": 20261103143522},
                        {"Name": "PhoneNumber", "Value": 254712345678},
                    ]
                },
            }
        }
    }
    payload = STKCallbackPayload(**raw_callback)
    assert payload.body.stk_callback.result_code == 0
    assert payload.receipt_number == "TK32XYZ123"
    assert payload.paid_amount == 1500.0
    extracted = payload.extract_metadata_dict()
    assert extracted["PhoneNumber"] == 254712345678


def test_cancelled_stk_callback_payload():
    raw_cancelled = {
        "Body": {
            "stkCallback": {
                "MerchantRequestID": "29115-34620561-1",
                "CheckoutRequestID": "ws_CO_031120261430001234",
                "ResultCode": 1032,
                "ResultDesc": "Request cancelled by user.",
            }
        }
    }
    payload = STKCallbackPayload(**raw_cancelled)
    assert payload.body.stk_callback.result_code == 1032
    assert payload.receipt_number is None
    assert payload.paid_amount is None
    assert payload.extract_metadata_dict() == {}
    