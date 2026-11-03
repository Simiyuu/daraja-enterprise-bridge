"""Tests for domain models and enumerations."""

import pytest
from src.models.enums import (
    AccountType,
    Environment,
    LedgerEntryType,
    ResultCode,
    RiskTier,
    TransactionStatus,
    TransactionType,
)


def test_environment_values():
    assert Environment.SANDBOX.value == "sandbox"
    assert Environment.PRODUCTION.value == "production"
    assert str(Environment.SANDBOX) == "sandbox"


def test_transaction_type_values():
    assert TransactionType.CUSTOMER_PAYBILL_ONLINE.value == "CustomerPayBillOnline"
    assert TransactionType.CUSTOMER_BUY_GOODS_ONLINE.value == "CustomerBuyGoodsOnline"


def test_transaction_status_membership():
    valid_statuses = {"PENDING", "COMPLETED", "FAILED", "CANCELLED", "REVERSED", "TIMEOUT"}
    assert {s.value for s in TransactionStatus} == valid_statuses


def test_result_code_mapping_and_descriptions():
    assert ResultCode.SUCCESS.value == 0
    assert ResultCode.CANCELLED_BY_USER.value == 1032
    assert ResultCode.USER_TIMEOUT.value == 1037

    success_desc = ResultCode.get_description(0)
    assert "completed successfully" in success_desc

    cancel_desc = ResultCode.get_description(1032)
    assert "cancelled by the subscriber" in cancel_desc

    unknown_desc = ResultCode.get_description(99999)
    assert "Unknown response code" in unknown_desc


def test_ledger_enums():
    assert LedgerEntryType.DEBIT.value == "DEBIT"
    assert LedgerEntryType.CREDIT.value == "CREDIT"
    assert AccountType.ASSET.value == "ASSET"
    assert AccountType.LIABILITY.value == "LIABILITY"


def test_risk_tier_classification():
    assert RiskTier.LOW.value == "LOW"
    assert RiskTier.ELEVATED.value == "ELEVATED"
    assert RiskTier.CRITICAL_INTERCEPT.value == "CRITICAL_INTERCEPT"
    