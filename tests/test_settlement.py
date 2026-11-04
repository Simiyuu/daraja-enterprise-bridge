"""Tests for settlement service, multi-leg fee slicing, and fee configurations."""

from decimal import Decimal
import pytest

from src.core.ledger import LedgerEngine
from src.core.models import Account
from src.core.settlement import FeeConfig, SettlementService
from src.models.enums import AccountType


@pytest.fixture
def settlement_setup():
    ledger = LedgerEngine()
    escrow = ledger.register_account(
        Account(code="1010-ESCROW", name="Escrow Account", account_type=AccountType.ASSET)
    )
    merchant = ledger.register_account(
        Account(code="2010-MERCHANT", name="Merchant Payable", account_type=AccountType.LIABILITY)
    )
    fee_rev = ledger.register_account(
        Account(code="4010-FEE", name="Fee Revenue", account_type=AccountType.REVENUE)
    )
    service = SettlementService(ledger)
    return service, ledger, escrow.id, merchant.id, fee_rev.id


def test_fee_config_calculation_rules():
    # Flat fee only
    cfg_flat = FeeConfig(flat_fee=Decimal("15.00"))
    assert cfg_flat.calculate_fee(Decimal("1000.00")) == Decimal("15.00")

    # Percentage fee (1.5%)
    cfg_pct = FeeConfig(percentage_rate=Decimal("0.015"))
    assert cfg_pct.calculate_fee(Decimal("1000.00")) == Decimal("15.00")

    # Half-up rounding check
    # 155.55 * 0.015 = 2.33325 -> 2.33
    assert cfg_pct.calculate_fee(Decimal("155.55")) == Decimal("2.33")

    # Min/Max cap enforcement
    cfg_capped = FeeConfig(
        percentage_rate=Decimal("0.02"),  # 2%
        min_fee=Decimal("5.00"),
        max_fee=Decimal("50.00"),
    )
    # 2% of 100 is 2.00 -> should cap to min 5.00
    assert cfg_capped.calculate_fee(Decimal("100.00")) == Decimal("5.00")
    # 2% of 5000 is 100.00 -> should cap to max 50.00
    assert cfg_capped.calculate_fee(Decimal("5000.00")) == Decimal("50.00")


def test_zero_fee_settlement(settlement_setup):
    service, ledger, escrow_id, merchant_id, fee_id = settlement_setup

    res = service.settle_stk_payment(
        reference_id="TX-ZERO-FEE",
        gross_amount=Decimal("1000.00"),
        merchant_account_id=merchant_id,
        escrow_account_id=escrow_id,
        fee_config=FeeConfig(),  # 0 fee
    )

    assert res.gross_amount == Decimal("1000.00")
    assert res.net_merchant_amount == Decimal("1000.00")
    assert res.fee_amount == Decimal("0.00")

    assert ledger.calculate_balance(escrow_id) == Decimal("1000.00")
    assert ledger.calculate_balance(merchant_id) == Decimal("1000.00")
    assert ledger.calculate_balance(fee_id) == Decimal("0.00")


def test_split_settlement_with_fee(settlement_setup):
    service, ledger, escrow_id, merchant_id, fee_id = settlement_setup

    fee_cfg = FeeConfig(flat_fee=Decimal("10.00"), percentage_rate=Decimal("0.01"))  # 10 + 1%

    # Gross: 1000.00 -> Fee: 10 + 10 = 20.00 -> Net: 980.00
    res = service.settle_stk_payment(
        reference_id="TX-FEE-SPLIT-01",
        gross_amount=Decimal("1000.00"),
        merchant_account_id=merchant_id,
        escrow_account_id=escrow_id,
        fee_revenue_account_id=fee_id,
        fee_config=fee_cfg,
    )

    assert res.gross_amount == Decimal("1000.00")
    assert res.net_merchant_amount == Decimal("980.00")
    assert res.fee_amount == Decimal("20.00")

    # Verify ledger state across all 3 chart-of-accounts entries
    assert ledger.calculate_balance(escrow_id) == Decimal("1000.00")
    assert ledger.calculate_balance(merchant_id) == Decimal("980.00")
    assert ledger.calculate_balance(fee_id) == Decimal("20.00")


def test_settlement_rejects_negative_or_zero_gross(settlement_setup):
    service, _, escrow_id, merchant_id, fee_id = settlement_setup

    with pytest.raises(ValueError, match="Gross settlement amount must be positive"):
        service.settle_stk_payment(
            reference_id="TX-INVALID",
            gross_amount=Decimal("0.00"),
            merchant_account_id=merchant_id,
            escrow_account_id=escrow_id,
        )


def test_settlement_rejects_fee_exceeding_gross(settlement_setup):
    service, _, escrow_id, merchant_id, fee_id = settlement_setup
    excessive_fee = FeeConfig(flat_fee=Decimal("150.00"))

    with pytest.raises(ValueError, match="cannot exceed or equal gross payment"):
        service.settle_stk_payment(
            reference_id="TX-EXCESSIVE",
            gross_amount=Decimal("100.00"),
            merchant_account_id=merchant_id,
            escrow_account_id=escrow_id,
            fee_revenue_account_id=fee_id,
            fee_config=excessive_fee,
        )


def test_settlement_requires_fee_account_when_fee_positive(settlement_setup):
    service, _, escrow_id, merchant_id, _ = settlement_setup
    fee_cfg = FeeConfig(flat_fee=Decimal("10.00"))

    with pytest.raises(ValueError, match="fee_revenue_account_id is required"):
        service.settle_stk_payment(
            reference_id="TX-MISSING-FEE-ACC",
            gross_amount=Decimal("500.00"),
            merchant_account_id=merchant_id,
            escrow_account_id=escrow_id,
            fee_revenue_account_id=None,  # Missing fee account
            fee_config=fee_cfg,
        )
        