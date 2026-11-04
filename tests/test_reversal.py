"""Tests for compensating journal entries, full reversals, and partial refunds."""

from decimal import Decimal
import pytest

from src.core.ledger import LedgerEngine
from src.core.models import Account
from src.core.reversal import ReversalService
from src.core.settlement import SettlementService
from src.models.enums import AccountType


@pytest.fixture
def reversal_fixture():
    ledger = LedgerEngine()
    escrow = ledger.register_account(
        Account(code="1010-ESCROW", name="Escrow Account", account_type=AccountType.ASSET)
    )
    merchant = ledger.register_account(
        Account(code="2010-MERCHANT", name="Merchant Payable", account_type=AccountType.LIABILITY)
    )
    settlement_svc = SettlementService(ledger)
    reversal_svc = ReversalService(ledger)

    # Execute a clean 5,000 KES baseline settlement
    settlement_svc.settle_stk_payment(
        reference_id="ORIG-TX-5000",
        gross_amount=Decimal("5000.00"),
        merchant_account_id=merchant.id,
        escrow_account_id=escrow.id,
    )

    return reversal_svc, ledger, escrow.id, merchant.id


def test_full_reversal_lifecycle(reversal_fixture):
    reversal_svc, ledger, escrow_id, merchant_id = reversal_fixture

    # Balances before refund
    assert ledger.calculate_balance(escrow_id) == Decimal("5000.00")
    assert ledger.calculate_balance(merchant_id) == Decimal("5000.00")

    # Perform full reversal
    result = reversal_svc.process_reversal(
        original_reference_id="ORIG-TX-5000",
        reversal_reference_id="REV-TX-5000-FULL",
        reason="Customer returned unopened merchandise",
    )

    assert result.is_full_reversal is True
    assert result.amount_reversed == Decimal("5000.00")

    # Balances must return to zero
    assert ledger.calculate_balance(escrow_id) == Decimal("0.00")
    assert ledger.calculate_balance(merchant_id) == Decimal("0.00")
    assert reversal_svc.get_total_refunded("ORIG-TX-5000") == Decimal("5000.00")


def test_partial_refunds_incremental(reversal_fixture):
    reversal_svc, ledger, escrow_id, merchant_id = reversal_fixture

    # 1. First partial refund: 2,000 KES
    res_1 = reversal_svc.process_reversal(
        original_reference_id="ORIG-TX-5000",
        reversal_reference_id="REV-PARTIAL-01",
        reversal_amount=Decimal("2000.00"),
    )
    assert res_1.is_full_reversal is False
    assert res_1.amount_reversed == Decimal("2000.00")
    assert ledger.calculate_balance(merchant_id) == Decimal("3000.00")

    # 2. Second partial refund: 3,000 KES (exhausts remainder)
    res_2 = reversal_svc.process_reversal(
        original_reference_id="ORIG-TX-5000",
        reversal_reference_id="REV-PARTIAL-02",
        reversal_amount=Decimal("3000.00"),
    )
    assert res_2.is_full_reversal is True
    assert res_2.amount_reversed == Decimal("3000.00")
    assert ledger.calculate_balance(merchant_id) == Decimal("0.00")


def test_reversal_exceeding_original_amount_rejected(reversal_fixture):
    reversal_svc, _, _, _ = reversal_fixture

    with pytest.raises(ValueError, match="exceeds remaining available refund balance"):
        reversal_svc.process_reversal(
            original_reference_id="ORIG-TX-5000",
            reversal_reference_id="REV-EXCESSIVE",
            reversal_amount=Decimal("5000.01"),
        )


def test_reversal_on_already_fully_refunded_rejected(reversal_fixture):
    reversal_svc, _, _, _ = reversal_fixture

    reversal_svc.process_reversal(
        original_reference_id="ORIG-TX-5000",
        reversal_reference_id="REV-FULL",
    )

    with pytest.raises(ValueError, match="already fully reversed"):
        reversal_svc.process_reversal(
            original_reference_id="ORIG-TX-5000",
            reversal_reference_id="REV-AGAIN",
        )


def test_reversal_missing_original_transaction_rejected(reversal_fixture):
    reversal_svc, _, _, _ = reversal_fixture

    with pytest.raises(KeyError, match="Original transaction 'NONEXISTENT' not found"):
        reversal_svc.process_reversal(
            original_reference_id="NONEXISTENT",
            reversal_reference_id="REV-ERR",
        )


def test_reversal_insufficient_merchant_liquidity(reversal_fixture):
    reversal_svc, ledger, escrow_id, merchant_id = reversal_fixture

    # Withdraw funds from merchant so balance drops to 100 KES
    drain_account = ledger.register_account(
        Account(code="3010-WITHDRAWAL", name="Merchant Bank Payout", account_type=AccountType.ASSET)
    )
    from src.core.models import JournalEntry, LedgerEntry
    from src.models.enums import LedgerEntryType

    withdrawal = JournalEntry(
        reference_id="BANK-PAYOUT-01",
        description="Payout to merchant bank account",
        entries=[
            LedgerEntry(account_id=merchant_id, entry_type=LedgerEntryType.DEBIT, amount=Decimal("4900.00")),
            LedgerEntry(account_id=drain_account.id, entry_type=LedgerEntryType.CREDIT, amount=Decimal("4900.00")),
        ],
    )
    ledger.post_journal(withdrawal)

    # Merchant only has 100 KES remaining
    assert ledger.calculate_balance(merchant_id) == Decimal("100.00")

    # Attempting to refund 500 KES must fail due to insufficient liquidity
    with pytest.raises(ValueError, match="insufficient balance"):
        reversal_svc.process_reversal(
            original_reference_id="ORIG-TX-5000",
            reversal_reference_id="REV-INSOLVENT",
            reversal_amount=Decimal("500.00"),
        )
        