"""Tests for double-entry ledger models and balance validation."""

from decimal import Decimal
import pytest
from pydantic import ValidationError

from src.core.models import Account, JournalEntry, LedgerEntry
from src.models.enums import AccountType, LedgerEntryType


def test_account_creation_and_code_normalization():
    account = Account(
        code=" 1010-safaricom-escrow ",
        name="Safaricom Ingress Holding Account",
        account_type=AccountType.ASSET,
    )
    assert account.code == "1010-SAFARICOM-ESCROW"
    assert account.currency == "KES"
    assert account.is_active is True
    assert account.id is not None


def test_ledger_entry_valid_precision():
    entry = LedgerEntry(
        account_id="acc-123",
        entry_type=LedgerEntryType.DEBIT,
        amount=Decimal("1500.50"),
    )
    assert entry.amount == Decimal("1500.50")


def test_ledger_entry_rejects_excess_precision():
    with pytest.raises(ValidationError, match="exceeds allowable currency precision"):
        LedgerEntry(
            account_id="acc-123",
            entry_type=LedgerEntryType.DEBIT,
            amount=Decimal("1500.555"),
        )


def test_ledger_entry_rejects_negative_or_zero_amount():
    with pytest.raises(ValidationError):
        LedgerEntry(
            account_id="acc-123",
            entry_type=LedgerEntryType.CREDIT,
            amount=Decimal("0.00"),
        )

    with pytest.raises(ValidationError):
        LedgerEntry(
            account_id="acc-123",
            entry_type=LedgerEntryType.CREDIT,
            amount=Decimal("-10.00"),
        )


def test_journal_entry_balanced_success():
    acc_escrow = "acc-escrow-01"
    acc_merchant = "acc-merchant-01"

    entry_debit = LedgerEntry(
        account_id=acc_escrow,
        entry_type=LedgerEntryType.DEBIT,
        amount=Decimal("2500.00"),
    )
    entry_credit = LedgerEntry(
        account_id=acc_merchant,
        entry_type=LedgerEntryType.CREDIT,
        amount=Decimal("2500.00"),
    )

    journal = JournalEntry(
        reference_id="WS_CO_20261104",
        description="M-Pesa payment settlement",
        entries=[entry_debit, entry_credit],
    )

    assert journal.total_amount == Decimal("2500.00")
    assert len(journal.entries) == 2


def test_journal_entry_unbalanced_raises_validation_error():
    entry_debit = LedgerEntry(
        account_id="acc-1",
        entry_type=LedgerEntryType.DEBIT,
        amount=Decimal("2500.00"),
    )
    entry_credit = LedgerEntry(
        account_id="acc-2",
        entry_type=LedgerEntryType.CREDIT,
        amount=Decimal("2400.00"),  # 100 KES discrepancy
    )

    with pytest.raises(ValidationError, match="Double-entry balance mismatch"):
        JournalEntry(
            reference_id="WS_DISCREPANCY",
            description="Unbalanced settlement",
            entries=[entry_debit, entry_credit],
        )


def test_journal_entry_requires_minimum_two_legs():
    single_entry = LedgerEntry(
        account_id="acc-1",
        entry_type=LedgerEntryType.DEBIT,
        amount=Decimal("100.00"),
    )

    with pytest.raises(ValidationError):
        JournalEntry(
            reference_id="REF-SINGLE",
            description="Single-legged entry",
            entries=[single_entry],
        )
        