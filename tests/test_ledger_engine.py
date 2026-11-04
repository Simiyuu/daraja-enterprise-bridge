"""Tests for the atomic ledger execution engine and balance calculations."""

import concurrent.futures
from decimal import Decimal
import pytest

from src.core.ledger import LedgerEngine
from src.core.models import Account, JournalEntry, LedgerEntry
from src.models.enums import AccountType, LedgerEntryType


@pytest.fixture
def ledger():
    engine = LedgerEngine()
    # Setup initial Chart of Accounts
    engine.register_account(Account(code="1010-ESCROW", name="Safaricom Escrow", account_type=AccountType.ASSET))
    engine.register_account(Account(code="2010-MERCHANT-PAYABLE", name="Merchant Payable", account_type=AccountType.LIABILITY))
    engine.register_account(Account(code="4010-FEE-REVENUE", name="Processing Fee Revenue", account_type=AccountType.REVENUE))
    return engine


def test_register_account_duplicate_code_or_id(ledger):
    acc = ledger.get_account_by_code("1010-ESCROW")
    assert acc is not None

    with pytest.raises(ValueError, match="already exists"):
        ledger.register_account(Account(code="1010-ESCROW", name="Duplicate Code", account_type=AccountType.ASSET))

    with pytest.raises(ValueError, match="already exists"):
        ledger.register_account(Account(id=acc.id, code="9999-NEW", name="Duplicate ID", account_type=AccountType.ASSET))


def test_post_journal_and_balance_calculation(ledger):
    escrow = ledger.get_account_by_code("1010-ESCROW")
    merchant = ledger.get_account_by_code("2010-MERCHANT-PAYABLE")

    # Transaction: Customer pays 10,000 KES
    # Debit Asset (Escrow) +10,000, Credit Liability (Merchant Payable) +10,000
    journal = JournalEntry(
        reference_id="TX-REF-1001",
        description="Customer checkout settlement",
        entries=[
            LedgerEntry(account_id=escrow.id, entry_type=LedgerEntryType.DEBIT, amount=Decimal("10000.00")),
            LedgerEntry(account_id=merchant.id, entry_type=LedgerEntryType.CREDIT, amount=Decimal("10000.00")),
        ],
    )
    ledger.post_journal(journal)

    # Asset normal balance is debit-positive
    assert ledger.calculate_balance(escrow.id) == Decimal("10000.00")
    # Liability normal balance is credit-positive
    assert ledger.calculate_balance(merchant.id) == Decimal("10000.00")


def test_post_journal_duplicate_reference_rejected(ledger):
    escrow = ledger.get_account_by_code("1010-ESCROW")
    merchant = ledger.get_account_by_code("2010-MERCHANT-PAYABLE")

    journal = JournalEntry(
        reference_id="TX-REF-DUP",
        description="Initial post",
        entries=[
            LedgerEntry(account_id=escrow.id, entry_type=LedgerEntryType.DEBIT, amount=Decimal("100.00")),
            LedgerEntry(account_id=merchant.id, entry_type=LedgerEntryType.CREDIT, amount=Decimal("100.00")),
        ],
    )
    ledger.post_journal(journal)

    # Attempt second post with identical reference ID
    with pytest.raises(ValueError, match="already been posted"):
        ledger.post_journal(journal)


def test_post_journal_missing_or_inactive_account(ledger):
    escrow = ledger.get_account_by_code("1010-ESCROW")

    # Inactive account
    inactive_acc = Account(
        code="2020-SUSPENDED",
        name="Suspended Merchant",
        account_type=AccountType.LIABILITY,
        is_active=False,
    )
    ledger.register_account(inactive_acc)

    journal_inactive = JournalEntry(
        reference_id="TX-INACTIVE",
        description="Settlement to suspended merchant",
        entries=[
            LedgerEntry(account_id=escrow.id, entry_type=LedgerEntryType.DEBIT, amount=Decimal("50.00")),
            LedgerEntry(account_id=inactive_acc.id, entry_type=LedgerEntryType.CREDIT, amount=Decimal("50.00")),
        ],
    )
    with pytest.raises(ValueError, match="Cannot post to inactive ledger account"):
        ledger.post_journal(journal_inactive)

    # Nonexistent account
    journal_missing = JournalEntry(
        reference_id="TX-MISSING",
        description="Settlement to nonexistent account",
        entries=[
            LedgerEntry(account_id=escrow.id, entry_type=LedgerEntryType.DEBIT, amount=Decimal("50.00")),
            LedgerEntry(account_id="nonexistent-id", entry_type=LedgerEntryType.CREDIT, amount=Decimal("50.00")),
        ],
    )
    with pytest.raises(KeyError, match="Target ledger account 'nonexistent-id' does not exist"):
        ledger.post_journal(journal_missing)


def test_concurrent_journal_posting_balance_integrity(ledger):
    escrow = ledger.get_account_by_code("1010-ESCROW")
    merchant = ledger.get_account_by_code("2010-MERCHANT-PAYABLE")

    # 50 threads posting 100.00 KES concurrently
    def worker(i: int):
        journal = JournalEntry(
            reference_id=f"CONCURRENT-TX-{i}",
            description=f"Concurrent batch {i}",
            entries=[
                LedgerEntry(account_id=escrow.id, entry_type=LedgerEntryType.DEBIT, amount=Decimal("100.00")),
                LedgerEntry(account_id=merchant.id, entry_type=LedgerEntryType.CREDIT, amount=Decimal("100.00")),
            ],
        )
        ledger.post_journal(journal)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        list(executor.map(worker, range(50)))

    # Both accounts must balance to exactly 5,000.00 KES without race conditions
    assert ledger.calculate_balance(escrow.id) == Decimal("5000.00")
    assert ledger.calculate_balance(merchant.id) == Decimal("5000.00")
    assert len(ledger.get_account_entries(escrow.id)) == 50
    