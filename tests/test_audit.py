"""Tests for the trial balance engine and ledger integrity audit service."""

from decimal import Decimal
import pytest

from src.core.audit import AuditService
from src.core.ledger import LedgerEngine
from src.core.models import Account, JournalEntry, LedgerEntry
from src.core.settlement import FeeConfig, SettlementService
from src.models.enums import AccountType, LedgerEntryType


@pytest.fixture
def audit_fixture():
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

    settlement_svc = SettlementService(ledger)
    fee_cfg = FeeConfig(flat_fee=Decimal("15.00"), percentage_rate=Decimal("0.01"))

    # Settle two transactions
    settlement_svc.settle_stk_payment(
        reference_id="TX-AUDIT-01",
        gross_amount=Decimal("10000.00"),  # 15 + 100 = 115 fee -> 9885 net
        merchant_account_id=merchant.id,
        escrow_account_id=escrow.id,
        fee_revenue_account_id=fee_rev.id,
        fee_config=fee_cfg,
    )
    settlement_svc.settle_stk_payment(
        reference_id="TX-AUDIT-02",
        gross_amount=Decimal("5000.00"),   # 15 + 50 = 65 fee -> 4935 net
        merchant_account_id=merchant.id,
        escrow_account_id=escrow.id,
        fee_revenue_account_id=fee_rev.id,
        fee_config=fee_cfg,
    )

    audit_svc = AuditService(ledger)
    return audit_svc, ledger, escrow, merchant, fee_rev


def test_empty_ledger_trial_balance_equilibrium():
    empty_ledger = LedgerEngine()
    empty_ledger.register_account(
        Account(code="1010-ESCROW", name="Escrow", account_type=AccountType.ASSET)
    )
    service = AuditService(empty_ledger)
    report = service.generate_trial_balance()

    assert report.is_balanced is True
    assert report.total_debits == Decimal("0.00")
    assert report.total_credits == Decimal("0.00")
    assert report.discrepancy == Decimal("0.00")
    assert len(report.rows) == 1


def test_settled_system_trial_balance_equilibrium(audit_fixture):
    audit_svc, _, escrow, merchant, fee_rev = audit_fixture
    report = audit_svc.generate_trial_balance()

    assert report.is_balanced is True
    assert report.discrepancy == Decimal("0.00")

    # Gross inflow = 15,000.00 KES (Escrow Asset Debit)
    assert report.total_debits == Decimal("15000.00")
    # Gross outflow = 14,820.00 (Merchant) + 180.00 (Fee) = 15,000.00 KES (Credit)
    assert report.total_credits == Decimal("15000.00")

    # Verify line items
    rows_by_code = {r.account_code: r for r in report.rows}
    assert rows_by_code["1010-ESCROW"].debit_balance == Decimal("15000.00")
    assert rows_by_code["2010-MERCHANT"].credit_balance == Decimal("14820.00")
    assert rows_by_code["4010-FEE"].credit_balance == Decimal("180.00")


def test_ledger_integrity_verification_on_sound_ledger(audit_fixture):
    audit_svc, _, _, _, _ = audit_fixture
    integrity = audit_svc.verify_ledger_integrity()

    assert integrity.is_sound is True
    assert integrity.total_journals_inspected == 2
    assert integrity.total_entries_inspected == 6  # 3 entries per settlement * 2
    assert len(integrity.corrupt_journals) == 0
    assert len(integrity.unbalanced_journals) == 0


def test_ledger_integrity_detects_corrupt_account_references(audit_fixture):
    audit_svc, ledger, escrow, merchant, _ = audit_fixture

    # Manually bypass standard entry validation to simulate internal database corruption
    unbalanced_journal = JournalEntry.model_construct(
        id="tampered-journal-id",
        reference_id="TAMPERED-REF",
        description="Tampered entry",
        entries=[
            LedgerEntry.model_construct(
                id="e1",
                account_id=escrow.id,
                entry_type=LedgerEntryType.DEBIT,
                amount=Decimal("100.00"),
            ),
            LedgerEntry.model_construct(
                id="e2",
                account_id="ghost-account-id",  # Invalid account reference
                entry_type=LedgerEntryType.CREDIT,
                amount=Decimal("100.00"),
            ),
        ],
    )
    ledger._journals_by_id[unbalanced_journal.id] = unbalanced_journal

    integrity = audit_svc.verify_ledger_integrity()
    assert integrity.is_sound is False
    assert "tampered-journal-id" in integrity.corrupt_journals
    