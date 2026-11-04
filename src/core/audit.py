"""Trial balance compilation and double-entry ledger integrity audit service."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Dict, List, Optional

from src.core.ledger import LedgerEngine
from src.core.models import Account
from src.models.enums import AccountType, LedgerEntryType


@dataclass(frozen=True)
class TrialBalanceRow:
    """Individual line item representing an account's trial balance position."""
    account_id: str
    account_code: str
    account_name: str
    account_type: AccountType
    debit_balance: Decimal
    credit_balance: Decimal


@dataclass(frozen=True)
class TrialBalanceReport:
    """System-wide financial snapshot proving debit-credit equilibrium."""
    generated_at: datetime
    rows: List[TrialBalanceRow]
    total_debits: Decimal
    total_credits: Decimal
    is_balanced: bool
    discrepancy: Decimal


@dataclass(frozen=True)
class LedgerIntegrityReport:
    """Deep structural verification of all underlying journals and entry lines."""
    total_journals_inspected: int
    total_entries_inspected: int
    is_sound: bool
    corrupt_journals: List[str] = field(default_factory=list)
    unbalanced_journals: List[str] = field(default_factory=list)


class AuditService:
    """Audit engine performing mathematical and structural ledger verification."""

    def __init__(self, ledger_engine: LedgerEngine):
        self.ledger_engine = ledger_engine

    def generate_trial_balance(self) -> TrialBalanceReport:
        """
        Compile the current trial balance across all registered chart of accounts.

        Returns:
            TrialBalanceReport: Aggregated balances, debit/credit totals, and equilibrium status.
        """
        rows: List[TrialBalanceRow] = []
        total_debits = Decimal("0.00")
        total_credits = Decimal("0.00")

        # Snapshot registered accounts safely under ledger lock
        with self.ledger_engine._lock:
            accounts = list(self.ledger_engine._accounts.values())

        for account in accounts:
            net_balance = self.ledger_engine.calculate_balance(account.id)
            debit_val = Decimal("0.00")
            credit_val = Decimal("0.00")

            # Assign normal balance placement
            if account.account_type in (AccountType.ASSET, AccountType.EXPENSE):
                if net_balance >= Decimal("0.00"):
                    debit_val = net_balance
                else:
                    # Abnormal balance (e.g. overdrawn asset)
                    credit_val = abs(net_balance)
            else:
                if net_balance >= Decimal("0.00"):
                    credit_val = net_balance
                else:
                    # Abnormal balance (e.g. debit position on liability)
                    debit_val = abs(net_balance)

            total_debits += debit_val
            total_credits += credit_val

            rows.append(
                TrialBalanceRow(
                    account_id=account.id,
                    account_code=account.code,
                    account_name=account.name,
                    account_type=account.account_type,
                    debit_balance=debit_val,
                    credit_balance=credit_val,
                )
            )

        discrepancy = abs(total_debits - total_credits)
        is_balanced = (discrepancy == Decimal("0.00"))

        return TrialBalanceReport(
            generated_at=datetime.now(timezone.utc),
            rows=rows,
            total_debits=total_debits,
            total_credits=total_credits,
            is_balanced=is_balanced,
            discrepancy=discrepancy,
        )

    def verify_ledger_integrity(self) -> LedgerIntegrityReport:
        """
        Perform exhaustive audit on all journal entries to detect internal tampering or corruption.
        """
        with self.ledger_engine._lock:
            journals = list(self.ledger_engine._journals_by_id.values())

        corrupt_journals: List[str] = []
        unbalanced_journals: List[str] = []
        total_entries = 0

        for journal in journals:
            total_entries += len(journal.entries)
            journal_debits = Decimal("0.00")
            journal_credits = Decimal("0.00")

            for entry in journal.entries:
                # Ensure target account exists
                if not self.ledger_engine.get_account(entry.account_id):
                    corrupt_journals.append(journal.id)

                if entry.entry_type == LedgerEntryType.DEBIT:
                    journal_debits += entry.amount
                elif entry.entry_type == LedgerEntryType.CREDIT:
                    journal_credits += entry.amount

            if journal_debits != journal_credits:
                unbalanced_journals.append(journal.id)

        is_sound = (len(corrupt_journals) == 0 and len(unbalanced_journals) == 0)

        return LedgerIntegrityReport(
            total_journals_inspected=len(journals),
            total_entries_inspected=total_entries,
            is_sound=is_sound,
            corrupt_journals=corrupt_journals,
            unbalanced_journals=unbalanced_journals,
        )
    