"""Atomic double-entry ledger execution engine and balance calculator."""

import threading
from decimal import Decimal
from typing import Dict, List, Optional

from src.core.models import Account, JournalEntry, LedgerEntry
from src.models.enums import AccountType, LedgerEntryType


class LedgerEngine:
    """Thread-safe ledger engine maintaining accounts, journals, and account mutations."""

    def __init__(self):
        self._accounts: Dict[str, Account] = {}
        self._accounts_by_code: Dict[str, str] = {}
        self._journals_by_id: Dict[str, JournalEntry] = {}
        self._journals_by_reference: Dict[str, JournalEntry] = {}
        self._entries_by_account: Dict[str, List[LedgerEntry]] = {}
        self._lock = threading.RLock()

    def register_account(self, account: Account) -> Account:
        """Register a new chart of accounts entry."""
        with self._lock:
            if account.id in self._accounts:
                raise ValueError(f"Account with ID '{account.id}' already exists.")
            if account.code in self._accounts_by_code:
                raise ValueError(f"Account with code '{account.code}' already exists.")

            self._accounts[account.id] = account
            self._accounts_by_code[account.code] = account.id
            self._entries_by_account[account.id] = []
            return account

    def get_account(self, account_id: str) -> Optional[Account]:
        """Fetch account by unique ID."""
        with self._lock:
            return self._accounts.get(account_id)

    def get_account_by_code(self, code: str) -> Optional[Account]:
        """Fetch account by unique accounting code."""
        with self._lock:
            acc_id = self._accounts_by_code.get(code.strip().upper())
            return self._accounts.get(acc_id) if acc_id else None

    def calculate_balance(self, account_id: str) -> Decimal:
        """
        Compute net account balance according to GAAP normal balance rules.

        - Asset & Expense: Balance = Total Debits - Total Credits
        - Liability, Equity, Revenue: Balance = Total Credits - Total Debits
        """
        with self._lock:
            account = self._accounts.get(account_id)
            if not account:
                raise KeyError(f"Account '{account_id}' does not exist.")

            entries = self._entries_by_account.get(account_id, [])
            total_debits = sum(
                (e.amount for e in entries if e.entry_type == LedgerEntryType.DEBIT),
                Decimal("0.00"),
            )
            total_credits = sum(
                (e.amount for e in entries if e.entry_type == LedgerEntryType.CREDIT),
                Decimal("0.00"),
            )

            if account.account_type in (AccountType.ASSET, AccountType.EXPENSE):
                return total_debits - total_credits
            else:
                return total_credits - total_debits

    def post_journal(self, journal: JournalEntry) -> None:
        """
        Atomically post a balanced journal entry across target accounts.

        Raises:
            KeyError: If any target account does not exist.
            ValueError: If an account is inactive or reference_id is duplicated.
        """
        with self._lock:
            if journal.reference_id in self._journals_by_reference:
                raise ValueError(
                    f"Journal entry with reference '{journal.reference_id}' has already been posted."
                )

            # Pre-flight check: ensure all accounts exist and are active
            for entry in journal.entries:
                account = self._accounts.get(entry.account_id)
                if not account:
                    raise KeyError(f"Target ledger account '{entry.account_id}' does not exist.")
                if not account.is_active:
                    raise ValueError(f"Cannot post to inactive ledger account '{account.code}'.")

            # Mutate state atomically
            self._journals_by_id[journal.id] = journal
            self._journals_by_reference[journal.reference_id] = journal

            for entry in journal.entries:
                self._entries_by_account[entry.account_id].append(entry)

    def get_journal_by_reference(self, reference_id: str) -> Optional[JournalEntry]:
        """Fetch journal entry by external reference/checkout identifier."""
        with self._lock:
            return self._journals_by_reference.get(reference_id)

    def get_account_entries(self, account_id: str) -> List[LedgerEntry]:
        """Return a copy of the ledger entries for an account."""
        with self._lock:
            if account_id not in self._accounts:
                raise KeyError(f"Account '{account_id}' does not exist.")
            return list(self._entries_by_account.get(account_id, []))
        