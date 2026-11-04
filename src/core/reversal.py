"""Compensating journal entry engine for processing full reversals and partial refunds."""

from dataclasses import dataclass
from decimal import Decimal
from typing import Dict, List, Optional
import threading

from src.core.ledger import LedgerEngine
from src.core.models import JournalEntry, LedgerEntry
from src.models.enums import LedgerEntryType


@dataclass(frozen=True)
class ReversalResult:
    """Immutable audit representation of a completed refund/reversal journal."""
    reversal_journal_id: str
    original_reference_id: str
    reversal_reference_id: str
    amount_reversed: Decimal
    is_full_reversal: bool


class ReversalService:
    """Coordinates dispute refunds and transaction reversals via compensating journal entries."""

    def __init__(self, ledger_engine: LedgerEngine):
        self.ledger_engine = ledger_engine
        self._refunded_totals: Dict[str, Decimal] = {}
        self._lock = threading.RLock()

    def get_total_refunded(self, original_reference_id: str) -> Decimal:
        """Return the cumulative amount refunded against an original reference."""
        with self._lock:
            return self._refunded_totals.get(original_reference_id, Decimal("0.00"))

    def process_reversal(
        self,
        original_reference_id: str,
        reversal_reference_id: str,
        reversal_amount: Optional[Decimal] = None,
        escrow_account_id: Optional[str] = None,
        merchant_account_id: Optional[str] = None,
        fee_revenue_account_id: Optional[str] = None,
        refund_fee: bool = False,
        reason: Optional[str] = None,
    ) -> ReversalResult:
        """
        Execute an atomic compensating journal entry to refund or reverse a prior settlement.

        Args:
            original_reference_id: Reference of the original settlement journal.
            reversal_reference_id: Unique idempotency reference for this refund action.
            reversal_amount: Desired refund amount (defaults to entire unrefunded gross amount).
            escrow_account_id: Holding account refunding the funds back to M-Pesa.
            merchant_account_id: Merchant account to debit for the refund.
            fee_revenue_account_id: Platform fee account (required if refund_fee is True).
            refund_fee: Whether the platform refunds its earned fee cut.
            reason: Audit notes for dispute resolution logs.
        """
        with self._lock:
            # 1. Locate original transaction
            original_journal = self.ledger_engine.get_journal_by_reference(original_reference_id)
            if not original_journal:
                raise KeyError(f"Original transaction '{original_reference_id}' not found in ledger.")

            gross_original = original_journal.total_amount
            already_refunded = self._refunded_totals.get(original_reference_id, Decimal("0.00"))
            available_to_refund = gross_original - already_refunded

            if available_to_refund <= Decimal("0.00"):
                raise ValueError(
                    f"Transaction '{original_reference_id}' is already fully reversed."
                )

            # 2. Determine target refund volume
            target_amount = reversal_amount if reversal_amount is not None else available_to_refund

            if target_amount <= Decimal("0.00"):
                raise ValueError(f"Reversal amount must be positive. Received: {target_amount}")

            if target_amount > available_to_refund:
                raise ValueError(
                    f"Requested reversal amount ({target_amount}) exceeds remaining available refund balance ({available_to_refund})."
                )

            # 3. Resolve target accounts
            # If not explicitly provided, infer accounts from original legs
            # Original: Debit Escrow, Credit Merchant (and optionally Credit Fee Revenue)
            debit_legs = [e for e in original_journal.entries if e.entry_type == LedgerEntryType.DEBIT]
            credit_legs = [e for e in original_journal.entries if e.entry_type == LedgerEntryType.CREDIT]

            target_escrow = escrow_account_id or (debit_legs[0].account_id if debit_legs else None)
            target_merchant = merchant_account_id or (credit_legs[0].account_id if credit_legs else None)

            if not target_escrow or not target_merchant:
                raise ValueError("Could not resolve escrow or merchant account for compensating entry.")

            # 4. Check merchant liquidity
            merchant_balance = self.ledger_engine.calculate_balance(target_merchant)
            if merchant_balance < target_amount:
                raise ValueError(
                    f"Merchant account '{target_merchant}' has insufficient balance ({merchant_balance}) to cover refund of {target_amount}."
                )

            # 5. Build compensating legs
            # Compensating entry: CREDIT Escrow (funds leaving holding), DEBIT Merchant (deducted from merchant)
            entries: List[LedgerEntry] = [
                LedgerEntry(
                    account_id=target_merchant,
                    entry_type=LedgerEntryType.DEBIT,
                    amount=target_amount,
                ),
                LedgerEntry(
                    account_id=target_escrow,
                    entry_type=LedgerEntryType.CREDIT,
                    amount=target_amount,
                ),
            ]

            reversal_desc = reason or f"Reversal of transaction {original_reference_id}"
            compensating_journal = JournalEntry(
                reference_id=reversal_reference_id,
                description=reversal_desc,
                entries=entries,
            )

            # 6. Post atomically
            self.ledger_engine.post_journal(compensating_journal)

            # 7. Update refund tracking state
            new_refunded_total = already_refunded + target_amount
            self._refunded_totals[original_reference_id] = new_refunded_total
            is_full = (new_refunded_total == gross_original)

            return ReversalResult(
                reversal_journal_id=compensating_journal.id,
                original_reference_id=original_reference_id,
                reversal_reference_id=reversal_reference_id,
                amount_reversed=target_amount,
                is_full_reversal=is_full,
            )
        