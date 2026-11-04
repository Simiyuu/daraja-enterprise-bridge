"""Transaction settlement service with multi-leg fee slicing and merchant allocation."""

from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional

from src.core.ledger import LedgerEngine
from src.core.models import JournalEntry, LedgerEntry
from src.models.enums import LedgerEntryType


@dataclass(frozen=True)
class FeeConfig:
    """Configurable tiered or flat fee calculation rules."""
    flat_fee: Decimal = Decimal("0.00")
    percentage_rate: Decimal = Decimal("0.00")  # e.g., Decimal("0.015") for 1.5%
    min_fee: Optional[Decimal] = None
    max_fee: Optional[Decimal] = None

    def calculate_fee(self, gross_amount: Decimal) -> Decimal:
        """Calculate total processing fee with rounding and cap enforcement."""
        if gross_amount <= Decimal("0.00"):
            return Decimal("0.00")

        pct_fee = (gross_amount * self.percentage_rate).quantize(
            Decimal("0.01"), rounding=ROUND_HALF_UP
        )
        total = self.flat_fee + pct_fee

        if self.min_fee is not None and total < self.min_fee:
            total = self.min_fee
        if self.max_fee is not None and total > self.max_fee:
            total = self.max_fee

        return total


@dataclass(frozen=True)
class SettlementResult:
    """Immutable outcome of a posted settlement journal."""
    journal_id: str
    reference_id: str
    gross_amount: Decimal
    net_merchant_amount: Decimal
    fee_amount: Decimal


class SettlementService:
    """Coordinates account settlement for confirmed M-Pesa payments."""

    def __init__(self, ledger_engine: LedgerEngine):
        self.ledger_engine = ledger_engine

    def settle_stk_payment(
        self,
        reference_id: str,
        gross_amount: Decimal,
        merchant_account_id: str,
        escrow_account_id: str,
        fee_revenue_account_id: Optional[str] = None,
        fee_config: Optional[FeeConfig] = None,
        description: Optional[str] = None,
    ) -> SettlementResult:
        """
        Slice gross payment into merchant net and processing fee, posting atomically to the ledger.

        Journal Legs:
            - DEBIT:  Escrow Holding Account (Gross Amount)
            - CREDIT: Merchant Payable Account (Net Amount = Gross - Fee)
            - CREDIT: Fee Revenue Account (Fee Amount, if fee > 0)
        """
        if gross_amount <= Decimal("0.00"):
            raise ValueError(f"Gross settlement amount must be positive. Received: {gross_amount}")

        # Compute fee split
        config = fee_config or FeeConfig()
        fee_amount = config.calculate_fee(gross_amount)

        if fee_amount >= gross_amount:
            raise ValueError(
                f"Fee amount ({fee_amount}) cannot exceed or equal gross payment ({gross_amount})."
            )

        if fee_amount > Decimal("0.00") and not fee_revenue_account_id:
            raise ValueError("fee_revenue_account_id is required when transaction fee is greater than zero.")

        net_merchant_amount = gross_amount - fee_amount

        # Build balanced journal entries
        entries = [
            LedgerEntry(
                account_id=escrow_account_id,
                entry_type=LedgerEntryType.DEBIT,
                amount=gross_amount,
            ),
            LedgerEntry(
                account_id=merchant_account_id,
                entry_type=LedgerEntryType.CREDIT,
                amount=net_merchant_amount,
            ),
        ]

        if fee_amount > Decimal("0.00") and fee_revenue_account_id:
            entries.append(
                LedgerEntry(
                    account_id=fee_revenue_account_id,
                    entry_type=LedgerEntryType.CREDIT,
                    amount=fee_amount,
                )
            )

        desc = description or f"Settlement for M-Pesa transaction {reference_id}"
        journal = JournalEntry(
            reference_id=reference_id,
            description=desc,
            entries=entries,
        )

        # Post atomically
        self.ledger_engine.post_journal(journal)

        return SettlementResult(
            journal_id=journal.id,
            reference_id=reference_id,
            gross_amount=gross_amount,
            net_merchant_amount=net_merchant_amount,
            fee_amount=fee_amount,
        )
    