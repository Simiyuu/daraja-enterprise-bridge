"""Domain models for double-entry bookkeeping, chart of accounts, and balanced journal entries."""

from datetime import datetime, timezone
from decimal import Decimal
from typing import List
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.models.enums import AccountType, LedgerEntryType


class Account(BaseModel):
    """Chart of accounts node representing an internal or external financial bucket."""
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    code: str = Field(..., min_length=3, max_length=64, description="Unique account code, e.g. 1010-ESCROW")
    name: str = Field(..., min_length=2, max_length=128)
    account_type: AccountType
    currency: str = Field(default="KES", min_length=3, max_length=3)
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("code")
    @classmethod
    def normalize_code(cls, v: str) -> str:
        return v.strip().upper()


class LedgerEntry(BaseModel):
    """An individual credit or debit movement attached to a specific account."""
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    account_id: str = Field(..., description="Target account ID being mutated")
    entry_type: LedgerEntryType
    amount: Decimal = Field(..., gt=Decimal("0.00"), description="Positive mutation value")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("amount")
    @classmethod
    def validate_precision(cls, v: Decimal) -> Decimal:
        """Enforce standard currency precision (2 decimal places)."""
        rounded = round(v, 2)
        if rounded != v:
            raise ValueError(f"Amount '{v}' exceeds allowable currency precision of 2 decimal places.")
        return rounded


class JournalEntry(BaseModel):
    """
    An atomic financial transaction comprising two or more balanced ledger entries.
    
    Invariant: Total Debits == Total Credits.
    """
    model_config = ConfigDict(populate_by_name=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    reference_id: str = Field(..., description="External payment receipt or checkout ID")
    description: str = Field(..., min_length=3, max_length=255)
    entries: List[LedgerEntry] = Field(..., min_length=2, description="At least two balanced legs required")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def verify_double_entry_balance(self) -> "JournalEntry":
        """Verify that sum of debits exactly matches sum of credits."""
        total_debit = Decimal("0.00")
        total_credit = Decimal("0.00")

        for entry in self.entries:
            if entry.entry_type == LedgerEntryType.DEBIT:
                total_debit += entry.amount
            elif entry.entry_type == LedgerEntryType.CREDIT:
                total_credit += entry.amount

        if total_debit != total_credit:
            raise ValueError(
                f"Double-entry balance mismatch: Total Debits ({total_debit}) != Total Credits ({total_credit})."
            )

        return self

    @property
    def total_amount(self) -> Decimal:
        """Return the transaction volume represented by the balanced debits."""
        return sum(
            (entry.amount for entry in self.entries if entry.entry_type == LedgerEntryType.DEBIT),
            Decimal("0.00"),
        )
    