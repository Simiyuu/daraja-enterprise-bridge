"""Domain enumerations for M-Pesa Daraja payment workflows and ledger operations."""

from enum import Enum

try:
    from enum import StrEnum
except ImportError:  # Fallback for Python < 3.11
    class StrEnum(str, Enum):
        def __str__(self) -> str:
            return str(self.value)


class Environment(StrEnum):
    """Daraja runtime environments."""
    SANDBOX = "sandbox"
    PRODUCTION = "production"


class TransactionType(StrEnum):
    """M-Pesa transaction channel identifiers."""
    CUSTOMER_PAYBILL_ONLINE = "CustomerPayBillOnline"
    CUSTOMER_BUY_GOODS_ONLINE = "CustomerBuyGoodsOnline"
    BUSINESS_PAYMENT = "BusinessPayment"
    SALARY_PAYMENT = "SalaryPayment"
    PROMOTION_PAYMENT = "PromotionPayment"
    BUSINESS_BUY_GOODS = "BusinessBuyGoods"


class TransactionStatus(StrEnum):
    """Lifecycle states for payment requests in the gateway."""
    PENDING = "PENDING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REVERSED = "REVERSED"
    TIMEOUT = "TIMEOUT"


class ResultCode(int, Enum):
    """Standard Safaricom Daraja callback result codes."""
    SUCCESS = 0
    INSUFFICIENT_FUNDS = 1
    LESS_THAN_MINIMUM = 2
    MORE_THAN_MAXIMUM = 3
    EXCEEDED_DAILY_LIMIT = 4
    CANCELLED_BY_USER = 1032
    USER_TIMEOUT = 1037
    INVALID_INITIATOR_OR_PASSWORD = 2001
    INTERNAL_SYSTEM_ERROR = 9999

    @classmethod
    def get_description(cls, code: int) -> str:
        """Translate numeric result code to standard enterprise audit message."""
        descriptions = {
            cls.SUCCESS: "Transaction completed successfully.",
            cls.INSUFFICIENT_FUNDS: "The subscriber has insufficient funds to complete the payment.",
            cls.LESS_THAN_MINIMUM: "The transaction amount is less than the minimum permitted.",
            cls.MORE_THAN_MAXIMUM: "The transaction amount exceeds the maximum allowable single transaction limit.",
            cls.EXCEEDED_DAILY_LIMIT: "The subscriber has reached their daily M-Pesa transaction limit.",
            cls.CANCELLED_BY_USER: "The transaction was explicitly cancelled by the subscriber on prompt.",
            cls.USER_TIMEOUT: "The USSD / SIM Toolkit push prompt timed out with no subscriber input.",
            cls.INVALID_INITIATOR_OR_PASSWORD: "Authentication failed due to an invalid initiator credential or password.",
            cls.INTERNAL_SYSTEM_ERROR: "Safaricom core payment switch encountered an unexpected internal error.",
        }
        return descriptions.get(code, "Unknown response code received from gateway.")


class LedgerEntryType(StrEnum):
    """Accounting entry mutation direction."""
    DEBIT = "DEBIT"
    CREDIT = "CREDIT"


class AccountType(StrEnum):
    """Double-entry ledger chart of accounts categorization."""
    ASSET = "ASSET"          # e.g., Safaricom Escrow / Till Holding
    LIABILITY = "LIABILITY"  # e.g., Merchant Unsettled Balances
    EQUITY = "EQUITY"        # e.g., Retained Earnings
    REVENUE = "REVENUE"      # e.g., Gateway Processing Fees
    EXPENSE = "EXPENSE"      # e.g., Telco Interchange Fees


class RiskTier(StrEnum):
    """Telco fraud interceptor classification levels."""
    LOW = "LOW"
    ELEVATED = "ELEVATED"
    CRITICAL_INTERCEPT = "CRITICAL_INTERCEPT"
    