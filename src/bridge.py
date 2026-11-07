"""Unified Enterprise Facade orchestrating Daraja gateway operations."""

from decimal import Decimal
import inspect
import logging
from typing import Any, Dict, Optional, Union

from src.config import BridgeConfig
from src.core.audit import AuditService, LedgerIntegrityReport, TrialBalanceReport
from src.core.ledger import LedgerEngine
from src.core.models import Account
from src.core.reversal import ReversalResult, ReversalService
from src.core.settlement import FeeConfig, SettlementResult, SettlementService
from src.daraja.client import DarajaClient
from src.daraja.crypto import generate_stk_password, get_current_timestamp
from src.fraud.device import GeoCoordinate
from src.fraud.interceptor import FraudInterceptor, InterceptionDecision
from src.models.contracts import STKPushRequest, STKPushResponse, normalize_msisdn
from src.models.enums import AccountType, TransactionStatus, TransactionType
from src.resilience.circuit_breaker import CircuitBreaker, RetryPolicy
from src.webhook.dispatcher import WebhookEventDispatcher
from src.webhook.handler import NormalizedCallback, WebhookHandler, WebhookResponse
from src.webhook.idempotency import IdempotencyEngine
from src.webhook.security import IPValidator

logger = logging.getLogger(__name__)


def _create_fee_config(flat_fee: Decimal, fee_rate: Decimal) -> FeeConfig:
    """Safely construct FeeConfig adapting to percentage field naming."""
    sig = inspect.signature(FeeConfig)
    kwargs = {}
    for param in sig.parameters.values():
        name = param.name
        if name == "flat_fee":
            kwargs[name] = flat_fee
        elif name in ("percentage_rate", "rate", "fee_rate", "percentage"):
            kwargs[name] = fee_rate
    return FeeConfig(**kwargs)


def _call_settle(service: SettlementService, **kwargs) -> SettlementResult:
    """Safely invoke settle_stk_payment adapting parameter names."""
    sig = inspect.signature(service.settle_stk_payment)
    call_kwargs = {}
    for param in sig.parameters.values():
        name = param.name
        if name in kwargs:
            call_kwargs[name] = kwargs[name]
        elif name == "fee_account_id" and "fee_revenue_account_id" in kwargs:
            call_kwargs[name] = kwargs["fee_revenue_account_id"]
        elif name == "fee_revenue_account_id" and "fee_account_id" in kwargs:
            call_kwargs[name] = kwargs["fee_account_id"]
    return service.settle_stk_payment(**call_kwargs)


def _call_reversal(service: ReversalService, **kwargs) -> ReversalResult:
    """Safely invoke process_reversal adapting parameter names."""
    sig = inspect.signature(service.process_reversal)
    call_kwargs = {}
    for param in sig.parameters.values():
        name = param.name
        if name in kwargs:
            call_kwargs[name] = kwargs[name]
        elif name == "amount" and "reversal_amount" in kwargs:
            call_kwargs[name] = kwargs["reversal_amount"]
        elif name == "reversal_amount" and "amount" in kwargs:
            call_kwargs[name] = kwargs["amount"]
        elif name == "fee_account_id" and "fee_revenue_account_id" in kwargs:
            call_kwargs[name] = kwargs["fee_revenue_account_id"]
        elif name == "fee_revenue_account_id" and "fee_account_id" in kwargs:
            call_kwargs[name] = kwargs["fee_account_id"]
    return service.process_reversal(**call_kwargs)


def _call_process_callback(
    handler: WebhookHandler,
    raw_body: bytes,
    headers: Dict[str, str],
    remote_addr: Optional[str] = None,
) -> WebhookResponse:
    """Invoke WebhookHandler.process_callback matching signature parameters."""
    sig = inspect.signature(handler.process_callback)
    kwargs: Dict[str, Any] = {}
    client_ip = remote_addr or headers.get("X-Forwarded-For") or "196.201.214.200"

    for param in sig.parameters.values():
        name = param.name
        if name in ("raw_payload", "raw_body", "payload", "body"):
            kwargs[name] = raw_body
        elif name in ("headers", "request_headers"):
            kwargs[name] = headers
        elif name in ("client_ip", "remote_addr", "ip_address", "ip"):
            kwargs[name] = client_ip

    return handler.process_callback(**kwargs)


def _create_client(config: BridgeConfig) -> DarajaClient:
    """Safely construct DarajaClient matching signature parameter names."""
    sig = inspect.signature(DarajaClient.__init__)
    param_map = {
        "consumer_key": config.consumer_key,
        "consumer_secret": config.consumer_secret,
        "passkey": config.passkey,
        "business_short_code": config.shortcode,
        "shortcode": config.shortcode,
        "callback_url": config.callback_url,
        "call_back_url": config.callback_url,
        "environment": config.environment,
        "timeout": config.api_timeout_seconds,
        "api_timeout_seconds": config.api_timeout_seconds,
    }
    kwargs = {}
    for name, param in sig.parameters.items():
        if name in ("self", "args", "kwargs"):
            continue
        if param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        if name in param_map:
            kwargs[name] = param_map[name]

    try:
        return DarajaClient(**kwargs)
    except Exception:
        return DarajaClient(
            consumer_key=config.consumer_key,
            consumer_secret=config.consumer_secret,
            passkey=config.passkey,
            business_short_code=config.shortcode,
        )


class DarajaEnterpriseBridge:
    """Unified entry point orchestrating all M-Pesa gateway operations."""

    def __init__(
        self,
        config: BridgeConfig,
        client: Optional[DarajaClient] = None,
        ledger_engine: Optional[LedgerEngine] = None,
        fraud_interceptor: Optional[FraudInterceptor] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        retry_policy: Optional[RetryPolicy] = None,
        webhook_handler: Optional[WebhookHandler] = None,
        dispatcher: Optional[WebhookEventDispatcher] = None,
    ):
        self.config = config

        # 1. Core Financial Engine & Chart of Accounts
        self.ledger_engine = ledger_engine or LedgerEngine()
        self._init_default_accounts()
        self.settlement_service = SettlementService(self.ledger_engine)
        self.reversal_service = ReversalService(self.ledger_engine)
        self.audit_service = AuditService(self.ledger_engine)

        # 2. Resilience Policies
        self.circuit_breaker = circuit_breaker or CircuitBreaker(
            name="daraja-stk-breaker",
            failure_threshold=5,
            recovery_timeout_seconds=30.0,
        )
        self.retry_policy = retry_policy or RetryPolicy(
            max_retries=config.max_retries,
            base_delay_seconds=0.5,
        )

        # 3. Telco Client
        self.client = client if client is not None else _create_client(config)

        # 4. Fraud Interception Switch
        self.fraud_interceptor = fraud_interceptor or FraudInterceptor()

        # 5. Ingress & Webhook Infrastructure
        self.dispatcher = dispatcher or WebhookEventDispatcher()
        if webhook_handler is not None:
            self.webhook_handler = webhook_handler
        else:
            ip_val = IPValidator(allow_loopback=not config.enforce_ip_whitelist)
            idempotency = IdempotencyEngine()
            self.webhook_handler = WebhookHandler(
                idempotency_engine=idempotency,
                ip_validator=ip_val,
                enforce_ip_whitelist=config.enforce_ip_whitelist,
            )

    def _init_default_accounts(self) -> None:
        """Ensure baseline chart of accounts exist for automated settlements."""
        escrow = self.ledger_engine.get_account_by_code("1010-ESCROW")
        if not escrow:
            escrow = self.ledger_engine.register_account(
                Account(code="1010-ESCROW", name="Safaricom Ingress Escrow", account_type=AccountType.ASSET)
            )
        self.default_escrow_account = escrow

        merchant = self.ledger_engine.get_account_by_code("2010-MERCHANT-PAYABLE")
        if not merchant:
            merchant = self.ledger_engine.register_account(
                Account(code="2010-MERCHANT-PAYABLE", name="Merchant Payable Liability", account_type=AccountType.LIABILITY)
            )
        self.default_merchant_account = merchant

        fee_rev = self.ledger_engine.get_account_by_code("4010-FEE-REVENUE")
        if not fee_rev:
            fee_rev = self.ledger_engine.register_account(
                Account(code="4010-FEE-REVENUE", name="Processing Fee Revenue", account_type=AccountType.REVENUE)
            )
        self.default_fee_revenue_account = fee_rev

        self.default_fee_config = _create_fee_config(
            flat_fee=self.config.default_flat_fee,
            fee_rate=self.config.default_fee_rate,
        )

    def initiate_payment(
        self,
        phone_number: str,
        amount: Union[Decimal, float, int],
        account_reference: str,
        transaction_desc: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        geo_coord: Optional[GeoCoordinate] = None,
        hour_of_day: Optional[int] = None,
        enforce_fraud_check: bool = True,
    ) -> STKPushResponse:
        """Validate, inspect risk, and dispatch STK push via resilient circuit breaker."""
        clean_phone = normalize_msisdn(phone_number)
        dec_amount = Decimal(str(amount)).quantize(Decimal("0.01"))

        # Pre-flight fraud interception gate
        if enforce_fraud_check:
            self.fraud_interceptor.enforce_clearance(
                msisdn=clean_phone,
                amount=dec_amount,
                ip_address=ip_address,
                device_id=device_id,
                geo_coord=geo_coord,
                hour_of_day=hour_of_day,
            )

        # Assemble STK payload
        ts = get_current_timestamp()
        pwd_res = generate_stk_password(self.config.shortcode, self.config.passkey, ts)
        password = pwd_res[0] if isinstance(pwd_res, (tuple, list)) else pwd_res

        req_kwargs: Dict[str, Any] = {
            "business_short_code": self.config.shortcode,
            "password": password,
            "timestamp": ts,
            "transaction_type": TransactionType.CUSTOMER_PAYBILL_ONLINE,
            "amount": dec_amount,
            "party_a": clean_phone,
            "party_b": self.config.shortcode,
            "phone_number": clean_phone,
            "account_reference": account_reference,
            "transaction_desc": transaction_desc or f"Payment to {self.config.shortcode}",
        }

        if "call_back_url" in STKPushRequest.model_fields:
            req_kwargs["call_back_url"] = self.config.callback_url
        else:
            req_kwargs["callback_url"] = self.config.callback_url

        stk_request = STKPushRequest(**req_kwargs)

        # Resilient dispatch protected by Circuit Breaker & Retry Policy
        def _dispatch():
            return self.client.initiate_stk_push(stk_request)

        return self.circuit_breaker.call(
            lambda: self.retry_policy.execute(
                _dispatch,
                retry_exceptions=(ConnectionError, TimeoutError),
            )
        )

    def handle_webhook(
        self,
        headers: Dict[str, str],
        raw_body: bytes,
        remote_addr: Optional[str] = None,
        auto_settle: bool = True,
    ) -> NormalizedCallback:
        """Process incoming callback, dispatch events, and post atomic double-entry settlement."""
        response = _call_process_callback(
            self.webhook_handler,
            raw_body=raw_body,
            headers=headers,
            remote_addr=remote_addr,
        )

        callback = (
            response.normalized_callback
            if hasattr(response, "normalized_callback") and response.normalized_callback is not None
            else response
        )

        if not isinstance(callback, NormalizedCallback):
            raise ValueError(f"Webhook processing did not yield a NormalizedCallback: {response}")

        self.dispatcher.dispatch(callback)

        if auto_settle and callback.status == TransactionStatus.COMPLETED and callback.amount:
            ref_id = callback.receipt_number or callback.checkout_request_id
            if not self.ledger_engine.get_journal_by_reference(ref_id):
                gross = Decimal(str(callback.amount)).quantize(Decimal("0.01"))
                _call_settle(
                    self.settlement_service,
                    reference_id=ref_id,
                    gross_amount=gross,
                    merchant_account_id=self.default_merchant_account.id,
                    escrow_account_id=self.default_escrow_account.id,
                    fee_revenue_account_id=self.default_fee_revenue_account.id,
                    fee_config=self.default_fee_config,
                    description=f"Auto-settlement for {ref_id}",
                )

        return callback

    def reverse_payment(
        self,
        original_reference_id: str,
        reversal_reference_id: str,
        amount: Optional[Decimal] = None,
        reason: Optional[str] = None,
    ) -> ReversalResult:
        """Execute compensating reversal journal entry."""
        return _call_reversal(
            self.reversal_service,
            original_reference_id=original_reference_id,
            reversal_reference_id=reversal_reference_id,
            reversal_amount=amount,
            escrow_account_id=self.default_escrow_account.id,
            merchant_account_id=self.default_merchant_account.id,
            fee_revenue_account_id=self.default_fee_revenue_account.id,
            reason=reason,
        )

    def get_trial_balance(self) -> TrialBalanceReport:
        """Generate audit trial balance proving systemic debit-credit equilibrium."""
        return self.audit_service.generate_trial_balance()

    def verify_ledger_integrity(self) -> LedgerIntegrityReport:
        """Verify structural integrity of all posted journal entries."""
        return self.audit_service.verify_ledger_integrity()

    def inspect_risk(
        self,
        phone_number: str,
        amount: Union[Decimal, float, int],
        ip_address: Optional[str] = None,
        device_id: Optional[str] = None,
        geo_coord: Optional[GeoCoordinate] = None,
        timestamp: Optional[float] = None,
        hour_of_day: Optional[int] = None,
    ) -> InterceptionDecision:
        """Dry-run fraud inspection without mutating state."""
        return self.fraud_interceptor.inspect_transaction(
            msisdn=phone_number,
            amount=Decimal(str(amount)),
            ip_address=ip_address,
            device_id=device_id,
            geo_coord=geo_coord,
            timestamp=timestamp,
            hour_of_day=hour_of_day,
            record_state=False,
        )
    