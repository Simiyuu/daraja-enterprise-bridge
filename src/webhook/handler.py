"""Asynchronous webhook ingress pipeline and callback normalizer."""

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Union

from pydantic import ValidationError

from src.models.contracts import STKCallbackPayload
from src.models.enums import ResultCode, TransactionStatus
from src.webhook.idempotency import IdempotencyEngine, IdempotencyStatus
from src.webhook.security import IPValidator, IngressSecurityError, extract_client_ip


@dataclass(frozen=True)
class NormalizedCallback:
    """Standardized internal representation of a completed or failed M-Pesa transaction."""
    merchant_request_id: str
    checkout_request_id: str
    result_code: int
    result_description: str
    status: TransactionStatus
    receipt_number: Optional[str] = None
    amount: Optional[float] = None
    phone_number: Optional[str] = None
    transaction_date: Optional[str] = None

    @property
    def is_successful(self) -> bool:
        return self.result_code == ResultCode.SUCCESS.value


@dataclass(frozen=True)
class WebhookResponse:
    """HTTP response tuple to return to the gateway caller."""
    status_code: int
    payload: Dict[str, Any]
    normalized_callback: Optional[NormalizedCallback] = None
    is_duplicate: bool = False


class WebhookHandler:
    """Ingress processor for Safaricom Daraja asynchronous payment callbacks."""

    ACK_SUCCESS = {"ResultCode": 0, "ResultDesc": "Accepted"}
    ACK_REJECTED = {"ResultCode": 1, "ResultDesc": "Rejected"}

    def __init__(
        self,
        idempotency_engine: Optional[IdempotencyEngine] = None,
        ip_validator: Optional[IPValidator] = None,
        enforce_ip_whitelist: bool = True,
    ):
        self.idempotency_engine = idempotency_engine or IdempotencyEngine()
        self.ip_validator = ip_validator or IPValidator()
        self.enforce_ip_whitelist = enforce_ip_whitelist

    def process_callback(
        self,
        raw_body: Union[str, bytes],
        headers: Dict[str, str],
        remote_addr: Optional[str] = None,
    ) -> WebhookResponse:
        """
        Ingest, authenticate, deduplicate, and normalize an incoming webhook payload.

        Returns:
            WebhookResponse containing status code, JSON response, and normalized domain data.
        """
        # 1. Source IP Verification
        client_ip = extract_client_ip(headers, remote_addr=remote_addr)
        if self.enforce_ip_whitelist:
            if not self.ip_validator.is_authorized(client_ip):
                return WebhookResponse(
                    status_code=403,
                    payload={"error": f"Unauthorized ingress source IP: {client_ip}"},
                )

        # 2. Body Serialization & Validation
        body_bytes = raw_body.encode("utf-8") if isinstance(raw_body, str) else raw_body
        try:
            body_dict = json.loads(body_bytes.decode("utf-8"))
            parsed_contract = STKCallbackPayload(**body_dict)
        except (json.JSONDecodeError, UnicodeDecodeError, ValidationError) as exc:
            return WebhookResponse(
                status_code=400,
                payload={"error": f"Invalid or malformed callback payload: {str(exc)}"},
            )

        stk_data = parsed_contract.body.stk_callback
        idempotency_key = stk_data.checkout_request_id

        # 3. Idempotency Check & Acquisition
        acquired, record = self.idempotency_engine.acquire(idempotency_key, body_bytes)
        if not acquired and record:
            # If completed previously, return cached ACK without re-running business logic
            if record.status == IdempotencyStatus.COMPLETED and record.response_payload:
                return WebhookResponse(
                    status_code=200,
                    payload=record.response_payload,
                    is_duplicate=True,
                )
            # If currently in-flight, return 200/ACK to prevent gateway flood
            return WebhookResponse(
                status_code=200,
                payload=self.ACK_SUCCESS,
                is_duplicate=True,
            )

        # 4. Normalize Domain Fields
        metadata = parsed_contract.extract_metadata_dict()
        status = (
            TransactionStatus.COMPLETED
            if stk_data.result_code == ResultCode.SUCCESS.value
            else TransactionStatus.FAILED
        )

        receipt = str(metadata.get("MpesaReceiptNumber")) if metadata.get("MpesaReceiptNumber") else None
        amount = float(metadata.get("Amount")) if metadata.get("Amount") is not None else None
        phone = str(metadata.get("PhoneNumber")) if metadata.get("PhoneNumber") else None
        tx_date = str(metadata.get("TransactionDate")) if metadata.get("TransactionDate") else None

        normalized = NormalizedCallback(
            merchant_request_id=stk_data.merchant_request_id,
            checkout_request_id=stk_data.checkout_request_id,
            result_code=stk_data.result_code,
            result_description=stk_data.result_desc,
            status=status,
            receipt_number=receipt,
            amount=amount,
            phone_number=phone,
            transaction_date=tx_date,
        )

        # 5. Mark Idempotency Record as Completed
        self.idempotency_engine.complete(idempotency_key, self.ACK_SUCCESS)

        return WebhookResponse(
            status_code=200,
            payload=self.ACK_SUCCESS,
            normalized_callback=normalized,
            is_duplicate=False,
        )
    