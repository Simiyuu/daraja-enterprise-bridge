"""Pydantic data contracts for M-Pesa Daraja requests, responses, and callback payloads."""

import re
from datetime import datetime
from typing import Any, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator
from src.models.enums import TransactionType


def normalize_msisdn(phone: str) -> str:
    """Normalize Kenyan mobile phone numbers to canonical 2547XXXXXXXX or 2541XXXXXXXX format."""
    cleaned = re.sub(r"[\s\-\+]", "", str(phone))
    if (cleaned.startswith("07") or cleaned.startswith("01")) and len(cleaned) == 10:
        cleaned = "254" + cleaned[1:]
    elif (cleaned.startswith("7") or cleaned.startswith("1")) and len(cleaned) == 9:
        cleaned = "254" + cleaned
    elif (cleaned.startswith("2547") or cleaned.startswith("2541")) and len(cleaned) == 12:
        pass
    else:
        raise ValueError(
            f"Invalid Kenyan MSISDN format: '{phone}'. Expected format: 2547XXXXXXXX or 2541XXXXXXXX."
        )
    return cleaned


class STKPushRequest(BaseModel):
    """Payload sent to Daraja's /mpesa/stkpush/v1/processrequest endpoint."""
    model_config = ConfigDict(populate_by_name=True)

    business_short_code: str = Field(..., alias="BusinessShortCode", min_length=5, max_length=7)
    password: str = Field(..., alias="Password", min_length=1)
    timestamp: str = Field(..., alias="Timestamp")
    transaction_type: TransactionType = Field(
        default=TransactionType.CUSTOMER_PAYBILL_ONLINE,
        alias="TransactionType"
    )
    amount: int = Field(..., alias="Amount", gt=0, description="Amount must be an integer greater than 0")
    party_a: str = Field(..., alias="PartyA", description="Phone number initiating payment")
    party_b: str = Field(..., alias="PartyB", description="Shortcode receiving payment")
    phone_number: str = Field(..., alias="PhoneNumber", description="Phone number receiving the prompt")
    callback_url: str = Field(..., alias="CallBackURL")
    account_reference: str = Field(..., alias="AccountReference", max_length=12)
    transaction_desc: str = Field(..., alias="TransactionDesc", max_length=100)

    @field_validator("phone_number", "party_a", mode="before")
    @classmethod
    def validate_and_normalize_phone(cls, v: Any) -> str:
        return normalize_msisdn(str(v))

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp_format(cls, v: str) -> str:
        try:
            datetime.strptime(v, "%Y%m%d%H%M%S")
        except ValueError:
            raise ValueError(f"Timestamp '{v}' must match format YYYYMMDDHHmmss.")
        return v


class STKPushResponse(BaseModel):
    """Immediate synchronous response returned by Daraja upon dispatching STK prompt."""
    model_config = ConfigDict(populate_by_name=True)

    merchant_request_id: str = Field(..., alias="MerchantRequestID")
    checkout_request_id: str = Field(..., alias="CheckoutRequestID")
    response_code: str = Field(..., alias="ResponseCode")
    response_description: str = Field(..., alias="ResponseDescription")
    customer_message: str = Field(..., alias="CustomerMessage")

    @property
    def is_successful(self) -> bool:
        return self.response_code == "0"


class CallbackItem(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    name: str = Field(..., alias="Name")
    value: Optional[Union[str, int, float]] = Field(default=None, alias="Value")


class CallbackMetadata(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    items: list[CallbackItem] = Field(default_factory=list, alias="Item")


class STKCallback(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    merchant_request_id: str = Field(..., alias="MerchantRequestID")
    checkout_request_id: str = Field(..., alias="CheckoutRequestID")
    result_code: int = Field(..., alias="ResultCode")
    result_desc: str = Field(..., alias="ResultDesc")
    metadata: Optional[CallbackMetadata] = Field(default=None, alias="CallbackMetadata")


class STKCallbackBody(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    stk_callback: STKCallback = Field(..., alias="stkCallback")


class STKCallbackPayload(BaseModel):
    """Top-level schema for the asynchronous webhook body posted by Safaricom."""
    model_config = ConfigDict(populate_by_name=True)

    body: STKCallbackBody = Field(..., alias="Body")

    def extract_metadata_dict(self) -> dict[str, Any]:
        """Flatten the nested Item list into a clean dictionary."""
        callback = self.body.stk_callback
        if not callback.metadata or not callback.metadata.items:
            return {}
        return {item.name: item.value for item in callback.metadata.items}

    @property
    def receipt_number(self) -> Optional[str]:
        data = self.extract_metadata_dict()
        val = data.get("MpesaReceiptNumber")
        return str(val) if val else None

    @property
    def paid_amount(self) -> Optional[float]:
        data = self.extract_metadata_dict()
        val = data.get("Amount")
        return float(val) if val is not None else None
    