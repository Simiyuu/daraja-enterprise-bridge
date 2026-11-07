"""Enterprise runtime configuration and environment variable manager."""

from decimal import Decimal
import os
from typing import Dict, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.models.enums import Environment


DARAJA_BASE_URLS: Dict[Environment, str] = {
    Environment.SANDBOX: "https://sandbox.safaricom.co.ke",
    Environment.PRODUCTION: "https://api.safaricom.co.ke",
}


class BridgeConfig(BaseModel):
    """Central configuration schema for the Daraja Enterprise Bridge."""
    model_config = ConfigDict(frozen=True, populate_by_name=True)

    # Core Telco Gateway Credentials
    environment: Environment = Field(default=Environment.SANDBOX)
    consumer_key: str = Field(..., min_length=8, description="Safaricom developer portal consumer key")
    consumer_secret: str = Field(..., min_length=8, description="Safaricom developer portal consumer secret")
    passkey: str = Field(..., min_length=16, description="Lipa Na M-Pesa Online passkey")
    shortcode: str = Field(..., min_length=5, max_length=10, description="Business paybill or till number")
    callback_url: str = Field(..., description="Fully qualified HTTPS callback ingress URL")

    # Ingress & Network Security
    enforce_ip_whitelist: bool = Field(default=True)
    api_timeout_seconds: float = Field(default=30.0, gt=0.0, le=120.0)
    max_retries: int = Field(default=3, ge=0, le=10)

    # Financial Settlement Defaults
    default_flat_fee: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"))
    default_fee_rate: Decimal = Field(default=Decimal("0.00"), ge=Decimal("0.00"), le=Decimal("1.00"))

    # Fraud Interceptor Defaults
    fraud_risk_low_threshold: int = Field(default=30, ge=1, le=100)
    fraud_risk_medium_threshold: int = Field(default=60, ge=1, le=100)
    fraud_risk_high_threshold: int = Field(default=85, ge=1, le=100)

    @field_validator("shortcode")
    @classmethod
    def validate_shortcode(cls, v: str) -> str:
        clean = v.strip()
        if not clean.isdigit():
            raise ValueError(f"Shortcode must contain only numeric digits. Received: '{v}'")
        return clean

    @field_validator("callback_url")
    @classmethod
    def validate_callback_url(cls, v: str) -> str:
        clean = v.strip()
        parsed = urlparse(clean)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"Callback URL must be a valid HTTP/HTTPS URL. Received: '{v}'")
        return clean

    @property
    def base_url(self) -> str:
        """Resolve Safaricom base API gateway URL according to active environment."""
        return DARAJA_BASE_URLS[self.environment]

    @property
    def oauth_url(self) -> str:
        return f"{self.base_url}/oauth/v1/generate?grant_type=client_credentials"

    @property
    def stk_push_url(self) -> str:
        return f"{self.base_url}/mpesa/stkpush/v1/processrequest"

    @classmethod
    def from_env(cls, env_dict: Optional[Dict[str, str]] = None) -> "BridgeConfig":
        """
        Instantiate configuration from a dictionary or system environment variables.
        """
        source = env_dict if env_dict is not None else os.environ

        env_raw = source.get("DARAJA_ENVIRONMENT", "SANDBOX").strip()
        try:
            active_env = Environment[env_raw.upper()]
        except KeyError:
            try:
                active_env = Environment(env_raw.lower())
            except ValueError:
                raise ValueError(f"Invalid DARAJA_ENVIRONMENT: '{env_raw}'. Must be SANDBOX or PRODUCTION.")

        return cls(
            environment=active_env,
            consumer_key=source.get("DARAJA_CONSUMER_KEY", "").strip(),
            consumer_secret=source.get("DARAJA_CONSUMER_SECRET", "").strip(),
            passkey=source.get("DARAJA_PASSKEY", "").strip(),
            shortcode=source.get("DARAJA_SHORTCODE", "").strip(),
            callback_url=source.get("DARAJA_CALLBACK_URL", "").strip(),
            enforce_ip_whitelist=source.get("DARAJA_ENFORCE_IP_WHITELIST", "true").lower() in ("true", "1", "yes"),
            api_timeout_seconds=float(source.get("DARAJA_TIMEOUT_SECONDS", "30.0")),
            max_retries=int(source.get("DARAJA_MAX_RETRIES", "3")),
            default_flat_fee=Decimal(source.get("DARAJA_DEFAULT_FLAT_FEE", "0.00")),
            default_fee_rate=Decimal(source.get("DARAJA_DEFAULT_FEE_RATE", "0.00")),
            fraud_risk_low_threshold=int(source.get("DARAJA_RISK_LOW_THRESHOLD", "30")),
            fraud_risk_medium_threshold=int(source.get("DARAJA_RISK_MEDIUM_THRESHOLD", "60")),
            fraud_risk_high_threshold=int(source.get("DARAJA_RISK_HIGH_THRESHOLD", "85")),
        )