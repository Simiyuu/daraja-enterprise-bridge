"""Thread-safe OAuth 2.0 token authority with in-memory caching for Safaricom Daraja API."""

import base64
import threading
import time
from dataclasses import dataclass
from typing import Optional
import requests

from src.models.enums import Environment


@dataclass(frozen=True)
class CachedToken:
    access_token: str
    expires_at: float

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """Return True if the token has expired or will expire within the buffer window."""
        return time.time() >= (self.expires_at - buffer_seconds)


class OAuthTokenManager:
    """Thread-safe manager for generating and caching Daraja OAuth 2.0 bearer tokens."""

    BASE_URLS = {
        Environment.SANDBOX: "https://sandbox.safaricom.co.ke",
        Environment.PRODUCTION: "https://api.safaricom.co.ke",
    }
    AUTH_PATH = "/oauth/v1/generate?grant_type=client_credentials"

    def __init__(
        self,
        consumer_key: str,
        consumer_secret: str,
        environment: Environment = Environment.SANDBOX,
        session: Optional[requests.Session] = None,
        expiry_buffer_seconds: int = 60,
    ):
        if not consumer_key or not consumer_key.strip():
            raise ValueError("consumer_key cannot be empty.")
        if not consumer_secret or not consumer_secret.strip():
            raise ValueError("consumer_secret cannot be empty.")

        self.consumer_key = consumer_key.strip()
        self.consumer_secret = consumer_secret.strip()
        self.environment = environment
        self.session = session or requests.Session()
        self.expiry_buffer_seconds = expiry_buffer_seconds

        self._cached_token: Optional[CachedToken] = None
        self._lock = threading.Lock()

    @property
    def auth_url(self) -> str:
        base = self.BASE_URLS.get(self.environment, self.BASE_URLS[Environment.SANDBOX])
        return f"{base}{self.AUTH_PATH}"

    def _build_basic_auth_header(self) -> str:
        credentials = f"{self.consumer_key}:{self.consumer_secret}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        return f"Basic {encoded}"

    def get_access_token(self, force_refresh: bool = False) -> str:
        """
        Retrieve an active access token.

        Reuses the valid in-memory cached token if present and not within the expiry buffer.
        Acquires a thread lock if an HTTP token fetch is necessary.
        """
        # Fast read check without locking
        current = self._cached_token
        if not force_refresh and current and not current.is_expired(self.expiry_buffer_seconds):
            return current.access_token

        with self._lock:
            # Double-checked locking pattern
            if (
                not force_refresh
                and self._cached_token
                and not self._cached_token.is_expired(self.expiry_buffer_seconds)
            ):
                return self._cached_token.access_token

            token, expires_in = self._fetch_token_from_gateway()
            expires_at = time.time() + expires_in
            self._cached_token = CachedToken(access_token=token, expires_at=expires_at)
            return self._cached_token.access_token

    def _fetch_token_from_gateway(self) -> tuple[str, int]:
        """Execute HTTP call to Daraja OAuth endpoint to exchange client credentials."""
        headers = {
            "Authorization": self._build_basic_auth_header(),
            "Accept": "application/json",
        }

        try:
            response = self.session.get(self.auth_url, headers=headers, timeout=15)
        except requests.RequestException as exc:
            raise ConnectionError(f"Failed to reach Daraja OAuth endpoint: {exc}") from exc

        if response.status_code != 200:
            raise PermissionError(
                f"Daraja OAuth authentication rejected [HTTP {response.status_code}]: {response.text}"
            )

        data = response.json()
        access_token = data.get("access_token")
        expires_in = data.get("expires_in", 3599)

        if not access_token:
            raise ValueError(f"Daraja OAuth response missing 'access_token' field: {data}")

        try:
            expires_in_int = int(expires_in)
        except (ValueError, TypeError):
            expires_in_int = 3599

        return access_token, expires_in_int
    