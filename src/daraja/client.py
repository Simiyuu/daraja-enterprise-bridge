"""Client for dispatching Lipa Na M-Pesa Online (STK Push) payment prompts."""

from typing import Optional, Union
import requests

from src.daraja.crypto import generate_stk_password
from src.daraja.oauth import OAuthTokenManager
from src.models.contracts import STKPushRequest, STKPushResponse
from src.models.enums import Environment, TransactionType


class DarajaClient:
    """Enterprise client for initiating Daraja transactions against Safaricom gateways."""

    STK_PUSH_PATHS = {
        Environment.SANDBOX: "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        Environment.PRODUCTION: "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
    }

    def __init__(
        self,
        consumer_key: str,
        consumer_secret: str,
        passkey: str,
        business_short_code: str,
        environment: Environment = Environment.SANDBOX,
        session: Optional[requests.Session] = None,
        token_manager: Optional[OAuthTokenManager] = None,
    ):
        if not passkey or not passkey.strip():
            raise ValueError("passkey cannot be empty.")
        if not business_short_code or not business_short_code.strip():
            raise ValueError("business_short_code cannot be empty.")

        self.passkey = passkey.strip()
        self.business_short_code = business_short_code.strip()
        self.environment = environment
        self.session = session or requests.Session()

        self.token_manager = token_manager or OAuthTokenManager(
            consumer_key=consumer_key,
            consumer_secret=consumer_secret,
            environment=self.environment,
            session=self.session,
        )

    @property
    def stk_endpoint(self) -> str:
        return self.STK_PUSH_PATHS.get(
            self.environment,
            self.STK_PUSH_PATHS[Environment.SANDBOX],
        )

    def initiate_stk_push(
        self,
        phone_number: str,
        amount: int,
        account_reference: str,
        transaction_desc: str,
        callback_url: str,
        party_b: Optional[str] = None,
        transaction_type: TransactionType = TransactionType.CUSTOMER_PAYBILL_ONLINE,
        timeout: int = 20,
    ) -> STKPushResponse:
        """
        Synthesize dynamic credentials and dispatch an STK Push payment prompt to a subscriber.

        Returns:
            STKPushResponse: Validated gateway acceptance details with CheckoutRequestID.
        """
        # 1. Compile dynamic Base64 password and UTC timestamp
        password, timestamp = generate_stk_password(
            business_short_code=self.business_short_code,
            passkey=self.passkey,
        )

        target_party_b = party_b or self.business_short_code

        # 2. Build and validate request data contract
        request_data = STKPushRequest(
            BusinessShortCode=self.business_short_code,
            Password=password,
            Timestamp=timestamp,
            TransactionType=transaction_type,
            Amount=amount,
            PartyA=phone_number,
            PartyB=target_party_b,
            PhoneNumber=phone_number,
            CallBackURL=callback_url,
            AccountReference=account_reference,
            TransactionDesc=transaction_desc,
        )

        # 3. Retrieve valid cached Bearer token
        access_token = self.token_manager.get_access_token()

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        # 4. Dispatch request
        try:
            response = self.session.post(
                self.stk_endpoint,
                headers=headers,
                json=request_data.model_dump(by_alias=True),
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise ConnectionError(f"Failed to connect to Daraja STK endpoint: {exc}") from exc

        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"Daraja STK push failed with status {response.status_code}: {response.text}"
            )

        # 5. Parse and return typed response
        response_json = response.json()
        return STKPushResponse(**response_json)
    