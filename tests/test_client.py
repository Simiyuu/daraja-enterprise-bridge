"""Unit tests for the DarajaClient STK push dispatcher."""

from unittest.mock import MagicMock
import pytest
import requests

from src.daraja.client import DarajaClient
from src.daraja.oauth import OAuthTokenManager
from src.models.contracts import STKPushResponse
from src.models.enums import Environment, TransactionType


@pytest.fixture
def mock_token_manager():
    manager = MagicMock(spec=OAuthTokenManager)
    manager.get_access_token.return_value = "mocked-valid-bearer-token"
    return manager


@pytest.fixture
def mock_session():
    return MagicMock(spec=requests.Session)


def test_daraja_client_initialization_validation():
    with pytest.raises(ValueError, match="passkey cannot be empty"):
        DarajaClient("key", "secret", passkey="", business_short_code="174379")

    with pytest.raises(ValueError, match="business_short_code cannot be empty"):
        DarajaClient("key", "secret", passkey="pass", business_short_code="   ")


def test_initiate_stk_push_success(mock_token_manager, mock_session):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "MerchantRequestID": "MR-100293",
        "CheckoutRequestID": "ws_CO_04112026190000001",
        "ResponseCode": "0",
        "ResponseDescription": "Success. Request accepted for processing",
        "CustomerMessage": "Success. Request accepted for processing",
    }
    mock_session.post.return_value = mock_response

    client = DarajaClient(
        consumer_key="mock_key",
        consumer_secret="mock_secret",
        passkey="mock_passkey",
        business_short_code="174379",
        environment=Environment.SANDBOX,
        session=mock_session,
        token_manager=mock_token_manager,
    )

    result = client.initiate_stk_push(
        phone_number="0712345678",
        amount=1500,
        account_reference="ORDER-99",
        transaction_desc="Payment for goods",
        callback_url="https://api.merchant.com/v1/callbacks",
    )

    assert isinstance(result, STKPushResponse)
    assert result.is_successful is True
    assert result.checkout_request_id == "ws_CO_04112026190000001"
    assert result.merchant_request_id == "MR-100293"

    # Verify headers and payload structure dispatched
    call_args = mock_session.post.call_args
    _, kwargs = call_args
    assert kwargs["headers"]["Authorization"] == "Bearer mocked-valid-bearer-token"
    assert kwargs["json"]["BusinessShortCode"] == "174379"
    assert kwargs["json"]["PhoneNumber"] == "254712345678"
    assert kwargs["json"]["Amount"] == 1500


def test_initiate_stk_push_http_failure(mock_token_manager, mock_session):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.text = '{"errorMessage": "Internal Server Error"}'
    mock_session.post.return_value = mock_response

    client = DarajaClient(
        consumer_key="key",
        consumer_secret="secret",
        passkey="passkey",
        business_short_code="174379",
        session=mock_session,
        token_manager=mock_token_manager,
    )

    with pytest.raises(RuntimeError, match="Daraja STK push failed with status 500"):
        client.initiate_stk_push(
            phone_number="0712345678",
            amount=500,
            account_reference="REF1",
            transaction_desc="Test",
            callback_url="https://api.test.com/cb",
        )


def test_initiate_stk_push_network_exception(mock_token_manager, mock_session):
    mock_session.post.side_effect = requests.exceptions.Timeout("Connection timeout")

    client = DarajaClient(
        consumer_key="key",
        consumer_secret="secret",
        passkey="passkey",
        business_short_code="174379",
        session=mock_session,
        token_manager=mock_token_manager,
    )

    with pytest.raises(ConnectionError, match="Failed to connect to Daraja STK endpoint"):
        client.initiate_stk_push(
            phone_number="0712345678",
            amount=500,
            account_reference="REF1",
            transaction_desc="Test",
            callback_url="https://api.test.com/cb",
        )
        