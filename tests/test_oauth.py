"""Tests for OAuth token manager, caching, and concurrency safety."""

import concurrent.futures
from unittest.mock import MagicMock
import pytest
import requests
from src.daraja.oauth import CachedToken, OAuthTokenManager
from src.models.enums import Environment


def test_cached_token_expiry_evaluation():
    token = CachedToken(access_token="test-token", expires_at=1000.0)
    # If current time is 900 and buffer is 60 -> expires_at - buffer is 940 -> not expired
    assert token.is_expired(buffer_seconds=60) is True  # epoch 1000 is in the far past


def test_oauth_manager_initialization_errors():
    with pytest.raises(ValueError, match="consumer_key cannot be empty"):
        OAuthTokenManager("", "secret")
    with pytest.raises(ValueError, match="consumer_secret cannot be empty"):
        OAuthTokenManager("key", "   ")


def test_oauth_token_caching_behavior():
    mock_session = MagicMock(spec=requests.Session)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "cached_access_token_abc123",
        "expires_in": "3599",
    }
    mock_session.get.return_value = mock_response

    manager = OAuthTokenManager(
        consumer_key="mock_key",
        consumer_secret="mock_secret",
        environment=Environment.SANDBOX,
        session=mock_session,
    )

    # First call: hits gateway
    token_1 = manager.get_access_token()
    assert token_1 == "cached_access_token_abc123"
    assert mock_session.get.call_count == 1

    # Second call: uses in-memory cache, no HTTP call
    token_2 = manager.get_access_token()
    assert token_2 == "cached_access_token_abc123"
    assert mock_session.get.call_count == 1

    # Force refresh call: triggers second HTTP call
    token_3 = manager.get_access_token(force_refresh=True)
    assert token_3 == "cached_access_token_abc123"
    assert mock_session.get.call_count == 2


def test_oauth_concurrent_access_thread_safety():
    mock_session = MagicMock(spec=requests.Session)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "thread_safe_token_xyz",
        "expires_in": "3599",
    }
    mock_session.get.return_value = mock_response

    manager = OAuthTokenManager(
        consumer_key="key",
        consumer_secret="secret",
        session=mock_session,
    )

    # Simulate 10 simultaneous threads requesting the token
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(manager.get_access_token) for _ in range(20)]
        results = [f.result() for f in futures]

    assert all(r == "thread_safe_token_xyz" for r in results)
    # Despite 20 concurrent thread calls, only 1 actual HTTP request must be made
    assert mock_session.get.call_count == 1


def test_oauth_http_401_error_handling():
    mock_session = MagicMock(spec=requests.Session)
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_response.text = '{"errorMessage": "Invalid Credentials"}'
    mock_session.get.return_value = mock_response

    manager = OAuthTokenManager("bad_key", "bad_secret", session=mock_session)

    with pytest.raises(PermissionError, match="Daraja OAuth authentication rejected"):
        manager.get_access_token()


def test_oauth_missing_access_token_field():
    mock_session = MagicMock(spec=requests.Session)
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"status": "ok"}  # Missing access_token
    mock_session.get.return_value = mock_response

    manager = OAuthTokenManager("key", "secret", session=mock_session)

    with pytest.raises(ValueError, match="missing 'access_token' field"):
        manager.get_access_token()


def test_oauth_network_connection_error():
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = requests.ConnectionError("Connection timed out")

    manager = OAuthTokenManager("key", "secret", session=mock_session)

    with pytest.raises(ConnectionError, match="Failed to reach Daraja OAuth endpoint"):
        manager.get_access_token()
        