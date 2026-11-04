"""Tests for webhook event dispatcher, subscription routing, and fault isolation."""

from unittest.mock import MagicMock
import pytest

from src.models.enums import TransactionStatus
from src.webhook.dispatcher import WebhookEventDispatcher
from src.webhook.handler import NormalizedCallback


@pytest.fixture
def mock_success_callback() -> NormalizedCallback:
    return NormalizedCallback(
        merchant_request_id="MR-100",
        checkout_request_id="ws_CO_001",
        result_code=0,
        result_description="Success",
        status=TransactionStatus.COMPLETED,
        receipt_number="QA12XYZ888",
        amount=5000.0,
        phone_number="254712345678",
    )


@pytest.fixture
def mock_failed_callback() -> NormalizedCallback:
    return NormalizedCallback(
        merchant_request_id="MR-101",
        checkout_request_id="ws_CO_002",
        result_code=1032,
        result_description="Cancelled by user",
        status=TransactionStatus.FAILED,
    )


def test_subscribe_type_validation():
    dispatcher = WebhookEventDispatcher()
    with pytest.raises(TypeError, match="Subscriber handler must be a callable"):
        dispatcher.subscribe("not-a-callable")  # type: ignore


def test_dispatch_invalid_type_validation():
    dispatcher = WebhookEventDispatcher()
    with pytest.raises(TypeError, match="Expected NormalizedCallback"):
        dispatcher.dispatch({"invalid": "object"})  # type: ignore


def test_status_specific_routing(mock_success_callback, mock_failed_callback):
    dispatcher = WebhookEventDispatcher()
    success_listener = MagicMock()
    failed_listener = MagicMock()

    dispatcher.subscribe(success_listener, status=TransactionStatus.COMPLETED)
    dispatcher.subscribe(failed_listener, status=TransactionStatus.FAILED)

    # Dispatch success
    res_success = dispatcher.dispatch(mock_success_callback)
    assert res_success.handlers_invoked == 1
    assert res_success.successful_dispatches == 1
    assert success_listener.call_count == 1
    assert failed_listener.call_count == 0

    # Dispatch failure
    res_failed = dispatcher.dispatch(mock_failed_callback)
    assert res_failed.handlers_invoked == 1
    assert res_failed.successful_dispatches == 1
    assert success_listener.call_count == 1
    assert failed_listener.call_count == 1


def test_wildcard_subscriber_invoked_for_all(mock_success_callback, mock_failed_callback):
    dispatcher = WebhookEventDispatcher()
    wildcard_listener = MagicMock()

    dispatcher.subscribe(wildcard_listener, status=None)

    dispatcher.dispatch(mock_success_callback)
    dispatcher.dispatch(mock_failed_callback)

    assert wildcard_listener.call_count == 2


def test_fault_isolation_when_subscriber_crashes(mock_success_callback):
    dispatcher = WebhookEventDispatcher()

    def faulty_handler(_):
        raise RuntimeError("Database connection timed out in subscriber!")

    resilient_listener = MagicMock()

    dispatcher.subscribe(faulty_handler, status=TransactionStatus.COMPLETED)
    dispatcher.subscribe(resilient_listener, status=TransactionStatus.COMPLETED)

    # Dispatch should not raise an exception
    result = dispatcher.dispatch(mock_success_callback)

    assert result.handlers_invoked == 2
    assert result.successful_dispatches == 1
    assert result.failed_dispatches == 1
    assert len(result.errors) == 1
    assert "faulty_handler" in result.errors[0]
    # The second handler still ran successfully despite the first failing
    assert resilient_listener.call_count == 1
    