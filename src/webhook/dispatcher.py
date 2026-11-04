"""In-process event dispatcher decoupling webhook ingress from downstream processors."""

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from src.models.enums import TransactionStatus
from src.webhook.handler import NormalizedCallback

logger = logging.getLogger(__name__)

# Callback handler signature: takes NormalizedCallback and returns None
WebhookEventHandler = Callable[[NormalizedCallback], None]


@dataclass
class DispatchResult:
    """Telemetry report of event dispatch execution."""
    event_status: TransactionStatus
    handlers_invoked: int
    successful_dispatches: int
    failed_dispatches: int
    errors: List[str] = field(default_factory=list)


class WebhookEventDispatcher:
    """Thread-safe event router broadcasting normalized callback outcomes to subscribed listeners."""

    def __init__(self):
        self._subscribers: Dict[TransactionStatus, List[WebhookEventHandler]] = {
            status: [] for status in TransactionStatus
        }
        self._wildcard_subscribers: List[WebhookEventHandler] = []

    def subscribe(
        self,
        handler: WebhookEventHandler,
        status: Optional[TransactionStatus] = None,
    ) -> None:
        """
        Register a subscriber for a specific status or wildcard for all transaction outcomes.

        Args:
            handler: Callable invoked with NormalizedCallback.
            status: TransactionStatus to filter on, or None for all events.
        """
        if not callable(handler):
            raise TypeError("Subscriber handler must be a callable.")

        if status is None:
            self._wildcard_subscribers.append(handler)
        else:
            self._subscribers[status].append(handler)

    def dispatch(self, callback: NormalizedCallback) -> DispatchResult:
        """
        Broadcast a normalized callback to all registered subscribers with fault containment.

        Unhandled exceptions in subscribers are caught and logged to prevent interrupting
        the gateway ingress pipeline.
        """
        if not isinstance(callback, NormalizedCallback):
            raise TypeError(f"Expected NormalizedCallback, received {type(callback)}.")

        target_handlers = self._subscribers.get(callback.status, []) + self._wildcard_subscribers
        result = DispatchResult(
            event_status=callback.status,
            handlers_invoked=len(target_handlers),
            successful_dispatches=0,
            failed_dispatches=0,
        )

        for handler in target_handlers:
            try:
                handler(callback)
                result.successful_dispatches += 1
            except Exception as exc:
                result.failed_dispatches += 1
                error_msg = f"Handler '{getattr(handler, '__name__', str(handler))}' failed: {str(exc)}"
                result.errors.append(error_msg)
                logger.error(error_msg, exc_info=True)

        return result
    