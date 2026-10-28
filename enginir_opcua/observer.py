"""
Hooks with which an application watches what a client does.

See ``docs/usage/common/observer.rst``. An application subclasses :class:`Observer`, overrides the hooks it needs and
gives an instance to the client (``Client(url, observer=...)``). Hooks run on the event loop of the client, so they
must be fast and must not block; an exception in a hook is logged and ignored.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager, nullcontext
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from enginir_opcua.client.ua_client import UaClientState

_logger = logging.getLogger(__name__)


class SubscriptionEvent(str, Enum):
    """What happened to a Subscription: it was created, recreated after the server lost it, or deleted."""

    CREATED = "created"
    RECREATED = "recreated"
    DELETED = "deleted"


class Observer:
    """
    Base class of observers. Every hook does nothing; override the ones you need. Hooks get names, counts and ids,
    never values or credentials.
    """

    def observe_request(self, request: Any) -> AbstractContextManager[None]:
        """Times a request and calls :meth:`on_request`; override :meth:`on_request` instead of this."""
        return self._time_request(type(request).__name__)

    @contextmanager
    def _time_request(self, request_type: str) -> Iterator[None]:
        started = time.monotonic()
        error: BaseException | None = None
        try:
            yield
        except BaseException as exc:
            error = exc
            raise
        finally:
            try:
                self.on_request(request_type, time.monotonic() - started, error)
            except Exception:
                _logger.exception("observer on_request raised")

    def on_request(self, request_type: str, duration: float, error: BaseException | None) -> None:
        """
        A request has finished. ``request_type`` is the class name of the request, ``duration`` is in seconds and
        includes the wait for a free request slot (and, for Publish, the time the server kept the request), ``error``
        is the exception that ended it, or None.
        """

    def on_state_change(self, state: UaClientState) -> None:
        """The connection state of the client changed to ``state``; each change is reported once, in order."""

    def on_subscription_event(self, subscription_id: int | None, event: SubscriptionEvent) -> None:
        """A Subscription was created, recreated (with a new id) or deleted."""

    def on_notification(self, subscription_id: int | None, event_count: int) -> None:
        """A message was processed; ``event_count`` events were passed on, 0 for a keep-alive."""

    def on_messages_dropped(self, subscription_id: int | None, count: int) -> None:
        """The client dropped ``count`` messages or events because the application was too slow or had no handler."""

    def on_messages_lost(self, subscription_id: int | None, count: int) -> None:
        """``count`` messages are missing and could not be fetched again; data was lost between server and client."""


class _NullObserver(Observer):
    def observe_request(self, request: Any) -> AbstractContextManager[None]:
        return nullcontext()


NULL_OBSERVER: Observer = _NullObserver()
