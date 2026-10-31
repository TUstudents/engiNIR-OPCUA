"""
The server side of one Subscription: the publishing timer, the notification queues and the retransmission queue
(OPC 10000-4 v1.05, 5.14.1).
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.common import utils
from enginir_opcua.crypto.permission_rules import User

from .address_space import AddressSpace
from .diagnostics_counters import SubscriptionCounters
from .monitored_item_service import MonitoredItemLimits, MonitoredItemService

if TYPE_CHECKING:
    from enginir_opcua.server.internal_session import PublishRequestData

    PublishResultCallback = Callable[..., Awaitable[None]]
    PublishRequestCallback = Callable[[int], PublishRequestData | None]
    DeleteCallback = Callable[[], Any]
    ExpireCallback = Callable[["InternalSubscription", ua.PublishResult], Any]

MAX_SEQUENCE_NUMBER = 4_294_967_295
_SERVE_ORDER = itertools.count()


class SubscriptionState(Enum):
    """The states of the publishing state machine (OPC 10000-4 v1.05, 5.14.1.2) a running Subscription can be in."""

    NORMAL = "normal"
    LATE = "late"
    KEEPALIVE = "keepalive"


class InternalSubscription:
    """
    One Subscription of the server.

    Runs the publishing timer, queues the notifications of its monitored items and keeps the sent
    NotificationMessages until the client acknowledges them.
    """

    def __init__(
        self,
        data: ua.CreateSubscriptionResult,
        aspace: AddressSpace,
        callback: PublishResultCallback,
        session_id: ua.NodeId,
        request_callback: PublishRequestCallback | None = None,
        delete_callback: DeleteCallback | None = None,
        expire_callback: ExpireCallback | None = None,
        no_acks_limit: int = 500,
        limits: MonitoredItemLimits | None = None,
        publishing_enabled: bool = True,
        max_notifications_per_publish: int = 10_000,
        priority: int = 0,
    ) -> None:
        """
        :param data: The revised parameters and the SubscriptionId.
        :param aspace: The address space of the server.
        :param callback: Called with each PublishResult, and with the PublishRequestData it answers.
        :param session_id: Id of the session that owns this subscription.
        :param request_callback: Returns a queued Publish request of the owning session, or None.
            If None, publishing is done without waiting for a request and no
            acknowledgement is expected (for server internal subscriptions).
        :param delete_callback: Called when the lifetime ends and no expire_callback is given.
        :param expire_callback: Called with the Bad_Timeout result when the lifetime ends.
        :param no_acks_limit: Maximum number of unacknowledged NotificationMessages kept for Republish.
        :param limits: Server limits for the monitored items.
        :param publishing_enabled: Initial PublishingEnabled flag.
        :param max_notifications_per_publish: Maximum number of notifications in one NotificationMessage.
        :param priority: Priority among the subscriptions of the session for Publish requests.
        """
        self.logger = logging.getLogger(__name__)
        self.data: ua.CreateSubscriptionResult = data
        self.pub_result_callback: PublishResultCallback = callback
        self.pub_request_callback: PublishRequestCallback | None = request_callback
        self.limits: MonitoredItemLimits = limits if limits is not None else MonitoredItemLimits()
        self.monitored_item_srv = MonitoredItemService(self, aspace)
        self.delete_callback: DeleteCallback | None = delete_callback
        self.expire_callback: ExpireCallback | None = expire_callback
        self.session_id: ua.NodeId = session_id
        self._triggered_datachanges: dict[int, list[ua.MonitoredItemNotification]] = {}
        self._triggered_events: dict[int, list[ua.EventFieldList]] = {}
        self._sequence = 1
        self._no_acks_limit = no_acks_limit
        self.max_notifications_per_publish: int = max_notifications_per_publish
        self.priority: int = priority
        self.owner_user: User | None = None
        self.owner_certificate: bytes | None = None
        self.owner_application_uri: str | None = None
        self._not_acknowledged_results: dict[int, ua.PublishResult] = {}
        self._publishing_enabled = publishing_enabled
        self.state: SubscriptionState = SubscriptionState.NORMAL
        self._message_sent = False
        self._keep_alive_counter = data.RevisedMaxKeepAliveCount
        self._lifetime_counter = data.RevisedLifetimeCount
        self.served_at = next(_SERVE_ORDER)
        self.counters = SubscriptionCounters()
        self._task: asyncio.Task[None] | None = None
        self._closing = False

    def __str__(self) -> str:
        return f"Subscription(id:{self.data.SubscriptionId})"

    async def start(self) -> None:
        """Start the publishing timer."""
        self.logger.debug("starting subscription %s", self.data.SubscriptionId)
        self._closing = False
        self._task = asyncio.create_task(self._subscription_loop())

    def update_parameters(
        self,
        interval: float,
        lifetime_count: int,
        keep_alive_count: int,
        max_notifications_per_publish: int,
        priority: int,
    ) -> None:
        """Apply the revised parameters of ModifySubscription and restart the lifetime counter."""
        self.data.RevisedPublishingInterval = interval
        self.data.RevisedLifetimeCount = lifetime_count
        self.data.RevisedMaxKeepAliveCount = keep_alive_count
        self.max_notifications_per_publish = max_notifications_per_publish
        self.priority = priority
        self.reset_lifetime()
        self._keep_alive_counter = min(self._keep_alive_counter, keep_alive_count)

    def next_sequence_number(self) -> int:
        """Return the sequence number the next NotificationMessage will get."""
        return self._sequence

    def queue_of(self, mid: int, event: bool) -> list[Any]:
        """Return the notification queue of a monitored item, creating it if needed."""
        return (self._triggered_events if event else self._triggered_datachanges).setdefault(mid, [])

    def take_queue(self, mid: int, event: bool) -> list[Any]:
        """Remove and return the notification queue of a monitored item."""
        return (self._triggered_events if event else self._triggered_datachanges).pop(mid, [])

    def has_queued_datachange(self, mid: int) -> bool:
        """Return True if a data change of the monitored item waits to be published."""
        return bool(self._triggered_datachanges.get(mid))

    def reset_lifetime(self) -> None:
        """Restart the lifetime counter (OPC 10000-4 v1.05, 5.14.1.1)."""
        self._lifetime_counter = self.data.RevisedLifetimeCount

    async def stop(self) -> None:
        """Stop the publishing timer and delete all monitored items."""
        self._closing = True
        if self._task:
            self.logger.debug("stopping internal subscription %s", self.data.SubscriptionId)
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
        self.monitored_item_srv.delete_all_monitored_items()

    async def _subscription_loop(self) -> None:
        ts = time.monotonic()
        try:
            while not self._closing:
                ts += self.data.RevisedPublishingInterval / 1000.0
                await asyncio.sleep(max(ts - time.monotonic(), 0))
                await self.timer_expired()
        except asyncio.CancelledError:
            self.logger.debug("exiting _subscription_loop for %s", self.data.SubscriptionId)
            raise
        except Exception:
            self.logger.exception("Exception in subscription loop")
            raise

    async def set_publishing_mode(self, enabled: bool) -> None:
        """Set the PublishingEnabled flag and restart the lifetime counter."""
        self.logger.debug("set publishing mode to %s for subscription %s", enabled, self.data.SubscriptionId)
        if enabled != self._publishing_enabled:
            if enabled:
                self.counters.enable_count += 1
            else:
                self.counters.disable_count += 1
        self._publishing_enabled = enabled
        self.reset_lifetime()

    def _has_data(self) -> bool:
        return self._publishing_enabled and (
            any(self._triggered_datachanges.values()) or any(self._triggered_events.values())
        )

    def _take_request(self) -> PublishRequestData | None:
        assert self.pub_request_callback is not None
        requestdata = self.pub_request_callback(self.data.SubscriptionId)
        if requestdata is None:
            if self.state is not SubscriptionState.LATE:
                self.counters.late_publish_request_count += 1
            self.state = SubscriptionState.LATE
            return None
        self.counters.publish_request_count += 1
        self.reset_lifetime()
        return requestdata

    async def timer_expired(self) -> None:
        """Run one publishing cycle: send a NotificationMessage or keep-alive if due, and count down the lifetime."""
        if self.pub_request_callback is None:
            await self._publish_in_process()
            return
        requestdata = self._on_timer()
        self._lifetime_counter -= 1
        if requestdata is not None:
            await self._send_and_flush(requestdata)
        if self._lifetime_counter <= 0 and not self._closing:
            self._expire()

    def _on_timer(self) -> PublishRequestData | None:
        if self.state is SubscriptionState.LATE:
            return None
        if self.state is SubscriptionState.NORMAL:
            if self._has_data() or not self._message_sent:
                return self._take_request()
            self.state = SubscriptionState.KEEPALIVE
            self.counters.keep_alive_entered_count += 1
            self._keep_alive_counter = self.data.RevisedMaxKeepAliveCount
        if self._has_data() or self._keep_alive_counter <= 1:
            return self._take_request()
        self._keep_alive_counter -= 1
        return None

    async def publish_results(self, requestdata: PublishRequestData) -> bool:
        """
        Answer a Publish request with the next message if the subscription is LATE.
        Returns True if the request was consumed.
        """
        if self.state is not SubscriptionState.LATE or self._closing:
            return False
        self.counters.publish_request_count += 1
        self.reset_lifetime()
        await self._send_and_flush(requestdata)
        return True

    async def _send_and_flush(self, requestdata: PublishRequestData) -> None:
        result = self._build_result(has_request=True)
        await self.pub_result_callback(result, requestdata)
        while result.MoreNotifications and not self._closing:
            next_request = self._take_request()
            if next_request is None:
                return
            result = self._build_result(has_request=True)
            await self.pub_result_callback(result, next_request)

    async def _publish_in_process(self) -> None:
        while self._has_data() and not self._closing:
            await self.pub_result_callback(self._build_result(has_request=False))

    def _expire(self) -> None:
        self.logger.warning("Subscription %s has expired, lifetime count %s", self, self.data.RevisedLifetimeCount)
        self._closing = True
        self._not_acknowledged_results.clear()
        result = ua.PublishResult()
        result.SubscriptionId = self.data.SubscriptionId
        notif = ua.StatusChangeNotification()
        notif.Status = ua.StatusCode(ua.StatusCodes.BadTimeout)
        result.NotificationMessage.NotificationData.append(notif)
        result.NotificationMessage.SequenceNumber = self._consume_sequence()
        result.NotificationMessage.PublishTime = datetime.now(UTC)
        self.monitored_item_srv.delete_all_monitored_items()
        if self.expire_callback:
            self.expire_callback(self, result)
        elif self.delete_callback:
            self.delete_callback()

    def _consume_sequence(self) -> int:
        number = self._sequence
        self._sequence = 1 if number >= MAX_SEQUENCE_NUMBER else number + 1
        return number

    def _build_result(self, has_request: bool) -> ua.PublishResult:
        result = ua.PublishResult()
        result.SubscriptionId = self.data.SubscriptionId
        message = result.NotificationMessage
        if self._has_data():
            budget = self.max_notifications_per_publish
            budget -= self._pop_triggered_datachanges(result, budget)
            self._pop_triggered_events(result, budget)
        message.PublishTime = datetime.now(UTC)
        if message.NotificationData:
            message.SequenceNumber = self._consume_sequence()
            self.state = SubscriptionState.NORMAL
            if has_request:
                self._not_acknowledged_results[message.SequenceNumber] = result
                while len(self._not_acknowledged_results) > self._no_acks_limit:
                    self.drop_oldest_unacknowledged()
        else:
            message.SequenceNumber = self._sequence
            self._keep_alive_counter = self.data.RevisedMaxKeepAliveCount
            if self.state is not SubscriptionState.NORMAL:
                self.state = SubscriptionState.KEEPALIVE
        self._message_sent = True
        self.served_at = next(_SERVE_ORDER)
        result.MoreNotifications = self._has_data()
        result.AvailableSequenceNumbers = list(self._not_acknowledged_results.keys())
        return result

    @staticmethod
    def _take(queue: dict[int, list[Any]], budget: int) -> list[Any]:
        taken: list[Any] = []
        for mid in list(queue):
            if len(taken) >= budget:
                break
            items = queue[mid]
            count = min(len(items), budget - len(taken))
            taken.extend(items[:count])
            del items[:count]
            if not items:
                del queue[mid]
        return taken

    def _pop_triggered_datachanges(self, result: ua.PublishResult, budget: int) -> int:
        items = self._take(self._triggered_datachanges, budget)
        self.counters.data_change_notifications_count += len(items)
        if items:
            notif = ua.DataChangeNotification()
            notif.MonitoredItems = items
            result.NotificationMessage.NotificationData.append(notif)
        return len(items)

    def _pop_triggered_events(self, result: ua.PublishResult, budget: int) -> None:
        items = self._take(self._triggered_events, budget)
        self.counters.event_notifications_count += len(items)
        if items:
            notif = ua.EventNotificationList()
            notif.Events = items
            result.NotificationMessage.NotificationData.append(notif)

    def acknowledge(self, sequence_number: int) -> bool:
        """Drop an acknowledged NotificationMessage; return False if the sequence number is unknown."""
        return self._not_acknowledged_results.pop(sequence_number, None) is not None

    def available_sequence_numbers(self) -> list[int]:
        """Return the sequence numbers of the NotificationMessages kept for Republish."""
        return list(self._not_acknowledged_results)

    @property
    def unacknowledged_count(self) -> int:
        """The number of NotificationMessages kept for Republish."""
        return len(self._not_acknowledged_results)

    def drop_oldest_unacknowledged(self) -> bool:
        """Drop the oldest unacknowledged NotificationMessage; return False if there is none."""
        if not self._not_acknowledged_results:
            return False
        del self._not_acknowledged_results[next(iter(self._not_acknowledged_results))]
        self.counters.discarded_message_count += 1
        return True

    def republish(self, sequence_number: int) -> ua.NotificationMessage:
        """Return a kept NotificationMessage (OPC 10000-4 v1.05, 5.14.6); raise BadMessageNotAvailable if gone."""
        self.counters.republish_request_count += 1
        result = self._not_acknowledged_results.get(sequence_number)
        if result is None:
            self.logger.debug("republish of unavailable message %s in subscription %s", sequence_number, self)
            raise utils.ServiceError(ua.StatusCodes.BadMessageNotAvailable)
        self.counters.republish_message_count += 1
        return result.NotificationMessage
