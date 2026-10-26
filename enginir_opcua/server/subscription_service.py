"""
server side implementation of subscription service
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from enginir_opcua import ua
from enginir_opcua.common import uamethod, utils
from enginir_opcua.crypto.permission_rules import User

from .address_space import AddressSpace
from .internal_subscription import InternalSubscription, SubscriptionState

if TYPE_CHECKING:
    from .internal_server import InternalServer
    from .internal_session import Session
    from .uaprocessor import PublishRequestData


def same_owner(owner_user: User | None, owner_certificate: bytes | None, user: User, certificate: bytes | None) -> bool:
    if owner_user is None:
        return False
    if owner_user.name is not None:
        return user.name == owner_user.name
    return user.name is None and owner_certificate is not None and certificate == owner_certificate


class SubscriptionService:
    """
    Manages subscriptions on the server side.
    There is one `SubscriptionService` instance for every `Server`/`InternalServer`.
    """

    def __init__(self, aspace: AddressSpace, iserver: "InternalServer | None" = None) -> None:
        self.logger = logging.getLogger(__name__)
        self.aspace: AddressSpace = aspace
        self.iserver: "InternalServer | None" = iserver
        self.subscriptions: dict[int, InternalSubscription] = {}
        self._sub_id_counter = 77
        self.standard_events: dict[int, Any] = {}
        self._conditions: dict[ua.NodeId, Any] = {}
        self._background: set[asyncio.Task[None]] = set()
        self._pending_notices: dict[ua.NodeId, list[tuple[ua.PublishResult, Callable[..., Any]]]] = {}

    async def create_subscription(
        self,
        params: ua.CreateSubscriptionParameters,
        callback: Callable[..., Any],
        session_id: ua.NodeId,
        request_callback: Callable[..., Any] | None = None,
    ) -> ua.CreateSubscriptionResult:
        self.logger.info("create subscription")
        max_subs = self.iserver.max_subscriptions if self.iserver else 1_000
        if len(self.subscriptions) >= max_subs:
            self.logger.warning("Refusing subscription: at max_subscriptions=%s", max_subs)
            raise utils.ServiceError(ua.StatusCodes.BadTooManySubscriptions)
        self._check_session_limit(session_id)
        result = ua.CreateSubscriptionResult()
        (
            result.RevisedPublishingInterval,
            result.RevisedLifetimeCount,
            result.RevisedMaxKeepAliveCount,
        ) = self._revise(
            params.RequestedPublishingInterval, params.RequestedLifetimeCount, params.RequestedMaxKeepAliveCount
        )
        self._sub_id_counter += 1
        result.SubscriptionId = self._sub_id_counter
        no_acks_limit = self.iserver.max_unacked_messages_per_subscription if self.iserver else 5000
        max_queue_size = self.iserver.max_monitored_item_queue_size if self.iserver else 10_000
        internal_sub = InternalSubscription(
            result,
            self.aspace,
            callback,
            session_id,
            request_callback=request_callback,
            delete_callback=lambda: self.subscriptions.pop(result.SubscriptionId, None),
            expire_callback=self._on_expired if request_callback is not None else None,
            no_acks_limit=no_acks_limit,
            max_queue_size=max_queue_size,
            publishing_enabled=params.PublishingEnabled,
            max_notifications_per_publish=self._revise_max_notifications(params.MaxNotificationsPerPublish),
            priority=params.Priority,
        )
        await internal_sub.start()
        owner = self._session(session_id)
        if owner is not None:
            internal_sub.owner_user, internal_sub.owner_certificate = owner.user, owner.client_certificate
        self.subscriptions[result.SubscriptionId] = internal_sub
        return result

    def _owned_count(self, session_id: ua.NodeId) -> int:
        return sum(1 for sub in self.subscriptions.values() if sub.session_id == session_id)

    def _at_session_limit(self, session_id: ua.NodeId) -> bool:
        if self.iserver is None or self.iserver.session_manager.session_by_id(session_id) is None:
            return False
        return self._owned_count(session_id) >= self.iserver.max_subscriptions_per_session

    def _check_session_limit(self, session_id: ua.NodeId) -> None:
        if self._at_session_limit(session_id):
            self.logger.warning("Refusing subscription: session at max_subscriptions_per_session")
            raise utils.ServiceError(ua.StatusCodes.BadTooManySubscriptions)

    def _setting(self, name: str, default: float) -> float:
        return getattr(self.iserver, name, default) if self.iserver else default

    def _revise_max_notifications(self, requested: int) -> int:
        cap = int(self._setting("max_notifications_per_publish", 10_000))
        return min(requested, cap) if requested > 0 else cap

    def _revise(self, interval: float, lifetime: int, keep_alive: int) -> tuple[float, int, int]:
        minimum = self._setting("min_publishing_interval_ms", 50.0)
        maximum = self._setting("max_publishing_interval_ms", 3_600_000.0)
        if interval != interval or interval <= 0:
            interval = minimum
        interval = min(max(interval, minimum), maximum)
        keep_alive = min(max(keep_alive, 1), int(self._setting("max_keep_alive_count", 5_000)))
        lifetime = min(lifetime, int(self._setting("max_lifetime_count", 15_000)))
        lifetime = max(lifetime, 3 * keep_alive)
        limit = int(self._setting("max_subscription_lifetime_ms", 86_400_000.0) // interval)
        if lifetime > limit:
            keep_alive = min(keep_alive, max(1, limit // 3))
            lifetime = max(limit, 3 * keep_alive)
        return interval, lifetime, keep_alive

    def _owned(self, subscription_id: int, session_id: ua.NodeId) -> InternalSubscription | None:
        sub = self.subscriptions.get(subscription_id)
        if sub is None or sub.session_id != session_id:
            return None
        return sub

    def _owned_or_raise(self, subscription_id: int, session_id: ua.NodeId) -> InternalSubscription:
        sub = self._owned(subscription_id, session_id)
        if sub is None:
            raise utils.ServiceError(ua.StatusCodes.BadSubscriptionIdInvalid)
        sub.reset_lifetime()
        return sub

    def _hold_notice(self, session_id: ua.NodeId, notice: ua.PublishResult, callback: Callable[..., Any]) -> None:
        pending = self._pending_notices.setdefault(session_id, [])
        if len(pending) >= int(self._setting("max_subscriptions_per_session", 100)):
            pending.pop(0)
        pending.append((notice, callback))

    def has_pending_notice(self, session_id: ua.NodeId) -> bool:
        return bool(self._pending_notices.get(session_id))

    def _on_expired(self, sub: InternalSubscription, notice: ua.PublishResult) -> None:
        self.subscriptions.pop(sub.data.SubscriptionId, None)
        self._hold_notice(sub.session_id, notice, sub.pub_result_callback)
        session = self._session(sub.session_id)
        if session is not None:
            task = asyncio.get_running_loop().create_task(session.settle_publish_queue())
            self._background.add(task)
            task.add_done_callback(self._background.discard)

    def pending_notice(self, session_id: ua.NodeId) -> tuple[ua.PublishResult, Callable[..., Any]] | None:
        pending = self._pending_notices.get(session_id)
        if not pending:
            return None
        notice = pending.pop(0)
        if not pending:
            del self._pending_notices[session_id]
        return notice

    def drop_pending_notices(self, session_id: ua.NodeId) -> None:
        self._pending_notices.pop(session_id, None)

    async def on_publish_request(self, session_id: ua.NodeId, requestdata: "PublishRequestData") -> bool:
        notice = self.pending_notice(session_id)
        if notice is not None:
            result, callback = notice
            await callback(result, requestdata)
            return True
        late = [
            sub
            for sub in self.subscriptions.values()
            if sub.session_id == session_id and sub.state is SubscriptionState.LATE
        ]
        late.sort(key=lambda sub: (-sub.priority, sub.served_at))
        for sub in late:
            if await sub.publish_results(requestdata):
                return True
        return False

    def modify_subscription(
        self, params: ua.ModifySubscriptionParameters, session_id: ua.NodeId
    ) -> ua.ModifySubscriptionResult:
        self.logger.info("modify subscription")
        sub = self._owned_or_raise(params.SubscriptionId, session_id)
        result = ua.ModifySubscriptionResult()
        result.RevisedPublishingInterval, result.RevisedLifetimeCount, result.RevisedMaxKeepAliveCount = self._revise(
            params.RequestedPublishingInterval, params.RequestedLifetimeCount, params.RequestedMaxKeepAliveCount
        )
        sub.update_parameters(
            result.RevisedPublishingInterval,
            result.RevisedLifetimeCount,
            result.RevisedMaxKeepAliveCount,
            self._revise_max_notifications(params.MaxNotificationsPerPublish),
            params.Priority,
        )
        return result

    async def delete_subscriptions(self, ids: list[int], session_id: ua.NodeId) -> list[ua.StatusCode]:
        self.logger.info("delete subscriptions: %s", ids)
        res: list[ua.StatusCode] = []
        existing_subs: list[InternalSubscription] = []
        for i in ids:
            sub = self._owned(i, session_id)
            if sub is None:
                res.append(ua.StatusCode(ua.StatusCodes.BadSubscriptionIdInvalid))
            else:
                del self.subscriptions[i]
                existing_subs.append(sub)
                res.append(ua.StatusCode())
        stop_results = await asyncio.gather(*[sub.stop() for sub in existing_subs], return_exceptions=True)
        for stop_result in stop_results:
            if isinstance(stop_result, Exception):
                self.logger.warning("Exception while stopping subscription", exc_info=stop_result)
        return res

    def publish(
        self, acks: Iterable[ua.SubscriptionAcknowledgement], session_id: ua.NodeId
    ) -> tuple[int, list[ua.StatusCode]]:
        self.logger.info("publish request with acks %s", acks)
        owned = [sub for sub in self.subscriptions.values() if sub.session_id == session_id]
        if not owned and not self.has_pending_notice(session_id):
            raise utils.ServiceError(ua.StatusCodes.BadNoSubscription)
        results: list[ua.StatusCode] = []
        for ack in acks:
            sub = self._owned(ack.SubscriptionId, session_id)
            if sub is None:
                results.append(ua.StatusCode(ua.StatusCodes.BadSubscriptionIdInvalid))
            else:
                known = sub.acknowledge(ack.SequenceNumber)
                code = ua.StatusCodes.Good if known else ua.StatusCodes.BadSequenceNumberUnknown
                results.append(ua.StatusCode(code))
        return len(owned), results

    async def create_monitored_items(
        self, params: ua.CreateMonitoredItemsParameters, session_id: ua.NodeId
    ) -> list[ua.MonitoredItemCreateResult]:
        self.logger.info("create monitored items")
        sub = self._owned_or_raise(params.SubscriptionId, session_id)
        return await sub.monitored_item_srv.create_monitored_items(params)

    def modify_monitored_items(
        self, params: ua.ModifyMonitoredItemsParameters, session_id: ua.NodeId
    ) -> list[ua.MonitoredItemModifyResult]:
        self.logger.info("modify monitored items")
        sub = self._owned_or_raise(params.SubscriptionId, session_id)
        return sub.monitored_item_srv.modify_monitored_items(params)

    async def set_publishing_mode(
        self, params: ua.SetPublishingModeParameters, session_id: ua.NodeId
    ) -> list[ua.StatusCode]:
        self.logger.info("set publishing mode")
        results: list[ua.StatusCode] = []
        for sid in params.SubscriptionIds:
            sub = self._owned(sid, session_id)
            if sub is None:
                results.append(ua.StatusCode(ua.StatusCodes.BadSubscriptionIdInvalid))
            else:
                await sub.set_publishing_mode(params.PublishingEnabled)
                results.append(ua.StatusCode())
        return results

    async def set_monitoring_mode(
        self, params: ua.SetMonitoringModeParameters, session_id: ua.NodeId
    ) -> list[ua.StatusCode]:
        self.logger.info("set monitoring mode")
        sub = self._owned_or_raise(params.SubscriptionId, session_id)
        return await sub.monitored_item_srv.set_monitoring_mode(params.MonitoringMode, params.MonitoredItemIds)

    def delete_monitored_items(
        self, params: ua.DeleteMonitoredItemsParameters, session_id: ua.NodeId
    ) -> list[ua.StatusCode]:
        self.logger.info("delete monitored items")
        sub = self._owned_or_raise(params.SubscriptionId, session_id)
        return sub.monitored_item_srv.delete_monitored_items(params.MonitoredItemIds)

    def republish(self, params: ua.RepublishParameters, session_id: ua.NodeId) -> ua.NotificationMessage:
        sub = self._owned_or_raise(params.SubscriptionId, session_id)
        return sub.republish(params.RetransmitSequenceNumber)

    async def transfer_subscriptions(
        self,
        params: ua.TransferSubscriptionsParameters,
        session_id: ua.NodeId,
        callback: Callable[..., Any],
        request_callback: Callable[..., Any] | None = None,
    ) -> list[ua.TransferResult]:
        self.logger.info("transfer_subscriptions: %s", params.SubscriptionIds)
        results: list[ua.TransferResult] = []
        previous_owners: list[ua.NodeId] = []
        for sub_id in params.SubscriptionIds:
            result = ua.TransferResult()
            sub = self.subscriptions.get(int(sub_id))
            if sub is None:
                result.StatusCode = ua.StatusCode(ua.StatusCodes.BadSubscriptionIdInvalid)
            elif sub.session_id == session_id:
                result.StatusCode = ua.StatusCode(ua.StatusCodes.BadNothingToDo)
            elif not self._may_take_over(sub, session_id):
                result.StatusCode = ua.StatusCode(ua.StatusCodes.BadUserAccessDenied)
            elif self._at_session_limit(session_id):
                result.StatusCode = ua.StatusCode(ua.StatusCodes.BadTooManySubscriptions)
            else:
                previous_owners.append(sub.session_id)
                await self._move(sub, session_id, callback, request_callback, params.SendInitialValues)
                result.AvailableSequenceNumbers = sorted(sub.available_sequence_numbers())
            results.append(result)
        for owner_id in dict.fromkeys(previous_owners):
            old = self._session(owner_id)
            if old is not None:
                await old.settle_publish_queue()
        return results

    def _session(self, session_id: ua.NodeId) -> "Session | None":
        return self.iserver.session_manager.session_by_id(session_id) if self.iserver else None

    def _may_take_over(self, sub: InternalSubscription, session_id: ua.NodeId) -> bool:
        caller = self._session(session_id)
        if caller is None:
            return False
        return same_owner(sub.owner_user, sub.owner_certificate, caller.user, caller.client_certificate)

    async def _move(
        self,
        sub: InternalSubscription,
        session_id: ua.NodeId,
        callback: Callable[..., Any],
        request_callback: Callable[..., Any] | None,
        send_initial_values: bool,
    ) -> None:
        previous_id, previous_callback = sub.session_id, sub.pub_result_callback
        caller = self._session(session_id)
        sub.session_id = session_id
        sub.pub_result_callback = callback
        sub.pub_request_callback = request_callback
        if caller is not None:
            sub.owner_user, sub.owner_certificate = caller.user, caller.client_certificate
        sub.reset_lifetime()
        if sub.state is SubscriptionState.LATE:
            sub.state = SubscriptionState.NORMAL
        if self._session(previous_id) is not None:
            self._hold_notice(previous_id, self._transferred_notice(sub), previous_callback)
        if send_initial_values:
            await sub.monitored_item_srv.resend_initial_values()

    @staticmethod
    def _transferred_notice(sub: InternalSubscription) -> ua.PublishResult:
        notice = ua.PublishResult()
        notice.SubscriptionId = sub.data.SubscriptionId
        notification = ua.StatusChangeNotification()
        notification.Status = ua.StatusCode(ua.StatusCodes.GoodSubscriptionTransferred)
        notice.NotificationMessage.NotificationData.append(notification)
        notice.NotificationMessage.SequenceNumber = sub.next_sequence_number()
        return notice

    async def trigger_event(self, event: Any, subscription_id: int | None = None) -> None:
        if hasattr(event, "Retain") and hasattr(event, "NodeId"):
            if event.Retain:
                self._conditions[event.NodeId] = event
            elif event.NodeId in self._conditions:
                del self._conditions[event.NodeId]
        if subscription_id is not None:
            if subscription_id in self.subscriptions:
                await self.subscriptions[subscription_id].monitored_item_srv.trigger_event(event)
        else:
            for sub in self.subscriptions.values():
                await sub.monitored_item_srv.trigger_event(event)

    @uamethod
    async def condition_refresh(
        self, parent: Any, subscription_id: int, mid: int | None = None
    ) -> ua.StatusCode | None:
        if subscription_id not in self.subscriptions:
            return ua.StatusCode(ua.StatusCodes.BadSubscriptionIdInvalid)
        sub = self.subscriptions[subscription_id]
        if mid is not None and mid not in sub.monitored_item_srv._monitored_items:
            return ua.StatusCode(ua.StatusCodes.BadMonitoredItemIdInvalid)
        if ua.ObjectIds.RefreshStartEventType in self.standard_events:
            await self.standard_events[ua.ObjectIds.RefreshStartEventType].trigger(subscription_id=subscription_id)
        for event in self._conditions.values():
            await sub.monitored_item_srv.trigger_event(event, mid)
        if ua.ObjectIds.RefreshEndEventType in self.standard_events:
            await self.standard_events[ua.ObjectIds.RefreshEndEventType].trigger(subscription_id=subscription_id)
        return None  # FIXME: really not sure this is correct, but this is the original behaviour
