"""Building blocks for in-process tests of the monitored item services."""

from __future__ import annotations

from typing import Any

from enginir_opcua import Server, ua
from enginir_opcua.server.internal_subscription import InternalSubscription

SESSION = ua.NodeId(1, 1)
SLOW = 3_600_000.0


class Wire:
    def __init__(self) -> None:
        self.results: list[ua.PublishResult] = []

    async def send(self, result: ua.PublishResult, _request: Any = None) -> None:
        self.results.append(result)

    def data(self) -> list[Any]:
        found: list[Any] = []
        for result in self.results:
            for notification in result.NotificationMessage.NotificationData:
                if isinstance(notification, ua.DataChangeNotification):
                    found.extend(notification.MonitoredItems)
                elif isinstance(notification, ua.EventNotificationList):
                    found.extend(notification.Events)
        return found

    def clear(self) -> None:
        self.results.clear()


async def make_server() -> Server:
    server = Server()
    await server.init()
    return server


async def open_subscription(server: Server, interval: float = SLOW) -> tuple[InternalSubscription, Wire]:
    wire = Wire()
    params = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=interval,
        RequestedLifetimeCount=30_000,
        RequestedMaxKeepAliveCount=10_000,
        PublishingEnabled=True,
    )
    created = await server.iserver.subscription_service.create_subscription(params, wire.send, SESSION)
    return server.iserver.subscription_service.subscriptions[created.SubscriptionId], wire


def item_request(
    nodeid: ua.NodeId,
    attribute: ua.AttributeIds = ua.AttributeIds.Value,
    mode: ua.MonitoringMode = ua.MonitoringMode.Reporting,
    sampling: float = -1.0,
    queue: int = 1,
    discard_oldest: bool = True,
    handle: int = 1,
    filter: Any = None,
) -> ua.MonitoredItemCreateRequest:
    return ua.MonitoredItemCreateRequest(
        ItemToMonitor=ua.ReadValueId(NodeId=nodeid, AttributeId=attribute),
        MonitoringMode=mode,
        RequestedParameters=ua.MonitoringParameters(
            ClientHandle=handle, SamplingInterval=sampling, Filter=filter, QueueSize=queue, DiscardOldest=discard_oldest
        ),
    )


async def create_items(
    server: Server,
    sub: InternalSubscription,
    *requests: ua.MonitoredItemCreateRequest,
    timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both,
) -> list[ua.MonitoredItemCreateResult]:
    params = ua.CreateMonitoredItemsParameters(
        SubscriptionId=sub.data.SubscriptionId, TimestampsToReturn=timestamps, ItemsToCreate=list(requests)
    )
    return await server.iserver.subscription_service.create_monitored_items(params, SESSION)


def modify_items(
    server: Server,
    sub: InternalSubscription,
    *changes: tuple[int, ua.MonitoringParameters],
    timestamps: ua.TimestampsToReturn = ua.TimestampsToReturn.Both,
) -> list[ua.MonitoredItemModifyResult]:
    params = ua.ModifyMonitoredItemsParameters(
        SubscriptionId=sub.data.SubscriptionId,
        TimestampsToReturn=timestamps,
        ItemsToModify=[ua.MonitoredItemModifyRequest(MonitoredItemId=mid, RequestedParameters=p) for mid, p in changes],
    )
    return server.iserver.subscription_service.modify_monitored_items(params, SESSION)


async def publish(sub: InternalSubscription, wire: Wire) -> list[Any]:
    wire.clear()
    await sub.timer_expired()
    return wire.data()
