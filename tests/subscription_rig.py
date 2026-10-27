"""A scripted session for unit tests of the client Subscription."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from enginir_opcua import ua
from enginir_opcua.observer import NULL_OBSERVER, Observer
from enginir_opcua.ua.uaerrors import BadMessageNotAvailable


class FakeSession:
    def __init__(self) -> None:
        self.observer: Observer = NULL_OBSERVER
        self.next_id = 1
        self.revise: Callable[[ua.CreateSubscriptionParameters], ua.CreateSubscriptionResult] | None = None
        self.created: list[ua.CreateSubscriptionParameters] = []
        self.modified: list[ua.ModifySubscriptionParameters] = []
        self.deleted: list[list[int]] = []
        self.delete_status = ua.StatusCode(ua.StatusCodes.Good)
        self.messages: dict[int, ua.NotificationMessage] = {}
        self.republished: list[int] = []
        self.acknowledged: list[tuple[int, int]] = []
        self.transfer_result: ua.TransferResult | None = None
        self._subscription_callbacks: dict[int, Callable[..., Any]] = {}
        self.next_monitored_item_id = 1000

    async def create_subscription(
        self, params: ua.CreateSubscriptionParameters, callback: Callable[..., Any]
    ) -> ua.CreateSubscriptionResult:
        self.created.append(params)
        if self.revise is not None:
            result = self.revise(params)
        else:
            result = ua.CreateSubscriptionResult(
                SubscriptionId=0,
                RevisedPublishingInterval=params.RequestedPublishingInterval,
                RevisedLifetimeCount=params.RequestedLifetimeCount,
                RevisedMaxKeepAliveCount=params.RequestedMaxKeepAliveCount,
            )
        result.SubscriptionId = self.next_id
        self.next_id += 1
        self._subscription_callbacks[result.SubscriptionId] = callback
        return result

    async def update_subscription(self, params: ua.ModifySubscriptionParameters) -> ua.ModifySubscriptionResult:
        self.modified.append(params)
        return ua.ModifySubscriptionResult(
            RevisedPublishingInterval=params.RequestedPublishingInterval,
            RevisedLifetimeCount=params.RequestedLifetimeCount,
            RevisedMaxKeepAliveCount=params.RequestedMaxKeepAliveCount,
        )

    async def delete_subscriptions(self, ids: list[int]) -> list[ua.StatusCode]:
        self.deleted.append(list(ids))
        return [self.delete_status for _ in ids]

    async def republish(self, subscription_id: int, sequence_number: int) -> ua.NotificationMessage:
        self.republished.append(sequence_number)
        message = self.messages.get(sequence_number)
        if message is None:
            raise BadMessageNotAvailable()
        return message

    async def transfer_subscriptions(self, params: ua.TransferSubscriptionsParameters) -> list[ua.TransferResult]:
        assert self.transfer_result is not None
        return [self.transfer_result]

    def acknowledge(self, subscription_id: int, sequence_number: int) -> None:
        self.acknowledged.append((subscription_id, sequence_number))

    async def create_monitored_items(self, params: ua.CreateMonitoredItemsParameters) -> list[Any]:
        results = []
        for request in params.ItemsToCreate:
            self.next_monitored_item_id += 1
            results.append(
                ua.MonitoredItemCreateResult(
                    StatusCode=ua.StatusCode(),
                    MonitoredItemId=self.next_monitored_item_id,
                    RevisedSamplingInterval=request.RequestedParameters.SamplingInterval,
                    RevisedQueueSize=request.RequestedParameters.QueueSize,
                )
            )
        return results


def data_change(client_handle: int, value: Any) -> ua.DataChangeNotification:
    return ua.DataChangeNotification(
        MonitoredItems=[ua.MonitoredItemNotification(ClientHandle=client_handle, Value=ua.DataValue(ua.Variant(value)))]
    )


def message(sequence_number: int, *notifications: Any) -> ua.NotificationMessage:
    return ua.NotificationMessage(SequenceNumber=sequence_number, NotificationData=list(notifications))


def publish_result(
    subscription_id: int, msg: ua.NotificationMessage, available: list[int] | None = None
) -> ua.PublishResult:
    return ua.PublishResult(
        SubscriptionId=subscription_id,
        AvailableSequenceNumbers=available if available is not None else [],
        NotificationMessage=msg,
    )
