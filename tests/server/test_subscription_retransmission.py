from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common import utils
from enginir_opcua.server.internal_server import InternalServer
from enginir_opcua.server.internal_subscription import InternalSubscription

ALICE = ua.NodeId(1, 1)
BOB = ua.NodeId(2, 1)


@dataclass
class Setup:
    iserver: InternalServer
    sub: InternalSubscription
    sent: list[ua.PublishResult]

    @property
    def subscription_id(self) -> int:
        return self.sub.data.SubscriptionId

    async def send_data(self, count: int) -> None:
        for mid in range(count):
            item = ua.MonitoredItemNotification(
                ClientHandle=mid, Value=ua.DataValue(ua.Variant(mid, ua.VariantType.Int32))
            )
            await self.sub.enqueue_datachange_event(mid, item, 0)
            await self.sub.timer_expired()


@pytest.fixture
async def setup() -> AsyncIterator[Setup]:
    iserver = InternalServer()
    sent: list[ua.PublishResult] = []

    async def send(result: ua.PublishResult, _request: Any = None) -> None:
        sent.append(result)

    params = ua.CreateSubscriptionParameters(
        RequestedPublishingInterval=3_600_000,
        RequestedLifetimeCount=300,
        RequestedMaxKeepAliveCount=100,
        PublishingEnabled=True,
    )
    created = await iserver.subscription_service.create_subscription(params, send, ALICE, lambda _id: object())
    sub = iserver.subscription_service.subscriptions[created.SubscriptionId]
    yield Setup(iserver, sub, sent)
    await sub.stop()


def republish(setup: Setup, session: ua.NodeId, subscription_id: int, number: int) -> ua.NotificationMessage:
    params = ua.RepublishParameters(SubscriptionId=subscription_id, RetransmitSequenceNumber=number)
    return setup.iserver.subscription_service.republish(params, session)


async def test_srv12_republish_does_not_remove_the_message(setup: Setup) -> None:
    """Part 4, 5.14.6: a message leaves the retransmission queue only when it is acknowledged."""
    await setup.send_data(2)
    first = republish(setup, ALICE, setup.subscription_id, 1)
    again = republish(setup, ALICE, setup.subscription_id, 1)
    assert first.SequenceNumber == 1
    assert again.SequenceNumber == 1
    assert again.PublishTime == setup.sent[0].NotificationMessage.PublishTime
    assert list(setup.sub.available_sequence_numbers()) == [1, 2]


async def test_srv12_republish_unknown_is_message_not_available(setup: Setup) -> None:
    """Part 4, 5.14.6: asking for a message that is not in the queue is Bad_MessageNotAvailable."""
    await setup.send_data(1)
    with pytest.raises(utils.ServiceError) as error:
        republish(setup, ALICE, setup.subscription_id, 99)
    assert error.value.code == ua.StatusCodes.BadMessageNotAvailable


async def test_srv12_republish_of_an_acknowledged_message_is_message_not_available(setup: Setup) -> None:
    """Part 4, 5.14.6: an acknowledged message is gone from the retransmission queue."""
    await setup.send_data(1)
    ack = ua.SubscriptionAcknowledgement(SubscriptionId=setup.subscription_id, SequenceNumber=1)
    setup.iserver.subscription_service.publish([ack], ALICE)
    with pytest.raises(utils.ServiceError) as error:
        republish(setup, ALICE, setup.subscription_id, 1)
    assert error.value.code == ua.StatusCodes.BadMessageNotAvailable


async def test_srv12_republish_of_a_foreign_subscription_is_subscription_id_invalid(setup: Setup) -> None:
    """Part 4, 5.14.6: a subscription of another session is not visible to Republish."""
    await setup.send_data(1)
    with pytest.raises(utils.ServiceError) as error:
        republish(setup, BOB, setup.subscription_id, 1)
    assert error.value.code == ua.StatusCodes.BadSubscriptionIdInvalid


async def test_srv32_ack_results_per_entry(setup: Setup) -> None:
    """Part 4, 5.14.5.4: each acknowledgement has its own result."""
    await setup.send_data(2)
    sid = setup.subscription_id
    acks = [
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=1),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=1),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=77),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid + 1000, SequenceNumber=2),
        ua.SubscriptionAcknowledgement(SubscriptionId=sid, SequenceNumber=2),
    ]
    _count, results = setup.iserver.subscription_service.publish(acks, ALICE)
    assert [r.value for r in results] == [
        ua.StatusCodes.Good,
        ua.StatusCodes.BadSequenceNumberUnknown,
        ua.StatusCodes.BadSequenceNumberUnknown,
        ua.StatusCodes.BadSubscriptionIdInvalid,
        ua.StatusCodes.Good,
    ]
    assert list(setup.sub.available_sequence_numbers()) == []


async def test_srv32_foreign_acknowledgement_leaves_the_message(setup: Setup) -> None:
    """Part 4, 5.14.5.4: a session cannot acknowledge the messages of another session."""
    await setup.send_data(1)
    ack = ua.SubscriptionAcknowledgement(SubscriptionId=setup.subscription_id, SequenceNumber=1)
    other = ua.NodeId(5, 1)
    other_params = ua.CreateSubscriptionParameters(RequestedMaxKeepAliveCount=10, RequestedLifetimeCount=30)
    created = await setup.iserver.subscription_service.create_subscription(
        other_params, setup.sub.pub_result_callback, other, lambda _id: None
    )
    _count, results = setup.iserver.subscription_service.publish([ack], other)
    await setup.iserver.subscription_service.subscriptions[created.SubscriptionId].stop()
    assert results[0].value == ua.StatusCodes.BadSubscriptionIdInvalid
    assert list(setup.sub.available_sequence_numbers()) == [1]


async def test_srv12_oldest_unacknowledged_message_can_be_dropped(setup: Setup) -> None:
    """Part 4, 5.14.1.1: the session bounds the retransmission queue by dropping the oldest message."""
    await setup.send_data(3)
    assert setup.sub.unacknowledged_count == 3
    assert setup.sub.drop_oldest_unacknowledged() is True
    assert list(setup.sub.available_sequence_numbers()) == [2, 3]
    assert setup.sub.drop_oldest_unacknowledged() is True
    assert setup.sub.drop_oldest_unacknowledged() is True
    assert setup.sub.drop_oldest_unacknowledged() is False
