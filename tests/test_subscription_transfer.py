"""TransferSubscriptions (Part 4, 5.14.7)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.server.internal_session import Session
from enginir_opcua.server.internal_subscription import InternalSubscription
from enginir_opcua.server.subscription_service import same_owner

from .conftest import find_free_port
from .harness import TWO_SESSION_USERS, TwoSessions


class Recorder:
    def __init__(self) -> None:
        self.values: list[Any] = []
        self.statuses: list[ua.StatusChangeNotification] = []
        self.status_event = asyncio.Event()

    def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
        self.values.append(val)

    def status_change_notification(self, status: ua.StatusChangeNotification) -> None:
        self.statuses.append(status)
        self.status_event.set()


async def second_client(two: TwoSessions, user: str = "alice") -> Client:
    endpoint = two.server.endpoint
    client = Client(f"opc.tcp://{user}:{TWO_SESSION_USERS[user]}@{endpoint.hostname}:{endpoint.port}")
    await client.connect()
    return client


def server_session(two: TwoSessions, client: Client) -> Session:
    token = client.uaclient.session.authentication_token
    return two.server.iserver.session_manager.sessions[token]


async def transfer(client: Client, ids: list[int], initial: bool = False) -> list[ua.TransferResult]:
    params = ua.TransferSubscriptionsParameters(SubscriptionIds=ids, SendInitialValues=initial)
    return await client.uaclient.transfer_subscriptions(params)


def internal(two: TwoSessions, subscription_id: int) -> InternalSubscription:
    return two.server.iserver.subscription_service.subscriptions[subscription_id]


async def watched_variable(two: TwoSessions, name: str) -> Any:
    return await two.server.nodes.objects.add_variable(ua.NodeId(name, 2), name, 1)


async def test_srv4_transfer_by_another_user_is_user_access_denied(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.7.2: only the same user can take a subscription over."""
    sub = await two_sessions.alice.create_subscription(100, None)
    assert sub.subscription_id is not None
    results = await transfer(two_sessions.bob, [sub.subscription_id, 424242])
    assert [r.StatusCode.value for r in results] == [
        ua.StatusCodes.BadUserAccessDenied,
        ua.StatusCodes.BadSubscriptionIdInvalid,
    ]
    assert internal(two_sessions, sub.subscription_id).session_id == server_session(two_sessions, two_sessions.alice).id


async def test_srv4_transfer_to_the_owner_is_nothing_to_do(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.7.2: a subscription the session already owns is not transferred."""
    sub = await two_sessions.alice.create_subscription(100, None)
    assert sub.subscription_id is not None
    results = await transfer(two_sessions.alice, [sub.subscription_id])
    assert results[0].StatusCode.value == ua.StatusCodes.BadNothingToDo


async def test_srv4_anonymous_transfer_over_an_unsecured_channel_is_denied() -> None:
    """Part 4, 5.14.7.2: an anonymous client needs the same client certificate to take a subscription over."""
    server = Server()
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await server.start()
    try:
        async with Client(server.endpoint.geturl()) as first, Client(server.endpoint.geturl()) as second:
            sub = await first.create_subscription(100, None)
            assert sub.subscription_id is not None
            params = ua.TransferSubscriptionsParameters(SubscriptionIds=[sub.subscription_id])
            results = await second.uaclient.transfer_subscriptions(params)
            assert results[0].StatusCode.value == ua.StatusCodes.BadUserAccessDenied
    finally:
        await server.stop()


async def test_srv4_transfer_moves_queue_and_binding_to_the_new_session(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.7.1: messages and the Publish binding follow the subscription to the new session."""
    var = await watched_variable(two_sessions, "moved")
    handler = Recorder()
    sub = await two_sessions.alice.create_subscription(50, handler)
    assert sub.subscription_id is not None
    await sub.subscribe_data_change(var)
    isub = internal(two_sessions, sub.subscription_id)
    await asyncio.sleep(0.3)
    isub._not_acknowledged_results[99] = ua.PublishResult(NotificationMessage=ua.NotificationMessage(SequenceNumber=99))
    alice2 = await second_client(two_sessions)
    try:
        results = await transfer(alice2, [sub.subscription_id])
        assert results[0].StatusCode.is_good()
        assert 99 in results[0].AvailableSequenceNumbers
        new_session = server_session(two_sessions, alice2)
        assert isub.session_id == new_session.id
        assert isub.pub_request_callback == new_session.get_publish_request
        assert isub.pub_result_callback == new_session.forward_publish_response
        assert (await alice2.uaclient.session.republish(sub.subscription_id, 99)).SequenceNumber == 99
        with pytest.raises(ua.uaerrors.BadSubscriptionIdInvalid):
            await two_sessions.alice.uaclient.session.republish(sub.subscription_id, 99)
        await var.write_value(2)
        response = await asyncio.wait_for(alice2.uaclient.publish([]), 3)
        assert response.Parameters.SubscriptionId == sub.subscription_id
    finally:
        await alice2.disconnect()


async def test_srv4_old_session_is_told_the_subscription_was_transferred(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.7.2: the previous session gets a Good_SubscriptionTransferred status change."""
    handler = Recorder()
    sub = await two_sessions.alice.create_subscription(50, handler)
    assert sub.subscription_id is not None
    alice2 = await second_client(two_sessions)
    try:
        next_number = internal(two_sessions, sub.subscription_id)._sequence
        await transfer(alice2, [sub.subscription_id])
        await asyncio.wait_for(handler.status_event.wait(), 3)
        assert handler.statuses[0].Status.value == ua.StatusCodes.GoodSubscriptionTransferred
        assert internal(two_sessions, sub.subscription_id)._sequence == next_number
    finally:
        await alice2.disconnect()


async def test_srv4_transfer_of_an_orphaned_subscription_works(two_sessions: TwoSessions) -> None:
    """Part 4, 5.7.4: a subscription whose session the server ended can be taken over within its lifetime."""
    sub = await two_sessions.alice.create_subscription(100, None)
    assert sub.subscription_id is not None
    await server_session(two_sessions, two_sessions.alice).close(False)
    assert sub.subscription_id in two_sessions.server.iserver.subscription_service.subscriptions
    alice2 = await second_client(two_sessions)
    try:
        results = await transfer(alice2, [sub.subscription_id])
        assert results[0].StatusCode.is_good()
        assert internal(two_sessions, sub.subscription_id).session_id == server_session(two_sessions, alice2).id
    finally:
        await alice2.disconnect()


async def test_srv4_transfer_respects_the_per_session_limit(two_sessions: TwoSessions) -> None:
    """Part 4, 5.14.7.4: a session cannot take over more subscriptions than it may own."""
    sub = await two_sessions.alice.create_subscription(100, None)
    assert sub.subscription_id is not None
    alice2 = await second_client(two_sessions)
    try:
        await alice2.create_subscription(100, None)
        two_sessions.server.iserver.max_subscriptions_per_session = 1
        results = await transfer(alice2, [sub.subscription_id])
        assert results[0].StatusCode.value == ua.StatusCodes.BadTooManySubscriptions
    finally:
        await alice2.disconnect()


@pytest.mark.parametrize("initial", [True, False])
async def test_srv4_send_initial_values(two_sessions: TwoSessions, initial: bool) -> None:
    """Part 4, 5.14.7.2: SendInitialValues makes the first Publish after the transfer carry the current values."""
    var = await watched_variable(two_sessions, f"initial-{initial}")
    handler = Recorder()
    sub = await two_sessions.alice.create_subscription(50, handler)
    assert sub.subscription_id is not None
    await sub.subscribe_data_change(var)
    await asyncio.sleep(0.3)
    assert handler.values == [1]
    alice2 = await second_client(two_sessions)
    try:
        await transfer(alice2, [sub.subscription_id], initial=initial)
        queued = internal(two_sessions, sub.subscription_id)._triggered_datachanges
        assert bool(queued) is initial
        if initial:
            assert next(iter(queued.values()))[0].Value.Value.Value == 1
    finally:
        await alice2.disconnect()


def test_srv4_anonymous_owner_needs_the_same_certificate() -> None:
    """Part 4, 5.14.7.2: anonymous sessions are the same owner only with the same client certificate."""
    anonymous = User(role=UserRole.Anonymous)
    assert same_owner(anonymous, b"cert", anonymous, b"cert") is True
    assert same_owner(anonymous, b"cert", anonymous, b"other") is False
    assert same_owner(anonymous, None, anonymous, None) is False
    assert same_owner(anonymous, b"cert", User(role=UserRole.User, name="alice"), b"cert") is False
    alice = User(role=UserRole.User, name="alice")
    assert same_owner(alice, None, alice, None) is True
    assert same_owner(alice, None, User(role=UserRole.User, name="bob"), None) is False
