import asyncio
from unittest import mock

import pytest

from enginir_opcua import Client, ua
from enginir_opcua.client.ua_client import UaClient, UaClientState
from enginir_opcua.common.subscription import DataChangeEvent, Subscription
from enginir_opcua.observer import NULL_OBSERVER, Observer, SubscriptionEvent

from .conftest import port_num


class RecordingObserver(Observer):
    def __init__(self):
        self.requests = []
        self.states = []
        self.subscriptions = []
        self.notifications = []
        self.dropped = []

    def on_request(self, request_type, duration, error):
        self.requests.append((request_type, duration, error))

    def on_state_change(self, state):
        self.states.append(state)

    def on_subscription_event(self, subscription_id, event):
        self.subscriptions.append((event, subscription_id))

    def on_notification(self, subscription_id, event_count):
        self.notifications.append((subscription_id, event_count))

    def on_messages_dropped(self, subscription_id, count):
        self.dropped.append((subscription_id, count))


class BrokenObserver(Observer):
    def on_request(self, request_type, duration, error):
        raise RuntimeError("observer is broken")

    def on_state_change(self, state):
        raise RuntimeError("observer is broken")

    def on_subscription_event(self, subscription_id, event):
        raise RuntimeError("observer is broken")

    def on_notification(self, subscription_id, event_count):
        raise RuntimeError("observer is broken")


def test_a_client_starts_with_the_null_observer():
    assert UaClient().observer is NULL_OBSERVER


async def test_the_null_observer_measures_nothing():
    client = UaClient()
    client.protocol = mock.AsyncMock()

    with mock.patch("enginir_opcua.observer.time.monotonic") as clock:
        await client._send_request(ua.ReadRequest())

    assert not clock.called


async def test_an_observer_only_implements_what_it_cares_about():
    class OnlyStates(Observer):
        def __init__(self):
            self.seen = []

        def on_state_change(self, state):
            self.seen.append(state)

    observer = OnlyStates()
    client = UaClient()
    client.observer = observer
    client.protocol = mock.AsyncMock()

    await client._send_request(ua.ReadRequest())
    client._set_state(UaClientState.CONNECTED)

    assert observer.seen == [UaClientState.CONNECTED]


async def test_a_request_is_reported_with_its_type_and_duration():
    observer = RecordingObserver()
    client = UaClient()
    client.observer = observer
    client.protocol = mock.AsyncMock()

    await client._send_request(ua.ReadRequest())

    assert len(observer.requests) == 1
    request_type, duration, error = observer.requests[0]
    assert request_type == "ReadRequest"
    assert duration >= 0
    assert error is None


async def test_a_failing_request_is_reported_with_its_error_and_still_raises():
    observer = RecordingObserver()
    client = UaClient()
    client.observer = observer
    client.protocol = mock.AsyncMock()
    client.protocol.send_request.side_effect = ConnectionError("gone")

    with pytest.raises(ConnectionError):
        await client._send_request(ua.ReadRequest())

    _, _, error = observer.requests[0]
    assert isinstance(error, ConnectionError)


async def test_a_cancelled_request_is_reported_and_still_cancels():
    observer = RecordingObserver()
    client = UaClient()
    client.observer = observer
    client.protocol = mock.AsyncMock()
    client.protocol.send_request.side_effect = asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await client._send_request(ua.ReadRequest())

    _, _, error = observer.requests[0]
    assert isinstance(error, asyncio.CancelledError)


def test_state_changes_are_reported_once_each():
    observer = RecordingObserver()
    client = UaClient()
    client.observer = observer

    client._set_state(UaClientState.CONNECTING)
    client._set_state(UaClientState.CONNECTING)
    client._set_state(UaClientState.CONNECTED)

    assert observer.states == [UaClientState.CONNECTING, UaClientState.CONNECTED]


async def test_a_broken_observer_does_not_break_a_request():
    client = UaClient()
    client.observer = BrokenObserver()
    client.protocol = mock.AsyncMock()

    await client._send_request(ua.ReadRequest())


def test_a_broken_observer_does_not_break_a_state_change():
    client = UaClient()
    client.observer = BrokenObserver()

    client._set_state(UaClientState.CONNECTED)

    assert client.state is UaClientState.CONNECTED


def test_a_broken_state_listener_does_not_break_the_transition():
    def broken(state):
        raise RuntimeError("listener is broken")

    client = UaClient()
    client.add_state_listener(broken)

    client._set_state(UaClientState.CONNECTED)

    assert client.state is UaClientState.CONNECTED


async def test_the_request_slot_is_free_while_the_observer_runs():
    held = []
    client = UaClient()
    client._request_semaphore = asyncio.Semaphore(1)
    client.protocol = mock.AsyncMock()

    class Probe(Observer):
        def on_request(self, request_type, duration, error):
            held.append(client._request_semaphore.locked())

    client.observer = Probe()
    await client._send_request(ua.ReadRequest())

    assert held == [False]


async def test_the_session_shares_the_observer_of_its_client():
    observer = RecordingObserver()
    client = UaClient()
    client.observer = observer

    assert client.session.observer is observer


async def test_the_subscription_lifecycle_is_reported(server):
    observer = RecordingObserver()
    async with Client(f"opc.tcp://127.0.0.1:{port_num}") as client:
        client.uaclient.observer = observer
        subscription = await client.create_subscription(100, mock.MagicMock())
        created = [e for e in observer.subscriptions if e[0] is SubscriptionEvent.CREATED]
        assert created
        await subscription.delete()

    assert any(event is SubscriptionEvent.DELETED for event, _ in observer.subscriptions)


async def test_a_deleted_subscription_is_marked_deleted_before_the_observer_runs(server):
    seen = []
    async with Client(f"opc.tcp://127.0.0.1:{port_num}") as client:
        subscription = await client.create_subscription(100, mock.MagicMock())

        class Late(Observer):
            def on_subscription_event(self, subscription_id, event):
                seen.append((event, subscription.is_deleted))

        client.uaclient.observer = Late()
        await subscription.delete()

    assert (SubscriptionEvent.DELETED, True) in seen


async def test_notifications_are_reported_with_their_item_count(server):
    observer = RecordingObserver()
    async with Client(f"opc.tcp://127.0.0.1:{port_num}") as client:
        client.uaclient.observer = observer
        node = client.get_node(ua.ObjectIds.Server_ServerStatus_CurrentTime)
        subscription = await client.create_subscription(50, mock.MagicMock())
        await subscription.subscribe_data_change(node)
        await asyncio.sleep(0.5)
        await subscription.delete()

    assert observer.notifications
    assert all(count >= 0 for _, count in observer.notifications)


async def test_a_recreated_subscription_is_reported_once(server):
    observer = RecordingObserver()
    async with Client(f"opc.tcp://127.0.0.1:{port_num}") as client:
        client.uaclient.observer = observer
        subscription = await client.create_subscription(100, mock.MagicMock())
        observer.subscriptions.clear()
        await subscription.recreate()
        await subscription.delete()

    events = [event for event, _ in observer.subscriptions]
    assert events.count(SubscriptionEvent.RECREATED) == 1
    assert SubscriptionEvent.CREATED not in events


async def test_a_broken_observer_does_not_break_a_subscription(server):
    async with Client(f"opc.tcp://127.0.0.1:{port_num}") as client:
        client.uaclient.observer = BrokenObserver()
        subscription = await client.create_subscription(100, mock.MagicMock())
        await subscription.delete()


async def test_a_server_side_subscription_has_the_null_observer(server):
    subscription = await server.create_subscription(100, mock.MagicMock())

    assert subscription.server.observer is NULL_OBSERVER

    await subscription.delete()


def _publish_result(notification_data):
    result = ua.PublishResult()
    result.NotificationMessage = ua.NotificationMessage()
    result.NotificationMessage.SequenceNumber = 1
    result.NotificationMessage.NotificationData = notification_data
    return result


async def test_a_notification_with_no_items_is_still_reported():
    observer = RecordingObserver()
    server = mock.MagicMock()
    server.observer = observer
    subscription = Subscription(server, ua.CreateSubscriptionParameters(), mock.MagicMock())
    subscription.subscription_id = 7

    await subscription.publish_callback(_publish_result([]))
    await asyncio.sleep(0.05)

    assert observer.notifications == [(7, 0)]


async def test_a_broken_observer_does_not_break_publishing():
    server = mock.MagicMock()
    server.observer = BrokenObserver()
    subscription = Subscription(server, ua.CreateSubscriptionParameters(), mock.MagicMock())
    subscription.subscription_id = 7

    await subscription.publish_callback(_publish_result([]))


def test_obs2_a_client_takes_an_observer_as_argument_and_property():
    """The observer is set on the Client, not on the UaClient inside it."""
    from enginir_opcua import Client

    observer = Observer()
    client = Client("opc.tcp://localhost:4840", observer=observer)
    assert client.observer is observer
    assert client.uaclient.observer is observer
    other = Observer()
    client.observer = other
    assert client.uaclient.observer is other
    assert Client("opc.tcp://localhost:4840").observer is NULL_OBSERVER


def test_obs1_every_hook_is_documented():
    """The usage page lists every hook, and every hook has a docstring."""
    from pathlib import Path

    page = (Path(__file__).parent.parent / "docs" / "usage" / "common" / "observer.rst").read_text()
    hooks = [name for name in vars(Observer) if name.startswith("on_")]
    assert len(hooks) == 6
    for name in hooks:
        assert f"``{name}(" in page
        assert getattr(Observer, name).__doc__
    assert Observer.__doc__


async def test_obs3_events_dropped_from_the_iterator_queue_are_reported():
    observer = RecordingObserver()
    server = mock.MagicMock()
    server.observer = observer
    subscription = Subscription(server, ua.CreateSubscriptionParameters(), None, queue_maxsize=2)
    subscription.subscription_id = 7

    for _ in range(4):
        subscription._put_event(mock.MagicMock())

    assert subscription.dropped_events == 2
    assert observer.dropped == [(7, 1), (7, 1)]


async def test_obs3_events_for_a_handler_without_the_method_are_reported():
    observer = RecordingObserver()
    server = mock.MagicMock()
    server.observer = observer
    subscription = Subscription(server, ua.CreateSubscriptionParameters(), object())
    subscription.subscription_id = 7

    await subscription._dispatch_to_handler(DataChangeEvent(node=mock.MagicMock(), value=1, data=mock.MagicMock()))

    assert subscription.dropped_events == 1
    assert observer.dropped == [(7, 1)]
