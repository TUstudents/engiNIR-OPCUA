from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client import ua_session
from enginir_opcua.client.ua_session import UaSession
from enginir_opcua.common.subscription import Subscription, subscription_parameters
from enginir_opcua.common.utils import Buffer
from enginir_opcua.observer import NULL_OBSERVER
from enginir_opcua.ua.ua_binary import struct_to_binary
from tests.conftest import find_free_port
from tests.subscription_rig import FakeSession


class ScriptedClient:
    def __init__(self) -> None:
        self._timeout = 0.2
        self.observer = NULL_OBSERVER
        self.protocol = None
        self.requests: list[Any] = []
        self.hints: list[float | None] = []
        self.script: asyncio.Queue[Any] = asyncio.Queue()

    async def _send_request(
        self,
        request: Any,
        timeout: float | None = None,
        message_type: Any = None,
        *,
        timeout_hint: float | None = None,
        limited: bool = True,
    ) -> Buffer:
        self.requests.append(request)
        self.hints.append(timeout_hint)
        item = await self.script.get()
        if isinstance(item, BaseException):
            raise item
        return Buffer(struct_to_binary(item))

    def acks(self, index: int) -> list[tuple[int, int]]:
        return [
            (a.SubscriptionId, a.SequenceNumber) for a in self.requests[index].Parameters.SubscriptionAcknowledgements
        ]


class RecordingSink:
    def __init__(self) -> None:
        self.results: list[ua.PublishResult] = []

    def enqueue(self, result: ua.PublishResult) -> None:
        self.results.append(result)

    def session_event(self, status: ua.StatusCode) -> None:
        pass


def data_response(
    subscription_id: int = 1, sequence: int = 5, available: list[int] | None = None, results: list[int] | None = None
) -> ua.PublishResponse:
    message = ua.NotificationMessage(SequenceNumber=sequence, NotificationData=[ua.DataChangeNotification()])
    return ua.PublishResponse(
        Parameters=ua.PublishResult(
            SubscriptionId=subscription_id,
            AvailableSequenceNumbers=[sequence] if available is None else available,
            NotificationMessage=message,
            Results=[ua.StatusCode(r) for r in results or []],
        )
    )


def keep_alive_response(subscription_id: int = 1, sequence: int = 6) -> ua.PublishResponse:
    return ua.PublishResponse(
        Parameters=ua.PublishResult(
            SubscriptionId=subscription_id,
            AvailableSequenceNumbers=[],
            NotificationMessage=ua.NotificationMessage(SequenceNumber=sequence, NotificationData=[]),
        )
    )


async def until(condition: Callable[[], bool], timeout: float = 3.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.01)


@pytest.fixture
def wire() -> ScriptedClient:
    return ScriptedClient()


@pytest.fixture
def sink() -> RecordingSink:
    return RecordingSink()


@pytest.fixture
async def session(wire: ScriptedClient, sink: RecordingSink) -> AsyncIterator[UaSession]:
    session = UaSession(wire)  # type: ignore[arg-type]
    session.max_outstanding_publish_requests = 1
    session._subscription_callbacks[1] = sink
    yield session
    await session.close_session(True)


async def test_cli5_acks_survive_a_failed_publish(wire: ScriptedClient, session: UaSession) -> None:
    """Part 4, 5.14.5.2: a message is acknowledged until a Publish carrying the acknowledgement was answered."""
    wire.script.put_nowait(data_response())
    wire.script.put_nowait(ua.uaerrors.BadTimeout())
    await until(lambda: len(wire.requests) >= 3)
    assert wire.acks(1) == [(1, 5)]
    assert wire.acks(2) == [(1, 5)]


async def test_cli5_acks_are_settled_by_the_response(wire: ScriptedClient, session: UaSession) -> None:
    """Part 4, 5.14.1.1: once the response to the request that carried an acknowledgement arrived, it is not repeated."""
    wire.script.put_nowait(data_response())
    wire.script.put_nowait(data_response(sequence=6, results=[ua.StatusCodes.Good]))
    await until(lambda: len(wire.requests) >= 3)
    assert wire.acks(1) == [(1, 5)]
    assert wire.acks(2) == [(1, 6)]


async def test_cli5_acks_survive_a_lost_connection(wire: ScriptedClient, session: UaSession) -> None:
    """Part 4, 6.7: acknowledgements of a request that never got an answer go into the next request."""
    wire.script.put_nowait(data_response())
    wire.script.put_nowait(ConnectionError("lost"))
    await until(lambda: session.publish_suspended)
    session.resume_publish()
    await until(lambda: len(wire.requests) >= 3)
    assert wire.acks(2) == [(1, 5)]


async def test_cli5_republished_messages_are_acknowledged(wire: ScriptedClient, session: UaSession) -> None:
    """Part 4, 5.14.1.1: a message fetched with Republish is acknowledged like a published one."""
    await until(lambda: len(wire.requests) >= 1)
    session.acknowledge(1, 9)
    wire.script.put_nowait(keep_alive_response())
    await until(lambda: len(wire.requests) >= 2)
    assert wire.acks(1) == [(1, 9)]


async def test_cli5_empty_available_sequence_numbers_are_not_acknowledged(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink
) -> None:
    """Part 4, 5.14.5.2: a Subscription without a retransmission queue lists no sequence numbers; nothing is acked."""
    wire.script.put_nowait(data_response(available=[]))
    await until(lambda: len(wire.requests) >= 2)
    assert wire.acks(1) == []
    assert len(sink.results) == 1


async def test_cli5_keep_alives_are_not_acknowledged(wire: ScriptedClient, session: UaSession) -> None:
    """Part 4, 5.14.1.1: only NotificationMessages with notifications are acknowledged."""
    wire.script.put_nowait(keep_alive_response())
    await until(lambda: len(wire.requests) >= 2)
    assert wire.acks(1) == []


async def test_cli5_acks_of_a_removed_subscription_are_dropped(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink
) -> None:
    """Part 4, 5.14.1.1: the server would answer Bad_SubscriptionIdInvalid for a deleted Subscription."""
    wire.script.put_nowait(data_response())
    await until(lambda: len(wire.requests) >= 2)
    wire.script.put_nowait(ua.uaerrors.BadTimeout())
    del session._subscription_callbacks[1]
    session._subscription_callbacks[2] = sink
    await until(lambda: len(wire.requests) >= 3)
    assert wire.acks(2) == []


async def test_cli5_unknown_sequence_number_is_logged_at_debug_level(
    wire: ScriptedClient, session: UaSession, caplog: pytest.LogCaptureFixture
) -> None:
    """Part 4, 5.14.5.2: Bad_SequenceNumberUnknown for an acknowledgement is not worth a warning."""
    caplog.set_level(logging.DEBUG)
    wire.script.put_nowait(data_response())
    wire.script.put_nowait(data_response(sequence=6, results=[ua.StatusCodes.BadSequenceNumberUnknown]))
    await until(lambda: len(wire.requests) >= 3)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


async def test_cli5_ledger_is_bounded(wire: ScriptedClient, session: UaSession) -> None:
    """The ledger keeps at most max_pending_acks entries and drops the oldest ones."""
    session.max_pending_acks = 3
    session.pause_publish()
    for sequence in range(1, 8):
        session.acknowledge(1, sequence)
    session.resume_publish()
    await until(lambda: len(wire.requests) >= 2)
    assert wire.acks(1) == [(1, 5), (1, 6), (1, 7)]


async def test_cli4_bad_no_subscription_with_a_sink_registered_does_not_end_the_pump(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.14.5.2: Bad_NoSubscription ends the pump only when no Subscription is left locally."""
    monkeypatch.setattr(ua_session, "NO_SUBSCRIPTION_RETRY_DELAYS", (0.05, 0.05))
    wire.script.put_nowait(ua.uaerrors.BadNoSubscription())
    await until(lambda: len(wire.requests) >= 2)
    wire.script.put_nowait(data_response())
    await until(lambda: len(sink.results) == 1)


async def test_cli4_pump_idles_without_sinks_and_wakes_on_the_next_one(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink
) -> None:
    """Part 4, 5.14.5.2: the pump idles while there is no Subscription and restarts with the next one."""
    wire.script.put_nowait(ua.uaerrors.BadNoSubscription())
    del session._subscription_callbacks[1]
    await asyncio.sleep(0.3)
    assert len(wire.requests) == 1
    assert session.publish_requests_outstanding == 0
    session._subscription_callbacks[7] = sink
    await until(lambda: len(wire.requests) >= 2)


async def test_cli4_response_with_subscription_id_zero_is_no_subscription(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.14.5.2: a SubscriptionId of 0 means the Session has no Subscription."""
    monkeypatch.setattr(ua_session, "NO_SUBSCRIPTION_RETRY_DELAYS", (0.05, 0.05))
    wire.script.put_nowait(data_response(subscription_id=0))
    await until(lambda: len(wire.requests) >= 2)
    assert sink.results == []


@pytest.mark.parametrize(
    "error",
    [
        ConnectionError("lost"),
        ua.uaerrors.BadSessionClosed(),
        ua.uaerrors.BadSessionIdInvalid(),
        ua.uaerrors.BadSessionNotActivated(),
        ua.uaerrors.BadSecureChannelClosed(),
        ua.uaerrors.BadSecureChannelIdInvalid(),
    ],
)
async def test_cli29_lost_connection_stops_the_pump(
    wire: ScriptedClient, session: UaSession, error: BaseException
) -> None:
    """Part 4, 6.7: when the Session or the channel is gone, no Publish request is retried until the client resumes."""
    wire.script.put_nowait(error)
    await until(lambda: session.publish_suspended)
    await asyncio.sleep(0.2)
    assert len(wire.requests) == 1
    assert session.publish_requests_outstanding == 0


async def test_cli3_other_bad_result_is_retried_after_a_delay(
    wire: ScriptedClient, session: UaSession, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A Publish that fails for another reason is retried with a growing delay."""
    monkeypatch.setattr(ua_session, "PUBLISH_ERROR_RETRY_DELAY", 0.05)
    wire.script.put_nowait(ua.uaerrors.BadInternalError())
    wire.script.put_nowait(ua.uaerrors.BadInternalError())
    await until(lambda: len(wire.requests) >= 3)


async def test_cli3_expected_publish_results_do_not_log_warnings(
    wire: ScriptedClient, session: UaSession, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 5.3: Bad_Timeout and Bad_NoSubscription are expected answers to Publish."""
    monkeypatch.setattr(ua_session, "NO_SUBSCRIPTION_RETRY_DELAYS", (0.05, 0.05))
    caplog.set_level(logging.DEBUG)
    wire.script.put_nowait(ua.uaerrors.BadTimeout())
    wire.script.put_nowait(ua.uaerrors.BadNoSubscription())
    await until(lambda: len(wire.requests) >= 3)
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


async def test_cli3_response_goes_to_the_sink_without_awaiting_it(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink
) -> None:
    """Part 4, 5.14.5: the pump hands a result to the sink and carries on."""
    wire.script.put_nowait(data_response())
    await until(lambda: len(sink.results) == 1)
    assert sink.results[0].SubscriptionId == 1


async def test_cli3_legacy_callback_that_blocks_does_not_stop_the_pump(
    wire: ScriptedClient, session: UaSession
) -> None:
    """A plain callback is run as its own task; the pump never awaits application code."""
    gate = asyncio.Event()

    async def blocked(result: ua.PublishResult) -> None:
        await gate.wait()

    session._subscription_callbacks[1] = blocked
    wire.script.put_nowait(data_response())
    await until(lambda: len(wire.requests) >= 2)
    gate.set()


async def test_cli3_pipeline_follows_the_number_of_subscriptions(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink
) -> None:
    """Part 4, 5.14.5.1: one request per Subscription and one more."""
    session.max_outstanding_publish_requests = 10
    session._subscription_callbacks[2] = sink
    session._subscription_callbacks[3] = sink
    await until(lambda: session.publish_requests_outstanding == 4)
    del session._subscription_callbacks[3]
    wire.script.put_nowait(keep_alive_response())
    await until(lambda: session.publish_requests_outstanding == 3)


async def test_cli3_pipeline_is_capped(session: UaSession, sink: RecordingSink) -> None:
    """The number of outstanding requests never exceeds max_outstanding_publish_requests."""
    session.max_outstanding_publish_requests = 3
    for subscription_id in range(2, 8):
        session._subscription_callbacks[subscription_id] = sink
    await until(lambda: session.publish_requests_outstanding == 3)
    await asyncio.sleep(0.2)
    assert session.publish_requests_outstanding == 3


async def test_cli3_round_trip_time_adds_requests(session: UaSession) -> None:
    """Part 4, 5.14.5.1: when the round trip is longer than the publishing interval, more requests are needed."""
    session.max_outstanding_publish_requests = 10
    session.note_subscription_timing(1, 1.0, 10)
    session._round_trip = 5.0
    session.ensure_publish_loop()
    await until(lambda: session.publish_requests_outstanding == 6)


async def test_cli3_too_many_publish_requests_lowers_the_target(
    wire: ScriptedClient, session: UaSession, sink: RecordingSink
) -> None:
    """Part 4, 5.14.5.1: Bad_TooManyPublishRequests means the server queue is full; the target drops by one."""
    session.max_outstanding_publish_requests = 4
    session._subscription_callbacks[2] = sink
    session._subscription_callbacks[3] = sink
    await until(lambda: session.publish_requests_outstanding == 4)
    wire.script.put_nowait(ua.uaerrors.BadTooManyPublishRequests())
    await until(lambda: session.publish_requests_outstanding == 3)
    await asyncio.sleep(0.2)
    assert session.publish_requests_outstanding == 3


async def test_cli3_publish_timeout_follows_the_keep_alive_time(wire: ScriptedClient, session: UaSession) -> None:
    """Part 4, 5.14.1.4 and 7.33: the hint is the longest keep-alive time plus the normal request timeout."""
    session.note_subscription_timing(1, 0.5, 20)
    session.note_subscription_timing(2, 1.0, 3)
    session.pause_publish()
    session.resume_publish()
    await until(lambda: len(wire.requests) >= 2)
    assert wire.hints[-1] == pytest.approx(10.2)


async def test_cli3_publish_requests_do_not_use_request_permits() -> None:
    """Part 4, 5.14.5.1: outstanding Publish requests must not starve the other services."""
    port = find_free_port()
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    async with server:
        client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=2)
        await client.connect()
        try:
            client.set_max_concurrent_requests(1)
            subs = [await client.create_subscription(500, MultiHandler()) for _ in range(2)]
            await asyncio.sleep(0.3)
            assert await asyncio.wait_for(client.get_objects_node().read_browse_name(), 1.5) is not None
            for sub in subs:
                await sub.delete()
        finally:
            await client.disconnect()


class MultiHandler:
    def __init__(self) -> None:
        self.values: list[Any] = []

    def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
        self.values.append(val)


async def test_com74_delete_of_an_unknown_subscription_unregisters_its_sink() -> None:
    """Part 4, 5.14.8: a Subscription the server does not know needs no Publish requests."""
    port = find_free_port()
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    async with server:
        client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=2)
        await client.connect()
        try:
            session = client.uaclient.session
            session._subscription_callbacks[9999] = RecordingSink()
            results = await session.delete_subscriptions([9999])
            assert results[0].value == ua.StatusCodes.BadSubscriptionIdInvalid
            assert 9999 not in session._subscription_callbacks
        finally:
            await client.disconnect()


async def test_cli4_delete_last_then_create_keeps_publishing() -> None:
    """Part 4, 5.14.5.2: a Subscription created while the request of a deleted one is outstanding gets data."""
    port = find_free_port()
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    async with server:
        var = await server.get_objects_node().add_variable(2, "RaceVar", 0)
        await var.set_writable()
        client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=2)
        await client.connect()
        try:
            node = client.get_node(var.nodeid)
            first = await client.create_subscription(5000, MultiHandler())
            await asyncio.sleep(0.05)
            for round_number in range(1, 21):
                await first.delete()
                handler = MultiHandler()
                first = await client.create_subscription(50, handler)
                await first.subscribe_data_change(node)
                await asyncio.wait_for(wait_for_values(handler), 2)
                await var.write_value(round_number)
        finally:
            await client.disconnect()


async def wait_for_values(handler: MultiHandler) -> None:
    while not handler.values:
        await asyncio.sleep(0.01)


async def test_cli29_lost_transport_without_reconnect_stops_the_pump() -> None:
    """Part 4, 6.7: after the transport is lost and the client does not reconnect, nothing keeps retrying Publish."""
    port = find_free_port()
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    async with server:
        client = Client(f"opc.tcp://127.0.0.1:{port}", timeout=2, watchdog_intervall=0.2)
        await client.connect()
        try:
            await client.create_subscription(100, MultiHandler())
            await asyncio.sleep(0.2)
            protocol = client.uaclient.protocol
            assert protocol is not None and protocol.transport is not None
            protocol.transport.close()
            await asyncio.sleep(0.5)
            session = client.uaclient.session
            assert session.publish_requests_outstanding == 0
            assert session.publish_suspended
        finally:
            await client.disconnect()


@pytest.mark.parametrize("period", [50, 100, 1000])
def test_cli10_counts_follow_the_3x_rule(period: int) -> None:
    """Part 4, 5.14.2.2: the lifetime is at least three times the keep-alive; keep-alive about 10 s."""
    params = subscription_parameters(period)
    assert params.RequestedLifetimeCount >= 3 * params.RequestedMaxKeepAliveCount
    assert params.RequestedMaxKeepAliveCount * period == pytest.approx(10_000, abs=period)
    assert params.RequestedLifetimeCount * period >= 300_000
    assert params.MaxNotificationsPerPublish == 0


def test_cli10_keep_alive_is_limited_to_a_quarter_of_the_session_timeout() -> None:
    """Part 4, 5.14.2.2: a keep-alive must arrive well within the Session timeout."""
    params = subscription_parameters(100, session_timeout=20_000)
    assert params.RequestedMaxKeepAliveCount * 100 <= 5_000


def test_cli10_period_zero_is_sent_as_zero() -> None:
    """Part 4, 5.14.2.2: an interval of 0 asks for the fastest one the server has."""
    params = subscription_parameters(0)
    assert params.RequestedPublishingInterval == 0
    assert params.RequestedMaxKeepAliveCount >= 1
    assert params.RequestedLifetimeCount >= 3 * params.RequestedMaxKeepAliveCount


@pytest.mark.parametrize("keep_alive,lifetime", [(10, 29), (5, 1), (1000, 2999)])
def test_cli10_explicit_counts_that_break_the_3x_rule_are_refused(keep_alive: int, lifetime: int) -> None:
    """Part 4, 5.14.2.2: the client refuses a lifetime below three keep-alives before sending anything."""
    with pytest.raises(ValueError):
        subscription_parameters(100, keep_alive_count=keep_alive, lifetime_count=lifetime)


def test_cli10_explicit_counts_are_kept() -> None:
    params = subscription_parameters(100, keep_alive_count=7, lifetime_count=30)
    assert (params.RequestedMaxKeepAliveCount, params.RequestedLifetimeCount) == (7, 30)


async def test_cli10_real_server_keep_alive_cadence(opc) -> None:
    """Part 4, 5.14.1.1: with the derived counts the revised keep-alive interval is about 10 s."""
    if opc.opc is opc.server:
        pytest.skip("same check for the in-process server is not needed")
    session = opc.opc.uaclient.session
    sub = Subscription(session, subscription_parameters(100))
    await sub.init()
    assert sub.revised is not None
    assert sub.revised.publishing_interval * sub.revised.max_keep_alive_count == pytest.approx(10_000, abs=200)
    await sub.delete()


async def test_com32_revised_values_are_stored() -> None:
    """Part 4, 5.14.2.2: the Subscription keeps what the server revised, next to what it asked for."""
    session = FakeSession()
    session.revise = lambda p: ua.CreateSubscriptionResult(
        RevisedPublishingInterval=500.0, RevisedLifetimeCount=900, RevisedMaxKeepAliveCount=30
    )
    sub = Subscription(session, subscription_parameters(100))  # type: ignore[arg-type]
    await sub.init()
    assert sub.revised is not None
    assert (sub.revised.publishing_interval, sub.revised.lifetime_count, sub.revised.max_keep_alive_count) == (
        500.0,
        900,
        30,
    )
    assert sub.parameters.RequestedPublishingInterval == 100


async def test_cli10_one_correction_only() -> None:
    """Part 4, 5.14.2.2: a revised keep-alive above the limit is corrected with one Modify, never a loop."""
    session = FakeSession()
    session.revise = lambda p: ua.CreateSubscriptionResult(
        RevisedPublishingInterval=10_000.0, RevisedLifetimeCount=600, RevisedMaxKeepAliveCount=100
    )
    sub = Subscription(session, subscription_parameters(100))  # type: ignore[arg-type]
    await sub.init()
    assert len(session.modified) == 1
    modified = session.modified[0]
    assert modified.RequestedPublishingInterval == 10_000.0
    assert modified.RequestedMaxKeepAliveCount * 10_000 <= 60_000
    assert modified.RequestedLifetimeCount >= 3 * modified.RequestedMaxKeepAliveCount
    assert sub.revised is not None
    assert sub.revised.max_keep_alive_count == modified.RequestedMaxKeepAliveCount


async def test_com32_update_stores_the_result_not_the_request() -> None:
    """Part 4, 5.13.3: the stored values are the revised ones."""
    session = FakeSession()
    sub = Subscription(session, subscription_parameters(100))  # type: ignore[arg-type]
    await sub.init()
    params = ua.ModifySubscriptionParameters(
        SubscriptionId=sub.subscription_id, RequestedPublishingInterval=250.0, RequestedLifetimeCount=5,
        RequestedMaxKeepAliveCount=4,
    )  # fmt: skip
    await sub.update(params)
    assert session.modified[0].RequestedLifetimeCount == 12
    assert sub.revised is not None
    assert sub.revised.lifetime_count == 12
    assert sub.parameters.RequestedLifetimeCount == 12


async def test_com72_never_answered_subscription_becomes_stale() -> None:
    """Part 4, 5.14.1.1: no message at all within the keep-alive time is a dead Subscription."""
    session = FakeSession()
    sub = Subscription(session, subscription_parameters(100, keep_alive_count=10, lifetime_count=30))  # type: ignore[arg-type]
    await sub.init()
    assert sub.last_publish_at is None
    assert not sub.is_stale(1.5)
    sub._created_at = time.monotonic() - 100
    assert sub.is_stale(1.5)


async def test_com32_stale_uses_revised_values() -> None:
    """Part 4, 5.14.2.2: a server that raises the interval does not make the Subscription stale."""
    session = FakeSession()
    session.revise = lambda p: ua.CreateSubscriptionResult(
        RevisedPublishingInterval=10_000.0, RevisedLifetimeCount=300, RevisedMaxKeepAliveCount=10
    )
    sub = Subscription(session, subscription_parameters(100, keep_alive_count=10, lifetime_count=30))  # type: ignore[arg-type]
    await sub.init()
    sub.last_publish_at = time.monotonic() - 5
    assert not sub.is_stale(1.5)
    sub.last_publish_at = time.monotonic() - 200
    assert sub.is_stale(1.5)
