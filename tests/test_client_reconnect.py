import asyncio
import json
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.client.ua_client import UaClientState

from .conftest import find_free_port


@pytest.fixture
async def local_server() -> AsyncIterator[Server]:
    server = Server(allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    await server.start()
    yield server
    await server.stop()


async def drop_transport(client: Client) -> None:
    protocol = client.uaclient.protocol
    assert protocol is not None and protocol.transport is not None
    protocol.transport.close()


async def wait_for_state(client: Client, state: UaClientState, timeout: float = 8.0) -> None:
    async with asyncio.timeout(timeout):
        while client.state is not state:
            await asyncio.sleep(0.02)


async def reconnect_cycle(client: Client, timeout: float = 10.0) -> None:
    async with client.subscribe_state() as states:
        await drop_transport(client)
        async with asyncio.timeout(timeout):
            while await states.next_change() is not UaClientState.RECONNECTING:
                pass
            while await states.next_change() is not UaClientState.CONNECTED:
                pass


async def reconnecting_client(server: Server, **settings: Any) -> Client:
    client = Client(server.endpoint.geturl(), timeout=1.0, watchdog_intervall=0.2)
    await client.connect(auto_reconnect=True, reconnect_max_delay=0.3, reconnect_request_timeout=5.0)
    for name, value in settings.items():
        setattr(client, name, value)
    return client


async def test_cli40_reconnect_shows_only_reconnecting_until_connected(local_server: Server) -> None:
    """Part 4, 6.7: the observable state of a reconnect is RECONNECTING until the client is connected again."""
    client = await reconnecting_client(local_server)
    try:
        async with client.subscribe_state() as states:
            await drop_transport(client)
            seen: list[UaClientState] = []
            async with asyncio.timeout(8):
                while not seen or seen[-1] is not UaClientState.CONNECTED:
                    seen.append(await states.next_change())
        assert seen == [UaClientState.RECONNECTING, UaClientState.CONNECTED]
    finally:
        await client.disconnect()


async def test_cli41_denied_server_state_read_is_not_a_connection_loss(local_server: Server) -> None:
    """Part 4, 6.7: an answer, even a refusal, proves that the server is there."""
    client = await reconnecting_client(local_server)
    lost: list[Exception] = []

    async def on_lost(exc: Exception) -> None:
        lost.append(exc)

    client.connection_lost_callback = on_lost

    async def denied() -> Any:
        raise ua.uaerrors.BadUserAccessDenied

    client.nodes.server_state.read_value = denied  # type: ignore[method-assign]
    try:
        await asyncio.sleep(1.0)
        assert lost == []
        assert client.state is UaClientState.CONNECTED
    finally:
        await client.disconnect()


async def test_cli31_timeout_during_activate_keeps_the_session(local_server: Server) -> None:
    """Part 4, 6.7: a new Session is created only when ActivateSession shows that the old one is gone."""
    client = await reconnecting_client(local_server)
    token = client.uaclient.session.authentication_token
    creations: list[int] = []
    real_create = client.uaclient.session.create_session

    async def counting_create(parameters: ua.CreateSessionParameters) -> ua.CreateSessionResult:
        creations.append(1)
        return await real_create(parameters)

    client.uaclient.session.create_session = counting_create  # type: ignore[method-assign]
    real_activate = client._activate_with_credentials
    failures: list[int] = []

    async def failing_once() -> ua.ActivateSessionResult:
        if not failures:
            failures.append(1)
            raise TimeoutError
        return await real_activate()

    client._activate_with_credentials = failing_once  # type: ignore[method-assign]
    try:
        await reconnect_cycle(client)
        assert failures == [1]
        assert creations == []
        assert client.uaclient.session.authentication_token == token
    finally:
        await client.disconnect()


async def test_cli31_repeated_activation_failures_create_a_new_session(local_server: Server) -> None:
    """After max_activation_failures failures in a row that are not a lost connection, a new Session is made."""
    client = await reconnecting_client(local_server)
    client._max_activation_failures = 2
    token = client.uaclient.session.authentication_token
    real_activate = client._activate_with_credentials
    failures: list[int] = []

    async def failing_twice() -> ua.ActivateSessionResult:
        if client.uaclient.session.authentication_token == token and len(failures) < 2:
            failures.append(1)
            raise TimeoutError
        return await real_activate()

    client._activate_with_credentials = failing_twice  # type: ignore[method-assign]
    try:
        await reconnect_cycle(client)
        assert client.uaclient.session.authentication_token != token
    finally:
        await client.disconnect()


async def test_cli30_record_is_rewritten_after_reconnect(local_server: Server, tmp_path: Path) -> None:
    """Part 4, 6.7: the persisted session record follows the nonce of every ActivateSession."""
    path = tmp_path / "session.json"
    client = Client(local_server.endpoint.geturl(), timeout=1.0, watchdog_intervall=0.2)
    client.session_state_path = path
    await client.connect(auto_reconnect=True, reconnect_max_delay=0.3, reconnect_request_timeout=5.0)
    try:
        before = json.loads(path.read_text())
        await asyncio.sleep(0.05)
        await reconnect_cycle(client)
        after = json.loads(path.read_text())
        assert after["saved_at"] > before["saved_at"]
        assert after["server_nonce"] == (client._server_nonce.hex() if client._server_nonce else None)
    finally:
        await client.disconnect()


async def test_cli32_no_publish_is_sent_before_restore_finished(local_server: Server) -> None:
    """Part 4, 6.7: Subscriptions are restored (Republish) before the normal Publish handling starts again."""
    variable = await local_server.get_objects_node().add_variable(2, "RestoreVar", 0)
    client = await reconnecting_client(local_server)
    log: list[str] = []
    try:
        subscription = await client.create_subscription(50)
        await subscription.subscribe_data_change(client.get_node(variable.nodeid))
        await asyncio.sleep(0.3)
        session = client.uaclient.session
        real_publish = session.publish
        real_restore = subscription.restore

        async def logging_publish(*arguments: Any, **keywords: Any) -> Any:
            log.append("publish")
            return await real_publish(*arguments, **keywords)

        async def slow_restore() -> None:
            log.append("restore-start")
            await asyncio.sleep(0.5)
            await real_restore()
            log.append("restore-end")

        session.publish = logging_publish  # type: ignore[method-assign]
        subscription.restore = slow_restore  # type: ignore[method-assign]
        log.append("lost")
        await reconnect_cycle(client)
        after_loss = log[log.index("lost") :]
        assert "restore-end" in after_loss
        first_publish = after_loss.index("publish") if "publish" in after_loss else len(after_loss)
        assert first_publish > after_loss.index("restore-end")
    finally:
        await client.disconnect()


async def test_cli39_stale_watchdog_survives_an_escalation(local_server: Server) -> None:
    """The stale-Subscription check keeps running after it escalated to a reconnect."""
    variable = await local_server.get_objects_node().add_variable(2, "WatchdogVar", 0)
    client = await reconnecting_client(local_server)
    client._stale_check_interval = 0.1
    try:
        subscription = await client.create_subscription(50)
        await subscription.subscribe_data_change(client.get_node(variable.nodeid))
        await asyncio.sleep(0.3)

        async def failing() -> None:
            raise RuntimeError("recreate failed")

        subscription.recreate = failing  # type: ignore[method-assign]
        client.uaclient.session._subscription_callbacks[subscription.subscription_id] = lambda _r: None  # type: ignore[index]
        async with client.subscribe_state() as states:
            subscription.last_publish_at = time.monotonic() - 1000
            await states.wait_for_state(UaClientState.RECONNECTING, timeout=5)
            await states.wait_for_state(UaClientState.CONNECTED, timeout=10)
        await asyncio.sleep(0.3)
        assert client._stale_watchdog_task is not None and not client._stale_watchdog_task.done()
    finally:
        await client.disconnect()


async def test_cli5_messages_fetched_with_republish_are_acknowledged_in_the_next_publish(
    local_server: Server,
) -> None:
    """Part 4, 5.14.1.1: after a restore with gaps, the next Publish request acknowledges what Republish returned."""
    variable = await local_server.get_objects_node().add_variable(2, "GapVar", 0)
    await variable.set_writable()
    client = await reconnecting_client(local_server)
    try:
        subscription = await client.create_subscription(50)
        await subscription.subscribe_data_change(client.get_node(variable.nodeid))
        await asyncio.sleep(0.3)
        session = client.uaclient.session
        republished: list[tuple[int, int]] = []
        carried: list[tuple[int, int]] = []
        real_acknowledge = session.acknowledge
        real_publish = session.publish

        def acknowledge(subscription_id: int, sequence_number: int) -> None:
            republished.append((subscription_id, sequence_number))
            real_acknowledge(subscription_id, sequence_number)

        async def publish(acks: list[ua.SubscriptionAcknowledgement], *arguments: Any) -> Any:
            carried.extend((a.SubscriptionId, a.SequenceNumber) for a in acks)
            return await real_publish(acks, *arguments)

        session.acknowledge = acknowledge  # type: ignore[method-assign]
        session.publish = publish  # type: ignore[method-assign]
        real_connect_socket = client.connect_socket
        delayed: list[int] = []

        async def slow_connect_socket() -> None:
            if not delayed:
                delayed.append(1)
                for value in range(1, 8):
                    await variable.write_value(value)
                    await asyncio.sleep(0.1)
            await real_connect_socket()

        client.connect_socket = slow_connect_socket  # type: ignore[method-assign]
        await reconnect_cycle(client)
        await asyncio.sleep(0.5)
        gap_acks = [ack for ack in republished if ack[1] > 0]
        assert gap_acks
        assert set(gap_acks) <= set(carried)
    finally:
        await client.disconnect()
