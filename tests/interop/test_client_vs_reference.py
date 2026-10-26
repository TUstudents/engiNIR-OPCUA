import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from enginir_opcua import Client, ua
from enginir_opcua.client.client import UaClientState

from .support import SECURITY_CASES, ClientIdentity, SecurityCase, connect, protocol_of, reference_nodeid

pytestmark = pytest.mark.interop

ALARMS_NAMESPACE_URI = "http://test.org/UA/Alarms/"


class Collector:
    def __init__(self) -> None:
        self.values: list[Any] = []
        self.events: list[Any] = []

    def datachange_notification(self, node: Any, val: Any, data: Any) -> None:
        self.values.append(val)

    def event_notification(self, event: Any) -> None:
        self.events.append(event)


async def wait_for(condition: Any, timeout: float = 15.0) -> None:
    async with asyncio.timeout(timeout):
        while not condition():
            await asyncio.sleep(0.05)


async def node_id(client: Client, identifier: str) -> ua.NodeId:
    return reference_nodeid(await client.get_namespace_array(), identifier)


async def test_get_endpoints_lists_every_policy_of_the_matrix(reference_server_url: str) -> None:
    client = Client(reference_server_url)
    endpoints = await client.connect_and_get_server_endpoints()
    offered = {(endpoint.SecurityPolicyUri, endpoint.SecurityMode) for endpoint in endpoints}
    for case in SECURITY_CASES:
        uri = case.policy.URI if case.policy is not None else "http://opcfoundation.org/UA/SecurityPolicy#None"
        assert (uri, case.mode) in offered


async def test_find_servers_returns_the_reference_server(reference_server_url: str) -> None:
    client = Client(reference_server_url)
    await client.connect_socket()
    try:
        await client.send_hello()
        await client.open_secure_channel()
        servers = await client.find_servers()
        await client.close_secure_channel()
    finally:
        client.disconnect_socket()
    assert any(server.ApplicationUri for server in servers)
    assert any("ReferenceServer" in url for server in servers for url in server.DiscoveryUrls)


async def test_connect_reads_server_state(client: Client) -> None:
    state = await client.nodes.server_state.read_value()
    assert state == ua.ServerState.Running


async def test_browse_objects_folder(client: Client) -> None:
    names = {(await child.read_browse_name()).Name for child in await client.nodes.objects.get_children()}
    assert {"Server", "CTT", "Data"} <= names


async def test_read_scalar_types(client: Client) -> None:
    for identifier, variant_type in [
        ("Scalar_Static_Int32", ua.VariantType.Int32),
        ("Scalar_Static_Double", ua.VariantType.Double),
        ("Scalar_Static_String", ua.VariantType.String),
        ("Scalar_Static_DateTime", ua.VariantType.DateTime),
        ("Scalar_Static_Guid", ua.VariantType.Guid),
        ("Scalar_Static_LocalizedText", ua.VariantType.LocalizedText),
    ]:
        node = client.get_node(await node_id(client, identifier))
        data_value = await node.read_data_value()
        assert data_value.StatusCode is not None and data_value.StatusCode.is_good()
        assert data_value.Value is not None
        assert data_value.Value.VariantType == variant_type


async def test_write_and_read_back(client: Client) -> None:
    int_node = client.get_node(await node_id(client, "Scalar_Static_Int32"))
    string_node = client.get_node(await node_id(client, "Scalar_Static_String"))
    await int_node.write_value(ua.Variant(123456, ua.VariantType.Int32))
    await string_node.write_value(ua.Variant("interop ü 試験", ua.VariantType.String))
    assert await int_node.read_value() == 123456
    assert await string_node.read_value() == "interop ü 試験"


async def test_large_array_write_and_read_needs_many_chunks(client: Client) -> None:
    node = client.get_node(await node_id(client, "Scalar_Static_Arrays_Double"))
    values = [i * 0.5 for i in range(20_000)]
    await node.write_value(ua.Variant(values, ua.VariantType.Double))
    assert await node.read_value() == values


async def test_method_call(client: Client) -> None:
    parent = client.get_node(await node_id(client, "Methods"))
    method = await node_id(client, "Methods_Add")
    result = await parent.call_method(
        method, ua.Variant(3.0, ua.VariantType.Float), ua.Variant(4, ua.VariantType.UInt32)
    )
    assert result == 7.0


async def test_subscription_delivers_data_changes(client: Client) -> None:
    collector = Collector()
    subscription = await client.create_subscription(100, collector)
    node = client.get_node(await node_id(client, "Scalar_Simulation_Int32"))
    await subscription.subscribe_data_change(node)
    await wait_for(lambda: len(set(collector.values)) >= 3)
    await subscription.delete()


async def test_subscription_delivers_events(client: Client) -> None:
    collector = Collector()
    subscription = await client.create_subscription(200, collector)
    await subscription.subscribe_events(client.nodes.server)
    namespaces = await client.get_namespace_array()
    alarms = ua.NodeId("Alarms", namespaces.index(ALARMS_NAMESPACE_URI))
    start = ua.NodeId("Alarms.Start", alarms.NamespaceIndex)
    await client.get_node(alarms).call_method(start, ua.Variant(30, ua.VariantType.UInt32))
    await wait_for(lambda: len(collector.events) >= 2)
    assert all(event.Severity > 0 for event in collector.events)
    await subscription.delete()


async def test_channel_token_renewal_with_short_requested_lifetime(
    matrix_case: tuple[SecurityCase, str], reference_server_url: str, identity: ClientIdentity
) -> None:
    case, user = matrix_case
    client = await connect(reference_server_url, identity, case, user, channel_lifetime_ms=3000)
    try:
        channel = protocol_of(client)._channel
        first_token = channel.security_token.TokenId
        for _ in range(2):
            await client.open_secure_channel(renew=True)
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
        assert channel.security_token.TokenId > first_token
    finally:
        await client.disconnect()


async def test_reconnect_keeps_session_and_subscription(
    matrix_case: tuple[SecurityCase, str], reference_server_url: str, identity: ClientIdentity
) -> None:
    case, user = matrix_case
    client = await connect(
        reference_server_url,
        identity,
        case,
        user,
        timeout=5,
        watchdog_intervall=0.5,
        auto_reconnect=True,
        reconnect_max_delay=1.0,
    )
    try:
        collector = Collector()
        subscription = await client.create_subscription(100, collector)
        node = client.get_node(await node_id(client, "Scalar_Simulation_Int32"))
        await subscription.subscribe_data_change(node)
        await wait_for(lambda: len(collector.values) >= 1)
        session_token = client.uaclient.session.authentication_token
        old_channel_id = protocol_of(client)._channel.security_token.ChannelId
        async with client.subscribe_state() as states:
            transport = protocol_of(client).transport
            assert transport is not None
            transport.close()
            left = False
            async with asyncio.timeout(30):
                while True:
                    state = await states.next_change()
                    left = left or state is not UaClientState.CONNECTED
                    if left and state is UaClientState.CONNECTED:
                        break
        assert protocol_of(client)._channel.security_token.ChannelId != old_channel_id
        assert client.uaclient.session.authentication_token == session_token
        seen = len(collector.values)
        await wait_for(lambda: len(collector.values) >= seen + 2)
        await subscription.delete()
    finally:
        await client.disconnect()


async def test_transfer_subscriptions_to_a_second_session(
    matrix_case: tuple[SecurityCase, str], client: Client, reference_server_url: str, identity: ClientIdentity
) -> None:
    case, user = matrix_case
    if case.policy is None:
        pytest.skip("an anonymous session on the None policy has no client certificate to prove ownership with")
    collector = Collector()
    subscription = await client.create_subscription(100, collector)
    node = client.get_node(await node_id(client, "Scalar_Simulation_Int32"))
    await subscription.subscribe_data_change(node)
    await wait_for(lambda: len(collector.values) >= 1)
    assert subscription.subscription_id is not None
    second = await connect(reference_server_url, identity, case, user)
    try:
        params = ua.TransferSubscriptionsParameters(
            SubscriptionIds=[subscription.subscription_id], SendInitialValues=True
        )
        results = await second.uaclient.transfer_subscriptions(params)
        assert results[0].StatusCode.is_good()
        response = await asyncio.wait_for(second.uaclient.publish([]), 15)
        assert response.Parameters.SubscriptionId == subscription.subscription_id
        for number in results[0].AvailableSequenceNumbers[:1]:
            message = await second.uaclient.session.republish(subscription.subscription_id, number)
            assert message.SequenceNumber == number
    finally:
        await second.disconnect()


async def test_history_read_when_the_server_exposes_history(client: Client) -> None:
    node = client.get_node(await node_id(client, "Scalar_Simulation_Int32"))
    now = datetime.now(UTC)
    try:
        values = await node.read_raw_history(now - timedelta(minutes=5), now, 10)
    except ua.uaerrors.BadHistoryOperationUnsupported:
        pytest.skip("the reference server does not expose history")
    assert values


async def test_load_data_type_definitions_of_the_server_types(client: Client, restore_ua_registry: None) -> None:
    definitions = await client.load_data_type_definitions()
    assert definitions
