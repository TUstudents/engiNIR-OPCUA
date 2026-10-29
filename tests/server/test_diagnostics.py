"""Server diagnostics (Part 5, 6.3.3 to 6.3.5, 7.8 to 7.16, 12.8 to 12.15)."""

from __future__ import annotations

import copy
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.node import Node
from enginir_opcua.crypto.permission_rules import User, UserRole
from enginir_opcua.crypto.security_policies import SecurityPolicyBasic256Sha256
from tests.conftest import find_free_port
from tests.harness import PKI, SessionProbe
from tests.waiting import wait_until

PASSWORD = "pw"
ROLES = {"root": UserRole.SecurityAdmin, "admin": UserRole.Admin, "alice": UserRole.User, "bob": UserRole.User}
SUMMARY = ua.NodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary)
ENABLED = ua.NodeId(ua.ObjectIds.Server_ServerDiagnostics_EnabledFlag)
SESSIONS = ua.NodeId(ua.ObjectIds.Server_ServerDiagnostics_SessionsDiagnosticsSummary)
SESSION_ARRAY = ua.NodeId(ua.ObjectIds.Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionDiagnosticsArray)
SECURITY_ARRAY = ua.NodeId(
    ua.ObjectIds.Server_ServerDiagnostics_SessionsDiagnosticsSummary_SessionSecurityDiagnosticsArray
)
SUBSCRIPTION_ARRAY = ua.NodeId(ua.ObjectIds.Server_ServerDiagnostics_SubscriptionDiagnosticsArray)
SAMPLING_ARRAY = ua.NodeId(ua.ObjectIds.Server_ServerDiagnostics_SamplingIntervalDiagnosticsArray)


class RoleManager:
    def get_user(self, iserver: Any, username: str | None = None, password: str | None = None, certificate: Any = None):
        if username is None:
            return User(role=UserRole.Anonymous)
        if password == PASSWORD and username in ROLES:
            return User(role=ROLES[username], name=username)
        return None


@pytest.fixture(scope="module", name="rig")
async def make_server() -> AsyncIterator[Server]:
    server = Server(allow_no_security=True, user_manager=RoleManager())
    server.allow_plaintext_password = True
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    server.set_identity_tokens([ua.AnonymousIdentityToken, ua.UserNameIdentityToken])
    await server.load_certificate(PKI.server.certificate)
    await server.load_private_key(PKI.server.key)
    server.set_trust_store(PKI.trust_store())
    await server.start()
    yield server
    await server.stop()


@pytest.fixture(name="server")
async def reset_server(rig: Server) -> AsyncIterator[Server]:
    rig.diagnostics.enabled = False
    rig.iserver.min_session_timeout_ms = 5_000
    yield rig
    rig.diagnostics.enabled = False
    rig.iserver.min_session_timeout_ms = 5_000


async def plain(server: Server, user: str | None = "alice", **settings: Any) -> Client:
    prefix = f"{user}:{PASSWORD}@" if user else ""
    client = Client(f"opc.tcp://{prefix}127.0.0.1:{server.endpoint.port}", timeout=5, **settings)
    await client.connect()
    return client


async def encrypted(server: Server, user: str) -> Client:
    client = Client(server.endpoint.geturl(), timeout=5)
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        PKI.peer1.certificate,
        PKI.peer1.key,
        None,
        PKI.server.certificate,
        ua.MessageSecurityMode.SignAndEncrypt,
    )
    client.set_user(user)
    client.set_password(PASSWORD)
    await client.connect()
    return client


def sname(server: Server, client: Client) -> str:
    return server.iserver.session_manager.sessions[client.uaclient.session.authentication_token].name


async def read(client: Client, nodeid: ua.NodeId) -> Any:
    return await client.get_node(nodeid).read_data_value(raise_on_bad_status=False)


async def value(client: Client, nodeid: ua.NodeId) -> Any:
    return await client.get_node(nodeid).read_value()


def summary(server: Server) -> ua.ServerDiagnosticsSummaryDataType:
    return server.diagnostics.summary()


async def test_srv91_summary_counts_sessions_and_cumulated_sessions(server: Server) -> None:
    """Part 5, 12.9: current and cumulated Session counts, also through the component Variables."""
    admin = await plain(server, "admin")
    try:
        before = await value(admin, SUMMARY)
        other = await plain(server, "alice")
        during = await value(admin, SUMMARY)
        assert during.CurrentSessionCount == before.CurrentSessionCount + 1
        assert during.CumulatedSessionCount == before.CumulatedSessionCount + 1
        component = ua.NodeId(ua.ObjectIds.Server_ServerDiagnostics_ServerDiagnosticsSummary_CurrentSessionCount)
        assert await value(admin, component) == during.CurrentSessionCount
        await other.disconnect()
        after = await value(admin, SUMMARY)
        assert after.CurrentSessionCount == before.CurrentSessionCount
        assert after.CumulatedSessionCount == during.CumulatedSessionCount
    finally:
        await admin.disconnect()


async def test_srv91_summary_is_readable_when_the_flag_is_false(server: Server) -> None:
    """Part 5, 6.3.3: the counters run always; the flag decides what else is visible."""
    admin = await plain(server, "admin")
    try:
        assert await value(admin, ENABLED) is False
        assert (await read(admin, SUMMARY)).StatusCode.is_good()
        assert isinstance(await value(admin, SUMMARY), ua.ServerDiagnosticsSummaryDataType)
    finally:
        await admin.disconnect()


async def test_srv91_arrays_are_empty_when_disabled(server: Server) -> None:
    """Part 5, 6.3.3: with the collection off the arrays are empty."""
    admin = await plain(server, "admin")
    try:
        for array in (SESSION_ARRAY, SECURITY_ARRAY, SUBSCRIPTION_ARRAY):
            data = await read(admin, array)
            assert data.StatusCode.is_good()
            assert not (data.Value.Value if data.Value is not None else None)
    finally:
        await admin.disconnect()


async def test_srv91_sampling_interval_array_is_not_exposed(server: Server) -> None:
    """Part 5, 6.3.3: only servers with a fixed set of sampling intervals expose it."""
    assert SAMPLING_ARRAY not in server.iserver.aspace


async def test_srv91_session_diagnostics_fields(server: Server) -> None:
    """Part 5, 12.11: what CreateSession and the Session carried."""
    server.diagnostics.enabled = True
    admin = await plain(server, "admin")
    try:
        [entry] = [e for e in await value(admin, SESSION_ARRAY) if e.SessionName == sname(server, admin)]
        assert entry.EndpointUrl.startswith("opc.tcp://")
        assert entry.ClientDescription.ApplicationUri == admin.application_uri
        assert entry.ActualSessionTimeout > 0
        assert entry.ClientConnectionTime is not None and entry.ClientLastContactTime is not None
        assert entry.TotalRequestCount.TotalCount >= 1
    finally:
        await admin.disconnect()


async def session_object_names(client: Client) -> list[str]:
    return [(await child.read_browse_name()).Name for child in await client.get_node(SESSIONS).get_children()]


async def test_srv91_session_object_per_session_and_removed_on_close(server: Server) -> None:
    """Part 5, 6.3.4 and 6.3.5: an Object per Session, with its three Variables, while the flag is TRUE."""
    server.diagnostics.enabled = True
    admin = await plain(server, "admin")
    other = await plain(server, "alice")
    try:
        names = await session_object_names(admin)
        assert sname(server, other) in names
        [session_object] = [
            child
            for child in await admin.get_node(SESSIONS).get_children()
            if (await child.read_browse_name()).Name == sname(server, other)
        ]
        children = [(await c.read_browse_name()).Name for c in await session_object.get_children()]
        assert sorted(children) == ["SessionDiagnostics", "SessionSecurityDiagnostics", "SubscriptionDiagnosticsArray"]
        gone = sname(server, other)
        await other.disconnect()
        await wait_until(lambda: gone not in server.diagnostics.session_object_names())
    finally:
        await admin.disconnect()


async def test_srv91_dynamic_nodes_raise_no_model_change_event(server: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    """Part 3, 9.32: the diagnostics nodes are the server's own bookkeeping and raise no model change event."""
    emitted: list[Any] = []

    async def spy(changes: Any) -> None:
        emitted.append(changes)

    monkeypatch.setattr(server.iserver.model_changes, "_emit", spy)
    server.diagnostics.enabled = True
    client = await plain(server, "alice")
    gone = sname(server, client)
    await client.disconnect()
    await wait_until(lambda: gone not in server.diagnostics.session_object_names())
    assert emitted == []


async def test_srv92_enabled_flag_starts_false_and_writing_true_resets_and_creates_session_nodes(
    server: Server,
) -> None:
    """Part 5, 6.3.3: TRUE resets and enables the collection."""
    admin = await plain(server, "admin")
    try:
        assert await value(admin, ENABLED) is False
        await admin.get_node(ENABLED).write_value(True)
        assert await value(admin, ENABLED) is True
        assert sname(server, admin) in await session_object_names(admin)
        current = summary(server)
        assert current.CumulatedSessionCount == current.CurrentSessionCount
        assert current.RejectedRequestsCount == 0
    finally:
        await admin.disconnect()


async def test_srv92_disabling_keeps_counters_and_deletes_nodes(server: Server) -> None:
    """Part 5, 6.3.3: FALSE disables the collection without resetting the values."""
    server.diagnostics.enabled = True
    admin = await plain(server, "admin")
    try:
        before = summary(server).CumulatedSessionCount
        await admin.get_node(ENABLED).write_value(False)
        assert sname(server, admin) not in server.diagnostics.session_object_names()
        assert summary(server).CumulatedSessionCount == before
    finally:
        await admin.disconnect()


async def test_srv92_enabled_flag_write_needs_admin(server: Server) -> None:
    """Part 5, 6.3.3 and Part 18: only Admin and SecurityAdmin switch the collection."""
    alice = await plain(server, "alice")
    root = await plain(server, "root")
    try:
        with pytest.raises(ua.UaStatusCodeError) as denied:
            await alice.get_node(ENABLED).write_value(True)
        assert denied.value.code == ua.StatusCodes.BadUserAccessDenied
        assert server.diagnostics.enabled is False
        await root.get_node(ENABLED).write_value(True)
        assert server.diagnostics.enabled is True
    finally:
        await alice.disconnect()
        await root.disconnect()


def service_counters(server: Server, name: str) -> ua.SessionDiagnosticsDataType:
    [entry] = [e for e in server.diagnostics.session_diagnostics() if e.SessionName == name]
    return entry


async def test_srv93_service_counters_count_total_and_errors_per_service(server: Server) -> None:
    """Part 5, 12.11 and 12.13: the counter of a Service counts its requests and the ones that were refused."""
    server.diagnostics.enabled = True
    client = await plain(server, "alice")
    try:
        node = ua.ReadValueId(NodeId=ua.NodeId(ua.ObjectIds.Server_ServerStatus_State), AttributeId=13)
        reads_before = copy.deepcopy(service_counters(server, sname(server, client)))
        await client.uaclient.session.read(ua.ReadParameters(NodesToRead=[node]))
        await client.uaclient.session.read(ua.ReadParameters(NodesToRead=[node]))
        with pytest.raises(ua.UaStatusCodeError):
            await client.uaclient.session.read(ua.ReadParameters(MaxAge=-1, NodesToRead=[node]))
        counters = service_counters(server, sname(server, client))
        assert counters.ReadCount.TotalCount == reads_before.ReadCount.TotalCount + 3
        assert counters.ReadCount.ErrorCount == 1
        assert counters.TotalRequestCount.TotalCount >= reads_before.TotalRequestCount.TotalCount + 3
    finally:
        await client.disconnect()


async def test_srv93_permission_denied_counts_unauthorized_and_security_rejected(server: Server) -> None:
    """Part 5, 12.9 and 12.11: a request refused for lack of rights is unauthorized and security rejected."""
    server.diagnostics.enabled = True
    client = await plain(server, "alice")
    try:
        before = summary(server)
        with pytest.raises(ua.UaStatusCodeError):
            await client.uaclient.session.delete_nodes(
                ua.DeleteNodesParameters(NodesToDelete=[ua.DeleteNodesItem(NodeId=ua.NodeId(1, 1))])
            )
        after = summary(server)
        assert service_counters(server, sname(server, client)).UnauthorizedRequestCount == 1
        assert after.SecurityRejectedRequestsCount == before.SecurityRejectedRequestsCount + 1
        assert after.RejectedRequestsCount == before.RejectedRequestsCount + 1
    finally:
        await client.disconnect()


async def test_srv93_unsupported_service_counts_rejected_requests_only(server: Server) -> None:
    """Part 5, 12.9: a service the server does not implement is a rejected request, not a security one."""
    server.diagnostics.enabled = True
    client = await plain(server, "alice")
    try:
        before = summary(server)
        with pytest.raises(ua.UaStatusCodeError):
            await client.uaclient._send_request(ua.QueryFirstRequest())
        after = summary(server)
        assert after.RejectedRequestsCount == before.RejectedRequestsCount + 1
        assert after.SecurityRejectedRequestsCount == before.SecurityRejectedRequestsCount
    finally:
        await client.disconnect()


async def test_srv93_idle_session_counts_as_timeout(server: Server) -> None:
    """Part 5, 12.9: a Session closed because its timeout elapsed."""
    server.iserver.min_session_timeout_ms = 100
    before = summary(server).SessionTimeoutCount
    client = Client(f"opc.tcp://127.0.0.1:{server.endpoint.port}", timeout=5, watchdog_intervall=60)
    client.session_timeout = 300
    await client.connect()
    try:
        await wait_until(lambda: summary(server).SessionTimeoutCount == before + 1, timeout=10)
    finally:
        client.disconnect_socket()


async def test_srv93_session_without_activation_on_a_lost_channel_counts_as_abort(server: Server) -> None:
    """Part 5, 12.9: a Session that was never activated and lost its channel was closed by an error."""
    probe = await SessionProbe.open(f"opc.tcp://127.0.0.1:{server.endpoint.port}")
    before = summary(server).SessionAbortCount
    await probe.create_session()
    probe.close()
    await wait_until(lambda: summary(server).SessionAbortCount == before + 1)


async def test_srv93_close_session_counts_neither_timeout_nor_abort(server: Server) -> None:
    """Part 5, 12.9: an orderly CloseSession is no error."""
    before = summary(server)
    client = await plain(server, "alice")
    await client.disconnect()
    await wait_until(lambda: summary(server).CurrentSessionCount == before.CurrentSessionCount)
    after = summary(server)
    assert (after.SessionTimeoutCount, after.SessionAbortCount) == (
        before.SessionTimeoutCount,
        before.SessionAbortCount,
    )


async def test_srv93_bad_identity_counts_security_rejected_session(server: Server) -> None:
    """Part 5, 12.9: a refused identity is a security-rejected Session establishment."""
    before = summary(server)
    client = Client(f"opc.tcp://alice:wrong@127.0.0.1:{server.endpoint.port}", timeout=5)
    with pytest.raises(ua.UaStatusCodeError):
        await client.connect()
    after = summary(server)
    assert after.SecurityRejectedSessionCount == before.SecurityRejectedSessionCount + 1
    assert after.RejectedSessionCount == before.RejectedSessionCount + 1


async def test_srv93_bad_nonce_counts_rejected_session_but_not_security_rejected(server: Server) -> None:
    """Part 5, 12.9: rejected Session establishment that is not a security matter."""
    before = summary(server)
    probe = await SessionProbe.open(f"opc.tcp://127.0.0.1:{server.endpoint.port}")
    try:
        with pytest.raises(ua.UaStatusCodeError):
            await probe.create_session(client_nonce=b"short")
    finally:
        probe.close()
    after = summary(server)
    assert after.RejectedSessionCount == before.RejectedSessionCount + 1
    assert after.SecurityRejectedSessionCount == before.SecurityRejectedSessionCount


async def subscription_entry(server: Server, subscription_id: int) -> ua.SubscriptionDiagnosticsDataType:
    [entry] = [e for e in server.diagnostics.subscription_diagnostics() if e.SubscriptionId == subscription_id]
    return entry


async def test_srv93_subscription_counters_follow_modify_enable_republish_and_notifications(server: Server) -> None:
    """Part 5, 12.15: the counters of a Subscription."""
    server.diagnostics.enabled = True
    client = await plain(server, "admin")
    notes: list[Any] = []

    class Handler:
        def datachange_notification(self, node: Node, val: Any, data: Any) -> None:
            notes.append(val)

    try:
        local = await server.nodes.objects.add_variable(ua.NodeId("diag", 2), "2:diag", 1)
        await local.set_writable()
        variable = client.get_node(local.nodeid)
        subscription = await client.create_subscription(50, Handler())
        subscription_id = subscription.subscription_id
        await subscription.subscribe_data_change(variable)
        await wait_until(lambda: len(notes) >= 1)
        await variable.write_value(2)
        await wait_until(lambda: len(notes) >= 2)
        await subscription.modify_subscription(100) if hasattr(subscription, "modify_subscription") else None
        params = ua.SetPublishingModeParameters(PublishingEnabled=False, SubscriptionIds=[subscription_id])
        await client.uaclient.session.set_publishing_mode(params)
        params.PublishingEnabled = True
        await client.uaclient.session.set_publishing_mode(params)
        with pytest.raises(ua.UaStatusCodeError):
            await client.uaclient.session.republish(subscription_id, 99999)
        entry = await subscription_entry(server, subscription_id)
        assert entry.DisableCount == 1
        assert entry.EnableCount == 1
        assert entry.RepublishRequestCount == 1
        assert entry.RepublishMessageRequestCount == 1
        assert entry.RepublishMessageCount == 0
        assert entry.DataChangeNotificationsCount >= 2
        assert entry.NotificationsCount == entry.DataChangeNotificationsCount + entry.EventNotificationsCount
        assert entry.PublishRequestCount >= 1
        assert entry.MonitoredItemCount == 1
        assert entry.PublishingInterval == 50
        summary_now = summary(server)
        assert summary_now.CurrentSubscriptionCount >= 1
        assert summary_now.CumulatedSubscriptionCount >= summary_now.CurrentSubscriptionCount
        assert summary_now.PublishingIntervalCount >= 1
    finally:
        await client.disconnect()


async def test_srv93_transfer_counts_move_to_the_same_client(server: Server) -> None:
    """Part 5, 12.15: a Subscription that moves to another Session of the same client."""
    server.diagnostics.enabled = True
    first = await plain(server, "alice")
    second = await plain(server, "alice")
    try:
        subscription = await first.create_subscription(
            100, type("H", (), {"datachange_notification": lambda *a: None})()
        )
        params = ua.TransferSubscriptionsParameters(
            SubscriptionIds=[subscription.subscription_id], SendInitialValues=False
        )
        await second.uaclient.session.transfer_subscriptions(params)
        entry = await subscription_entry(server, subscription.subscription_id)
        assert entry.TransferRequestCount == 1
        assert entry.TransferredToSameClientCount == 1
        assert entry.TransferredToAltClientCount == 0
    finally:
        await first.disconnect()
        await second.disconnect()


async def security_entries(client: Client) -> Any:
    return await read(client, SECURITY_ARRAY)


async def test_srv94_security_diagnostics_only_for_security_admin_on_encrypted_channel(server: Server) -> None:
    """Part 5, 6.3.4 and 12.12: security-related data for authorised users over encrypted channels."""
    server.diagnostics.enabled = True
    root_secure = await encrypted(server, "root")
    admin_secure = await encrypted(server, "admin")
    root_plain = await plain(server, "root")
    try:
        data = await security_entries(root_secure)
        assert data.StatusCode.is_good()
        names = {e.ClientUserIdOfSession for e in data.Value.Value}
        assert {"root", "admin"} <= names
        entry = next(e for e in data.Value.Value if e.ClientUserIdOfSession == "root" and e.SecurityMode)
        assert entry.SecurityPolicyUri == SecurityPolicyBasic256Sha256.URI
        assert entry.Encoding == "UA Binary" and entry.TransportProtocol == "opc.tcp"
        assert entry.AuthenticationMechanism == "UserName"
        assert (await security_entries(admin_secure)).StatusCode.value == ua.StatusCodes.BadUserAccessDenied
        assert (await security_entries(root_plain)).StatusCode.value == ua.StatusCodes.BadUserAccessDenied
    finally:
        for client in (root_secure, admin_secure, root_plain):
            await client.disconnect()


async def security_variable(client: Client, owner_name: str) -> Node:
    [session_object] = [
        child
        for child in await client.get_node(SESSIONS).get_children()
        if (await child.read_browse_name()).Name == owner_name
    ]
    return await session_object.get_child("0:SessionSecurityDiagnostics")


async def test_srv94_own_session_may_read_its_security_diagnostics_on_an_encrypted_channel(server: Server) -> None:
    """Part 5, 6.3.5 and 12.12: a Session may see its own security diagnostics, but not another one's."""
    server.diagnostics.enabled = True
    alice = await encrypted(server, "alice")
    bob = await encrypted(server, "bob")
    try:
        own: Any = await (await security_variable(alice, sname(server, alice))).read_data_value(
            raise_on_bad_status=False
        )
        assert own.StatusCode.is_good()
        assert own.Value.Value.ClientUserIdOfSession == "alice"
        foreign: Any = await (await security_variable(alice, sname(server, bob))).read_data_value(
            raise_on_bad_status=False
        )
        assert foreign.StatusCode.value == ua.StatusCodes.BadUserAccessDenied
    finally:
        await alice.disconnect()
        await bob.disconnect()


async def test_srv94_subscription_sampling_does_not_leak_security_diagnostics(server: Server) -> None:
    """Part 5, 12.12: a monitored item reads as the owner of its Subscription, so it is refused too."""
    server.diagnostics.enabled = True
    alice = await encrypted(server, "alice")
    statuses: list[Any] = []

    class Handler:
        def datachange_notification(self, node: Node, val: Any, data: Any) -> None:
            statuses.append(data.monitored_item.Value.StatusCode)

    try:
        subscription = await alice.create_subscription(50, Handler())
        await subscription.subscribe_data_change(alice.get_node(SECURITY_ARRAY))
        await wait_until(lambda: bool(statuses))
        assert all(status.value == ua.StatusCodes.BadUserAccessDenied for status in statuses)
    finally:
        await alice.disconnect()
