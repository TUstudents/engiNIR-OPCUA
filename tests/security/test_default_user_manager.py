from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.server.user_managers import (
    AnonymousReadOnlyUserManager,
    CertificateUserManager,
    PermissiveUserManager,
    UserManager,
)
from tests.conftest import find_free_port


async def _started(**server_arguments: Any) -> Server:
    srv = Server(**server_arguments)
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    return srv


@pytest.fixture
async def default_server() -> AsyncIterator[Server]:
    srv = await _started()
    variable = await srv.nodes.objects.add_variable(2, "Setpoint", 1.0)
    await variable.set_writable()
    yield srv
    await srv.stop()


def test_srv7_default_user_manager_is_anonymous_read_only() -> None:
    """Part 4, 7.40.1: a server without a configured user manager accepts Anonymous only."""
    srv = Server()
    assert isinstance(srv.iserver.user_manager, AnonymousReadOnlyUserManager)
    assert not isinstance(srv.iserver.user_manager, PermissiveUserManager)


def test_srv7_remote_admin_switch_is_gone() -> None:
    """Part 4, 7.40.1: there is no built-in Admin user to switch on or off."""
    assert not hasattr(Server, "allow_remote_admin")
    assert not hasattr(Server().iserver, "allow_remote_admin")


async def test_srv7_default_server_offers_only_anonymous(default_server: Server) -> None:
    """Part 4, 7.41: the endpoints list only the UserTokenPolicies the server can accept."""
    for endpoint in await default_server.get_endpoints():
        assert {policy.TokenType for policy in endpoint.UserIdentityTokens} == {ua.UserTokenType.Anonymous}


@pytest.mark.parametrize("user", ["admin", "Admin", "alice"])
async def test_srv7_default_server_rejects_username_tokens(default_server: Server, user: str) -> None:
    """Part 4, 5.7.3.2: without a user manager no UserName policy is offered, so the client does not try one."""
    client = Client(default_server.endpoint.geturl())
    client.set_user(user)
    client.set_password("anything")
    with pytest.raises(ua.uaerrors.ConfigurationError):
        await client.connect()
    await client.disconnect()


async def test_srv7_default_server_anonymous_reads_but_does_not_write(default_server: Server) -> None:
    """Part 4, 5.7.3.1: the default user is Anonymous, which reads and cannot write."""
    async with Client(default_server.endpoint.geturl()) as client:
        variable = client.get_node(await default_server.nodes.objects.get_child("2:Setpoint"))
        assert await variable.read_value() == 1.0
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await variable.write_value(2.0)


async def test_srv7_permissive_manager_is_an_explicit_opt_in() -> None:
    """Part 4, 7.40.1: an application that wants every login accepted has to ask for it."""
    srv = Server(user_manager=PermissiveUserManager())
    srv.allow_plaintext_password = True
    await srv.init()
    srv.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    await srv.start()
    try:
        async with Client(srv.endpoint.geturl().replace("//", "//admin@")) as client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
    finally:
        await srv.stop()


async def test_srv7_certificate_manager_refuses_anonymous_by_default() -> None:
    """Part 4, 5.7.3.2: with a CertificateUserManager an Anonymous login without a registered certificate is refused."""
    srv = await _started(user_manager=CertificateUserManager())
    try:
        client = Client(srv.endpoint.geturl())
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await client.connect()
        await client.disconnect()
    finally:
        await srv.stop()


async def test_srv7_certificate_manager_accepts_anonymous_when_allowed() -> None:
    """Part 4, 5.7.3.2: allow_anonymous lets Anonymous in, as the read-only role."""
    srv = await _started(user_manager=CertificateUserManager(allow_anonymous=True))
    try:
        async with Client(srv.endpoint.geturl()) as client:
            assert await client.nodes.server_state.read_value() == ua.ServerState.Running
            with pytest.raises(ua.uaerrors.BadUserAccessDenied):
                await client.nodes.server_state.write_value(1)
    finally:
        await srv.stop()


async def test_srv7_custom_manager_without_token_types_keeps_all_configured_tokens() -> None:
    """Part 4, 7.41: a manager that doesn't list token types is offered every token class the server supports."""

    class Duck:
        def get_user(self, iserver: Any, username: Any = None, password: Any = None, certificate: Any = None) -> None:
            return None

    srv = Server(user_manager=Duck())  # type: ignore[arg-type]
    assert set(srv.iserver.offered_token_classes()) == set(srv.iserver.supported_tokens)
    assert UserManager.accepted_token_types == {
        ua.UserTokenType.Anonymous,
        ua.UserTokenType.UserName,
        ua.UserTokenType.Certificate,
    }
