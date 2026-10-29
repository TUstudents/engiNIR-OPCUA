import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto import security_policies
from enginir_opcua.crypto.permission_rules import ROLE_RANK, SimpleRoleRuleset, User, UserRole
from enginir_opcua.server.service_dispatch import Permission
from enginir_opcua.server.service_handlers import build_service_table
from enginir_opcua.server.user_managers import CertificateUserManager
from tests.conftest import find_free_port
from tests.pki import generated_pki

uri_crypto_cert = f"opc.tcp://127.0.0.1:{find_free_port()}"
PKI = generated_pki()
srv_crypto_params = (PKI.server.key, PKI.server.certificate)

admin_peer_creds = {"certificate": PKI.peer1.certificate, "private_key": PKI.peer1.key}

user_peer_creds = {"certificate": PKI.peer2.certificate, "private_key": PKI.peer2.key}

anonymous_peer_creds = {"certificate": PKI.peer3.certificate, "private_key": PKI.peer3.key}


@pytest.fixture(scope="module")
async def srv_crypto_one_cert(request):
    cert_user_manager = CertificateUserManager()
    admin_peer_certificate = admin_peer_creds["certificate"]
    user_peer_certificate = user_peer_creds["certificate"]
    anonymous_peer_certificate = anonymous_peer_creds["certificate"]
    key, cert = srv_crypto_params
    await cert_user_manager.add_admin(admin_peer_certificate, name="Admin")
    await cert_user_manager.add_user(user_peer_certificate, name="User")
    await cert_user_manager.add_role(anonymous_peer_certificate, name="Anonymous", user_role=UserRole.Anonymous)
    srv = Server(allow_no_security=True, user_manager=cert_user_manager)

    srv.set_endpoint(uri_crypto_cert)
    srv.set_security_policy([ua.SecurityPolicyType.NoSecurity, ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await srv.init()
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    idx = 0
    myobj = await srv.nodes.objects.add_object(idx, "MyObject")
    myvar = await myobj.add_variable(idx, "MyVariable", 0.0)
    await myvar.set_writable()  # Set MyVariable to be writable by clients

    await srv.start()
    yield srv
    # stop the server
    await srv.delete_nodes([myobj, myvar])
    await srv.stop()


async def test_client_admin(srv_crypto_one_cert):
    clt = Client(uri_crypto_cert)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        admin_peer_creds["certificate"],
        admin_peer_creds["private_key"],
        None,
        server_certificate=srv_crypto_params[1],
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )

    async with clt:
        assert await clt.get_objects_node().get_children()
        objects = clt.nodes.objects
        child = await objects.get_child(["0:MyObject", "0:MyVariable"])
        await child.set_value(42.0)
        assert await child.read_value() == 42.0
        await child.add_property(2, "MyProperty1", 3)


async def test_client_user(srv_crypto_one_cert):
    clt = Client(uri_crypto_cert)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        user_peer_creds["certificate"],
        user_peer_creds["private_key"],
        None,
        server_certificate=srv_crypto_params[1],
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    async with clt:
        assert await clt.get_objects_node().get_children()
        objects = clt.nodes.objects
        child = await objects.get_child(["0:MyObject", "0:MyVariable"])
        await child.set_value(44.0)
        assert await child.read_value() == 44.0
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await child.add_property(0, "MyProperty2", 3)


async def test_client_anonymous(srv_crypto_one_cert):
    clt = Client(uri_crypto_cert)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        anonymous_peer_creds["certificate"],
        anonymous_peer_creds["private_key"],
        None,
        server_certificate=srv_crypto_params[1],
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    async with clt:
        await clt.get_endpoints()
        assert await clt.nodes.objects.get_children()
        child = await clt.nodes.objects.get_child(["0:MyObject", "0:MyVariable"])
        assert await child.read_value() is not None
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await child.set_value(1.0)


async def test_x509identity_user(srv_crypto_one_cert):
    clt = Client(uri_crypto_cert)
    await clt.load_client_certificate(user_peer_creds["certificate"])
    await clt.load_private_key(user_peer_creds["private_key"])
    async with clt:
        assert await clt.get_objects_node().get_children()
        objects = clt.nodes.objects
        child = await objects.get_child(["0:MyObject", "0:MyVariable"])
        await child.set_value(46.0)
        assert await child.read_value() == 46.0
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await child.add_property(0, "MyProperty3", 3)


async def test_x509identity_anonymous(srv_crypto_one_cert):
    clt = Client(uri_crypto_cert)
    await clt.load_client_certificate(anonymous_peer_creds["certificate"])
    await clt.load_private_key(anonymous_peer_creds["private_key"])
    async with clt:
        await clt.get_endpoints()
        assert await clt.nodes.objects.get_children()
        child = await clt.nodes.objects.get_child(["0:MyObject", "0:MyVariable"])
        assert await child.read_value() is not None
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await child.set_value(1.0)


async def test_client_user_x509identity_admin(srv_crypto_one_cert):
    clt = Client(uri_crypto_cert)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        user_peer_creds["certificate"],
        user_peer_creds["private_key"],
        None,
        server_certificate=srv_crypto_params[1],
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    await clt.load_client_certificate(admin_peer_creds["certificate"])
    await clt.load_private_key(admin_peer_creds["private_key"])
    async with clt:
        assert await clt.get_objects_node().get_children()
        objects = clt.nodes.objects
        child = await objects.get_child(["0:MyObject", "0:MyVariable"])
        await child.set_value(48.0)
        assert await child.read_value() == 48.0
        await child.add_property(2, "MyProperty4", 3)


def _type_id(request_type: str) -> ua.NodeId:
    return ua.NodeId(getattr(ua.ObjectIds, f"{request_type}Request_Encoding_DefaultBinary"))


def _allows(role: UserRole, request_type: str) -> bool:
    return SimpleRoleRuleset().check_validity(User(role=role), _type_id(request_type), None)


READ_ONLY_SERVICES = [
    "Read",
    "Browse",
    "BrowseNext",
    "TranslateBrowsePathsToNodeIds",
    "RegisterNodes",
    "UnregisterNodes",
    "HistoryRead",
    "CreateSubscription",
    "ModifySubscription",
    "SetPublishingMode",
    "DeleteSubscriptions",
    "Republish",
    "TransferSubscriptions",
    "Publish",
    "CreateMonitoredItems",
    "ModifyMonitoredItems",
    "SetMonitoringMode",
    "DeleteMonitoredItems",
    "Cancel",
]
USER_SERVICES = ["Write", "Call", "HistoryUpdate"]
ADMIN_SERVICES = ["AddNodes", "DeleteNodes", "AddReferences", "DeleteReferences"]
SERVICES_WITHOUT_A_ROW = [
    "CreateSession",
    "ActivateSession",
    "CloseSession",
    "GetEndpoints",
    "FindServers",
    "CloseSecureChannel",
    "RegisterServer",
    "RegisterServer2",
]


@pytest.mark.parametrize("request_type", READ_ONLY_SERVICES)
def test_cry12_anonymous_may_read_browse_subscribe(request_type: str) -> None:
    """Part 4, 5.7.3.1 and the service sets of Part 4: Anonymous is the read-only role."""
    assert _allows(UserRole.Anonymous, request_type)


@pytest.mark.parametrize("request_type", USER_SERVICES + ADMIN_SERVICES)
def test_cry12_anonymous_may_not_write_call_or_add_nodes(request_type: str) -> None:
    """Part 4, 5.7.3.1: Anonymous cannot change values, call methods or change the address space."""
    assert not _allows(UserRole.Anonymous, request_type)


@pytest.mark.parametrize("request_type", ADMIN_SERVICES)
def test_cry12_user_may_not_add_nodes(request_type: str) -> None:
    """Part 4, 5.7.3.1: only Admin changes the address space."""
    assert not _allows(UserRole.User, request_type)
    assert _allows(UserRole.Admin, request_type)


@pytest.mark.parametrize("request_type", USER_SERVICES)
def test_cry12_user_may_write_and_call(request_type: str) -> None:
    """Part 4, 5.7.3.1: User may change values and call methods."""
    assert _allows(UserRole.User, request_type)


@pytest.mark.parametrize("role", list(UserRole))
@pytest.mark.parametrize("request_type", SERVICES_WITHOUT_A_ROW)
def test_cry12_services_the_dispatcher_handles_itself_have_no_row(role: UserRole, request_type: str) -> None:
    """Part 4, 5.3: a service without a row is denied; Session and discovery services never reach the ruleset."""
    assert not _allows(role, request_type)


def test_cry12_unknown_role_and_unknown_service_are_denied() -> None:
    """Part 4, 5.3: neither an unknown role nor an unknown request type is allowed."""
    ruleset = SimpleRoleRuleset()
    assert not ruleset.check_validity(User(role="Operator"), _type_id("Read"), None)  # type: ignore[arg-type]
    assert not ruleset.check_validity(User(role=UserRole.Admin), ua.NodeId(1, 99), None)


def test_cry12_every_dispatch_entry_has_a_permission_class() -> None:
    """Part 4, 5.3: each service in the dispatch table states who may call it, and the ruleset agrees."""
    ruleset = SimpleRoleRuleset()
    classes = {
        Permission.Anonymous: UserRole.Anonymous,
        Permission.User: UserRole.User,
        Permission.Admin: UserRole.Admin,
    }
    for service in build_service_table():
        if service.permission is Permission.Unchecked:
            assert not ruleset.check_validity(User(role=UserRole.Admin), service.type_id, None), service.name
            continue
        lowest = classes[service.permission]
        for role in UserRole:
            expected = ROLE_RANK[role] >= ROLE_RANK[lowest]
            assert ruleset.check_validity(User(role=role), service.type_id, None) is expected, (service.name, role)


def test_security_admin_role_has_the_admin_service_permissions():
    ruleset = SimpleRoleRuleset()
    add_nodes = ua.NodeId(ua.ObjectIds.AddNodesRequest_Encoding_DefaultBinary)
    assert ruleset.check_validity(User(role=UserRole.SecurityAdmin), add_nodes, None)
    assert ROLE_RANK[UserRole.SecurityAdmin] > ROLE_RANK[UserRole.Admin]
