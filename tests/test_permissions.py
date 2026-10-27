import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto import security_policies
from enginir_opcua.crypto.permission_rules import UserRole
from enginir_opcua.server.user_managers import CertificateUserManager

from .conftest import find_free_port
from .pki import generated_pki

pytestmark = pytest.mark.asyncio

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
        await child.add_property(0, "MyProperty1", 3)


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
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await clt.nodes.objects.get_children()


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
        with pytest.raises(ua.uaerrors.BadUserAccessDenied):
            await clt.nodes.objects.get_children()


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
        await child.add_property(0, "MyProperty4", 3)
