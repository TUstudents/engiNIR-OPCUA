import asyncio
import logging
from asyncio import TimeoutError

import anyio
import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto import security_policies, uacrypto
from enginir_opcua.crypto.security_policies import (
    SECURITY_POLICY_TYPE_MAP,
    SecurityPolicyBasic128Rsa15,
    SecurityPolicyBasic256Sha256,
)
from enginir_opcua.crypto.uacrypto import CertProperties
from enginir_opcua.server.user_managers import CertificateUserManager
from enginir_opcua.ua.uaerrors import ConfigurationError
from tests.conftest import find_free_port
from tests.pki import generated_pki

port_num1 = find_free_port()
port_num2 = find_free_port()
port_num3 = find_free_port()
uri_crypto = "opc.tcp://127.0.0.1:{0:d}".format(port_num1)
uri_no_crypto = "opc.tcp://127.0.0.1:{0:d}".format(port_num2)
uri_crypto_cert = "opc.tcp://127.0.0.1:{0:d}".format(port_num3)
uri_crypto_basic128rsa15 = f"opc.tcp://127.0.0.1:{find_free_port()}"
uri_crypto_encrypted_key = f"opc.tcp://127.0.0.1:{find_free_port()}"
uri_crypto_standalone = f"opc.tcp://127.0.0.1:{find_free_port()}"
PKI = generated_pki()
srv_crypto_params = [
    (PKI.server.key, PKI.server.certificate),
    (PKI.server_3072.key, PKI.server_3072.certificate),
]

peer_creds = {"certificate": PKI.peer1.certificate, "private_key": PKI.peer1.key}

unauthorized_peer_creds = {"certificate": PKI.peer2.certificate, "private_key": PKI.peer2.key}

encrypted_private_key_peer_creds = {
    "private_key": PKI.peer_encrypted.key,
    "certificate": PKI.peer_encrypted.certificate,
    "password": b"password",
}


@pytest.fixture(scope="module", params=srv_crypto_params)
async def srv_crypto_encrypted_key_one_cert(request):
    peer_certificate = encrypted_private_key_peer_creds["certificate"]
    user_manager = CertificateUserManager()
    key, cert = request.param
    await user_manager.add_admin(peer_certificate, "test1")

    srv = Server(allow_no_security=True, user_manager=user_manager)

    await srv.init()
    srv.set_endpoint(uri_crypto_encrypted_key)
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    yield srv, cert
    # stop the server
    await srv.stop()


@pytest.fixture(scope="module", params=srv_crypto_params)
async def srv_crypto_all_certs(request):
    # start our own server
    srv = Server(allow_no_security=True)
    key, cert = request.param
    await srv.init()
    srv.set_endpoint(uri_crypto)
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    yield srv, cert
    # stop the server
    await srv.stop()


@pytest.fixture(scope="module", params=srv_crypto_params)
async def srv_crypto_one_cert(request):
    peer_certificate = peer_creds["certificate"]
    user_manager = CertificateUserManager()
    key, cert = request.param
    await user_manager.add_admin(peer_certificate, "test1")

    srv = Server(allow_no_security=True, user_manager=user_manager)

    await srv.init()
    srv.set_endpoint(uri_crypto_cert)
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    yield srv, cert
    # stop the server
    await srv.stop()


@pytest.fixture(scope="module", params=srv_crypto_params[:1])
async def srv_crypto_all_cert_basic128rsa15(request):
    # start our own server
    srv = Server(allow_deprecated_policies=True)
    key, cert = request.param
    await srv.init()
    srv.set_endpoint(uri_crypto_basic128rsa15)
    srv.set_security_policy([ua.SecurityPolicyType.Basic128Rsa15_Sign])
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    yield srv, cert
    # stop the server
    await srv.stop()


@pytest.fixture(scope="module")
async def srv_no_crypto():
    # start our own server
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(uri_no_crypto)
    await srv.start()
    yield srv
    # stop the server
    await srv.stop()


async def test_cert_warning():
    """check if a warning for a no longer valid cert is generated"""
    cert = await uacrypto.load_certificate(peer_creds["certificate"])
    assert uacrypto.check_certificate(cert, "abc")


async def test_nocrypto(srv_no_crypto):
    clt = Client(uri_no_crypto)
    async with clt:
        await clt.nodes.objects.get_children()


async def test_nocrypto_fail(srv_no_crypto):
    clt = Client(uri_no_crypto)
    with pytest.raises(ua.UaError):
        await clt.set_security_string(f"Basic256Sha256,Sign,{PKI.peer1.certificate},{PKI.peer1.key}")


async def test_basic256(srv_crypto_all_certs):
    _, cert = srv_crypto_all_certs
    clt = Client(uri_crypto)
    await clt.set_security_string(f"Basic256Sha256,Sign,{PKI.peer1.certificate},{PKI.peer1.key},{cert}")
    async with clt:
        assert await clt.nodes.objects.get_children()


async def test_basic128rsa15(srv_crypto_all_cert_basic128rsa15):
    _, cert = srv_crypto_all_cert_basic128rsa15
    clt = Client(uri_crypto_basic128rsa15, allow_deprecated_policies=True)
    print(await clt.connect_and_get_server_endpoints())
    await clt.set_security_string(f"Basic128Rsa15,Sign,{PKI.peer1.certificate},{PKI.peer1.key},{cert}")
    async with clt:
        assert await clt.nodes.objects.get_children()


async def test_basic256_encrypt(srv_crypto_all_certs):
    _, cert = srv_crypto_all_certs
    clt = Client(uri_crypto)
    await clt.set_security_string(f"Basic256Sha256,SignAndEncrypt,{PKI.peer1.certificate},{PKI.peer1.key},{cert}")
    async with clt:
        assert await clt.nodes.objects.get_children()


async def test_basic256_encrypt_success(srv_crypto_all_certs):
    clt = Client(uri_crypto)
    _, cert = srv_crypto_all_certs
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        f"{PKI.peer1.certificate}",
        f"{PKI.peer1.key}",
        None,
        cert,
        ua.MessageSecurityMode.SignAndEncrypt,
    )

    async with clt:
        assert await clt.nodes.objects.get_children()


async def test_basic256_encrypt_use_certificate_bytes(srv_crypto_all_certs):
    clt = Client(uri_crypto)
    _, cert = srv_crypto_all_certs
    async with await anyio.open_file(cert, "rb") as server_cert:
        async with await anyio.open_file(f"{PKI.peer1.certificate}", "rb") as user_cert:
            async with await anyio.open_file(f"{PKI.peer1.key}", "rb") as user_key:
                await clt.set_security(
                    security_policies.SecurityPolicyBasic256Sha256,
                    await user_cert.read(),
                    CertProperties(await user_key.read(), extension="pem"),
                    None,
                    await server_cert.read(),
                    ua.MessageSecurityMode.SignAndEncrypt,
                )

    async with clt:
        assert await clt.nodes.objects.get_children()


@pytest.mark.skip("# FIXME: how to make it fail???")
async def test_basic256_encrypt_fail(srv_crypto_all_certs):
    # FIXME: how to make it fail???
    _, _cert = srv_crypto_all_certs
    clt = Client(uri_crypto)
    with pytest.raises(ua.UaError):
        await clt.set_security(
            security_policies.SecurityPolicyBasic256Sha256,
            f"{PKI.peer1.certificate}",
            f"{PKI.peer1.key}",
            None,
            None,
            mode=ua.MessageSecurityMode.None_,
        )


async def test_Aes128Sha256RsaOaep_encrypt_success(srv_crypto_all_certs):
    clt = Client(uri_crypto)
    _, cert = srv_crypto_all_certs
    await clt.set_security(
        security_policies.SecurityPolicyAes128Sha256RsaOaep,
        f"{PKI.peer1.certificate}",
        f"{PKI.peer1.key}",
        None,
        cert,
        ua.MessageSecurityMode.SignAndEncrypt,
    )

    async with clt:
        assert await clt.nodes.objects.get_children()


async def test_Aes256Sha256RsaPss_encrypt_success(srv_crypto_all_certs):
    clt = Client(uri_crypto)
    _, cert = srv_crypto_all_certs
    await clt.set_security(
        security_policies.SecurityPolicyAes256Sha256RsaPss,
        f"{PKI.peer1.certificate}",
        f"{PKI.peer1.key}",
        None,
        cert,
        ua.MessageSecurityMode.SignAndEncrypt,
    )

    async with clt:
        assert await clt.nodes.objects.get_children()


async def test_certificate_handling_success(srv_crypto_one_cert):
    _, cert = srv_crypto_one_cert
    clt = Client(uri_crypto_cert)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        peer_creds["certificate"],
        peer_creds["private_key"],
        None,
        cert,
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    async with clt:
        assert await clt.get_objects_node().get_children()


async def test_encrypted_private_key_handling_success(srv_crypto_encrypted_key_one_cert):
    _, cert = srv_crypto_encrypted_key_one_cert
    clt = Client(uri_crypto_encrypted_key)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        encrypted_private_key_peer_creds["certificate"],
        encrypted_private_key_peer_creds["private_key"],
        encrypted_private_key_peer_creds["password"],
        cert,
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    async with clt:
        assert await clt.get_objects_node().get_children()


async def test_encrypted_private_key_handling_success_with_cert_props(srv_crypto_encrypted_key_one_cert):
    _, cert = srv_crypto_encrypted_key_one_cert
    clt = Client(uri_crypto_encrypted_key)
    user_cert = uacrypto.CertProperties(encrypted_private_key_peer_creds["certificate"], "DER")
    user_key = uacrypto.CertProperties(
        path_or_content=encrypted_private_key_peer_creds["private_key"],
        password=encrypted_private_key_peer_creds["password"],
        extension="PEM",
    )
    server_cert = uacrypto.CertProperties(cert)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        user_cert,
        user_key,
        server_certificate=server_cert,
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    async with clt:
        assert await clt.get_objects_node().get_children()


async def test_certificate_handling_failure(srv_crypto_one_cert):
    _, _cert = srv_crypto_one_cert
    clt = Client(uri_crypto_cert)
    clt.set_trust_store(PKI.trust_store())

    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await clt.set_security(
            security_policies.SecurityPolicyBasic256Sha256,
            unauthorized_peer_creds["certificate"],
            unauthorized_peer_creds["private_key"],
            None,
            mode=ua.MessageSecurityMode.SignAndEncrypt,
        )

        async with clt:
            assert await clt.get_objects_node().get_children()


async def test_encrypted_private_key_handling_failure(srv_crypto_one_cert):
    _, cert = srv_crypto_one_cert
    clt = Client(uri_crypto_cert)

    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await clt.set_security(
            security_policies.SecurityPolicyBasic256Sha256,
            unauthorized_peer_creds["certificate"],
            unauthorized_peer_creds["private_key"],
            None,  # Pass None for an empty password to test incorrect password.
            cert,
            mode=ua.MessageSecurityMode.SignAndEncrypt,
        )
        async with clt:
            assert await clt.get_objects_node().get_children()


async def test_certificate_handling_mismatched_creds(srv_crypto_one_cert):
    _, cert = srv_crypto_one_cert
    clt = Client(uri_crypto_cert, timeout=1)
    with pytest.raises((AttributeError, TimeoutError, ua.uaerrors.BadSecurityChecksFailed)):
        await clt.set_security(
            security_policies.SecurityPolicyBasic256Sha256,
            peer_creds["certificate"],
            unauthorized_peer_creds["private_key"],
            None,
            cert,
            mode=ua.MessageSecurityMode.SignAndEncrypt,
        )
        async with clt:
            assert await clt.get_objects_node().get_children()


async def test_secure_channel_key_expiration(srv_crypto_one_cert, monkeypatch):
    timeout = 2
    srv, cert = srv_crypto_one_cert
    monkeypatch.setattr(srv.iserver.channel_settings, "min_lifetime", 500)
    clt = Client(uri_crypto_cert)
    clt.secure_channel_timeout = timeout * 1000
    user_cert = uacrypto.CertProperties(peer_creds["certificate"], "DER")
    user_key = uacrypto.CertProperties(
        path_or_content=peer_creds["private_key"],
        extension="PEM",
    )
    server_cert = uacrypto.CertProperties(cert)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        user_cert,
        user_key,
        server_certificate=server_cert,
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    async with clt:
        channel = clt.uaclient.protocol._channel
        assert channel._previous is None

        await asyncio.sleep(timeout * 0.85)
        previous = channel._previous
        assert previous is not None
        assert previous.token.TokenId != channel.security_token.TokenId

        await asyncio.sleep(timeout * 0.45)
        assert await clt.get_objects_node().get_children()
        assert channel._previous is not previous


async def test_always_catch_new_cert_on_set_security():
    """
    Test client reconnection after server cert update.
    This could be useful when we prefer to keep a unique
    client instance (i.e HaClient).
    """
    # Client connecting with encryption to server
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(uri_crypto_standalone)
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    key, cert = srv_crypto_params[0]
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    clt = Client(uri_crypto_standalone, timeout=1)
    clt.set_trust_store(PKI.trust_store())
    peer_cert = peer_creds["certificate"]
    peer_key = peer_creds["private_key"]
    security_string = f"Basic256Sha256,SignAndEncrypt,{peer_cert},{peer_key}"
    await clt.set_security_string(security_string)
    assert await clt.connect_and_get_server_endpoints()
    srv_original_cert = clt.security_policy.peer_certificate
    await srv.stop()

    # Simulation of a server cert renewal
    srv = Server(allow_no_security=True)
    await srv.init()
    srv.set_endpoint(uri_crypto_standalone)
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    key, cert = srv_crypto_params[1]
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    # The same client instance fails to open a SecureChannel because the
    # security_policy contains the previous SecurityMode and server certificate.
    with pytest.raises((TimeoutError, ua.uaerrors.BadSecurityChecksFailed)):
        await clt.connect_and_get_server_endpoints()

    assert clt.security_policy == clt.uaclient.security_policy
    assert clt.security_policy.peer_certificate == srv_original_cert

    # If the server cert isn't passed to set_security we clear the security_policy
    await clt.set_security_string(security_string)
    assert await clt.connect_and_get_server_endpoints()
    assert clt.security_policy == clt.uaclient.security_policy
    assert clt.security_policy.peer_certificate
    assert clt.security_policy.peer_certificate != srv_original_cert
    await srv.stop()


async def test_anonymous_rejection():
    peer_certificate = peer_creds["certificate"]
    user_manager = CertificateUserManager()
    key, cert = srv_crypto_params[0]
    await user_manager.add_admin(peer_certificate, "test1")

    srv = Server(allow_no_security=True, user_manager=user_manager)

    await srv.init()
    srv.set_endpoint(uri_crypto_standalone)
    srv.set_security_policy([ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt])
    srv.set_identity_tokens([ua.UserNameIdentityToken, ua.X509IdentityToken])
    await srv.load_certificate(cert)
    await srv.load_private_key(key)
    srv.set_trust_store(PKI.trust_store())
    await srv.start()
    clt = Client(uri_crypto_standalone)
    await clt.set_security(
        security_policies.SecurityPolicyBasic256Sha256,
        peer_creds["certificate"],
        peer_creds["private_key"],
        None,
        cert,
        mode=ua.MessageSecurityMode.SignAndEncrypt,
    )
    with pytest.raises(ua.uaerrors.ConfigurationError):
        await clt.connect()
    await srv.stop()


async def test_security_level_endpoints(srv_crypto_all_certs: tuple[Server, str]):
    srv = srv_crypto_all_certs[0]

    end_points: list[ua.EndpointDescription] = await srv.get_endpoints()

    for end_point in end_points:
        if end_point.SecurityMode == ua.MessageSecurityMode.None_:
            policy_type = ua.SecurityPolicyType.NoSecurity
        else:
            policy_type = ua.SecurityPolicyType[
                f"{end_point.SecurityPolicyUri.split('#')[1].replace('_', '')}_{end_point.SecurityMode.name}"
            ]
        assert end_point.SecurityLevel == SECURITY_POLICY_TYPE_MAP[policy_type][2]


async def make_server(*, with_certificate: bool = True, **options: bool) -> Server:
    server = Server(**options)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{find_free_port()}")
    if with_certificate:
        await server.load_certificate(PKI.server.certificate)
        await server.load_private_key(PKI.server.key)
        server.set_trust_store(PKI.trust_store())
    return server


async def offered_policies(server: Server) -> set[str]:
    return {endpoint.SecurityPolicyUri for endpoint in await server.get_endpoints()}


async def test_srv45_no_security_endpoint_is_not_offered_by_default() -> None:
    """Part 4, 7.10 and the design's secure defaults: SecurityPolicy None has to be enabled explicitly."""
    server = await make_server()
    async with server:
        policies = await offered_policies(server)
    assert "http://opcfoundation.org/UA/SecurityPolicy#None" not in policies
    assert SecurityPolicyBasic256Sha256.URI in policies


async def test_srv45_server_without_certificate_and_without_no_security_does_not_start() -> None:
    """A server that would offer no endpoint at all fails at start and names what to do."""
    server = await make_server(with_certificate=False)
    with pytest.raises(ConfigurationError, match="allow_no_security"):
        await server.start()


async def test_srv45_allow_no_security_offers_the_endpoint() -> None:
    """The None endpoint is offered when it is enabled explicitly."""
    server = await make_server(allow_no_security=True)
    async with server:
        assert "http://opcfoundation.org/UA/SecurityPolicy#None" in await offered_policies(server)
        async with Client(server.endpoint.geturl()) as client:
            assert await client.nodes.objects.get_children()


async def test_srv45_listing_no_security_in_the_policies_offers_it() -> None:
    """Part 4, 7.10: naming the policy in set_security_policy is an explicit choice."""
    server = await make_server(with_certificate=False)
    server.set_security_policy([ua.SecurityPolicyType.NoSecurity])
    async with server:
        assert await offered_policies(server) == {"http://opcfoundation.org/UA/SecurityPolicy#None"}


async def test_cry8_deprecated_policy_needs_allow_deprecated_policies() -> None:
    """Part 7: Basic128Rsa15 and Basic256 are deprecated and have to be enabled explicitly."""
    server = await make_server()
    with pytest.raises(ConfigurationError, match="allow_deprecated_policies"):
        server.set_security_policy([ua.SecurityPolicyType.Basic128Rsa15_Sign])


async def test_cry8_allowed_deprecated_policy_is_offered_with_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    """Part 7: the deprecated policies are available when enabled, and the start says so."""
    server = await make_server(allow_deprecated_policies=True)
    server.set_security_policy([ua.SecurityPolicyType.Basic128Rsa15_Sign, ua.SecurityPolicyType.Basic256Sha256_Sign])
    with caplog.at_level(logging.WARNING):
        async with server:
            policies = await offered_policies(server)
    assert SecurityPolicyBasic128Rsa15.URI in policies
    assert "Basic128Rsa15" in caplog.text


async def test_cry8_client_refuses_a_deprecated_policy_unless_allowed() -> None:
    """Part 7: the client selects a deprecated policy only when it is enabled explicitly."""
    client = Client("opc.tcp://127.0.0.1:4840")
    with pytest.raises(ConfigurationError, match="allow_deprecated_policies"):
        await client.set_security(
            SecurityPolicyBasic128Rsa15,
            PKI.peer1.certificate,
            PKI.peer1.key,
            None,
            PKI.server.certificate,
            ua.MessageSecurityMode.Sign,
        )
    allowed = Client("opc.tcp://127.0.0.1:4840", allow_deprecated_policies=True)
    await allowed.set_security(
        SecurityPolicyBasic128Rsa15,
        PKI.peer1.certificate,
        PKI.peer1.key,
        None,
        PKI.server.certificate,
        ua.MessageSecurityMode.Sign,
    )
