import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.crypto.permission_rules import User, UserRole
from tests.conftest import find_free_port

port_num = find_free_port()
uri = f"opc.tcp://127.0.0.1:{port_num}/baz/server"
uri_creds = f"opc.tcp://foobar:hR%26yjjGhP%246%40nQ4e@127.0.0.1:{port_num}/baz/server"
uri_wrong_creds = f"opc.tcp://foobar:wrong@127.0.0.1:{port_num}/baz/server"


class UserManager:
    def get_user(self, iserver, username=None, password=None, certificate=None):
        if username == "foobar" and password == "hR&yjjGhP$6@nQ4e":
            return User(role=UserRole.User)
        return None


@pytest.fixture()
async def srv_user():
    srv = Server(allow_no_security=True, user_manager=UserManager())
    srv.set_endpoint(uri)
    srv.set_identity_tokens([ua.UserNameIdentityToken])
    srv.allow_plaintext_password = True

    await srv.init()
    await srv.start()
    yield srv
    await srv.stop()


async def test_creds(srv_user):
    clt = Client(uri)
    clt.set_user("foobar")
    clt.set_password("hR&yjjGhP$6@nQ4e")
    await clt.connect()
    await clt.disconnect()


async def test_wrong_creds(srv_user):
    clt = Client(uri)
    clt.set_user("foobar")
    clt.set_password("wrong")
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await clt.connect()
    await clt.disconnect()


async def test_creds_in_uri(srv_user):
    clt = Client(uri_creds)
    # check if credentials got removed
    assert clt.server_url.geturl() == uri
    await clt.connect()
    await clt.disconnect()


async def test_wrong_creds_in_uri(srv_user):
    clt = Client(uri_wrong_creds)
    with pytest.raises(ua.uaerrors.BadUserAccessDenied):
        await clt.connect()
    await clt.disconnect()
