import pytest

from enginir_opcua import Server, ua
from tests.harness import ResponseTampering, signing_client


async def _connect_expecting_bad_nonce(server: Server) -> None:
    client = await signing_client(server)
    with pytest.raises(ua.uaerrors.BadNonceInvalid):
        await client.connect()
    await client.disconnect()


async def test_cli6_short_create_session_nonce_is_rejected(
    shared_signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.2.2: the ServerNonce has 32 to 128 bytes, and the Client shall check the length."""

    def shorten(response: ua.CreateSessionResponse) -> None:
        response.Parameters.ServerNonce = b"\x01" * 8

    tampered_responses.on(ua.CreateSessionResponse, shorten)
    await _connect_expecting_bad_nonce(shared_signing_server)


async def test_cli6_missing_activate_session_nonce_is_rejected(
    shared_signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.7.3.2: the ServerNonce returned by ActivateSession has 32 to 128 bytes."""

    def drop(response: ua.ActivateSessionResponse) -> None:
        response.Parameters.ServerNonce = None

    tampered_responses.on(ua.ActivateSessionResponse, drop)
    await _connect_expecting_bad_nonce(shared_signing_server)


async def test_cli6_open_secure_channel_nonce_of_wrong_length_is_rejected(
    shared_signing_server: Server, tampered_responses: ResponseTampering
) -> None:
    """Part 4, 5.6.2.2: the ServerNonce length equals the SecureChannelNonceLength of the SecurityPolicy."""

    def shorten(response: ua.OpenSecureChannelResponse) -> None:
        response.Parameters.ServerNonce = response.Parameters.ServerNonce[:16]

    tampered_responses.on(ua.OpenSecureChannelResponse, shorten)
    await _connect_expecting_bad_nonce(shared_signing_server)
