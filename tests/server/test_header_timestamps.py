from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.client import ua_client
from enginir_opcua.server import uaprocessor
from tests.access_rig import AccessRig, make_access_rig  # noqa: F401


def capture(monkeypatch: pytest.MonkeyPatch, module: Any) -> list[Any]:
    sent: list[Any] = []
    encode = module.struct_to_binary

    def spy(obj: Any) -> bytes:
        sent.append(obj)
        return encode(obj)

    monkeypatch.setattr(module, "struct_to_binary", spy)
    return sent


async def test_request_header_carries_the_time_the_client_sent_it(
    access_rig: AccessRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.33: the RequestHeader timestamp is the time the Client sent the request."""
    sent = capture(monkeypatch, ua_client)
    before = datetime.now(UTC)
    await access_rig.admin.nodes.server_state.read_value()
    after = datetime.now(UTC)
    request = next(obj for obj in sent if isinstance(obj, ua.ReadRequest))
    assert before <= request.RequestHeader.Timestamp <= after


async def test_response_header_carries_the_time_the_server_sent_it(
    access_rig: AccessRig, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Part 4, 7.34: the ResponseHeader timestamp is the time the Server sent the response."""
    sent = capture(monkeypatch, uaprocessor)
    before = datetime.now(UTC)
    await access_rig.admin.nodes.server_state.read_value()
    after = datetime.now(UTC)
    response = next(obj for obj in sent if isinstance(obj, ua.ReadResponse))
    assert before <= response.ResponseHeader.Timestamp <= after
