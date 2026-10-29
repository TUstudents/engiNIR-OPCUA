import inspect

import pytest

from enginir_opcua import sync
from enginir_opcua.client.client import Client as AsyncClient
from enginir_opcua.common.node import Node as AsyncNode
from enginir_opcua.common.subscription import Subscription as AsyncSubscription
from enginir_opcua.server.server import Server as AsyncServer

EXCLUDED = {
    "Client": {"subscribe_state"},
    "Server": {"init", "get_pubsub"},
    "SyncNode": {"new_node"},
    "Subscription": {"init", "publish_callback", "enqueue", "session_event", "close", "restore"},
}

PAIRS = [
    ("Client", AsyncClient, sync.Client),
    ("Server", AsyncServer, sync.Server),
    ("SyncNode", AsyncNode, sync.SyncNode),
    ("Subscription", AsyncSubscription, sync.Subscription),
]


def public_members(cls: type) -> dict[str, object]:
    return {name: member for name, member in inspect.getmembers(cls) if not name.startswith("_")}


def describe(function: object) -> list[tuple[str, object, object]]:
    return [(p.name, p.kind, p.default) for p in inspect.signature(function).parameters.values()]  # type: ignore[arg-type]


@pytest.mark.parametrize(("name", "aio_class", "sync_class"), PAIRS)
def test_syn10_every_public_async_member_has_a_sync_twin(name, aio_class, sync_class):
    """The sync classes follow the async ones, apart from a short list of members that serve the internals."""
    missing = sorted(set(public_members(aio_class)) - set(public_members(sync_class)) - EXCLUDED[name])
    assert not missing


@pytest.mark.parametrize(("name", "aio_class", "sync_class"), PAIRS)
def test_syn8_sync_signatures_match_the_async_ones(name, aio_class, sync_class):
    drift = []
    sync_members = public_members(sync_class)
    for member_name, member in public_members(aio_class).items():
        twin = sync_members.get(member_name)
        if not inspect.isfunction(member) or not inspect.isfunction(twin) or member_name in EXCLUDED[name]:
            continue
        if describe(member) != describe(twin):
            drift.append(member_name)
    assert not drift


def test_syn10_configuration_attributes_are_forwarded():
    for attribute in ("application_uri", "name", "product_uri", "session_state_path", "max_messagesize", "state"):
        assert isinstance(getattr(sync.Client, attribute), property)


def test_syn9_wrapped_methods_keep_name_and_doc():
    assert sync.Client.connect_sessionless.__name__ == "connect_sessionless"
    assert sync.SyncNode.read_value.__name__ == "read_value"
    assert list(inspect.signature(sync.Client.set_security).parameters)[1] == "policy"
