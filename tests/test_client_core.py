from collections.abc import Iterator

import pytest

from enginir_opcua import Client, Server, ua

from .harness import ResponseTampering


@pytest.fixture
async def connected(server: Server) -> Iterator[Client]:
    client = Client(server.endpoint.geturl())
    await client.connect()
    yield client  # type: ignore[misc]
    await client.disconnect()


async def test_cli9_register_and_unregister_nodes_accept_generators(connected: Client) -> None:
    """Part 4, 5.9.5: every node of the request is registered and paired with its result."""
    nodes = [
        connected.get_node(ua.ObjectIds.Server_ServerStatus),
        connected.get_node(ua.ObjectIds.Server_NamespaceArray),
    ]
    registered = await connected.register_nodes(node for node in nodes)
    assert [node.basenodeid for node in registered] == [
        ua.NodeId(ua.ObjectIds.Server_ServerStatus),
        ua.NodeId(ua.ObjectIds.Server_NamespaceArray),
    ]
    await connected.unregister_nodes(node for node in registered)
    assert all(node.basenodeid is None for node in registered)


async def test_cli9_browse_nodes_accepts_a_generator(connected: Client) -> None:
    """Part 4, 5.8.2: every node of the request is browsed and paired with its result."""
    nodes = [connected.get_root_node(), connected.get_objects_node()]
    pairs = await connected.browse_nodes(node for node in nodes)
    assert [node.nodeid for node, _ in pairs] == [node.nodeid for node in nodes]


async def test_cli9_result_count_mismatch_is_an_error(connected: Client, tampered_responses: ResponseTampering) -> None:
    """Part 4, 5.3: a response has one result per request item; a different count is an error."""

    def drop_one(response: ua.ReadResponse) -> None:
        response.Results = response.Results[:-1]

    tampered_responses.on(ua.ReadResponse, drop_one)
    nodes = [
        connected.get_node(ua.ObjectIds.Server_NamespaceArray),
        connected.get_node(ua.ObjectIds.Server_ServerArray),
    ]
    with pytest.raises(ua.UaError, match="2"):
        await connected.read_attributes(nodes)


async def test_cli9_write_values_needs_equal_lengths(connected: Client) -> None:
    """Part 4, 5.10.4: one value per node."""
    nodes = [connected.get_node(ua.ObjectIds.Server_NamespaceArray)]
    with pytest.raises(ValueError):
        await connected.write_values(nodes, [1, 2])
