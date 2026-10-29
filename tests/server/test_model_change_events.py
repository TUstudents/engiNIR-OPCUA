"""ModelChangeEvents (Part 3, 9.32; Part 5, 6.4.31, 6.4.32 and 12.16): one event per changing request."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.node import Node
from tests.monitoring import create_items, item_request, make_server, open_subscription, publish

SERVER_OBJECT = ua.NodeId(ua.ObjectIds.Server)
ADDED, DELETED, REF_ADDED, REF_DELETED = 1, 2, 4, 8
FIELDS = ("Changes", "SourceNode", "SourceName", "EventType", "Message")


@pytest.fixture(scope="module", name="shared")
async def make_shared_server() -> Server:
    return await make_server()


@pytest.fixture
async def server(shared: Server) -> AsyncIterator[Server]:
    notifier = shared.iserver.model_changes
    notifier.enabled = True
    yield shared
    notifier.enabled = False
    notifier.max_changes = 10_000
    shared.iserver.model_change_events = "all"


def select() -> ua.EventFilter:
    return ua.EventFilter(
        SelectClauses=[
            ua.SimpleAttributeOperand(
                TypeDefinitionId=ua.NodeId(ua.ObjectIds.BaseEventType),
                BrowsePath=[ua.QualifiedName(name, 0)],
                AttributeId=ua.AttributeIds.Value,
            )
            for name in FIELDS
        ]
    )


async def watch(server: Server) -> tuple[Any, Any]:
    sub, wire = await open_subscription(server)
    [result] = await create_items(
        server, sub, item_request(SERVER_OBJECT, ua.AttributeIds.EventNotifier, queue=100, filter=select())
    )
    assert result.StatusCode.is_good()
    return sub, wire


def changes_of(notification: Any) -> dict[ua.NodeId, tuple[ua.NodeId, int]]:
    return {c.Affected: (c.AffectedType, c.Verb) for c in notification.EventFields[0].Value}


async def test_srv96_add_nodes_raises_one_general_model_change_event(server: Server) -> None:
    """Part 3, 9.32.6: one event per request, with the new Node and the parent that gained a reference."""
    sub, wire = await watch(server)
    parent = await server.nodes.objects.add_folder(2, "Plant")
    await publish(sub, wire)
    child = await parent.add_object(2, "Boiler")
    [event] = await publish(sub, wire)
    changes = changes_of(event)
    assert changes[child.nodeid] == (ua.NodeId(ua.ObjectIds.BaseObjectType), ADDED)
    assert changes[parent.nodeid] == (ua.NodeId(ua.ObjectIds.FolderType), REF_ADDED)
    assert len(changes) == 2


async def test_srv96_event_source_is_the_server_object(server: Server) -> None:
    """Part 5, 6.4.31: the context of the change is the whole address space, so the source is the Server Object."""
    sub, wire = await watch(server)
    await server.nodes.objects.add_object(2, "A")
    [event] = await publish(sub, wire)
    _, source, name, event_type, message = (field.Value for field in event.EventFields)
    assert source == SERVER_OBJECT
    assert name == "Server"
    assert event_type == ua.NodeId(ua.ObjectIds.GeneralModelChangeEventType)
    assert message.Text


async def test_srv96_failed_add_nodes_raises_none(server: Server) -> None:
    """Part 3, 9.32.1: only a change is reported."""
    sub, wire = await watch(server)
    item = ua.AddNodesItem(
        ParentNodeId=ua.NodeId(99999, 2),
        ReferenceTypeId=ua.NodeId(ua.ObjectIds.Organizes),
        RequestedNewNodeId=ua.NodeId(1, 2),
        BrowseName=ua.QualifiedName("X", 2),
        NodeClass=ua.NodeClass.Object,
        NodeAttributes=ua.ObjectAttributes(DisplayName=ua.LocalizedText("X")),
        TypeDefinition=ua.NodeId(ua.ObjectIds.BaseObjectType),
    )
    [result] = await server.iserver.isession.add_nodes([item])
    assert result.StatusCode.is_bad()
    assert await publish(sub, wire) == []


async def test_srv96_delete_nodes_reports_type_and_lost_references(server: Server) -> None:
    """Part 5, 12.16: the deleted Node with its type, and every Node that lost a reference to it."""
    parent = await server.nodes.objects.add_folder(2, "Plant")
    child = await parent.add_object(2, "Boiler")
    sub, wire = await watch(server)
    await server.delete_nodes([child])
    [event] = await publish(sub, wire)
    changes = changes_of(event)
    assert changes[child.nodeid] == (ua.NodeId(ua.ObjectIds.BaseObjectType), DELETED)
    assert changes[parent.nodeid][1] == REF_DELETED


async def test_srv96_add_and_delete_references_report_both_sides(server: Server) -> None:
    """Part 5, 12.16: a bidirectional reference is two changes, one for each node."""
    a = await server.nodes.objects.add_object(2, "A")
    b = await server.nodes.objects.add_object(2, "B")
    sub, wire = await watch(server)
    await a.add_reference(b, ua.ObjectIds.Organizes)
    [added] = await publish(sub, wire)
    changes = changes_of(added)
    assert changes[a.nodeid][1] == REF_ADDED
    assert changes[b.nodeid][1] == REF_ADDED
    await a.delete_reference(b, ua.ObjectIds.Organizes)
    [deleted] = await publish(sub, wire)
    changes = changes_of(deleted)
    assert changes[a.nodeid][1] == REF_DELETED
    assert changes[b.nodeid][1] == REF_DELETED


async def version(node: Node) -> str:
    return await (await node.get_child("0:NodeVersion")).read_value()


async def test_srv96_node_version_changes_on_named_nodes(server: Server) -> None:
    """Part 3, 9.32.2: a Node that has a NodeVersion gets a new one whenever an event names it."""
    parent = await server.nodes.objects.add_folder(2, "Plant")
    await parent.add_property(0, "NodeVersion", "0")
    before = await version(parent)
    await parent.add_object(2, "Boiler")
    after = await version(parent)
    assert after != before
    await parent.add_object(2, "Boiler2")
    assert await version(parent) not in (before, after)


async def test_srv96_model_change_block_batches_one_event(server: Server) -> None:
    """Part 3, 9.32.4: one event for a series of updates; nested blocks merge into the outer one."""
    sub, wire = await watch(server)
    async with server.model_change():
        a = await server.nodes.objects.add_object(2, "A")
        async with server.model_change():
            b = await a.add_object(2, "B")
        await server.delete_nodes([b])
        assert await publish(sub, wire) == []
    [event] = await publish(sub, wire)
    changes = changes_of(event)
    assert changes[a.nodeid][1] == ADDED | REF_ADDED | REF_DELETED
    assert changes[b.nodeid][1] == ADDED | DELETED


async def test_srv96_block_with_no_change_emits_nothing(server: Server) -> None:
    """Part 3, 9.32.1: nothing changed, nothing to report."""
    sub, wire = await watch(server)
    async with server.model_change():
        pass
    assert await publish(sub, wire) == []


async def test_srv96_concurrent_request_is_not_batched(server: Server) -> None:
    """A change made by another task while a block is open emits its own event."""
    sub, wire = await watch(server)
    go = asyncio.Event()
    done = asyncio.Event()

    async def other() -> None:
        await go.wait()
        await server.nodes.objects.add_object(2, "Other")
        done.set()

    task = asyncio.create_task(other())
    async with server.model_change():
        await server.nodes.objects.add_object(2, "Mine")
        go.set()
        await done.wait()
        [other_event] = await publish(sub, wire)
    [mine] = await publish(sub, wire)
    await task
    assert len(changes_of(other_event)) == 2
    assert len(changes_of(mine)) == 2


async def test_srv96_more_than_the_limit_sends_a_base_event_without_changes(server: Server) -> None:
    """Part 3, 9.32.5: a server that cannot list every Node says that any Node may have changed."""
    server.iserver.model_changes.max_changes = 3
    sub, wire = await watch(server)
    async with server.model_change():
        for index in range(5):
            await server.nodes.objects.add_object(2, f"N{index}")
    [event] = await publish(sub, wire)
    assert event.EventFields[0].Value is None
    assert event.EventFields[3].Value == ua.NodeId(ua.ObjectIds.BaseModelChangeEventType)


async def test_srv96_nothing_before_start() -> None:
    """Part 3, 9.32.1: a server that is not started has no subscribers; nothing is raised."""
    server = await make_server()
    sub, wire = await watch(server)
    await server.nodes.objects.add_object(2, "A")
    assert await publish(sub, wire) == []


async def test_srv96_versioned_setting_names_only_nodes_with_a_version(server: Server) -> None:
    """Part 3, 9.32.2, literal reading: only Nodes that have a NodeVersion trigger an event."""
    server.iserver.model_change_events = "versioned"
    parent = await server.nodes.objects.add_folder(2, "Plant")
    await parent.add_property(0, "NodeVersion", "0")
    sub, wire = await watch(server)
    child = await parent.add_object(2, "Boiler")
    [event] = await publish(sub, wire)
    assert list(changes_of(event)) == [parent.nodeid]
    await server.nodes.objects.add_object(2, "Unversioned")
    assert await publish(sub, wire) == []
    assert child.nodeid not in changes_of(event)
