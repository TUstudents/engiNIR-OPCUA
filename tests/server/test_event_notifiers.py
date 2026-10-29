from __future__ import annotations

import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import event_objects
from tests.monitoring import create_items, item_request, make_server, open_subscription, publish

"""Event delivery: the notifier hierarchy and the BaseEventType stamping of the EventGenerator."""


@pytest.fixture(scope="module")
async def server() -> AsyncIterator[Server]:
    srv = await make_server()
    yield srv


def select(*names: str) -> ua.EventFilter:
    return ua.EventFilter(
        SelectClauses=[
            ua.SimpleAttributeOperand(
                TypeDefinitionId=ua.NodeId(ua.ObjectIds.BaseEventType),
                BrowsePath=[ua.QualifiedName(name, 0) for name in path.split("/")],
                AttributeId=ua.AttributeIds.Value,
            )
            for path in names
        ]
    )


async def watch(server: Server, source: ua.NodeId, *names: str, queue: int = 10) -> tuple[Any, Any]:
    sub, wire = await open_subscription(server)
    [result] = await create_items(
        server, sub, item_request(source, ua.AttributeIds.EventNotifier, queue=queue, filter=select(*names))
    )
    assert result.StatusCode.is_good(), result.StatusCode
    return sub, wire


async def test_srv23_default_message_is_the_browse_name_of_the_source(server: Server) -> None:
    """Part 5, 6.4.2: the Message is a LocalizedText holding the source's BrowseName."""
    source = await server.nodes.objects.add_object(2, "Boiler1")
    await source.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
    sub, wire = await watch(server, source.nodeid, "Message", "SourceName")
    generator = await server.get_event_generator(emitting_node=source)
    await generator.trigger()
    [notification] = await publish(sub, wire)
    message, name = notification.EventFields
    assert message.VariantType == ua.VariantType.LocalizedText
    assert message.Value.Text == "Boiler1"
    assert name.Value == "Boiler1"


@pytest.mark.parametrize("isdst, expected", [(0, False), (1, True), (-1, False)])
async def test_srv23_daylight_saving_in_offset_follows_tm_isdst(
    server: Server, monkeypatch: pytest.MonkeyPatch, isdst: int, expected: bool
) -> None:
    """Part 5, 6.4.2 and Part 3 TimeZoneDataType: TRUE only when daylight saving time is in effect."""
    real = time.localtime

    def localtime(seconds: float | None = None) -> Any:
        return SimpleNamespace(tm_gmtoff=real(seconds).tm_gmtoff, tm_isdst=isdst)

    monkeypatch.setattr("enginir_opcua.server.event_generator.time.localtime", localtime)
    sub, wire = await watch(server, ua.NodeId(ua.ObjectIds.Server), "LocalTime")
    generator = await server.get_event_generator()
    await generator.trigger(message="dst")
    [notification] = await publish(sub, wire)
    assert notification.EventFields[0].Value.DaylightSavingInOffset is expected


async def test_srv23_the_generator_keeps_the_other_event_notifier_bits(server: Server) -> None:
    """Part 3, 8.59: SubscribeToEvents is set without clearing HistoryRead."""
    source = await server.nodes.objects.add_object(2, "Historized")
    await source.set_event_notifier([ua.EventNotifier.HistoryRead])
    await server.get_event_generator(emitting_node=source)
    bits = await source.read_event_notifier()
    assert ua.EventNotifier.SubscribeToEvents in bits
    assert ua.EventNotifier.HistoryRead in bits


async def make_notifier(server: Server, parent: Any, name: str, reference: int) -> Any:
    node = await server.nodes.objects.add_object(2, name)
    await node.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
    await parent.add_reference(node, ua.NodeId(reference))
    return node


async def test_srv23_an_event_reaches_the_server_object_and_every_notifier_above(server: Server) -> None:
    """Part 3, 7.17 and 7.18: HasNotifier and HasEventSource lead the event up to the Server Object."""
    plant = await server.nodes.objects.add_object(2, "Plant")
    await plant.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
    await server.nodes.server.add_reference(plant, ua.NodeId(ua.ObjectIds.HasNotifier))
    boiler = await make_notifier(server, plant, "Boiler", ua.ObjectIds.HasEventSource)
    watchers = {}
    for name, node in (("boiler", boiler.nodeid), ("plant", plant.nodeid), ("server", ua.NodeId(ua.ObjectIds.Server))):
        watchers[name] = await watch(server, node, "Message")
    generator = await server.get_event_generator(emitting_node=boiler)
    await generator.trigger(message="from the boiler")
    for name, (sub, wire) in watchers.items():
        notifications = await publish(sub, wire)
        assert [n.EventFields[0].Value.Text for n in notifications] == ["from the boiler"], name


async def test_srv23_an_event_reaches_an_item_once_however_many_paths_lead_to_it(server: Server) -> None:
    """Part 3, 7.18."""
    left = await server.nodes.objects.add_object(2, "AreaLeft")
    right = await server.nodes.objects.add_object(2, "AreaRight")
    for area in (left, right):
        await area.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
        await server.nodes.server.add_reference(area, ua.NodeId(ua.ObjectIds.HasNotifier))
    pump = await make_notifier(server, left, "Pump", ua.ObjectIds.HasNotifier)
    await right.add_reference(pump, ua.NodeId(ua.ObjectIds.HasNotifier))
    sub, wire = await watch(server, ua.NodeId(ua.ObjectIds.Server), "Message")
    generator = await server.get_event_generator(emitting_node=pump)
    await generator.trigger(message="diamond")
    assert len(await publish(sub, wire)) == 1


async def test_srv23_hierarchical_references_do_not_propagate_events(server: Server) -> None:
    """Part 3, 7.18: a parent that only has HasComponent to the source is not a notifier of it."""
    parent = await server.nodes.objects.add_object(2, "OwnerOnly")
    await parent.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
    child = await parent.add_object(2, "Component")
    sub, wire = await watch(server, parent.nodeid, "Message")
    generator = await server.get_event_generator(emitting_node=child)
    await generator.trigger(message="component")
    assert await publish(sub, wire) == []


async def test_srv23_a_source_without_a_notifier_reference_still_reaches_the_server_object(server: Server) -> None:
    """Part 3, 7.17: the Server Object has an implied HasEventSource to every source."""
    lonely = await server.nodes.objects.add_object(2, "Lonely")
    sub, wire = await watch(server, ua.NodeId(ua.ObjectIds.Server), "Message")
    generator = await server.get_event_generator(emitting_node=lonely)
    await generator.trigger(message="lonely")
    assert [n.EventFields[0].Value.Text for n in await publish(sub, wire)] == ["lonely"]


"""Generated event classes."""


@pytest.mark.parametrize("event_class", sorted(event_objects.IMPLEMENTED_EVENTS.values(), key=repr))
def test_com66_every_field_of_a_generated_event_declares_a_built_in_type(event_class: Any) -> None:
    """Part 6, 5.1.2: a Variant carries a built-in type, never the NodeId of a DataType."""
    event = event_class()
    wrong = {name: kind for name, kind in event.data_types.items() if not isinstance(kind, ua.VariantType)}
    assert wrong == {}


async def test_com66_an_audit_event_with_a_time_field_can_be_selected(server: Server) -> None:
    """Part 5, 6.4.2 and Part 6, 5.1.2: ActionTimeStamp is a DateTime on the wire."""
    sub, wire = await watch(server, ua.NodeId(ua.ObjectIds.Server), "ActionTimeStamp", "Message")
    generator = await server.get_event_generator(ua.ObjectIds.AuditEventType)
    stamp = datetime.now(UTC)
    generator.event.ActionTimeStamp = stamp
    await generator.trigger(message="audit")
    [notification] = await publish(sub, wire)
    assert notification.EventFields[0].VariantType == ua.VariantType.DateTime
    assert notification.EventFields[0].Value == stamp
