"""Generated event classes."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import event_objects
from tests.monitoring import create_items, item_request, make_server, open_subscription, publish


@pytest.fixture(scope="module")
async def server() -> AsyncIterator[Server]:
    srv = await make_server()
    yield srv


@pytest.mark.parametrize("event_class", sorted(event_objects.IMPLEMENTED_EVENTS.values(), key=repr))
def test_com66_every_field_of_a_generated_event_declares_a_built_in_type(event_class: Any) -> None:
    """Part 6, 5.1.2: a Variant carries a built-in type, never the NodeId of a DataType."""
    event = event_class()
    wrong = {name: kind for name, kind in event.data_types.items() if not isinstance(kind, ua.VariantType)}
    assert wrong == {}


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
