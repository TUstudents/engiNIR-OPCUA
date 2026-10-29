from typing import Any

from enginir_opcua import Server, ua
from enginir_opcua.common.events import Event


async def custom_event() -> tuple[Server, Any]:
    server = Server()
    await server.init()
    etype = await server.create_custom_event_type(
        2,
        "FieldDictEvent",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    generator = await server.get_event_generator(etype)
    return server, generator.event


async def test_com27_field_dict_of_a_fresh_custom_event_does_not_raise() -> None:
    """Design: the field dict is the storage form of an event (events R19)."""
    server, event = await custom_event()
    fields = event.get_event_props_as_fields_dict()
    assert "_freeze" not in fields
    assert "PropertyNum" in fields
    assert "PropertyString" in fields
    assert "Message" in fields
    await server.stop()


async def test_com27_field_dict_round_trips() -> None:
    """Design: from_field_dict(field_dict(e)) has the same field dict."""
    server, event = await custom_event()
    event.PropertyNum = 2.5
    event.PropertyString = "text"
    fields = event.get_event_props_as_fields_dict()
    again = Event.from_field_dict(fields).get_event_props_as_fields_dict()
    assert again == fields
    assert again["PropertyNum"].Value == 2.5
    await server.stop()
