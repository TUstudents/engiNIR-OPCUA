from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.copy_node_util import copy_node
from enginir_opcua.common.instantiate_util import instantiate
from enginir_opcua.common.node import Node


@pytest.fixture
async def srv() -> Any:
    server = Server()
    await server.init()
    await server.register_namespace("urn:test:inst")
    yield server


def new_id(name: str) -> ua.NodeId:
    return ua.NodeId(name, 2)


async def names(node: Node) -> list[str]:
    return sorted([(await child.read_browse_name()).Name for child in await node.get_children()])


async def exists(node: Node) -> bool:
    try:
        await node.read_browse_name()
    except ua.UaStatusCodeError:
        return False
    return True


async def test_com22_placeholders_are_not_instantiated(srv: Server) -> None:
    """Part 3, 6.4.4.4.4 and 6.4.4.4.5: a placeholder defines no BrowseName."""
    directory = await srv.nodes.objects.add_object(new_id("dir"), "2:dir", ua.NodeId(ua.ObjectIds.FileDirectoryType))
    assert not [n for n in await names(directory) if n.startswith("<")]


async def test_com22_mandatory_placeholder_and_exposes_its_array_are_skipped(srv: Server) -> None:
    kind = await srv.nodes.base_object_type.add_object_type(new_id("kind"), "2:kind")
    plain = await kind.add_variable(new_id("plain"), "2:plain", 1)
    await plain.set_modelling_rule(True)
    holder = await kind.add_object(new_id("holder"), "2:<Slot>")
    await holder.add_reference(
        ua.NodeId(ua.ObjectIds.ModellingRule_MandatoryPlaceholder), ua.ObjectIds.HasModellingRule, True, False
    )
    inner = await holder.add_variable(new_id("inner"), "2:inner", 1)
    await inner.set_modelling_rule(True)
    array = await kind.add_variable(new_id("array"), "2:array", 1)
    await array.add_reference(
        ua.NodeId(ua.ObjectIds.ModellingRule_ExposesItsArray), ua.ObjectIds.HasModellingRule, True, False
    )
    instance = await srv.nodes.objects.add_object(new_id("i"), "2:i", kind.nodeid)
    assert await names(instance) == ["plain"]


async def test_com90_children_of_a_typed_declaration_are_instantiated(srv: Server) -> None:
    """Part 3, 6.4.2, 6.4.3: a child has what its own type requires."""
    inner_type = await srv.nodes.base_object_type.add_object_type(new_id("A"), "2:A")
    x = await inner_type.add_variable(new_id("X"), "2:X", 1.0)
    await x.set_modelling_rule(True)
    outer_type = await srv.nodes.base_object_type.add_object_type(new_id("B"), "2:B")
    c = await outer_type.add_object(new_id("c"), "2:c", inner_type.nodeid)
    await c.set_modelling_rule(True)
    instance = await srv.nodes.objects.add_object(new_id("binst"), "2:binst", outer_type.nodeid)
    child = await instance.get_child("2:c")
    assert await names(child) == ["X"]


async def test_com91_event_notifier_of_declaration_is_copied_to_instance(srv: Server) -> None:
    kind = await srv.nodes.base_object_type.add_object_type(new_id("EN"), "2:EN")
    declared = await kind.add_object(new_id("o"), "2:o")
    await declared.set_modelling_rule(True)
    await declared.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
    instance = await srv.nodes.objects.add_object(new_id("eni"), "2:eni", kind.nodeid)
    assert await (await instance.get_child("2:o")).read_event_notifier() == {ua.EventNotifier.SubscribeToEvents}


async def test_com92_no_warning_for_attributes_the_type_lacks(srv: Server, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("WARNING")
    await srv.nodes.objects.add_object(new_id("sm"), "2:sm", ua.NodeId(ua.ObjectIds.StateMachineType))
    assert not [r for r in caplog.records if "statuscode" in r.getMessage()]


async def test_com24_abstract_variable_type_is_rejected(srv: Server) -> None:
    vt = await srv.nodes.base_variable_type.add_variable_type(
        new_id("avt"), "2:avt", ua.NodeId(ua.ObjectIds.Int32), is_abstract=True
    )
    with pytest.raises(ua.UaError):
        await instantiate(srv.nodes.objects, vt)


async def test_com24_data_type_cannot_be_instantiated(srv: Server) -> None:
    dt = await srv.nodes.base_structure_type.add_data_type(new_id("adt"), "2:adt")
    with pytest.raises(ua.UaError):
        await instantiate(srv.nodes.objects, dt)


async def test_com23_existing_node_id_raises_and_leaves_nothing(srv: Server) -> None:
    kind = await srv.nodes.base_object_type.add_object_type(new_id("K"), "2:K")
    var = await kind.add_variable(new_id("kv"), "2:kv", 1)
    await var.set_modelling_rule(True)
    await srv.nodes.objects.add_object(new_id("taken"), "2:taken")
    with pytest.raises(ua.UaStatusCodeError):
        await instantiate(srv.nodes.objects, kind, new_id("taken"), "2:again")
    assert await exists(srv.get_node(new_id("taken")))
    assert await names(srv.nodes.objects) == sorted(set(await names(srv.nodes.objects)))
    assert "again" not in await names(srv.nodes.objects)


async def test_com23_failed_child_removes_created_nodes(srv: Server) -> None:
    kind = await srv.nodes.base_object_type.add_object_type(new_id("K2"), "2:K2")
    var = await kind.add_variable(new_id("k2v"), "2:k2v", 1)
    await var.set_modelling_rule(True)
    await srv.nodes.objects.add_variable(new_id("rootp.k2v"), "2:blocker", 1)
    with pytest.raises(ua.UaStatusCodeError):
        await instantiate(srv.nodes.objects, kind, new_id("rootp"), "2:rootp")
    assert not await exists(srv.get_node(new_id("rootp")))
    assert await exists(srv.get_node(new_id("rootp.k2v")))


async def test_com26_copy_keeps_event_notifier_and_is_abstract(srv: Server) -> None:
    obj = await srv.nodes.objects.add_object(new_id("en"), "2:en")
    await obj.set_event_notifier([ua.EventNotifier.SubscribeToEvents])
    copy = (await copy_node(srv.nodes.objects, obj, recursive=False))[0]
    assert await copy.read_event_notifier() == {ua.EventNotifier.SubscribeToEvents}
    abstract = await srv.nodes.base_object_type.add_object_type(new_id("abs"), "2:abs", is_abstract=True)
    concrete = await srv.nodes.base_object_type.add_object_type(new_id("con"), "2:con")
    for kind, expected in ((abstract, True), (concrete, False)):
        duplicate = (await copy_node(srv.nodes.base_object_type, kind, recursive=False))[0]
        assert (await duplicate.read_attribute(ua.AttributeIds.IsAbstract)).Value.Value is expected  # type: ignore[union-attr]


async def test_com26_copied_property_uses_has_property(srv: Server) -> None:
    holder = await srv.nodes.objects.add_object(new_id("h"), "2:h")
    prop = await holder.add_property(new_id("p"), "2:p", 3)
    target = await srv.nodes.objects.add_object(new_id("t"), "2:t")
    copy = (await copy_node(target, prop))[0]
    assert await target.get_properties() == [copy]


async def test_com26_copied_type_uses_has_subtype_and_explicit_reference_type(srv: Server) -> None:
    kind = await srv.nodes.base_object_type.add_object_type(new_id("ct"), "2:ct")
    copy = (await copy_node(srv.nodes.base_object_type, kind, recursive=False))[0]
    parents = await copy.get_referenced_nodes(ua.ObjectIds.HasSubtype, ua.BrowseDirection.Inverse)
    assert parents == [srv.nodes.base_object_type]
    box = await srv.nodes.objects.add_object(new_id("box"), "2:box")
    other = await srv.nodes.objects.add_object(new_id("oo"), "2:oo")
    organized = (await copy_node(box, other, recursive=False, referenceType=ua.NodeId(ua.ObjectIds.Organizes)))[0]
    assert await box.get_children(ua.ObjectIds.Organizes) == [organized]


async def test_com105_copied_type_keeps_modelling_rules(srv: Server) -> None:
    kind = await srv.nodes.base_object_type.add_object_type(new_id("mr"), "2:mr")
    var = await kind.add_variable(new_id("mrv"), "2:mrv", 1)
    await var.set_modelling_rule(True)
    copy = (await copy_node(srv.nodes.base_object_type, kind))[0]
    instance = await srv.nodes.objects.add_object(new_id("mri"), "2:mri", copy.nodeid)
    assert await names(instance) == ["mrv"]


async def test_com25_recursive_copy_does_not_follow_organizes(srv: Server) -> None:
    other = await srv.nodes.objects.add_folder(new_id("org"), "2:org")
    mine = await srv.nodes.objects.add_object(new_id("my"), "2:my")
    await mine.add_reference(other, ua.ObjectIds.Organizes, True, True)
    own = await mine.add_variable(new_id("ownv"), "2:ownv", 1)
    copied = await copy_node(srv.nodes.objects, mine)
    assert len(copied) == 2
    assert own.nodeid not in [n.nodeid for n in copied]
    assert other.nodeid not in [n.nodeid for n in copied]


async def test_com25_copy_survives_a_cycle(srv: Server) -> None:
    top = await srv.nodes.objects.add_object(new_id("ctop"), "2:ctop")
    below = await top.add_object(new_id("cbelow"), "2:cbelow")
    await below.add_reference(top, ua.ObjectIds.HasNotifier, True, True)
    assert len(await copy_node(srv.nodes.objects, top)) == 2
