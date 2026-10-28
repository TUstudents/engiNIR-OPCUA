from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common import manage_nodes
from enginir_opcua.common.node import Node


@pytest.fixture
async def srv() -> Any:
    server = Server()
    await server.init()
    await server.register_namespace("urn:test:manage")
    yield server


def new_id(name: str) -> ua.NodeId:
    return ua.NodeId(name, 2)


async def value_of(node: Node, attribute: ua.AttributeIds) -> Any:
    variant = (await node.read_attribute(attribute)).Value
    assert variant is not None
    return variant.Value


async def exists(node: Node) -> bool:
    try:
        await node.read_browse_name()
    except ua.UaStatusCodeError:
        return False
    return True


async def test_com20_scalar_defaults(srv: Server) -> None:
    """Part 3, 5.6.2: a scalar has ValueRank -1 and no ArrayDimensions."""
    node = await srv.nodes.objects.add_variable(new_id("s"), "2:s", 5)
    assert await node.read_value_rank() == ua.ValueRank.Scalar
    assert (await value_of(node, ua.AttributeIds.ArrayDimensions)) is None
    assert (await node.read_description()).Text is None
    assert (await node.read_display_name()).Text == "s"
    assert await node.get_access_level() == {ua.AccessLevel.CurrentRead}


async def test_com20_one_dimensional_list_has_value_rank_one(srv: Server) -> None:
    node = await srv.nodes.objects.add_variable(new_id("a"), "2:a", [1, 2, 3])
    assert await node.read_value_rank() == ua.ValueRank.OneDimension


async def test_com20_array_dimensions_are_unknown_maximums(srv: Server) -> None:
    """Part 3, 5.6.2: the maximum length per dimension, 0 when unknown; the present shape is not a maximum."""
    one = await srv.nodes.objects.add_variable(new_id("a1"), "2:a1", [1, 2, 3])
    two = await srv.nodes.objects.add_variable(new_id("a2"), "2:a2", [[1, 2], [3, 4]])
    assert await one.read_array_dimensions() == [0]
    assert await two.read_value_rank() == ua.ValueRank.TwoDimensions
    assert await two.read_array_dimensions() == [0, 0]
    await two.write_value([[1, 2, 3], [4, 5, 6], [7, 8, 9]])


async def test_com20_falsy_initial_value_of_variable_type_is_kept(srv: Server) -> None:
    parent = srv.get_node(ua.ObjectIds.BaseDataVariableType)
    nodeid = await manage_nodes._create_variable_type(
        srv.iserver.isession, parent.nodeid, new_id("vt0"), ua.QualifiedName("vt0", 2), ua.NodeId(ua.ObjectIds.Int32), 0
    )
    assert (await srv.get_node(nodeid).read_value()) == 0


async def test_com98_scalar_variable_type_has_scalar_value_rank(srv: Server) -> None:
    node = await srv.nodes.base_variable_type.add_variable_type(new_id("vt"), "2:vt", ua.NodeId(ua.ObjectIds.Int32))
    assert await node.read_value_rank() == ua.ValueRank.Scalar


async def test_types_can_be_created_abstract(srv: Server) -> None:
    object_type = await srv.nodes.base_object_type.add_object_type(new_id("ot"), "2:ot", is_abstract=True)
    variable_type = await srv.nodes.base_variable_type.add_variable_type(
        new_id("vt2"), "2:vt2", ua.NodeId(ua.ObjectIds.Int32), is_abstract=True
    )
    data_type = await srv.nodes.base_structure_type.add_data_type(new_id("dt"), "2:dt", is_abstract=True)
    for node in (object_type, variable_type, data_type):
        assert (await value_of(node, ua.AttributeIds.IsAbstract)) is True
    concrete = await srv.nodes.base_object_type.add_object_type(new_id("ot2"), "2:ot2")
    assert (await value_of(concrete, ua.AttributeIds.IsAbstract)) is False


async def test_com21_non_symmetric_reference_type_needs_inverse_name(srv: Server) -> None:
    parent = srv.get_node(ua.ObjectIds.NonHierarchicalReferences)
    with pytest.raises(ValueError):
        await parent.add_reference_type(new_id("r1"), "2:r1", symmetric=False)
    with pytest.raises(ValueError):
        await parent.add_reference_type(new_id("r2"), "2:r2", symmetric=True, inversename="Back")
    node = await parent.add_reference_type(new_id("r3"), "2:r3", symmetric=False, inversename="Back")
    assert (await value_of(node, ua.AttributeIds.InverseName)).Text == "Back"
    symmetric = await parent.add_reference_type(new_id("r4"), "2:r4")
    assert (await value_of(symmetric, ua.AttributeIds.InverseName)).Text is None


async def test_com19_create_data_type_adds_one_reference(srv: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    session = srv.iserver.isession
    calls: list[Any] = []
    original = session.add_references

    async def spy(items: Any) -> Any:
        calls.append(items)
        return await original(items)

    monkeypatch.setattr(session, "add_references", spy)
    node = await srv.nodes.base_structure_type.add_data_type(new_id("dt1"), "2:dt1")
    assert calls == []
    parents = await node.get_referenced_nodes(ua.ObjectIds.HasSubtype, ua.BrowseDirection.Inverse)
    assert parents == [srv.nodes.base_structure_type]


async def test_com96_encoding_has_data_type_encoding_type(srv: Server) -> None:
    data_type = await srv.nodes.base_structure_type.add_data_type(new_id("dt2"), "2:dt2")
    encoding = await manage_nodes.create_encoding(data_type, new_id("enc"), ua.QualifiedName("Default Binary", 0))
    assert await encoding.read_type_definition() == ua.NodeId(ua.ObjectIds.DataTypeEncodingType)
    assert await data_type.get_encoding_refs() == [encoding]
    with pytest.raises(ua.UaError):
        await manage_nodes.create_encoding(data_type, new_id("enc2"), ua.QualifiedName("Default Binary", 2))


async def test_com21_arguments_have_names_and_array_arguments_are_arrays(srv: Server) -> None:
    def callback(parent: ua.NodeId, *arguments: ua.Variant) -> list[ua.Variant]:
        return []

    method = await srv.nodes.objects.add_method(
        new_id("m"), "2:m", callback, [ua.VariantType.Int32, [ua.VariantType.Double]], [ua.VariantType.String]
    )
    inputs = await (await method.get_child("0:InputArguments")).read_value()
    assert [a.Name for a in inputs] == ["Input0", "Input1"]
    assert inputs[0].ValueRank == ua.ValueRank.Scalar and not inputs[0].ArrayDimensions
    assert inputs[1].ValueRank == ua.ValueRank.OneDimension and inputs[1].ArrayDimensions == [0]
    outputs = await (await method.get_child("0:OutputArguments")).read_value()
    assert [a.Name for a in outputs] == ["Output0"]


async def test_create_method_with_callback_on_session_without_callbacks_raises() -> None:
    class Session:
        async def add_nodes(self, items: Any) -> Any:
            raise AssertionError("nothing may be sent")

    parent = Node(Session(), ua.NodeId(85))  # type: ignore[arg-type]
    with pytest.raises(ua.UaError):
        await parent.add_method(new_id("m2"), "2:m2", lambda parent: None)


async def test_failed_argument_properties_remove_the_method(srv: Server, monkeypatch: pytest.MonkeyPatch) -> None:
    async def failing(*args: Any, **kwargs: Any) -> Any:
        raise ua.UaError("no")

    monkeypatch.setattr(manage_nodes, "create_property", failing)
    with pytest.raises(ua.UaError):
        await srv.nodes.objects.add_method(new_id("m3"), "2:m3", lambda parent, *a: [], [ua.VariantType.Int32])
    assert not await exists(srv.get_node(new_id("m3")))


async def test_com101_delete_nodes_accepts_a_generator(srv: Server) -> None:
    folder = await srv.nodes.objects.add_folder(new_id("g"), "2:g")
    nodes, results = await manage_nodes.delete_nodes(srv.iserver.isession, (n for n in [folder]))
    assert nodes == [folder]
    assert [r.is_good() for r in results] == [True]


async def test_com18_recursive_delete_keeps_organized_nodes(srv: Server) -> None:
    other = await srv.nodes.objects.add_folder(new_id("other"), "2:other")
    mine = await srv.nodes.objects.add_object(new_id("mine"), "2:mine")
    await mine.add_reference(other, ua.ObjectIds.Organizes, True, True)
    own = await mine.add_object(new_id("own"), "2:own")
    await mine.delete(recursive=True)
    assert await exists(other)
    assert not await exists(own)
    assert not await exists(mine)


async def test_com18_recursive_delete_survives_a_cycle(srv: Server) -> None:
    top = await srv.nodes.objects.add_object(new_id("top"), "2:top")
    below = await top.add_object(new_id("below"), "2:below")
    await below.add_reference(top, ua.ObjectIds.HasNotifier, True, True)
    nodes = await top.delete(recursive=True)
    assert sorted(n.nodeid.to_string() for n in nodes) == sorted([top.nodeid.to_string(), below.nodeid.to_string()])
    assert not await exists(top) and not await exists(below)


async def test_com18_node_with_another_aggregating_parent_is_kept(srv: Server) -> None:
    first = await srv.nodes.objects.add_object(new_id("first"), "2:first")
    second = await srv.nodes.objects.add_object(new_id("second"), "2:second")
    shared = await first.add_object(new_id("shared"), "2:shared")
    inside = await shared.add_variable(new_id("inside"), "2:inside", 1)
    await second.add_reference(shared, ua.ObjectIds.HasComponent, True, True)
    await first.delete(recursive=True)
    assert not await exists(first)
    assert await exists(shared) and await exists(inside)


async def test_com18_children_are_deleted_before_their_parent(srv: Server) -> None:
    parent = await srv.nodes.objects.add_object(new_id("p"), "2:p")
    child = await parent.add_variable(new_id("c"), "2:c", 1)
    nodes, results = await manage_nodes.delete_nodes(srv.iserver.isession, [parent], recursive=True)
    assert nodes == [child, parent]
    assert all(r.is_good() for r in results)
