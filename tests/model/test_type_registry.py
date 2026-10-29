from dataclasses import dataclass

import pytest

from enginir_opcua import Client, Server, ua
from enginir_opcua.common.structures104 import new_enum, new_struct, new_struct_field
from enginir_opcua.common.utils import Buffer
from enginir_opcua.server.user_managers import PermissiveUserManager
from enginir_opcua.ua.uatypes import TypeRegistry
from tests.conftest import find_free_port


@dataclass
class First:
    a: ua.Int32 = 0


@dataclass
class Second:
    b: ua.String = ""


def registry(*uris: str) -> tuple[TypeRegistry, list[str]]:
    table = ["http://opcfoundation.org/UA/", *uris]
    return TypeRegistry(namespaces=lambda: table, parents=(ua.default_types,)), table


def test_com40_registries_do_not_share_entries() -> None:
    reg_a, _ = registry("urn:a")
    reg_b, _ = registry("urn:b")
    reg_a.register_struct(ua.NodeId(5001, 1), ua.NodeId(5002, 1), First, "First")
    reg_b.register_struct(ua.NodeId(5001, 1), ua.NodeId(5002, 1), Second, "Second")
    assert reg_a.get(ua.NodeId(5001, 1)) is First
    assert reg_b.get(ua.NodeId(5001, 1)) is Second
    assert reg_a.class_for_encoding(ua.NodeId(5002, 1)) is First
    assert reg_b.class_for_encoding(ua.NodeId(5002, 1)) is Second


def test_com40_lookup_follows_the_namespace_uri_when_the_array_changes() -> None:
    reg, table = registry("urn:a", "urn:b")
    reg.register_struct(ua.NodeId(7, 2), ua.NodeId(8, 2), First, "First")
    table[1], table[2] = table[2], table[1]
    assert reg.class_for_encoding(ua.NodeId(8, 1)) is First
    assert reg.class_for_encoding(ua.NodeId(8, 2)) is None
    assert reg.encoding_id_of(First) == ua.NodeId(8, 1)
    assert reg.data_type_of(First) == ua.NodeId(7, 1)


def test_com40_unknown_namespace_index_is_keyed_as_given() -> None:
    reg, _ = registry("urn:a")
    assert reg.class_for_encoding(ua.NodeId(8, 9)) is None
    with pytest.raises(KeyError):
        reg.get(ua.NodeId(8, 9))


def test_com40_base_types_are_found_through_any_registry() -> None:
    reg, _ = registry("urn:a")
    argument_encoding = ua.NodeId(ua.ObjectIds.Argument_Encoding_DefaultBinary)
    assert reg.class_for_encoding(argument_encoding) is ua.uaprotocol_auto.Argument


def test_com40_namespace_zero_type_of_a_server_shadows_only_in_its_own_registry() -> None:
    reg, _ = registry("urn:a")
    other, _ = registry("urn:b")
    argument = ua.NodeId(ua.ObjectIds.Argument)
    reg.register_struct(argument, ua.NodeId(5, 0), First, "First")
    assert reg.get(argument) is First
    assert other.find(argument) is not First


def test_com40_encoding_a_foreign_class_raises() -> None:
    reg_a, _ = registry("urn:a")
    reg_b, _ = registry("urn:b")
    reg_a.register_struct(ua.NodeId(1, 1), ua.NodeId(2, 1), First, "First")
    with reg_b.encoding():
        with pytest.raises(ua.UaError, match="First"):
            ua.ua_binary.extensionobject_to_binary(First())
    with reg_a.encoding():
        assert ua.ua_binary.extensionobject_to_binary(First())


def test_com40_decode_uses_the_registry_of_the_buffer() -> None:
    reg_a, _ = registry("urn:a")
    reg_b, _ = registry("urn:b")
    reg_a.register_struct(ua.NodeId(1, 1), ua.NodeId(2, 1), First, "First")
    reg_b.register_struct(ua.NodeId(1, 1), ua.NodeId(2, 1), Second, "Second")
    with reg_a.encoding():
        data = ua.ua_binary.extensionobject_to_binary(First(a=ua.Int32(7)))
    decoded_a = ua.ua_binary.extensionobject_from_binary(Buffer(data, types=reg_a))
    assert decoded_a == First(a=7)
    opaque = ua.ua_binary.extensionobject_from_binary(Buffer(data, types=registry("urn:c")[0]))
    assert isinstance(opaque, ua.ExtensionObject)


def test_com40_buffer_copy_keeps_the_registry() -> None:
    reg, _ = registry("urn:a")
    assert Buffer(b"abc", types=reg).copy(2).types is reg


def test_com40_legacy_registration_goes_to_the_default_registry(restore_ua_registry: None) -> None:
    ua.register_extension_object("LegacyFirst", ua.NodeId(321, 1), First, ua.NodeId(320, 1))
    reg, _ = registry("urn:a")
    assert reg.class_for_encoding(ua.NodeId(321, 1)) is First
    assert reg.get(ua.NodeId(320, 1)) is First


async def start_server(port: int, field_name: str) -> tuple[Server, int]:
    server = Server(user_manager=PermissiveUserManager(), allow_no_security=True)
    await server.init()
    server.set_endpoint(f"opc.tcp://127.0.0.1:{port}")
    idx = await server.register_namespace("http://test.example/com40")
    await new_struct(server, idx, "Shared", [new_struct_field(field_name, ua.VariantType.Int32)])
    await new_enum(server, idx, "Mode", ["A", "B"])
    await server.load_data_type_definitions()
    value = server.types.by_name("Shared")(**{field_name: 41})
    holder = await server.nodes.objects.add_variable(
        idx,
        "holder",
        ua.Variant(value, ua.VariantType.ExtensionObject),
        datatype=server.types.data_type_of(type(value)),
    )
    assert holder.nodeid.NamespaceIndex == idx
    await server.start()
    return server, idx


async def test_com40_two_servers_two_clients_same_node_ids(restore_ua_registry: None) -> None:
    server_a, _ = await start_server(find_free_port(), "alpha")
    server_b, _ = await start_server(find_free_port(), "beta")
    try:
        clients = []
        for server, field_name in ((server_a, "alpha"), (server_b, "beta")):
            client = Client(server.endpoint.geturl())
            await client.connect()
            clients.append(client)
            await client.load_data_type_definitions()
            holder = await client.nodes.objects.get_child("2:holder")
            value = await holder.read_value()
            assert getattr(value, field_name) == 41
            assert type(value) is client.types.by_name("Shared")
        assert clients[0].types.by_name("Shared") is not clients[1].types.by_name("Shared")
        assert server_a.types.by_name("Shared") is not server_b.types.by_name("Shared")
        for client in clients:
            await client.disconnect()
    finally:
        await server_a.stop()
        await server_b.stop()


async def test_com40_client_must_load_definitions_itself(restore_ua_registry: None) -> None:
    server, _ = await start_server(find_free_port(), "alpha")
    try:
        async with Client(server.endpoint.geturl()) as client:
            holder = await client.nodes.objects.get_child("2:holder")
            assert isinstance(await holder.read_value(), ua.ExtensionObject)
            await client.load_data_type_definitions()
            assert (await holder.read_value()).alpha == 41
    finally:
        await server.stop()


def test_com40_codecs_of_a_dropped_registry_do_not_keep_its_classes_alive() -> None:
    import gc
    import weakref

    from enginir_opcua.common.structures104 import make_structure

    reg, _ = registry("urn:a")
    sdef = ua.StructureDefinition()
    sdef.StructureType = ua.StructureType.Structure
    field = ua.StructureField()
    field.Name = "n"
    field.IsOptional = False
    field.ValueRank = -1
    field.DataType = ua.NodeId(ua.ObjectIds.Int32)
    sdef.Fields = [field]
    cls = make_structure(ua.NodeId(10, 1), "Leaky", sdef, types=reg)["Leaky"]
    reg.register_struct(ua.NodeId(10, 1), ua.NodeId(11, 1), cls, "Leaky")
    with reg.encoding():
        data = ua.ua_binary.extensionobject_to_binary(cls(n=3))
    assert ua.ua_binary.extensionobject_from_binary(Buffer(data, types=reg)).n == 3
    reference = weakref.ref(cls)
    del cls, reg, sdef
    delattr(ua, "Leaky")
    gc.collect()
    assert reference() is None


def test_com40_data_type_of_class_uses_the_owner_registry() -> None:
    reg, table = registry("urn:a", "urn:b")
    reg.register_struct(ua.NodeId(7, 2), ua.NodeId(8, 2), First, "First")
    assert ua.data_type_of_class(First) == ua.NodeId(7, 2)
    table[1], table[2] = table[2], table[1]
    assert ua.data_type_of_class(First) == ua.NodeId(7, 1)

    @dataclass
    class Unknown:
        pass

    assert ua.data_type_of_class(Unknown) is None
