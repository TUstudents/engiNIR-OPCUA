import pytest

from enginir_opcua import Node, ua
from enginir_opcua.common import ua_utils
from enginir_opcua.common.structures104 import new_enum
from tests.access_rig import declare_writable

pytestmark = pytest.mark.asyncio


async def test_enum(opc):
    # create enum type
    enums = await opc.opc.nodes.root.get_child(["0:Types", "0:DataTypes", "0:BaseDataType", "0:Enumeration"])
    myenum_type = await enums.add_data_type(ua.NodeId(NamespaceIndex=2), "0:MyEnum")
    es = await myenum_type.add_variable(
        ua.NodeId(NamespaceIndex=2),
        "0:EnumStrings",
        [
            ua.LocalizedText("String0"),
            ua.LocalizedText("String1"),
            ua.LocalizedText("String2"),
        ],
        ua.VariantType.LocalizedText,
    )
    # es.write_value_rank(1)
    # instantiate
    o = opc.opc.nodes.objects
    myvar = await o.add_variable(2, "MyEnumVar", ua.Variant(1, ua.VariantType.Int32), datatype=myenum_type.nodeid)
    await declare_writable(opc, myvar)
    assert myenum_type.nodeid == await myvar.read_data_type()
    await myvar.write_value(ua.Variant(2, ua.VariantType.Int32))
    await opc.opc.delete_nodes([es, myvar])
    await opc.opc.delete_nodes([myenum_type])


async def test_supertypes(opc):
    nint32 = opc.opc.get_node(ua.ObjectIds.Int32)
    node = await ua_utils.get_node_supertype(nint32)
    assert opc.opc.get_node(ua.ObjectIds.Integer) == node

    nodes = await ua_utils.get_node_supertypes(nint32)
    assert opc.opc.get_node(ua.ObjectIds.Number) == nodes[1]
    assert opc.opc.get_node(ua.ObjectIds.Integer) == nodes[0]

    # test custom
    dtype = await nint32.add_data_type(ua.NodeId(NamespaceIndex=2), "0:MyCustomDataType")
    node = await ua_utils.get_node_supertype(dtype)
    assert nint32 == node

    dtype2 = await dtype.add_data_type(ua.NodeId(NamespaceIndex=2), "0:MyCustomDataType2")
    node = await ua_utils.get_node_supertype(dtype2)
    assert dtype == node
    await opc.opc.delete_nodes([dtype, dtype2])


async def test_base_data_type(opc):
    nint32 = opc.opc.get_node(ua.ObjectIds.Int32)
    dtype = await nint32.add_data_type(ua.NodeId(NamespaceIndex=2), "0:MyCustomDataType")
    dtype2 = await dtype.add_data_type(ua.NodeId(NamespaceIndex=2), "0:MyCustomDataType2")
    assert nint32 == await ua_utils.get_base_data_type(dtype)
    assert nint32 == await ua_utils.get_base_data_type(dtype2)

    ext = await opc.opc.nodes.objects.add_variable(ua.NodeId(NamespaceIndex=2), "0:MyExtensionObject", ua.Argument())
    d = await ext.read_data_type()
    d = opc.opc.get_node(d)
    assert opc.opc.get_node(ua.ObjectIds.Structure) == await ua_utils.get_base_data_type(d)
    assert ua.VariantType.ExtensionObject == await ua_utils.data_type_to_variant_type(d)
    await opc.opc.delete_nodes([ext])


async def test_data_type_to_variant_type(opc):
    test_data = {
        ua.ObjectIds.Boolean: ua.VariantType.Boolean,
        ua.ObjectIds.Byte: ua.VariantType.Byte,
        ua.ObjectIds.String: ua.VariantType.String,
        ua.ObjectIds.Int32: ua.VariantType.Int32,
        ua.ObjectIds.UInt32: ua.VariantType.UInt32,
        ua.ObjectIds.NodeId: ua.VariantType.NodeId,
        ua.ObjectIds.LocalizedText: ua.VariantType.LocalizedText,
        ua.ObjectIds.Structure: ua.VariantType.ExtensionObject,
        ua.ObjectIds.EnumValueType: ua.VariantType.ExtensionObject,
        ua.ObjectIds.Enumeration: ua.VariantType.Int32,  # enumeration
        ua.ObjectIds.AttributeWriteMask: ua.VariantType.UInt32,
        ua.ObjectIds.AxisScaleEnumeration: ua.VariantType.Int32,  # enumeration
    }
    for dt, vdt in test_data.items():
        k = await ua_utils.data_type_to_variant_type(opc.opc.get_node(ua.NodeId(dt)))
        assert vdt == k


async def test_guid_node_id():
    """
    Test that a Node can be instantiated with a GUID string and that the NodeId ca be converted to binary.
    """
    node = Node(None, "ns=4;g=35d5f86f-2777-4550-9d48-b098f5ee285c")
    binary_node_id = ua.ua_binary.nodeid_to_binary(node.nodeid)
    assert isinstance(binary_node_id, bytes)


async def test_import_xml_data_type_definition(opc):
    if hasattr(ua, "MySubstruct"):
        delattr(ua, "MySubstruct")
    if hasattr(ua, "MyStruct"):
        delattr(ua, "MyStruct")

    nodes = await opc.opc.import_xml("tests/model/substructs.xml")
    assert hasattr(ua, "MySubstruct")
    assert hasattr(ua, "MyStruct")

    datatype = opc.opc.get_node(ua.MySubstruct.data_type)
    sdef = await datatype.read_data_type_definition()
    assert isinstance(sdef, ua.StructureDefinition)
    s = ua.MyStruct()

    s.toto = 0.1
    ss = ua.MySubstruct()
    assert ss.titi is None
    assert ss.opt_array is None
    assert isinstance(ss.structs, list)
    ss.titi = 1.0
    ss.structs.append(s)
    ss.structs.append(s)

    var = await opc.opc.nodes.objects.add_variable(2, "MySubStructVar", ss, datatype=ua.MySubstruct.data_type)
    await declare_writable(opc, var)

    s2 = await var.read_value()
    assert s2.structs[1].toto == ss.structs[1].toto == 0.1
    assert s2.opt_array is None
    s2.opt_array = [1]
    await var.write_value(s2)
    s2 = await var.read_value()
    assert s2.opt_array == [1]
    await opc.opc.delete_nodes([datatype, var])
    n = []
    [n.append(opc.opc.get_node(node)) for node in nodes]
    await opc.opc.delete_nodes(n)


async def test_import_xml_data_no_auto_load_type_definition(opc):
    # if al present in ua remove it (left overs of other tests)
    if hasattr(ua, "MySubstruct"):
        delattr(ua, "MySubstruct")
    if hasattr(ua, "MyStruct"):
        delattr(ua, "MyStruct")
    if hasattr(ua, "MyEnum"):
        delattr(ua, "MyEnum")
    await opc.opc.import_xml("tests/model/substructs.xml", auto_load_definitions=False)
    assert hasattr(ua, "MySubstruct") is False
    assert hasattr(ua, "MyStruct") is False
    assert hasattr(ua, "MyEnum") is False


async def test_struct_data_type(opc):
    assert isinstance(ua.AddNodesItem.data_type, ua.NodeId)
    node = opc.opc.get_node(ua.AddNodesItem.data_type)
    path = await node.get_path()
    assert opc.opc.nodes.base_structure_type in path
    await opc.opc.delete_nodes([node])


async def test_import_xml_enum_data_type_definition(opc):
    if hasattr(ua, "MyEnum"):
        delattr(ua, "MyEnum")

    nodes = await opc.opc.import_xml("tests/model/testenum104.xml")
    assert hasattr(ua, "MyEnum")
    e = ua.MyEnum.val2
    var = await opc.opc.nodes.objects.add_variable(2, "MyEnumVar", e, datatype=ua.enums_datatypes[ua.MyEnum])
    e2 = await var.read_value()
    assert e2 == ua.MyEnum.val2
    await opc.opc.delete_nodes([var])
    n = []
    [n.append(opc.opc.get_node(node)) for node in nodes]
    await opc.opc.delete_nodes(n)


async def test_custom_enum_x(opc):
    idx = 4
    await new_enum(
        opc.opc,
        idx,
        "MyCustEnum",
        [
            "titi",
            "toto",
            "None",
        ],
    )

    await opc.opc.load_data_type_definitions()

    var = await opc.opc.nodes.objects.add_variable(idx, "my_enum", ua.MyCustEnum.toto)
    val = await var.read_value()
    assert val == 1


async def test_custom_enum_with_bad_dtd(opc, caplog):
    """Enum with invalid type definition is skipped and an error is logged"""
    caplog.set_level("ERROR")
    idx = 4
    dtype = await opc.opc.nodes.enum_data_type.add_data_type(idx, "MyEnum")
    # Set some garbage as type definition
    await dtype.write_data_type_definition(ua.StructureField())

    # If leftover from previous test, it would be skipped, clear out
    try:
        del ua.MyEnum
    except AttributeError:
        pass
    # Does not raise
    await opc.opc.load_data_type_definitions()
    # Check that error was logged
    logs = [t for t in caplog.record_tuples if t[0].endswith(".structures104")]
    assert len(logs) == 1
    message = logs[0][2]
    assert "MyEnum" in message
    assert "Failed to generate class from UA datatype" in message


async def test_custom_option_set(opc):
    idx = 4
    option_set = await new_enum(opc.opc, idx, "MyOptionSet", ["tata", "titi", "toto", "None"], True)
    await opc.opc.load_data_type_definitions()
    assert ua.MyOptionSet.toto | ua.MyOptionSet.titi == ua.MyOptionSet((1 << 2) | (1 << 1))
    var = await opc.opc.nodes.objects.add_variable(idx, "my_option", ua.MyOptionSet.toto | ua.MyOptionSet.titi)
    val = await var.read_value()
    assert val == (1 << 2) | (1 << 1)
    await opc.opc.delete_nodes([var, option_set])


async def test_custom_option_set_as_structure_definition(opc):
    """Option set defined via structure definition is understood.

    This is arguably outside the standard but observed on some servers.
    """
    idx = 4
    server = opc.opc
    await new_enum(opc.opc, idx, "MyOptionSet", ["tata", "titi", "toto", "None"], True)
    sdef = ua.StructureDefinition()
    for name in ["tata", "titi", "toto", "None"]:
        field = ua.StructureField()
        field.Name = name
        sdef.Fields.append(field)
    dtype = await server.nodes.option_set_type.add_data_type(idx, name)
    await dtype.write_data_type_definition(sdef)

    await opc.opc.load_data_type_definitions()
    assert ua.MyOptionSet.toto | ua.MyOptionSet.titi == ua.MyOptionSet((1 << 2) | (1 << 1))
    var = await opc.opc.nodes.objects.add_variable(idx, "my_option", ua.MyOptionSet.toto | ua.MyOptionSet.titi)
    val = await var.read_value()
    assert val == (1 << 2) | (1 << 1)


async def test_enum_string_identifier_and_spaces(opc):
    idx = 4
    nodeid = ua.NodeId("My Identifier", idx)
    qname = ua.QualifiedName("My Enum", idx)
    await new_enum(
        opc.opc,
        nodeid,
        qname,
        [
            "my name with hole",
            "toto",
            "tutu",
        ],
    )

    await opc.opc.load_data_type_definitions()

    var = await opc.opc.nodes.objects.add_variable(idx, "my enum", ua.My_Enum.my_name_with_hole)
    val = await var.read_value()
    assert val == 0
