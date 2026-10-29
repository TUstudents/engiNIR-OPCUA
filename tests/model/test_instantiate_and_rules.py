import pytest

from enginir_opcua import ua
from enginir_opcua.common.instantiate_util import instantiate

pytestmark = pytest.mark.asyncio


async def test_modelling_rules(opc):
    obj = await opc.opc.nodes.base_object_type.add_object_type(2, "MyFooObjectType")
    v = await obj.add_variable(2, "myvar", 1.1)
    await v.set_modelling_rule(True)
    p = await obj.add_property(2, "myvar2", 1.1)
    await p.set_modelling_rule(False)

    refs = await obj.get_referenced_nodes(refs=ua.ObjectIds.HasModellingRule)
    assert 0 == len(refs)

    refs = await v.get_referenced_nodes(refs=ua.ObjectIds.HasModellingRule)
    assert opc.opc.get_node(ua.ObjectIds.ModellingRule_Mandatory) == refs[0]

    refs = await p.get_referenced_nodes(refs=ua.ObjectIds.HasModellingRule)
    assert opc.opc.get_node(ua.ObjectIds.ModellingRule_Optional) == refs[0]

    await p.set_modelling_rule(None)
    refs = await p.get_referenced_nodes(refs=ua.ObjectIds.HasModellingRule)
    assert 0 == len(refs)
    await opc.opc.delete_nodes([v, p])


async def test_instantiate_1(opc):
    # Create device type
    dev_t = await opc.opc.nodes.base_object_type.add_object_type(ua.NodeId(NamespaceIndex=2), "0:MyDevice")
    v_t = await dev_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:sensor", 1.0)
    await v_t.set_modelling_rule(True)
    p_t = await dev_t.add_property(ua.NodeId(NamespaceIndex=2), "0:sensor_id", "0340")
    await p_t.set_modelling_rule(True)
    ctrl_t = await dev_t.add_object(ua.NodeId(NamespaceIndex=2), "0:controller")
    await ctrl_t.set_modelling_rule(True)
    v_opt_t = await dev_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:vendor", 1.0)
    await v_opt_t.set_modelling_rule(False)
    v_none_t = await dev_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:model", 1.0)
    await v_none_t.set_modelling_rule(None)
    prop_t = await ctrl_t.add_property(ua.NodeId(NamespaceIndex=2), "0:state", "Running")
    await prop_t.set_modelling_rule(True)
    assert await prop_t.read_value() == "Running"

    # Create device sutype
    devd_t = await dev_t.add_object_type(ua.NodeId(NamespaceIndex=2), "0:MyDeviceDerived")
    v_t = await devd_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:childparam", 1.0)
    await v_t.set_modelling_rule(True)
    p_t = await devd_t.add_property(ua.NodeId(NamespaceIndex=2), "0:sensorx_id", "0340")
    await p_t.set_modelling_rule(True)

    # instanciate device
    nodes = await instantiate(opc.opc.nodes.objects, dev_t, bname="2:Device0001", idx=2)
    mydevice = nodes[0]

    assert ua.NodeClass.Object == await mydevice.read_node_class()
    assert dev_t.nodeid == await mydevice.read_type_definition()
    _ = await mydevice.get_child(["0:controller"])
    prop = await mydevice.get_child(["0:controller", "0:state"])
    _ = await mydevice.get_child(["0:vendor"])
    with pytest.raises(ua.uaerrors.BadNoMatch):
        await mydevice.get_child(["0:model"])
    with pytest.raises(ua.uaerrors.BadNoMatch):
        await mydevice.get_child(["0:MyDeviceDerived"])

    assert ua.NodeId(ua.ObjectIds.PropertyType) == await prop.read_type_definition()
    assert "Running" == await prop.read_value()
    assert prop.nodeid != prop_t.nodeid

    # instanciate device subtype
    nodes = await instantiate(opc.opc.nodes.objects, devd_t, bname="2:Device0002", idx=2)
    mydevicederived = nodes[0]
    _ = await mydevicederived.get_child(["0:sensorx_id"])
    _ = await mydevicederived.get_child(["0:childparam"])
    _ = await mydevicederived.get_child(["0:sensor"])
    _ = await mydevicederived.get_child(["0:sensor_id"])
    await opc.opc.delete_nodes([devd_t, dev_t])


async def test_instantiate_string_nodeid(opc):
    # Create device type
    dev_t = await opc.opc.nodes.base_object_type.add_object_type(ua.NodeId(NamespaceIndex=2), "0:MyDevice2")
    v_t = await dev_t.add_variable(ua.NodeId(NamespaceIndex=2), "0:sensor", 1.0)
    await v_t.set_modelling_rule(True)
    p_t = await dev_t.add_property(ua.NodeId(NamespaceIndex=2), "0:sensor_id", "0340")
    await p_t.set_modelling_rule(True)
    ctrl_t = await dev_t.add_object(ua.NodeId(NamespaceIndex=2), "0:controller")
    await ctrl_t.set_modelling_rule(True)
    prop_t = await ctrl_t.add_property(ua.NodeId(NamespaceIndex=2), "0:state", "Running")
    await prop_t.set_modelling_rule(True)

    # instanciate device
    nodes = await instantiate(
        opc.opc.nodes.objects,
        dev_t,
        nodeid=ua.NodeId("InstDevice", 2, ua.NodeIdType.String),
        bname="2:InstDevice",
    )
    mydevice = nodes[0]

    assert ua.NodeClass.Object == await mydevice.read_node_class()
    assert dev_t.nodeid == await mydevice.read_type_definition()
    obj = await mydevice.get_child(["0:controller"])
    obj_nodeid_ident = obj.nodeid.Identifier
    prop = await mydevice.get_child(["0:controller", "0:state"])
    assert "InstDevice.controller" == obj_nodeid_ident
    assert ua.NodeId(ua.ObjectIds.PropertyType) == await prop.read_type_definition()
    assert "Running" == await prop.read_value()
    assert prop.nodeid != prop_t.nodeid
    await opc.opc.delete_nodes([dev_t])


async def test_instantiate_abstract(opc):
    finit_statemachine_type = opc.opc.get_node("ns=0;i=2771")  # IsAbstract=True
    with pytest.raises(ua.UaError):
        _ = await instantiate(
            opc.opc.nodes.objects,
            finit_statemachine_type,
            bname="2:TestFiniteStateMachine",
        )
