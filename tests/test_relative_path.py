import pytest

from enginir_opcua import ua
from enginir_opcua.ua.object_ids import ObjectIds
from enginir_opcua.ua.relative_path import RelativePathElementFormatter, RelativePathElementType
from enginir_opcua.ua.uaerrors import UaStringParsingError
from enginir_opcua.ua.uatypes import RelativePath


def test_relative_path():
    """
    The following examples from 1 to 7 are taken from OPC 10000-4 v1.05, A.2 (BNF of RelativePath).
    """

    path1 = RelativePath.from_string("/2:Block&.Output")

    assert 1 == len(path1.Elements)
    assert path1.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path1.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HierarchicalReferences
    assert path1.Elements[0].IncludeSubtypes is True
    assert path1.Elements[0].IsInverse is False
    assert path1.Elements[0].TargetName.NamespaceIndex == 2
    assert path1.Elements[0].TargetName.Name == "Block.Output"
    assert path1.to_string() == "/2:Block&.Output"

    path1_1 = RelativePath.from_string(".2:Block&.Output")

    assert 1 == len(path1.Elements)
    assert path1_1.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path1_1.Elements[0].ReferenceTypeId.Identifier == ObjectIds.Aggregates
    assert path1_1.Elements[0].IncludeSubtypes is True
    assert path1_1.Elements[0].IsInverse is False
    assert path1_1.Elements[0].TargetName.NamespaceIndex == 2
    assert path1_1.Elements[0].TargetName.Name == "Block.Output"
    assert path1_1.to_string() == ".2:Block&.Output"

    path2 = RelativePath.from_string("/3:Truck.0:NodeVersion")

    assert 2 == len(path2.Elements)
    assert path2.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path2.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HierarchicalReferences
    assert path2.Elements[0].IncludeSubtypes is True
    assert path2.Elements[0].IsInverse is False
    assert path2.Elements[0].TargetName.NamespaceIndex == 3
    assert path2.Elements[0].TargetName.Name == "Truck"
    assert path2.Elements[1].ReferenceTypeId.NamespaceIndex == 0
    assert path2.Elements[1].ReferenceTypeId.Identifier == ObjectIds.Aggregates
    assert path2.Elements[1].IncludeSubtypes is True
    assert path2.Elements[1].IsInverse is False
    assert path2.Elements[1].TargetName.NamespaceIndex == 0
    assert path2.Elements[1].TargetName.Name == "NodeVersion"
    assert path2.to_string() == "/3:Truck.NodeVersion"

    # TODO: Fix to use <1:ConnectedTo> when the non-standard reference types are supported.
    path3 = RelativePath.from_string("<0:HasChild>1:Boiler/1:HeatSensor")

    assert 2 == len(path3.Elements)
    assert path3.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path3.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasChild
    assert path3.Elements[0].IncludeSubtypes is True
    assert path3.Elements[0].IsInverse is False
    assert path3.Elements[0].TargetName.NamespaceIndex == 1
    assert path3.Elements[0].TargetName.Name == "Boiler"
    assert path3.Elements[1].ReferenceTypeId.NamespaceIndex == 0
    assert path3.Elements[1].ReferenceTypeId.Identifier == ObjectIds.HierarchicalReferences
    assert path3.Elements[1].IncludeSubtypes is True
    assert path3.Elements[1].IsInverse is False
    assert path3.Elements[1].TargetName.NamespaceIndex == 1
    assert path3.Elements[1].TargetName.Name == "HeatSensor"
    assert path3.to_string() == "<HasChild>1:Boiler/1:HeatSensor"

    # TODO: Fix to use <1:ConnectedTo> when the non-standard reference types are supported.
    path4 = RelativePath.from_string("<0:HasChild>1:Boiler/")

    assert 2 == len(path4.Elements)
    assert path4.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path4.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasChild
    assert path4.Elements[0].IncludeSubtypes is True
    assert path4.Elements[0].IsInverse is False
    assert path4.Elements[0].TargetName.NamespaceIndex == 1
    assert path4.Elements[0].TargetName.Name == "Boiler"
    assert path4.Elements[1].ReferenceTypeId.NamespaceIndex == 0
    assert path4.Elements[1].ReferenceTypeId.Identifier == ObjectIds.HierarchicalReferences
    assert path4.Elements[1].IncludeSubtypes is True
    assert path4.Elements[1].IsInverse is False
    assert path4.Elements[1].TargetName is None
    assert path4.to_string() == "<HasChild>1:Boiler/"

    path5 = RelativePath.from_string("<0:HasChild>2:Wheel")

    assert 1 == len(path5.Elements)
    assert path5.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path5.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasChild
    assert path5.Elements[0].IncludeSubtypes is True
    assert path5.Elements[0].IsInverse is False
    assert path5.Elements[0].TargetName.NamespaceIndex == 2
    assert path5.Elements[0].TargetName.Name == "Wheel"
    assert path5.to_string() == "<HasChild>2:Wheel"

    path6 = RelativePath.from_string("<!HasChild>Truck")

    assert 1 == len(path6.Elements)
    assert path6.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path6.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasChild
    assert path6.Elements[0].IncludeSubtypes is True
    assert path6.Elements[0].IsInverse is True
    assert path6.Elements[0].TargetName.NamespaceIndex == 0
    assert path6.Elements[0].TargetName.Name == "Truck"
    assert path6.to_string() == "<!HasChild>Truck"

    path7 = RelativePath.from_string("<0:HasChild>")

    assert 1 == len(path7.Elements)
    assert path7.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path7.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasChild
    assert path7.Elements[0].IncludeSubtypes is True
    assert path7.Elements[0].IsInverse is False
    assert path7.Elements[0].TargetName is None
    assert path7.to_string() == "<HasChild>"

    path8 = RelativePath.from_string("<#0:HasChild>Truck")

    assert 1 == len(path8.Elements)
    assert path8.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path8.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasChild
    assert path8.Elements[0].IncludeSubtypes is False
    assert path8.Elements[0].IsInverse is False
    assert path8.Elements[0].TargetName.NamespaceIndex == 0
    assert path8.Elements[0].TargetName.Name == "Truck"
    assert path8.to_string() == "<#HasChild>Truck"

    path9 = RelativePath.from_string("<#!0:HasChild>Truck")

    assert 1 == len(path9.Elements)
    assert path9.Elements[0].ReferenceTypeId.NamespaceIndex == 0
    assert path9.Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasChild
    assert path9.Elements[0].IncludeSubtypes is False
    assert path9.Elements[0].IsInverse is True
    assert path9.Elements[0].TargetName.NamespaceIndex == 0
    assert path9.Elements[0].TargetName.Name == "Truck"
    assert path9.to_string() == "<#!HasChild>Truck"


def test_relative_path_with_non_standard_reference_type():
    # TODO: Remove after the non-standard reference types are supported.
    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("<1:ConnectedTo>1:Boiler/1:HeatSensor")

    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("<1:ConnectedTo>1:Boiler/")


def test_relative_path_with_invalid_format():
    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("/1:<Boiler")  # Non-escaped '<' is invalid.

    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("/1:Boiler&")  # '&' is appeared without a follwing character.

    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("/1:Boiler&Output")  # '&' is followed by a non-reserved char.

    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("<0:HasChild")  # Closing delimiter '>' is missing.

    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("<0:>1:Boiler")  # Empty reference type name


def test_ua23_relative_path_element_is_forward_by_default() -> None:
    """Part 4, 7.30: IsInverse false means the reference is followed forward."""
    assert ua.RelativePathElement().IsInverse is False
    assert ua.RelativePathElement().IncludeSubtypes is True


def test_ua34_reference_type_name_must_be_a_reference_type() -> None:
    """Part 4, A.2: the name between the angle brackets is a ReferenceType BrowseName."""
    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("<Server>Foo")
    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("<Boolean>Foo")
    assert (
        RelativePath.from_string("<HasComponent>Foo").Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasComponent
    )


def test_ua34_reference_type_name_namespace_must_be_zero() -> None:
    """Part 4, A.2: a namespace index in the reference type name selects the namespace."""
    with pytest.raises(UaStringParsingError):
        RelativePath.from_string("<2:HasComponent>Foo")
    assert (
        RelativePath.from_string("<0:HasComponent>Foo").Elements[0].ReferenceTypeId.Identifier == ObjectIds.HasComponent
    )


def test_ua35_reference_type_id_in_other_namespace_is_not_written_as_a_name() -> None:
    """Part 4, A.2: only namespace 0 ReferenceTypes have a name in the text form."""
    element = ua.RelativePathElement(
        ReferenceTypeId=ua.NodeId(ObjectIds.HierarchicalReferences, 2),
        IsInverse=False,
        IncludeSubtypes=True,
        TargetName=ua.QualifiedName("x", 2),
    )
    with pytest.raises(UaStringParsingError):
        RelativePath(Elements=[element]).to_string()
    element.ReferenceTypeId = ua.NodeId(ObjectIds.Aggregates, 2)
    with pytest.raises(UaStringParsingError):
        RelativePath(Elements=[element]).to_string()


def test_ua35_non_reference_type_id_is_not_written_as_a_name() -> None:
    """Part 4, A.2: only ReferenceTypes have a name in the text form."""
    element = ua.RelativePathElement(
        ReferenceTypeId=ua.NodeId(ObjectIds.Server),
        IsInverse=False,
        IncludeSubtypes=True,
        TargetName=ua.QualifiedName("x", 2),
    )
    with pytest.raises(UaStringParsingError):
        RelativePath(Elements=[element]).to_string()


def test_ua36_target_with_namespace_and_empty_name_round_trips() -> None:
    """Part 4, A.2: a target is an optional namespace index and a name."""
    path = RelativePath.from_string("/2:")
    assert path.Elements[0].TargetName.NamespaceIndex == 2
    assert path.Elements[0].TargetName.Name == ""
    assert path.to_string() == "/2:"


def test_ua36_reference_without_name_cannot_be_written() -> None:
    """Part 4, A.2: a step without a reference type name is a hierarchical step."""
    formatter = RelativePathElementFormatter()
    formatter._element_type = RelativePathElementType.ForwardReference
    with pytest.raises(UaStringParsingError):
        formatter.to_string()
    formatter._element_type = RelativePathElementType.InverseReference
    with pytest.raises(UaStringParsingError):
        formatter.to_string()


def test_relative_path_error_names_the_input() -> None:
    with pytest.raises(UaStringParsingError, match="Boiler&Output"):
        RelativePath.from_string("/1:Boiler&Output")
