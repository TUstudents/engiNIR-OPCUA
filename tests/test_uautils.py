from dataclasses import dataclass

from enginir_opcua import ua
from enginir_opcua.common.ua_utils import copy_dataclass_attr, value_to_datavalue


def test_copy_dataclass_attr() -> None:
    @dataclass
    class A:
        x: int = 1
        y: int = 2

    @dataclass
    class B:
        y: int = 12
        z: int = 13

    b = B()
    a = A()

    assert a.y != b.y
    copy_dataclass_attr(a, b)
    assert a.y == b.y == 2
    assert a.x == 1
    assert b.z == 13

    b.y = 9
    copy_dataclass_attr(b, a)
    assert a.y == b.y == 9
    assert a.x == 1
    assert b.z == 13


def test_com12_write_value_sends_no_source_timestamp() -> None:
    """Part 4, 5.11.4.2: a server needs the TimestampWrite bit for a timestamp the client sends."""
    for value in (5, ua.Variant(5, ua.VariantType.Int32)):
        dv = value_to_datavalue(value)
        assert dv.SourceTimestamp is None
        assert dv.ServerTimestamp is None
