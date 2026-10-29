import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer, NotEnoughData, fields_with_resolved_types


def test_com1_negative_read_raises() -> None:
    """Part 6, 5.1.2: a decoder never reads before its current position."""
    buf = Buffer(b"0123456789")
    buf.read(4)
    with pytest.raises(NotEnoughData):
        buf.read(-2)
    assert buf.cur_pos == 4
    assert len(buf) == 6


def test_com1_negative_skip_raises() -> None:
    """Part 6, 5.1.2: a decoder never reads before its current position."""
    buf = Buffer(b"0123456789")
    buf.skip(4)
    with pytest.raises(NotEnoughData):
        buf.skip(-2)
    assert buf.cur_pos == 4
    assert len(buf) == 6


def test_com1_read_past_end_leaves_cursor() -> None:
    buf = Buffer(b"0123")
    with pytest.raises(NotEnoughData):
        buf.read(5)
    assert buf.read(4) == b"0123"


def test_com2_copy_window_bytes_len_rewind() -> None:
    """Part 6, 5.1.2: a copy is limited to its window."""
    window = Buffer(b"0123456789").copy(3)
    assert bytes(window) == b"012"
    assert len(window) == 3
    window.read(2)
    assert bytes(window) == b"2"
    window.rewind()
    assert len(window) == 3
    assert bytes(window) == b"012"


def test_com2_rewind_defaults_to_window_start() -> None:
    buf = Buffer(b"0123456789")
    buf.read(4)
    window = buf.copy(3)
    window.read(3)
    window.rewind()
    assert window.cur_pos == 4
    assert bytes(window) == b"456"


def test_com2_rewind_outside_window_raises() -> None:
    buf = Buffer(b"0123456789")
    buf.read(4)
    window = buf.copy(3)
    with pytest.raises(ua.UaError):
        window.rewind(2)
    with pytest.raises(ua.UaError):
        window.rewind(8)
    window.rewind(7)
    assert len(window) == 0


def test_com2_rewind_absolute_position_in_window() -> None:
    buf = Buffer(b"0123456789")
    buf.read(4)
    window = buf.copy(5)
    window.read(3)
    window.rewind(5)
    assert bytes(window) == b"5678"


def test_com2_copy_larger_than_remaining_raises() -> None:
    buf = Buffer(b"0123")
    buf.read(1)
    with pytest.raises(NotEnoughData):
        buf.copy(4)
    assert len(buf.copy()) == 3
    assert len(buf.copy(3)) == 3


def test_com2_copy_negative_raises() -> None:
    with pytest.raises(ua.UaError):
        Buffer(b"0123").copy(-2)


def test_com2_copy_does_not_move_original() -> None:
    buf = Buffer(b"0123456789")
    window = buf.copy(3)
    window.read(3)
    assert buf.cur_pos == 0
    assert len(buf) == 10


@pytest.mark.parametrize(
    ("start", "size"),
    [(-1, -1), (11, -1), (0, 11), (5, 6), (0, -2), (2, -5)],
)
def test_com2_constructor_validates_window(start: int, size: int) -> None:
    """Part 6, 5.1.2: the window must lie inside the data."""
    with pytest.raises(ua.UaError):
        Buffer(b"0123456789", start, size)


def test_com2_constructor_accepts_valid_windows() -> None:
    assert len(Buffer(b"0123456789", 10)) == 0
    assert len(Buffer(b"0123456789", 2, 8)) == 8
    assert len(Buffer(b"")) == 0


def test_com3_fields_with_resolved_types_returns_copies() -> None:
    original = [f.type for f in ua.ReadValueId.__dataclass_fields__.values()]
    assert all(isinstance(t, str) for t in original)
    resolved = fields_with_resolved_types(ua.ReadValueId, globalns={"ua": ua})
    assert all(not isinstance(f.type, str) for f in resolved)
    assert [f.type for f in ua.ReadValueId.__dataclass_fields__.values()] == original
