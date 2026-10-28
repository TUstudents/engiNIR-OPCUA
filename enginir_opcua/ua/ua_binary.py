"""
Binary protocol specific functions and constants
"""

from __future__ import annotations

import contextvars
import functools
import logging
import math
import struct
import sys
import typing
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import Field, fields, is_dataclass
from enum import Enum, IntFlag
from io import BytesIO
from types import UnionType
from typing import IO, Any, get_args, get_origin

from enginir_opcua import ua

from ..common.utils import Buffer, NotEnoughData
from .uaerrors import BadTcpMessageTypeInvalid, UaError
from .uatypes import (
    type_allow_subclass,
    type_from_list,
    type_from_optional,
    type_is_list,
    type_is_optional,
    type_is_union,
    types_or_list_from_union,
)

_logger = logging.getLogger(__name__)


_string_encoding = contextvars.ContextVar("ua_string_encoding", default="utf-8")
_nesting_depth = contextvars.ContextVar("ua_binary_nesting_depth", default=0)

MAX_NESTING_DEPTH: int = 100
MAX_ZERO_SIZE_ARRAY_COUNT: int = 65_536
MAX_DIAGNOSTIC_INFO_DEPTH: int = 10


def _bounded[**P, R](decode: Callable[P, R]) -> Callable[P, R]:
    @functools.wraps(decode)
    def bounded(*args: P.args, **kwargs: P.kwargs) -> R:
        depth = _nesting_depth.get()
        if depth >= MAX_NESTING_DEPTH:
            raise UaError(f"Data nested deeper than {MAX_NESTING_DEPTH} levels")
        token = _nesting_depth.set(depth + 1)
        try:
            return decode(*args, **kwargs)
        finally:
            _nesting_depth.reset(token)

    return bounded


def _read(data: Buffer | IO, size: int) -> bytes:
    if size < 0:
        raise UaError(f"Invalid length {size}")
    result = data.read(size)
    if len(result) != size:
        raise NotEnoughData(f"Not enough data left, request for {size}, we have {len(result)}")
    return result


def _check_array_count(data: Buffer | IO, count: int, element_size: int) -> None:
    if count < -1:
        raise UaError(f"Invalid array length {count}")
    if element_size == 0:
        if count > MAX_ZERO_SIZE_ARRAY_COUNT:
            raise UaError(f"Array of {count} elements without content exceeds {MAX_ZERO_SIZE_ARRAY_COUNT}")
    elif isinstance(data, Buffer) and count * element_size > len(data):
        raise NotEnoughData(f"Array of {count} elements does not fit the {len(data)} bytes left")


def _as_list(data: Any, allow_bytes: bool = False) -> list[Any]:
    if isinstance(data, list):
        return data
    if isinstance(data, str) or (isinstance(data, bytes | bytearray | memoryview) and not allow_bytes):
        raise UaError(f"Expected a sequence for an array, got {type(data).__name__}")
    try:
        return list(data)
    except TypeError as ex:
        raise UaError(f"Expected a sequence for an array, got {type(data).__name__}") from ex


def _can_be_empty(uatype: Any) -> bool:
    return (
        isinstance(uatype, type) and is_dataclass(uatype) and not issubclass(uatype, ua.UaUnion) and not fields(uatype)
    )


def get_string_encoding() -> str:
    return _string_encoding.get()


def set_string_encoding(new_encoding: str) -> None:
    _string_encoding.set(new_encoding)


def get_safe_type_hints(cls: type, extra_ns: dict[str, Any] | None = None) -> dict[str, Any]:
    # Use globalns=None so that get_type_hints automatically resolves the
    # module globals of cls (e.g. bare names like Byte).
    # Pass extra_ns (e.g. {'ua': ua}) as localns so ua.Xxx annotations resolve too.
    # Filter out properties from the class dict to avoid shadowing.
    localns = {k: v for k, v in cls.__dict__.items() if not isinstance(v, property)}
    if extra_ns:
        localns.update(extra_ns)

    return typing.get_type_hints(cls, globalns=None, localns=localns)


def is_bit_set(data: int, offset: int) -> bool:
    return bool(data & (1 << offset))


def set_bit(data: int, offset: int) -> int:
    mask = 1 << offset
    return data | mask


def unset_bit(data: int, offset: int) -> int:
    mask = 1 << offset
    return data & ~mask


class _DateTime:
    @staticmethod
    def pack(dt: Any) -> bytes:
        epch = ua.datetime_to_win_epoch(dt)
        return Primitives.Int64.pack(epch)

    @staticmethod
    def unpack(data: Buffer | IO) -> Any:
        epch = Primitives.Int64.unpack(data)
        return ua.win_epoch_to_datetime(epch)


class _Bytes:
    @staticmethod
    def pack(data: bytes | None) -> bytes:
        if data is None:
            return Primitives.Int32.pack(-1)
        length = len(data)
        return Primitives.Int32.pack(length) + data

    @staticmethod
    def unpack(data: Buffer | IO) -> bytes | None:
        length = Primitives.Int32.unpack(data)
        if length == -1:
            return None
        return _read(data, length)


class _String:
    @staticmethod
    def pack(string: str | bytes | None) -> bytes:
        if isinstance(string, str):
            string = string.encode(get_string_encoding(), errors="surrogateescape")
        return _Bytes.pack(string)

    @staticmethod
    def unpack(data: Buffer | IO) -> str | None:
        b = _Bytes.unpack(data)
        if b is None:
            return b
        return b.decode(
            get_string_encoding(), errors="surrogateescape"
        )  # not need to be strict here, this is user data


class _Null:
    @staticmethod
    def pack(data: Any) -> bytes:
        return b""

    @staticmethod
    def unpack(data: Any) -> None:
        return None


class _Guid:
    @staticmethod
    def pack(guid: uuid.UUID) -> bytes:
        # convert python UUID 6 field format to OPC UA 4 field format
        f1 = Primitives.UInt32.pack(guid.time_low)
        f2 = Primitives.UInt16.pack(guid.time_mid)
        f3 = Primitives.UInt16.pack(guid.time_hi_version)
        f4a = Primitives.Byte.pack(guid.clock_seq_hi_variant)
        f4b = Primitives.Byte.pack(guid.clock_seq_low)
        f4c = struct.pack(">Q", guid.node)[2:8]  # no primitive .pack available for 6 byte int
        f4 = f4a + f4b + f4c
        # concat byte fields
        b = f1 + f2 + f3 + f4

        return b

    @staticmethod
    def unpack(data: Buffer | IO) -> uuid.UUID:
        # convert OPC UA 4 field format to python UUID bytes
        f1 = struct.pack(">I", Primitives.UInt32.unpack(data))
        f2 = struct.pack(">H", Primitives.UInt16.unpack(data))
        f3 = struct.pack(">H", Primitives.UInt16.unpack(data))
        f4 = _read(data, 8)
        # concat byte fields
        b = f1 + f2 + f3 + f4

        return uuid.UUID(bytes=b)


class _Primitive1:
    def __init__(self, fmt: str) -> None:
        self._fmt = fmt
        st = struct.Struct(fmt.format(1))
        self.size = st.size
        self.format = st.format

    def pack(self, data: Any) -> bytes:
        return struct.pack(self.format, data)

    def unpack(self, data: Buffer | IO) -> Any:
        return struct.unpack(self.format, _read(data, self.size))[0]

    def pack_array(self, data: Iterable[Any] | None) -> bytes:
        if data is None:
            return Primitives.Int32.pack(-1)
        items = _as_list(data, allow_bytes=True)
        size_data = Primitives.Int32.pack(len(items))
        return size_data + struct.pack(self._fmt.format(len(items)), *items)

    def unpack_array(self, data: Buffer | IO, length: int) -> tuple[Any, ...] | None:
        _check_array_count(data, length, self.size)
        if length == -1:
            return None
        if length == 0:
            return ()
        return struct.unpack(self._fmt.format(length), _read(data, self.size * length))


class Primitives1:
    SByte = _Primitive1("<{:d}b")
    Int16 = _Primitive1("<{:d}h")
    Int32 = _Primitive1("<{:d}i")
    Int64 = _Primitive1("<{:d}q")
    Byte = _Primitive1("<{:d}B")
    Char = Byte
    UInt16 = _Primitive1("<{:d}H")
    UInt32 = _Primitive1("<{:d}I")
    UInt64 = _Primitive1("<{:d}Q")
    Boolean = _Primitive1("<{:d}?")
    Double = _Primitive1("<{:d}d")
    Float = _Primitive1("<{:d}f")


class Primitives(Primitives1):
    Null = _Null()
    String = _String()
    Bytes = _Bytes()
    ByteString = _Bytes()
    CharArray = _String()
    DateTime = _DateTime()
    Guid = _Guid()


@functools.cache
def create_uatype_serializer(vtype: ua.VariantType) -> Callable[[Any], bytes]:
    if hasattr(Primitives, vtype.name):
        return getattr(Primitives, vtype.name).pack
    if vtype.value > 25:
        return Primitives.Bytes.pack
    if vtype == ua.VariantType.ExtensionObject:
        return extensionobject_to_binary
    if vtype in (ua.VariantType.NodeId, ua.VariantType.ExpandedNodeId):
        return nodeid_to_binary
    if vtype == ua.VariantType.Variant:
        return variant_to_binary
    return struct_to_binary


def pack_uatype(vtype: ua.VariantType, value: Any) -> bytes:
    return create_uatype_serializer(vtype)(value)


@functools.cache
def _create_uatype_deserializer(vtype: ua.VariantType) -> Callable[[Any], Any]:
    if hasattr(Primitives, vtype.name):
        return getattr(Primitives, vtype.name).unpack
    if vtype.value > 25:
        return Primitives.Bytes.unpack
    if vtype == ua.VariantType.ExtensionObject:
        return extensionobject_from_binary
    if vtype in (ua.VariantType.NodeId, ua.VariantType.ExpandedNodeId):
        return nodeid_from_binary
    if vtype == ua.VariantType.Variant:
        return variant_from_binary
    if hasattr(ua, vtype.name):
        cls = getattr(ua, vtype.name)
        return _create_dataclass_deserializer(cls)
    raise UaError(f"Cannot unpack unknown variant type {vtype}")


def unpack_uatype(vtype: ua.VariantType, data: Buffer | IO) -> Any:
    return _create_uatype_deserializer(vtype)(data)


@functools.cache
def create_uatype_array_serializer(vtype: ua.VariantType) -> Callable[[Any], bytes]:
    if hasattr(Primitives1, vtype.name):
        data_type = getattr(Primitives1, vtype.name)
        return data_type.pack_array
    serializer = create_uatype_serializer(vtype)

    def serialize(array: Iterable[Any] | None) -> bytes:
        if array is None:
            return b"\xff\xff\xff\xff"
        items = _as_list(array)
        length = Primitives.Int32.pack(len(items))
        return length + b"".join(serializer(val) for val in items)

    return serialize


def pack_uatype_array(vtype: ua.VariantType, array: Iterable[Any] | None) -> bytes:
    return create_uatype_array_serializer(vtype)(array)


def unpack_uatype_array(vtype: ua.VariantType, data: Buffer | IO) -> list[Any] | None:
    return _create_uatype_array_deserializer(vtype)(data)


@functools.cache
def _create_uatype_array_deserializer(vtype: ua.VariantType) -> Callable[[Any], list[Any] | None]:
    if hasattr(Primitives1, vtype.name):  # Fast primitive array deserializer
        unpack_array = getattr(Primitives1, vtype.name).unpack_array
    else:  # Revert to slow serial unpacking.
        deserialize_element = _create_uatype_deserializer(vtype)

        element_size = 0 if vtype == ua.VariantType.Null else 1

        def unpack_array(data: Buffer | IO, length: int) -> Iterable[Any]:
            _check_array_count(data, length, element_size)
            return (deserialize_element(data) for _ in range(length))

    def deserialize(data: Buffer | IO) -> list[Any] | None:
        length = Primitives.Int32.unpack(data)
        if length == -1:
            return None
        # Remark: works without tuple conversion to list.
        return list(unpack_array(data, length))

    return deserialize


@functools.cache
def resolve_uatype(ftype: Any) -> tuple[Any, bool]:
    if isinstance(ftype, str):
        # Resolve string hint
        if ftype.startswith("ua."):
            ftype = getattr(ua, ftype[3:])
        elif hasattr(ua, ftype):
            ftype = getattr(ua, ftype)
        else:
            try:
                ftype = eval(
                    ftype,
                    {
                        "ua": ua,
                        "typing": typing,
                        "list": list,
                        "List": list,
                        "Union": typing.Union,
                        "Optional": typing.Optional,
                        "Dict": dict,
                    },
                )  # type: ignore[arg-type]
            except Exception:
                _logger.exception("Failed to resolve type hint: %s", ftype)
    is_optional = type_is_optional(ftype)
    if is_optional:
        ftype = type_from_optional(ftype)
    return ftype, is_optional


def _resolve_type_in_dataclass_context(ftype: Any, dataclazz: type) -> Any:
    # Forward references stored as raw strings (e.g. "OtherDataclass") need to be
    # eval'd against the dataclass's module globals so list element types can be
    # resolved without the eager class lookup breaking on mutually-recursive
    # dataclasses (A has list[B], B has list[A]).
    if not isinstance(ftype, str):
        return ftype
    module = sys.modules.get(getattr(dataclazz, "__module__", "")) if isinstance(dataclazz, type) else None
    namespace: dict[str, Any] = {
        "ua": ua,
        "typing": typing,
        "list": list,
        "List": list,
        "Union": typing.Union,
        "Optional": typing.Optional,
        "Dict": dict,
    }
    if module is not None:
        namespace.update(vars(module))
    if isinstance(dataclazz, type):
        namespace.update({k: v for k, v in dataclazz.__dict__.items() if not isinstance(v, property)})
    try:
        return eval(ftype, namespace)
    except Exception:
        return ftype


def field_serializer(uatype: Any, is_optional: bool, dataclazz: type) -> Callable[[Any], bytes]:
    if type_is_list(uatype):
        ft = type_from_list(uatype)
        ft = _resolve_type_in_dataclass_context(ft, dataclazz)
        if is_optional:
            return lambda val: b"" if val is None else create_list_serializer(ft)(val)
        return create_list_serializer(ft)
    if uatype == dataclazz:
        if is_optional:
            return lambda val: b"" if val is None else create_type_serializer(uatype)(val)
        return lambda x: create_type_serializer(uatype)(x)
    serializer = create_type_serializer(uatype)
    if is_optional:
        return lambda val: b"" if val is None else serializer(val)
    return serializer


@functools.cache
def create_dataclass_serializer(dataclazz: type) -> Callable[[Any], bytes]:
    """Given a dataclass, return a function that serializes instances of this dataclass"""
    if dataclazz is ua.LocalizedText:
        return _localizedtext_to_binary
    if dataclazz is ua.DiagnosticInfo:
        return diagnosticinfo_to_binary
    data_fields = fields(dataclazz)
    # The result is cached, so get_type_hints only runs once per class.
    try:
        resolved_fieldtypes = get_safe_type_hints(dataclazz, {"ua": ua})
    except Exception:
        _logger.warning("Failed to resolve type hints for %s", dataclazz)
        resolved_fieldtypes = {f.name: f.type for f in data_fields}

    if issubclass(dataclazz, ua.UaUnion):
        union_clazz: type[ua.UaUnion] = dataclazz  # type: ignore[assignment]
        encoding_funcs = [field_serializer(*resolve_uatype(t), dataclazz) for t in union_clazz._union_types]

        def union_serialize(obj: Any) -> bytes:
            bin = Primitives.UInt32.pack(obj.Encoding)
            if obj.Encoding == 0:
                return bin
            if obj.Encoding > len(encoding_funcs):
                raise UaError(f"Union {dataclazz.__name__} has {len(encoding_funcs)} fields, not {obj.Encoding}")
            serialize = encoding_funcs[obj.Encoding - 1]
            return b"".join([bin, serialize(obj.Value)])

        return union_serialize
    option_fields_encodings = [  # Name and binary encoding of optional fields
        (field.name, 1 << enc_count)
        for enc_count, field in enumerate(filter(lambda f: type_is_optional(resolved_fieldtypes[f.name]), data_fields))
    ]

    def enc_value(obj: Any) -> int:
        enc = 0
        for name, enc_val in option_fields_encodings:
            if getattr(obj, name) is not None:
                enc |= enc_val
        return enc

    encoding_functions = [
        (f.name, field_serializer(*resolve_uatype(resolved_fieldtypes[f.name]), dataclazz)) for f in data_fields
    ]

    def serialize(obj: Any) -> bytes:
        parts: list[bytes] = []
        for name, serializer in encoding_functions:
            if name == "Encoding":
                parts.append(serializer(enc_value(obj)))
            else:
                parts.append(serializer(getattr(obj, name)))
        return b"".join(parts)

    return serialize


def _localizedtext_to_binary(obj: ua.LocalizedText) -> bytes:
    mask = 0
    parts: list[bytes] = []
    if obj.Locale:
        mask |= 0x01
        parts.append(Primitives.String.pack(obj.Locale))
    if obj.Text:
        mask |= 0x02
        parts.append(Primitives.String.pack(obj.Text))
    return Primitives.Byte.pack(mask) + b"".join(parts)


_DIAGNOSTIC_INFO_INDEX_FIELDS = (
    ("SymbolicId", 0x01),
    ("NamespaceUri", 0x02),
    ("Locale", 0x08),
    ("LocalizedText", 0x04),
)
_DIAGNOSTIC_INFO_ADDITIONAL_INFO = 0x10
_DIAGNOSTIC_INFO_INNER_STATUS_CODE = 0x20
_DIAGNOSTIC_INFO_INNER_DIAGNOSTIC_INFO = 0x40


def diagnosticinfo_to_binary(info: ua.DiagnosticInfo, _level: int = 1) -> bytes:
    if _level > MAX_DIAGNOSTIC_INFO_DEPTH:
        raise UaError(f"DiagnosticInfo nested deeper than {MAX_DIAGNOSTIC_INFO_DEPTH} levels")
    mask = 0
    parts: list[bytes] = []
    for name, bit in _DIAGNOSTIC_INFO_INDEX_FIELDS:
        value = getattr(info, name)
        if value is not None:
            mask |= bit
            parts.append(Primitives.Int32.pack(value))
    if info.AdditionalInfo is not None:
        mask |= _DIAGNOSTIC_INFO_ADDITIONAL_INFO
        parts.append(Primitives.String.pack(info.AdditionalInfo))
    if info.InnerStatusCode is not None:
        mask |= _DIAGNOSTIC_INFO_INNER_STATUS_CODE
        parts.append(to_binary(ua.StatusCode, info.InnerStatusCode))
    if info.InnerDiagnosticInfo is not None:
        mask |= _DIAGNOSTIC_INFO_INNER_DIAGNOSTIC_INFO
        parts.append(diagnosticinfo_to_binary(info.InnerDiagnosticInfo, _level + 1))
    return Primitives.Byte.pack(mask) + b"".join(parts)


def struct_to_binary(obj: Any) -> bytes:
    serializer = create_dataclass_serializer(obj.__class__)
    return serializer(obj)


@functools.cache
def create_enum_serializer(uatype: type) -> Callable[[Any], bytes]:
    if issubclass(uatype, IntFlag):
        typename = "UInt32"
        if hasattr(uatype, "datatype"):
            typename = uatype.datatype()
        return getattr(Primitives, typename).pack
    if issubclass(uatype, int):
        return Primitives.Int32.pack
    return lambda val: Primitives.Int32.pack(val.value)


def strip_optional(tp: Any) -> Any:
    """Return the type with NoneType stripped if tp is Optional."""
    if get_origin(tp) in (UnionType, typing.Union):
        args = tuple(a for a in get_args(tp) if a is not type(None))
        if len(args) == 1:
            return args[0]
        return args  # still a union, but without NoneType
    return tp


@functools.cache
def create_type_serializer(uatype: type) -> Callable[[Any], bytes]:
    """Create a binary serialization function for the given UA type"""
    if not type_is_optional(uatype) and type_allow_subclass(uatype):
        return extensionobject_to_binary
    if type_is_list(uatype):
        return create_list_serializer(type_from_list(uatype))
    if issubclass(uatype, Enum):
        return create_enum_serializer(uatype)
    if hasattr(Primitives, uatype.__name__):
        return getattr(Primitives, uatype.__name__).pack
    if hasattr(ua.VariantType, uatype.__name__):
        vtype = getattr(ua.VariantType, uatype.__name__)
        return create_uatype_serializer(vtype)
    if issubclass(uatype, ua.NodeId):
        return nodeid_to_binary
    if issubclass(uatype, ua.Variant):
        return variant_to_binary
    if is_dataclass(uatype):
        return create_dataclass_serializer(uatype)
    raise UaError(f"No known way to pack value of type {uatype} to ua binary")


def to_binary(uatype: type, val: Any) -> bytes:
    return create_type_serializer(uatype)(val)


@functools.cache
def create_list_serializer(uatype: Any) -> Callable[[Iterable[Any] | None], bytes]:
    """
    Given a type, return a function that takes a list of instances
    of that type and serializes it.

    The element serializer is resolved on first call, not at construction time,
    so mutually-recursive dataclass lists (A has list[B], B has list[A]) do not
    infinitely re-enter when their codecs are first built.
    """
    if isinstance(uatype, type) and hasattr(Primitives1, uatype.__name__):
        data_type = getattr(Primitives1, uatype.__name__)
        return data_type.pack_array
    none_val = Primitives.Int32.pack(-1)
    type_serializer: Callable[[Any], bytes] | None = None

    def serialize(val: Iterable[Any] | None) -> bytes:
        nonlocal type_serializer
        if val is None:
            return none_val
        if type_serializer is None:
            type_serializer = create_type_serializer(uatype)
        items = _as_list(val)
        data_size = Primitives.Int32.pack(len(items))
        return data_size + b"".join(type_serializer(el) for el in items)

    return serialize


def list_to_binary(uatype: type, val: Iterable[Any] | None) -> bytes:
    return create_list_serializer(uatype)(val)


def nodeid_to_binary(nodeid: ua.NodeId) -> bytes:
    if isinstance(nodeid, ua.ExpandedNodeId) and nodeid.NamespaceUri and nodeid.NamespaceIndex:
        nodeid = ua.ExpandedNodeId(nodeid.Identifier, 0, nodeid.NodeIdType, nodeid.NamespaceUri, nodeid.ServerIndex)
    if nodeid.NodeIdType == ua.NodeIdType.TwoByte:
        packed = struct.pack("<BB", nodeid.NodeIdType.value, nodeid.Identifier)
    elif nodeid.NodeIdType == ua.NodeIdType.FourByte:
        packed = struct.pack("<BBH", nodeid.NodeIdType.value, nodeid.NamespaceIndex, nodeid.Identifier)
    elif nodeid.NodeIdType == ua.NodeIdType.Numeric:
        packed = struct.pack("<BHI", nodeid.NodeIdType.value, nodeid.NamespaceIndex, nodeid.Identifier)
    elif nodeid.NodeIdType == ua.NodeIdType.String:
        packed = struct.pack("<BH", nodeid.NodeIdType.value, nodeid.NamespaceIndex) + Primitives.String.pack(
            nodeid.Identifier
        )
    elif nodeid.NodeIdType == ua.NodeIdType.ByteString:
        packed = struct.pack("<BH", nodeid.NodeIdType.value, nodeid.NamespaceIndex) + Primitives.Bytes.pack(
            nodeid.Identifier
        )
    elif nodeid.NodeIdType == ua.NodeIdType.Guid:
        packed = struct.pack("<BH", nodeid.NodeIdType.value, nodeid.NamespaceIndex) + Primitives.Guid.pack(
            nodeid.Identifier
        )
    else:
        raise UaError(f"Unknown NodeIdType: {nodeid.NodeIdType} for NodeId: {nodeid}")
    if not isinstance(nodeid, ua.ExpandedNodeId):
        return packed
    if not nodeid.NamespaceUri and not nodeid.ServerIndex:
        return packed
    data = bytearray(packed)
    if nodeid.NamespaceUri:
        data[0] = set_bit(data[0], 7)
        data.extend(Primitives.String.pack(nodeid.NamespaceUri))
    if nodeid.ServerIndex:
        data[0] = set_bit(data[0], 6)
        data.extend(Primitives.UInt32.pack(nodeid.ServerIndex))
    return bytes(data)


def nodeid_from_binary(data: BytesIO | Buffer) -> ua.NodeId | ua.ExpandedNodeId:
    encoding = _read(data, 1)[0]
    try:
        nidtype = ua.NodeIdType(encoding & 0b00111111)
    except ValueError as ex:
        raise UaError(f"Unknown NodeId encoding: {encoding & 0b00111111}") from ex
    uri = None
    server_idx = None

    if nidtype == ua.NodeIdType.TwoByte:
        identifier = _read(data, 1)[0]
        nidx = 0
    elif nidtype == ua.NodeIdType.FourByte:
        nidx, identifier = struct.unpack("<BH", _read(data, 3))
    elif nidtype == ua.NodeIdType.Numeric:
        nidx, identifier = struct.unpack("<HI", _read(data, 6))
    elif nidtype == ua.NodeIdType.String:
        nidx = Primitives.UInt16.unpack(data)
        identifier = Primitives.String.unpack(data)
    elif nidtype == ua.NodeIdType.ByteString:
        nidx = Primitives.UInt16.unpack(data)
        identifier = Primitives.Bytes.unpack(data)
    else:
        nidx = Primitives.UInt16.unpack(data)
        identifier = Primitives.Guid.unpack(data)

    if is_bit_set(encoding, 7):
        uri = Primitives.String.unpack(data)
    if is_bit_set(encoding, 6):
        server_idx = Primitives.UInt32.unpack(data)

    if uri is not None or server_idx is not None:
        return ua.ExpandedNodeId(identifier, nidx, nidtype, uri, server_idx)
    return ua.NodeId(identifier, nidx, nidtype)


def variant_to_binary(var: ua.Variant) -> bytes:
    encoding = var.VariantType.value & 0b0011_1111
    try:
        if var.is_array or isinstance(var.Value, list | tuple):
            body = pack_uatype_array(var.VariantType, ua.flatten(var.Value))
            if var.Dimensions is None or len(var.Dimensions) < 2 or min(var.Dimensions) <= 0:
                encoding |= 0b1000_0000
            else:
                encoding |= 0b1100_0000
                body += pack_uatype_array(ua.VariantType.Int32, var.Dimensions)
        else:
            body = pack_uatype(var.VariantType, var.Value)
    except (struct.error, TypeError, OverflowError) as ex:
        # Common when a Python value does not match VariantType (e.g. float written as Int32).
        # Include VariantType and Python type so callers can find the offender (#1614).
        raise UaError(
            f"Cannot pack VariantType.{getattr(var.VariantType, 'name', var.VariantType)} "
            f"with value {var.Value!r} (python type {type(var.Value).__name__}): {ex}"
        ) from ex
    return Primitives.Byte.pack(encoding) + body


@_bounded
def variant_from_binary(data: Buffer | IO) -> ua.Variant:
    dimensions = None
    array = False
    encoding = _read(data, 1)[0]
    int_type = encoding & 0b00111111
    vtype = ua.datatype_to_varianttype(int_type)
    if is_bit_set(encoding, 7):
        value = unpack_uatype_array(vtype, data)
        array = True
    else:
        value = unpack_uatype(vtype, data)
    if is_bit_set(encoding, 6):
        if not array:
            raise UaError("Variant has dimensions but is not an array")
        dimensions = unpack_uatype_array(ua.VariantType.Int32, data)
        if not dimensions or min(dimensions) < 0:
            raise UaError(f"Variant has invalid dimensions {dimensions}")
        if value:
            value = _reshape(value, dimensions)
        elif value is not None and 0 not in dimensions:
            raise UaError(f"Variant has dimensions {dimensions} but no elements")
    return ua.Variant(value, vtype, dimensions, is_array=array)


MAX_RESHAPE_ELEMENTS: int = 1_000_000
"""Upper bound on the declared total size of a Variant Dimensions array.

Guards _reshape() against attacker-controlled Dimensions that would otherwise
allocate hundreds of MB of empty lists. Override at import time on a
per-deployment basis if you legitimately exchange larger dense arrays.
"""


def _reshape(flat: list[Any], dims: Sequence[int]) -> list[Any]:
    if not dims or min(dims) <= 0:
        raise UaError(f"Invalid Variant Dimensions {list(dims)}")
    declared = math.prod(dims)
    if declared > MAX_RESHAPE_ELEMENTS:
        raise UaError(
            f"Variant Dimensions declare {declared} elements, exceeds MAX_RESHAPE_ELEMENTS={MAX_RESHAPE_ELEMENTS}"
        )
    if declared != len(flat):
        raise UaError(f"Variant Dimensions {list(dims)} declare {declared} elements, the array has {len(flat)}")
    return _split(flat, dims)


def _split(flat: list[Any], dims: Sequence[int]) -> list[Any]:
    if len(dims) == 1:
        return flat
    subdims = dims[1:]
    subsize = math.prod(subdims)
    return [_split(flat[i : i + subsize], subdims) for i in range(0, len(flat), subsize)]


def _window(data: Buffer | IO, length: int) -> Buffer:
    if isinstance(data, Buffer):
        window = data.copy(length)
        data.skip(length)
        return window
    return Buffer(_read(data, length))


def _is_null_nodeid(nodeid: ua.NodeId) -> bool:
    return nodeid.NamespaceIndex == 0 and nodeid.Identifier == 0


@_bounded
def extensionobject_from_binary(data: Buffer | IO) -> Any:
    """
    Convert binary-coded ExtensionObject to a Python object.
    Returns an object, or None if TypeId is zero
    """
    typeid = nodeid_from_binary(data)
    encoding = _read(data, 1)[0]
    if encoding > 2:
        raise UaError(f"Unknown ExtensionObject encoding {encoding}")
    types = getattr(data, "types", None) or ua.default_types
    cls = types.class_for_encoding(typeid)
    registered = cls is not None
    window: Buffer | None = None
    unframed = False
    if encoding != 0:
        length = Primitives.Int32.unpack(data)
        if length < -1:
            raise UaError(f"Invalid ExtensionObject length {length}")
        if length == -1:
            if encoding != 1 or not registered:
                raise UaError(f"ExtensionObject {typeid} without length")
            unframed = True
        else:
            window = _window(data, length)
    if _is_null_nodeid(typeid):
        return ua.ExtensionObject()
    if registered and encoding != 2:
        assert cls is not None
        if not unframed and window is None:
            raise UaError(f"parsing ExtensionObject {cls.__name__} without data")
        return from_binary(cls, data if unframed else window)  # type: ignore[arg-type]
    opaque = ua.ExtensionObject(TypeId=typeid, Body=None if window is None else bytes(window))
    if encoding == 2:
        object.__setattr__(opaque, "Encoding", 2)
    return opaque


def _encoding_for_class_via_mro(cls: type) -> Any:
    # Slow path for the first encode of a hand-written subclass in uaprotocol_hand
    # (e.g. ObjectAttributes): walk the MRO to find an ancestor registered in
    # typeid_by_extension_objects, then cache the hit on the subclass so subsequent
    # encodes go through the dict-get fast path.
    for base in cls.__mro__[1:]:
        type_id = ua.typeid_by_extension_objects.get(base)
        if type_id is not None:
            ua.typeid_by_extension_objects[cls] = type_id
            return type_id
    raise KeyError(f"No registered encoding for class {cls}")


def extensionobject_to_binary(obj: Any) -> bytes:
    """
    Convert Python object to binary-coded ExtensionObject.
    If obj is None, convert to empty ExtensionObject (TypeId=0, no Body).
    Returns a binary string
    """
    if isinstance(obj, ua.ExtensionObject):
        if obj.Body is None:
            return nodeid_to_binary(obj.TypeId) + Primitives.Byte.pack(0)
        encoding = 0x02 if obj.Encoding == 2 else 0x01
        return nodeid_to_binary(obj.TypeId) + Primitives.Byte.pack(encoding) + Primitives.Bytes.pack(obj.Body)
    if obj is None:
        type_id = ua.NodeId()
        encoding = 0
        body = None
    else:
        type_id = ua.uatypes.encoding_id_for_class(obj.__class__)
        if type_id is None:
            type_id = _encoding_for_class_via_mro(obj.__class__)
        encoding = 0x01
        body = struct_to_binary(obj)
    packet = [
        nodeid_to_binary(type_id),
        Primitives.Byte.pack(encoding),
    ]
    if body is not None:
        packet.append(Primitives.Bytes.pack(body))
    return b"".join(packet)


@functools.cache
def _create_list_deserializer(uatype: Any) -> Callable[[Buffer | IO], list[Any]]:
    # Resolve the element deserializer lazily so mutually-recursive dataclass
    # lists don't infinitely re-enter during codec construction.
    element_deserializer: Callable[[Any], Any] | None = None

    element_size = 1

    def _deserialize(data: Buffer | IO) -> list[Any]:
        nonlocal element_deserializer, element_size
        size = Primitives.Int32.unpack(data)
        if element_deserializer is None:
            element_deserializer = _create_type_deserializer(uatype, type(None))
            element_size = 0 if _can_be_empty(resolve_uatype(uatype)[0]) else 1
        _check_array_count(data, size, element_size)
        if size == -1:
            return []
        return [element_deserializer(data) for _ in range(size)]

    return _deserialize


@functools.cache
def _create_type_deserializer(uatype: Any, dataclazz: type) -> Callable[[Buffer | IO], Any]:
    uatype, is_optional = resolve_uatype(uatype)

    if not is_optional and type_is_union(uatype):
        array, uatype = types_or_list_from_union(uatype)
        if not array:
            return _create_type_deserializer(uatype, uatype)
    if type_is_list(uatype):
        utype = type_from_list(uatype)
        utype = _resolve_type_in_dataclass_context(utype, dataclazz)
        if isinstance(utype, type) and hasattr(ua.VariantType, utype.__name__):
            vtype = getattr(ua.VariantType, utype.__name__)
            return _create_uatype_array_deserializer(vtype)
        return _create_list_deserializer(utype)
    if hasattr(ua.VariantType, uatype.__name__):
        vtype = getattr(ua.VariantType, uatype.__name__)
        return _create_uatype_deserializer(vtype)
    if hasattr(Primitives, uatype.__name__):
        return getattr(Primitives, uatype.__name__).unpack
    if uatype is dataclazz:
        # Self-recursive scalar field: defer the inner deserializer lookup until decode
        # time so building the outer deserializer doesn't infinitely re-enter.
        return lambda data: _create_dataclass_deserializer(uatype)(data)
    return _create_dataclass_deserializer(uatype)


def create_enum_deserializer(uatype: type[IntFlag] | type[Enum]) -> Callable[[Any], Any]:
    if issubclass(uatype, IntFlag):
        typename = "UInt32"
        if hasattr(uatype, "datatype"):
            typename = uatype.datatype()
        unpack = getattr(Primitives, typename).unpack
        return lambda val: uatype(unpack(val))

    is_abstract = not uatype.__members__

    def decode_enum(data: Buffer | IO) -> Any:
        value = Primitives.Int32.unpack(data)
        if is_abstract:
            return value
        try:
            return uatype(value)
        except ValueError as ex:
            raise UaError(f"{value} is not a valid {uatype.__name__}") from ex

    return decode_enum


def from_binary[T](uatype: type[T] | str, data: Buffer | IO) -> T:
    """
    unpack data given an uatype as a string or a python dataclass using ua types
    """
    return _create_type_deserializer(uatype, type(None))(data)


@functools.cache
def _create_dataclass_deserializer(objtype: type | str) -> Callable[[Buffer | IO], Any]:
    if isinstance(objtype, str):
        objtype = getattr(ua, objtype)
    assert isinstance(objtype, type)
    if objtype is ua.DiagnosticInfo:
        return diagnosticinfo_from_binary
    if issubclass(objtype, Enum):
        return create_enum_deserializer(objtype)  # type: ignore[arg-type]
    if issubclass(objtype, ua.UaUnion):
        union_type: type[ua.UaUnion] = objtype  # type: ignore[assignment]
        typefields = fields(union_type)
        union_field_deserializers = [_create_type_deserializer(t, union_type) for t in union_type._union_types]
        byte_decode = next(_create_type_deserializer(f.type, type(None)) for f in typefields if f.name == "Encoding")

        @_bounded
        def decode_union(data: Buffer | IO) -> Any:
            enc = byte_decode(data)
            if enc > len(union_field_deserializers):
                raise UaError(f"Union {objtype.__name__} has {len(union_field_deserializers)} fields, not {enc}")
            obj: Any = objtype()
            obj.Encoding = enc
            if enc > 0:
                obj.Value = union_field_deserializers[enc - 1](data)
            else:
                obj.Value = None
            return obj

        return decode_union
    enc_count = 0
    dc_field_deserializers: list[tuple[Field[Any], int, Callable[[Buffer | IO], Any]]] = []
    resolved_fieldtypes = get_safe_type_hints(objtype, {"ua": ua})
    for field in fields(objtype):
        optional_enc_bit = 0
        field_type = resolved_fieldtypes[field.name]
        # if our member has a switch and it is not set we will need to skip it
        if type_is_optional(field_type):
            optional_enc_bit = 1 << enc_count
            enc_count += 1
            field_type = type_from_optional(field_type)
        subtypes = type_allow_subclass(field_type)
        if subtypes:
            deserialize_field = extensionobject_from_binary
        else:
            deserialize_field = _create_type_deserializer(field_type, objtype)
        dc_field_deserializers.append((field, optional_enc_bit, deserialize_field))

    unassigned_bits_mask = ~functools.reduce(lambda mask, item: mask | item[1], dc_field_deserializers, 0)

    @_bounded
    def decode(data: Buffer | IO) -> Any:
        kwargs: dict[str, Any] = {}
        enc: int = 0
        for field, optional_enc_bit, deserialize_field in dc_field_deserializers:
            if field.name == "Encoding":
                enc = deserialize_field(data)
                if enc & unassigned_bits_mask:
                    raise UaError(f"{objtype.__name__} has unassigned encoding bits {enc & unassigned_bits_mask:#x}")
            elif optional_enc_bit == 0 or enc & optional_enc_bit:
                kwargs[field.name] = deserialize_field(data)
        return objtype(**kwargs)

    return decode


def _diagnosticinfo_from_binary(data: Buffer | IO, level: int) -> ua.DiagnosticInfo:
    if level > MAX_DIAGNOSTIC_INFO_DEPTH:
        raise UaError(f"DiagnosticInfo nested deeper than {MAX_DIAGNOSTIC_INFO_DEPTH} levels")
    mask = Primitives.Byte.unpack(data)
    if mask & 0x80:
        raise UaError(f"DiagnosticInfo has unassigned encoding bits {mask & 0x80:#x}")
    kwargs: dict[str, Any] = {}
    for name, bit in _DIAGNOSTIC_INFO_INDEX_FIELDS:
        if mask & bit:
            kwargs[name] = Primitives.Int32.unpack(data)
    if mask & _DIAGNOSTIC_INFO_ADDITIONAL_INFO:
        kwargs["AdditionalInfo"] = Primitives.String.unpack(data)
    if mask & _DIAGNOSTIC_INFO_INNER_STATUS_CODE:
        kwargs["InnerStatusCode"] = from_binary(ua.StatusCode, data)
    if mask & _DIAGNOSTIC_INFO_INNER_DIAGNOSTIC_INFO:
        kwargs["InnerDiagnosticInfo"] = _diagnosticinfo_from_binary(data, level + 1)
    return ua.DiagnosticInfo(**kwargs)


@_bounded
def diagnosticinfo_from_binary(data: Buffer | IO) -> ua.DiagnosticInfo:
    return _diagnosticinfo_from_binary(data, 1)


def struct_from_binary[T](objtype: type[T] | str, data: IO | Buffer) -> T:
    """
    unpack an ua struct. Arguments are an objtype as Python dataclass or string
    """
    return _create_dataclass_deserializer(objtype)(data)


def header_to_binary(hdr: ua.Header) -> bytes:
    b = [struct.pack("<3ss", hdr.MessageType, hdr.ChunkType)]
    size = hdr.body_size + 8
    if hdr.MessageType in (ua.MessageType.SecureOpen, ua.MessageType.SecureClose, ua.MessageType.SecureMessage):
        size += 4
    b.append(Primitives.UInt32.pack(size))
    if hdr.MessageType in (ua.MessageType.SecureOpen, ua.MessageType.SecureClose, ua.MessageType.SecureMessage):
        b.append(Primitives.UInt32.pack(hdr.ChannelId))
    return b"".join(b)


def header_from_binary(data: Buffer | IO) -> ua.Header:
    hdr = ua.Header()
    hdr.MessageType, hdr.ChunkType, hdr.packet_size = struct.unpack("<3scI", _read(data, 8))
    if hdr.packet_size < hdr.header_size:
        raise BadTcpMessageTypeInvalid()
    hdr.body_size = hdr.packet_size - hdr.header_size
    if hdr.header_size == 12:
        hdr.ChannelId = Primitives.UInt32.unpack(data)
    return hdr


def uatcp_to_binary(message_type: ua.MessageType, message: Any) -> bytes:
    """
    Convert OPC UA TCP message (see OPC UA specs Part 6, 7.1) to binary.
    The only supported types are Hello, Acknowledge and ErrorMessage
    """
    header = ua.Header(message_type, ua.ChunkType.Single)
    binmsg = struct_to_binary(message)
    header.body_size = len(binmsg)
    return header_to_binary(header) + binmsg
