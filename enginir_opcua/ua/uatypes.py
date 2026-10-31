"""
implement ua datatypes
"""

from __future__ import annotations

import ast
import contextlib
import contextvars
import functools
import itertools
import logging
import operator
import re
import types
import uuid
import weakref
from base64 import b64decode, b64encode
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import TYPE_CHECKING, Any, ClassVar, Self, Union, cast, get_args, get_origin
from urllib.parse import unquote

from enginir_opcua.ua.object_ids import ObjectIds

if TYPE_CHECKING:
    import enginir_opcua.ua as ua


from enginir_opcua.ua import status_codes

from .uaerrors import UaError, UaStatusCodeError, UaStringParsingError

_logger = logging.getLogger(__name__)

EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
FILETIME_EPOCH_AS_DATETIME = datetime(1601, 1, 1)
FILETIME_EPOCH_AS_UTC_DATETIME = FILETIME_EPOCH_AS_DATETIME.replace(tzinfo=UTC)
MAX_FILETIME_EPOCH_DATETIME = datetime(9999, 12, 31, 23, 59, 59)
MAX_FILETIME_EPOCH_AS_UTC_DATETIME = MAX_FILETIME_EPOCH_DATETIME.replace(tzinfo=UTC)
MAX_OPC_FILETIME = (
    int((MAX_FILETIME_EPOCH_DATETIME - FILETIME_EPOCH_AS_DATETIME).total_seconds()) * HUNDREDS_OF_NANOSECONDS
)
MAX_INT64 = 2**63 - 1


def type_is_optional(uatype: Any) -> bool:
    return get_origin(uatype) in (Union, types.UnionType) and type(None) in get_args(uatype)


def type_is_union(uatype: Any) -> bool:
    return get_origin(uatype) in (Union, types.UnionType)


def type_is_list(uatype: Any) -> bool:
    return get_origin(uatype) is list


def type_allow_subclass(uatype: Any) -> bool:
    return get_origin(uatype) not in [types.UnionType, Union, list, None]


def types_or_list_from_union(uatype: Any) -> tuple[bool, Any]:
    members = []
    for subtype in get_args(uatype):
        if type_is_list(subtype):
            return True, subtype
        if subtype is not type(None):
            members.append(subtype)
    if not members:
        raise ValueError(f"Union {uatype} does not seem to contain a valid type")
    return False, members[0]


def types_from_union(uatype: Any, origin: Any = None) -> list[Any]:
    if origin is None:
        origin = get_origin(uatype)
    if origin not in (Union, types.UnionType):
        raise ValueError(f"{uatype} is not an Union")
    members = [subtype for subtype in get_args(uatype) if subtype is not type(None)]
    if not members:
        raise ValueError(f"Union {uatype} does not seem to contain a valid type")
    return members


def type_from_list(uatype: Any) -> Any:
    return get_args(uatype)[0]


def type_from_optional(uatype: Any) -> Any:
    return get_args(uatype)[0]


def type_from_allow_subtype(uatype: Any) -> Any:
    return get_args(uatype)[0]


def _split_top_level_union(annotation: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for position, char in enumerate(annotation):
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
        elif char == "|" and depth == 0:
            parts.append(annotation[start:position].strip())
            start = position + 1
    parts.append(annotation[start:].strip())
    return parts


def _type_name_from_string(annotation: str) -> str:
    annotation = annotation.strip("'\" ")
    members = [member for member in _split_top_level_union(annotation) if member.strip("'\" ") != "None"]
    member = members[0].strip("'\" ") if members else annotation
    for prefix in ("Optional[", "list[", "List["):
        if member.startswith(prefix) and member.endswith("]"):
            return _type_name_from_string(member[len(prefix) : -1])
    return member.rsplit(".", 1)[-1]


def type_string_from_type(uatype: Any) -> str:
    if isinstance(uatype, str):
        return _type_name_from_string(uatype)
    while True:
        if type_is_union(uatype):
            uatype = types_from_union(uatype)[0]
        elif type_is_list(uatype):
            uatype = type_from_list(uatype)
        elif type_allow_subclass(uatype):
            uatype = type_from_allow_subtype(uatype)
        else:
            return uatype.__name__


@dataclass
class UaUnion:
    _union_types: ClassVar[list[Any]] = []


class Number(float):
    pass


if TYPE_CHECKING:
    SByte = int
    Byte = int
    Bytes = bytes
    ByteString = bytes
    Int16 = int
    Int32 = int
    Int64 = int
    UInt16 = int
    UInt32 = int
    UInt64 = int
    Boolean = bool
    Double = float
    Float = float
    String = str
    CharArray = str
    DateTime = datetime
    Guid = uuid.UUID
else:

    class SByte(int):
        pass

    class Byte(int):
        pass

    class Bytes(bytes):
        pass

    class ByteString(bytes):
        pass

    class Int16(int):
        pass

    class Int32(int):
        pass

    class Int64(int):
        pass

    class UInt16(int):
        pass

    class UInt32(int):
        pass

    class UInt64(int):
        pass

    class Boolean:
        pass

    class Double(float):
        pass

    class Float(float):
        pass

    class String(str):
        pass

    class CharArray(str):
        pass

    class DateTime(datetime):
        pass

    class Guid(uuid.UUID):
        pass


class Null:
    pass


class Enumeration(IntEnum):
    pass


_microsecond = timedelta(microseconds=1)


def datetime_to_win_epoch(dt: datetime) -> int:
    if dt.tzinfo is None:
        ref = FILETIME_EPOCH_AS_DATETIME
        max_ep = MAX_FILETIME_EPOCH_DATETIME
    else:
        ref = FILETIME_EPOCH_AS_UTC_DATETIME
        max_ep = MAX_FILETIME_EPOCH_AS_UTC_DATETIME
    # Python datetime starts from year 1, opc ua only support dates starting 1601-01-01 12:00AM UTC
    # So we need to trunc the value to zero
    if ref >= dt:
        return 0
    # A date/time is encoded as the maximum value for an Int64 if either
    # The value is equal to or greater than 9999-12-31 11:59:59PM UTC,
    if dt >= max_ep:
        return MAX_INT64
    return 10 * ((dt - ref) // _microsecond)


def get_win_epoch() -> datetime:
    return win_epoch_to_datetime(0)


def win_epoch_to_datetime(epch: int) -> datetime:
    if epch >= MAX_OPC_FILETIME:
        # FILETIMEs after 31 Dec 9999 are truncated to max value
        return MAX_FILETIME_EPOCH_AS_UTC_DATETIME
    if epch < 0:
        return FILETIME_EPOCH_AS_UTC_DATETIME
    return FILETIME_EPOCH_AS_UTC_DATETIME + timedelta(microseconds=epch // 10)


class ValueRank(IntEnum):
    """
    Defines dimensions of a variable.
    This enum does not support all cases since ValueRank support any n>0
    but since it is an IntEnum it can be replaced by a normal int
    """

    ScalarOrOneDimension = -3
    Any = -2
    Scalar = -1
    OneOrMoreDimensions = 0
    OneDimension = 1
    # the next names are not in spec but so common we express them here
    TwoDimensions = 2
    ThreeDimensions = 3
    FourDimensions = 4


class _MaskEnum(IntEnum):
    @classmethod
    def parse_bitfield(cls, the_int: int) -> set[Self]:
        """Take an integer and interpret it as a set of enum values."""
        if not isinstance(the_int, int):
            raise ValueError(f"Argument should be an int, we received {the_int} of type {type(the_int)}")
        return {cls(b) for b in cls._bits(the_int) if b in cls._value2member_map_}

    @classmethod
    def to_bitfield(cls, collection: Any) -> int:
        """Takes some enum values and creates an integer from them."""
        # make sure all elements are of the correct type (use itertools.tee in case we get passed an
        # iterator)
        iter1, iter2 = itertools.tee(iter(collection))
        if not all(isinstance(x, cls) for x in iter1):
            raise TypeError(f"All elements have to be of type {cls}")
        return functools.reduce(operator.or_, (x.mask for x in iter2), 0)

    @property
    def mask(self) -> int:
        return 1 << self.value

    @staticmethod
    def _bits(n: int) -> Any:
        """Iterate over the bits in n.

        e.g. bits(44) yields at 2, 3, 5
        """
        if not n >= 0:  # avoid infinite recursion
            raise ValueError()
        pos = 0
        while n:
            if n & 0x1:
                yield pos
            n //= 2
            pos += 1


class AccessLevel(_MaskEnum):
    """
    Bit index to indicate what the access level is.

    OPC 10000-3 v1.05, 5.6.2 (Variable NodeClass), and in the other NodeClasses that have the Attribute.
    """

    CurrentRead = 0
    CurrentWrite = 1
    HistoryRead = 2
    HistoryWrite = 3
    SemanticChange = 4
    StatusWrite = 5
    TimestampWrite = 6


class WriteMask(_MaskEnum):
    """
    Bit index to indicate which attribute of a node is writable

    OPC 10000-3 v1.05, 5.2.7 (WriteMask).
    """

    AccessLevel = 0
    ArrayDimensions = 1
    BrowseName = 2
    ContainsNoLoops = 3
    DataType = 4
    Description = 5
    DisplayName = 6
    EventNotifier = 7
    Executable = 8
    Historizing = 9
    InverseName = 10
    IsAbstract = 11
    MinimumSamplingInterval = 12
    NodeClass = 13
    NodeId = 14
    Symmetric = 15
    UserAccessLevel = 16
    UserExecutable = 17
    UserWriteMask = 18
    ValueRank = 19
    WriteMask = 20
    ValueForVariableType = 21
    DataTypeDefinition = 22
    RolePermissions = 23
    AccessRestrictions = 24
    AccessLevelEx = 25


class EventNotifier(_MaskEnum):
    """
    Bit index to indicate how a node can be used for events.

    OPC 10000-3 v1.05, 5.4 (View NodeClass), and in the other NodeClasses that have the Attribute.
    """

    SubscribeToEvents = 0
    # Reserved        = 1
    HistoryRead = 2
    HistoryWrite = 3


@dataclass(slots=True)
class StatusCode:
    """
    :ivar value:
    :vartype value: int
    :ivar name: symbolic name, ignoring the low 16 bits
    :vartype name: string
    :ivar doc: description, ignoring the low 16 bits
    :vartype doc: string
    """

    value: "ua.UInt32" = status_codes.StatusCodes.Good

    def __post_init__(self) -> None:
        if isinstance(self.value, str):
            try:
                object.__setattr__(self, "value", getattr(status_codes.StatusCodes, self.value))
            except AttributeError:
                raise UaError(f"Unknown StatusCode name: {self.value!r}") from None

    def check(self) -> None:
        """
        Raises an exception if the severity is not Good, so Uncertain raises too.
        """
        if not self.is_good():
            raise UaStatusCodeError(self.value)

    def is_good(self) -> bool:
        """
        return True if status is Good (00).
        """
        mask = 3 << 30
        if mask & self.value == 0x00000000:
            return True
        return False

    def is_bad(self) -> bool:
        """
        OPC 10000-4 v1.05, 7.38.1:
        11   Reserved for future use. All Clients should treat a StatusCode with this severity as “Bad”.

        return True if status is Bad (10) or (11).
        """
        mask = 3 << 30
        if mask & self.value in (0x80000000, 0xC0000000):
            return True
        return False

    def is_uncertain(self) -> bool:
        """
        return True if status is Uncertain (01).
        """
        mask = 3 << 30
        if mask & self.value == 0x40000000:
            return True
        return False

    @property
    def name(self) -> str:
        name, _ = status_codes.get_name_and_doc(self.value & 0xFFFF0000)
        return name

    @property
    def doc(self) -> str:
        _, doc = status_codes.get_name_and_doc(self.value & 0xFFFF0000)
        return doc


class NodeIdType(IntEnum):
    TwoByte = 0
    FourByte = 1
    Numeric = 2
    String = 3
    Guid = 4
    ByteString = 5


_OPC_UA_NAMESPACE_URI = "http://opcfoundation.org/UA/"
_GUID_PATTERN = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_DIGITS_PATTERN = re.compile(r"[0-9]+")
_INDEX_PREFIX_PATTERN = re.compile(r"([0-9]+):")
_NODEID_FAMILY = {
    NodeIdType.TwoByte: 0,
    NodeIdType.FourByte: 0,
    NodeIdType.Numeric: 0,
    NodeIdType.String: 1,
    NodeIdType.Guid: 2,
    NodeIdType.ByteString: 3,
}


def _encode_uri(uri: str) -> str:
    return uri.replace("%", "%25").replace(";", "%3B")


def _decode_uri(uri: str) -> str:
    return unquote(uri, errors="strict")


def _parse_digits(value: str, what: str) -> int:
    if not _DIGITS_PATTERN.fullmatch(value):
        raise ValueError(f"{what} must be a sequence of digits, got {value!r}")
    return int(value)


@dataclass(eq=False, order=False, slots=True)
class NodeId:
    """
    NodeId Object

    Args:
        identifier: The identifier might be an int, a string, bytes or a Guid
        namespace_index(int): The index of the namespace
        node_id_type(NodeIdType): The type of the nodeid if it cannot be guessed, or you want something
        special like twobyte nodeid or fourbytenodeid

    The string form is the one of OPC 10000-6 v1.05, 5.1.12, for example ``ns=2;s=Name``.

    :ivar Identifier: int, str, bytes or uuid.UUID
    :vartype Identifier: UInt32, String, Guid or ByteString
    :ivar NamespaceIndex:
    :vartype NamespaceIndex: UInt16
    :ivar NodeIdType: the wire format, not part of the identity
    :vartype NodeIdType: NodeIdType
    """

    Identifier: "ua.UInt32 | ua.String | ua.Guid | ua.ByteString" = 0
    NamespaceIndex: "ua.UInt16" = 0
    NodeIdType: "ua.NodeIdType" = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.NodeIdType is None:
            if isinstance(self.Identifier, int):
                if self.Identifier <= 255 and self.NamespaceIndex == 0:
                    object.__setattr__(self, "NodeIdType", NodeIdType.TwoByte)
                elif self.Identifier <= 65535 and self.NamespaceIndex <= 255:
                    object.__setattr__(self, "NodeIdType", NodeIdType.FourByte)
                else:
                    object.__setattr__(self, "NodeIdType", NodeIdType.Numeric)
            elif isinstance(self.Identifier, str):
                object.__setattr__(self, "NodeIdType", NodeIdType.String)
            elif isinstance(self.Identifier, bytes):
                object.__setattr__(self, "NodeIdType", NodeIdType.ByteString)
            elif isinstance(self.Identifier, uuid.UUID):
                object.__setattr__(self, "NodeIdType", NodeIdType.Guid)
            else:
                raise UaError("NodeId: Could not guess type of NodeId, set NodeIdType")
        else:
            self.check_identifier_type_compatibility()

    def check_identifier_type_compatibility(self) -> None:
        """
        Check whether the given identifier can be interpreted as the given node identifier type.
        """
        valid_type_combinations = [
            (int, [NodeIdType.Numeric, NodeIdType.TwoByte, NodeIdType.FourByte]),
            (str, [NodeIdType.String]),
            (bytes, [NodeIdType.ByteString]),
            (uuid.UUID, [NodeIdType.Guid]),
        ]
        for identifier, valid_node_types in valid_type_combinations:
            if isinstance(self.Identifier, identifier) and self.NodeIdType in valid_node_types:
                return
        raise UaError(
            f"NodeId of type {self.NodeIdType.name} has an incompatible identifier {self.Identifier!r} of type {type(self.Identifier)}"
        )

    def __eq__(self, node: object) -> bool:
        if isinstance(node, ExpandedNodeId) and not isinstance(self, ExpandedNodeId):
            return node.__eq__(self)
        return (
            isinstance(node, NodeId)
            and self.NamespaceIndex == node.NamespaceIndex
            and self.Identifier == node.Identifier
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def __hash__(self) -> int:
        return hash((self.NamespaceIndex, self.Identifier))

    def _sort_key(self) -> tuple[Any, ...]:
        return (_NODEID_FAMILY[self.NodeIdType], self.NamespaceIndex, self.Identifier, "", 0)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, NodeId):
            return NotImplemented
        return self._sort_key() < other._sort_key()

    def __le__(self, other: object) -> bool:
        if not isinstance(other, NodeId):
            return NotImplemented
        return self._sort_key() <= other._sort_key()

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, NodeId):
            return NotImplemented
        return self._sort_key() > other._sort_key()

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, NodeId):
            return NotImplemented
        return self._sort_key() >= other._sort_key()

    def is_null(self) -> bool:
        if self.NamespaceIndex != 0:
            return False
        return self.has_null_identifier()

    def has_null_identifier(self) -> bool:
        if not self.Identifier:
            return True
        if self.NodeIdType is NodeIdType.Guid:
            if not isinstance(self.Identifier, uuid.UUID):
                raise ValueError(f"Expected Guid, got {type(self.Identifier)}")
            return self.Identifier.int == 0
        return False

    @staticmethod
    def from_string(string: str) -> NodeId:
        try:
            return NodeId._from_string(string)
        except ValueError as ex:
            raise UaStringParsingError(f"Error parsing string {string}", ex) from ex

    @staticmethod
    def _parse_identifier(component: str) -> tuple["ua.NodeIdType", Any]:
        key, separator, value = component.partition("=")
        if not separator:
            raise ValueError(f"Unknown component {component!r}")
        if key == "i":
            return NodeIdType.Numeric, _parse_digits(value, "Numeric identifier")
        if key == "s":
            return NodeIdType.String, String(value)
        if key == "g":
            if not _GUID_PATTERN.fullmatch(value):
                raise ValueError(f"Malformed Guid {value!r}")
            return NodeIdType.Guid, uuid.UUID(value)
        if key == "b":
            return NodeIdType.ByteString, b64decode(value.encode("ascii"), validate=True)
        raise ValueError(f"Unknown key {key!r}")

    @staticmethod
    def _from_string(string: str) -> NodeId:
        remaining = string
        server_index = 0
        namespace_index = 0
        namespace_uri: str | None = None
        has_server = False
        stage = 0
        while True:
            key, separator, value = remaining.partition("=")
            if separator and key in ("svr", "srv", "svu", "ns", "nsu"):
                text, semicolon, rest = value.partition(";")
                if not semicolon:
                    raise ValueError("The identifier must come last")
                if key == "svu":
                    raise ValueError("Server URIs are not supported")
                if key in ("svr", "srv"):
                    if stage > 0:
                        raise ValueError("svr must come first")
                    server_index = _parse_digits(text, "svr")
                    has_server = True
                    stage = 1
                else:
                    if stage > 1:
                        raise ValueError("Only one of ns and nsu is allowed")
                    if key == "ns":
                        namespace_index = _parse_digits(text, "ns")
                    else:
                        namespace_uri = _decode_uri(text)
                    stage = 2
                remaining = rest
                continue
            break
        if remaining.endswith(";") and not remaining.startswith("s="):
            remaining = remaining[:-1]
        node_id_type, identifier = NodeId._parse_identifier(remaining)
        if namespace_uri is not None or has_server:
            return ExpandedNodeId(
                identifier, namespace_index, node_id_type, NamespaceUri=namespace_uri, ServerIndex=server_index
            )
        return NodeId(identifier, namespace_index, node_id_type)

    def _identifier_string(self) -> str:
        identifier = self.Identifier
        if self.NodeIdType == NodeIdType.Guid:
            return f"g={identifier!s}"
        if self.NodeIdType == NodeIdType.ByteString:
            return f"b={b64encode(cast(bytes, identifier)).decode('ascii')}"
        if self.NodeIdType == NodeIdType.String:
            return f"s={identifier!s}"
        return f"i={identifier!s}"

    def to_string(self) -> str:
        if self.NamespaceIndex != 0:
            return f"ns={self.NamespaceIndex};{self._identifier_string()}"
        return self._identifier_string()

    def to_binary(self) -> bytes | bytearray:
        import enginir_opcua

        return enginir_opcua.ua.ua_binary.nodeid_to_binary(self)


@dataclass(eq=False, order=False, slots=True)
class TwoByteNodeId(NodeId):
    def __post_init__(self) -> None:
        object.__setattr__(self, "NodeIdType", NodeIdType.TwoByte)
        if not isinstance(self.Identifier, int):
            raise ValueError(f"{self.__class__.__name__} Identifier must be int")
        if self.Identifier > 255:
            raise ValueError(f"{self.__class__.__name__} cannot have identifier > 255")
        if self.NamespaceIndex != 0:
            raise ValueError(f"{self.__class__.__name__} cannot have NamespaceIndex != 0")


@dataclass(eq=False, order=False, slots=True)
class FourByteNodeId(NodeId):
    def __post_init__(self) -> None:
        object.__setattr__(self, "NodeIdType", NodeIdType.FourByte)
        if not isinstance(self.Identifier, int):
            raise ValueError(f"{self.__class__.__name__} Identifier must be int")
        if self.Identifier > 65535:
            raise ValueError(f"{self.__class__.__name__} cannot have identifier > 65535")
        if self.NamespaceIndex > 255:
            raise ValueError(f"{self.__class__.__name__} cannot have NamespaceIndex > 255")


@dataclass(eq=False, order=False, slots=True)
class NumericNodeId(NodeId):
    def __post_init__(self) -> None:
        object.__setattr__(self, "NodeIdType", NodeIdType.Numeric)
        if not isinstance(self.Identifier, int):
            raise ValueError(f"{self.__class__.__name__} Identifier must be int")


@dataclass(eq=False, order=False, slots=True)
class ByteStringNodeId(NodeId):
    def __post_init__(self) -> None:
        object.__setattr__(self, "NodeIdType", NodeIdType.ByteString)
        if not isinstance(self.Identifier, bytes):
            raise ValueError(f"{self.__class__.__name__} Identifier must be bytes")


@dataclass(eq=False, order=False, slots=True)
class GuidNodeId(NodeId):
    def __post_init__(self) -> None:
        object.__setattr__(self, "NodeIdType", NodeIdType.Guid)
        if not isinstance(self.Identifier, uuid.UUID):
            raise ValueError(f"{self.__class__.__name__} Identifier must be uuid")


@dataclass(eq=False, order=False, slots=True)
class StringNodeId(NodeId):
    def __post_init__(self) -> None:
        object.__setattr__(self, "NodeIdType", NodeIdType.String)
        if not isinstance(self.Identifier, str):
            raise ValueError(f"{self.__class__.__name__} Identifier must be string")


@dataclass(eq=False, order=False, slots=True)
class ExpandedNodeId(NodeId):
    NamespaceUri: String | None = field(default=None, compare=True)
    ServerIndex: UInt32 = field(default=0, compare=True)

    def __eq__(self, node: object) -> bool:
        if not isinstance(node, NodeId):
            return False
        if self.Identifier != node.Identifier:
            return False
        other_uri = node.NamespaceUri if isinstance(node, ExpandedNodeId) else None
        other_server = node.ServerIndex if isinstance(node, ExpandedNodeId) else 0
        if (self.NamespaceUri or None) != (other_uri or None) or self.ServerIndex != other_server:
            return False
        return bool(self.NamespaceUri) or self.NamespaceIndex == node.NamespaceIndex

    def __hash__(self) -> int:
        if self.NamespaceUri:
            return hash((self.NamespaceUri, self.ServerIndex, self.Identifier))
        if self.ServerIndex:
            return hash((self.NamespaceIndex, self.Identifier, self.ServerIndex))
        return hash((self.NamespaceIndex, self.Identifier))

    def _sort_key(self) -> tuple[Any, ...]:
        namespace_index = 0 if self.NamespaceUri else self.NamespaceIndex
        return (
            _NODEID_FAMILY[self.NodeIdType],
            namespace_index,
            self.Identifier,
            self.NamespaceUri or "",
            self.ServerIndex,
        )

    def to_string(self) -> str:
        parts = []
        if self.ServerIndex:
            parts.append(f"svr={self.ServerIndex}")
        if self.NamespaceUri:
            if self.NamespaceUri != _OPC_UA_NAMESPACE_URI:
                parts.append(f"nsu={_encode_uri(self.NamespaceUri)}")
        elif self.NamespaceIndex != 0:
            parts.append(f"ns={self.NamespaceIndex}")
        parts.append(self._identifier_string())
        return ";".join(parts)


@dataclass(init=False, order=True, slots=True)
class QualifiedName:
    """
    A name qualified with a namespace index (OPC 10000-3 v1.05, 8.3; OPC 10000-6 v1.05, 5.2.2.13).

    The string form is the one of OPC 10000-6 v1.05, 5.1.12, Table 7: the bare name for namespace 0 and
    ``<index>:<name>`` otherwise.
    """

    NamespaceIndex: "ua.UInt16" = 0
    Name: "ua.String" = ""

    def __init__(self, Name: str | None = None, NamespaceIndex: int = 0) -> None:
        if isinstance(Name, int) and isinstance(NamespaceIndex, str):
            raise TypeError(
                f"QualifiedName(Name, NamespaceIndex): the arguments are swapped, got ({Name!r}, {NamespaceIndex!r})"
            )
        if not isinstance(Name, str | type(None)):
            raise TypeError(f"QualifiedName Name must be a string or None, got {type(Name).__name__}")
        if not isinstance(NamespaceIndex, int):
            raise TypeError(f"QualifiedName NamespaceIndex must be an int, got {type(NamespaceIndex).__name__}")
        object.__setattr__(self, "Name", Name)
        object.__setattr__(self, "NamespaceIndex", NamespaceIndex)

    def to_string(self) -> str:
        name = self.Name or ""
        if self.NamespaceIndex == 0:
            if _INDEX_PREFIX_PATTERN.match(name):
                raise UaError(f"The name {name!r} in namespace 0 would read back as a name in another namespace")
            return name
        return f"{self.NamespaceIndex}:{name}"

    @staticmethod
    def from_string(string: str, default_idx: int = 0, namespaces: list[str] | None = None) -> QualifiedName:
        if string.startswith("nsu="):
            uri, separator, name = string[4:].partition(";")
            if not separator:
                raise UaStringParsingError(f"Error parsing string {string}: no name after the namespace URI")
            if namespaces is None:
                raise UaStringParsingError(f"Error parsing string {string}: nsu= needs a namespace table")
            try:
                index = namespaces.index(_decode_uri(uri))
            except ValueError as ex:
                raise UaStringParsingError(f"Error parsing string {string}: unknown namespace URI", ex) from ex
            return QualifiedName(Name=name, NamespaceIndex=index)
        match = _INDEX_PREFIX_PATTERN.match(string)
        if match:
            return QualifiedName(Name=string[match.end() :], NamespaceIndex=int(match.group(1)))
        return QualifiedName(Name=string, NamespaceIndex=default_idx)


@dataclass(frozen=False)
class RelativePathElement:
    """
    OPC 10000-4 v1.05, 7.30

    :ivar ReferenceTypeId:
    :vartype ReferenceTypeId: NodeId
    :ivar IsInverse:
    :vartype IsInverse: Boolean
    :ivar IncludeSubtypes:
    :vartype IncludeSubtypes: Boolean
    :ivar TargetName:
    :vartype TargetName: QualifiedName
    """

    data_type = NodeId(537)

    ReferenceTypeId: "ua.NodeId" = field(default_factory=NodeId)
    IsInverse: "ua.Boolean" = False
    IncludeSubtypes: "ua.Boolean" = True
    TargetName: "ua.QualifiedName" = field(default_factory=QualifiedName)


@dataclass(frozen=False)
class RelativePath:
    """
    OPC 10000-4 v1.05, 7.30

    :ivar Elements:
    :vartype Elements: RelativePathElement
    """

    data_type = NodeId(540)

    Elements: "list[ua.RelativePathElement]" = field(default_factory=list)

    @staticmethod
    def from_string(string: str) -> RelativePath:
        from enginir_opcua.ua.relative_path import RelativePathFormatter

        return RelativePathFormatter.parse(string).build()

    def to_string(self) -> str:
        from enginir_opcua.ua.relative_path import RelativePathFormatter

        # Note: RelativePathFormatter will raise ValueError if ReferenceType is non-standard.
        return RelativePathFormatter(self).to_string()


@dataclass(init=False, slots=True)
class LocalizedText:
    """
    Human readable text with an optional locale identifier (OPC 10000-6 v1.05, 5.2.2.14).

    The string form is specific to this library and reads back exactly.
    """

    Encoding: "ua.Byte" = field(default=0, repr=False, init=False, compare=False)
    Locale: "ua.String | None" = None
    Text: "ua.String | None" = None

    def __init__(self, Text: str | None = None, Locale: str | None = None) -> None:
        object.__setattr__(self, "Text", Text)
        object.__setattr__(self, "Locale", Locale)
        object.__setattr__(self, "Encoding", 0)

        if self.Text is not None:
            if not isinstance(self.Text, str):
                raise ValueError(
                    f'A LocalizedText object takes a string as argument "Text" not a {type(self.Text)}, {self.Text}'
                )

        if self.Locale is not None:
            if not isinstance(self.Locale, str):
                raise ValueError(
                    f'A LocalizedText object takes a string as argument "Locale",'
                    f" not a {type(self.Locale)}, {self.Locale}"
                )

    def to_string(self) -> str:
        return f"LocalizedText(Locale={self.Locale!r}, Text={self.Text!r})"

    @staticmethod
    def from_string(string: str) -> LocalizedText:
        try:
            tree = ast.parse(string, mode="eval").body
        except (SyntaxError, ValueError, RecursionError, MemoryError):
            return LocalizedText(string)
        if not (
            isinstance(tree, ast.Call)
            and isinstance(tree.func, ast.Name)
            and tree.func.id == "LocalizedText"
            and not tree.args
            and [keyword.arg for keyword in tree.keywords] == ["Locale", "Text"]
            and all(
                isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str | type(None))
                for keyword in tree.keywords
            )
        ):
            return LocalizedText(string)
        locale, text = (cast(str | None, cast(ast.Constant, keyword.value).value) for keyword in tree.keywords)
        return LocalizedText(Text=text, Locale=locale)


@dataclass(frozen=True)
class ExtensionObject:
    """
    Any UA object packed as an ExtensionObject

    :ivar TypeId:
    :vartype TypeId: NodeId
    :ivar Body:
    :vartype Body: bytes
    """

    TypeId: "ua.NodeId" = field(default_factory=NodeId)
    Encoding: "ua.Byte" = field(default=0, repr=False, init=False, compare=False)
    Body: "ua.ByteString | None" = None

    def __bool__(self) -> bool:
        return self.Body is not None


class VariantType(IntEnum):
    """
    The possible types of a variant.

    :ivar Null:
    :ivar Boolean:
    :ivar SByte:
    :ivar Byte:
    :ivar Int16:
    :ivar UInt16:
    :ivar Int32:
    :ivar UInt32:
    :ivar Int64:
    :ivar UInt64:
    :ivar Float:
    :ivar Double:
    :ivar String:
    :ivar DateTime:
    :ivar Guid:
    :ivar ByteString:
    :ivar XmlElement:
    :ivar NodeId:
    :ivar ExpandedNodeId:
    :ivar StatusCode:
    :ivar QualifiedName:
    :ivar LocalizedText:
    :ivar ExtensionObject:
    :ivar DataValue:
    :ivar Variant:
    :ivar DiagnosticInfo:
    """

    Null = 0
    Boolean = 1
    SByte = 2
    Byte = 3
    Int16 = 4
    UInt16 = 5
    Int32 = 6
    UInt32 = 7
    Int64 = 8
    UInt64 = 9
    Float = 10
    Double = 11
    String = 12
    DateTime = 13
    Guid = 14
    ByteString = 15
    XmlElement = 16
    NodeId = 17
    ExpandedNodeId = 18
    StatusCode = 19
    QualifiedName = 20
    LocalizedText = 21
    ExtensionObject = 22
    DataValue = 23
    Variant = 24
    DiagnosticInfo = 25


class VariantTypeCustom:
    """
    A Variant type id from 26 to 63: it fits the six type bits of the encoding byte but names no built-in type.

    A decoder keeps the id and reads such a value as a ByteString, so a message from a newer peer can still be
    decoded and passed on.
    """

    def __init__(self, val: int) -> None:
        self.name = "Custom"
        self.value = val
        if not 25 < self.value <= 0b00111111:
            raise UaError(f"Cannot create VariantType. VariantType must be in the range 26 to 63, received {val}")

    def __str__(self) -> str:
        return f"VariantType.Custom:{self.value}"

    __repr__ = __str__

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and self.value == other.value

    def __hash__(self) -> int:
        return self.value.__hash__()


_VariantTypeUnion = VariantType | VariantTypeCustom

_NULLABLE_VARIANT_TYPES = frozenset(
    {
        VariantType.Null,
        VariantType.String,
        VariantType.DateTime,
        VariantType.Guid,
        VariantType.ByteString,
        VariantType.XmlElement,
        VariantType.NodeId,
        VariantType.ExpandedNodeId,
        VariantType.QualifiedName,
        VariantType.LocalizedText,
        VariantType.ExtensionObject,
        VariantType.DataValue,
        VariantType.Variant,
    }
)


@dataclass(slots=True)
class Variant:
    """
    Create an OPC-UA Variant object.
    if no argument a Null Variant is created.
    if not variant type is given, attempts to guess type from python type
    if a variant is given as value, the new objects becomes a copy of the argument

    :ivar Value:
    :vartype Value: Any supported type
    :ivar VariantType:
    :vartype VariantType: VariantType
    :ivar Dimensions:
    :vartype Dimensions: The length of each dimension. Make the variant a Matrix
    :ivar is_array:
    :vartype is_array: If the variant is an array. Always True if Dimension is specified
    """

    Value: Any = None
    VariantType: "ua.VariantType | ua.VariantTypeCustom" = None  # type: ignore[assignment]
    Dimensions: "list[ua.Int32]" | None = None
    is_array: bool | None = None

    def __post_init__(self) -> None:
        if isinstance(self.Value, Variant):
            inner = self.Value
            object.__setattr__(self, "VariantType", inner.VariantType)
            object.__setattr__(self, "Value", inner.Value)
            object.__setattr__(self, "Dimensions", inner.Dimensions)
            object.__setattr__(self, "is_array", inner.is_array)

        if self.is_array is None:
            if isinstance(self.Value, list | tuple) or self.Dimensions:
                object.__setattr__(self, "is_array", True)
            else:
                object.__setattr__(self, "is_array", False)

        if not isinstance(self.VariantType, VariantType | VariantTypeCustom):
            if self.VariantType is None:
                object.__setattr__(self, "VariantType", self._guess_type(self.Value))
            else:
                if hasattr(VariantType, self.VariantType.__name__):
                    object.__setattr__(self, "VariantType", VariantType[self.VariantType.__name__])
                else:
                    raise ValueError("VariantType argument must be an instance of VariantType")

        if self.VariantType == VariantType.DiagnosticInfo:
            raise UaError("A Variant cannot contain a DiagnosticInfo (OPC 10000-6 v1.05, 5.1.9)")

        if self.Value is None and not self.is_array:
            if self.VariantType in _NULLABLE_VARIANT_TYPES:
                null_factory = _NULL_SCALAR_FACTORIES.get(self.VariantType)
                if null_factory is not None:
                    object.__setattr__(self, "Value", null_factory())
            else:
                raise UaError(f"Non array Variant of type {self.VariantType} cannot have value None")

        if self.Dimensions is None and isinstance(self.Value, list | tuple):
            dims = get_shape(self.Value)
            if len(dims) > 1:
                object.__setattr__(self, "Dimensions", dims)

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Variant)
            and self.VariantType == other.VariantType
            and self.Value == other.Value
            and bool(self.is_array) == bool(other.is_array)
            and (self.Dimensions or None) == (other.Dimensions or None)
        )

    def __ne__(self, other: object) -> bool:
        return not self.__eq__(other)

    def _guess_type(self, val: Any) -> _VariantTypeUnion:
        error_val = None
        if isinstance(val, list | tuple):
            error_val = val
        while isinstance(val, list | tuple):
            if len(val) == 0:
                raise UaError(f"could not guess UA type of variable {error_val}")
            val = val[0]
        type_name = type(val).__name__
        if hasattr(VariantType, type_name):
            return VariantType[type_name]
        if val is None:
            return VariantType.Null
        if isinstance(val, ExpandedNodeId):
            return VariantType.ExpandedNodeId
        if isinstance(val, NodeId):
            return VariantType.NodeId
        if isinstance(val, bool):
            return VariantType.Boolean
        if isinstance(val, float):
            return VariantType.Double
        if isinstance(val, IntEnum):
            return VariantType.Int32
        if isinstance(val, int):
            return VariantType.Int64
        if isinstance(val, str):
            return VariantType.String
        if isinstance(val, bytes):
            return VariantType.ByteString
        if isinstance(val, datetime):
            return VariantType.DateTime
        if isinstance(val, uuid.UUID):
            return VariantType.Guid
        if any(cls in typeid_by_extension_objects for cls in type(val).__mro__):
            return VariantType.ExtensionObject
        raise UaError(f"Could not guess UA type of {val} with type {type(val)}, specify UA type")


def flatten_and_get_shape(mylist: list[Any]) -> tuple[list[Any], list[int]]:
    dims = [len(mylist)]
    while isinstance(mylist[0], list | tuple):
        dims.append(len(mylist[0]))
        mylist = [item for sublist in mylist for item in sublist]
        if len(mylist) == 0:
            break
    return mylist, dims


def flatten(mylist: list[Any] | None) -> list[Any] | None:
    if mylist is None:
        return None
    if len(mylist) == 0:
        return mylist
    while isinstance(mylist[0], list | tuple):
        mylist = [item for sublist in mylist for item in sublist]
        if len(mylist) == 0:
            break
    return mylist


def get_shape(mylist: Any) -> list[int]:
    dims: list[int] = []
    while isinstance(mylist, list | tuple):
        dims.append(len(mylist))
        if len(mylist) == 0:
            break
        mylist = mylist[0]
    return dims


# For completeness, these datatypes are abstract!
# If they are used in structs, abstract types are either Variant or ExtensionObjects.
# If they only contain basic types (int16, float, double..) they are Variants
UInteger = Variant
Integer = Variant


@dataclass(slots=True)
class DataValue:
    """
    A value with an associated timestamp, and quality.
    Automatically generated from xml , copied and modified here to fix errors in xml spec

    :ivar Value:
    :vartype Value: Variant
    :ivar StatusCode:
    :vartype StatusCode: StatusCode
    :ivar SourceTimestamp:
    :vartype SourceTimestamp: datetime
    :ivar SourcePicoSeconds:
    :vartype SourcePicoseconds: int
    :ivar ServerTimestamp:
    :vartype ServerTimestamp: datetime
    :ivar ServerPicoseconds:
    :vartype ServerPicoseconds: int
    """

    data_type = NodeId(Int32(ObjectIds.DataValue))

    Encoding: "ua.Byte" = field(default=0, repr=False, init=False, compare=False)
    Value: "ua.Variant | None" = None
    StatusCode: "ua.StatusCode | None" = field(default_factory=StatusCode)
    SourceTimestamp: "ua.DateTime | None" = None
    ServerTimestamp: "ua.DateTime | None" = None
    SourcePicoseconds: "ua.UInt16 | None" = None
    ServerPicoseconds: "ua.UInt16 | None" = None

    def __post_init__(
        self,
    ) -> None:
        if not isinstance(self.Value, Variant):
            object.__setattr__(self, "Value", Variant(self.Value))


@dataclass(slots=True)
class DiagnosticInfo:
    """
    A recursive structure containing diagnostic information associated with a status code.

    :ivar Encoding:
    :vartype Encoding: Byte
    :ivar SymbolicId:
    :vartype SymbolicId: Int32
    :ivar NamespaceUri:
    :vartype NamespaceUri: Int32
    :ivar Locale:
    :vartype Locale: Int32
    :ivar LocalizedText:
    :vartype LocalizedText: Int32
    :ivar AdditionalInfo:
    :vartype AdditionalInfo: String
    :ivar InnerStatusCode:
    :vartype InnerStatusCode: StatusCode
    :ivar InnerDiagnosticInfo:
    :vartype InnerDiagnosticInfo: DiagnosticInfo
    """

    data_type = NodeId(25)

    Encoding: "ua.Byte" = field(default=0, repr=False, init=False, compare=False)
    SymbolicId: "ua.Int32 | None" = None
    NamespaceUri: "ua.Int32 | None" = None
    Locale: "ua.Int32 | None" = None
    LocalizedText: "ua.Int32 | None" = None
    AdditionalInfo: "ua.String | None" = None
    InnerStatusCode: "ua.StatusCode | None" = None
    InnerDiagnosticInfo: "ua.DiagnosticInfo | None" = None


def datatype_to_varianttype(int_type: int | NodeId) -> VariantType | VariantTypeCustom:
    """
    Takes a NodeId or int and return a VariantType
    This is only supported if int_type < 63 due to VariantType encoding
    At low level we do not have access to address space thus decoding is limited
    a better version of this method can be find in ua_utils.py
    """
    identifier = int_type.Identifier if isinstance(int_type, NodeId) else int_type
    if not isinstance(identifier, int):
        raise UaError(f"Expected int type for VariantType, got {type(identifier)}")

    if 0 <= identifier <= 25:
        return VariantType(identifier)
    return VariantTypeCustom(identifier)


_NULL_SCALAR_FACTORIES: dict[VariantType | VariantTypeCustom, Callable[[], Any]] = {
    VariantType.DateTime: get_win_epoch,
    VariantType.Guid: lambda: uuid.UUID(int=0),
    VariantType.NodeId: NodeId,
    VariantType.ExpandedNodeId: ExpandedNodeId,
    VariantType.QualifiedName: QualifiedName,
    VariantType.LocalizedText: LocalizedText,
    VariantType.DataValue: DataValue,
    VariantType.Variant: Variant,
}


def register_null_scalar(vtype: VariantType, factory: Callable[[], Any]) -> None:
    _NULL_SCALAR_FACTORIES[vtype] = factory


def get_default_value(vtype: VariantType) -> Any:
    """
    Given a variant type return default value for this type
    """
    if vtype == VariantType.Null:
        return None
    if vtype == VariantType.Boolean:
        return False
    if vtype in (VariantType.SByte, VariantType.Byte):
        return 0
    if vtype == VariantType.ByteString:
        return b""
    if 4 <= vtype.value <= 9:
        return 0
    if vtype in (VariantType.Float, VariantType.Double):
        return 0.0
    if vtype == VariantType.String:
        return None
    if vtype == VariantType.DateTime:
        return get_win_epoch()
    if vtype == VariantType.Guid:
        return uuid.UUID(int=0)
    if vtype == VariantType.XmlElement:
        return None
    if vtype == VariantType.NodeId:
        return NodeId()
    if vtype == VariantType.ExpandedNodeId:
        return ExpandedNodeId()
    if vtype == VariantType.StatusCode:
        return StatusCode()
    if vtype == VariantType.QualifiedName:
        return QualifiedName()
    if vtype == VariantType.LocalizedText:
        return LocalizedText()
    if vtype == VariantType.ExtensionObject:
        return ExtensionObject()
    if vtype == VariantType.DataValue:
        return DataValue()
    if vtype == VariantType.Variant:
        return Variant()
    if vtype == VariantType.DiagnosticInfo:
        return DiagnosticInfo()
    raise RuntimeError(f"function take a uatype as argument, got: {vtype}")


basetype_by_datatype: dict[NodeId, str] = {}
basetype_datatypes: dict[type, NodeId] = {}
enums_by_datatype: dict[NodeId, type] = {}
enums_datatypes: weakref.WeakKeyDictionary[type, NodeId] = weakref.WeakKeyDictionary()
extension_objects_by_datatype: dict[NodeId, type] = {}
extension_objects_by_typeid: dict[NodeId, type] = {}
datatype_by_extension_object: weakref.WeakKeyDictionary[type, NodeId] = weakref.WeakKeyDictionary()
typeid_by_extension_objects: weakref.WeakKeyDictionary[type, NodeId] = weakref.WeakKeyDictionary()

TypeKey = Any


class TypeRegistry:
    """
    The classes of structures, unions, enumerations and aliases that one session knows, and the ExtensionObject
    encoding ids that belong to them. Entries are keyed by namespace URI and identifier, so they stay valid when the
    namespace array of the server changes; a registry without a namespace table keys by NodeId as given.
    A registry falls back to its parents, which end in the shared registry of namespace 0.
    """

    def __init__(
        self,
        namespaces: Callable[[], Sequence[str]] | None = None,
        parents: tuple[TypeRegistry, ...] = (),
        base_tables: bool = False,
    ) -> None:
        self._namespaces = namespaces
        self._parents = parents
        self._is_base = base_tables
        self._datatypes: dict[TypeKey, type] = {}
        self._class_datatype: dict[type, TypeKey] = {}
        self._encodings: dict[TypeKey, type] = {}
        self._class_encoding: dict[type, TypeKey] = {}
        self._names: dict[str, type] = {}
        self._named: dict[tuple[str, str], type] = {}
        self._qualified: dict[type, str] = {}
        if base_tables:
            self._datatypes = extension_objects_by_datatype  # type: ignore[assignment]
            self._class_datatype = datatype_by_extension_object  # type: ignore[assignment]
            self._encodings = extension_objects_by_typeid  # type: ignore[assignment]
            self._class_encoding = typeid_by_extension_objects  # type: ignore[assignment]

    def _key(self, nodeid: NodeId) -> TypeKey | None:
        if self._namespaces is None or nodeid.NamespaceIndex == 0:
            return nodeid
        table = self._namespaces()
        if nodeid.NamespaceIndex >= len(table):
            return nodeid
        return (table[nodeid.NamespaceIndex], type(nodeid.Identifier), nodeid.Identifier)

    def _nodeid(self, key: TypeKey) -> NodeId:
        if isinstance(key, NodeId):
            return key
        uri, _, identifier = key
        assert self._namespaces is not None
        return NodeId(identifier, list(self._namespaces()).index(uri))

    def _required_key(self, nodeid: NodeId) -> TypeKey:
        key = self._key(nodeid)
        return key

    def _own(self, table: dict[TypeKey, type], nodeid: NodeId) -> type | None:
        key = self._key(nodeid)
        return None if key is None else table.get(key)

    def _lookup(self, table_name: str, nodeid: NodeId) -> type | None:
        found = self._own(getattr(self, table_name), nodeid)
        if found is not None:
            return found
        for parent in self._parents:
            found = parent._lookup(table_name, nodeid)
            if found is not None:
                return found
        return None

    def _bind(self, name: str, cls: type, nodeid: NodeId | None) -> None:
        self._names.setdefault(name, cls)
        if not self._is_base:
            _set_ua_attribute(name, cls, nodeid)
        if nodeid is not None and self._namespaces is not None and nodeid.NamespaceIndex != 0:
            table = self._namespaces()
            if nodeid.NamespaceIndex < len(table):
                self._named.setdefault((table[nodeid.NamespaceIndex], name), cls)

    def register_struct(self, data_type: NodeId | None, encoding_id: NodeId | None, cls: type, name: str) -> None:
        if data_type is not None and not data_type.is_null():
            key = self._required_key(data_type)
            self._claim(self._datatypes, key, cls, data_type)
            self._class_datatype[cls] = key
        if encoding_id is not None and not encoding_id.is_null():
            key = self._required_key(encoding_id)
            self._claim(self._encodings, key, cls, encoding_id)
            self._class_encoding[cls] = key
        cls.__ua_registry__ = weakref.ref(self)  # type: ignore[attr-defined]
        if not self._is_base:
            if data_type is not None and not data_type.is_null():
                datatype_by_extension_object[cls] = data_type
            if encoding_id is not None and not encoding_id.is_null():
                typeid_by_extension_objects[cls] = encoding_id
        self._bind(name, cls, data_type or encoding_id)

    def register_enum(self, data_type: NodeId, cls: type, name: str) -> None:
        key = self._required_key(data_type)
        self._claim(self._datatypes, key, cls, data_type)
        self._class_datatype[cls] = key
        if not self._is_base:
            enums_datatypes[cls] = data_type
        cls.data_type = data_type  # type: ignore[attr-defined]
        self._bind(name, cls, data_type)

    def register_alias(self, data_type: NodeId, base_cls: type, name: str) -> None:
        key = self._required_key(data_type)
        self._claim(self._datatypes, key, base_cls, data_type)
        self._bind(name, base_cls, data_type)

    def _claim(self, table: dict[TypeKey, type], key: TypeKey, cls: type, nodeid: NodeId) -> None:
        existing = table.get(key)
        if existing is not None and existing is not cls:
            _logger.info("%s is registered again, the previous class is replaced", nodeid)
        table[key] = cls

    def find_own(self, data_type: NodeId) -> type | None:
        return self._own(self._datatypes, data_type)

    def find(self, data_type: NodeId) -> type | None:
        return self._lookup("_datatypes", data_type)

    def get(self, data_type: NodeId) -> type:
        found = self.find(data_type)
        if found is None:
            raise KeyError(f"No registered type for DataType {data_type}")
        return found

    def class_for_encoding(self, encoding_id: NodeId) -> type | None:
        return self._lookup("_encodings", encoding_id)

    def _reverse(self, table_name: str, cls: type) -> NodeId | None:
        key = getattr(self, table_name).get(cls)
        if key is not None:
            return self._nodeid(key) if not isinstance(key, NodeId) else key
        for parent in self._parents:
            found = parent._reverse(table_name, cls)
            if found is not None:
                return found
        return None

    def encoding_id_of(self, cls: type) -> NodeId:
        found = self._reverse("_class_encoding", cls)
        if found is None:
            raise KeyError(f"No registered encoding for class {cls}")
        return found

    def data_type_of(self, cls: type) -> NodeId:
        found = self._reverse("_class_datatype", cls)
        if found is None:
            raise KeyError(f"No registered DataType for class {cls}")
        return found

    def by_name(self, name: str, namespace_uri: str | None = None) -> type:
        if namespace_uri is not None:
            found = self._named.get((namespace_uri, name))
            if found is not None:
                return found
            raise KeyError(f"No registered type {name} in {namespace_uri}")
        if name in self._names:
            return self._names[name]
        for parent in self._parents:
            try:
                return parent.by_name(name)
            except KeyError:
                continue
        raise KeyError(f"No registered type named {name}")

    def names(self) -> dict[str, type]:
        return dict(self._names)

    def includes(self, other: TypeRegistry) -> bool:
        return other is self or any(parent.includes(other) for parent in self._parents)

    def snapshot(self) -> tuple[Any, ...]:
        return tuple(
            dict(table)
            for table in (
                self._datatypes,
                self._class_datatype,
                self._encodings,
                self._class_encoding,
                self._names,
                self._named,
            )
        )

    def restore(self, saved: tuple[Any, ...]) -> None:
        tables: tuple[dict[Any, Any], ...] = (
            self._datatypes,
            self._class_datatype,
            self._encodings,
            self._class_encoding,
            self._names,
            self._named,
        )
        for table, content in zip(tables, saved):
            table.clear()
            table.update(content)

    @contextlib.contextmanager
    def encoding(self) -> Iterator[None]:
        token = _encoding_registry.set(self)
        try:
            yield
        finally:
            _encoding_registry.reset(token)


_encoding_registry: contextvars.ContextVar[TypeRegistry | None] = contextvars.ContextVar(
    "encoding_registry", default=None
)

base_types = TypeRegistry(base_tables=True)
default_types = base_types


def encoding_id_for_class(cls: type) -> NodeId | None:
    """
    The ExtensionObject encoding id of a class, or None if no registry knows it. A class built for a session is
    encoded with the namespace array of that session; sending it through another session raises.
    """
    owner_ref = cls.__dict__.get("__ua_registry__")
    owner = owner_ref() if owner_ref is not None else None
    if owner is None or owner._is_base:
        found = typeid_by_extension_objects.get(cls)
        if found is not None:
            return found
    if owner is not None:
        current = _encoding_registry.get()
        if current is not None and not current.includes(owner):
            raise UaError(f"{cls.__name__} belongs to the type registry of another session")
        return owner.encoding_id_of(cls)
    try:
        return default_types.encoding_id_of(cls)
    except KeyError:
        return None


def data_type_of_class(cls: type) -> NodeId | None:
    """
    The DataType NodeId of a structure or enumeration class, in the namespace indices of the session that made the
    class (or the default registry); None if no registry knows the class.
    """
    owner_ref = cls.__dict__.get("__ua_registry__")
    owner = owner_ref() if owner_ref is not None else None
    try:
        return (owner or default_types).data_type_of(cls)
    except KeyError:
        return None


def _set_ua_attribute(name: str, class_type: type, data_type: NodeId | None) -> None:
    import enginir_opcua.ua as _ua

    existing = getattr(_ua, name, None)
    if existing is None:
        setattr(_ua, name, class_type)
        return
    if existing is class_type:
        return
    existing_dt = getattr(existing, "data_type", None)
    if existing_dt is not None and data_type is not None and existing_dt == data_type:
        return
    _logger.warning(
        "Browsename collision: ua.%s is already bound (data_type=%s); the new class with data_type=%s "
        "is registered only in its type registry. Use session.types.get(node_id) to access it.",
        name,
        existing_dt,
        data_type,
    )


def register_basetype(name: str, nodeid: NodeId, class_type: type) -> None:
    """
    Deprecated: register an alias of a built-in type in the process-wide default registry.
    """
    default_types.register_alias(nodeid, class_type, name)
    _set_ua_attribute(name, class_type, None)


def register_enum(name: str, nodeid: NodeId, class_type: type) -> None:
    """
    Deprecated: register an enum in the process-wide default registry. Sessions register in their own registry.
    """
    default_types.register_enum(nodeid, class_type, name)
    _set_ua_attribute(name, class_type, nodeid)


def register_extension_object(
    name: str, encoding_nodeid: NodeId, class_type: type, datatype_nodeid: NodeId | None = None
) -> None:
    """
    Deprecated: register a structure in the process-wide default registry. Sessions register in their own registry.
    """
    default_types.register_struct(datatype_nodeid, encoding_nodeid, class_type, name)
    _set_ua_attribute(name, class_type, datatype_nodeid)


def get_type(node_id: NodeId) -> type:
    """
    Deprecated: resolve a DataType NodeId in the default registry. Use the types of a Client or Server.
    """
    return default_types.get(node_id)


def get_extensionobject_class_type(typeid: NodeId) -> type | None:
    """
    Deprecated: the class registered for an ExtensionObject encoding id in the default registry.
    """
    return default_types.class_for_encoding(typeid)
