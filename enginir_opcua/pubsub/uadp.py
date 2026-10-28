"""
Implements the UADP network encoding of OPC 10000-14 v1.05, 7.2.4. Not implemented: message security,
chunk reassembly, discovery bodies, ActionHeader and action messages.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Any, Protocol

from ..common.utils import Buffer
from ..ua import VariantType
from ..ua.ua_binary import (
    Primitives,
    pack_uatype,
    struct_from_binary,
    struct_to_binary,
    to_binary,
    unpack_uatype,
)
from ..ua.uaerrors import UaError
from ..ua.uaprotocol_auto import FieldMetaData, VersionTime
from ..ua.uatypes import (
    Byte,
    Bytes,
    DataValue,
    DateTime,
    Guid,
    String,
    UInt16,
    UInt32,
    UInt64,
    Variant,
    get_default_value,
)

logger = logging.getLogger(__name__)

PublisherIdValue = Byte | UInt16 | UInt32 | UInt64 | String

_PUBLISHER_ID_VARIANT_TYPES: dict[type, VariantType] = {
    Byte: VariantType.Byte,
    UInt16: VariantType.UInt16,
    UInt32: VariantType.UInt32,
    UInt64: VariantType.UInt64,
    String: VariantType.String,
}
_PUBLISHER_ID_CLASSES: dict[VariantType, type] = {vt: cls for cls, vt in _PUBLISHER_ID_VARIANT_TYPES.items()}
_PUBLISHER_ID_TYPE_BITS: dict[VariantType, int] = {
    VariantType.Byte: 0,
    VariantType.UInt16: 1,
    VariantType.UInt32: 2,
    VariantType.UInt64: 3,
    VariantType.String: 4,
}
_PUBLISHER_ID_READERS: dict[int, tuple[Any, type | None]] = {
    0: (Primitives.Byte, Byte),
    1: (Primitives.UInt16, UInt16),
    2: (Primitives.UInt32, UInt32),
    3: (Primitives.UInt64, UInt64),
    4: (Primitives.String, None),
}


class UadpSkip(Exception):
    """A message that must be ignored by a receiver, for example because it uses a reserved value (7.2.4)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def publisher_id_variant_type(publisher_id: Any) -> VariantType:
    """The Variant type of a typed PublisherId value, raising for a value of unknown type."""
    if isinstance(publisher_id, str):
        return VariantType.String
    for cls in (UInt64, UInt32, UInt16, Byte):
        if isinstance(publisher_id, cls):
            return _PUBLISHER_ID_VARIANT_TYPES[cls]
    raise UaError(f"PublisherId {publisher_id!r} has no OPC UA type; wrap it in Byte, UInt16, UInt32, UInt64 or String")


def publisher_id_from_variant(variant: Variant) -> PublisherIdValue | None:
    """The typed PublisherId value of a Variant. The type of the Variant decides how it is encoded (7.2.4.4.2)."""
    if variant is None or variant.VariantType == VariantType.Null:
        return None
    cls = _PUBLISHER_ID_CLASSES.get(variant.VariantType)
    if cls is None:
        raise UaError(f"No valid PublisherId: {variant}")
    return cls(variant.Value)


def publisher_id_matches(configured: Variant | None, received: PublisherIdValue | None) -> bool:
    """A null configured PublisherId passes every message; otherwise type and value must be equal (6.2.9.1)."""
    if configured is None or configured.VariantType == VariantType.Null:
        return True
    if received is None:
        return False
    return configured.VariantType == publisher_id_variant_type(received) and configured.Value == received


class MessageHeaderFlags(IntFlag):
    """
    UADP NetworkMessage flags, OPC 10000-14 v1.05, 7.2.4.4.2, Table 154
    """

    NONE = 0
    UADP_VERSION_BIT0 = 0b1
    PUBLISHER_ID = 0b00010000
    GROUP_HEADER = 0b00100000
    PAYLOAD_HEADER = 0b01000000
    EXTENDED_FLAGS_1 = 0b10000000
    PUBLISHER_ID_UINT16 = 0b001 << 8
    PUBLISHER_ID_UINT32 = 0b010 << 8
    PUBLISHER_ID_UINT64 = 0b011 << 8
    PUBLISHER_ID_STRING = 0b100 << 8
    DATACLASS_SET = 0b0000100000000000
    SECURITY_MODE = 0b0001000000000000
    TIMESTAMP = 0b0010000000000000
    PICO_SECONDS = 0b0100000000000000
    EXTENDED_FLAGS_2 = 0b1000000000000000
    CHUNK = 0b1 << 16
    PROMOTEDFIELDS = 0b10 << 16
    DISCOVERYREQUEST = 0b001 << 18
    DISCOVERYRESPONSE = 0b010 << 18


_PUBLISHER_ID_TYPE_MASK = 0b111 << 8
_NETWORK_MESSAGE_TYPE_MASK = 0b111 << 18
_EXTENDED_FLAGS_2_ACTION_HEADER = 0b100000 << 16
_EXTENDED_FLAGS_2_RESERVED = 0b11000000 << 16


class MessageGroupHeaderFlags(IntFlag):
    """
    UADP group header flags, OPC 10000-14 v1.05, 7.2.4.4.2, Table 154
    """

    WRITER_GROUP_ID = 0b0001
    GROUP_VERSION = 0b0010
    NETWORK_MESSAGE_NUMBER = 0b0100
    SEQUENCE_NUMBER = 0b1000


class MessageDataSetFlags(IntFlag):
    """
    UADP DataSetMessage header flags, OPC 10000-14 v1.05, 7.2.4.5.4, Table 162
    """

    VALID = 0b00000001
    RAW_DATA = 0b00000010
    DATA_VALUE = 0b00000100
    SEQUENCE_NUMBER = 0b00001000
    STATUS = 0b00010000
    CFG_MAJOR_VERSION = 0b00100000
    CFG_MINOR_VERSION = 0b01000000
    FLAGS2 = 0b10000000
    DELTA_FRAME = 0b0000000100000000
    EVENT = 0b0000001000000000
    KEEP_ALIVE = 0b0000001100000000
    TIMESTAMP = 0b0001000000000000
    PICOSECONDS = 0b0010000000000000


_FIELD_ENCODING_MASK = 0b110
_FIELD_ENCODING_RESERVED = 0b110
_MESSAGE_TYPE_MASK = 0b1111 << 8
_MESSAGE_TYPE_DELTA_FRAME = 1 << 8
_MESSAGE_TYPE_EVENT = 2 << 8
_MESSAGE_TYPE_KEEP_ALIVE = 3 << 8
_DATASET_FLAGS_2_RESERVED = 0b11000000 << 8
_MAX_PICOSECONDS = 9999
_MAX_UINT16 = 0xFFFF


class InformationType(IntEnum):
    PublisherEndpoints = 1
    DataSetMetaData = 2
    DataSetWriter = 3


def _clamp_picoseconds(value: int) -> UInt16:
    return UInt16(min(value, _MAX_PICOSECONDS))


def _read_datetime(data: Buffer) -> DateTime:
    d = Primitives.DateTime.unpack(data)
    return DateTime(d.year, d.month, d.day, d.hour, d.minute, d.second, d.microsecond, d.tzinfo, fold=d.fold)


@dataclass
class UadpHeader:
    """
    Header of an Uadp  Message
    """

    PublisherId: PublisherIdValue | None = None
    DataSetClassId: Guid | None = None

    def to_binary(self, flags: MessageHeaderFlags) -> bytes:
        b = []
        type_bits = 0
        if self.PublisherId is not None:
            flags |= MessageHeaderFlags.PUBLISHER_ID
            type_bits = _PUBLISHER_ID_TYPE_BITS[publisher_id_variant_type(self.PublisherId)]
            flags |= MessageHeaderFlags(type_bits << 8)
        if self.DataSetClassId is not None:
            flags |= MessageHeaderFlags.DATACLASS_SET
        if flags > 0xFF:
            flags |= MessageHeaderFlags.EXTENDED_FLAGS_1
            if flags > 0xFFFF:
                flags |= MessageHeaderFlags.EXTENDED_FLAGS_2
                b.append(Primitives.UInt16.pack(flags & 0xFFFF))
                b.append(Primitives.Byte.pack(flags >> 16))
            else:
                b.append(Primitives.UInt16.pack(flags))
        else:
            b.append(Primitives.Byte.pack(flags))
        if self.PublisherId is not None:
            primitive, _ = _PUBLISHER_ID_READERS[type_bits]
            b.append(primitive.pack(self.PublisherId))
        if self.DataSetClassId is not None:
            b.append(Primitives.Guid.pack(self.DataSetClassId))
        return b"".join(b)

    @staticmethod
    def from_binary(data: Buffer) -> tuple[MessageHeaderFlags, UadpHeader]:
        header = UadpHeader()
        first = Primitives.Byte.unpack(data)
        if first & 0x0F != 1:
            raise UadpSkip(f"UADP version {first & 0x0F}")
        value = first
        if first & MessageHeaderFlags.EXTENDED_FLAGS_1:
            extended_1 = Primitives.Byte.unpack(data)
            value |= extended_1 << 8
            if extended_1 & (MessageHeaderFlags.EXTENDED_FLAGS_2 >> 8):
                value |= Primitives.Byte.unpack(data) << 16
        flags = MessageHeaderFlags(value)
        if flags & MessageHeaderFlags.SECURITY_MODE:
            raise UadpSkip("SecurityHeader")
        if value & _EXTENDED_FLAGS_2_RESERVED:
            raise UadpSkip("reserved bit in ExtendedFlags2")
        if value & _EXTENDED_FLAGS_2_ACTION_HEADER:
            raise UadpSkip("ActionHeader")
        if (value & _NETWORK_MESSAGE_TYPE_MASK) >> 18 > 2:
            raise UadpSkip("reserved NetworkMessage type")
        if flags & MessageHeaderFlags.PUBLISHER_ID:
            type_bits = (value & _PUBLISHER_ID_TYPE_MASK) >> 8
            if type_bits not in _PUBLISHER_ID_READERS:
                raise UadpSkip(f"reserved PublisherId type {type_bits:03b}")
            primitive, cls = _PUBLISHER_ID_READERS[type_bits]
            raw = primitive.unpack(data)
            header.PublisherId = cls(raw) if cls is not None else String(raw)
        if flags & MessageHeaderFlags.DATACLASS_SET:
            header.DataSetClassId = Primitives.Guid.unpack(data)
        return flags, header


def has_security_header(data: bytes) -> bool:
    if len(data) < 2 or not data[0] & MessageHeaderFlags.EXTENDED_FLAGS_1:
        return False
    return bool(data[1] << 8 & MessageHeaderFlags.SECURITY_MODE)


@dataclass
class UadpChunk:
    """Chunk of a DataSetMessage, OPC 10000-14 v1.05, 7.2.4.4.4, Tables 158 and 159"""

    DataSetWriterId: UInt16 = field(default_factory=lambda: UInt16(0))
    MessageSequenceNo: UInt16 = field(default_factory=lambda: UInt16(0))
    ChunkOffset: UInt32 = field(default_factory=lambda: UInt32(0))
    TotalSize: UInt32 = field(default_factory=lambda: UInt32(0))
    ChunkData: Bytes = field(default_factory=lambda: Bytes(b""))

    def header_to_binary(self) -> bytes:
        return Primitives.UInt16.pack(self.DataSetWriterId)

    def to_binary(self) -> bytes:
        b: list[bytes] = []
        b.append(Primitives.UInt16.pack(self.MessageSequenceNo))
        b.append(Primitives.UInt32.pack(self.ChunkOffset))
        b.append(Primitives.UInt32.pack(self.TotalSize))
        b.append(Primitives.ByteString.pack(self.ChunkData))
        return b"".join(b)

    @staticmethod
    def from_binary(data: Buffer, dataset_writer_id: UInt16) -> UadpChunk:
        chunk = UadpChunk(DataSetWriterId=dataset_writer_id)
        chunk.MessageSequenceNo = Primitives.UInt16.unpack(data)
        chunk.ChunkOffset = Primitives.UInt32.unpack(data)
        chunk.TotalSize = Primitives.UInt32.unpack(data)
        chunk.ChunkData = Primitives.ByteString.unpack(data)
        return chunk


@dataclass
class UadpGroupHeader:
    """
    Header of group part of an uadp message
    """

    WriterGroupId: UInt16 | None = None
    GroupVersion: VersionTime | None = None
    NetworkMessageNo: UInt16 | None = None
    SequenceNo: UInt16 | None = None

    def to_bytes(self) -> bytes:
        flags = MessageGroupHeaderFlags(0)
        if self.WriterGroupId is not None:
            flags |= MessageGroupHeaderFlags.WRITER_GROUP_ID
        if self.GroupVersion is not None:
            flags |= MessageGroupHeaderFlags.GROUP_VERSION
        if self.NetworkMessageNo is not None:
            flags |= MessageGroupHeaderFlags.NETWORK_MESSAGE_NUMBER
        if self.SequenceNo is not None:
            flags |= MessageGroupHeaderFlags.SEQUENCE_NUMBER
        b = []
        b.append(Primitives.Byte.pack(flags))
        if self.WriterGroupId is not None:
            b.append(Primitives.UInt16.pack(self.WriterGroupId))
        if self.GroupVersion is not None:
            b.append(Primitives.UInt32.pack(self.GroupVersion))
        if self.NetworkMessageNo is not None:
            b.append(Primitives.UInt16.pack(self.NetworkMessageNo))
        if self.SequenceNo is not None:
            b.append(Primitives.UInt16.pack(self.SequenceNo))
        return b"".join(b)

    @staticmethod
    def from_binary(data: Buffer) -> UadpGroupHeader:
        gp = UadpGroupHeader()
        raw_flags = Primitives.Byte.unpack(data)
        if raw_flags & 0xF0:
            raise UadpSkip("reserved bit in GroupFlags")
        flags = MessageGroupHeaderFlags(raw_flags)
        if MessageGroupHeaderFlags.WRITER_GROUP_ID in flags:
            gp.WriterGroupId = Primitives.UInt16.unpack(data)
        if MessageGroupHeaderFlags.GROUP_VERSION in flags:
            gp.GroupVersion = Primitives.UInt32.unpack(data)
        if MessageGroupHeaderFlags.NETWORK_MESSAGE_NUMBER in flags:
            gp.NetworkMessageNo = Primitives.UInt16.unpack(data)
        if MessageGroupHeaderFlags.SEQUENCE_NUMBER in flags:
            gp.SequenceNo = Primitives.UInt16.unpack(data)
        return gp


@dataclass
class UadpDataSetMessageHeader:
    Valid: bool = True
    SequenceNo: UInt16 | None = None
    Timestamp: DateTime | None = None
    PicoSeconds: UInt16 | None = None
    Status: UInt16 | None = None
    CfgMajorVersion: VersionTime | None = None
    CfgMinorVersion: VersionTime | None = None

    def to_binary(self, flags: MessageDataSetFlags) -> bytes:
        if self.Valid:
            flags |= MessageDataSetFlags.VALID
        if self.SequenceNo is not None:
            flags |= MessageDataSetFlags.SEQUENCE_NUMBER
        if self.Timestamp is not None:
            flags |= MessageDataSetFlags.TIMESTAMP
        if self.PicoSeconds is not None:
            if self.Timestamp is None:
                raise UaError("PicoSeconds need a Timestamp in a DataSetMessage header")
            flags |= MessageDataSetFlags.PICOSECONDS
        if self.Status is not None:
            flags |= MessageDataSetFlags.STATUS
        if self.CfgMajorVersion is not None:
            flags |= MessageDataSetFlags.CFG_MAJOR_VERSION
        if self.CfgMinorVersion is not None:
            flags |= MessageDataSetFlags.CFG_MINOR_VERSION
        b = []
        if flags > 0xFF:
            flags |= MessageDataSetFlags.FLAGS2
            b.append(Primitives.UInt16.pack(flags))
        else:
            b.append(Primitives.Byte.pack(flags))
        if self.SequenceNo is not None:
            b.append(Primitives.UInt16.pack(self.SequenceNo))
        if self.Timestamp is not None:
            b.append(Primitives.DateTime.pack(self.Timestamp))
        if self.PicoSeconds is not None:
            b.append(Primitives.UInt16.pack(self.PicoSeconds))
        if self.Status is not None:
            b.append(Primitives.UInt16.pack(self.Status))
        if self.CfgMajorVersion is not None:
            b.append(Primitives.UInt32.pack(self.CfgMajorVersion))
        if self.CfgMinorVersion is not None:
            b.append(Primitives.UInt32.pack(self.CfgMinorVersion))
        return b"".join(b)

    @staticmethod
    def from_binary(data: Buffer) -> tuple[MessageDataSetFlags, UadpDataSetMessageHeader]:
        header = UadpDataSetMessageHeader()
        value = Primitives.Byte.unpack(data)
        if value & MessageDataSetFlags.FLAGS2:
            value |= Primitives.Byte.unpack(data) << 8
        flags = MessageDataSetFlags(value)
        if value & _FIELD_ENCODING_MASK == _FIELD_ENCODING_RESERVED:
            raise UadpSkip("reserved field encoding")
        if value & _DATASET_FLAGS_2_RESERVED:
            raise UadpSkip("reserved bit in DataSetFlags2")
        if value & _MESSAGE_TYPE_MASK > _MESSAGE_TYPE_KEEP_ALIVE:
            raise UadpSkip(f"unsupported DataSetMessage type {(value & _MESSAGE_TYPE_MASK) >> 8}")
        header.Valid = bool(flags & MessageDataSetFlags.VALID)
        if MessageDataSetFlags.SEQUENCE_NUMBER in flags:
            header.SequenceNo = Primitives.UInt16.unpack(data)
        if MessageDataSetFlags.TIMESTAMP in flags:
            header.Timestamp = _read_datetime(data)
        if MessageDataSetFlags.PICOSECONDS in flags:
            header.PicoSeconds = _clamp_picoseconds(Primitives.UInt16.unpack(data))
        if MessageDataSetFlags.STATUS in flags:
            header.Status = Primitives.UInt16.unpack(data)
        if MessageDataSetFlags.CFG_MAJOR_VERSION in flags:
            header.CfgMajorVersion = Primitives.UInt32.unpack(data)
        if MessageDataSetFlags.CFG_MINOR_VERSION in flags:
            header.CfgMinorVersion = Primitives.UInt32.unpack(data)
        return flags, header


@dataclass
class UadpDiscoveryProbe:
    """Discovery probe NetworkMessage, OPC 10000-14 v1.05, 7.2.4.6.12; the body is kept as it came"""

    ProbeType: Byte = field(default_factory=lambda: Byte(0))
    Body: bytes = b""

    def to_binary(self) -> bytes:
        return Primitives.Byte.pack(self.ProbeType) + self.Body

    @staticmethod
    def from_binary(data: Buffer) -> UadpDiscoveryProbe:
        probe_type = Byte(Primitives.Byte.unpack(data))
        return UadpDiscoveryProbe(probe_type, data.read(len(data)))


@dataclass
class UadpDiscoveryAnnouncement:
    """Discovery announcement NetworkMessage, OPC 10000-14 v1.05, 7.2.4.6.3; the body is kept as it came"""

    AnnouncementType: Byte = field(default_factory=lambda: Byte(0))
    SequenceNumber: UInt16 = field(default_factory=lambda: UInt16(0))
    Body: bytes = b""

    def to_binary(self) -> bytes:
        return Primitives.Byte.pack(self.AnnouncementType) + Primitives.UInt16.pack(self.SequenceNumber) + self.Body

    @staticmethod
    def from_binary(data: Buffer) -> UadpDiscoveryAnnouncement:
        announcement_type = Byte(Primitives.Byte.unpack(data))
        sequence_number = UInt16(Primitives.UInt16.unpack(data))
        return UadpDiscoveryAnnouncement(announcement_type, sequence_number, data.read(len(data)))


_FIXED_SIZES = {
    VariantType.Boolean: 1,
    VariantType.SByte: 1,
    VariantType.Byte: 1,
    VariantType.Int16: 2,
    VariantType.UInt16: 2,
    VariantType.Int32: 4,
    VariantType.UInt32: 4,
    VariantType.Int64: 8,
    VariantType.UInt64: 8,
    VariantType.Float: 4,
    VariantType.Double: 8,
    VariantType.DateTime: 8,
    VariantType.Guid: 16,
    VariantType.StatusCode: 4,
}
_RAW_PADDED_TYPES = (VariantType.String, VariantType.ByteString)
_INT32_SIZE = 4


def _raw_layout(meta: FieldMetaData) -> tuple[VariantType, int | None, int]:
    """The built-in type, the array length (None for a scalar) and the padded size of one element of a RawData
    field, or a UaError if the field can't be sent as RawData (7.2.4.5.11)."""
    try:
        vtype = VariantType(int(meta.BuiltInType))
    except ValueError as e:
        raise UaError(f"RawData field {meta.Name}: unknown built-in type {meta.BuiltInType}") from e
    if vtype in _RAW_PADDED_TYPES:
        if not meta.MaxStringLength:
            raise UaError(f"RawData field {meta.Name}: a String or ByteString needs MaxStringLength")
        element = _INT32_SIZE + int(meta.MaxStringLength)
    elif vtype in _FIXED_SIZES:
        element = _FIXED_SIZES[vtype]
    else:
        raise UaError(f"RawData field {meta.Name}: built-in type {vtype.name} can't be sent as RawData")
    if meta.ValueRank == -1:
        return vtype, None, element
    if meta.ValueRank == 1:
        dims = list(meta.ArrayDimensions or [])
        if len(dims) != 1 or not dims[0]:
            raise UaError(f"RawData field {meta.Name}: a one-dimensional array needs a fixed ArrayDimensions")
        return vtype, int(dims[0]), element
    raise UaError(f"RawData field {meta.Name}: ValueRank {meta.ValueRank} can't be sent as RawData")


def raw_layout_error(meta: FieldMetaData) -> str | None:
    """Why the field can't be sent as RawData, or None"""
    try:
        _raw_layout(meta)
    except UaError as e:
        return str(e)
    return None


def _pad(encoded: bytes, size: int, name: str) -> bytes:
    if len(encoded) > size:
        raise UaError(f"RawData field {name}: value is longer than its configured size")
    return encoded + bytes(size - len(encoded))


def _raw_element_to_binary(vtype: VariantType, value: Any, element: int, name: str) -> bytes:
    if vtype in _RAW_PADDED_TYPES:
        return _pad(pack_uatype(vtype, value), element, name)
    return pack_uatype(vtype, value)


def raw_field_to_binary(meta: FieldMetaData, value: Variant | None) -> bytes:
    """Encodes one field as RawData, padded to its maximum size (7.2.4.5.11)"""
    vtype, count, element = _raw_layout(meta)
    name = str(meta.Name)
    if value is None or value.Value is None:
        value = Variant([], vtype, is_array=True) if count is not None else Variant(get_default_value(vtype), vtype)
    if count is None:
        if value.is_array:
            raise UaError(f"RawData field {name}: array given for a scalar field")
        return _raw_element_to_binary(vtype, value.Value, element, name)
    if not value.is_array:
        raise UaError(f"RawData field {name}: scalar given for an array field")
    items = list(value.Value)
    if len(items) > count:
        raise UaError(f"RawData field {name}: {len(items)} elements for {count} allowed")
    parts = [Primitives.Int32.pack(len(items))]
    parts.extend(_raw_element_to_binary(vtype, item, element, name) for item in items)
    parts.append(bytes((count - len(items)) * element))
    return b"".join(parts)


def _raw_element_from_binary(vtype: VariantType, data: Buffer, element: int) -> Any:
    window = data.copy(element)
    data.skip(element)
    return unpack_uatype(vtype, window)


def raw_fields_from_binary(data: Buffer, fields: list[FieldMetaData]) -> list[Variant]:
    """Decodes the fields of a RawData key frame with the layout of the DataSetMetaData"""
    values: list[Variant] = []
    for meta in fields:
        vtype, count, element = _raw_layout(meta)
        if count is None:
            values.append(Variant(_raw_element_from_binary(vtype, data, element), vtype))
            continue
        length = Primitives.Int32.unpack(data)
        if length < 0 or length > count:
            raise UaError(f"RawData field {meta.Name}: array length {length} outside 0 to {count}")
        items = [_raw_element_from_binary(vtype, data, element) for _ in range(length)]
        data.skip((count - length) * element)
        values.append(Variant(items, vtype, is_array=True))
    return values


@dataclass
class DeltaVariant:
    No: UInt16 = field(default_factory=lambda: UInt16(0))
    Value: Variant = field(default_factory=Variant)


@dataclass
class DeltaDataValue:
    No: UInt16 = field(default_factory=lambda: UInt16(0))
    Value: DataValue = field(default_factory=DataValue)


@dataclass
class UadpDataSetDeltaVariant:
    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)
    Data: list[DeltaVariant] = field(default_factory=list)

    def message_to_binary(self) -> bytes:
        b = []
        b.append(self.Header.to_binary(MessageDataSetFlags.DELTA_FRAME))
        b.append(Primitives.UInt16.pack(len(self.Data)))
        for value in self.Data:
            b.append(struct_to_binary(value))
        return b"".join(b)

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        Data = [struct_from_binary(DeltaVariant, data) for _ in range(Primitives.UInt16.unpack(data))]
        return UadpDataSetDeltaVariant(header, Data)


@dataclass
class UadpDataSetDeltaDataValue:
    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)
    Data: list[DeltaDataValue] = field(default_factory=list)

    def message_to_binary(self) -> bytes:
        b = []
        b.append(self.Header.to_binary(MessageDataSetFlags.DELTA_FRAME | MessageDataSetFlags.DATA_VALUE))
        b.append(Primitives.UInt16.pack(len(self.Data)))
        for value in self.Data:
            b.append(struct_to_binary(value))
        return b"".join(b)

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        Data = [struct_from_binary(DeltaDataValue, data) for _ in range(Primitives.UInt16.unpack(data))]
        return UadpDataSetDeltaDataValue(header, Data)


@dataclass
class UadpDataSetVariant:
    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)
    Data: list[Variant] = field(default_factory=list)

    def message_to_binary(self) -> bytes:
        b = []
        b.append(self.Header.to_binary(MessageDataSetFlags(0)))
        b.append(Primitives.UInt16.pack(len(self.Data)))
        for value in self.Data:
            b.append(pack_uatype(VariantType.Variant, value))
        return b"".join(b)

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        Data = [unpack_uatype(VariantType.Variant, data) for _ in range(Primitives.UInt16.unpack(data))]
        return UadpDataSetVariant(header, Data)


@dataclass
class UadpDataSetEvent:
    """Event DataSetMessage, OPC 10000-14 v1.05, 7.2.4.5.7; the fields are always Variants"""

    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)
    Data: list[Variant] = field(default_factory=list)

    def message_to_binary(self) -> bytes:
        b = []
        b.append(self.Header.to_binary(MessageDataSetFlags.EVENT))
        b.append(Primitives.UInt16.pack(len(self.Data)))
        for value in self.Data:
            b.append(pack_uatype(VariantType.Variant, value))
        return b"".join(b)

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        Data = [unpack_uatype(VariantType.Variant, data) for _ in range(Primitives.UInt16.unpack(data))]
        return UadpDataSetEvent(header, Data)


@dataclass
class UadpDataSetDataValue:
    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)
    Data: list[DataValue] = field(default_factory=list)

    def message_to_binary(self) -> bytes:
        b = []
        b.append(self.Header.to_binary(MessageDataSetFlags.DATA_VALUE))
        b.append(Primitives.UInt16.pack(len(self.Data)))
        for value in self.Data:
            b.append(to_binary(DataValue, value))
        return b"".join(b)

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        Data = [struct_from_binary(DataValue, data) for _ in range(Primitives.UInt16.unpack(data))]
        return UadpDataSetDataValue(header, Data)


@dataclass
class UadpDataSetRaw:
    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)
    Data: bytes = b""

    def message_to_binary(self) -> bytes:
        return b"".join([self.Header.to_binary(MessageDataSetFlags.RAW_DATA), self.Data])

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        return UadpDataSetRaw(header, data.read(size))


@dataclass
class UadpDataSetKeepAlive:
    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)

    def message_to_binary(self) -> bytes:
        return self.Header.to_binary(MessageDataSetFlags.KEEP_ALIVE)

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        return UadpDataSetKeepAlive(header)


@dataclass
class UadpDataSetHeartbeat:
    """A key frame that only has a header, OPC 10000-14 v1.05, 7.2.4.5.5"""

    Header: UadpDataSetMessageHeader = field(default_factory=UadpDataSetMessageHeader)

    def message_to_binary(self) -> bytes:
        return self.Header.to_binary(MessageDataSetFlags(0))

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        return UadpDataSetHeartbeat(header)


@dataclass
class UadpDataSetSkipped:
    """A DataSetMessage a receiver must ignore; it keeps its place so the payload header still lines up"""

    Reason: str = ""

    def message_to_binary(self) -> bytes:
        raise UaError("A skipped DataSetMessage can't be encoded")


class UadpDataSetMessage(Protocol):
    Header: UadpDataSetMessageHeader

    def message_to_binary(self) -> bytes:
        raise NotImplementedError("UadpDataSetMessage is a abstract class")

    @staticmethod
    def message_from_binary(header: UadpDataSetMessageHeader, data: Buffer, size: int) -> UadpDataSetMessage:
        raise NotImplementedError("UadpDataSetMessage is a abstract class")


def _pack_payload(msgs: list[UadpDataSetMessage], has_payload_header: bool) -> bytes:
    encoded = [msg.message_to_binary() for msg in msgs]
    b: list[bytes] = []
    if has_payload_header and len(encoded) > 1:
        for blob in encoded:
            if len(blob) > _MAX_UINT16:
                raise UaError(f"A DataSetMessage of {len(blob)} bytes doesn't fit the UInt16 size field")
        b.extend(Primitives.UInt16.pack(len(blob)) for blob in encoded)
    b.extend(encoded)
    return b"".join(b)


def _decode_dataset_message(data: Buffer) -> UadpDataSetMessage:
    flags, header = UadpDataSetMessageHeader.from_binary(data)
    size = len(data)
    message_type = int(flags) & _MESSAGE_TYPE_MASK
    encoding = int(flags) & _FIELD_ENCODING_MASK
    if message_type == _MESSAGE_TYPE_KEEP_ALIVE:
        return UadpDataSetKeepAlive.message_from_binary(header, data, size)
    if size == 0:
        return UadpDataSetHeartbeat.message_from_binary(header, data, size)
    if message_type == _MESSAGE_TYPE_EVENT:
        if encoding:
            raise UadpSkip("Event DataSetMessage with a field encoding other than Variant")
        return UadpDataSetEvent.message_from_binary(header, data, size)
    if message_type == _MESSAGE_TYPE_DELTA_FRAME:
        if encoding & MessageDataSetFlags.RAW_DATA:
            raise UadpSkip("delta frame with RawData encoding")
        if encoding & MessageDataSetFlags.DATA_VALUE:
            return UadpDataSetDeltaDataValue.message_from_binary(header, data, size)
        return UadpDataSetDeltaVariant.message_from_binary(header, data, size)
    if encoding & MessageDataSetFlags.RAW_DATA:
        return UadpDataSetRaw.message_from_binary(header, data, size)
    if encoding & MessageDataSetFlags.DATA_VALUE:
        return UadpDataSetDataValue.message_from_binary(header, data, size)
    return UadpDataSetVariant.message_from_binary(header, data, size)


def _unpack_payload(data: Buffer, payload_header_count: int | None) -> list[UadpDataSetMessage]:
    """
    Unpack (at least one) DataSet payload. The size of each DataSetMessage bounds what is read for it, so padding
    after the fields can't shift the next message (7.2.4.5.3)
    """
    sizes: list[int] = []
    if not payload_header_count and not data:
        return []
    if payload_header_count and payload_header_count > 1:
        for _ in range(payload_header_count):
            sizes.append(Primitives.UInt16.unpack(data))
    else:
        sizes.append(len(data))
    payload: list[UadpDataSetMessage] = []
    for size in sizes:
        window = data.copy(size)
        data.skip(size)
        try:
            payload.append(_decode_dataset_message(window))
        except UadpSkip as skip:
            payload.append(UadpDataSetSkipped(skip.reason))
    return payload


@dataclass
class UadpNetworkMessage:
    """
    Network Message for UADP
    """

    Header: UadpHeader = field(default_factory=UadpHeader)
    GroupHeader: UadpGroupHeader | None = None
    DataSetPayloadHeader: list[UInt16] = field(default_factory=list)
    Timestamp: DateTime | None = None
    PicoSeconds: UInt16 | None = None
    PromotedFields: list[Variant] = field(default_factory=list)
    Payload: list[UadpDataSetMessage] | UadpDiscoveryProbe | UadpDiscoveryAnnouncement | UadpChunk | None = None

    def to_binary(self) -> bytes:
        flags = MessageHeaderFlags.UADP_VERSION_BIT0
        is_discovery = isinstance(self.Payload, UadpDiscoveryProbe | UadpDiscoveryAnnouncement)
        if self.GroupHeader is not None:
            flags |= MessageHeaderFlags.GROUP_HEADER
        if (self.DataSetPayloadHeader and not is_discovery) or isinstance(self.Payload, UadpChunk):
            flags |= MessageHeaderFlags.PAYLOAD_HEADER
        if self.Timestamp is not None:
            flags |= MessageHeaderFlags.TIMESTAMP
        if self.PicoSeconds is not None:
            if self.Timestamp is None:
                raise UaError("PicoSeconds need a Timestamp in a NetworkMessage")
            flags |= MessageHeaderFlags.PICO_SECONDS
        if self.PromotedFields:
            flags |= MessageHeaderFlags.PROMOTEDFIELDS
        if isinstance(self.Payload, UadpDiscoveryProbe):
            flags |= MessageHeaderFlags.DISCOVERYREQUEST
        elif isinstance(self.Payload, UadpDiscoveryAnnouncement):
            flags |= MessageHeaderFlags.DISCOVERYRESPONSE
        elif isinstance(self.Payload, UadpChunk):
            flags |= MessageHeaderFlags.CHUNK
        b = []
        b.append(self.Header.to_binary(flags))
        if self.GroupHeader is not None:
            b.append(self.GroupHeader.to_bytes())
        if isinstance(self.Payload, UadpChunk):
            b.append(self.Payload.header_to_binary())
        elif self.DataSetPayloadHeader and not is_discovery:
            if len(self.DataSetPayloadHeader) > 0xFF:
                raise UaError("A NetworkMessage holds at most 255 DataSetMessages")
            b.append(Primitives.Byte.pack(len(self.DataSetPayloadHeader)))
            for ds in self.DataSetPayloadHeader:
                b.append(Primitives.UInt16.pack(ds))
        if self.Timestamp is not None:
            b.append(Primitives.DateTime.pack(self.Timestamp))
        if self.PicoSeconds is not None:
            b.append(Primitives.UInt16.pack(self.PicoSeconds))
        if self.PromotedFields:
            promoted = b"".join(pack_uatype(VariantType.Variant, p) for p in self.PromotedFields)
            if len(promoted) > _MAX_UINT16:
                raise UaError("PromotedFields are larger than 65535 bytes")
            b.append(Primitives.UInt16.pack(len(promoted)))
            b.append(promoted)
        if isinstance(self.Payload, UadpDiscoveryProbe | UadpDiscoveryAnnouncement | UadpChunk):
            b.append(self.Payload.to_binary())
        else:
            b.append(_pack_payload(self.Payload or [], bool(self.DataSetPayloadHeader)))
        return b"".join(b)

    @staticmethod
    def from_binary(data: Buffer) -> UadpNetworkMessage:
        """Decodes one datagram. Raises UadpSkip for a message a receiver must ignore, UaError for a broken one."""
        msg = UadpNetworkMessage()
        flags, msg.Header = UadpHeader.from_binary(data)
        message_type = int(flags) & _NETWORK_MESSAGE_TYPE_MASK
        chunk = bool(flags & MessageHeaderFlags.CHUNK)
        if flags & MessageHeaderFlags.GROUP_HEADER:
            msg.GroupHeader = UadpGroupHeader.from_binary(data)
        chunk_writer_id = UInt16(0)
        if flags & MessageHeaderFlags.PAYLOAD_HEADER:
            if message_type:
                raise UadpSkip("payload header in a discovery message")
            if chunk:
                chunk_writer_id = UInt16(Primitives.UInt16.unpack(data))
            else:
                sz = Primitives.Byte.unpack(data)
                msg.DataSetPayloadHeader = [Primitives.UInt16.unpack(data) for _ in range(sz)]
        if flags & MessageHeaderFlags.TIMESTAMP:
            msg.Timestamp = _read_datetime(data)
        if flags & MessageHeaderFlags.PICO_SECONDS:
            msg.PicoSeconds = _clamp_picoseconds(Primitives.UInt16.unpack(data))
        if flags & MessageHeaderFlags.PROMOTEDFIELDS:
            promoted_size = Primitives.UInt16.unpack(data)
            window = data.copy(promoted_size)
            data.skip(promoted_size)
            while window:
                msg.PromotedFields.append(unpack_uatype(VariantType.Variant, window))
        if chunk:
            msg.Payload = UadpChunk.from_binary(data, chunk_writer_id)
        elif message_type == MessageHeaderFlags.DISCOVERYREQUEST:
            msg.Payload = UadpDiscoveryProbe.from_binary(data)
        elif message_type == MessageHeaderFlags.DISCOVERYRESPONSE:
            msg.Payload = UadpDiscoveryAnnouncement.from_binary(data)
        else:
            msg.Payload = _unpack_payload(data, len(msg.DataSetPayloadHeader))
        return msg


def decode_network_message(data: Buffer) -> UadpNetworkMessage | UadpSkip:
    """Decodes a datagram; a message to ignore comes back as a UadpSkip, a broken one raises UaError."""
    try:
        return UadpNetworkMessage.from_binary(data)
    except UadpSkip as skip:
        return skip
