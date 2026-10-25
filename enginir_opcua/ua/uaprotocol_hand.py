import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from enginir_opcua.common import utils
from enginir_opcua.ua import uaprotocol_auto as auto
from enginir_opcua.ua import uatypes

if TYPE_CHECKING:
    from enginir_opcua.common.connection import MessageChunk

OPC_TCP_SCHEME = "opc.tcp"


@dataclass(slots=True)
class Hello:
    ProtocolVersion: uatypes.UInt32 = 0
    # the following values could be set to 0 (meaning no limits)
    # unfortunately many servers do not support it
    # even newer version of prosys is broken,
    # so we set then to a high value known to work most places
    ReceiveBufferSize: uatypes.UInt32 = 2**31 - 1
    SendBufferSize: uatypes.UInt32 = 2**31 - 1
    MaxMessageSize: uatypes.UInt32 = 2**31 - 1
    MaxChunkCount: uatypes.UInt32 = 2**31 - 1
    EndpointUrl: uatypes.String = ""


class MessageType:
    Hello: bytes = b"HEL"
    Acknowledge: bytes = b"ACK"
    Error: bytes = b"ERR"
    SecureOpen: bytes = b"OPN"
    SecureClose: bytes = b"CLO"
    SecureMessage: bytes = b"MSG"


class ChunkType:
    Single: bytes = b"F"
    Intermediate: bytes = b"C"
    Abort: bytes = b"A"  # when an error occurred and the Message is aborted (body is ErrorMessage)


SECURE_MESSAGE_TYPES = (MessageType.SecureOpen, MessageType.SecureClose, MessageType.SecureMessage)


@dataclass(slots=False)
class Header:
    MessageType: bytes = b""
    ChunkType: bytes = b""
    ChannelId: int = 0
    body_size: int = 0
    packet_size: int = 0

    @property
    def header_size(self) -> int:
        return 12 if self.MessageType in SECURE_MESSAGE_TYPES else 8

    def add_size(self, size: int) -> None:
        self.body_size += size

    @staticmethod
    def max_size() -> int:
        return struct.calcsize("<3scII")


@dataclass(slots=True)
class ErrorMessage:
    Error: uatypes.StatusCode = field(default_factory=lambda: uatypes.StatusCode())
    Reason: uatypes.String = field(default_factory=lambda: uatypes.String())


@dataclass(slots=True)
class Acknowledge:
    ProtocolVersion: uatypes.UInt32 = 0
    ReceiveBufferSize: uatypes.UInt32 = 65536
    SendBufferSize: uatypes.UInt32 = 65536
    MaxMessageSize: uatypes.UInt32 = 0  # No limits
    MaxChunkCount: uatypes.UInt32 = 0  # No limits


@dataclass(slots=True)
class AsymmetricAlgorithmHeader:
    SecurityPolicyURI: uatypes.String = "http://opcfoundation.org/UA/SecurityPolicy#None"
    SenderCertificate: uatypes.ByteString = None
    ReceiverCertificateThumbPrint: uatypes.ByteString = None

    def __str__(self) -> str:
        size1 = len(self.SenderCertificate) if self.SenderCertificate is not None else None
        size2 = len(self.ReceiverCertificateThumbPrint) if self.ReceiverCertificateThumbPrint is not None else None
        return (
            f"{self.__class__.__name__}(SecurityPolicy:{self.SecurityPolicyURI},"
            f" certificatesize:{size1}, receiverCertificatesize:{size2} )"
        )

    __repr__ = __str__


@dataclass(slots=True)
class SymmetricAlgorithmHeader:
    TokenId: uatypes.UInt32 = 0

    @staticmethod
    def max_size() -> int:
        return struct.calcsize("<I")


@dataclass(slots=True)
class SequenceHeader:
    SequenceNumber: uatypes.UInt32 = None
    RequestId: uatypes.UInt32 = None

    @staticmethod
    def max_size() -> int:
        return struct.calcsize("<II")


class Message:
    def __init__(self, chunks: Sequence["MessageChunk"]) -> None:
        self._chunks = chunks

    def request_id(self) -> int:
        return self._chunks[0].SequenceHeader.RequestId

    def sequence_header(self) -> SequenceHeader:
        return self._chunks[0].SequenceHeader

    def security_header(self) -> AsymmetricAlgorithmHeader | SymmetricAlgorithmHeader:
        return self._chunks[0].SecurityHeader

    def body(self) -> utils.Buffer:
        body = b"".join([c.Body for c in self._chunks])
        return utils.Buffer(body)


ana = auto.NodeAttributesMask


@dataclass(slots=True)
class ObjectAttributes(auto.ObjectAttributes):
    SpecifiedAttributes: uatypes.UInt32 = (
        ana.DisplayName | ana.Description | ana.WriteMask | ana.UserWriteMask | ana.EventNotifier
    )


@dataclass(slots=True)
class ObjectTypeAttributes(auto.ObjectTypeAttributes):
    SpecifiedAttributes: uatypes.UInt32 = (
        ana.DisplayName | ana.Description | ana.WriteMask | ana.UserWriteMask | ana.IsAbstract
    )


@dataclass(slots=True)
class VariableAttributes(auto.VariableAttributes):
    ArrayDimensions: list[uatypes.UInt32] = None
    Historizing: uatypes.Boolean = False
    AccessLevel: uatypes.Byte = auto.AccessLevel.CurrentRead.mask
    UserAccessLevel: uatypes.Byte = auto.AccessLevel.CurrentRead.mask
    SpecifiedAttributes: uatypes.UInt32 = (
        ana.DisplayName
        | ana.Description
        | ana.WriteMask
        | ana.UserWriteMask
        | ana.Value
        | ana.DataType
        | ana.ValueRank
        | ana.ArrayDimensions
        | ana.AccessLevel
        | ana.UserAccessLevel
        | ana.MinimumSamplingInterval
        | ana.Historizing
    )


@dataclass(slots=True)
class VariableTypeAttributes(auto.VariableTypeAttributes):
    SpecifiedAttributes: uatypes.UInt32 = (
        ana.DisplayName
        | ana.Description
        | ana.WriteMask
        | ana.UserWriteMask
        | ana.Value
        | ana.DataType
        | ana.ValueRank
        | ana.ArrayDimensions
        | ana.IsAbstract
    )


@dataclass(slots=True)
class MethodAttributes(auto.MethodAttributes):
    SpecifiedAttributes: uatypes.UInt32 = (
        ana.DisplayName | ana.Description | ana.WriteMask | ana.UserWriteMask | ana.Executable | ana.UserExecutable
    )


@dataclass(slots=True)
class ReferenceTypeAttributes(auto.ReferenceTypeAttributes):
    SpecifiedAttributes: uatypes.UInt32 = (
        ana.DisplayName
        | ana.Description
        | ana.WriteMask
        | ana.UserWriteMask
        | ana.IsAbstract
        | ana.Symmetric
        | ana.InverseName
    )


@dataclass(slots=True)
class DataTypeAttributes(auto.DataTypeAttributes):
    DataTypeDefinition: uatypes.ExtensionObject = field(default_factory=auto.ExtensionObject)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "SpecifiedAttributes",
            (
                ana.DisplayName
                | ana.Description
                | ana.WriteMask
                | ana.UserWriteMask
                | ana.IsAbstract
                | ana.DataTypeDefinition
            ),
        )


nid = uatypes.FourByteNodeId(auto.ObjectIds.DataTypeAttributes_Encoding_DefaultBinary)
uatypes.extension_objects_by_typeid[nid] = DataTypeAttributes
uatypes.typeid_by_extension_objects[DataTypeAttributes] = nid


@dataclass(slots=True)
class ViewAttributes(auto.ViewAttributes):
    SpecifiedAttributes: uatypes.UInt32 = (
        ana.DisplayName | ana.Description | ana.WriteMask | ana.UserWriteMask | ana.ContainsNoLoops | ana.EventNotifier
    )


@dataclass(slots=True)
class Argument(auto.Argument):
    ValueRank: auto.Int32 = -1


@dataclass(slots=True)
class XmlElement:
    """
    An XML element encoded as a UTF-8 string.
    :ivar Value:
    :vartype Value: String
    """

    Value: uatypes.String = ""


@dataclass(slots=True)
class DataChangeFilter(auto.DataChangeFilter):
    Trigger: auto.DataChangeTrigger = auto.DataChangeTrigger.StatusValue
