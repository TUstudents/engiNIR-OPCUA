import dataclasses
import functools
import operator
from types import SimpleNamespace
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import from_binary, struct_to_binary
from enginir_opcua.ua.uaprotocol_hand import Message

ATTRIBUTES_BITS = {
    "ObjectAttributes": ("DisplayName", "Description", "WriteMask", "UserWriteMask", "EventNotifier"),
    "ObjectTypeAttributes": ("DisplayName", "Description", "WriteMask", "UserWriteMask", "IsAbstract"),
    "VariableAttributes": (
        "DisplayName",
        "Description",
        "WriteMask",
        "UserWriteMask",
        "Value",
        "DataType",
        "ValueRank",
        "ArrayDimensions",
        "AccessLevel",
        "UserAccessLevel",
        "MinimumSamplingInterval",
        "Historizing",
    ),
    "VariableTypeAttributes": (
        "DisplayName",
        "Description",
        "WriteMask",
        "UserWriteMask",
        "Value",
        "DataType",
        "ValueRank",
        "ArrayDimensions",
        "IsAbstract",
    ),
    "MethodAttributes": ("DisplayName", "Description", "WriteMask", "UserWriteMask", "Executable", "UserExecutable"),
    "ReferenceTypeAttributes": (
        "DisplayName",
        "Description",
        "WriteMask",
        "UserWriteMask",
        "IsAbstract",
        "Symmetric",
        "InverseName",
    ),
    "ViewAttributes": ("DisplayName", "Description", "WriteMask", "UserWriteMask", "ContainsNoLoops", "EventNotifier"),
}


def _bits(names: tuple[str, ...]) -> int:
    return int(functools.reduce(operator.or_, (getattr(ua.NodeAttributesMask, name) for name in names)))


def test_ua29_data_change_filter_default_trigger_is_status_value() -> None:
    """Part 4, 7.22.2: StatusValue is the default trigger."""
    assert ua.DataChangeFilter().Trigger == ua.DataChangeTrigger.StatusValue
    assert struct_to_binary(ua.DataChangeFilter()) == bytes.fromhex("01000000 00000000 0000000000000000")


def test_ua29_data_change_filter_decoded_keeps_wire_trigger() -> None:
    """Part 4, 7.22.2: a decoded filter has the trigger of the wire."""
    data = bytes.fromhex("00000000 00000000 0000000000000000")
    assert from_binary(ua.DataChangeFilter, Buffer(data)).Trigger == ua.DataChangeTrigger.Status


def test_ua30_asymmetric_header_str_shows_both_lengths() -> None:
    """Part 6, 6.7.2.3: the header holds a sender certificate and a receiver thumbprint."""
    header = ua.AsymmetricAlgorithmHeader(SenderCertificate=b"c" * 100, ReceiverCertificateThumbPrint=b"t" * 20)
    text = str(header)
    assert "certificatesize:100" in text
    assert "receiverCertificatesize:20" in text
    assert "ccc" not in text


def test_ua30_asymmetric_header_str_without_certificates() -> None:
    text = str(ua.AsymmetricAlgorithmHeader())
    assert "certificatesize:None" in text
    assert "receiverCertificatesize:None" in text


def test_ua31_header_sizes_are_fields_of_the_instance() -> None:
    """Part 6, 7.1.2.2: the derived sizes belong to one header."""
    names = {f.name for f in dataclasses.fields(ua.Header)}
    assert {"body_size", "packet_size"} <= names
    header = ua.Header(ua.MessageType.SecureMessage, ua.ChunkType.Single)
    header.body_size = 5
    header.packet_size = 29
    copy = dataclasses.replace(header, ChannelId=3)
    assert (copy.body_size, copy.packet_size) == (5, 29)
    assert ua.Header().body_size == 0


def test_ua31_header_size_follows_message_type() -> None:
    """Part 6, 7.1.2.2 and 6.7.2.2: secure messages carry a SecureChannelId after the size."""
    assert ua.Header(ua.MessageType.Hello, ua.ChunkType.Single).header_size == 8
    assert ua.Header(ua.MessageType.Error, ua.ChunkType.Single).header_size == 8
    for message_type in (ua.MessageType.SecureOpen, ua.MessageType.SecureClose, ua.MessageType.SecureMessage):
        assert ua.Header(message_type, ua.ChunkType.Single).header_size == 12


def test_ua31_header_fields_do_not_shadow_constant_classes() -> None:
    """Part 6, 7.1.2.2: the message type and chunk type are ASCII bytes."""
    types = {f.name: f.type for f in dataclasses.fields(ua.Header)}
    assert types["MessageType"] is bytes
    assert types["ChunkType"] is bytes


def test_ua31_no_invalid_message_or_chunk_type() -> None:
    """Part 6, 7.1.2.2 and 6.7.2.2 define no invalid message type or chunk type."""
    assert not hasattr(ua.MessageType, "Invalid")
    assert not hasattr(ua.ChunkType, "Invalid")


def test_ua32_message_accessors_are_snake_case() -> None:
    chunks: Any = [
        SimpleNamespace(SequenceHeader="seq", SecurityHeader="sec", Body=b"ab"),
        SimpleNamespace(SequenceHeader="seq", SecurityHeader="sec", Body=b"cd"),
    ]
    message = Message(chunks)
    assert message.sequence_header() == "seq"
    assert message.security_header() == "sec"
    assert bytes(message.body()) == b"abcd"
    assert not hasattr(Message, "SequenceHeader")
    assert not hasattr(Message, "SecurityHeader")


@pytest.mark.parametrize("name", sorted(ATTRIBUTES_BITS))
def test_ua33_specified_attributes_default_bits(name: str) -> None:
    """Part 4, 7.24.1: SpecifiedAttributes tells which attributes the structure carries."""
    assert int(getattr(ua, name)().SpecifiedAttributes) == _bits(ATTRIBUTES_BITS[name])


@pytest.mark.parametrize("name", sorted(ATTRIBUTES_BITS))
def test_ua33_caller_specified_attributes_are_kept(name: str) -> None:
    """Part 4, 7.24.1: the client chooses which attributes are valid."""
    cls: Any = getattr(ua, name)
    attributes = cls(SpecifiedAttributes=int(ua.NodeAttributesMask.DisplayName))
    assert int(attributes.SpecifiedAttributes) == int(ua.NodeAttributesMask.DisplayName)
    assert from_binary(cls, Buffer(struct_to_binary(attributes))).SpecifiedAttributes == attributes.SpecifiedAttributes
