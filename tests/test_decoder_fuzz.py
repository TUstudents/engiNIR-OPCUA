import random
import time
from collections.abc import Callable
from typing import Any

import pytest

from enginir_opcua import ua
from enginir_opcua.common.utils import Buffer
from enginir_opcua.ua.ua_binary import (
    extensionobject_from_binary,
    extensionobject_to_binary,
    struct_from_binary,
    struct_to_binary,
)

Decoder = Callable[[Buffer], Any]

MAX_SECONDS_PER_DECODE = 1.0
BOUNDARY_BYTES = (0x00, 0xFF, 0x7F, 0x80, 0x01)
LENGTH_VALUES = (-2, -1, 0, 1, 2**31 - 1, 2**31 - 2, 2**24, 65_537, -(2**31))


def _nested_diagnostics(levels: int) -> ua.DiagnosticInfo:
    info = ua.DiagnosticInfo(SymbolicId=1, AdditionalInfo="deep")
    for level in range(levels - 1):
        info = ua.DiagnosticInfo(
            SymbolicId=level, LocalizedText=2, InnerStatusCode=ua.StatusCode(0x80010000), InnerDiagnosticInfo=info
        )
    return info


def _data_values() -> list[ua.DataValue]:
    now = ua.get_win_epoch()
    return [
        ua.DataValue(ua.Variant(3.5, ua.VariantType.Double), SourceTimestamp=now),
        ua.DataValue(ua.Variant([1, 2, 3], ua.VariantType.Int32), StatusCode=ua.StatusCode(0x80000000)),
        ua.DataValue(ua.Variant([[1, 2, 3], [4, 5, 6]], ua.VariantType.UInt16)),
        ua.DataValue(ua.Variant(["a", "bc", None], ua.VariantType.String)),
        ua.DataValue(ua.Variant(ua.LocalizedText("t", "en"), ua.VariantType.LocalizedText)),
        ua.DataValue(ua.Variant(ua.NodeId("x", 2), ua.VariantType.NodeId)),
        ua.DataValue(ua.Variant(b"\x00\x01", ua.VariantType.ByteString)),
    ]


def _corpus() -> list[tuple[str, bytes, Decoder]]:
    def struct_decoder(cls: type) -> Decoder:
        return lambda buf: struct_from_binary(cls, buf)

    read_request = ua.ReadParameters(
        NodesToRead=[ua.ReadValueId(NodeId=ua.NodeId(i, 2), AttributeId=13) for i in range(4)]
    )
    read_response = ua.ReadResponse(Results=_data_values(), DiagnosticInfos=[_nested_diagnostics(2)])
    session = ua.CreateSessionResponse(
        Parameters=ua.CreateSessionResult(
            SessionId=ua.NodeId(1, 1),
            AuthenticationToken=ua.NodeId(b"tok", 1),
            ServerNonce=b"n" * 32,
            ServerCertificate=b"c" * 40,
            ServerEndpoints=[
                ua.EndpointDescription(
                    EndpointUrl="opc.tcp://localhost:4840",
                    SecurityPolicyUri="http://opcfoundation.org/UA/SecurityPolicy#None",
                    UserIdentityTokens=[ua.UserTokenPolicy(PolicyId="anon")],
                )
            ],
        )
    )
    notification = ua.DataChangeNotification(
        MonitoredItems=[ua.MonitoredItemNotification(ClientHandle=i, Value=dv) for i, dv in enumerate(_data_values())]
    )
    publish = ua.PublishResponse(
        Parameters=ua.PublishResult(
            SubscriptionId=3,
            AvailableSequenceNumbers=[1, 2],
            NotificationMessage=ua.NotificationMessage(
                SequenceNumber=1,
                NotificationData=[ua.ExtensionObject(ua.FourByteNodeId(811), Body=struct_to_binary(notification))],
            ),
            Results=[ua.StatusCode(0)],
        )
    )
    browse = ua.BrowseResponse(
        Results=[
            ua.BrowseResult(
                References=[
                    ua.ReferenceDescription(
                        ReferenceTypeId=ua.NodeId(35),
                        IsForward=True,
                        NodeId=ua.ExpandedNodeId("n", 2, ua.NodeIdType.String, "urn:x", 1),
                        BrowseName=ua.QualifiedName("b", 2),
                        DisplayName=ua.LocalizedText("d", "en"),
                        NodeClass=ua.NodeClass.Object,
                        TypeDefinition=ua.ExpandedNodeId(61),
                    )
                    for _ in range(3)
                ],
                ContinuationPoint=b"cp",
            )
        ]
    )
    extension = extensionobject_to_binary(notification)
    xml_extension = bytes.fromhex("01 02 0500 02 04000000") + b"<a/>"
    return [
        ("ReadParameters", struct_to_binary(read_request), struct_decoder(ua.ReadParameters)),
        ("ReadResponse", struct_to_binary(read_response), struct_decoder(ua.ReadResponse)),
        ("CreateSessionResponse", struct_to_binary(session), struct_decoder(ua.CreateSessionResponse)),
        ("PublishResponse", struct_to_binary(publish), struct_decoder(ua.PublishResponse)),
        ("BrowseResponse", struct_to_binary(browse), struct_decoder(ua.BrowseResponse)),
        ("DiagnosticInfo", struct_to_binary(_nested_diagnostics(8)), struct_decoder(ua.DiagnosticInfo)),
        ("ExtensionObject", extension, extensionobject_from_binary),
        ("ExtensionObjectXml", xml_extension, extensionobject_from_binary),
    ]


def _mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        kind = rng.randrange(7)
        if not buf:
            buf.append(rng.randrange(256))
            continue
        pos = rng.randrange(len(buf))
        if kind == 0:
            buf[pos] ^= 1 << rng.randrange(8)
        elif kind == 1:
            buf[pos] = rng.choice(BOUNDARY_BYTES)
        elif kind == 2:
            del buf[pos:]
        elif kind == 3:
            buf.insert(pos, rng.randrange(256))
        elif kind == 4:
            del buf[pos : pos + rng.randint(1, 8)]
        elif kind == 5:
            value = rng.choice(LENGTH_VALUES).to_bytes(4, "little", signed=True)
            buf[pos : pos + 4] = value
        else:
            buf[pos] = rng.randrange(256)
    return bytes(buf)


def _run(seed: int, iterations: int) -> None:
    rng = random.Random(seed)
    corpus = _corpus()
    for _, valid, decoder in corpus:
        decoder(Buffer(valid))
    for _ in range(iterations):
        name, valid, decoder = rng.choice(corpus)
        case = _mutate(rng, valid)
        start = time.perf_counter()
        try:
            decoder(Buffer(case))
        except ua.UaError:
            pass
        except Exception as ex:
            pytest.fail(f"{name}: {type(ex).__name__}: {ex} for {case.hex()}")
        elapsed = time.perf_counter() - start
        assert elapsed < MAX_SECONDS_PER_DECODE, f"{name}: decode took {elapsed:.2f}s for {case.hex()}"


def test_decoders_only_raise_uaerror_on_mutated_input() -> None:
    """Part 6, 5.2: malformed input is a decoding error and nothing else (A8 fuzz test)."""
    _run(seed=20261025, iterations=3_000)


def test_decoders_only_raise_uaerror_on_every_truncation() -> None:
    """Part 6, 5.2: a truncated message is a decoding error and nothing else."""
    for name, valid, decoder in _corpus():
        for cut in range(len(valid)):
            try:
                decoder(Buffer(valid[:cut]))
            except ua.UaError:
                continue
            except Exception as ex:
                pytest.fail(f"{name} cut at {cut}: {type(ex).__name__}: {ex}")


def test_decoders_only_raise_uaerror_on_length_fields() -> None:
    """Part 6, 5.2.5: every Int32 position overwritten with boundary lengths is a decoding error or a decode."""
    for name, valid, decoder in _corpus():
        for pos in range(len(valid) - 3):
            for value in LENGTH_VALUES:
                case = valid[:pos] + value.to_bytes(4, "little", signed=True) + valid[pos + 4 :]
                start = time.perf_counter()
                try:
                    decoder(Buffer(case))
                except ua.UaError:
                    pass
                except Exception as ex:
                    pytest.fail(f"{name} at {pos}: {type(ex).__name__}: {ex} for {case.hex()}")
                assert time.perf_counter() - start < MAX_SECONDS_PER_DECODE, f"{name} at {pos} too slow"


@pytest.mark.slow
@pytest.mark.parametrize("seed", range(5))
def test_decoders_only_raise_uaerror_on_mutated_input_many(seed: int) -> None:
    _run(seed=seed, iterations=100_000)
