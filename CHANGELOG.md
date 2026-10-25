# Changelog

## 3.0.0 (unreleased)

The first release of `enginir-opcua`, a fork of [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0.
All breaking changes are collected here and released together.

### Migrating from asyncua 2.x

Package and identity:
- The import package is `enginir_opcua` and the distribution is `enginir-opcua`. There is no `asyncua` alias, so both
  packages can be installed side by side.
- The command-line tools are `enginir-ua<tool>` (`enginir-uaread`, `enginir-uals`, `enginir-uaserver`, …).
- The default application identity changed: server endpoint `opc.tcp://0.0.0.0:4840/enginir-opcua/server/`,
  ApplicationUri `urn:enginir:opcua:server` and `urn:enginir:opcua:client`, ProductUri `urn:enginir:opcua`,
  ManufacturerName `engiNIR`.
- Python 3.12 or newer is required.

Security:
- RegisterServer and RegisterServer2 answer `Bad_ServiceUnsupported` unless the server calls
  `Server.accept_server_registrations()`.

Status codes:
- Status codes are matched by their top 16 bits, so `except ua.uaerrors.BadNodeIdUnknown` also catches a code with info
  bits set. `error.code` is the full code as received; `StatusCode.name` and `.doc` ignore the info bits.
- `StatusCode("unknown name")` raises `UaError` instead of `AttributeError`.

NodeId, QualifiedName and LocalizedText strings (OPC 10000-6, 5.1.12):
- `NodeId.to_string()` writes `[svr=<index>;][ns=<index>;|nsu=<uri>;]<identifier>`. The server index comes first and
  is spelled `svr=`, not `srv=` after the identifier. Namespace URIs are percent-encoded.
- `NodeId.from_string()` is strict: unknown keys, trailing components, malformed numbers and GUIDs, invalid Base64 and
  `svu=` raise `UaStringParsingError`. `srv=` is still read, but only in front. `b=` is Base64 only; the `0x` hex form
  and the raw-bytes fallback are gone. Spaces after `;` are no longer allowed. `nsu=` strings give `ServerIndex` 0.
- `QualifiedName.to_string()` writes names in namespace 0 without a prefix (`Root`, not `0:Root`), which also changes
  `Node.get_path(as_string=True)`. `QualifiedName.from_string()` takes `namespaces=` for the `nsu=` form, and `a:b` is
  a name. Swapped or wrongly typed constructor arguments raise `TypeError`.
- `LocalizedText.to_string()` writes `LocalizedText(Locale=<repr>, Text=<repr>)`, which `from_string()` reads back
  exactly. A text of `"None"` stays a text.

Identity and ordering:
- `ExpandedNodeId` equality and hashing include `NamespaceUri` and `ServerIndex`. A `NodeId` equals an `ExpandedNodeId`
  only when the latter has no URI and ServerIndex 0.
- A text identifier with type ByteString, or bytes with TwoByte or FourByte, raises `UaError`. Comparing a NodeId with
  something else raises `TypeError`.
- An `ExpandedNodeId` with a NamespaceUri is encoded with namespace index 0.

Variant and defaults:
- `Variant` equality compares `Dimensions` and `is_array`. A Variant copied from a Variant keeps both.
- A Variant can't hold a DiagnosticInfo; constructing or decoding one raises `UaError`.
- Type guessing raises `UaError` for objects it doesn't know instead of assuming ExtensionObject. `VariantTypeCustom`
  accepts 26 to 63 only.
- A scalar `None` is accepted for every nullable type and becomes that type's null value.
- ArrayDimensions are written only for two or more dimensions, all above 0, so an empty multi-dimensional array comes
  back flat.
- `get_default_value()` returns the null values: DateTime 1601-01-01 UTC and the all-zero Guid instead of the current
  time and a random Guid.
- `WriteMask` has the members for bits 22 to 25.

Encoding and decoding:
- Decoding malformed input raises only `UaError` subclasses: unknown enum values, bad NodeId formats, union switches
  out of range, unassigned optional-field bits, ExtensionObject length -1 for an unknown type, inconsistent Variant
  dimensions, nesting deeper than 100 levels and impossible array counts.
- Arrays accept any iterable and raise `UaError` for a scalar or a `str`; a non-list used to be sent as a null array.
- An ExtensionObject with an XML body decodes to an `ExtensionObject` with `Encoding == 2` and the XML in `Body`.
- LocalizedText leaves out empty Locale and Text on the wire.
- `DiagnosticInfo.NamespaceURI` is `NamespaceUri`, `InnerDiagnosticInfo` is a `DiagnosticInfo`, and nesting deeper
  than 10 levels raises.
- `Buffer.copy(n)` beyond the remaining bytes raises, `Buffer.rewind()` stays inside its window, and
  `Buffer(data, start, size)` checks the window.
- `ua_binary.test_bit` is `is_bit_set` and returns a `bool`.

Messages and paths:
- `ua.DataChangeFilter().Trigger` defaults to `StatusValue`.
- The `*Attributes` classes keep a `SpecifiedAttributes` value passed by the caller (except `DataTypeAttributes`).
- `Message.SequenceHeader()` and `SecurityHeader()` are `sequence_header()` and `security_header()`.
  `Header.header_size` is a read-only property, `body_size` and `packet_size` are constructor fields, and
  `MessageType.Invalid` and `ChunkType.Invalid` are gone.
- `RelativePathElement()` defaults to `IsInverse=False` (forward).
- RelativePath text errors raise `UaStringParsingError` instead of `ValueError`. Only standard ReferenceTypes in
  namespace 0 are accepted by name, so `<Server>` and `<2:HasComponent>` raise. A forward or inverse step without a
  reference name raises when written.

XML import:
- Nodes marked `DesignToolOnly`, their children and references to them are skipped (OPC 10000-6, F.7).

Code generation:
- The generated code comes from the `nodeset` submodule, pinned to UA-Nodeset `UA-1.05.07-2026-05-01`.
  `schemas/regenerate.py` replaces `schemas/update_ua_nodeset.py`.
