# Code review findings

Review of the hand-written code in `asyncua/`, going module by module and file by file. Each file's docstrings and the matching `docs/` pages are compared against what the code actually does. This file is the working list for the bug-fixing pass that follows the review.

Severity:
- **bug**: wrong behaviour that a caller can hit.
- **doc**: a docstring or doc page that doesn't match the code.
- **cleanup**: dead code, typos, inconsistencies or missing pieces that don't change behaviour.

"Verified" means the finding was reproduced by running code. "Spec-checked" means it was compared with the specification text, using a local copy from `docs/opcua-spec/fetch_specs.py` (see `docs/opcua-spec/README.md`). Everything else comes from reading the code. The specification may not be reproduced here, so it's cited by part and section and paraphrased.

Spec baseline:
- Findings are checked against **OPC 10000 v1.05**. Look up any cited section with `python docs/opcua-spec/fetch_specs.py show <part> <section> [--edition v1.04]`.
- The current editions are 1.05.07 for Parts 4 and 6 and 1.05.06 for Parts 1 and 3. **v1.04** (2017-11-22) is also online for every part. 1.00–1.03 and the intermediate 1.05.x releases aren't online.
- The generated code comes from the `nodeset` submodule, UA-Nodeset **1.05.02** (2022-11-01).
- Section numbers below are the 1.05 ones. Where 1.04 says something different, that's noted.

Differences between 1.04 and 1.05 found so far (they matter for interoperability with older peers):
- **Hello `ProtocolVersion`** (Part 6, 7.1.2.3). In 1.04 the client sends the *latest* version it supports, and the server must always accept a version higher than its own. In 1.05 the server rejects with `Bad_ProtocolVersionUnsupported` only if it supports neither the requested version nor any lower one, and returns the version it will use in the Acknowledge. Both editions define version `0`, so they're wire-compatible today. Check the server's Hello handling against both in the `server` review.
- **DiagnosticInfo nesting** (Part 6, 5.2.2.12). 1.04 requires decoders to support at least 100 nesting levels. 1.05 requires at least 4 and says decoders aren't expected to support more than 10. The limit our decoder enforces should satisfy both: support at least 4, and reject deep nesting with an error instead of recursing without bound.
- **XmlElement** is marked *Deprecated* in 1.05 (Part 6, 5.2.2.8). Decoders still have to handle it (see UA-37).

---

## asyncua/ua

### uaerrors/_base.py

- **UA-1 (bug)** (spec-checked): `UaStatusCodeError(code)` looks up the specific subclass by exact value (`_subclasses.get(code)`, line 44). Per Part 4, 7.38.1, the top 16 bits identify the specific condition, and the bottom 16 bits are flags that don't change the code's meaning. In that case the lookup misses, and the result is a plain `UaStatusCodeError` instead of, for example, `BadNodeIdUnknown`. So `except ua.uaerrors.BadNodeIdUnknown` doesn't catch it. Verified via `StatusCode(BadNodeIdUnknown | 0x0400).check()`. Fix: look up `code & 0xFFFF0000`, and keep the full code in `args`.
- **UA-2 (cleanup)**: `__init_subclass__` is decorated with `@classmethod`, which is redundant because it's an implicit classmethod.
  - Defining the subclass `UaStatusCodeErrors` also registers `_subclasses[<property object>] = UaStatusCodeErrors`, because `UaStatusCodeErrors.code` is the inherited property, not an int. That's a junk key.
- **UA-3 (doc)**: in the class docstring, "`code' property" has mismatched quotes.
- **UA-4 (cleanup)**: `UaStatusCodeErrors.__init__` doesn't call `super().__init__`. It works, because `args` gets set in `__new__`, but it's inconsistent with the base class.

### uatypes.py

- **UA-5 (bug)**: `types_or_list_from_union` (line 69) only recognises `typing.List[...]` as a list, via the `_name == "List"` hack.
  - With PEP 585/604 annotations (`list[int] | None`, `Optional[list[int]]`), it reaches `isinstance(None, list[int])`, which raises `TypeError: isinstance() argument 2 cannot be a parameterized generic`. Verified.
  - It's used by `ua_binary.py:749` when decoding optional struct fields. Custom structures with annotations written in modern syntax would fail to decode.
- **UA-6 (bug)**: `types_from_union` (line 89) only accepts `typing.Union`.
  - `type_string_from_type(int | str)` gets past `type_is_union` (which accepts `types.UnionType`) and then raises `ValueError: int | str is not an Union`. Verified.
  - It's also used by `xmlimporter.py:521`.
- **UA-7 (cleanup)**: the `hasattr(types, "UnionType")` guards in `type_is_optional` and `type_is_union` are dead code, because Python 3.10 is the minimum. `type_allow_subclass` already uses `types.UnionType` without a guard.
- **UA-8 (cleanup)**: in the `parse_bitfield` error message, "fo type" should be "of type".
- **UA-9 (cleanup)**: `WriteMask` stops at bit 21 (`ValueForVariableType`). Part 3, 5.2.7 also defines `DataTypeDefinition` (22), `RolePermissions` (23), `AccessRestrictions` (24) and `AccessLevelEx` (25).
- **UA-10 (doc)**: the `StatusCode.check()` docstring says it raises "if the status code is anything else than 0 (good)". It actually raises when the severity isn't Good, so Uncertain raises and Good codes with info bits don't. The class docstring lists `name()` and `doc()` as ivars, but they're properties.
- **UA-11 (bug)** (spec-checked, Part 4, 7.38.1): `StatusCode.name` and `.doc` have the same exact-value lookup problem as UA-1. With info bits set, `StatusCode(BadNodeIdUnknown | 0x0400).name` returns `"Bad"`. Verified. Fix: look up `value & 0xFFFF0000`.
- **UA-12 (bug)**: the NodeId and ExpandedNodeId string forms don't follow Part 6, 5.1.12. Spec-checked. Verified:
  - The spec form is `[svr=<idx>; | svu=<uri>;] (ns=<idx>; | nsu=<encoded-uri>;) <identifier>`. The server part comes first, and `ns=` and `nsu=` are alternatives.
  - `to_string()` writes `srv=` (not `svr=`), puts it and `nsu=` *after* the identifier, and can write `ns=` and `nsu=` together.
  - Since `s=` takes the rest of the string, `ExpandedNodeId("abc", NamespaceUri="urn:x", ServerIndex=2)` round-trips to `NodeId("abc;srv=2;nsu=urn:x")`.
  - Parsing the spec form `svr=2;nsu=urn:x;s=abc` silently ignores `svr`.
  - `svu=` (server URI) isn't supported.
  - URIs aren't percent-encoded or decoded. The spec requires RFC 3986 percent-encoding, with `;` escaped as `%3B`.
- **UA-13 (bug)**: `NodeId.from_string("nsu=urn:x;i=5")` produces `ServerIndex=None` instead of `0`, because `srv` defaults to `None` and is passed straight through (line 600). Verified.
- **UA-14 (bug)**: `ExpandedNodeId` equality and hashing ignore `NamespaceUri` and `ServerIndex`, because it inherits `NodeId.__eq__` and `__hash__`, and `eq=False` makes the `compare=True` on those fields meaningless. So `ExpandedNodeId(1, NamespaceUri="a") == ExpandedNodeId(1, NamespaceUri="b")` is `True`. Verified. A plain `NodeId` also compares equal to an `ExpandedNodeId` on another server.
- **UA-15 (bug)**: the `QualifiedName` constructor detects swapped arguments, logs "switching" and then doesn't switch. It goes on to raise `ValueError`. Verified with `QualifiedName(1, "x")`. Either swap the arguments as the message says, or drop the warning and raise a clear error.
- **UA-16 (bug)**: `QualifiedName.NamespaceIndex` is annotated `ua.Int16`, so binary encoding packs it as a signed `'h'`. Index values above 32767 fail with `struct.error`. Verified with 40000. The spec type is UInt16. `NodeId.NamespaceIndex` is also annotated `ua.Int16`, but `NodeId` uses its own encoder, so it works. The annotations should still say UInt16 (and UInt32 for numeric identifiers and `ExpandedNodeId.ServerIndex`, which says `Int32`).
- **UA-17 (bug)**: `check_identifier_type_compatibility` accepts a `str` identifier with `NodeIdType.ByteString` and a `bytes` identifier with `TwoByte`/`FourByte`. Those combinations then break later. For example, `NodeId("abc", 0, ByteString).to_string()` raises `TypeError` from `b64encode`. Verified. The compatibility table should only allow `bytes` with ByteString and `int` with the numeric types.
- **UA-18 (doc)**: `NodeId.from_string("b=...")` decodes the value as base64 whenever it's valid base64, and otherwise uses the raw ASCII bytes. So `b=abcd` becomes `b'i\xb7\x1d'`, while `b=abc` stays `b'abc'`. Verified. That ambiguity isn't documented anywhere. `to_string()` always writes base64, so only hand-written strings are affected. Unknown keys in a NodeId string (e.g. `x=1;i=5`) are silently ignored.
- **UA-19 (doc)**: the `NodeId` docstring doesn't match the class:
  - It documents args `identifier`, `namespaceidx` and `nodeidtype`, but the fields are `Identifier`, `NamespaceIndex` and `NodeIdType`.
  - It lists `NamespaceUri` and `ServerIndex` as ivars, which only exist on `ExpandedNodeId`.
  - It gives the `Identifier` vartype as `NodeId`.
- **UA-20 (doc)**: in `FourByteNodeId`, the error message for `NamespaceIndex > 255` says "cannot have NamespaceIndex != 0". `TwoByteNodeId`'s message has a double space.
- **UA-21 (cleanup)**: `NodeId.__lt__` raises `AttributeError` for a non-NodeId. It should return `NotImplemented` (or raise `TypeError`).
- **UA-22 (doc)**: the `LocalizedText` docstring ("A string qualified with a namespace index.") was copied from `QualifiedName`. The `Locale` annotation is `"ua.String| None"`.
- **UA-23 (question)**: `RelativePathElement` (there's no generated version, so `uaprotocol_auto` imports this one) defaults to `IsInverse=True`. Forward (`False`) would be the natural default. The internal callers (`node.py:665`, `relative_path.py:150`) set it explicitly, but user code that leaves it out gets inverse browsing. Decide whether the default should change.
- **UA-24 (bug)** (spec-checked): `DiagnosticInfo` is encoded by the generic struct encoder, which assigns mask bits in field order. Part 6, 5.2.2.12, Table 22 orders the stream fields `SymbolicId`, `NamespaceUri`, `Locale`, `LocalizedText`, but defines the mask bits as `LocalizedText = 0x04` and `Locale = 0x08`. Decoders have to support at least 4 levels of `InnerDiagnosticInfo` nesting. Verified:
  - That gives `Locale = 0x04` and `LocalizedText = 0x08`, but Part 6, 5.2.2.12 defines `LocalizedText = 0x04` and `Locale = 0x08`. Diagnostics exchanged with other stacks get those two fields swapped.
  - `InnerDiagnosticInfo` is annotated as `ExtensionObject`, but it's a nested `DiagnosticInfo`. Encoding a nested one raises `KeyError: No registered encoding for class DiagnosticInfo`. Decoding a spec-encoded nested one misreads the bytes as an empty `ExtensionObject`.
  - It only matters when a client asks for diagnostics (`ReturnDiagnostics`), so it's low-impact but wrong on the wire.
  - The docstring also repeats `:vartype LocalizedText:` twice.
- **UA-25 (bug)**: `Variant(Variant([...]))` is supposed to copy the argument (per the docstring), but loses `is_array`. `__post_init__` computes `is_array` before replacing `Value` with the inner list, so `Variant(Variant([1, 2, 3])).is_array` is `False` while `Dimensions` is copied. Verified. Binary encoding still comes out right, but code that checks `.is_array` (ValueRank or type checks) sees a scalar. `Dimensions` and `is_array` from the inner variant should be copied too.
- **UA-26 (cleanup)**: in `Variant._guess_type`, `isinstance(val, object)` is always true, so the final `raise UaError(...)` can never run. Any unknown object (a `dict`, for example) is classified as `ExtensionObject` and only fails later during encoding, with an unclear error.
- **UA-27 (cleanup)**: in `VariantTypeCustom`, the error message says "must be 63 > x > 25", but only `> 63` is rejected. Values from 0 to 25 and negative values are accepted.
- **UA-28 (question)**: `get_default_value` returns `datetime.now()` for DateTime and `uuid.uuid4()` for Guid. It's used to fill new variables and properties (`server.py:668, 736, 743`, `ua_utils.py:316`). A "default" that's different on every call is surprising. The spec's null values are `DateTime` min (0) and an all-zero Guid. Decide whether to change it.

### uaprotocol_hand.py

- **UA-29 (bug)**: the hand-written `DataChangeFilter` is meant to change the default trigger to `StatusValue` (comment: "Default is StatusValue", Part 4, 7.10). It does this with an unannotated class attribute (`Trigger = ...`), which is neither a dataclass field override nor kept by `@dataclass(slots=True)`. So `ua.DataChangeFilter().Trigger` is still `DataChangeTrigger.Status`. Verified.
  - With that default, a filter built by user code only reports status changes, not value changes.
  - The internal callers (`subscription.py:890, 963`) set `Trigger` explicitly, so they aren't affected.
  - Fix: `Trigger: auto.DataChangeTrigger = auto.DataChangeTrigger.StatusValue` as an annotated field.
- **UA-30 (bug)**: `AsymmetricAlgorithmHeader.__str__` computes the sender certificate length and throws it away (line 81). It then prints the thumbprint size for both `certificatesize` and `receiverCertificatesize`. Verified: a 100-byte certificate and a 20-byte thumbprint print as `20, 20`. Only debug output is affected.
- **UA-31 (cleanup)**: `Header` is a dataclass, but `body_size`, `packet_size` and `header_size` are unannotated class attributes, not fields. They only become per-instance values once they're assigned. The field annotations `MessageType: MessageType` and `ChunkType: ChunkType` shadow the classes of the same names. `MessageType.Invalid` and `ChunkType.Invalid` have `FIXME: check value` comments, and neither value exists in the spec.
- **UA-32 (cleanup)**: the `Message` accessor methods `SequenceHeader()` and `SecurityHeader()` use CamelCase names, which look like attributes but are methods. The file is also exempt from the annotation rule (`ANN` in `per-file-ignores`), but it's hand-written.
- **UA-33 (cleanup)**: in the `*Attributes` overrides, `__post_init__` always overwrites `SpecifiedAttributes`, so a value the caller passes is silently ignored. `VariableAttributes` instead uses a field default, which a caller can override. The `DataTypeAttributes` FIXME comment ("not sure what the spec expect…1.05???") is out of date: the spec defines `DataTypeDefinition` (bit 22 of `NodeAttributesMask`) since 1.04.

### relative_path.py

- **UA-34 (bug)**: `_find_reference_type` resolves `<Name>` with `getattr(ObjectIds, Name)`, so any standard node name is accepted, not just reference types. `RelativePath.from_string("<Server>Foo")` builds an element whose `ReferenceTypeId` is `i=2253` (the Server object). Verified. It also ignores the namespace index: `<2:HasComponent>` silently becomes ns=0 `HasComponent` (`i=47`). Verified. The name should only resolve when it's a ReferenceType in ns=0, and other namespaces should raise the existing "Non-standard ReferenceTypes are not supported" error.
- **UA-35 (bug)**: the reverse direction has the same problem. `_find_reference_type_name` and the `HierarchicalReferences`/`Aggregates` checks in `RelativePathElementFormatter.__init__` compare `Identifier` only. So `ns=2;i=33` is written out as `HierarchicalReferences`. Verified: `<#HierarchicalReferences>2:x`.
- **UA-36 (cleanup)**: `if self._element_type is None` (line 49) can never be true, because the attribute always has a value. In `to_string()`, a forward or inverse element with no reference name writes no reference part at all, and so parses back as `AnyHierarchical`. A target name with a namespace but an empty `Name` is dropped.

### ua_binary.py

- **UA-37 (bug)** (spec-checked): `extensionobject_from_binary` only handles encoding bit 0 (binary body). With bit 1 set (XML body, Part 6, 5.2.2.15), it reads neither the length nor the XML bytes. Everything after the ExtensionObject is then decoded from the wrong offset. Verified: a following Int32 1234 decodes as 4, the XML length. Fix: read the `XmlElement` (Int32 length plus bytes) and return it, e.g. as `ExtensionObject(TypeId, Body=xml)` with an XML flag, or at least skip it.
- **UA-38 (bug)** (spec-checked): `extensionobject_to_binary` sets encoding `0x01` (body follows) but only writes the body `if body:`. A structure with no fields serializes to `b""`, so the length field is left out and the message is malformed. Verified: `ua.MonitoringFilter()` encodes as `0100d10201` with no length, and decoding it then reads the following bytes as the length. 26 registered structure types have no fields (e.g. `DataTypeDefinition`, `DiscoveryConfiguration`, `DataSetReaderMessageDataType` and the other PubSub base types). Fix: `if body is not None:`.
- **UA-39 (cleanup, was bug)**: `_create_list_deserializer` (arrays of structures) decodes a null array (length `-1`) as `[]`, while the primitive and VariantType array decoders return `None`. Verified. Part 6, 5.1.11 says null and empty arrays are semantically the same and decoders needn't preserve the distinction, so this isn't a spec violation. It's only inconsistent within the library. Spec-checked.
- **UA-40 (bug)**: `_Primitive1.pack_array` logs a warning and encodes a **null array** when it gets something other than a `list` or `tuple` (e.g. a generator, `range`, `array.array` or a numpy array). The caller's data is silently replaced by null on the wire. It should either accept any sequence (`list(data)`) or raise.
- **UA-41 (cleanup)**: in `create_enum_serializer`, `isinstance(uatype, Enum)` checks a class, not an instance, so it's always false and that branch can never run. Everything falls through to `Int32.pack`, which works for `IntEnum` but would fail for a non-int `Enum`.
- **UA-42 (cleanup)**: `strip_optional` only handles PEP 604 unions (`X | None`), not `typing.Optional`/`Union`. `test_bit` has a name that pytest would collect if it were ever imported into a test module.
- **UA-43 (question/security)**: `resolve_uatype` and `_resolve_type_in_dataclass_context` `eval()` type-hint strings. Those come from dataclass annotations, which include classes generated at runtime from a **server's** DataTypeDefinitions (`common/structures104.py`). Check, in the `common` review, that field and type names from the remote side are always sanitized before they reach an annotation that gets `eval`'d.
- **UA-44 (cleanup)**: `extensionobject_from_binary` with length `-1` (the "old implementations" interop fix) uses the **whole remaining buffer** as the body. For an unregistered TypeId it then reads everything that's left into `Body`, which swallows the fields that follow. `_reshape` quietly pads with `[]` when `Dimensions` declares more elements than the array has, instead of rejecting the mismatch.

- **UA-46 (bug)** (spec-checked): `QualifiedName.to_string()` always writes `<idx>:<name>`, including `0:Name` for the OPC UA namespace. Part 6, 5.1.12, Table 7 requires names in the OPC UA namespace to use the form without a prefix. `from_string` also doesn't support the `nsu=<uri>;<name>` form. Changing `to_string` affects anyone who stores or compares these strings, so do it together with UA-12.

### docs/usage/common/node-nodeid.rst (NodeId part)

- **UA-45 (doc)**: the NodeId string format section doesn't match the spec or the code:
  - It documents `srv=` as the server-index key, but the spec key is `svr=` (see UA-12).
  - It doesn't say that `s=` takes the rest of the string, semicolons included, so `s=` has to come last.
  - It doesn't say that `b=` is base64, or that the non-standard `0x…` hex form and the raw-bytes fallback exist (see UA-18).
  - The `Guid` (`g=`) format isn't described.
  - The Node part of the page says `write_value(5)` "would result in an error" because it's sent as Int64. Check that claim against `Node.write_value` in the `common` review.

### Summary: asyncua/ua

46 findings: 20 bugs, 7 doc, 16 cleanup, 3 questions (one of them about security). 19 of the bugs were reproduced by running code; UA-40 is from reading the code. UA-1, UA-11, UA-12, UA-24, UA-37, UA-38, UA-39 and UA-46 were also checked against the spec text. Highest impact:

1. **UA-37, UA-38**: ExtensionObject encoding and decoding can desynchronise the stream (XML bodies; structures with no fields).
2. **UA-1, UA-11**: status codes with info bits don't map to the specific exception class or name.
3. **UA-5, UA-6**: modern type annotations (`list[X] | None`, `A | B`) break the union and list helpers.
4. **UA-29**: the `DataChangeFilter` default trigger override has no effect.
5. **UA-12 to UA-14**: `ExpandedNodeId` string form, parsing and equality.
6. **UA-24**: `DiagnosticInfo` bit layout and nesting.
