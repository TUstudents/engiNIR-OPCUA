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
- The generated code was built from UA-Nodeset tag **`UA-1.05.07-2026-05-01`** (core model 1.05.07, published 2026-05-01; see the header of `asyncua/server/standard_address_space/standard_address_space_services.py`). `schemas/update_ua_nodeset.py` clones UA-Nodeset into `schemas/UA-Nodeset-master/` for that; the `nodeset` submodule is an older copy (commit `526c5e59`, 2023) that only the tests use. An earlier version of this line said the code came from the submodule's 1.05.02, which was wrong.
- Section numbers below are the 1.05 ones. Where 1.04 says something different, that's noted.

Differences between 1.04 and 1.05 found so far (they matter for interoperability with older peers):
- **Hello `ProtocolVersion`** (Part 6, 7.1.2.3). In 1.04 the client sends the *latest* version it supports, and the server must always accept a version higher than its own. In 1.05 the server rejects with `Bad_ProtocolVersionUnsupported` only if it supports neither the requested version nor any lower one, and returns the version it will use in the Acknowledge. Both editions define version `0`, so they're wire-compatible today. The server never checks the version and always answers `0`, which is correct for both while `0` is the only version (SRV-8).
- **DiagnosticInfo nesting** (Part 6, 5.2.2.12). 1.04 requires decoders to support at least 100 nesting levels. 1.05 requires at least 4 and says decoders aren't expected to support more than 10. The limit our decoder enforces should satisfy both: support at least 4, and reject deep nesting with an error instead of recursing without bound.
- **XmlElement** is marked *Deprecated* in 1.05 (Part 6, 5.2.2.8). Decoders still have to handle it (see UA-37).
- **`DesignToolOnly` in UANodeSet files** (Part 6, F.7, new in 1.05). Nodes marked this way are for modelling tools only and are not added to the address space. Current companion nodesets use it (see COM-57).
- **Channel-bound session signatures** (Part 4, 6.1.8, new in 1.05). CreateSession and ActivateSession signatures include the channel's certificates, but only for SecurityPolicies with `SecureChannelEnhancements = TRUE` (the newer policies). The RSA policies asyncua supports keep the legacy calculation, so nothing changes until new policies are added.

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

---

## asyncua/common

### utils.py

- **COM-1 (bug, robustness)**: `Buffer.read()` and `Buffer.skip()` only check `size > self._size`, so a negative size is accepted and moves the cursor *backwards*. Verified:
  - `_Bytes.unpack` and `_String.unpack` pass any length other than `-1` straight through.
  - A String whose length on the wire is `-5` decodes as `'abcde'` and leaves the cursor at `-1`, with 11 bytes "remaining" in a 10-byte buffer.
  - Malformed or hostile input can therefore make the decoder re-read data, and an array of such elements could loop without ever reaching the end.
  - Part 6, 5.2.2.4 and 5.2.5 define only `-1` (null). Fix: in `read()` and `skip()`, raise on `size < 0`, and reject lengths below `-1` in the String, ByteString and array decoders.
- **COM-2 (bug)**: `Buffer.copy(size)` creates a window over the same data, but `__bytes__` returns `data[cur_pos:]` and `rewind()` resets `_size` to `len(data) - cur_pos`. Both ignore the window. Verified: `bytes(Buffer(b"0123456789").copy(3))` gives all 10 bytes, and after `rewind()` the window's length is 10. `connection.py:477` rewinds a body buffer, so check it there.
- **COM-3 (cleanup)**: `fields_with_resolved_types` assigns resolved types to the `Field` objects returned by `dataclasses.fields()`. Those are the class's shared field objects, so calling it permanently changes the dataclass metadata for all later users. It should return resolved copies instead (it's only used by `xmlexporter.py:542`).

### callback.py

- **COM-4 (bug)**: `CallbackService.addListener` stores listeners in a dict keyed by `priority`. A second listener added with the same priority, including the default `0`, **replaces** the first without any warning. Verified: after adding `a` and then `b` to `PreWrite`, only `b` is called. Fix: keep a list per priority, or a sorted list of `(priority, sequence, listener)`.
- **COM-5 (cleanup)**: `call_listener` decides whether to await based on `inspect.iscoroutinefunction(listener)`. An object with an `async def __call__` isn't detected, so its coroutine is never awaited. Calling the listener and awaiting the result when `inspect.isawaitable(result)` covers every case. The `CallbackType` docstring lists `:ivar MonitoredItem:`, which isn't a member, and leaves out the real members. The API uses camelCase (`addListener`, `setName`).

### session_interface.py, and spec links across the codebase

- **COM-6 (doc, codebase-wide)**: about 50 docstring links use the old URL forms `reference.opcfoundation.org/Core/Part4/v104/<section>` and `/v104/Core/docs/...`. The site now redirects those to the **current** edition, keeping the section number. Part 4 renumbered its service sets in 1.05, so these links land on the wrong section. Spec-checked against both editions:
  - Browse (1.04 §5.8.2) opens AddNodes in 1.05.
  - Call (1.04 §5.11.2) opens Read.
  - CreateSubscription (1.04 §5.13.2) opens CreateMonitoredItems.
  - Every link in `session_interface.py` is affected.
  - Fix: either use the versioned form `/specs/OPC-10000-4/v1.04/<section>`, which still serves 1.04, or update the numbers to 1.05.
  - The docstrings also copy spec sentences word for word ("This Service is used to…"). The licence (see `docs/opcua-spec/README.md`) argues for short paraphrases instead.

### methods.py

- **COM-7 (doc)**: `@uamethod` turns return values into output arguments according to rules nobody wrote down:
  - `None` becomes no outputs.
  - A `tuple` becomes one output argument per element.
  - A `list` becomes a single array output.
  - A `StatusCode` or `CallMethodResult` is passed through as is.
  - The decorator also works out whether it's wrapping a method (`self`) by checking `isinstance(parent, ua.NodeId)`.
  - None of this is in the docstring or `docs/`. The `call_method`/`call_method_full` docstrings say `methodid` is a browse name or a `NodeId`, but a `Node` is accepted too. The `_call_method` docstring documents `:param server:`, but the parameter is called `session`.
- **COM-8 (cleanup)**: `call_method_full` calls `res.StatusCode.check()`, so a failed call raises with only the top-level code. The per-argument `InputArgumentResults` (which argument was wrong) and `InputArgumentDiagnosticInfos` are thrown away, although they're exactly what the caller needs to fix a `BadInvalidArgument`. Attach them to the exception.

### ua_utils.py

- **COM-9 (bug)**: `val_to_string` and `string_to_val` are documented as a round-trip pair ("not too hard to parse back"), but aren't. Verified:
  - **Enums**: `val_to_string(NodeClass.Object)` gives `"Object"`, but `string_to_val` only accepts digits or the UANodeSet form `Name_Value`. `string_to_val("Object", NodeClass)` raises `IndexError`.
  - **Lists of strings**: elements aren't quoted, and `string_to_val` splits on `,`. So `["a,b", "c"]` comes back as `["a", "b", "c"]`.
  - **Unsupported types**: VariantTypes the function doesn't handle (ExtensionObject, DataValue, Variant, DiagnosticInfo) reach `issubclass(vtype, Enum)` with an enum *member* and raise `TypeError` instead of the intended `NotImplementedError`.
- **COM-10 (cleanup)**: `string_to_val` for Boolean returns `False` for anything it doesn't recognise (`"TRUE"`, `"yes"`, a typo) instead of raising. Integer types aren't range-checked (`"300"` is accepted for a Byte and only fails later during encoding). XML only allows `true`/`false`/`1`/`0`, so the XML importer isn't affected, but the CLI tools and other callers are.
- **COM-11 (doc)**: several docstrings don't match their functions:
  - `get_base_data_type` says it takes a "NodeId of a datatype" and returns "NodeId … or None". It takes and returns a `Node`, and raises `UaError` instead of returning `None`.
  - `get_node_supertypes` says `node` "can be an ua.Node or ua.NodeId", but only a `Node` works.
  - `get_nodes_of_namespace` accepts any `server: Any`, but reads `server.iserver.aspace`, so it only works on a local `Server`. A namespace URI that isn't in the namespace array raises a bare `ValueError` from `list.index`.

### node.py

- **COM-12 (bug, interop)** (spec-checked): `Node.write_value()` goes through `value_to_datavalue`, which stamps every value it builds with `SourceTimestamp=now`, unless the caller passes a ready-made `DataValue`.
  - Per Part 4, 5.11.4, a server has to use timestamps it's sent, and has to answer `Bad_WriteNotSupported` if it doesn't support writing them.
  - So a plain `node.write_value(5.0)` from a client fails on any server that doesn't allow timestamp writes (many PLC servers don't) and overwrites the source timestamp on servers that do.
  - Client writes should leave both timestamps empty by default. On a local `Server`, the address space can set them.
  - This is also the "error" the docs blame on Int64 vs Double in `docs/usage/common/node-nodeid.rst` (UA-45). That type-mismatch claim is a separate issue: it's true only for servers that reject the subtype.
- **COM-13 (bug)** (spec-checked): `write_array_dimensions(value: int)` writes a **scalar** UInt32, but the ArrayDimensions attribute is `UInt32[]`, with one entry per dimension (Part 3, Variable and VariableType attributes). Verified: after `write_array_dimensions(3)` the attribute holds `3`, and `read_array_dimensions()`, annotated `-> list[int]`, returns `3`. Our server accepted the scalar without checking the type (see the `server` review).
- **COM-14 (bug)**: `get_references`/`get_children` never look at `BrowseResult.StatusCode`. Browsing a node that doesn't exist returns `[]` instead of raising. Verified: the raw result was `BadNodeIdInvalid` (it should be `BadNodeIdUnknown`, see the server review). `_browse_next` likewise ends quietly with partial results when `BrowseNext` fails (e.g. `BadContinuationPointInvalid`). If it stops early, it doesn't release the continuation point.
- **COM-15 (bug, interop)** (spec-checked): `read_raw_history()` and `read_event_history()` called with no arguments send `StartTime = EndTime = DateTime.min` and `NumValuesPerNode = 0`. That leaves all three parameters unspecified, but Part 11, 6.5.2 and 6.5.3 require at least two of them. A conforming server can reject the request. The defaults should be something valid, for example `EndTime = now`, or callers should be required to pass the range.
- **COM-16 (bug)**: continuation points in history reads aren't handled properly:
  - `read_event_history` never follows them, so only the first page of events is returned and the rest is silently lost. `history_read_events` doesn't even accept a continuation point.
  - `read_raw_history` stops after the first page when `numvalues > 0` or when the server repeats a continuation point, and in both cases leaves the continuation point open on the server. `ReleaseContinuationPoints` is never sent. Servers limit continuation points per session, so leaking them eventually causes `BadNoContinuationPoints`.
- **COM-17 (doc)**: `history_read`, `history_read_events` and `read_*_history` all say "result code from server is checked and an exception is raised". `history_read` and `history_read_events` don't check anything. `get_path` says it "may return an empty list", but it always includes the node itself. `get_child` and `get_children_by_path` take the first target without checking `RemainingPathIndex`, so a path that leaves the server returns an intermediate node as if it were the target. `get_children_by_path` is annotated `list[list[Node | None]]`, but returns `list[list[Node] | None]`.

### manage_nodes.py

- **COM-18 (bug, data loss)**: `delete_nodes(recursive=True)`, and so `Node.delete(recursive=True)`, collects descendants via `get_children()`, which follows **all** forward hierarchical references, including `Organizes` and `HasNotifier`/`HasEventSource`. Verified:
  - Deleting folder A, which only *organizes* a folder owned by `Objects`, also deletes that folder.
  - With a cycle of hierarchical references (C `HasNotifier` → B, its parent), `_add_childs` recurses until `RecursionError`.
  - The same node can be collected more than once.
  - Fix: follow only ownership references (`HasChild`: `HasComponent`, `HasProperty`, `HasSubtype`, and so on), and track visited nodes.
- **COM-19 (bug)**: `create_data_type` adds the node with `ParentNodeId` and `ReferenceTypeId = HasSubtype`, so the server already creates both directions of the reference. It then adds an extra inverse `HasSubtype` reference and **ignores the result** (`results` is never checked). Either drop the extra call or check the result.
- **COM-20 (cleanup)**: the defaults for new variables don't match the spec's meaning of these attributes. Verified:
  - A 1-D list gets `ValueRank = 0` (`OneOrMoreDimensions`) instead of `1`.
  - A multi-dimensional value pins `ArrayDimensions` to the current shape, e.g. `[2, 2]`. Part 3 defines ArrayDimensions as the *maximum* length per dimension, with `0` meaning unknown, so this declares that larger arrays aren't allowed.
  - Every node created here gets its browse name as its `Description`.
  - `_create_variable_type` drops falsy initial values (`if value:` ignores `0`, `False`, `[]`).
- **COM-21 (question)**: in `create_method`/`_vtype_to_argument`, an argument type given as a list (`[ua.VariantType.Int32]`) uses the first element as the type but leaves `ValueRank = -1` (scalar). If a list is meant to declare an array argument, the array-ness is lost. All generated `Argument`s also have an empty `Name` and `Description`, so clients see unnamed method arguments. `create_reference_type(symmetric=False)` without an `inversename` creates a non-symmetric reference type with no `InverseName`, which Part 3 requires. The `create_encoding` error message has a typo ("QualigiedName").

### instantiate_util.py

- **COM-22 (bug)** (spec-checked): `_instantiate_node` instantiates `OptionalPlaceholder` children when `instantiate_optional=True` (the default), and `MandatoryPlaceholder` children always, as if they were ordinary declarations. Per Part 3, 6.4.4.4.4–5, a placeholder doesn't define an instance's BrowseName. It only declares that instances may (or must) be added later, and its sub-declarations aren't considered for instantiation. Verified: `add_object(..., FileDirectoryType)` creates literal children `<FileDirectoryName>` and `<FileName>` next to the real methods. Placeholders should be skipped.
- **COM-23 (bug)**: `_instantiate_node` doesn't check the `AddNodesResult` status (line 112). If the add fails, it carries on with the null `AddedNodeId`. Verified: instantiating with a node id that already exists (`BadNodeIdExists`) returns `Node(i=0)` with no error, and tries to instantiate children under that null id.
- **COM-24 (cleanup)**: the abstract-type check lists `ReferenceType` twice and leaves out `VariableType`, so an abstract VariableType isn't rejected. Only the first `HasModellingRule` reference is looked at. `is_child_present` re-browses the new node once per child declaration, which costs N extra round trips from a client.

### copy_node_util.py

- **COM-25 (bug)**: `copy_node(recursive=True)` has the same problems as recursive delete (COM-18). It walks `get_children_descriptions()`, which follows **all** hierarchical references, so nodes the source only *organizes* get duplicated as well, and a hierarchical cycle recurses without end. Like COM-23, `_copy_node` doesn't check the `AddNodesResult` status.
- **COM-26 (bug)**: `_read_and_copy_attrs`, used by both `copy_node` and `instantiate`, never copies `EventNotifier` or `IsAbstract`. That's correct when instantiating from an ObjectType, which has no `EventNotifier` attribute. But `copy_node` of an Object that can emit events produces a copy with `EventNotifier = 0`, and copying an abstract type produces a concrete one. When copying the root node, the reference type to the new parent is guessed (`Organizes` under folders, otherwise `HasComponent`), so a copied property is attached with `HasComponent` instead of `HasProperty`.

### events.py

- **COM-27 (bug)**: `Event.get_event_props_as_fields_dict()` (used by `server/history_sql.py:291` to store events) builds a `Variant` for every attribute that isn't internal:
  - A property that is still `None` with a non-nullable type raises. Verified: a fresh custom event fails with `UaError: Non array Variant of type 21 cannot have value None`, i.e. `Message` is unset.
  - `CustomEvent.init()` sets `self._freeze = True`, which is neither in `internal_properties` nor in `data_types`. By reading the code, `data_types["_freeze"]` therefore raises `KeyError`.
  - So custom events can't be turned into a field dict. While checking this I found that SQL event history with a custom event type is broken end to end. Reading events back logs `near "FROM": syntax error`, and the in-memory SQLite database had no tables after the event was triggered. That's carried over to the `server` review as a reproduction.
- **COM-28 (cleanup)**: `_select_clause_from_childs` compares `ref.ReferenceTypeId == ua.ObjectIds.HasProperty`, a `NodeId` against an `int`, which is always `False`. So the property branch never runs, and every property is also browsed for children, which costs one extra round trip per property when building a filter. `browse_path_to_attribute_name` joins only the `Name`s, so `ns=0 Severity` and `ns=2 Severity` map to the same attribute. `Event.from_event_fields` uses `sattr.AttributeId.name`, which fails if `AttributeId` is a plain `int`, as it is after decoding. `to_event_fields` already converts it with `ua.AttributeIds(...)`.
- **COM-29 (cleanup)**: `where_clause_from_evtype` builds `EventType InList [all subtypes]`. It browses the whole subtype tree from the client first, and misses event types added to the server later. Part 4's `OfType` filter operator does this check on the server in one operand. `_event_type_nodes_up_to_base` returns `[]` when a type has no single parent, which gives a filter with no select clauses.

### subscription.py

- **COM-30 (bug)**: `modify_monitored_item` sets `item.mfilter = results[0].FilterResult`, replacing the item's *filter* with the server's *filter result*: an `ExtensionObject`, `EventFilterResult` or `None`. Verified on an event subscription:
  - After `modify_monitored_item(handle, 100)`, the stored filter is an `ExtensionObject`. `_explode_events` then rejects every event ("monitored item has no event filter"), so events stop arriving with only a log warning (1 event before the modify, still 1 after).
  - The same wrong value is used when the item is recreated after a reconnect.
  - The new sampling interval and queue size aren't stored either, so a recreate restores the old ones.
  - The result's `StatusCode` isn't checked.
- **COM-31 (bug)**: `modify_monitored_item` with an unknown handle raises `RuntimeError: coroutine raised StopIteration`. Verified. `next()` without a default raises `StopIteration` inside a coroutine, so the following `if not item_to_change: raise ValueError(...)` can never run. Use `next(..., None)`.
- **COM-32 (bug)**: after the server revises a subscription's parameters, `self.parameters` keeps the *requested* values in most cases:
  - `_create` never stores the revised values.
  - `Client.create_subscription` only calls `update()` when both the interval and the derived keep-alive count changed, and `update()` copies the *requested* modify parameters, not the revised result.
  - `is_stale()` computes its deadline from these values. A server that raises the publishing interval or keep-alive count therefore makes the stale-subscription watchdog fire early and recreate a healthy subscription.
  - Found by reading the code; not reproduced.
- **COM-33 (bug)**: delivery happens inside the client's single publish loop (`ua_session._publish_loop` awaits each callback):
  - In iterator mode, `_deliver` does `await queue.put()` on a bounded queue (`queue_maxsize=1000`). A subscription created without a handler whose iterator is never consumed (or is consumed slowly) blocks the publish loop once the queue is full. **All** subscriptions on the session then stop receiving data and keep-alives, and the server may eventually time them out.
  - Slow async legacy handlers have the same effect.
  - The `_dispatch_to_handler` docstring says the handler runs "in its own task", but it's awaited inline.
- **COM-34 (bug)**: local state goes out of sync with the server:
  - `unsubscribe()` checks only `results[0]`, then removes **all** given handles locally, even ones the server failed to delete.
  - `set_monitoring_mode()` doesn't update the stored `monitoring_mode`, so a recreate after a reconnect restores the old mode.
  - `set_monitoring_mode()` also sends `None` for items that don't have a server handle yet.
  - `recreate()` always sets `DiscardOldest=True`, regardless of the original request.
- **COM-35 (doc)**: the `subscribe_data_change` overloads declare `sampling_interval=0.0`, but the implementation defaults to `50.0`. The `deadband_monitor` docstring says the queue size defaults to 1, but it's `0`. The class docstring's `:param server:` describes a parameter that is called `server` but holds a session.

### connection.py

- **COM-36 (bug, robustness)** (spec-checked): `TransportLimits.create_acknowledge_and_set_limits` accepts any buffer size from the peer's Hello. Part 6, 7.1.2.3 requires `ReceiveBufferSize` and `SendBufferSize` to be at least 8192 bytes (1024 with ECC policies). Verified:
  - After `Hello(ReceiveBufferSize=16)`, the server's send buffer is 16, `max_body_size()` is `-8`, and `message_to_chunks` turns a 500-byte response into **zero chunks**. The response is silently never sent, and the client waits until it times out.
  - Values just above the header size (e.g. 32) produce one chunk per few bytes instead.
  - Fix: reject Hellos below the minimum with `Bad_TcpMessageTooLarge`/`Bad_ProtocolVersionUnsupported`-style errors, or clamp them up. `update_client_limits` should validate the Acknowledge the same way.
- **COM-37 (bug)** (spec-checked): `SecureConnection.open` (server side) copies `RequestedLifetime` into `RevisedLifetime` unchanged, both when issuing and when renewing. Part 4, OpenSecureChannel requires the server to return a lifetime greater than 0 and a sensible value. A client requesting `0` gets a token that expires immediately, and a client requesting about 49 days (`UInt32` max) gets keys that are never rotated, which weakens the reason for token renewal. Clamp the value to a configured minimum and maximum.
- **COM-38 (cleanup)**: `TransportLimits.create_hello_limits` is never called, and has a bug: it sets `MaxMessageSize = self.max_chunk_count`. Delete it or fix it. The client sends the `ua.Hello` defaults instead: 2³¹−1 for both buffers and `0` (no limit) for message size and chunk count. The server's `TokenId` is the constant `13` for every new channel ("random value"). `_receive` checks `packet_size > max_recv_buffer` only *after* the chunk has been decrypted and verified, so an oversized chunk costs the full crypto work before it's rejected. The `InvalidSignature` retry path calls `body.rewind()`, which ignores a buffer window (COM-2).

### structures.py (legacy, pre-1.04 type dictionaries)

- **COM-39 (security, high, fixed in `6f9f1a14`)**: **a server can execute arbitrary Python code in the client.** `Client.load_type_definitions()` (and `Server.load_type_definitions()`, plus the sync wrappers) works like this:
  1. It reads the server's OPC Binary type dictionary (`structures.py:268`).
  2. It builds Python source from it (`EnumType.get_code`, `Struct.get_code`).
  3. It `exec`s that source (`_generate_python_class`, line 336).
  - Names are passed through `clean_name`, but `EnumeratedValue`'s **`Value` attribute is pasted into the source unchanged** (`f"    {name} = {value}\n"`). Through `get_default_value(..., enums)`, it also ends up as a struct field's default value.
  - Verified with a harmless payload: an enum value of `__import__('builtins').__setattr__('PWNED_BY_SERVER', True) or 1` in the dictionary XML ran in the client process. Any client that calls `load_type_definitions()` against a malicious or compromised server, or a man-in-the-middle when security is off, can be taken over.
  - `StructGenerator.save_to_file` writes the same injected code into a `.py` file for later import.
  - Fix: stop generating source code. Build the enums and dataclasses with `IntEnum(name, members)` and `make_dataclass`, as `structures104` already does. At the very least, parse `Value` with `int()` and reject anything else.
  - This resolves UA-43. The 1.04 path (`structures104.py`) is safe: every name goes through `clean_name`, enum values arrive as typed integers from `EnumDefinition`, and classes are built with `make_dataclass`/`IntEnum(...)`, not from source text.

### structures104.py

- **COM-40 (bug)**: generated structure and enum classes go into **process-wide** registries (`ua.extension_objects_by_typeid`, `extension_objects_by_datatype`, `enums_by_datatype`, and attributes on the `ua` module). These are keyed by NodeIds that contain a namespace **index**, which only means something within one server session.
  - Two `Client`s in the same process, connected to different servers that both use e.g. `ns=2;i=5001` for different structures (common for PLCs from the same vendor), overwrite each other's classes. Values from one server are then decoded with the other server's class.
  - `_set_ua_attribute` only warns about collisions of the *name* attribute.
  - Found by reading the code; not reproduced. The registries would have to be per session, or at least keyed by namespace URI.
- **COM-41 (bug)** (spec-checked): `new_struct_field(array=True)` sets `ArrayDimensions = [1]`. Part 3 (StructureField) defines ArrayDimensions as the maximum length per dimension, with `0` for unknown, so `[1]` declares that the array holds at most one element. Use `[0]`, or leave ArrayDimensions null.
- **COM-42 (cleanup)**: `make_enum` builds members from `clean_name(field.Name)`, so two fields whose names clean to the same identifier (`"A-B"` and `"A_B"`) silently collapse into one. `load_enum_xml_import` uses `DisplayName.Text` as the class name without `clean_name`. The default values for generated structures share the "different on every call" problem of UA-28: `Guid` is `uuid.uuid4()` and `DateTime` is `now()`.

### type_dictionary_builder.py

- **COM-43 (cleanup)**: `StructNode.add_field(type_name, field_name, is_array)` has its parameter names swapped. Callers pass the field name first and the type second (`add_field("Speed", ua.VariantType.Double)`), and the method forwards them in that order to `DataTypeDictionaryBuilder.add_field(type_name, variable_name, …)`. Verified that the generated dictionary is correct, so only the names (and the `isinstance(field_name, StructNode)` branch, which is really about the type) are misleading. `_add_dictionary` and `_create_data_type` don't check the `AddNodesResult` status codes, and `_link_nodes` ignores the `add_references` results. Nothing in the tests exercises this module.

### statemachine.py

- **COM-44 (bug)**: `FiniteStateMachine.install()` always fails with `InstantiationError … i=2771 is abstract`. `FiniteStateMachineType` is `IsAbstract="true"` in the nodeset, and `tests/test_common.py::test_instantiate_abstract` checks exactly that, but the helper instantiates the type directly. Verified: `examples/finitestatemachine-example.py` crashes on start. The helper would need to create (or be given) a concrete subtype, with the states and transitions as its `InstanceDeclaration`s.
- **COM-45 (bug)**: `FiniteStateMachine.set_available_states` *returns* `ValueError(...)` for invalid input instead of raising it. `set_available_transitions` writes a valid list and then falls through to an unconditional `raise ValueError(...)`, so it **always** raises when `optionals=True`. Found by reading the code; it couldn't be run because of COM-44.
- **COM-46 (bug)**: `StateMachine.install(optionals=True)` checks `"TransitionTime" not in childnames`, but `childnames` holds `QualifiedName` objects, so the test is always true. It then always adds a `TransitionTime` property, and it creates it in **namespace 0** (`add_property(0, …)`), the reserved OPC UA namespace. If `TransitionTime` already exists, the second property collides with it.
- **COM-47 (cleanup)**:
  - `add_state`/`add_transition` reject state number `0` (`if not state.number`), and `_write_state` skips writing it.
  - `FromState` is written without a locale while `ToState` uses `self.locale`.
  - The module and class docstrings link to `v104` pages (see COM-6).
  - `Transition`'s docstring says `number` "identifies the current state", copied from `State`.
  - The module lives in `common`, but imports `Server` and only works server-side.

### xmlparser.py

- **COM-48 (bug, interop)**: `IsOptional`, `IsUnion` and the definition-level `IsOptional` are read with `bool(attr)` / `if el.attrib.get(...)`. For an attribute string, `"false"` is truthy, so explicit `IsOptional="false"` / `IsUnion="false"` count as **true**. Verified: importing a two-field structure written with `IsUnion="false"` and `IsOptional="false"` produced `StructureType.Union` with both fields optional. The binary encoding of that type is then wrong for every client.
  - The bundled UA-Nodeset files only ever write `"true"`, so they aren't affected. Nodesets from other modelling tools that write explicit defaults are.
  - `_to_bool` (via `string_to_val`) already handles this for the node attributes. Use it here too.
- **COM-49 (bug)**: in `_parse_value` for `DateTime`, `utc.localize(obj.value)` returns a new object, which is thrown away. So naive timestamps stay naive despite the comment "Forcing to UTC". Empty `<String/>` and `<XmlElement/>` values (`text is None`) go to the `Null` branch before the "support importing null strings" code runs, so they import as `None`, not `""`.
- **COM-50 (cleanup)**:
  - `_parse_body` drops every child whose value is empty (`if val:`), so empty strings and empty nested structures disappear from ExtensionObject bodies.
  - `get_nodeset_namespaces` only accepts `PublicationDate` as `…T…Z` or with a `%z` offset. `xs:dateTime` also allows fractional seconds, which raise `ValueError`.
  - When there are several localized `DisplayName`/`Description` elements, only the last one is kept.
  - `NodeData.symname` has a FIXME saying it's never used.

### xmlimporter.py

- **COM-51 (bug)**: `add_method` ignores the `Executable` attribute that the parser reads into `obj.executable`. Imported methods always get `MethodAttributes`' default `Executable = UserExecutable = True`, so a method marked `Executable="false"` in the nodeset becomes callable. Verified that the default applies to imported methods. `add_method` instead sets `AccessLevel`, `UserAccessLevel`, `MinimumSamplingInterval` and `ArrayDimensions`, which `MethodAttributes` doesn't have; those lines are copied from `add_variable` and can't apply.
- **COM-52 (bug)**: `_check_if_namespace_meta_information_is_added` creates every NamespaceMetadata object with `IsNamespaceSubset = True`, even when the whole nodeset of that namespace has just been imported. Per Part 5 (NamespaceMetadataType), that tells clients the server only has part of the namespace. In `_check_required_models`, the missing-model log line reads `missing_model["Version"]`, which raises `KeyError` when a `RequiredModel` has no `Version`. `PublicationDate` values are compared as **strings** in different formats (our server's `…Z` against the file's value, which may have fractional seconds or an offset). `_parse_version` fails on versions that aren't purely numeric (`1.0.0-rc1`).
- **COM-53 (cleanup)**:
  - Attributes guarded with `if obj.<attr>:` drop legitimate zero or false values. `AccessLevel="0"` imports as `CurrentRead` (the default `1`). `add_variable_type` uses `if obj.value:`, so values `0`, `False` and `""` are lost (`add_variable` correctly uses `is not None`).
  - `_to_nodeid` maps an empty or missing NodeId string to `i=12` (**String**). For a missing `DataType`, the UANodeSet schema default is `i=24` (BaseDataType).
  - `_to_nodeid` also checks the standard `ObjectIds` names *before* the file's own `<Aliases>`, so a nodeset alias that happens to share a standard name is ignored.
  - In `_add_variable_value` for `LocalizedText`, `myargs` (with `Encoding` removed) is built and then not used, and `LocalizedText(**dict(obj.value))` is called with the unfiltered dict.
- **COM-57 (bug, interop)** (verified, spec-checked; added 2026-10-25, after the module review): `xmlparser.py` and the importer ignore the `DesignToolOnly` attribute of `UAObject` and `UAVariable`, which is new in 1.05 (Part 6, F.7; 1.04 has no such attribute).
  - Per F.7, a node with `DesignToolOnly="true"` is only a placeholder for modelling tools. It isn't part of the address space, has no `ParentNodeId`, mustn't be the target of references from other nodes, and its children aren't added.
  - The importer adds it like any other object. The server rejects it with `BadParentNodeIdInvalid`, and `import_xml()` aborts.
  - Verified with the current UA-Nodeset: DI 1.05.0 (2025-11-15) contains 9 such nodes and fails at the first one (`ns=1;i=73`, `Configuration`). Machinery 1.04.2 contains one. So the current DI can't be loaded, and neither can anything built on it (ADI, Machinery, LADS, …). The DI in the `nodeset` submodule (2023) predates the attribute, which is why the tests pass.
  - Fix: read the attribute in `xmlparser.py`, and skip such nodes, and references to them, in the importer.
- **COM-58 (bug, interop)** (verified; added 2026-10-25, after the module review): `add_object` skips the AddNodes status check for DataTypeEncoding objects, which often fail to add, and recognises them only by the DisplayNames `"Default Binary"`, `"Default XML"` and `"Default Json"`.
  - The standard name is `"Default JSON"`. Part 6 v1.04, 5.4.1 names it, and the core 1.05.07 model uses it for all 359 of its JSON encodings. The `"Default Json"` spelling matches no standard nodeset.
  - Verified with LADS 1.0.0, on DI 1.05.0 with COM-57 worked around, AMB 1.01.1 and Machinery 1.03.0. Its `"Default JSON"` encoding object `i=5044` fails with `BadParentNodeIdInvalid`, and the import aborts.
  - With the DisplayName changed to `"Default Json"` the import completes, but the exemption only hides the failure. Six LADS encoding objects are missing from the address space, and the `HasEncoding` references from the LADS DataTypes to them are dropped (logged as "could not be imported and are probably broken"). `import_xml()` still returns the NodeIds of the six missing nodes.
  - The encoding objects of DI (12) and AMB (4) are added correctly, so parent resolution fails only for some files. The cause wasn't traced.
  - Fix: recognise encoding objects by their type definition (`DataTypeEncodingType`, `i=76`) instead of by name, add them through the inverse `HasEncoding` reference of their DataType, and make `import_xml()` raise or report every node it couldn't add instead of returning its NodeId.

### sql_injection.py (and how history_sql.py uses it)

- **COM-54 (security, medium)**: `validate_table_name` is the only guard, and only table names go through it. `server/history_sql.py` puts these into SQL text without escaping:
  - column names (`_get_event_columns`, `_list_to_sql_str`), which are event property **browse names**
  - `event_type` and `event.Time` (`VALUES (NULL, "{event.Time}", "{event_type}", …)`, line 183)
  - A browse name containing `"` (from an imported nodeset or a custom event type) breaks out of the quoted identifier.
  - Names from a *remote client's* event filter are filtered against the known field names first (`_get_select_clauses`), so a client can't inject SQL through HistoryRead. The exposure is through the server's own information model.
  - Fix: bind values with `?` placeholders (including the timestamp and the event type), and escape identifiers by doubling `"` instead of keeping a blacklist. `validate_table_name` also lets `\n`, `-` and `/` through, and has no length limit.
- **Hand-over to the `server` review** (`history_sql.py`): when no requested select clause matches a stored field, the query becomes `SELECT "_Timestamp", FROM …`, which is the `near "FROM": syntax error` seen under COM-27. A clause with an empty `BrowsePath` reads `select_clause.Attribute`, but the field is `AttributeId`, so it always hits the `AttributeError` branch. Custom events weren't stored at all in the COM-27 reproduction.

### xmlexporter.py

- **COM-55 (bug)**: exporting and re-importing loses attributes. Verified by exporting nodes from one server and importing them into another:
  - A reference type with `Symmetric=True, IsAbstract=True` comes back as `Symmetric=False, IsAbstract=False`. `add_etree_reference_type` writes only `InverseName`.
  - An abstract structure DataType comes back concrete. `add_etree_datatype` never writes `IsAbstract`.
  - A variable with `AccessLevel=0` comes back with `AccessLevel=1` (readable). The exporter skips `0` as if it were a default, and the importer's default is `CurrentRead` (COM-53).
  - `StructureWithSubtypedValues` definitions are exported without a marker, so they re-import as plain structures.
  - `WriteMask`/`UserWriteMask` are never exported (FIXME in `_add_node_common`).
- **COM-56 (cleanup)**: `fields_with_resolved_types` permanently changes dataclass metadata during export (COM-3). Structure field `ArrayDimensions` are joined with `", "`, while variable `ArrayDimensions` use `","`. Both parse, but the output is inconsistent.

### Summary: asyncua/common

58 findings (COM-1 … COM-58): 37 bugs (two of them security: COM-39 high, COM-54 medium; plus COM-1 and COM-36 robustness), 5 doc, 15 cleanup and 1 question. COM-57 and COM-58 were added on 2026-10-25, after the module review, while loading companion specifications. Bugs marked "Verified" were reproduced by running code. COM-27 (partly), COM-32, COM-40 and COM-45 are from reading the code.

Highest impact:
1. **COM-39**: `load_type_definitions()` executes code from the server's type dictionary. Remote code execution in the client.
2. **COM-1, COM-36**: a negative length moves the decoder backwards, and a tiny Hello buffer size makes the server silently drop responses.
3. **COM-12**: `Node.write_value()` always sends a SourceTimestamp, and many servers reject that with `Bad_WriteNotSupported`.
4. **COM-18, COM-25**: recursive delete and copy follow `Organizes`, so they delete or duplicate nodes owned elsewhere, and loop on cycles.
5. **COM-22, COM-23**: instantiation creates literal `<Placeholder>` nodes and ignores failed adds.
6. **COM-30**: `modify_monitored_item` silently breaks event subscriptions.
7. **COM-57, COM-58, COM-48, COM-55**: current 1.05 companion nodesets (DI 1.05, LADS) can't be imported at all; XML import treats `"false"` as true; export and re-import loses Symmetric, IsAbstract and AccessLevel.
8. **COM-15, COM-16**: history reads send invalid default ranges, lose pages of events and leak continuation points.
9. **COM-40**: generated types are registered process-wide by namespace *index*, so multiple servers in one process collide.
10. **COM-44**: the `FiniteStateMachine` helper (and its example) can't work, because the type is abstract.

---

## asyncua/client

### ua_client.py

- **CLI-1 (bug)**: a request that times out leaves its future in `UASocketProtocol._callbackmap`:
  - `send_request` wraps the future in `wait_for(...)`, which cancels it on timeout, but nothing removes the map entry. It stays until a late response arrives (which then logs "Future for request id … is already done") or the connection closes.
  - A client hitting many timeouts against a slow server keeps growing the map.
  - A *response* for an id that isn't in the map makes `_call_callback` raise `UaError`, which `_process_received_data` handles by **closing the connection**. Only one unexpected response is enough.
  - Fix: pop the entry on timeout or cancellation, and log responses for unknown ids instead of dropping the connection.
- **CLI-2 (doc)**: `Client.register_server`/`unregister_server` (`client.py:694, 716`) say "if discovery_configuration is provided, the newer register_server2 service call is used". They actually call `RegisterServer2` **and then** `RegisterServer` as well. `unregister_server`'s docstring says "register a server". The low-level `UaClient.unregister_server`/`unregister_server2` are identical copies of the register methods; only the caller's `IsOnline = False` makes them unregister. That's correct, but the docstrings don't say so.

### ua_session.py

- **CLI-3 (bug)** (spec-checked): `_publish_loop` keeps exactly **one** Publish request outstanding for the whole session, and sends it with `timeout=0` (no timeout).
  - Part 4, 5.14.5 allows one-at-a-time "in many cases". But when the latency is higher than the publishing interval, the client *shall* pipeline, sending more than one Publish request per subscription.
  - With several subscriptions, or a fast subscription over a slow link, the server can return at most one NotificationMessage per round trip for **all** subscriptions together. Notifications then queue up on the server and get dropped once its queue limits are reached.
  - With no timeout, a lost Publish response leaves the loop waiting forever. Only the stale-subscription watchdog notices.
  - Fix: keep N requests in flight (e.g. one or two per subscription, with a cap), and give them a timeout based on the keep-alive interval.
- **CLI-4 (bug)**: race between deleting the last subscription and creating a new one. `ensure_publish_loop()` only starts a loop when the old task is done. If the last subscription is deleted and a new one created while the old loop's Publish request is still in flight:
  - The server answers that request with `BadNoSubscription`, and the loop **returns**.
  - The new subscription then has no publish loop and never receives data.
  - Found by reading the code; not reproduced.
- **CLI-5 (bug)**: acknowledgements get lost in two places:
  - `_publish_loop` drops `pending_acks` whenever a Publish fails (timeout, parse error, any exception).
  - Messages fetched with `republish()` (`Subscription._republish_gaps`) are never acknowledged.
  - Unacknowledged messages stay in the server's retransmission queue until it overflows, and reconnect logic later sees `AvailableSequenceNumbers` it already processed.
  - Acks should be kept until a Publish request carrying them has been sent successfully.

### client.py

- **CLI-6 (bug, security)** (spec-checked): `create_session()` doesn't check the `ServerNonce` length. Part 4 (CreateSession) requires 32–128 bytes and says "the Client shall check the length". The nonce is the challenge the client signs to prove possession of its certificate, and that the password and user-certificate tokens are bound to. `open_secure_channel()` doesn't check the OpenSecureChannel `ServerNonce` length either, which Part 4 requires to equal the policy's `SecureChannelNonceLength`. A server or man-in-the-middle could send an empty nonce, and the channel keys and signatures would then be derived from client-side randomness only.
- **CLI-7 (bug, security)** (spec-checked): no protection against endpoint downgrade.
  - Part 4 (CreateSession, `serverEndpoints`): if the client picked its security settings from a discovery endpoint, it "shall verify" the endpoint list returned by CreateSession against that list.
  - `set_security()` calls GetEndpoints over an unsecured channel, takes the server certificate from the matching endpoint and discards the list. `create_session()` only looks up its own endpoint in `ServerEndpoints`.
  - A man-in-the-middle on the discovery connection can therefore hide the stronger endpoints or substitute a server certificate, and the client won't notice.
  - Fix: keep the discovery result and compare it with `ServerEndpoints` (security modes, policies and certificates).
- **CLI-8 (bug)**: `_renew_channel_loop` calculates its sleep interval (`secure_channel_timeout * 0.75`) once, before the loop starts. When a renewal returns a different `RevisedLifetime`, `open_secure_channel` updates `secure_channel_timeout`, but the loop keeps the old interval. A shorter revised lifetime lets the token expire before the next renewal. A `RevisedLifetime` of `0` (see COM-37) would make the loop renew without pause. Recompute the interval every time round the loop, with a minimum.
- **CLI-9 (bug)**: `register_nodes`, `unregister_nodes` and `browse_nodes` take `nodes: Iterable[Node]` but iterate it twice: once to build the request, then again to zip with the results. With a generator, the second pass is empty. Verified: `browse_nodes(<generator>)` returns 0 results, and `register_nodes(<generator>)` returns `[]` after registering the nodes on the server without updating the `Node` objects. Fix: `nodes = list(nodes)` first.
- **CLI-10 (bug)** (spec-checked): `create_subscription(period)` always requests `RequestedLifetimeCount = 10000` and a keep-alive count of `session_timeout / period * 0.75`. Part 4 (CreateSubscription) requires the lifetime count to be at least three times the keep-alive count. Verified: with the session timeout used in the test, intervals of 100 ms and 50 ms request keep-alive counts of 4500 and 9000, both above 10000/3. Conforming servers revise these values, and the revised values aren't stored (COM-32).
  - For ordinary intervals the keep-alive is very long: with the default one-hour session, a 1 s subscription only sends a keep-alive every 45 minutes. A dead subscription (`is_stale`) or a broken publish loop is then noticed after more than an hour.
  - The docstring cites "Part4 5.13.2", which is the 1.04 numbering (COM-6).
- **CLI-11 (cleanup)**:
  - `_refresh_endpoints_quiet()` is called on security errors during reconnect ("refreshing endpoints"), but throws the GetEndpoints result away, and runs with the current security policy, so it most likely fails the same way. After a server certificate change, auto-reconnect keeps failing forever, which is safer than silently trusting a new certificate. Either remove the call or make re-fetching the certificate an explicit, validated step.
  - `register_namespace()` writes the whole `NamespaceArray` back (read, modify, write), which most servers don't allow and which races with other clients.

### ua_file_transfer.py and ua_file.py

- **CLI-12 (bug)** (spec-checked): `UaFile.read()`, in both modules, reads the whole file with a **single** `Read(handle, length=Size)` call. File Transfer is Part 20 in 1.05 (Part 5, Annex C in 1.04). Per Part 20, 4.2.4:
  - The server "is allowed to return less data than specified length", and an empty result means end of file. So on servers that cap the length (e.g. at `MaxByteStringLength` or by message size), large files come back **truncated without any error**.
  - `length` must be positive, so reading an empty file (`Size = 0`) fails with `Bad_InvalidArgument`.
  - `Size` is a `UInt64`, but it's passed as an `Int32`, so files over 2 GiB fail to encode.
  - The read should loop in chunks until an empty `ByteString` comes back. `read()` also ignores the current file position (it always asks for `Size` bytes).
- **CLI-13 (cleanup)**: `asyncua/client/ua_file.py` is an older, smaller copy of `ua_file_transfer.UaFile` with the same bugs. It also passes `open_mode` as a string (`"r"`/`"w"`) while the newer one uses `OpenFileMode`. Pick one and deprecate the other. `ua_file_transfer.UaFile.open()` logs the `OpenFileMode` *class* instead of the mode it uses. The module docstring cites "OPC 10000-5 V1.04 … Annex C"; in 1.05 that's OPC 10000-20.

### ha/ha_client.py, ha/reconciliator.py

- **CLI-14 (bug, security)**: like CLI-7, but on every reconnect. When `HaSecurityConfig.server_certificate` isn't set, each `HaClient.reconnect()` calls `client.set_security(**config)`, and `set_security()` re-fetches the server certificate from an unsecured GetEndpoints call. An HA pair configured "with security" therefore trusts whatever certificate is presented each time it fails over or reconnects. The docstring and docs don't say that `server_certificate` is required for real protection.
- **CLI-15 (bug)**: in `KeepAlive.run()`:
  - It catches `asyncio.CancelledError` and only sets the status (there's a FIXME saying this is wrong), so cancelling the task doesn't stop it. Only `stop_event` does.
  - After connecting, the loop waits a fixed `asyncio.sleep(3)` "for HaManager to connect clients".
  - `HaManager` only ever selects a server with `ServiceLevel >= 200` (Healthy). If all servers are *Degraded* (2–199, which per Part 4, 6.6.2.4.2 means partly operational), no client is active at all and the application gets no data. That's spec-checked as far as the ServiceLevel ranges go; whether falling back to the best degraded server is wanted is a design question.
- **CLI-16 (cleanup)**:
  - Only `HaMode.WARM` is implemented (`COLD`, `HOT_A` and `HOT_B` raise `NotImplementedError`), but the class docstring and the enum read as if all four modes are supported.
  - `delete_subscriptions` for an unknown name logs a warning and then raises `KeyError` from `self.sub_names.remove()`.
  - `generate_sub_name` loops forever without yielding once all 9999 names are taken.
  - `HaSecurityConfig`/`set_security` accept a security `mode` but no user credentials, so HA clients can only use anonymous or URL-embedded logins.
  - The `HaMode` comments cite Part 4, 6.6.2.4.5.x; those numbers are correct in both 1.04 and 1.05.

### docs/usage/client/overview.rst

- **CLI-17 (doc)**: the page only says to create a `Client`, plus three `.. todo::` placeholders ("Show different examples, with / without security", namespaces, browsing). The URL example uses backslashes, `opc.tcp:\\<server>:4840`; it should be `opc.tcp://<server>:4840`. Nothing in `docs/` covers auto-reconnect, subscriptions in iterator mode, session persistence or the HA client, though each has substantial API surface.

### Summary: asyncua/client

17 findings (CLI-1 … CLI-17): 12 bugs (three of them with security impact: CLI-6, CLI-7 and CLI-14), 2 doc and 3 cleanup. Bugs marked "Verified" were reproduced by running code. CLI-4 is from reading the code, and CLI-6, CLI-7 and CLI-14 were checked against the code paths and the spec text but not exercised against a hostile server. Highest impact:
1. **CLI-6, CLI-7, CLI-14**: missing client-side checks the spec requires: nonce lengths, and comparing the CreateSession endpoints with the discovery result. Server certificates fetched over unsecured connections are trusted on first use, and with HA on every reconnect.
2. **CLI-3, CLI-4, CLI-5**: the publish loop has only one outstanding request, can die in a delete/create race, and loses acknowledgements.
3. **CLI-12**: file reads are truncated silently on servers that return short reads, and empty files fail.
4. **CLI-1**: timed-out requests leak, and one unexpected response id closes the connection.
5. **CLI-9, CLI-10**: generator arguments silently return nothing, and the subscription lifetime and keep-alive counts break the 3× rule for fast intervals.

## asyncua/server

The scripts used for the "Verified" findings below started a real `Server` on localhost and talked to it with `Client`, raw `UaClient` calls or a raw socket. Release information comes from `git tag --contains` on the full upstream history.

### uaprocessor.py, internal_session.py, internal_server.py (sessions and authentication)

- **SRV-1 (bug, security, critical)** (verified, spec-checked) — **fixed in `7c63c2ec`** (branch `fix/session-activation-checks`, for upstream): **session hijack through ActivateSession on a new channel.** The reconnect path added in `aec7430b` (2026-05-13; in every tag from `v1.0` to `v2.1.0`) works like this:
  - When a channel without a session receives ActivateSession, `_process_message` looks up the session by `RequestHeader.AuthenticationToken`. It then **assigns `self.session = existing` and rebinds all of that session's subscriptions** to the new channel (`uaprocessor.py:278-289`). The client signature and identity token are checked only after that.
  - If the checks fail, the exception is turned into a ServiceFault, but `self.session` stays assigned. That session is still `Activated` with the victim's user and role, so every later request on the attacker's channel runs as the victim.
  - None of the checks that Part 4, 5.7.3 requires for moving a session to a new channel are made (1.04: 5.6.3). The client certificate must match the original channel's, the user identity must be the same, and SecurityPolicy and SecurityMode must be the same. Anonymous over Sign must fail, and requests on the old channel must be rejected afterwards.
  - The token is the only secret, and it is a small sequential integer (SRV-2).
  - Verified, default server: an attacker channel guesses tokens 1000–1009. ActivateSession fails for every one of them, yet afterwards the attacker reads values and adds nodes as the victim's `Admin` user. The victim's subscription receives nothing more, because its publish callbacks now point at the attacker's channel.
  - Verified, hardened server (`Basic256Sha256_SignAndEncrypt` only, `CertificateUserManager` with one admin certificate, a validator that rejects every other certificate, as in `examples/server-with-encryption.py`): the attacker opens a channel with an **untrusted** certificate (SRV-3), guesses token 1001, gets `BadInternalError` back from ActivateSession, and still writes the setpoint.
  - Fix: run every check before touching `self.session` or the subscriptions, and only bind once all of them pass. Add the 5.7.3 checks (same channel for the first activation; same certificate, policy, mode and user for a move), detach the session from the old channel, and use random tokens (SRV-2).
- **SRV-2 (bug, security)** (spec-checked) — **partly fixed in `7c63c2ec`**: tokens are now random 32-byte ByteStrings, and every request's token is checked. Still open: a second CreateSession on the same channel, and the shared class counters.
  - `InternalSession.auth_token` and `session_id` are class-level counters (`1000, 1001, …` and `10, 11, …`). Part 4, 7.35 (1.04: 7.31) calls the `SessionAuthenticationToken` the secret form of the session id. When the server can't tie it to the channel, it must be a random ByteString of at least 32 bytes. This server does tie sessions to channels, but by object identity in `UaProcessor`, not by checking the token.
  - The `AuthenticationToken` of ordinary requests is never compared with `self.session.auth_token`.
  - A second CreateSession on the same channel replaces `self.session`. The first session is left behind with its watchdog task still running, until its own timeout closes it.
  - `_current_connections`, `_counter` and `_auth_counter` are class attributes, so two `Server` instances in one process share them.
- **SRV-3 (bug, security)** (verified, spec-checked) — **fixed in `7c63c2ec`** (CreateSession now requires the channel certificate). Still open: validating at OpenSecureChannel. **The certificate validator can be bypassed.** `set_certificate_validator()` is the only application-level trust check, and it only runs in `InternalSession.create_session`, on `params.ClientCertificate`:
  - When `ClientCertificate` is empty, the check is skipped (`if self.iserver.certificate_validator and params.ClientCertificate`). Verified: with a validator that rejects everything, the normal connect fails with `BadCertificateUntrusted`. A client that leaves `ClientCertificate` out of CreateSession connects over `Basic256Sha256_SignAndEncrypt` and reads `ServerState`.
  - The certificate passed to the validator is never compared with the certificate that opened the channel. Part 4, 5.7.2 says the server shall verify that they are the same. A client can present someone else's trusted certificate in CreateSession, then sign ActivateSession with its own channel key.
  - OpenSecureChannel doesn't consult the validator at all. So GetEndpoints, FindServers, RegisterServer (SRV-5) and the SRV-1 path all work on channels opened with untrusted certificates.
  - Introduced with the validator hook in `0cd54642` (2023-08-25). First released in `v1.0.5a1`, and present in every release since.
  - Fix: validate the peer certificate when the channel is opened, and require `ClientCertificate` to equal the channel certificate whenever the mode isn't None.
- **SRV-4 (bug, security)** (verified): **subscriptions are shared across sessions.**
  - `SubscriptionService` keeps one dict for the whole server. Delete/ModifySubscription, SetPublishingMode, Create/Modify/Delete/SetMonitoringMode on monitored items, Publish acknowledgements, Republish and TransferSubscriptions look up any subscription id without checking `sub.session_id`.
  - Subscription ids are sequential, starting at 78. Verified: session B deleted session A's subscription and got `Good`.
  - `TransferSubscriptions` also lacks the Part 4, 5.14.7 checks: the user identity must match the owner's, or the user needs the transfer right. It updates `pub_result_callback` but **not** `pub_request_callback`, so a transferred subscription keeps taking Publish requests from the old channel. It sends no `Good_SubscriptionTransferred` status change to the old session, and ignores `SendInitialValues`.
  - Publish raises `BadNoSubscription` only when the *server* has no subscriptions at all, and `publish_request_limit` is based on the count across all sessions.
- **SRV-5 (bug, security)** (verified, spec-checked): RegisterServer and RegisterServer2 are accepted from any client, with no session, on any channel, including SecurityPolicy None. Every `Server` acts as a discovery server.
  - Part 4, 5.5.5 (1.04: 5.4.5) requires the registration to come over a SecureChannel, and its `serverUri` to match the `applicationUri` in the certificate of that channel.
  - Verified: an anonymous client registered `urn:evil` with `opc.tcp://evil:4840`, and `FindServers` then returned it to everyone.
  - Fix: either drop discovery-server behaviour unless it's enabled explicitly, or enforce the spec rule.
- **SRV-6 (bug, security)** (spec-checked): user identity tokens are under-checked (`internal_server.decrypt_user_token`, `verify_x509_token`):
  - The encrypted password secret ends with the server nonce (Part 4, 7.40.2.2; 1.04: 7.36.2.2, "Legacy Encrypted Token Secret Format"). The code strips `len(nonce)` bytes **without comparing them** with the session's current nonce. So an encrypted token captured in one session can be replayed in any later session.
  - A password that arrives unencrypted is accepted even when the endpoint's `UserTokenPolicy` requires encryption, including over SecurityPolicy None.
  - `PolicyId` is never matched against the policies the endpoint offers.
  - The `EncryptionAlgorithm` and signature algorithm aren't checked against the policy (both are `TODO`s). Plain SHA-1 RSA signatures are accepted.
  - The certificate in an `X509IdentityToken` isn't passed to the certificate validator. Proof of possession is the only check, and after that the user manager decides.
- **SRV-7 (bug, security default)** (verified): the default `PermissiveUserManager` gives `Admin` to the username `admin`/`Admin` with **any** password, and `User` to everything else. `Admin` bypasses `AccessLevel` and `WriteMask` (SRV-16), and is the only role allowed to AddNodes, DeleteNodes or change references.
  - Verified: `set_user("admin"); set_password("wrong-password")` wrote a read-only variable and its `BrowseName`.
  - Together with the defaults (NoSecurity endpoint on, no certificate validator), a server started from the examples accepts unauthenticated administrators. This belongs to the security-defaults work; it's listed here so it isn't lost.
- **SRV-8 (bug)**:
  - Other requests that arrive before a session exists get `BadUserAccessDenied`. They should get `BadSessionIdInvalid`. The separate `except BadUserAccessDenied` branch in `process_message` is unreachable, because the `except UaStatusCodeError` above it catches it first. Publish has a dead `if not self.session: return False`.
  - `_session_watchdog_loop` reads the session timeout once at start. On expiry it closes the session but leaves the TCP connection open.
  - Hello handling (the open question from the 1.04/1.05 list at the top): the server never looks at the client's `ProtocolVersion` and always answers `0`. That's fine for both editions while `0` is the only version. It doesn't enforce the 4096-byte `EndpointUrl` limit, or the 8192-byte minimum buffer sizes (Part 6, 7.1.2.3).

### binary_server_asyncio.py, server.py

- **SRV-9 (bug, DoS)** (verified): `OPCUAProtocol.data_received` buffers until the length from the header has arrived, without comparing that length with `max_recv_buffer` or `max_message_size`. It also re-copies the whole buffer (`self._buffer += data`, then `Buffer(self._buffer)`) for every TCP segment.
  - Verified: one connection that sent `HELF` with a length of 2 GiB, then 64 MiB of zeros, was still open, holding 61 MiB in `_buffer`. Sending took 9.8 s because of the quadratic copying.
  - This is before Hello, so it needs no credentials, and each of the 1000 allowed connections can do it.
  - Fix: reject a chunk whose header length is larger than the receive buffer size (`Bad_TcpMessageTooLarge`, Part 6, 7.1.5) or, before Hello, larger than 8192. Use a `bytearray` or a list of segments instead of concatenating `bytes`.
- **SRV-10 (bug)** (verified):
  - `Server.start()` calls `_setup_server_nodes()`, which *appends* endpoints and policy factories. After `stop()` and `start()`, `GetEndpoints` returns every endpoint twice (verified: 1, then 2).
  - `register_to_discovery()` starts a new renewal task on every call, but keeps only the last handle, so the earlier tasks keep running and `stop()` doesn't cancel them. `_renew_registration` drops the `discovery_configuration` (there's a `FIXME`).
  - `Server.default_timeout` ("timeout in milliseconds for sessions and secure channel") isn't used anywhere.

### subscription_service.py, internal_subscription.py

- **SRV-11 (bug)** (verified, spec-checked): **the publishing interval is never revised.** Part 4, 5.14.2 says that for a requested value of 0 or less, the server shall use its fastest supported interval. Verified: requests for `0` and `-5` come back unchanged.
  - With an interval ≤ 0, `start()` doesn't create the publishing loop. Each change then publishes at once with no rate limit, keep-alives are never sent, and the lifetime counter never runs, so the subscription never expires. Huge intervals aren't capped either.
  - `ModifySubscription` ignores every requested value (there's a comment saying so) and returns the old ones.
  - `MaxNotificationsPerPublish` is ignored, and `MoreNotifications` is always `False`, so one publish can exceed the negotiated message size.
  - The lifetime counter only starts counting once the keep-alive count has been reached.
  - The `Bad_Timeout` status change for an expired subscription is never sent (there's a `FIXME`).
  - `_notification_seq` doesn't roll over to 1 after 2³²−1 (Part 4, 5.14.1.1). A subscription with a 1 ms interval that has data every cycle would fail to encode after about 50 days.
- **SRV-12 (bug)** (spec-checked):
  - `republish()` *pops* the message from `_not_acknowledged_results`, so a Republish acts like an acknowledgement, and a second Republish of the same number finds nothing.
  - For an unknown sequence number or subscription, it returns an empty `NotificationMessage` with `Good`. It should return `Bad_MessageNotAvailable` or `Bad_SubscriptionIdInvalid` (Part 4, 5.14.6).
  - Part 4, 6.7 tells a reconnecting client to call Republish in a loop until it gets `Bad_MessageNotAvailable`, so a spec-following client either never ends that loop or gets empty messages.
  - Found by reading the code, not run.

### monitored_item_service.py

- **SRV-13 (bug)** (verified, spec-checked): queue handling.
  - A requested `QueueSize` of 0 or 1 is revised to the server maximum (10 000) instead of 1. Part 4, 7.21 says 0 or 1 means a queue of 1 for data items. Verified: requesting 0 returns 10 000. asyncua's own client requests 0 by default, so every data change item queues up to 10 000 values instead of the latest one.
  - `ModifyMonitoredItems` with an unknown id raises `TypeError: 'StatusCode' object is not callable` (`result.StatusCode(...)` at line 106). The **whole request** then fails with `BadInternalError` (verified).
  - A valid Modify copies the requested `QueueSize` without capping it. `0` there means *unlimited* to `_enqueue_event` (`size != 0`), so any client can make one item's queue grow without bound.
  - The sampling interval is never revised.
  - `DiscardOldest` is ignored (the oldest value is always dropped), and the `Overflow` InfoBit is never set.
  - `MonitoringMode.Sampling` is treated like `Reporting` (Part 4, 5.13.1.3).
- **SRV-14 (bug)** (verified): filters.
  - An event monitored item without an `EventFilter` raises `AttributeError` (`mdata.filter.WhereClause`), and the whole CreateMonitoredItems request fails with `BadInternalError` (verified). It should fail just that item, with `Bad_MonitoredItemFilterInvalid`.
  - No `EventFilterResult` is returned.
  - An event item on a node that doesn't exist fails with `BadServiceUnsupported` instead of `BadNodeIdUnknown`.
  - The absolute deadband compares each value with the previously *sampled* value, not the last *reported* one (Part 4, 7.22.2). A value that drifts slowly by less than the deadband per sample is therefore never reported.
  - A deadband on a non-numeric or array value raises `TypeError` inside the write path.
  - `Percent` deadband is accepted, logs "not implemented" and reports everything.
  - In the `WhereClauseEvaluator`, `OfType` ignores subtypes, `Like` raises `NotImplementedError` (the event is dropped), and `Cast` is treated as `True`.

### address_space.py (Read, Write, Browse, Call, NodeManagement)

- **SRV-15 (bug)** (verified, spec-checked): **`IndexRange` is ignored**, for Read, Write and HistoryRead (Part 4, 7.27).
  - Verified: reading `[1, 2, 3, 4]` with `IndexRange="1:2"` returns all four values.
  - Writing `[9.0]` with `IndexRange="1"` returns `Good` and replaces the **whole array** with `[9.0]`. A client that updates one element of an array destroys the rest of it.
  - Read also ignores `TimestampsToReturn` and `DataEncoding`.
- **SRV-16 (bug)** (verified):
  - Write access checks: `Admin` skips the `AccessLevel` and `WriteMask` checks entirely. Verified: it changed `BrowseName` and wrote a read-only value.
  - For other users, a missing `CurrentWrite` in `AccessLevel` returns `BadUserAccessDenied`; it should be `BadNotWritable`. Read checks neither `AccessLevel` nor `UserAccessLevel` (`BadNotReadable`).
  - `_is_expected_variant_type` only compares `VariantType`. A scalar is accepted for an array variable, because `ValueRank` and `ArrayDimensions` aren't checked (hand-over from the client review).
  - A value of a valid subtype is refused when the stored value has a different concrete type.
  - For DataTypes with id > 25, whichever type is written first is accepted.
  - `set_attribute_value_setter` says the setter can "return appropriate status codes to the client". In fact its return value is ignored, Write answers `Good`, and data change subscribers are still notified with the value the setter rejected.
- **SRV-17 (bug)** (verified): Browse and TranslateBrowsePaths.
  - A node that doesn't exist gives `BadNodeIdInvalid` instead of `BadNodeIdUnknown` (`_browse`, `_translate_browsepath_to_nodeid`, and `MethodService._call`). This was seen from the client side under COM-14.
  - `RequestedMaxReferencesPerNode` is ignored and no continuation points are made, so `BrowseNext` doesn't exist (`BadServiceUnsupported`). `ResultMask` and `View` are ignored.
  - An invalid `BrowseDirection` returns an empty `Good` result.
  - An empty `RelativePath` raises `IndexError` (`Elements[-1]`), and the whole request fails with `BadInternalError` (verified). It should fail just that path, with `Bad_NothingToDo`.
- **SRV-18 (bug, security)** (verified, spec-checked): Call.
  - There's no check that `MethodId` is a method of `ObjectId` (`Bad_MethodInvalid`, Part 4, 5.12.2). Verified: a method on a custom object ran with the `Server` object passed in as its parent.
  - No `Executable`/`UserExecutable` or role check, so an anonymous client can call any method that has a callback.
  - Input arguments aren't checked against the method's `InputArguments`. Verified: two extra arguments led to a Python `TypeError`, reported as `BadUnexpectedError`. It should be `Bad_TooManyArguments`, `Bad_ArgumentsMissing` or `Bad_TypeMismatch` for each argument.
  - Synchronous callbacks run in a `ThreadPoolExecutor`, which contradicts the docstring (SRV-24).
- **SRV-19 (cleanup)**:
  - `BrowseNext`, `HistoryUpdate`, `SetTriggering`, `Cancel` and `QueryFirst`/`QueryNext` have no handler and return `BadServiceUnsupported`. `HistoryManager.update_history` and `InternalSession.history_update`/`browse_next` exist but are never reached.
  - AddNodes doesn't validate `NodeClass` against the attributes, or the `ReferenceTypeId`, and accepts new nodes in namespace 0.
  - `translate_browsepaths_to_nodeids` has three `FIXME`s, including the magic `4294967295` for `RemainingPathIndex`.

### history.py, history_sql.py

- **SRV-20 (bug)** (verified, spec-checked): `HistoryDict` read semantics (Part 11, 6.5.3.2; Part 4, 5.11.3).
  - With no start time and an end time given, the end time is ignored. Verified: values 0–9, end = t4 returns `[9, 8, 7]`, which are all *after* the end.
  - `NumValuesPerNode` cuts the result off **without** a continuation point (verified: `[0, 1]`, cont `None`). The spec requires a continuation point when there's more data.
  - The continuation point is the timestamp of the next value. When more values than one page share a timestamp, the client gets the same page forever (verified: four identical pages `[0, 1, 2]`).
  - In `HistorySQLite._get_bounds`, the second page of a backwards read (no start time) is read *forwards*, because the continuation timestamp is now the start.
  - A value without `SourceTimestamp` raises `TypeError` when it's saved (in a background task) and again on every read of that node (verified). The `# type: ignore[operator]` comments hide this.
  - `HistoryRead` doesn't check the `HistoryRead` access bits, whether the node exists, or whether it's historized. Those cases return an empty `Good` result instead of `BadNodeIdUnknown` or `Bad_HistoryOperationUnsupported`.
  - `ReadProcessedDetails`/`ReadAtTimeDetails` return `BadNotImplemented` instead of `Bad_HistoryOperationUnsupported`. `TimestampsToReturn` is ignored.
- **SRV-21 (bug)** (verified): event history in memory works only for the `Server` object.
  - Events that come back through the internal subscription have `emitting_node == Server`. `HistoryDict.save_event` then raises `KeyError` on `_events_periods` for every other source, inside fire-and-forget tasks. Verified with an object `Boiler`: every save raised `KeyError: i=2253`, and `read_event_history` returned `[]`. The tests use the `Server` object as the source, which hides this.
  - When `historize_node_event()` runs before an `EventGenerator` has added `GeneratesEvent` references, it subscribes to no event types and stores nothing.
  - `SubHandler` keeps a reference to only the last task it created, so earlier save tasks can be garbage-collected before they finish, and saves can complete out of order.
  - `save_event` contains a duplicated line.
- **SRV-22 (bug)** (verified): `HistorySQLite`.
  - `_get_table_name` uses `repr(identifier)`, so string NodeIds become `2_'Boiler.Temp'` and GUIDs `2_UUID('…')`. `validate_table_name` rejects the quote and the parenthesis. Verified: `new_historized_node` raises `SqlInjectionError` for any string or GUID NodeId, so the SQLite backend only works with numeric NodeIds. Broken since the validation was added in `22b6a757` (2023-01-22).
  - The event table columns are created from the properties' **DisplayNames**, but rows are inserted using the event object's attribute names, which are **BrowseNames**. A custom property whose display name differs from its browse name, or contains a space, breaks either CREATE TABLE or every INSERT. That's the "custom events weren't stored" symptom from COM-27.
  - Events are stored under `event.SourceNode`, read under the source id, and their retention period is looked up by `emitting_node`.
  - Old events are deleted `WHERE Time < ?`, but `Time` is a BLOB column and the parameter is text, so nothing is ever deleted. The `count` limit is ignored for events.
  - The hand-over items from the common review are confirmed. With no matching select clause the query is `SELECT "_Timestamp", FROM`, and `select_clause.Attribute` should be `AttributeId`.
  - With `NumValuesPerNode = 0`, all rows are loaded into memory before being cut down to `max_history_data_response_size`, and HistoryRead has no access check (SRV-20). Use `LIMIT max + 1`.
  - Values are ordered by `_Id`, not by `SourceTimestamp`, and rows with a NULL `SourceTimestamp` are never returned.
  - The code relies on the `sqlite3` default datetime adapters, which are deprecated since Python 3.12.
  - For the identifier injection, see COM-54.

### event_generator.py

- **SRV-23 (bug)** (verified):
  - `init()` *overwrites* the emitting node's `EventNotifier` with `{SubscribeToEvents}`. Verified: creating a generator after `historize_node_event()` clears the `HistoryRead` bit.
  - `DaylightSavingInOffset = tm_isdst != -1` is `True` whenever DST information is known, including in winter. Verified: `tm_isdst = 0` (Europe/Berlin in winter) still gives `True`. It should be `tm_isdst > 0`.
  - Without `message`, the default message is meant to be the source's browse name, but `ua.LocalizedText(name).Text` assigns a plain `str`. Verified: the client receives `LocalizedText(Text=None)`.
  - Events aren't passed up the notifier hierarchy. Clients usually subscribe to the `Server` object for all events (Part 3, `HasNotifier`/`HasEventSource`), and here that subscription gets only events emitted *by* the `Server` object. Verified: an event from `Boiler` reached the `Boiler` item but not the `Server` item.

### Docs: docs/usage/server/overview.rst, docstrings

- **SRV-24 (doc)**:
  - `docs/usage/server/overview.rst` contains only its title.
  - The `Server` class docstring says "All methods are threadsafe". They aren't. The address space and the services have no locking, and synchronous method callbacks run in a thread pool (SRV-18).
  - `set_security_policy` shows a default list of three policies, but the default enables seven, including `NoSecurity`.
  - The `set_attribute_value_setter` docstring is covered under SRV-16.
  - The comment on `max_lifetime_count` says "PublishingInterval is left to the client", which is the gap in SRV-11.
  - `InternalSession.browse_next` cites the 1.04 section numbers.

### Summary: asyncua/server

24 findings (SRV-1 … SRV-24): 22 bugs, 1 doc and 1 cleanup. Seven of the bugs have security impact (SRV-1 to SRV-6 and SRV-18), and SRV-7, the permissive default user manager, is a security default. Highest impact:
1. **SRV-1**: anyone who can open a channel can take over another client's activated session, including its user role and subscriptions. The token is a small sequential number, and the attacker's own failed ActivateSession is enough. This works against the hardened example configuration. It is a regression from May 2026, in releases `v1.0`–`v2.1.0`. It should be fixed and reported the same way as COM-39, but more urgently, because it needs no prior access.
2. **SRV-3**: the certificate validator only runs in CreateSession, and is skipped when the client leaves out its certificate. It has been bypassable since it was introduced in 1.0.5 (2023).
3. **SRV-4, SRV-5, SRV-6, SRV-18**: no per-session ownership of subscriptions, unauthenticated RegisterServer, replayable password tokens, and method calls without object, argument or permission checks.
4. **SRV-9**: an unauthenticated client can make the server buffer gigabytes, at quadratic cost.
5. **SRV-15**: a Write with `IndexRange` silently replaces the whole array.
6. **SRV-11, SRV-13**: the publishing interval isn't revised, and queue sizes 0/1 become 10 000, which changes the data clients get by default. A Modify can make a queue unbounded.
7. **SRV-20, SRV-21, SRV-22**: in-memory event history only works for the `Server` object, the SQLite backend rejects string and GUID NodeIds, and history paging can loop forever.

## asyncua/crypto

The certificate-validation rules referred to below are in Part 4, 6.1.3 (the table of checks for "Determining if a Certificate is trusted"). The certificate profile is in Part 6, 6.2.2, and the per-policy key limits are in Part 6, 6.1 (the policy tables are in Part 7).

### validator.py

- **CRY-1 (bug, security)** (verified, spec-checked): **`CertificateValidator` doesn't check trust unless asked to, and passes everything when asked without a store.**
  - The default options are `BASIC_VALIDATION | PEER_CLIENT`, and `BASIC_VALIDATION` is just `TIME_RANGE | URI`. Neither the certificate signature nor trust is checked. Verified: `CertificateValidator()` accepted a freshly generated self-signed certificate whose only matching property was the URI. The class docstring says it is "a basic certificate validator including trusted store".
  - `TRUSTED` and `REVOKED` only run `if self._trust_store`. With `TRUSTED_VALIDATION` but no `trust_store`, every certificate is accepted. Verified.
  - The `else` branch of `examples/server-with-encryption.py` and `client-with-encryption.py` uses `EXT_VALIDATION` without a store, so it accepts any certificate with the right URI and key usage.
  - Part 4, 6.1.3 says a certificate with an invalid signature shall always be rejected (a self-signed one is its own issuer), and an untrusted one shall get `Bad_CertificateUntrusted`. Fix: make the trust check the default, and raise a configuration error when `TRUSTED` or `REVOKED` is set without a store.
- **CRY-2 (bug)** (spec-checked):
  - On the server, the detailed status codes (`Bad_CertificateUntrusted`, `…UriInvalid`, `…TimeInvalid`, …) are sent back to the client. Part 4, 6.1.3 says the server shall report `Bad_SecurityChecksFailed` and log the detail.
  - The host name check is commented out. A client using the validator never checks that the server certificate names the host it connected to (`Bad_CertificateHostNameInvalid`).
  - A missing extension gives `BadCertificateInvalid` even for checks that weren't requested. With `URI` set and no `app_description`, it raises `AttributeError`.
  - Revocation is checked only for the leaf certificate, not for the CAs in the chain.
  - The docstring lists "ApplicationDescription" as an exception for revoked certificates; it should say `BadCertificateRevoked`.

### truststore.py

- **CRY-3 (bug, security)** (spec-checked, from reading the code; not run):
  - `is_revoked()` compares serial numbers only, ignoring the issuer. A CRL from any CA revokes every certificate with the same serial from any other CA.
  - CRL signatures aren't verified against the issuing CA.
  - A CA without a CRL isn't reported (`Bad_CertificateRevocationUnknown`). Part 4, 6.1.3 requires the revocation check as in RFC 5280, 6.3.
  - `is_trusted()` calls `verifier.verify(cert, [])` with no intermediates, and `x509_from_der` drops the rest of a chain the peer sent. A chain whose intermediate CA isn't itself in the trust directory can't be validated.
  - The trust anchor policy requires `cA = TRUE`. Part 6, 6.2.2 (1.05) says application instance certificates, self-signed ones included, shall have `cA = FALSE`. So a spec-conforming self-signed peer certificate placed in the trust directory most likely can't be trusted. This needs a test.
- **CRY-4 (cleanup)**:
  - The file filter `re.match(".*(der|pem)", name)` matches any name containing "der" or "pem", such as `header.txt` or `notes-pem.md`. One unreadable file aborts the whole `load()`.
  - An untrusted certificate is logged with `_logger.exception`, a full traceback for every rejected peer.
  - The logger is named `asyncuagds.validate`, a leftover from another project.

### security_policies.py

- **CRY-5 (bug, security)** (verified, spec-checked): **the policies' key limits and certificate signature algorithms are never enforced.**
  - Each policy's docstring lists `MinAsymmetricKeyLength`/`MaxAsymmetricKeyLength` (2048–4096 for the SHA-256 policies) and the required `CertificateSignatureAlgorithm`. No code checks either.
  - Verified: a client with a **1024-bit** RSA certificate connected to a `Basic256Sha256_SignAndEncrypt`-only server and read `ServerState`.
  - By reading the code, SHA-1-signed certificates are accepted under the SHA-256 policies in the same way.
  - Part 4, 6.1.3 ("Security Policy Check") and Part 6 (the limits apply to every certificate in the chain) require rejecting both, with `Bad_CertificatePolicyCheckFailed`, reported as `Bad_SecurityChecksFailed` on the server.
- **CRY-6 (bug, security, low)**: `VerifierHMac256.verify` and `VerifierAesCbc.verify` compare the MAC with `!=`, which isn't constant-time. Use `hmac.compare_digest`.
- **CRY-7 (bug)**:
  - Asymmetric signature failures raise `cryptography.exceptions.InvalidSignature`. `uacrypto` defines its own `InvalidSignature` with the same name, and that is the one `connection.py` catches. So a bad ActivateSession, CreateSession or user-token signature ends up as `BadInternalError` instead of `Bad_ApplicationSignatureInvalid`/`Bad_IdentityTokenInvalid`. SRV-1's reproduction got `BadInternalError` for a missing signature (via a `TypeError`).
  - `sign_asymmetric(…, policy_uri=None/None-URI)` returns **the data itself** as the "signature". The client uses this for X509 user tokens when the token policy has no SecurityPolicyUri.
  - The SymmetricAlgorithmHeader `TokenId` isn't used to pick the key. Every chunk is tried with the current key and, on failure, with the previous one, so a chunk with a bad MAC costs two decryptions and two verifications.
  - The previous key's lifetime has the 25 % margin only in `SecurityPolicyBasic256`. The other policies drop it at the bare lifetime.
- **CRY-8 (bug, security note)**:
  - `Basic128Rsa15` and `Basic256` are deprecated in 1.04 and 1.05 but still selectable.
  - `Basic128Rsa15` decrypts OpenSecureChannel with RSA PKCS#1 v1.5. Independently of the channel policy, `decrypt_user_token` accepts `rsa-1_5`-encrypted passwords on any endpoint, Basic256Sha256 included (SRV-6). A PKCS#1 v1.5 decryption that answers differently for bad padding and for a bad password is the classic Bleichenbacher oracle.
  - Fix: accept only the encryption algorithm of the endpoint's user token policy, and don't offer the deprecated policies unless they are enabled explicitly.
- **CRY-9 (cleanup)**:
  - `Signer`, `Verifier`, `Encryptor`, `Decryptor` and `SecurityPolicy` use `__metaclass__ = ABCMeta`, which is Python 2 syntax with no effect in Python 3. The `@abstractmethod`s aren't enforced.
  - `EncryptorAesCbc`/`DecryptorAesCbc` report the *key* size (32 for AES-256) as the block size, but the AES block is always 16 bytes. Messages are padded to 32-byte blocks. That's valid, but wasteful.
  - The `SecurityPolicyAes128Sha256RsaOaep` docstring lists the `aes256-cbc` URI for AES-128.
  - The five policy classes repeat the same `__init__`/`make_*_symmetric_key` bodies, and differ only in algorithms and sizes.
  - `revolved_expired_key` is a typo for "revoke".

### uacrypto.py

- **CRY-10 (cleanup)**:
  - `InvalidSignature` is imported from `cryptography` and then shadowed by a local class ("Do not remove this line"). That's the cause of CRY-7. Use a clearly named local exception, or catch both.
  - `check_certificate()` returns `True` when the certificate has **problems**. Callers ignore the result (`Server.start`, `Client`), apart from `cert_gen`, which uses it to decide on regeneration (CRY-11). The log messages contain typos ("vaild", "this is need for").
  - `encrypt_basic256` is unused, and despite its name it uses OAEP-SHA256 (Basic256 uses OAEP-SHA1).
  - `x509_from_der` parses DER lengths by hand without bounds checks, and silently drops everything after the first certificate.
  - The module has no type annotations.

### cert_gen.py

- **CRY-11 (bug)** (verified, spec-checked):
  - `generate_self_signed_app_certificate()` sets `BasicConstraints(ca=True, path_length=0)` and `keyCertSign` on every application certificate. Verified on a generated client certificate. Part 6, 6.2.2 (1.05) says `cA` shall be FALSE for application instance certificates. TRUE is only accepted for backwards compatibility, should not be accepted when revocation checks are off, and must be logged as a warning. So certificates made by asyncua are ones that strict 1.05 peers should reject. The docstring claims conformance with Part 4, 6.1 and Part 6, 6.2.2.
  - `setup_self_signed_certificate()` **overwrites** an existing certificate whenever `check_certificate()` finds anything to warn about, for example a host name missing from the SAN or an application URI mismatch. That includes CA-issued certificates. Verified: an installed certificate without the host name was replaced by a new self-signed one.
  - The private key is written with the process umask. Verified: mode `0644` (world-readable) with umask `022`. It should be created `0600`.

### permission_rules.py

- **CRY-12 (bug, security)**:
  - `ADMIN_TYPES` lists RegisterServer and RegisterServer2. `UaProcessor` handles those, and CreateSession, ActivateSession, CloseSession, GetEndpoints and FindServers, *before* the permission check. The admin-only rule for RegisterServer therefore never applies (SRV-5), and those entries in `USER_TYPES` are dead.
  - `Anonymous` gets an empty permission set, but the default `PermissiveUserManager` maps anonymous logins to `UserRole.User` (SRV-7). On a default server, anonymous clients therefore have full user rights, including Write and Call.
  - The docstring says "admins and users can read/write", but `Call`, `TransferSubscriptions` and the other user services are allowed too. BrowseNext, HistoryUpdate and SetTriggering are in neither list, so they'll be denied to everyone once implemented.
  - A role missing from the dict raises `KeyError`, which becomes `BadInternalError`.

### Summary: asyncua/crypto

12 findings (CRY-1 … CRY-12): 9 bugs, 3 cleanup. Six of the bugs have security impact (CRY-1, CRY-3, CRY-5, CRY-6, CRY-8, CRY-12). Together with SRV-3 and SRV-7, they make up most of the security-defaults work. Highest impact:
1. **CRY-1**: the validator accepts unknown self-signed certificates by default, and accepts everything with `TRUSTED` but no store. The examples' non-trust-store branch is configured this way.
2. **CRY-5**: certificate key length and signature algorithm aren't checked against the policy. A 1024-bit key is accepted on Basic256Sha256.
3. **CRY-3**: revocation ignores the issuer and CRL signatures, and certificate chains with intermediates can't be validated.
4. **CRY-11**: generated application certificates have `cA = TRUE`, `setup_self_signed_certificate` can replace an installed CA-issued certificate, and it writes a world-readable private key.
5. **CRY-8**: password tokens are accepted RSA-1.5-encrypted on any endpoint, and the deprecated policies are still available.

## asyncua/pubsub

Checked against Part 14 (1.05.06). The UADP layout is in 7.2.4.4 (NetworkMessage) and 7.2.4.5 (DataSetMessage), and UADP security is in 7.2.4.4.3.

### Security (writer.py, reader.py, uadp.py)

- **PUB-1 (bug, security)** (spec-checked): **PubSub message security isn't implemented, but it can be configured.**
  - `SecurityMode`, `SecurityGroupId` and `SecurityKeyServices` of writer groups and readers are only copied into the address space.
  - A writer group configured for `Sign` or `SignAndEncrypt` sends unsigned plaintext messages, and a reader configured the same way accepts them.
  - A received NetworkMessage with the SecurityHeader flag (ExtendedFlags1 bit 4) isn't rejected. The SecurityHeader isn't parsed, so the rest of the message is decoded from the wrong offset.
  - UADP over UDP multicast has no other authentication. Any host on the segment can send DataSetMessages that `SubScribedTargetVariables` writes into server variables.
  - Fix: refuse to start writers and readers whose `SecurityMode` isn't `None` until security is implemented, skip messages with the SecurityHeader flag, and document that PubSub data is unauthenticated.

### uadp.py

- **PUB-2 (bug)** (verified, spec-checked): **encoding errors in the UADP headers.**
  - `PUBLISHER_ID_UINT64 = 0b110 << 8`, but Part 14 defines UInt64 as `011`; `11x` is reserved. Verified: a UInt64 id is sent with type bits `110`. A spec-encoded UInt64 id (`011`) is decoded as **UInt16**, because the UInt16 bit is tested first: `0x0102030405060708` came back as `UInt16 1800`. Reserved PublisherId types aren't skipped as required.
  - The DataSetMessage `Valid` flag is lost. `UadpDataSetMessageHeader.Valid` defaults to `True`, and `from_binary` only ever sets it to `True`. Verified: a message sent with `Valid=False` is decoded as valid.
  - `PromotedFields` are written with the field *count* in `Size`, but `Size` is the total size of the fields in bytes. Verified: `Size = 2` for two UInt16 fields, where it should be 4 plus encoding.
  - DataSetMessage type `Event` (`0010`) isn't handled, so event messages are decoded as Variant key frames. Field encoding `11` (reserved) is treated as RawData.
  - The UADP version, the reserved bits of ExtendedFlags2 and GroupFlags, and the 1.05 ActionHeader (ExtendedFlags2 bit 5) are never checked. Part 14 says the receiver shall skip messages with reserved values.
  - `DeltaVariant.Value` defaults to the `Variant` *class* (`lambda: Variant`). `UadpDataSetDeltaRaw.Data` is typed as a list but defaults to `bytes`. `_pack_payload` encodes every DataSetMessage twice when there's a payload header.

### reader.py

- **PUB-3 (bug)**:
  - `MessageReceiveTimeout` is a Duration in **milliseconds**, but `_timeout_task` waits `MessageReceiveTimeout * 1000` **seconds**. Also, `timeout_ev` is never set when a message arrives. With a timeout configured, the reader therefore never reaches the timeout in practice, and if it did, it would switch to `Error` even while data keeps arriving. It also never goes back to `Operational`.
  - The DataSetMessage's `CfgMajorVersion`/`CfgMinorVersion` aren't compared with the reader's `DataSetMetaData.ConfigurationVersion`. Field lists are combined with `zip`, so a message with more or fewer fields than the metadata is silently cut to the shorter length.
  - A delta frame's field index `No` comes from the network and is used unchecked (`IndexError`).
  - `ReaderGroup.__init__(cfg)` replaces `cfg` with a fresh `ReaderGroupDataType()`, so a loaded reader group loses its name and settings.
  - `handle_msg` uses `assert isinstance(msg.Payload, Iterable)`. Chunk, discovery-probe and announcement messages trip it (or pass it with `-O`). Chunked messages are never reassembled.
  - `ReaderGroup.set_name()` returns the name and doesn't set it.

### writer.py

- **PUB-4 (bug)**:
  - `WriterGroup._init_information_model` writes the `Priority` node from `WriterGroupId` (`Variant(self._cfg.WriterGroupId, VariantType.Byte)`). Ids above 255 can't be encoded as a Byte.
  - The `Enabled` flags of connections, writer groups and DataSetWriters are never checked. Everything configured publishes.
  - `run()` sleeps the full `PublishingInterval` *after* each publish, so the interval drifts by the processing time. An interval of 0 is a busy loop.
  - `KeepAliveTime`, `MaxNetworkMessageSize` (no chunking above it), `KeyFrameCount` and delta frames aren't implemented.
  - The GroupHeader sequence number wraps with `% 0xFFFF`, so 65535 is never used. The DataSetMessage sequence number skips 0. Part 14 defines both as plain UInt16 counters that roll over.
  - With `DataSetClassId` in the content mask, a warning is logged on every publish.
  - `PubSubDataSource.get_raw()` drops fields whose value is `None`. With RawData encoding, every later field then lands in the wrong position on the reader.

### pubsub.py, connection.py

- **PUB-5 (bug)** (partly verified):
  - `PubSub.start()` uses `asyncio.wait`, which doesn't propagate exceptions. Verified: a connection that can't bind its socket only logs "Task exception was never retrieved", and `start()` returns with `_running = True`. With no connections, `asyncio.wait([])` raises `ValueError`.
  - `init_information_model()` initializes the connections *inside* the loop over published datasets. With no datasets, connections never appear in the address space; with two, each connection is instantiated twice.
  - Connections passed to `PubSub(cfg)` or `PubSub.new()` never get `set_if(self)`, so their writer groups run with `ps=None`. Only `add_connection()` sets it.
  - `remove_published_dataset()` and `remove_connection()` call `node.delete()` without `await`, so nothing is deleted, and they don't remove the entry from their lists. `remove_connection()` targets the whole `PublishSubscribe` node.
  - `PubSubConnection.remove_reader_group()` does `del r._meta`, which a ReaderGroup doesn't have (`AttributeError`). Neither remove method takes the group out of `_reader_groups`/`_writer_groups`, so a removed group keeps running.
  - `load_binary_file` raises `UaError(BadInvalidArgument)` with the class instead of a status code. `get_connection()` contains a debug `print`. One error message has a stray `f` inside the f-string (`f"... f{...}"`).

### subscribed_dataset.py

- **PUB-6 (bug)**:
  - With `OverrideValueHandling.OverrideValue`, `on_dataset_received` reads `cfg.OverrideValue` on the `FieldTargets` wrapper, which has no such attribute. That's an `AttributeError` when a bad status arrives; it should be `cfg._cfg.OverrideValue`.
  - The target's `AttributeId`, `ReceiverIndexRange` and `WriteIndexRange` are ignored. Values are always written to `Value`, as a whole.
  - `except KeyError: pass` hides unmapped fields, and also any `KeyError` raised while writing the node.
  - `on_state_change` receives the reader's `DataSetReaderDataType` where a `DataSetMeta` is expected.

### udp.py

- **PUB-7 (bug)**:
  - `Loopback=False` is never applied. The socket option is only set when loopback is *enabled*, so the operating system default (loopback on) stays.
  - The configured `NetworkInterface` isn't used for multicast. The group is joined with `INADDR_ANY`, and `IP_MULTICAST_IF` isn't set for sending. Instead, the socket is *bound* to the interface address, which on Linux stops it from receiving multicast at all. On hosts with more than one network card, publishing and subscribing go through whichever interface the OS picks.
  - Every malformed datagram is logged with a full traceback through the root logger (`logging.exception`). Any host on the network can flood the log.
  - Received messages are dispatched with a fire-and-forget `ensure_future` (there's a `FIXME`).
  - `"Unsupported socket family f{sock.family}"` is missing the `f` prefix.

### Docs and module layout

- **PUB-8 (doc)**:
  - There is no PubSub page in `docs/`. The only documentation is `examples/pubsub` and the module docstrings, which list the missing features ("implement a lot of specs correct (timing, publishing)", "JsonEncoding: all", "DataSetWriter: implement state").
  - Nothing tells users that security (PUB-1), JSON encoding, MQTT, keep-alives and chunking are missing.
  - `asyncua/pubsub/__init__.py` star-imports `connection` and `writer` twice.

### Summary: asyncua/pubsub

8 findings (PUB-1 … PUB-8): 7 bugs and 1 doc. One of the bugs has security impact (PUB-1). Highest impact:
1. **PUB-1**: configuring PubSub security silently does nothing. Data received over UDP is unauthenticated and is written into server variables.
2. **PUB-2**: UInt64 publisher ids are encoded and decoded incorrectly, which breaks interoperability with spec-conforming peers. The `Valid` flag and the PromotedFields size are wrong too.
3. **PUB-3**: the receive timeout is a factor of a million off, and never reset. Configuration version mismatches aren't detected.
4. **PUB-5**: `PubSub.start()` hides startup failures, connections are registered in the address space zero or several times, and the remove methods do nothing.
5. **PUB-7**: the network interface and loopback settings don't take effect for multicast.

## asyncua/sync.py, asyncua/tools.py, asyncua/observer.py

### sync.py and docs/usage/sync/overview.rst

- **SYN-1 (bug)** (verified): **calling the sync API from a sync subscription handler deadlocks.**
  - `_SubHandler` calls the user's handler on the ThreadLoop's own event loop thread. When the handler calls any sync method (e.g. `node.read_value()`), `ThreadLoop.post()` schedules a coroutine on that same loop and then blocks it, waiting for the result.
  - Verified with a 3 s ThreadLoop timeout: the read inside `datachange_notification` failed with `TimeoutError` after 3.0 s. With the default `sync_wrapper_timeout = 120`, the whole client, every subscription included, stalls for two minutes per notification.
  - Neither the docs nor the docstrings mention this. Either run sync handlers on a separate worker thread, or detect a call from the loop thread and raise a clear error.
- **SYN-2 (bug)** (verified): when `ThreadLoop.post()` times out it raises `TimeoutError`, but leaves the coroutine running. Verified: a coroutine that outlived a 0.5 s timeout still ran to completion. A Write or method Call that "timed out" for the caller can therefore still be carried out later. Fix: cancel the future on timeout.
- **SYN-3 (bug)** (verified):
  - `Client.disconnect()` (and `disconnect_sessionless`, `disconnect_socket`) stops the client's private ThreadLoop, and a thread can't be started twice. Verified: `connect(); disconnect(); connect()` raises `ThreadLoopNotRunning`.
  - The sync `Client` exposes neither `auto_reconnect` nor `reconnect_max_delay`/`reconnect_request_timeout`, so sync users have no reconnect path at all.
  - The sync `Server` has no `user_manager` parameter.
- **SYN-4 (cleanup)**:
  - `_to_async` converts `SyncNode`, `Client` and `Server` in positional arguments (including nested lists), but in keyword arguments only a bare `SyncNode`. `delete_nodes(nodes=[...])` therefore passes `SyncNode`s into async code.
  - `_to_sync` turns tuples into lists, so `delete_nodes` returns a list instead of the documented tuple. It doesn't convert dicts.
  - `ThreadLoop.stop()` stops and closes the loop without cancelling pending tasks, which gives "Task was destroyed but it is pending" warnings.
  - If `run()` fails before it notifies, `ThreadLoop.start()` waits forever.
  - `Server.get_node(SyncNode)` passes the `SyncNode` straight to the async `Node`.
  - There are typos in both class docstrings ("defualt").
  - `docs/usage/sync/overview.rst` is a single paragraph. It doesn't cover the ThreadLoop, the timeout, handler threading (SYN-1) or the lifetime of a client (SYN-3).

### tools.py (the `ua*` command-line tools)

- **TOOL-1 (bug)** (verified):
  - `uawrite` and `uacall` offer `--datatype` choices that `_val_to_variant` doesn't know. Verified: `bytestring`, `xmlelement` and `localizedtext` fail with "Invalid datatype", and `datetime` with `NotImplementedError`. The converter only checks `"ByteString"`, `"xml"` and `"LocalizedText"`, which argparse rejects.
  - The `Guid` and `ByteString` branches call `bytes(str)`, which raises `TypeError` (verified). There's no `guid` choice.
  - With `--datatype guess`, any value containing a comma is turned into an array, so string values can't contain commas.
- **TOOL-2 (bug)**:
  - `uaclient` describes itself as "Connect to server and start python shell", with `root`, `objects` and `mynode` available. It connects, resolves the node and exits; `embed()` is never called.
  - `uaserver --shell` calls the blocking `embed()` *inside* the running event loop, so the server answers no requests while the shell is open.
  - `uadiscover --network` prints an empty "Server n:" heading for each result (the printing is commented out).
  - Ctrl-C in `uasubscribe` ("Type Ctr-C to exit") and `uaserver` ends with a traceback. `asyncio.run` cancels the coroutine and then raises `KeyboardInterrupt` outside it, where the `except KeyboardInterrupt` doesn't see it.
  - `--timeout` is `type=int`, so sub-second timeouts can't be given.
  - `uasubscribe -t event` treats an explicit `-n i=84` as "no node given" (there's a `FIXME`).
  - `str_to_datetime` returns naive datetimes for user input but timezone-aware defaults.
- **TOOL-3 (bug, security, low)**:
  - `--password` (and a password in the URL) is visible in the process list and the shell history. Offer a prompt or an environment variable.
  - `uaserver` listens on `0.0.0.0` with the default endpoints (including NoSecurity) and the default user manager (SRV-7). With `--populate` it adds a writable variable and a callable method. That's fine for a demo, but the help text should say so.

### observer.py

- **OBS-1 (doc)**: `Observer` is a public extension point, used by `UaSession` and `Subscription` to report request timings, state changes and notifications. It isn't mentioned in `docs/` or in any docstring. No other findings: hook exceptions are caught and logged, and the null observer avoids the timing overhead.

### Summary: sync, tools, observer

8 findings: 6 bugs, 1 doc and 1 cleanup. One bug has (low) security impact: TOOL-3. Highest impact:
1. **SYN-1**: using the sync API inside a sync subscription handler stalls the client for the full wrapper timeout (120 s by default).
2. **SYN-2**: operations that time out in the sync wrapper still run afterwards.
3. **SYN-3**: a sync client can't reconnect after `disconnect()`, and auto-reconnect isn't exposed.
4. **TOOL-1, TOOL-2**: several advertised `--datatype` choices fail, `uaclient` doesn't open the shell it describes, and `uaserver --shell` blocks the server.

---

## Overall summary

The review covers every hand-written module in `asyncua/`, plus the matching `docs/` pages. That's 173 findings:

| Area | Findings | Bug | Security-only | Doc | Cleanup | Question |
|---|---|---|---|---|---|---|
| `ua` (UA-) | 46 | 20 | – | 7 | 16 | 3 |
| `common` (COM-) | 58 | 35 | 2 | 5 | 15 | 1 |
| `client` (CLI-) | 17 | 12 | – | 2 | 3 | – |
| `server` (SRV-) | 24 | 22 | – | 1 | 1 | – |
| `crypto` (CRY-) | 12 | 9 | – | – | 3 | – |
| `pubsub` (PUB-) | 8 | 7 | – | 1 | – | – |
| `sync`, `tools`, `observer` (SYN-, TOOL-, OBS-) | 8 | 6 | – | 1 | 1 | – |
| **Total** | **173** | **111** | **2** | **17** | **39** | **4** |

Twenty-three findings touch security. Three are fixed so far:
- **COM-39** (code execution from legacy type dictionaries), commit `6f9f1a14`, upstream branch `fix/legacy-type-dictionary-exec`.
- **SRV-1** (session hijack) and **SRV-3** (validator bypass), commit `7c63c2ec`, upstream branch `fix/session-activation-checks`.
- **SRV-2** (sequential session tokens) is partly fixed in the same commit.

Suggested order for the bug-fixing pass:
1. **Remaining security bugs that a remote peer can trigger**:
   - SRV-4 (subscriptions shared across sessions)
   - SRV-5 (unauthenticated RegisterServer)
   - SRV-6 and CRY-8 (replayable and RSA-1.5 password tokens)
   - SRV-9 (pre-Hello buffering)
   - SRV-18 (Call without object, argument or permission checks)
   - CLI-6, CLI-7, CLI-14 (client-side nonce and endpoint checks)
   - PUB-1 (refuse PubSub security modes that aren't implemented)
   - COM-54 (SQL identifiers)
   - CRY-6 (constant-time MAC comparison)
2. **Secure by default**, the goal stated at the start of this work:
   - SRV-7 (permissive user manager)
   - CRY-1 (validator defaults)
   - CRY-5 (policy key limits)
   - CRY-3 (revocation and chains)
   - CRY-11 (generated certificates, key file mode)
   - the NoSecurity default endpoint
   - TOOL-3
   - the README and docs pages
3. **Data correctness**:
   - SRV-15 (`IndexRange` replaces whole arrays)
   - SRV-11, SRV-12, SRV-13 (publishing interval, Republish, queue sizes)
   - CLI-3, CLI-4, CLI-5 (publish loop and acknowledgements)
   - CLI-12 (truncated file reads)
   - SRV-20, SRV-21, SRV-22 (history)
   - PUB-2, PUB-3 (UADP encoding, reader timeout)
   - SYN-2 (timed-out sync calls still run)
   - the COM bugs marked data loss or interop
4. **Robustness**:
   - SYN-1 (sync handler deadlock)
   - SRV-8, SRV-10, SRV-14, SRV-16, SRV-17
   - CLI-1, CLI-8, CLI-9, CLI-10
   - PUB-4 to PUB-7
   - TOOL-1, TOOL-2
5. **Docs and cleanup**: the doc and cleanup items, the empty client and server overview pages, and the PubSub and Observer documentation.
