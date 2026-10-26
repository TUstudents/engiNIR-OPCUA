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

Transport (OPC 10000-6, 7.1):
- `TransportLimits` keeps the peer's limits apart (`send_max_message_size`, `send_max_chunk_count`).
  `max_message_size` and `max_chunk_count` are this side's receive limits, and a configured 0 means the default
  (100 MiB, 1601 chunks), not unlimited. The same holds for `Client.max_messagesize` and `max_chunkcount`.
- The client's Hello carries its real limits; the `ua.Hello` defaults are 65535, 65535, 100 MiB and 1601.
- A Hello or Acknowledge with buffers below 8192 bytes is rejected with `Bad_InvalidArgument`, so a server
  configured below 8192 can't be reached. An EndpointUrl above 4096 bytes gets `Bad_TcpEndpointUrlInvalid`.
- A connection without a Hello is closed after `InternalServer.hello_timeout_seconds` (30 s). At the connection limit
  the server closes its oldest connection without a session instead of refusing the new one.
- A request above the server's limits fails locally with `Bad_RequestTooLarge`; a response above the client's limits
  becomes a ServiceFault `Bad_ResponseTooLarge`. An Abort chunk fails its request at once.
- Channel failures send an Error message and close the connection, so clients see `Bad_SecurityChecksFailed`,
  `Bad_TcpSecureChannelUnknown` or `Bad_SecureChannelTokenUnknown` instead of a timeout.
- Hello is handled by `OPCUAProtocol` (`UaProcessor.accept_hello`). Removed: `UASocketProtocol.receive_buffer`,
  `is_receiving` and `_process_received_data`.

SecureChannel (OPC 10000-6, 6.7; OPC 10000-4, 5.6.2):
- `SecureConnection` is `SecureChannel`, with no alias. Removed: `next_security_token`, `prev_security_token`,
  `revolve_tokens`, `UaClient.revolve_security_token` and the previous-key members of the crypto classes. New:
  `SecurityPolicy.make_symmetric_cryptography()`.
- The server clamps RevisedLifetime to `InternalServer.channel_settings` (10 s to 1 h; a request for 0 gets 1 h).
  TokenIds are random. Keys are chosen by TokenId, every token is accepted until 125 % of its lifetime, and a channel
  without a valid token is closed.
- Issue on an open channel and Renew on an unopened one fail with `Bad_RequestTypeInvalid`. Nonces, the receiver
  thumbprint, certificate, policy, mode and protocol version are checked on both sides.
- The client renews after 75 % of each revised lifetime, at least every second.

Server sessions (OPC 10000-4, 5.7):
- `Session` and `SessionManager` (`iserver.session_manager`) replace the session state of `InternalSession`. A channel
  can carry several sessions; every request is matched to its session by AuthenticationToken and has to arrive on
  that session's channel. Removed: `InternalServer.create_session`, `lookup_external_session`,
  `register_external_session`, `unregister_external_session` and `InternalSession.max_connections`;
  `InternalSession.transfer_subscriptions(params)` takes no callback.
- At most `session_manager.max_sessions` (100) sessions; at the limit the oldest session that was never activated is
  closed, otherwise CreateSession gets `Bad_TooManySessions` (was `Bad_MaxConnectionsReached`). A ClientNonce shorter
  than 32 bytes is rejected.
- Requests on an unknown, closed or timed-out session get `Bad_SessionIdInvalid`, on a created but not activated one
  `Bad_SessionNotActivated`. CloseSession of an unknown session is no longer Good.
- A session the server ends (timeout, lost channel) keeps its subscriptions until their own lifetime ends, so a client
  can transfer them; only CloseSession with deleteSubscriptions deletes them. An activated session survives the loss
  of its channel until its timeout.
- Empty operation arrays return `Bad_NothingToDo`, arrays above `iserver.operation_limits` `Bad_TooManyOperations`;
  an undecodable request body `Bad_DecodingError`. Requests of a session may run concurrently.
- `CloseSecureChannelRequest` is honoured only as a CLO message.
- `Server.default_timeout` is removed. `start()` after `stop()` gives the same endpoints as the first start;
  `stop()` sets ServerState to Shutdown, withdraws discovery registrations and closes sessions and subscriptions.
  `register_to_discovery()` refuses a period above 600 s; `unregister_from_discovery()` of an unknown URL raises
  `UaError`.

Subscriptions (OPC 10000-4, 5.13 and 5.14):
- The publishing interval is revised to between 50 ms and 1 h (0 or less gets 50 ms), also for in-process
  subscriptions; keep-alive 0 becomes 1; the lifetime count is at least 3 × keep-alive and interval × lifetime is at
  most 24 h. ModifySubscription applies and returns the revised values. The first message goes out after the first
  cycle.
- Subscriptions follow the Part 4 state machine; an expired subscription sends `Bad_Timeout` and the owner's queued
  Publish requests are answered. Sequence numbers roll over to 1; MaxNotificationsPerPublish and MoreNotifications
  are honoured; Priority decides between waiting subscriptions.
- Republish keeps the message; an unknown sequence number gives `Bad_MessageNotAvailable`. Acknowledging an unknown
  sequence number gives `Bad_SequenceNumberUnknown` for that entry. The retransmission queue holds 2 × the Publish
  limit per session.
- At most 10 Publish requests per session (`max_publish_requests_per_session`); one more answers the oldest with
  `Bad_TooManyPublishRequests`. At most 100 subscriptions per session (`max_subscriptions_per_session`).
- TransferSubscriptions requires the same user (anonymous only with the same client certificate), moves the queue
  and both Publish bindings, tells the previous owner `Good_SubscriptionTransferred` and honours SendInitialValues.
- `InternalSubscription.publish()`, `has_published_results()` and `_trigger_publish` are removed.

Crypto:
- Verifiers raise `ua.uaerrors.SignatureError` and decryption failures `ua.uaerrors.DecryptionError` (both
  `UaError`); `uacrypto.InvalidSignature` is gone.
- A bad ActivateSession client signature is answered with `Bad_ApplicationSignatureInvalid`, a bad or missing X509
  user-token signature with `Bad_UserSignatureInvalid`.
- `sign_asymmetric` raises without a signing policy instead of returning the data, so an X509 user token on an
  endpoint without security fails on the client.
- `check_certificate()` returns a list of problems (empty when fine) instead of `True` for "has problems".
  `x509_from_der()` raises `UaError` on malformed input; `split_certificate_chain()` returns the whole chain.
- `SecurityPolicyType` lives in `crypto/security_policy_type.py` (still `ua.SecurityPolicyType`).
  `revolved_expired_key` was renamed and then removed with the previous-key handling.
- AES-256 policies pad to 16-byte blocks (wire-compatible).

XML import:
- Nodes marked `DesignToolOnly`, their children and references to them are skipped (OPC 10000-6, F.7).

Code generation:
- The generated code comes from the `nodeset` submodule, pinned to UA-Nodeset `UA-1.05.07-2026-05-01`.
  `schemas/regenerate.py` replaces `schemas/update_ua_nodeset.py`.
