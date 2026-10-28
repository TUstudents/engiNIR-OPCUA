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
  `Server.accept_server_registrations()`. When enabled, a registration needs a secure channel whose certificate
  carries the ServerUri; empty ServerNames give `Bad_ServerNameMissing`, `IsOnline = false` removes the entry, the
  registry holds at most 100 servers and entries expire after 10 minutes.

Secure defaults and certificate trust (OPC 10000-4, 6.1.3):
- One `CertificateValidator(trust_store, suppress=..., check_revocation=..., accept_ca_application_certificates=...)`
  runs the validation steps in the spec's order (chain, signature, security policy, trust, validity, host name, URI,
  usage, revocation). It replaces the flag-based `CertificateValidator`/`CertificateValidatorOptions`.
- It runs at every OpenSecureChannel and renewal, on both server and client. Both sides trust nothing until
  `Server.set_trust_store()` / `Client.set_trust_store()` is called. A server certificate passed to
  `Client.set_security()` is pinned; one fetched over an unsecured GetEndpoints isn't trusted.
- A PKI directory (`own/`, `trusted/`, `issuer/` with `crl/` folders, `rejected/`) configures the certificate, the key and
  the trust in one call: `Server.set_pki_directory()`, `Client.set_pki_directory()`, `Server.set_user_pki_directory()`.
  A peer certificate that fails validation is kept in `rejected/certs` (never trusted); `Server.reload_trust_store()`
  picks up files moved to `trusted/certs`.
- The server tells a peer only `Bad_SecurityChecksFailed` and logs the detail; the client raises the detailed code.
- Certificates are checked for expiry, key usage, key length and signature hash per security policy, the host name
  (client side) and the ApplicationUri. A ClientDescription ApplicationUri that isn't in the client certificate gives
  `Bad_CertificateUriInvalid`. The certificates committed under `examples/` fail these checks; the examples now
  generate their own.
- `Server.set_certificate_validator(hook)` and `Client.certificate_validator` are now `set_application_hook()` /
  `application_hook`; `set_certificate_validator()` takes a whole validator.
- The NoSecurity endpoint is offered only with `Server(allow_no_security=True)` or `NoSecurity` in
  `set_security_policy()`. `Basic128Rsa15` and `Basic256` need `allow_deprecated_policies=True` on both sides. A server
  without any endpoint refuses to start with `ConfigurationError`.
- Generated application certificates have `cA = FALSE` (self-signed ones keep keyCertSign); keys are written atomically
  with mode 0600. `setup_self_signed_certificate()` only replaces certificates it generated itself.
- New: `Server.load_certificate_chain()` to send an intermediate chain, `UaStatusCodeError(code, detail)`.

Users and permissions:
- The default user manager accepts Anonymous as read-only (read, browse, subscribe, history read; no write, call or
  node management) and rejects UserName and X509 tokens with `Bad_IdentityTokenRejected`. `admin` with any password
  is gone, and so is `Server.allow_remote_admin`. `PermissiveUserManager` remains as an explicit, insecure opt-in.
- Identity tokens are matched to the endpoint's UserTokenPolicy (PolicyId, token type, security policy); an Anonymous
  token with an empty or wrong PolicyId gives `Bad_IdentityTokenInvalid`. A wrong password gives
  `Bad_UserAccessDenied`. No UserName policy is advertised on an unsecured endpoint unless an encrypting policy exists
  or `allow_plaintext_password` is set.
- X509 user tokens are validated against a separate user trust list (`Server.set_user_trust_store()`); without one
  they are refused, except for the certificates registered with a `CertificateUserManager`. The user manager receives
  the leaf certificate only. A session whose X509 user certificate expires drops to Anonymous (or is closed when the
  endpoint offers no Anonymous policy).
- After 5 failed logins from one peer, further ActivateSession requests are delayed from 1 s up to 30 s.
- `SimpleRoleRuleset` takes a map from request type to role; `Permission` has an `Anonymous` level;
  `SessionManager.activate_session` is async.

Client:
- A client that took its security from GetEndpoints compares that list with CreateSession's ServerEndpoints and fails
  with `Bad_SecurityChecksFailed` when they differ. Endpoints are no longer re-fetched on reconnect.
- `HaSecurityConfig` needs a `server_certificate` or a `trust_store` when security is on.
- Publish requests are pipelined: up to `UaSession.max_outstanding_publish_requests` (default 10) are in flight,
  sized by the number of Subscriptions and the measured round trip, each with a timeout from the keep-alive time.
  Acknowledgements are kept until the response to the request that carried them arrives (`max_pending_acks`, 2000),
  and messages fetched with Republish are acknowledged too. Subscriptions register with `UaSession.register_sink`.
- A timed-out request is removed from the request table; a late response to it is dropped, a response for an id that
  was never sent closes the channel. A timed-out OpenSecureChannel no longer blocks every later renewal.
- `connect()` on a connected client raises; a failure during `connect()` closes the Session it created.
  `disconnect()` closes the local Subscriptions, and a later `connect()` doesn't bring them back. After a reconnect,
  Subscriptions are restored before publishing resumes; the stale watchdog keeps running.
- The client checks the server certificate's ApplicationUri against the endpoint's. `Client(url)` refuses schemes
  other than `opc.tcp`; a URL without a port uses 4840. A user token type the endpoint doesn't offer raises
  `ConfigurationError` before anything is sent.
- `Node.call_method` converts arguments to the method's declared InputArguments types; services take a per-call
  `timeout`. `UaClient.add_state_listener` is public. `get_keepalive_count` and `get_subscription_revised_params`
  are removed; use `subscription_parameters`.
- `HaClient` needs at least two server URLs.

Client subscriptions (OPC 10000-4, 5.13 and 5.14):
- `subscription_parameters(period, ...)` derives the keep-alive count from a keep-alive time (default 10 s) and the
  lifetime count from a lifetime (default 300 s), never below three times the keep-alive; `MaxNotificationsPerPublish`
  is 0. A `Subscription` stores the revised values (`revised`) and corrects a revised keep-alive above 60 s once.
- The default sampling interval of `subscribe_data_change` is -1 (the publishing interval), not 50 ms.
  `unsubscribe` skips handles it doesn't know instead of raising; it keeps items the server couldn't delete and raises
  after removing the others. `modify_monitored_item` raises `ValueError` for an unknown handle and keeps the stored
  filter, queue size, discard policy and timestamps unless given.
- Notifications are delivered from a task per Subscription. A full inbox or event queue drops the oldest entry and
  counts it (`dropped_messages`, `dropped_events`); a slow handler delays only its own Subscription. Handlers may
  return any awaitable. Duplicate messages are dropped and missing ones are fetched with Republish
  (`max_republish`, `republish_missing`). `Bad_Timeout` marks the Subscription lost; `Good_SubscriptionTransferred`
  ends it without recreating. `Subscription.close()` ends it locally; `Subscription.state` is new.

File transfer (OPC 10000-5, Annex C):
- `UaFile.read()` reads in chunks until an empty ByteString and no longer uses `Size`; `write()` is chunked.
  `UaFile(node, mode, chunk_size=, timeout=)` validates the open mode, resolves Methods once with a fallback to the
  FileType Methods, refuses a second `open()` and sends no Close for a closed file. New: `read_chunk`, `iter_chunks`,
  `adopt`, `get_mime_type`, `FileTransferError`, `InvalidStateError`. `client/ua_file.py` is a deprecated wrapper,
  removed in 4.0.0.

High availability:
- `HaClient` keeps a Healthy active server whatever the others report, uses the best Degraded server when none is
  Healthy, never resets a connected standby for its ServiceLevel, and disconnects a server in maintenance
  (ServiceLevel 0). Probe and manager default to 5 s and wake each other. A server that reports no Warm or Hot
  `RedundancySupport` is not used unless `HaConfig(allow_unsupported_redundancy=True)`.
  `HaSecurityConfig` takes user credentials. Unknown subscription names raise `KeyError`; `HaClient.status()` is new.

Tools:
- `--password` is gone; use `--ask-password` or `ENGINIR_OPCUA_PASSWORD`. `uaserver` is a demo without security and
  says so; `--accept-all-logins` opts into permissive logins. The sync `Server` takes `user_manager`.

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

Attribute, method and view services (OPC 10000-4, 5.8 to 5.12):
- No role bypasses AccessLevel or WriteMask, Admin included; only the server's own in-process session is exempt. Remote
  clients can't write read-only variables or attributes without the WriteMask bit, `NamespaceArray` included.
- Write checks the DataType (subtypes allowed), ValueRank, ArrayDimensions and null values; a StatusCode or
  SourceTimestamp from a client needs the StatusWrite or TimestampWrite bit, otherwise `Bad_WriteNotSupported`.
  `Node.write_value` no longer sends a SourceTimestamp. A value setter's return value is the write result, and
  `Server.write_attribute_value` raises on a bad result. A client write to an attribute with a value callback is
  `Bad_NotWritable`.
- Read honours IndexRange and TimestampsToReturn and ignores DataEncoding; a variable that was never set reads as
  `Bad_NoValue`. `ua.IndexRange` implements NumericRange (OPC 10000-4, 7.27) for Read, Write, HistoryRead, monitored
  items and PubSub targets.
- Call checks that the method belongs to the object, Executable/UserExecutable and every input argument.
  `Node.call_method` sends Python ints as Int64, so methods with other integer argument types need typed Variants.
  Hand-built `ua.Argument` objects need a ValueRank; a method without a callback gives `Bad_NotSupported`.
- Browse honours ResultMask, NodeClassMask and RequestedMaxReferencesPerNode; BrowseNext and continuation points
  exist; unknown nodes give `Bad_NodeIdUnknown`. With ResultMask 0, `get_children` returns empty fields.
- AddNodes from a client: namespace 0 is refused (`Bad_NodeIdRejected`, also `instantiate()` with `idx=0`), the
  parent reference must be hierarchical and the BrowseName unique. AddReferences refuses duplicates; DeleteNodes and
  DeleteReferences refuse namespace 0.

Monitored items and events (OPC 10000-4, 5.13):
- QueueSize 0 or 1 means 1 for data items (it used to mean 10 000); the maximum is 1000. The sampling interval is
  revised (0 becomes 10 ms, a negative value the publishing interval). A null filter in ModifyMonitoredItems removes
  the filter. A deleted monitored node delivers `Bad_NodeIdUnknown`. `InternalSubscription(max_queue_size=...)` is
  now `limits=MonitoredItemLimits(...)`; `MonitoredItemValues` is removed.
- Events also reach the Server object and every notifier above their source. `EventGenerator` no longer clears other
  EventNotifier bits; the default Message is a LocalizedText; DaylightSavingInOffset is set only while DST applies.
  68 fields of the generated event classes now declare built-in types.

History (OPC 10000-11):
- `HistoryStorageInterface` is replaced for custom backends: reads take a `TimeDomain` and return a `Page`; saves are
  `save_node_value()` and `save_event()`; new `has_node()`, `has_event()`, `flush()` and `stores_server_timestamp`.
- SQLite history files from earlier releases are refused with an error naming the file.
- A HistoryRead of a node that isn't historized gives `Bad_HistoryOperationUnsupported`, without the HistoryRead bit
  `Bad_NotReadable`. Two of start, end and count are required. Equal timestamps return the latest value with the
  ExtraData bit; empty ranges give `Good_NoData`.
- `Node.read_raw_history()` and `read_event_history()` without arguments read everything until now, and with only a
  count the newest values; `read_raw_history` defaults `return_bounds` to False.
- `validate_table_name` and `SqlInjectionError` are removed. `set_storage()` after historizing raises. A notifier's
  event history includes the events of the sources below it.

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

Node helpers:
- `CallbackService` keeps every listener, ordered by priority and then insertion order (a second listener with the
  same priority used to replace the first); any awaitable result is awaited and dispatch works on a snapshot.
- `string_to_val` is the inverse of `val_to_string`: lists quote elements that contain commas, quotes or brackets,
  nested and empty lists work, enumerations read by name. Invalid text raises `ValueError`, integers are range
  checked, Booleans are `true`/`false`/`1`/`0` in any case (the legacy `on`/`yes` are gone), and types without a text
  form raise `NotImplementedError`.
- `get_references`, `get_children` and the other browse helpers raise on a Bad browse result and release the
  continuation point when a page fails. `get_child` and `get_children_by_path` accept a target only when the whole
  path resolved. `read_event_history` and `read_raw_history` read every page and release an open continuation point;
  `history_read_events` takes a continuation point. `history_update` checks the operation results.
- `write_array_dimensions` writes a `UInt32[]`; `read_value_rank` returns a plain integer above four dimensions.
  `Node.add_reference` sends the target NodeClass.
- A failed method call raises `UaStatusCodeError` with `input_argument_results` and `input_argument_diagnostic_infos`;
  multi-dimensional arguments are converted.
- `create_method` takes `(nodeid, bname, callback, inputs, outputs)`; binding a callback on a client session raises
  `UaError` (pass no callback to create the Method node without one). Arguments are named `Input<i>`/`Output<i>`,
  an argument type given as a list is an array. A symmetric ReferenceType has no InverseName, a non-symmetric one
  needs it (`ValueError`). `add_object_type`, `add_variable_type` and `add_data_type` take `is_abstract`.
- New variables: a list has ValueRank 1 (or the number of dimensions) and ArrayDimensions of zeros (unknown maximum),
  there is no Description, and a VariableType without a value is scalar; falsy initial values are kept. Encoding
  objects have the DataTypeEncodingType type definition. `create_data_type` adds no second HasSubtype reference.
- Recursive `delete_nodes` and `copy_node` follow only aggregating references (HasComponent, HasProperty, ...), each
  node once, children first; nodes another parent still aggregates are kept. `copy_node` copies EventNotifier,
  IsAbstract and the ModellingRule, takes `referenceType` (default: the reference the source hangs on), and removes
  what it created when it fails.
- `instantiate` accepts only ObjectTypes and VariableTypes, skips placeholder and ExposesItsArray declarations,
  instantiates the declarations of a child's own type (and its EventNotifier), checks every AddNodes result and removes
  what it created when it fails.
- Event filters: `where_clause_from_evtype` uses the `OfType` operator (one element per type, combined with `Or`)
  instead of listing the subtypes; an EventType without a supertype chain to BaseEventType raises `UaError`.
- State machines: `FiniteStateMachine.install()` creates a concrete subtype (or takes `state_machine_type`).
  `add_transition(..., from_state=, to_state=)` creates the FromState and ToState references; names and numbers
  must be unique, number 0 is valid, there is at most one initial State, and `change_state` rejects a transition that
  does not connect the current state to the new one and always raises a TransitionEvent (default message
  "<from> to <to>"). `State`/`Transition` ids follow the DataType of the `Id` property. The classes
  `ExclusiveLimitStateMachine`, `FileTransferStateMachine`, `ProgramStateMachine` and `ShelvedStateMachine` are removed.
- `get_node_supertypes` returns the nearest supertype first; `get_nodes_of_namespace` can return namespace 0 and raises
  `UaError` for an unknown URI; `get_node_children` and `get_node_subtypes` list each node once.
