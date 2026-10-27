# Tests

Run the fast tests with `uv run pytest -q -m "not slow"` and everything with `uv run pytest -q`. Tests marked `slow` can be skipped unless their sources changed: `uv run pytest --changed-since origin/master`.

## Tests for review findings

Tests that reproduce a review finding carry its ID in the name, for example `test_srv4_bob_cannot_delete_alice_subscription`. The docstring cites the spec section by part and section number only, for example `Part 4, 5.14.1.2`. Never paste spec text; it's copyrighted (see `docs/opcua-spec/README.md`).

## Peer harness

`tests/harness.py` holds the building blocks, and `tests/conftest.py` holds the fixtures:

| Fixture | Use it for |
|---|---|
| `raw_peer` | Sending hand-made UA-TCP bytes to the module's `server` and reading the raw replies: Hello and buffer limits, malformed chunks, connection handling |
| `raw_server` | Acting as a hostile server for a client under test: `peer = await raw_server.accept()` hands over the client's connection as a `RawPeer` |
| `tampered_responses` | Acting as a hostile server: `tampered_responses.on(ua.CreateSessionResponse, change)` modifies every response of that type before it's encoded |
| `signing_server` | A server with only Basic256Sha256 Sign and the users of `two_sessions`; connect with `signing_client(server, "alice")` |
| `two_sessions` | Ownership and isolation checks: a fresh server with users `alice` and `bob`, each connected with their own client |

## Certificates in tests

Tests that connect with security generate their certificates: `tests/pki.py` builds them (`make_identity`, `make_ca`, `make_crl`, `sha1_signed`) and `generated_pki()` returns a set of server and client certificates, written once per run to a temporary directory. The committed certificates under `examples/` are expired and have no key usage, so no test connects with them. Never commit a key for a test.

The library trusts nothing by default, so a test trusts explicitly: `server.set_trust_store(PKI.trust_store())` for the client certificates of the server, and either `client.set_trust_store(PKI.trust_store())` or a server certificate passed to `set_security` (which pins it) for the client. A server that offers the None policy asks for it with `Server(allow_no_security=True)`; one that offers Basic128Rsa15 or Basic256 with `Server(allow_deprecated_policies=True)`. Never weaken the validator to make a test pass: name the step in `suppress` when a test needs it.

`SessionProbe` (in `harness.py`, no fixture) is a client with an open None-policy channel on which a test creates several sessions and sends requests under any session's token: `probe = await SessionProbe.open(url)`, `create_session()`, `activate(token)`, `read_server_state(token)`, `send(token, request, response_type)`, `send_edited(token, request, response_type, edit)` for malformed bodies, `close_session(token)`. Use it for session binding, limits, channel moves and Publish queue tests; open a second probe for a second channel.

## Spec byte vectors

Encoding tests build the expected bytes from the spec's encoding tables and write them inline. For example, this is the test for UA-24, which fails until UA-24 is fixed:

```python
from enginir_opcua import ua
from enginir_opcua.ua.ua_binary import struct_to_binary


def test_ua24_diagnostic_info_locale_uses_mask_bit_0x08() -> None:
    """Part 6, 5.2.2.12: Locale is mask bit 0x08; LocalizedText is 0x04."""
    assert struct_to_binary(ua.DiagnosticInfo(Locale=2)) == bytes.fromhex("08 02000000")
```

Today the encoder writes `04 02000000`, which is the bug.

## Interoperability tests

`tests/interop/` runs our client against the OPC Foundation reference server and the reference console client against our server. Both come from the .NET Standard stack (`OPCFoundation/UA-.NETStandard`), pinned to the tag in `tools/interop/reference-stack-tag.txt`; moving the tag is a deliberate change. The tests carry the `interop` marker and are only selected by `-m interop`: a plain `uv run pytest` and `-m "not slow"` deselect them. Without `ENGINIR_INTEROP_SERVER_URL` (our client tests) or `ENGINIR_INTEROP_CLIENT_DLL` (our server tests) they skip with a reason.

| Module | Scenarios | Matrix |
|---|---|---|
| `test_client_vs_reference.py` | GetEndpoints, FindServers, connect, browse, read, write, a 20,000 element array (many chunks), method call, data change and event subscriptions, channel token renewal, reconnect, TransferSubscriptions with Republish, HistoryRead (skips: the reference server has no history), `load_data_type_definitions` | None; Basic256Sha256 Sign and SignAndEncrypt; Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss SignAndEncrypt; each with Anonymous, UserName (`user1`) and X509 user token (None only with Anonymous) |
| `test_reference_client_vs_server.py` | The console client connects and browses (`--browseall`), then reads, writes, calls a method and subscribes against nodes our server publishes under the reference server's node ids | The same policies; Anonymous and UserName |

The client picks the most secure endpoint, so the tests start our server with one policy at a time. The reference client accepts our server's certificate (`--autoaccept`, the only choice its command line offers). Our client trusts the reference server's own certificate by copying it into an explicit trust store, and suppresses the host name step, because that certificate carries the machine's host name and the tests connect to `localhost`. Our server only accepts the client's certificate after the test copied it into an explicit trust directory, and a test checks that an untrusted certificate is refused.

To run them locally you need the .NET 8 SDK (Microsoft's `dotnet-install.sh` can install it into any directory with `--install-dir`):

```bash
git clone --branch "$(cat tools/interop/reference-stack-tag.txt)" https://github.com/OPCFoundation/UA-.NETStandard /tmp/interop-src/UA-.NETStandard
tools/interop/build.sh /tmp/interop-src/UA-.NETStandard /tmp/interop-build
tools/interop/run.sh /tmp/interop-build
```

The clone needs its full history (no `--depth`), because the build computes its version from it. `run.sh` starts the reference server on port 62541 with its own certificate store in a temporary directory, waits until it answers, runs `pytest -m interop tests/interop` with any extra arguments you pass, and stops the server. Set `ENGINIR_INTEROP_KEEP_LOGS=1` to keep the reference server's log. `.github/workflows/interop.yml` does the same on pushes to `master`, weekly and on manual dispatch; it is not a required check.
