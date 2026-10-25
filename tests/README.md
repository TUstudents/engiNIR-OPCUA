# Tests

Run the fast tests with `uv run pytest -q -m "not slow"` and everything with `uv run pytest -q`. Tests marked `slow` can be skipped unless their sources changed: `uv run pytest --changed-since origin/master`.

## Tests for review findings

Tests that reproduce a finding from `docs/code-review.md` carry its ID in the name, for example `test_srv4_bob_cannot_delete_alice_subscription`. The docstring cites the spec section by part and section number only, for example `Part 4, 5.14.1.2`. Never paste spec text; it's copyrighted (see `docs/opcua-spec/README.md`).

## Peer harness

`tests/harness.py` holds the building blocks, and `tests/conftest.py` holds the fixtures:

| Fixture | Use it for |
|---|---|
| `raw_peer` | Sending hand-made UA-TCP bytes to the module's `server` and reading the raw replies: Hello and buffer limits, malformed chunks, connection handling |
| `tampered_responses` | Acting as a hostile server: `tampered_responses.on(ua.CreateSessionResponse, change)` modifies every response of that type before it's encoded |
| `two_sessions` | Ownership and isolation checks: a fresh server with users `alice` and `bob`, each connected with their own client |

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
