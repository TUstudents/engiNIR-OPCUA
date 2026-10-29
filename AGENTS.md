# Agent Guidelines

## Running

- Use `uv` to run commands: `uv run pytest ...`
- Use `uv` to run commands: `uv run mypy ...`
- Use `uv` to run commands: `uv run ruff ...`
- Use `uv` to run commands: `uv run python ...`
- Build the docs with the `docs` dependency group: `uv run --group docs sphinx-build -b html docs docs/_build/html`. All dependencies and tool settings live in `pyproject.toml`; Read the Docs installs the same group (`.readthedocs.yml`).

## Code Style

- Type annotations are required on all new and modified functions.
- Do not add comments to the code. The code should be self-explanatory. If it is not, refactor it.
- Line length limit is 120 characters.
- Use `ruff` for formatting and linting: `uv run ruff check` and `uv run ruff format`.
- Target Python 3.12+ (development uses 3.14). Use modern syntax (`X | Y` unions, `list[...]`, `dict[...]`, etc.).

## Communication

- Do not summarize changes after editing files. The diff is visible directly.
- Never include "🤖 Generated with [Claude Code](https://claude.com/claude-code)", Claude session links, or any similar attribution footer in commit messages, pull request descriptions, comments, or issues. This includes `Co-Authored-By: Claude` and `Claude-Session:` trailers.

## Tests

Layout: one directory per component under `tests/`, one file per behaviour of that component.

| Directory | Holds |
|---|---|
| `tests/ua/` | types, binary encoding and decoding, messages, generated code, option sets, structures |
| `tests/transport/` | UACP handshake and messages, secure channel, size and chunk limits, connections |
| `tests/security/` | certificates, trust stores and PKI directories, crypto policies, users and identity tokens, permissions |
| `tests/server/` | sessions, service dispatch, attributes, views, methods, subscriptions, monitored items, events, history, lifecycle |
| `tests/client/` | client core, publish, reconnect, endpoints, high availability, file transfer |
| `tests/model/` | node helpers, node management, instantiation, XML import and export, custom types, registry, companion models |
| `tests/pubsub/` | PubSub |
| `tests/tools/` | command-line tools, the sync wrapper, the observer |
| `tests/interop/` | tests against the OPC Foundation reference stack (marker `interop`) |

- Put a new test in the file of the behaviour it checks. Create a file only for a new behaviour, named `test_<behaviour>.py`; never one file per finding, per task or per agent. Data files (XML, BSD, binary) sit next to the tests that use them.
- Fixtures used by one area live in that area's `conftest.py`. `tests/conftest.py` keeps the shared ones. Rigs used by several areas (`harness`, `pki`, `access_rig`, `history_rig`, `subscription_rig`, `monitoring`, `file_rig`, `waiting`) stay in `tests/`; import them as `from tests.<rig> import ...`.
- A test that reproduces a review finding has the ID in its name (`test_srv13_...`). When tests merge into a parametrised table, the ID goes into the parameter id (`pytest.param(..., id="srv13_zero_queue_size")`). No ID may disappear from the suite.
- Parametrise near-identical tests into one table. Remove a test that asserts the same behaviour with the same inputs as another, and list the removal in the commit message.
- Parametrise over client and server (the `opc` fixture) only when the two variants take different paths: services, encoding, permissions, session state. Pure logic (helpers, conversions, local state) gets one variant.
- Servers and clients are expensive. Start them once per module (`scope="module"`) when the tests do not change shared state, and give each test its own namespace, node names or a reset of what it changed (the `history_rig`, `two_sessions` and `shared_signing_server` fixtures do this). A test that changes server configuration, or that needs a fresh server, takes a function-scoped one.
- Never wait with a fixed `sleep()`. Wait for the condition with `await wait_until(lambda: ...)` from `tests/waiting.py`, or for an event with a timeout. A sleep stays only to prove that something does not happen, and then as short as the interval it must outlast.
- Use `find_free_port()` for every port; never bind 4840 or another fixed port. A client URL that is never connected to may name any port.
- Mark a test `@pytest.mark.slow(<source paths>)` when it takes more than about 5 seconds; with `--changed-since REF` it then runs only when one of those paths, its file or `tests/conftest.py` changed. Shorten timeouts through the test's own configuration, not by changing library defaults.
- Do not add `pytestmark = pytest.mark.asyncio`; asyncio mode is auto.
- The suite runs in parallel with `pytest-xdist` as `-n 4 --dist loadfile`: tests of one file share a worker, so module-scoped servers stay safe. Plain `-n` without `loadfile` breaks tests that share module fixtures.
- Sync code waits with `wait_until_sync` from `tests/tools/sync_waiting.py`.
- A test that sends Ctrl-C to a CLI subprocess starts it with the default SIGINT handler (`preexec_fn` or `start_new_session` plus `signal.signal(SIGINT, SIG_DFL)`); background runs ignore SIGINT and the CLI would hang.
- Tests change tests, rigs and conftest only. A library bug that a test reveals gets a finding ID in the review tracker, and the test stays as it is.
- New workstreams put their tests in the directory of the component they change and add to the existing behaviour file; a new component gets a new directory with its own `conftest.py`.
- Tests use `pytest` with `pytest-asyncio` in auto mode. Run specific tests with `uv run pytest tests/<area>/<file>.py -k "<pattern>" -x`. The fast suite is `uv run pytest -q -m "not slow"`; run the full suite only in CI. Details of the rigs and fixtures are in `tests/README.md`.
