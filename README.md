# engiNIR-OPCUA

[![PyPI][pypi-badge]][pypi]
[![Python][python-badge]][pypi]
[![CI][ci-badge]][ci]
[![Interoperability][interop-badge]][interop]
[![Documentation][docs-badge]][docs]
[![License: LGPL-3.0-or-later][license-badge]][copying]

**An OPC UA client and server for Python, built on asyncio and secure from the first line.**

engiNIR-OPCUA implements OPC UA (IEC 62541, OPC 10000 v1.05) for Python 3.12 and newer: clients, servers,
subscriptions, events, alarms and conditions, history, methods, file transfer, redundancy, certificate management and
experimental PubSub, with a synchronous API and a command line program on top. Encrypted connections, certificate
trust and user roles are switched on by default, and every one of them can be set up in a few lines. Every change is
tested against the OPC Foundation's reference stack.

It is a fork of [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0. The import package is
`enginir_opcua` and the commands start with `enginir-opcua`, so it can be installed next to `asyncua`; the
[migration guide][migration] lists what changed.

## Installation

```bash
uv add enginir-opcua
```

or `pip install enginir-opcua`. The command line program on its own:

```bash
uv tool install enginir-opcua
```

## Quick start

A server and a client with a secure channel between them, in one process. Both create a PKI directory with a
self-signed certificate. Nothing is trusted automatically, so each side copies the other's certificate into its
`trusted/certs` folder (`enginir-opcua pair` does the same on the command line).

```python
import asyncio
import shutil

from enginir_opcua import Client, Server


async def main() -> None:
    url = "opc.tcp://127.0.0.1:4840/enginir-opcua/server/"
    server = Server.quickstart(url, pki="server-pki")
    client = Client.quickstart(url, pki="client-pki")
    await server.init()
    await client.init_pki()
    shutil.copy("client-pki/own/certs/application.der", "server-pki/trusted/certs/client.der")
    shutil.copy("server-pki/own/certs/application.der", "client-pki/trusted/certs/server.der")

    idx = await server.register_namespace("urn:example:quickstart")
    temperature = await server.nodes.objects.add_variable(idx, "Temperature", 21.5)
    async with server, client:
        print(await client.get_node(temperature.nodeid).read_value())


asyncio.run(main())
```

The same with two programs, a users file and the command line is in [A Minimal Server][minimal-server] and
[A Minimal Client][minimal-client].

## Secure by default

- **Encrypted endpoints.** The quick setup offers only SignAndEncrypt with Basic256Sha256, Aes128_Sha256_RsaOaep and
  Aes256_Sha256_RsaPss. An endpoint without security exists only when you ask for it. `Client(url)` without a
  security choice refuses to connect; `Client(url, allow_no_security=True)` is the explicit request.
- **Profiles.** `secure` is the default; `development` (this machine only, no security) and `legacy` (old devices,
  every policy) are your decision, and every weaker setting is logged at start. See [Security Profiles][security].
- **Explicit trust.** Both sides check the peer's certificate at every secure channel, in the order of OPC 10000-4,
  and trust nobody until a certificate is put into the PKI directory.
- **Users and roles.** Anonymous sessions may read, browse and subscribe. Writing, calling methods and changing the
  address space need a user with the right role; passwords are stored as salted hashes.
- **Bounded resources.** Message sizes, sessions, subscriptions, monitored items and queues all have limits, an
  unauthenticated peer can make the server hold only a small message, and inconsistent limits stop the server at
  start.
- **Clear errors.** A wrong setting raises a `ConfigurationError` that names it, and a refused certificate is
  reported with its thumbprint and the command that trusts it.

## Command line

Set up the certificates of a server and a client, make them trust each other, start the server and browse it:

```bash
enginir-opcua init server srv --endpoint opc.tcp://127.0.0.1:4840/enginir-opcua/server/
enginir-opcua init client cli
enginir-opcua pair srv/pki cli/pki
enginir-opcua server --config srv/server.toml &
enginir-opcua ls -u opc.tcp://127.0.0.1:4840/enginir-opcua/server/ --pki-dir cli/pki -n i=85
```

`enginir-opcua` has the subcommands `read`, `write`, `call`, `ls`, `subscribe`, `history`, `discover`, `server`,
`shell` and `generate-structs`, and `init`, `trust`, `pki`, `pair` and `user` to set up certificates and users. The
client commands need `--pki-dir` or `--security`, and `--security None` asks for a connection without security. The
demo server needs `--config`, `--pki-dir` or `--no-security`. See [Installation & CLI Tools][installation].

## Documentation

The documentation is at <https://enginir-opcua.readthedocs.io/en/latest/>.

- [Quick Setup][quick-setup]: profiles, configuration files, users and roles, the trust commands
- [OPC UA Basics][basics]: the terms the documentation uses
- [Client][client], [Server][server], [Synchronous API][sync] and [PubSub][pubsub] (experimental)
- [Examples][examples]: 17 runnable programs in [`examples/`][examples-dir], from a secure pair to alarms, history,
  file transfer and reverse connect
- [Migrating from asyncua][migration], and every change in [CHANGELOG.md][changelog]

Build the documentation locally with `uv run --group docs sphinx-build -b html docs docs/_build/html`.

## Development

```bash
uv sync
git submodule update --init --depth 1 nodeset
uv run pytest -q -m "not slow"
uv run ruff check . && uv run ruff format --check . && uv run mypy enginir_opcua tests
```

The conventions for code and tests are in [AGENTS.md][agents] and [tests/README.md][tests-readme].

## License

LGPL-3.0-or-later; see [COPYING][copying], [COPYING.GPL][copying-gpl] and [NOTICE][notice]. The original library
was written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors; this fork was made on 2026-10-25.

[pypi]: https://pypi.org/project/enginir-opcua/
[pypi-badge]: https://img.shields.io/pypi/v/enginir-opcua
[python-badge]: https://img.shields.io/pypi/pyversions/enginir-opcua
[ci]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/python-package.yml
[ci-badge]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/python-package.yml/badge.svg
[interop]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/interop.yml
[interop-badge]: https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/interop.yml/badge.svg
[docs]: https://enginir-opcua.readthedocs.io/en/latest/
[docs-badge]: https://readthedocs.org/projects/enginir-opcua/badge/?version=latest
[license-badge]: https://img.shields.io/badge/license-LGPL--3.0--or--later-blue
[copying]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/COPYING
[copying-gpl]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/COPYING.GPL
[notice]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/NOTICE
[changelog]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/CHANGELOG.md
[agents]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/AGENTS.md
[tests-readme]: https://github.com/TUstudents/engiNIR-OPCUA/blob/master/tests/README.md
[examples-dir]: https://github.com/TUstudents/engiNIR-OPCUA/tree/master/examples
[migration]: https://enginir-opcua.readthedocs.io/en/latest/migration.html
[minimal-server]: https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/minimal-server.html
[minimal-client]: https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/minimal-client.html
[security]: https://enginir-opcua.readthedocs.io/en/latest/usage/common/security.html
[installation]: https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/installation.html
[quick-setup]: https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/quick-setup.html
[basics]: https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/opc-ua-basics.html
[client]: https://enginir-opcua.readthedocs.io/en/latest/usage/client/overview.html
[server]: https://enginir-opcua.readthedocs.io/en/latest/usage/server/overview.html
[sync]: https://enginir-opcua.readthedocs.io/en/latest/usage/sync/overview.html
[pubsub]: https://enginir-opcua.readthedocs.io/en/latest/usage/pubsub/overview.html
[examples]: https://enginir-opcua.readthedocs.io/en/latest/usage/examples.html
