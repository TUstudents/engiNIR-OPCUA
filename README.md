# engiNIR-OPCUA

[![PyPI](https://img.shields.io/pypi/v/enginir-opcua)](https://pypi.org/project/enginir-opcua/)
[![Python](https://img.shields.io/pypi/pyversions/enginir-opcua)](https://pypi.org/project/enginir-opcua/)
[![CI](https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/python-package.yml/badge.svg)](https://github.com/TUstudents/engiNIR-OPCUA/actions/workflows/python-package.yml)
[![Documentation](https://readthedocs.org/projects/enginir-opcua/badge/?version=latest)](https://enginir-opcua.readthedocs.io/en/latest/)
[![License: LGPL-3.0-or-later](https://img.shields.io/badge/license-LGPL--3.0--or--later-blue)](https://github.com/TUstudents/engiNIR-OPCUA/blob/master/COPYING)

**An OPC UA client and server for Python, built on asyncio and secure from the first line.**

engiNIR-OPCUA implements OPC UA (IEC 62541) for Python 3.12 and newer: clients, servers, subscriptions, events,
alarms and conditions, history, methods, file transfer, redundancy, certificate management and PubSub, with a
synchronous API and a command line program on top. Encrypted connections, certificate trust and user roles are
switched on by default, and every one of them can be set up in a few lines.

It is a fork of [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0. The import package is
`enginir_opcua` and the commands start with `enginir-opcua`, so it can be installed next to `asyncua`.

## Installation

```bash
uv add enginir-opcua
```

The command line program on its own:

```bash
uv tool install enginir-opcua
```

## Quick start

A server and a client with a secure channel between them, in one process. Both create a PKI directory with a
self-signed certificate; nothing is trusted automatically, so each side copies the other's certificate into its
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

The same with two programs, a users file and the command line is in
[A Minimal Server](https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/minimal-server.html) and
[A Minimal Client](https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/minimal-client.html).

## Secure by default

- **Encrypted endpoints.** The quick setup offers only SignAndEncrypt with Basic256Sha256, Aes128_Sha256_RsaOaep and
  Aes256_Sha256_RsaPss. An endpoint without security exists only when you ask for it.
- **Explicit trust.** Both sides check the peer's certificate at every secure channel, in the order of OPC 10000-4,
  and trust nobody until a certificate is put into the PKI directory.
- **Users and roles.** Anonymous sessions may read, browse and subscribe. Writing, calling methods and changing the
  address space need a user with the right role; passwords are stored as salted hashes.
- **Clear errors.** A wrong setting raises a `ConfigurationError` that names it, and a refused certificate is
  reported with its thumbprint and the command that trusts it.

## Command line

Set up the certificates of a server and a client, make them trust each other, and browse the server once it runs:

```bash
enginir-opcua init server srv --endpoint opc.tcp://127.0.0.1:4840/enginir-opcua/server/
enginir-opcua init client cli --application-uri urn:enginir:opcua:client
enginir-opcua pair srv/pki cli/pki
enginir-opcua ls -u opc.tcp://127.0.0.1:4840/enginir-opcua/server/ --pki-dir cli/pki \
    --security Basic256Sha256,SignAndEncrypt -n i=85
```

`enginir-opcua` has the subcommands `read`, `write`, `call`, `ls`, `subscribe`, `history`, `discover`, `server`,
`shell` and `generate-structs`, and `init`, `trust`, `pki`, `pair` and `user` to set up certificates and users. See
[Installation & CLI Tools](https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/installation.html).

## Documentation

The documentation is at <https://enginir-opcua.readthedocs.io/en/latest/>.

- [Quick Setup](https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/quick-setup.html): profiles, configuration files, users and roles, the trust
  commands
- [OPC UA Basics](https://enginir-opcua.readthedocs.io/en/latest/usage/get-started/opc-ua-basics.html): the terms the documentation uses
- [Client](https://enginir-opcua.readthedocs.io/en/latest/usage/client/overview.html), [Server](https://enginir-opcua.readthedocs.io/en/latest/usage/server/overview.html),
  [Synchronous API](https://enginir-opcua.readthedocs.io/en/latest/usage/sync/overview.html) and [PubSub](https://enginir-opcua.readthedocs.io/en/latest/usage/pubsub/overview.html) (experimental)
- [Examples](https://enginir-opcua.readthedocs.io/en/latest/usage/examples.html): 16 runnable programs in [`examples/`](https://github.com/TUstudents/engiNIR-OPCUA/tree/master/examples), from a secure pair to alarms,
  history, file transfer and reverse connect
- [Migrating from asyncua](https://enginir-opcua.readthedocs.io/en/latest/migration.html), and every change in [CHANGELOG.md](https://github.com/TUstudents/engiNIR-OPCUA/blob/master/CHANGELOG.md)

Build the documentation locally with `uv run --group docs sphinx-build -b html docs docs/_build/html`.

## Development

```bash
uv sync
git submodule update --init --depth 1 nodeset
uv run pytest -q -m "not slow"
uv run ruff check . && uv run ruff format --check . && uv run mypy enginir_opcua tests
```

The conventions for code and tests are in [AGENTS.md](https://github.com/TUstudents/engiNIR-OPCUA/blob/master/AGENTS.md) and [tests/README.md](https://github.com/TUstudents/engiNIR-OPCUA/blob/master/tests/README.md).

## License

LGPL-3.0-or-later; see [COPYING](https://github.com/TUstudents/engiNIR-OPCUA/blob/master/COPYING), [COPYING.GPL](https://github.com/TUstudents/engiNIR-OPCUA/blob/master/COPYING.GPL) and [NOTICE](https://github.com/TUstudents/engiNIR-OPCUA/blob/master/NOTICE). The original library was
written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors; this fork was made on 2026-10-25.
