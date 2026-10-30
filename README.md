# engiNIR-OPCUA

OPC UA / IEC 62541 client and server library for Python 3.12+, built on asyncio.

This repository is a fork of [FreeOpcUa/opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0, made on 2026-10-25. The original library was written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors.

License: LGPL-3.0-or-later. See [COPYING](COPYING), [COPYING.GPL](COPYING.GPL) and [NOTICE](NOTICE).

## Installation

The package is [`enginir-opcua`](https://pypi.org/project/enginir-opcua/) on PyPI:

```bash
uv add enginir-opcua
```

The breaking changes from `asyncua` 2.x are listed in [CHANGELOG.md](CHANGELOG.md).

## Quick start

A secure server and client in one process. Both create a PKI directory with a self-signed certificate; each side then
has to trust the other's certificate, which nothing does automatically (`enginir-opcua pair` does it on the command
line).

```python
import asyncio
import shutil
from pathlib import Path

from enginir_opcua import Client, Server
from enginir_opcua.crypto import pki


async def main() -> None:
    url = "opc.tcp://127.0.0.1:4840/enginir-opcua/server/"
    server = Server.quickstart(url, pki="server-pki")
    client = Client.quickstart(url, pki="client-pki")
    await server.init()
    pki.create_directories(Path("client-pki"))
    await pki.load_own_credentials(
        Path("client-pki"), application_uri=client.application_uri, host_names=["localhost"], usage=pki.CLIENT_USAGE
    )
    shutil.copy("client-pki/own/certs/application.der", "server-pki/trusted/certs/client.der")
    shutil.copy("server-pki/own/certs/application.der", "client-pki/trusted/certs/server.der")

    idx = await server.register_namespace("urn:example:quickstart")
    temperature = await server.nodes.objects.add_variable(idx, "Temperature", 21.5)
    async with server, client:
        print(await client.get_node(temperature.nodeid).read_value())


asyncio.run(main())
```

Profiles, users and roles, configuration files, the `enginir-opcua init`, `trust`, `pki`, `pair` and `user` commands
and the 16 runnable examples in [`examples/`](examples) are described in
[Quick Setup](docs/usage/get-started/quick-setup.rst).

## Development

```bash
uv sync
git submodule update --init --depth 1 nodeset
uv run pytest -q
uv run ruff check . && uv run ruff format --check . && uv run mypy enginir_opcua tests
```
