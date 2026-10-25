# engiNIR-OPCUA

OPC UA / IEC 62541 client and server library for Python 3.12+, built on asyncio.

This repository is a fork of [FreeOpcUa/opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) 2.1.0, made on 2026-10-25. The original library was written by Olivier Roulet-Dubonnet and the opcua-asyncio contributors.

**A new package, `enginir-opcua`, is coming soon.** It isn't on PyPI yet, and the code is being reworked, so expect breaking changes. Until then, use upstream [`asyncua`](https://pypi.org/project/asyncua/) for production.

License: LGPL-3.0-or-later. See [COPYING](COPYING), [COPYING.GPL](COPYING.GPL) and [NOTICE](NOTICE).

## Development

```bash
uv sync
git submodule update --init --depth 1 nodeset
uv run pytest -q
uv run ruff check . && uv run ruff format --check . && uv run mypy enginir_opcua tests
```
