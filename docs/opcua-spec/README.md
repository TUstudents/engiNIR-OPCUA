# OPC UA specification reference

This library implements the OPC UA core specification, **OPC 10000**. The baseline is **v1.05**. Peers that implement **v1.04** must keep working, so where the two editions conflict we accept what either allows on input and send what 1.05 requires.

## Why the specifications are not in this repository

The specifications are copyrighted by the OPC Foundation. The [OPC Foundation Specifications Agreement of Use](https://opcfoundation.org/license/specifications/1.15/) forbids copying and redistributing them: every copy has to be obtained individually from the OPC Foundation website. So the text is never committed here, and `downloads/` is git-ignored.

Downloading a specification counts as accepting that agreement. It allows you to download and reproduce the specifications for internal use, to the extent reasonably necessary to implement them.

## Getting a local copy

```
python docs/opcua-spec/fetch_specs.py download          # Parts 1-14, current edition and v1.04 (~6 MB)
python docs/opcua-spec/fetch_specs.py show 6 5.2.2.12   # print a section of the current edition
python docs/opcua-spec/fetch_specs.py show 6 5.2.2.12 --edition v1.04
```

The script downloads the OPC Foundation's official Markdown export of each part into `docs/opcua-spec/downloads/`. `show` prints a single section, which makes it easy to compare code with the spec text or with the other edition.

## Editions

The online reference serves the current 1.05 edition and **1.04** (published 2017-11-22) for every part. Earlier editions (1.00–1.03) and the intermediate 1.05.x releases aren't available online. The generated code in `enginir_opcua/ua` and `enginir_opcua/server/standard_address_space` was built from [UA-Nodeset](https://github.com/OPCFoundation/UA-Nodeset) tag **`UA-1.05.07-2026-05-01`** (core model 1.05.07, published 2026-05-01). The `nodeset` submodule is pinned to that tag, and `schemas/regenerate.py` regenerates the code from it.

| Part | Title | Current | v1.04 |
|---|---|---|---|
| 1 | Overview and Concepts | [1.05.06](https://reference.opcfoundation.org/specs/OPC-10000-1) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-1/v1.04) |
| 2 | Security Model | [1.05.06](https://reference.opcfoundation.org/specs/OPC-10000-2) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-2/v1.04) |
| 3 | Address Space Model | [1.05.06](https://reference.opcfoundation.org/specs/OPC-10000-3) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-3/v1.04) |
| 4 | Services | [1.05.07](https://reference.opcfoundation.org/specs/OPC-10000-4) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-4/v1.04) |
| 5 | Information Model | [1.05.06](https://reference.opcfoundation.org/specs/OPC-10000-5) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-5/v1.04) |
| 6 | Mappings (encodings, transport, secure channel) | [1.05.07](https://reference.opcfoundation.org/specs/OPC-10000-6) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-6/v1.04) |
| 7 | Profiles | [1.05.02](https://reference.opcfoundation.org/specs/OPC-10000-7) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-7/v1.04) |
| 8 | Data Access | [1.05.07](https://reference.opcfoundation.org/specs/OPC-10000-8) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-8/v1.04) |
| 9 | Alarms and Conditions | [1.05.06](https://reference.opcfoundation.org/specs/OPC-10000-9) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-9/v1.04) |
| 10 | Programs | [1.05.00](https://reference.opcfoundation.org/specs/OPC-10000-10) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-10/v1.04) |
| 11 | Historical Access | [1.05.04](https://reference.opcfoundation.org/specs/OPC-10000-11) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-11/v1.04) |
| 12 | Discovery and Global Services | [1.05.07](https://reference.opcfoundation.org/specs/OPC-10000-12) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-12/v1.04) |
| 13 | Aggregates | [1.05.07](https://reference.opcfoundation.org/specs/OPC-10000-13) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-13/v1.04) |
| 14 | PubSub | [1.05.06](https://reference.opcfoundation.org/specs/OPC-10000-14) | [1.04](https://reference.opcfoundation.org/specs/OPC-10000-14/v1.04) |

The "current" column shows the editions served when this table was written (2026-10). The links always go to the latest edition.

File Transfer (`FileType`, `FileDirectoryType`) is Part 5, Annex C in 1.04 and moved to its own part, [OPC 10000-20](https://reference.opcfoundation.org/specs/OPC-10000-20), in 1.05. Download it with `fetch_specs.py download --parts 20 --editions current`.

The 1.05 Part 7 only defines how profiles are structured. The profiles themselves are maintained in the online database at [profiles.opcfoundation.org](https://profiles.opcfoundation.org/). The 1.04 Part 7 still contains the full profile tables.
