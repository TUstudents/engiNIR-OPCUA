## Regenerating the code from the OPC Foundation UA-Nodeset

The generated code in `enginir_opcua` is built from the `nodeset` git submodule, which is pinned to a tag of
[UA-Nodeset](https://github.com/OPCFoundation/UA-Nodeset). The generated headers name the tag, the core model version
and its publication date, so regenerating from the same checkout always gives the same files.

Move to a new UA-Nodeset release and regenerate:

    uv run python schemas/regenerate.py --tag UA-1.05.07-2026-05-01

This initialises the submodule, fetches the tag, checks it out, records the tag in `schemas/nodeset-tag.txt`, and runs
every generator once, in dependency order. Commit the changed `nodeset` submodule and `nodeset-tag.txt` together with
the regenerated files. The headers take the tag from `nodeset-tag.txt`, so the command without `--tag` needs no network.

Regenerate from the checked-out submodule without touching git (this is what CI runs, followed by
`git diff --exit-code`):

    uv run python schemas/regenerate.py

Both commands work from any directory.

Generators and what they write:

| Generator | Output |
| --- | --- |
| `generate_ids.py` | `enginir_opcua/ua/object_ids.py`, `enginir_opcua/ua/attribute_ids.py` |
| `generate_statuscode.py` | `enginir_opcua/ua/status_codes.py` (adds `StatusCodes_add.csv`) |
| `generate_uaerrors.py` | `enginir_opcua/ua/uaerrors/_auto.py` |
| `generate_protocol_python.py` | `enginir_opcua/ua/uaprotocol_auto.py` |
| `generate_address_space.py` | `enginir_opcua/server/standard_address_space/standard_address_space_services*.py` |
| `generate_event_objects.py` | `enginir_opcua/common/event_objects.py` |

`nodeset_source.py` holds the paths into the submodule and the header text. `generate_model_from_nodeset.py` and
`generate_model_event.py` are libraries used by the generators.

Warnings:
- Don't put your own nodesets into `nodeset/`. Keep them in a separate folder.
- Questions and bugs with the generators: https://github.com/TUstudents/engiNIR-OPCUA/issues
