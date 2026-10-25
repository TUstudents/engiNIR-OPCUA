from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

SCHEMAS_DIR = Path(__file__).resolve().parent
BASE_DIR = SCHEMAS_DIR.parent
NODESET_DIR = BASE_DIR / "nodeset"
TAG_FILE = SCHEMAS_DIR / "nodeset-tag.txt"

GENERATORS = [
    "generate_ids.py",
    "generate_statuscode.py",
    "generate_uaerrors.py",
    "generate_protocol_python.py",
    "generate_address_space.py",
    "generate_event_objects.py",
]


def checkout_tag(tag: str) -> None:
    subprocess.run(["git", "-C", str(BASE_DIR), "submodule", "update", "--init", "nodeset"], check=True)
    subprocess.run(["git", "-C", str(NODESET_DIR), "fetch", "origin", "tag", tag, "--no-tags"], check=True)
    subprocess.run(["git", "-C", str(NODESET_DIR), "checkout", "--detach", f"refs/tags/{tag}"], check=True)
    TAG_FILE.write_text(f"{tag}\n")


def run_generators() -> None:
    for generator in GENERATORS:
        print(f"Running {generator}", flush=True)
        subprocess.run([sys.executable, str(SCHEMAS_DIR / generator)], cwd=BASE_DIR, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Regenerate the code in enginir_opcua from the UA-Nodeset submodule in nodeset/"
    )
    parser.add_argument(
        "--tag",
        help="UA-Nodeset tag to fetch and check out in nodeset/ before generating. "
        "Without it the generators run on the current checkout and git is not touched.",
    )
    args = parser.parse_args()
    if args.tag:
        checkout_tag(args.tag)
    run_generators()
    if args.tag:
        print("Done. Review the diff and commit the changed nodeset submodule, schemas/nodeset-tag.txt and the generated files.")


if __name__ == "__main__":
    main()
