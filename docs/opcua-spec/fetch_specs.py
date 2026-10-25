"""Download the OPC UA core specifications and look up sections in them.

The specifications are copyrighted by the OPC Foundation and may not be redistributed,
so they are never committed. Every user downloads a personal copy from
reference.opcfoundation.org into ``downloads/`` (git-ignored). Downloading accepts the
OPC Foundation Specifications Agreement of Use, see README.md.

    python docs/opcua-spec/fetch_specs.py download                 # parts 1-14, current and v1.04
    python docs/opcua-spec/fetch_specs.py download --parts 4 6 --editions v1.04
    python docs/opcua-spec/fetch_specs.py show 6 5.2.2.12          # current edition
    python docs/opcua-spec/fetch_specs.py show 6 5.2.2.12 --edition v1.04
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

BASE_URL = "https://reference.opcfoundation.org"
DOWNLOADS = Path(__file__).resolve().parent / "downloads"
DEFAULT_PARTS = list(range(1, 15))
DEFAULT_EDITIONS = ["current", "v1.04"]
SECTION_NUMBER = re.compile(r"^((?:\d+|[A-Z](?=\.\d))(?:\.\d+)*) [A-Z][^.]{0,150}$")


def _get(url: str) -> tuple[bytes, str]:
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read(), response.headers.get("Content-Disposition", "")


def _markdown_url(part: int, edition: str) -> str:
    landing = f"{BASE_URL}/specs/OPC-10000-{part}" + ("" if edition == "current" else f"/{edition}")
    page = _get(landing)[0].decode("utf-8", "ignore")
    match = re.search(r'href="(/specs/OPC-10000-%d/v[\d.]+/t\d+/download/markdown)"' % part, page)
    if match is None:
        raise LookupError(f"no Markdown download link on {landing}")
    return BASE_URL + match.group(1)


def download(parts: list[int], editions: list[str]) -> None:
    DOWNLOADS.mkdir(exist_ok=True)
    for part in parts:
        for edition in editions:
            try:
                body, disposition = _get(_markdown_url(part, edition))
            except (urllib.error.HTTPError, LookupError) as exc:
                print(f"Part {part} {edition}: not available ({exc})")
                continue
            match = re.search(r'filename="([^"]+)"', disposition)
            name = match.group(1) if match else f"OPC-10000-{part}-{edition}.md"
            (DOWNLOADS / name).write_bytes(body)
            print(f"Part {part} {edition}: {name} ({len(body) // 1024} KiB)")


def _edition_file(part: int, edition: str) -> Path:
    files = sorted(DOWNLOADS.glob(f"OPC-10000-{part}-v*.md"))
    if edition != "current":
        files = [f for f in files if f.stem.endswith(f"-{edition}")]
    else:
        files = [f for f in files if not f.stem.endswith("-v1.04")]
    if not files:
        raise FileNotFoundError(f"Part {part} {edition} is not downloaded; run the download command first")
    return files[-1]


def _is_inside(candidate: str, section: str) -> bool:
    return candidate == section or candidate.startswith(f"{section}.")


def show(part: int, section: str, edition: str, max_lines: int) -> None:
    path = _edition_file(part, edition)
    lines = path.read_text(encoding="utf-8").splitlines()
    start = next(
        (i for i, line in enumerate(lines) if (m := SECTION_NUMBER.match(line)) and m.group(1) == section), None
    )
    if start is None:
        sys.exit(f"section {section} not found in {path.name}")
    end = next(
        (
            i
            for i in range(start + 1, len(lines))
            if (m := SECTION_NUMBER.match(lines[i])) and not _is_inside(m.group(1), section)
        ),
        len(lines),
    )
    print(f"[{path.stem} {section}]")
    print("\n".join(lines[start : min(end, start + max_lines)]))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch = commands.add_parser("download", help="download the Markdown edition of each part")
    fetch.add_argument("--parts", type=int, nargs="+", default=DEFAULT_PARTS)
    fetch.add_argument("--editions", nargs="+", default=DEFAULT_EDITIONS, help="'current' and/or 'v1.04'")
    lookup = commands.add_parser("show", help="print one section of a downloaded part")
    lookup.add_argument("part", type=int)
    lookup.add_argument("section", help="section number, e.g. 5.2.2.12 or A.2")
    lookup.add_argument("--edition", default="current", help="'current' or 'v1.04'")
    lookup.add_argument("--lines", type=int, default=200, help="maximum number of lines to print")
    args = parser.parse_args()
    if args.command == "download":
        download(args.parts, args.editions)
    else:
        show(args.part, args.section, args.edition, args.lines)


if __name__ == "__main__":
    main()
