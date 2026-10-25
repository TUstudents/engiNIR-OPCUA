from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
NODESET_DIR = BASE_DIR / "nodeset"
SCHEMA_DIR = NODESET_DIR / "Schema"
CORE_NODESET = SCHEMA_DIR / "Opc.Ua.NodeSet2.xml"
SERVICES_NODESET = SCHEMA_DIR / "Opc.Ua.NodeSet2.Services.xml"
NODE_IDS_CSV = SCHEMA_DIR / "NodeIds.csv"
ATTRIBUTE_IDS_CSV = SCHEMA_DIR / "AttributeIds.csv"
STATUS_CODE_CSV = SCHEMA_DIR / "StatusCode.csv"
TAG_FILE = Path(__file__).resolve().parent / "nodeset-tag.txt"


def nodeset_tag() -> str:
    return TAG_FILE.read_text().strip()


def core_model() -> tuple[str, str]:
    for _, element in ET.iterparse(CORE_NODESET):
        if element.tag.endswith("Model"):
            return element.attrib["Version"], element.attrib["PublicationDate"]
    raise RuntimeError(f"No <Model> element found in {CORE_NODESET}")


def provenance() -> str:
    version, publication_date = core_model()
    return f"UA-Nodeset tag {nodeset_tag()}, core model {version} published {publication_date}"
