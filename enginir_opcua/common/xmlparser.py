"""
parse xml file from enginir_opcua-spec
"""

import asyncio
import base64
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from dateutil.tz import tzutc

from enginir_opcua import ua

from .ua_utils import string_to_val

XSI_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"
NODE_TAGS = frozenset(
    ("UAObject", "UAVariable", "UAMethod", "UAView", "UAObjectType", "UAVariableType", "UADataType", "UAReferenceType")
)
INTEGER_TYPES = {
    "SByte": (-(2**7), 2**7 - 1),
    "Int16": (-(2**15), 2**15 - 1),
    "Int32": (-(2**31), 2**31 - 1),
    "Int64": (-(2**63), 2**63 - 1),
    "Byte": (0, 2**8 - 1),
    "UInt16": (0, 2**16 - 1),
    "UInt32": (0, 2**32 - 1),
    "UInt64": (0, 2**64 - 1),
}
FLOAT_SPELLINGS = {"INF": float("inf"), "-INF": float("-inf"), "+INF": float("inf"), "NaN": float("nan")}
NULL_DATETIME = datetime(1, 1, 1, tzinfo=UTC)


def xs_boolean(text: str) -> bool:
    """
    Parse an xs:boolean: true, false, 1 or 0 (Part 6, 5.3.1.2). Anything else raises ValueError.
    """
    value = text.strip()
    if value in ("true", "1"):
        return True
    if value in ("false", "0"):
        return False
    raise ValueError(f"'{text}' is not an xs:boolean")


def xs_integer(text: str, type_name: str) -> int:
    value = int(text.strip())
    low, high = INTEGER_TYPES[type_name]
    if not low <= value <= high:
        raise ValueError(f"{value} is out of range for {type_name}")
    return value


def xs_float(text: str) -> float:
    value = text.strip()
    if value in FLOAT_SPELLINGS:
        return FLOAT_SPELLINGS[value]
    if value.lower() in ("inf", "-inf", "nan", "infinity", "-infinity"):
        raise ValueError(f"'{text}' is not an xs:double")
    return float(value)


def xs_datetime(text: str) -> datetime:
    """
    Parse an xs:dateTime. A value without a time zone is UTC. The earliest representable value is the null DateTime
    (Part 6, 5.3.1.6).
    """
    value = text.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as ex:
        raise ValueError(f"'{text}' is not an xs:dateTime") from ex
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(tzutc())


def parse_scalar(text: str, type_name: str | type) -> Any:
    """
    Convert the text of an XML element to the Python value of a built-in type or enumeration (Part 6, 5.3.1, 5.3.3).
    """
    if isinstance(type_name, type) and issubclass(type_name, Enum):
        value = text.strip()
        number = int(value) if value.lstrip("-").isdigit() else int(value.rsplit("_", 1)[1])
        return type_name(number)
    name = type_name if isinstance(type_name, str) else type_name.__name__
    if name == "Boolean":
        return xs_boolean(text)
    if name in INTEGER_TYPES:
        return xs_integer(text, name)
    if name in ("Float", "Double"):
        return xs_float(text)
    if name == "DateTime":
        return xs_datetime(text)
    if name in ("String", "CharArray"):
        return text
    if name == "ByteString":
        return base64.b64decode("".join(text.split()))
    if name == "Guid":
        return uuid.UUID(text.strip())
    if hasattr(ua.VariantType, name):
        return string_to_val(text, getattr(ua.VariantType, name))
    if hasattr(ua, name):
        return string_to_val(text, getattr(ua, name))
    raise ValueError(f"cannot convert '{text}' to {name}")


def ua_type_to_python(val: str, uatype_as_str: str) -> Any:
    """
    Converts a string value to a python value according to ua_utils.
    """
    return parse_scalar(val, uatype_as_str)


def _to_bool(val: str) -> bool:
    return xs_boolean(val)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class NodeData:
    def __init__(self):
        self.nodetype = None
        self.nodeid = None
        self.browsename = None
        self.displayname = None
        self.has_displayname = False
        self.symname = None
        self.parent = None
        self.parent_attr = None
        self.parentlink = None
        self.desc = ""
        self.typedef = None
        self.refs = []
        self.nodeclass = None
        self.eventnotifier = 0
        self.design_tool_only = False
        self.writemask = None
        self.containsnoloops = None

        # variable
        self.datatype = None
        self.rank = -1  # check default value
        self.value = None
        self.valuetype = None
        self.dimensions = None
        self.accesslevel = None
        self.useraccesslevel = None
        self.minsample = None
        self.historizing = False

        # method
        self.executable = None
        self.userexecutable = None

        # referencetype
        self.inversename = ""
        self.abstract = False
        self.symmetric = False

        # datatype
        self.definitions = []
        self.struct_type = ""
        self.option_set = False
        self.has_definition = False

    def __str__(self):
        return f"NodeData(nodeid:{self.nodeid})"

    __repr__ = __str__


def _array_dimensions(text: str | None) -> list[int] | None:
    if text is None or not text.strip():
        return None
    return [int(i) for i in text.split(",")]


class Field:
    def __init__(self, data):
        self.datatype = data.get("DataType", "i=24")  # Default is BaseDataType
        self.name = data.get("Name")
        self.dname = data.get("DisplayName", "")
        self.optional = xs_boolean(data.get("IsOptional", "false"))
        self.allow_subtypes = xs_boolean(data.get("AllowSubTypes", "false"))
        self.valuerank = int(data.get("ValueRank", -1))
        self.arraydim = data.get("ArrayDimensions", None)
        self.value = int(data.get("Value", -1))
        self.desc = data.get("Description", "")
        self.max_str_len = int(data.get("MaxStringLength", 0))


class RefStruct:
    def __init__(self):
        self.reftype = None
        self.forward = True
        self.target = None

    def __str__(self):
        return f"RefStruct({self.reftype, self.forward, self.target})"

    __repr__ = __str__


class ExtObj:
    def __init__(self):
        self.typeid = None
        self.objname = None
        self.bodytype = None
        self.body = {}
        self.body_namespace = None

    def __str__(self):
        return f"ExtObj({self.objname}, {self.body})"

    __repr__ = __str__


def _choose_localized(entries: list[tuple[str, str | None]]) -> str | None:
    for locale, text in entries:
        if not locale:
            return text
    return entries[0][1] if entries else None


class XMLParser:
    def __init__(self, keep_empty_body_values: bool = False):
        self.keep_empty_body_values = keep_empty_body_values
        self.logger = logging.getLogger(__name__)
        self._retag = re.compile(r"(\{.*\})?(.*)")
        self.root = None
        self.ns = {
            "base": "http://opcfoundation.org/UA/2011/03/UANodeSet.xsd",
            "uax": "http://opcfoundation.org/UA/2008/02/Types.xsd",
            "xsd": "http://www.w3.org/2001/XMLSchema",
            "xsi": "http://www.w3.org/2001/XMLSchema-instance",
        }

    async def parse(self, xmlpath=None, xmlstring=None):
        if xmlstring:
            self.root = ET.fromstring(xmlstring)
        else:
            tree = await asyncio.get_running_loop().run_in_executor(None, ET.parse, xmlpath)
            self.root = tree.getroot()

    def parse_sync(self, xmlpath=None, xmlstring=None):
        if xmlstring:
            self.root = ET.fromstring(xmlstring)
        else:
            tree = ET.parse(xmlpath)
            self.root = tree.getroot()

    def _children(self, name: str) -> list[ET.Element]:
        assert self.root is not None
        for child in self.root:
            if local_name(child.tag) == name:
                return list(child)
        return []

    def get_used_namespaces(self):
        """
        Return the used namespace uris in this import file
        """
        return [ns_element.text for ns_element in self._children("NamespaceUris")]

    def get_used_servers(self) -> list[str]:
        return [el.text for el in self._children("ServerUris")]

    def get_aliases(self) -> dict:
        """
        Return the used node aliases in this import file
        """
        return {el.attrib["Alias"]: el.text for el in self._children("Aliases")}

    def get_node_datas(self):
        nodes = []
        for child in self.root:
            tag = local_name(child.tag)
            if tag in NODE_TAGS:
                nodes.append(self._parse_node(tag, child))
            else:
                self.logger.debug("Skipping element %s: it does not define a node", tag)
        return nodes

    def _parse_node(self, nodetype, child):
        """
        Parse a XML node and create a NodeData object.
        """
        obj = NodeData()
        obj.nodetype = nodetype
        for key, val in child.attrib.items():
            self._set_attr(key, val, obj)
        self.logger.debug("Parsing node: %s %s", obj.nodeid, obj.browsename)
        obj.displayname = obj.browsename  # give a default value to display name
        names: list[tuple[str, str | None]] = []
        descriptions: list[tuple[str, str | None]] = []
        for el in child:
            tag = local_name(el.tag)
            if tag == "DisplayName":
                names.append((el.attrib.get("Locale", ""), el.text))
            elif tag == "Description":
                descriptions.append((el.attrib.get("Locale", ""), el.text))
            else:
                self._parse_attr(el, obj)
        if names:
            obj.displayname = _choose_localized(names)
            obj.has_displayname = True
        if descriptions:
            obj.desc = _choose_localized(descriptions)
        return obj

    def _set_attr(self, key, val, obj):
        if key == "NodeId":
            obj.nodeid = val
        elif key == "BrowseName":
            obj.browsename = val
        elif key == "SymbolicName":
            obj.symname = val
        elif key == "ParentNodeId":
            obj.parent = val
            obj.parent_attr = val
        elif key == "DataType":
            obj.datatype = val
        elif key == "IsAbstract":
            obj.abstract = xs_boolean(val)
        elif key == "Executable":
            obj.executable = xs_boolean(val)
        elif key == "UserExecutable":
            obj.userexecutable = xs_boolean(val)
        elif key == "EventNotifier":
            obj.eventnotifier = int(val)
        elif key == "ValueRank":
            obj.rank = int(val)
        elif key == "ArrayDimensions":
            obj.dimensions = _array_dimensions(val)
        elif key == "MinimumSamplingInterval":
            obj.minsample = xs_float(val)
        elif key == "AccessLevel":
            obj.accesslevel = int(val)
        elif key == "UserAccessLevel":
            obj.useraccesslevel = int(val)
        elif key == "WriteMask":
            obj.writemask = int(val)
        elif key == "ContainsNoLoops":
            obj.containsnoloops = xs_boolean(val)
        elif key == "Symmetric":
            obj.symmetric = xs_boolean(val)
        elif key == "Historizing":
            obj.historizing = xs_boolean(val)
        elif key == "DesignToolOnly":
            obj.design_tool_only = xs_boolean(val)
        else:
            self.logger.info("Attribute not implemented: %s:%s", key, val)

    def _parse_attr(self, el, obj):
        tag = local_name(el.tag)

        if tag == "References":
            self._parse_refs(el, obj)
        elif tag == "Value":
            self._parse_contained_value(el, obj)
        elif tag == "InverseName":
            obj.inversename = el.text
        elif tag == "Definition":
            if xs_boolean(el.attrib.get("IsUnion", "false")):
                obj.struct_type = "IsUnion"
            elif xs_boolean(el.attrib.get("IsOptional", "false")):
                obj.struct_type = "IsOptional"
            obj.option_set = xs_boolean(el.attrib.get("IsOptionSet", "false"))
            obj.has_definition = True
            for field in el:
                obj.definitions.append(self._parse_field(field))
        elif tag in ("Documentation", "Category", "Extensions", "RolePermissions", "Translation"):
            pass
        else:
            self.logger.info("Not implemented tag: %s", el)

    def _parse_field(self, el):
        field = Field(el.attrib)
        names: list[tuple[str, str | None]] = []
        descriptions: list[tuple[str, str | None]] = []
        for child in el:
            tag = local_name(child.tag)
            if tag == "DisplayName":
                names.append((child.attrib.get("Locale", ""), child.text))
            elif tag == "Description":
                descriptions.append((child.attrib.get("Locale", ""), child.text))
        if names:
            field.dname = _choose_localized(names) or ""
        if descriptions:
            field.desc = _choose_localized(descriptions) or ""
        return field

    def _parse_contained_value(self, el, obj):
        """
        Parse the child of el as a constant.
        """
        val_el = next(iter(el), None)
        self._parse_value(val_el, obj)

    def _parse_value(self, val_el, obj):
        """
        Parse the node val_el as a constant.
        """
        if val_el is None:
            obj.valuetype = "Null"
            obj.value = None
            return
        ntag = local_name(val_el.tag)
        obj.valuetype = ntag
        if val_el.attrib.get(XSI_NIL, "false") in ("true", "1"):
            obj.value = None
        elif ntag in INTEGER_TYPES or ntag in ("Boolean", "Float", "Double", "DateTime", "ByteString"):
            obj.value = self._scalar(val_el, ntag)
        elif ntag in ("String", "XmlElement"):
            mytext = val_el.text or ""
            obj.value = ua.XmlElement(mytext) if ntag == "XmlElement" else mytext
        elif ntag == "Guid":
            obj.value = self._child_text(val_el, "String")
        elif ntag == "NodeId":
            obj.value = self._child_text(val_el, "Identifier")
        elif ntag == "ExpandedNodeId":
            identifier = self._child_text(val_el, "Identifier")
            if identifier is not None:
                obj.value = ua.NodeId.from_string(identifier)
                if not isinstance(obj.value, ua.ExpandedNodeId):
                    obj.value = ua.ExpandedNodeId(obj.value.Identifier, obj.value.NamespaceIndex)
        elif ntag == "ExtensionObject":
            obj.value = self._parse_ext_obj(val_el)
        elif ntag == "LocalizedText":
            obj.value = self._parse_body(val_el)
        elif ntag == "ListOfLocalizedText":
            obj.value = self._parse_list_of_localized_text(val_el)
        elif ntag == "ListOfExtensionObject":
            obj.value = self._parse_list_of_extension_object(val_el)
        elif ntag == "StatusCode":
            code = self._child_text(val_el, "Code")
            obj.value = ua.StatusCode(xs_integer(code if code is not None else "0", "UInt32"))
        elif ntag == "QualifiedName":
            obj.value = self._parse_qualifed_name(val_el)
        elif ntag == "Matrix":
            obj.value = self._parse_matrix(val_el)
        elif ntag.startswith("ListOf"):
            obj.value = []
            for item in val_el:
                tmp = NodeData()
                self._parse_value(item, tmp)
                obj.value.append(tmp.value)
        else:
            raise ValueError(f"Parsing value of type '{ntag}' is not implemented")

    def _scalar(self, el, ntag: str) -> Any:
        if not (el.text or "").strip():
            return b"" if ntag == "ByteString" else None
        return parse_scalar(el.text, ntag)

    def _child_text(self, el, name: str) -> str | None:
        for child in el:
            if local_name(child.tag) == name:
                return child.text
        return None

    def _parse_matrix(self, el) -> tuple[list[int], str, list]:
        dimensions: list[int] = []
        elements: list = []
        element_type = "Null"
        for child in el:
            tag = local_name(child.tag)
            if tag == "Dimensions":
                dimensions = [xs_integer(item.text or "0", "Int32") for item in child]
            elif tag == "Elements":
                for item in child:
                    tmp = NodeData()
                    self._parse_value(item, tmp)
                    element_type = tmp.valuetype
                    elements.append(tmp.value)
        return dimensions, element_type, elements

    def _get_text(self, el):
        txtlist = [txt.strip() for txt in el.itertext()]
        return "".join(txtlist)

    def _parse_list_of_localized_text(self, el):
        value = []
        for localized_text in el:
            mylist = self._parse_body(localized_text)
            # each localized text is in a dictionary with "Locale" and "Text" keys
            item = {"Text": None, "Locale": None}
            for name, val in mylist:
                item.update({str(name): val})
            # value is an array of dictionaries with localized texts
            value.append(item)
        return value

    def _parse_list_of_extension_object(self, el):
        """
        Parse an uax:ListOfExtensionObject Value
        Return a list of ExtObj
        """
        return [self._parse_ext_obj(extension_object) for extension_object in el]

    def _parse_ext_obj(self, el):
        ext = ExtObj()
        for extension_object_part in el:
            ntag = local_name(extension_object_part.tag)
            if ntag == "TypeId":
                ext.typeid = self._get_text(extension_object_part)
            elif ntag == "Body":
                inner = next(iter(extension_object_part), None)
                if inner is None:
                    continue
                ext.objname = local_name(inner.tag)
                ext.body_namespace = inner.tag[1:].split("}")[0] if inner.tag.startswith("{") else None
                if ext.objname == "ByteString":
                    ext.body = base64.b64decode("".join((inner.text or "").split()))
                else:
                    ext.body = self._parse_body(extension_object_part)
            else:
                self.logger.warning("Unknown ntag: %s", ntag)
        return ext

    def _parse_body(self, el):
        body = []
        for body_item in el:
            otag = local_name(body_item.tag)
            if len(body_item):
                body.append((otag, self._parse_body(body_item)))
            else:
                text = self._get_text(body_item)
                if text or self.keep_empty_body_values:
                    body.append((otag, text))
        return body

    def _parse_qualifed_name(self, el):
        name = self._child_text(el, "Name")
        namespace = self._child_text(el, "NamespaceIndex")
        return ua.QualifiedName(name, xs_integer(namespace, "UInt16") if namespace is not None else 0)

    def _parse_refs(self, el, obj):
        parent, parentlink = obj.parent, None

        for ref in el:
            struct = RefStruct()
            struct.forward = xs_boolean(ref.attrib.get("IsForward", "true"))
            struct.target = ref.text
            struct.reftype = ref.attrib["ReferenceType"]
            obj.refs.append(struct)

            if ref.attrib["ReferenceType"] == "HasTypeDefinition":
                obj.typedef = ref.text
            elif not struct.forward:
                parent, parentlink = struct.target, struct.reftype
                if obj.parent == parent or (obj.parent != parent and not obj.parentlink):
                    obj.parentlink = parentlink

        if obj.parent and not obj.parentlink:
            # the case of asimple parent attribute without any reverse link
            obj.parentlink = "HasComponent"
        if not obj.parent:
            obj.parent, obj.parentlink = parent, parent and parentlink
        if not obj.parent:
            self.logger.info("Could not find parent for node '%s'", obj.nodeid)

    @staticmethod
    def list_required_models(xmlpath, xmlstring):
        """
        Try getting required XML Models, before parsing NodeSet
        """
        if xmlpath:
            tree = ET.parse(xmlpath)
        else:
            tree = ET.fromstring(xmlstring)
        required_models = []

        for child in tree.iter():
            if child.tag.endswith("RequiredModel"):
                # check if ModelUri X, in Version Y from time Z was already imported
                required_models.append(child.attrib)
        return required_models

    def get_nodeset_namespaces(self) -> list[tuple[str, str, datetime]]:
        """
        Get all namespaces that are registered with version and date_time
        """
        ns: list[tuple[str, str, datetime]] = []
        for model in self._children("Models"):
            uri = model.attrib.get("ModelUri")
            if uri is not None:
                published = model.attrib.get("PublicationDate")
                date_time = NULL_DATETIME if published is None else xs_datetime(published)
                ns.append((uri, model.attrib.get("Version", ""), date_time))
        return ns
