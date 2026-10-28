from __future__ import annotations

import re
from enum import IntEnum

from enginir_opcua.ua.object_ids import ObjectIdNames, ObjectIds, ReferenceTypeIds
from enginir_opcua.ua.uaerrors import UaStringParsingError
from enginir_opcua.ua.uatypes import NodeId, NodeIdType, QualifiedName, RelativePath, RelativePathElement

_NS_IDX_PATTERN = re.compile(r"([0-9]*):")
_REFERENCE_TYPE_PREFIX_CHARS = "/.<"
_REFERENCE_TYPE_SUFFIX_CHAR = ">"
_RESERVED_CHARS = "/.<>:#!&"


class RelativePathElementType(IntEnum):
    AnyHierarchical = 0
    AnyComponent = 1
    ForwardReference = 2
    InverseReference = 3


class RelativePathElementFormatter:
    _element_type: RelativePathElementType = RelativePathElementType.AnyHierarchical
    _include_subtypes: bool = True
    _target_name: QualifiedName | None = None
    _reference_type_name: QualifiedName | None = None

    def __init__(self, element: RelativePathElement | None = None) -> None:
        if element is not None:
            self._include_subtypes = element.IncludeSubtypes
            self._target_name = element.TargetName

            if not element.IsInverse and element.IncludeSubtypes:
                if _is_standard_id(element.ReferenceTypeId, ObjectIds.HierarchicalReferences):
                    self._element_type = RelativePathElementType.AnyHierarchical
                elif _is_standard_id(element.ReferenceTypeId, ObjectIds.Aggregates):
                    self._element_type = RelativePathElementType.AnyComponent
                else:
                    self._element_type = RelativePathElementType.ForwardReference
                    self._reference_type_name = _find_reference_type_name(element.ReferenceTypeId)
            else:
                if not element.IsInverse:
                    self._element_type = RelativePathElementType.ForwardReference
                else:
                    self._element_type = RelativePathElementType.InverseReference
                self._reference_type_name = _find_reference_type_name(element.ReferenceTypeId)

    @staticmethod
    def parse(string: str) -> tuple["RelativePathElementFormatter", str]:
        el = RelativePathElementFormatter()

        rest = string
        head = _peek(rest)
        if head == "/":
            el._element_type = RelativePathElementType.AnyHierarchical
            rest = rest[1:]
        elif head == ".":
            el._element_type = RelativePathElementType.AnyComponent
            rest = rest[1:]
        elif head == "<":
            el._element_type = RelativePathElementType.ForwardReference
            rest = rest[1:]
            if _peek(rest) == "#":
                el._include_subtypes = False
                rest = rest[1:]
            if _peek(rest) == "!":
                el._element_type = RelativePathElementType.InverseReference
                rest = rest[1:]
            el._reference_type_name, rest = RelativePathElementFormatter._parse_name(rest, True)
        else:
            el._element_type = RelativePathElementType.AnyHierarchical

        el._target_name, rest = RelativePathElementFormatter._parse_name(rest, False)

        return el, rest

    @staticmethod
    def _parse_name(string: str, is_reference: bool) -> tuple[QualifiedName | None, str]:
        rest = string

        # Extract namespace index if present.
        idx = 0
        m = _NS_IDX_PATTERN.match(rest)
        if m:
            idx_str = m.group(1)
            if idx_str:
                idx = int(idx_str)
            rest = rest[m.end() :]

        # Extract rest of name.
        name = []
        head: str = ""
        while len(rest) > 0:
            head = rest[0]

            if is_reference:
                if head == _REFERENCE_TYPE_SUFFIX_CHAR:
                    rest = rest[1:]
                    break
            elif head in _REFERENCE_TYPE_PREFIX_CHARS:
                break

            if head == "&":
                rest = rest[1:]
                if len(rest) > 0:
                    head = rest[0]
                    if head in _RESERVED_CHARS:
                        name.append(head)
                        rest = rest[1:]
                        continue
                    raise UaStringParsingError(f"Invalid escape sequence '&{head}' in browse path.")
                raise UaStringParsingError("Unexpected end after escape character '&'.")
            name.append(head)
            rest = rest[1:]

        if is_reference and head != ">":
            raise UaStringParsingError("Missing closing '>' for reference type name in browse path.")

        if len(name) == 0:
            if is_reference:
                raise UaStringParsingError("Reference type name is null in browse path.")
            if idx == 0:
                return None, rest

        return QualifiedName("".join(name), idx), rest

    def build(self) -> RelativePathElement:
        reference_type_id: NodeId | None = None
        is_inverse = False
        include_subtypes = self._include_subtypes
        target_name = self._target_name

        if self._element_type == RelativePathElementType.AnyHierarchical:
            reference_type_id = NodeId(ObjectIds.HierarchicalReferences)
        elif self._element_type == RelativePathElementType.AnyComponent:
            reference_type_id = NodeId(ObjectIds.Aggregates)
        elif self._element_type == RelativePathElementType.ForwardReference:
            reference_type_id = _find_reference_type(self._reference_type_name)
        elif self._element_type == RelativePathElementType.InverseReference:
            reference_type_id = _find_reference_type(self._reference_type_name)
            is_inverse = True

        if reference_type_id is None:
            raise UaStringParsingError(
                f"Could not convert BrowseName to a ReferenceTypeId: {self._reference_type_name}"
            )

        return RelativePathElement(
            ReferenceTypeId=reference_type_id,
            IsInverse=is_inverse,
            IncludeSubtypes=include_subtypes,
            TargetName=target_name,
        )

    def to_string(self) -> str:
        path = []

        # Append the reference type component.
        if self._element_type == RelativePathElementType.AnyHierarchical:
            path.append("/")
        elif self._element_type == RelativePathElementType.AnyComponent:
            path.append(".")
        elif (
            self._element_type == RelativePathElementType.ForwardReference
            or self._element_type == RelativePathElementType.InverseReference
        ):
            if not self._reference_type_name or not self._reference_type_name.Name:
                raise UaStringParsingError("A forward or inverse step needs a reference type name.")
            path.append("<")
            if not self._include_subtypes:
                path.append("#")
            if self._element_type == RelativePathElementType.InverseReference:
                path.append("!")
            if self._reference_type_name.NamespaceIndex != 0:
                path.append(f"{self._reference_type_name.NamespaceIndex}:")
            path.append(_encode_name(self._reference_type_name.Name))
            path.append(">")

        if self._target_name and (self._target_name.Name or self._target_name.NamespaceIndex != 0):
            if self._target_name.NamespaceIndex != 0:
                path.append(f"{self._target_name.NamespaceIndex}:")
            path.append(_encode_name(self._target_name.Name or ""))

        return "".join(path)


class RelativePathFormatter:
    """
    Implementation of the BNF of RelativePath, OPC 10000-4 v1.05, A.2.
    """

    _elements: list[RelativePathElementFormatter]

    def __init__(self, relative_path: RelativePath | None = None) -> None:
        self._elements = []
        if relative_path:
            self._elements = [RelativePathElementFormatter(el) for el in relative_path.Elements]

    @staticmethod
    def parse(string: str) -> RelativePathFormatter:
        formatter = RelativePathFormatter()

        if string:
            rest = string
            try:
                while len(rest) > 0:
                    el, rest = RelativePathElementFormatter.parse(rest)
                    formatter._elements.append(el)
            except Exception as e:
                raise UaStringParsingError(f"Cannot parse relative path: {string}") from e

        return formatter

    def build(self) -> RelativePath:
        return RelativePath(Elements=[el.build() for el in self._elements])

    def to_string(self) -> str:
        return "".join([el.to_string() for el in self._elements])


def _peek(string: str) -> str | None:
    return string[0] if len(string) > 0 else None


def _encode_name(name: str) -> str:
    return "".join([ch if ch not in _RESERVED_CHARS else f"&{ch}" for ch in name])


def _is_standard_id(node_id: NodeId, identifier: int) -> bool:
    return node_id.NamespaceIndex == 0 and node_id.Identifier == identifier


def _find_reference_type(reference_type_name: QualifiedName) -> NodeId:
    if reference_type_name.NamespaceIndex == 0:
        type_id = getattr(ObjectIds, reference_type_name.Name, None)
        if isinstance(type_id, int) and type_id in ReferenceTypeIds:
            return NodeId(Identifier=type_id, NamespaceIndex=0)
    raise UaStringParsingError(f"Non-standard ReferenceTypes are not supported: {reference_type_name}")


def _find_reference_type_name(reference_type_id: NodeId) -> QualifiedName:
    if reference_type_id.NamespaceIndex == 0 and reference_type_id.Identifier in ReferenceTypeIds:
        id_type = reference_type_id.NodeIdType
        if id_type == NodeIdType.TwoByte or id_type == NodeIdType.FourByte or id_type == NodeIdType.Numeric:
            type_id: int = reference_type_id.Identifier
            return QualifiedName.from_string(ObjectIdNames[type_id])
        raise UaStringParsingError("Non-integer NodeIds are not supported.")
    raise UaStringParsingError(f"Non-standard ReferenceTypes are not supported: {reference_type_id}")
