from __future__ import annotations

import math
import uuid
from datetime import datetime
from logging import Logger
from typing import Any

from enginir_opcua import ua
from enginir_opcua.ua.numeric_range import IndexRange, select_index_range
from enginir_opcua.ua.uaerrors import BadIndexRangeInvalid

from .address_space import AddressSpace
from .node_walk import is_subtype

VT = ua.VariantType
Operator = ua.FilterOperator
Value = ua.Variant | None

MAX_FILTER_ELEMENTS = 100
BASE_EVENT_TYPE = ua.NodeId(ua.ObjectIds.BaseEventType)
AGGREGATES = ua.NodeId(ua.ObjectIds.Aggregates)

PRECEDENCE = (
    VT.Double,
    VT.Float,
    VT.Int64,
    VT.UInt64,
    VT.Int32,
    VT.UInt32,
    VT.StatusCode,
    VT.Int16,
    VT.UInt16,
    VT.SByte,
    VT.Byte,
    VT.Boolean,
    VT.Guid,
    VT.String,
    VT.ExpandedNodeId,
    VT.NodeId,
    VT.LocalizedText,
    VT.QualifiedName,
)
INTEGER_RANGES: dict[ua.VariantType, tuple[int, int]] = {
    VT.SByte: (-(2**7), 2**7 - 1),
    VT.Byte: (0, 2**8 - 1),
    VT.Int16: (-(2**15), 2**15 - 1),
    VT.UInt16: (0, 2**16 - 1),
    VT.Int32: (-(2**31), 2**31 - 1),
    VT.UInt32: (0, 2**32 - 1),
    VT.Int64: (-(2**63), 2**63 - 1),
    VT.UInt64: (0, 2**64 - 1),
}
FLOAT_TYPES = (VT.Float, VT.Double)
NUMERIC_TYPES = (*INTEGER_RANGES, *FLOAT_TYPES)
ORDERED_TYPES = (*NUMERIC_TYPES, VT.DateTime)
NUMBER_OR_BOOLEAN = (*NUMERIC_TYPES, VT.Boolean)
NAME_TYPES = (VT.NodeId, VT.ExpandedNodeId, VT.LocalizedText, VT.QualifiedName)
MAX_FLOAT = 3.4028234663852886e38

OPERAND_COUNTS: dict[int, tuple[int, int | None]] = {
    Operator.Equals: (2, 2),
    Operator.IsNull: (1, 1),
    Operator.GreaterThan: (2, 2),
    Operator.LessThan: (2, 2),
    Operator.GreaterThanOrEqual: (2, 2),
    Operator.LessThanOrEqual: (2, 2),
    Operator.Like: (2, 2),
    Operator.Not: (1, 1),
    Operator.Between: (3, 3),
    Operator.InList: (2, None),
    Operator.And: (2, 2),
    Operator.Or: (2, 2),
    Operator.Cast: (2, 2),
    Operator.InView: (1, 1),
    Operator.OfType: (1, 1),
    Operator.RelatedTo: (6, 6),
    Operator.BitwiseAnd: (2, 2),
    Operator.BitwiseOr: (2, 2),
}
UNSUPPORTED_OPERATORS = (Operator.InView, Operator.RelatedTo)


def _rank(vtype: ua.VariantType) -> int | None:
    return PRECEDENCE.index(vtype) if vtype in PRECEDENCE else None


def _to_integer(value: Any, vtype: ua.VariantType) -> int | None:
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        value = math.trunc(value + 0.5)
    low, high = INTEGER_RANGES[vtype]
    number = int(value)
    return number if low <= number <= high else None


def _numeric_from_text(text: str, target: ua.VariantType) -> Any:
    try:
        if target in FLOAT_TYPES:
            return float(text)
        return int(text) if text.strip().lstrip("+-").isdigit() else float(text)
    except ValueError:
        return None


def _boolean_from_text(text: str) -> bool | None:
    lowered = text.strip().lower()
    if lowered in ("true", "1"):
        return True
    if lowered in ("false", "0"):
        return False
    return None


def _convert_number(value: Any, target: ua.VariantType) -> Any:
    if target == VT.Boolean:
        return bool(value)
    if target in FLOAT_TYPES:
        number = float(value)
        return None if target == VT.Float and math.isfinite(number) and abs(number) > MAX_FLOAT else number
    return _to_integer(value, target)


def _to_text(value: Any, source: ua.VariantType) -> str | None:
    if source == VT.Boolean:
        return "1" if value else "0"
    if source in NUMERIC_TYPES:
        return str(value)
    if source == VT.DateTime:
        return value.isoformat()
    if source == VT.ByteString:
        return value.hex().upper()
    if source in (VT.NodeId, VT.ExpandedNodeId):
        return value.to_string()
    if source == VT.LocalizedText:
        return value.Text or ""
    if source == VT.QualifiedName:
        return value.Name or ""
    if source == VT.Guid:
        return str(value)
    return None


def _from_text(text: str, target: ua.VariantType) -> Any:
    try:
        if target == VT.Boolean:
            return _boolean_from_text(text)
        if target in NUMERIC_TYPES:
            number = _numeric_from_text(text, target)
            return None if number is None else _convert_number(number, target)
        if target == VT.Guid:
            return uuid.UUID(text)
        if target in (VT.NodeId, VT.ExpandedNodeId):
            return ua.NodeId.from_string(text) if target == VT.NodeId else ua.ExpandedNodeId.from_string(text)
        if target == VT.DateTime:
            return datetime.fromisoformat(text)
        if target == VT.LocalizedText:
            return ua.LocalizedText(Text=text)
        if target == VT.QualifiedName:
            return ua.QualifiedName(text, 0)
    except (ValueError, TypeError, ua.UaError):
        return None
    return None


def _convert_status_code(value: Any, source: ua.VariantType, target: ua.VariantType) -> Any:
    if source == VT.StatusCode and target in INTEGER_RANGES:
        if target in (VT.UInt16, VT.Int16):
            return _to_integer(value.value >> 16, target)
        return _to_integer(value.value, target) if target != VT.Int32 else _signed(value.value, 32)
    if target == VT.StatusCode and source in INTEGER_RANGES:
        if source in (VT.UInt16, VT.Int16):
            return ua.StatusCode((int(value) & 0xFFFF) << 16)
        return ua.StatusCode(int(value) & 0xFFFFFFFF)
    return None


def _signed(number: int, bits: int) -> int:
    return number - (1 << bits) if number >= 1 << (bits - 1) else number


def convert_value(value: Any, source: ua.VariantType, target: ua.VariantType) -> Any:
    if source == target:
        return value
    if VT.StatusCode in (source, target):
        return _convert_status_code(value, source, target)
    if source in NUMBER_OR_BOOLEAN and target in NUMBER_OR_BOOLEAN:
        return _convert_number(value, target)
    if target == VT.String:
        return _to_text(value, source)
    if source == VT.String:
        return _from_text(value or "", target)
    if source == VT.ByteString and target == VT.Guid and isinstance(value, bytes) and len(value) == 16:
        return uuid.UUID(bytes=value)
    if source == VT.Guid and target == VT.ByteString:
        return value.bytes
    if source == VT.NodeId and target == VT.ExpandedNodeId:
        return ua.ExpandedNodeId(value.Identifier, value.NamespaceIndex, value.NodeIdType)
    if source == VT.ExpandedNodeId and target == VT.NodeId:
        return ua.NodeId(value.Identifier, value.NamespaceIndex, value.NodeIdType)
    return None


def convert_variant(variant: ua.Variant, target: ua.VariantType) -> ua.Variant | None:
    if isinstance(variant.Value, list):
        converted = [convert_value(item, variant.VariantType, target) for item in variant.Value]
        if any(item is None for item in converted):
            return None
        return ua.Variant(converted, target, variant.Dimensions, is_array=True)
    result = convert_value(variant.Value, variant.VariantType, target)
    return None if result is None else ua.Variant(result, target)


def _implicitly_convertible(source: ua.VariantType, target: ua.VariantType) -> bool:
    if source == target:
        return True
    if source in NUMBER_OR_BOOLEAN and target in NUMBER_OR_BOOLEAN:
        return True
    if source == VT.String and target in (*NUMBER_OR_BOOLEAN, VT.Guid):
        return True
    if target == VT.String and source in NAME_TYPES:
        return True
    return source == VT.NodeId and target == VT.ExpandedNodeId


def _scalar(variant: ua.Variant) -> ua.Variant:
    if isinstance(variant.Value, list) and len(variant.Value) == 1:
        return ua.Variant(variant.Value[0], variant.VariantType)
    return variant


def _is_null(variant: Value) -> bool:
    return variant is None or variant.VariantType == VT.Null or variant.Value is None


def _empty_text(variant: ua.Variant) -> bool:
    return variant.VariantType in (VT.String, VT.ByteString) and variant.Value in (None, "", b"")


def _common(first: ua.Variant, second: ua.Variant) -> tuple[ua.Variant, ua.Variant] | None:
    first, second = _scalar(first), _scalar(second)
    if first.VariantType == second.VariantType:
        return first, second
    low, high = _rank(first.VariantType), _rank(second.VariantType)
    if low is None or high is None:
        return None
    target = first.VariantType if low < high else second.VariantType
    if not (_implicitly_convertible(first.VariantType, target) and _implicitly_convertible(second.VariantType, target)):
        return None
    left, right = convert_variant(first, target), convert_variant(second, target)
    if left is None or right is None:
        return None
    return left, right


def values_equal(first: Value, second: Value) -> bool | None:
    if first is None or second is None:
        return None
    if _empty_text(first) and _empty_text(second):
        return True
    if _is_null(first) or _is_null(second):
        return None
    if isinstance(first.Value, list) and isinstance(second.Value, list) and len(first.Value) != 1:
        if len(first.Value) != len(second.Value):
            return False
        return all(
            values_equal(ua.Variant(a, first.VariantType), ua.Variant(b, second.VariantType)) is True
            for a, b in zip(first.Value, second.Value)
        )
    pair = _common(first, second)
    if pair is None:
        return False
    return bool(pair[0].Value == pair[1].Value)


def _order(first: Value, second: Value) -> tuple[Any, Any] | bool | None:
    if _is_null(first) or _is_null(second):
        return None
    assert first is not None and second is not None
    left, right = _scalar(first), _scalar(second)
    if isinstance(left.Value, list) or isinstance(right.Value, list):
        return None
    pair = _common(left, right)
    if pair is None:
        return None if (left.VariantType not in ORDERED_TYPES or right.VariantType not in ORDERED_TYPES) else False
    if pair[0].VariantType not in ORDERED_TYPES:
        return None
    return pair[0].Value, pair[1].Value


def _boolean(variant: Value) -> bool | None:
    if variant is None or variant.VariantType != VT.Boolean or isinstance(variant.Value, list):
        return None
    return bool(variant.Value)


def _wrap(result: bool | None) -> Value:
    return None if result is None else ua.Variant(result, VT.Boolean)


def like_match(text: str, pattern: str) -> bool:
    tokens = _like_tokens(pattern)
    t = p = 0
    star = -1
    mark = 0
    while t < len(text):
        if p < len(tokens) and tokens[p][0] == "many":
            star, mark = p, t
            p += 1
        elif p < len(tokens) and _like_token_matches(tokens[p], text[t]):
            p += 1
            t += 1
        elif star >= 0:
            mark += 1
            t, p = mark, star + 1
        else:
            return False
    while p < len(tokens) and tokens[p][0] == "many":
        p += 1
    return p == len(tokens)


def _like_token_matches(token: tuple[str, Any], char: str) -> bool:
    kind, data = token
    if kind == "any":
        return True
    if kind == "char":
        return bool(char == data)
    members, negated = data
    found = any(low <= char <= high for low, high in members)
    return found != negated


def _like_tokens(pattern: str) -> list[tuple[str, Any]]:
    tokens: list[tuple[str, Any]] = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\" and i + 1 < len(pattern):
            tokens.append(("char", pattern[i + 1]))
            i += 2
        elif char == "%":
            if not tokens or tokens[-1][0] != "many":
                tokens.append(("many", None))
            i += 1
        elif char == "_":
            tokens.append(("any", None))
            i += 1
        elif char == "[" and (end := pattern.find("]", i + 2)) > 0:
            tokens.append(("set", _like_set(pattern[i + 1 : end])))
            i = end + 1
        else:
            tokens.append(("char", char))
            i += 1
    return tokens


def _like_set(body: str) -> tuple[list[tuple[str, str]], bool]:
    negated = body.startswith("^")
    if negated:
        body = body[1:]
    members: list[tuple[str, str]] = []
    i = 0
    while i < len(body):
        if i + 2 < len(body) and body[i + 1] == "-":
            members.append((body[i], body[i + 2]))
            i += 3
        else:
            members.append((body[i], body[i]))
            i += 1
    return members, negated


def _text_of(variant: Value) -> str | None:
    if variant is None or isinstance(variant.Value, list) or variant.Value is None:
        return None
    if variant.VariantType == VT.String:
        return str(variant.Value)
    if variant.VariantType in (VT.LocalizedText, VT.QualifiedName):
        return _to_text(variant.Value, variant.VariantType)
    return None


def _integer_width(vtype: ua.VariantType) -> int:
    low, high = INTEGER_RANGES[vtype]
    return (high - low).bit_length()


def _bitwise(first: Value, second: Value, use_and: bool) -> Value:
    if _is_null(first) or _is_null(second):
        return None
    assert first is not None and second is not None
    left, right = _scalar(first), _scalar(second)
    if left.VariantType not in INTEGER_RANGES or right.VariantType not in INTEGER_RANGES:
        return None
    if isinstance(left.Value, list) or isinstance(right.Value, list):
        return None
    target = left.VariantType
    if _integer_width(right.VariantType) > _integer_width(left.VariantType):
        target = right.VariantType
    low, high = INTEGER_RANGES[target]
    bits = _integer_width(target)
    mask = (1 << bits) - 1
    a, b = int(left.Value), int(right.Value)
    if not (low <= a <= high and low <= b <= high):
        return None
    raw = (a & b if use_and else a | b) & mask
    return ua.Variant(_signed(raw, bits) if low < 0 else raw, target)


def _cast_target(variant: Value) -> ua.VariantType | None:
    if variant is None or variant.VariantType not in (VT.NodeId, VT.ExpandedNodeId):
        return None
    node_id = variant.Value
    if node_id.NamespaceIndex != 0 or not isinstance(node_id.Identifier, int) or not 1 <= node_id.Identifier <= 25:
        return None
    return ua.VariantType(node_id.Identifier)


class WhereClauseEvaluator:
    def __init__(self, logger: Logger, aspace: AddressSpace | None, whereclause: ua.ContentFilter) -> None:
        self.logger = logger
        self.elements = whereclause.Elements
        self._aspace = aspace

    def eval(self, event: Any) -> bool:
        if not self.elements:
            return True
        try:
            result = _boolean(self._eval_el(0, event))
        except Exception as ex:
            self.logger.exception(
                "Exception while evaluating WhereClause %s for event %s: %s", self.elements, event, ex
            )
            return False
        return result is True

    def _eval_el(self, index: int, event: Any) -> Value:
        el = self.elements[index]
        ops = el.FilterOperands
        operator = el.FilterOperator
        if operator in (Operator.And, Operator.Or):
            return self._logic(operator == Operator.And, ops, index, event)
        if operator == Operator.Not:
            return _wrap(None if (a := _boolean(self._operand(ops[0], index, event))) is None else not a)
        if operator == Operator.IsNull:
            return _wrap(_is_null(self._operand(ops[0], index, event)))
        if operator == Operator.Equals:
            return _wrap(values_equal(self._operand(ops[0], index, event), self._operand(ops[1], index, event)))
        if operator == Operator.InList:
            return self._in_list(ops, index, event)
        if operator in (Operator.GreaterThan, Operator.LessThan, Operator.GreaterThanOrEqual, Operator.LessThanOrEqual):
            return self._ordering(operator, ops, index, event)
        if operator == Operator.Between:
            return self._between(ops, index, event)
        if operator == Operator.Like:
            return self._like(ops, index, event)
        if operator == Operator.Cast:
            return self._cast(ops, index, event)
        if operator in (Operator.BitwiseAnd, Operator.BitwiseOr):
            first, second = self._operand(ops[0], index, event), self._operand(ops[1], index, event)
            return _bitwise(first, second, operator == Operator.BitwiseAnd)
        if operator == Operator.OfType:
            return self._of_type(ops, index, event)
        self.logger.warning("WhereClause operator %s is not supported", operator)
        return None

    def _logic(self, use_and: bool, ops: list[Any], index: int, event: Any) -> Value:
        first = _boolean(self._operand(ops[0], index, event))
        second = _boolean(self._operand(ops[1], index, event))
        decisive = False if use_and else True
        if first is decisive or second is decisive:
            return _wrap(decisive)
        if first is None or second is None:
            return None
        return _wrap(not decisive)

    def _in_list(self, ops: list[Any], index: int, event: Any) -> Value:
        first = self._operand(ops[0], index, event)
        if _is_null(first):
            return None
        return _wrap(any(values_equal(first, self._operand(op, index, event)) is True for op in ops[1:]))

    def _ordering(self, operator: ua.FilterOperator, ops: list[Any], index: int, event: Any) -> Value:
        pair = _order(self._operand(ops[0], index, event), self._operand(ops[1], index, event))
        if pair is None:
            return None
        if pair is False:
            return _wrap(False)
        assert isinstance(pair, tuple)
        left, right = pair
        if operator == Operator.GreaterThan:
            return _wrap(left > right)
        if operator == Operator.LessThan:
            return _wrap(left < right)
        if operator == Operator.GreaterThanOrEqual:
            return _wrap(left >= right)
        return _wrap(left <= right)

    def _between(self, ops: list[Any], index: int, event: Any) -> Value:
        value, low, high = (self._operand(op, index, event) for op in ops[:3])
        lower, upper = _order(value, low), _order(value, high)
        if lower is None or upper is None:
            return None
        if lower is False or upper is False:
            return _wrap(False)
        assert isinstance(lower, tuple) and isinstance(upper, tuple)
        return _wrap(lower[0] >= lower[1] and upper[0] <= upper[1])

    def _like(self, ops: list[Any], index: int, event: Any) -> Value:
        first, second = self._operand(ops[0], index, event), self._operand(ops[1], index, event)
        if first is None or second is None:
            return None
        text, pattern = _text_of(first), _text_of(second)
        if text is None or pattern is None:
            return _wrap(False)
        return _wrap(like_match(text, pattern))

    def _cast(self, ops: list[Any], index: int, event: Any) -> Value:
        value = self._operand(ops[0], index, event)
        target = _cast_target(self._operand(ops[1], index, event))
        if _is_null(value) or target is None:
            return None
        assert value is not None
        return convert_variant(value, target)

    def _of_type(self, ops: list[Any], index: int, event: Any) -> Value:
        wanted = self._operand(ops[0], index, event)
        if wanted is None or not isinstance(wanted.Value, ua.NodeId):
            return _wrap(False)
        event_type = getattr(event, "EventType", None)
        if not isinstance(event_type, ua.NodeId):
            return _wrap(False)
        if self._aspace is None:
            return _wrap(event_type == wanted.Value)
        if not self._is_object_type(wanted.Value):
            return _wrap(False)
        return _wrap(is_subtype(self._aspace, event_type, wanted.Value))

    def _is_object_type(self, node_id: ua.NodeId) -> bool:
        assert self._aspace is not None
        dv = self._aspace.read_attribute_value(node_id, ua.AttributeIds.NodeClass)
        return dv.Value is not None and dv.Value.Value == ua.NodeClass.ObjectType

    def _operand(self, op: Any, index: int, event: Any) -> Value:
        if isinstance(op, ua.uaprotocol_auto.ElementOperand):
            return self._eval_el(op.Index, event) if index < op.Index < len(self.elements) else None
        if isinstance(op, ua.uaprotocol_auto.LiteralOperand):
            return op.Value if isinstance(op.Value, ua.Variant) and not _is_null(op.Value) else None
        if isinstance(op, ua.uaprotocol_auto.SimpleAttributeOperand):
            return self._simple_operand(op, event)
        self.logger.warning("Where clause operand %s is not of a known type", op)
        return None

    def _simple_operand(self, op: ua.SimpleAttributeOperand, event: Any) -> Value:
        if len(op.BrowsePath) == 0 and op.AttributeId != ua.AttributeIds.NodeId:
            return self._event_type_attribute(event, op.AttributeId)
        is_sub = None if self._aspace is None else self._subtype_check
        variant = event.select_field(op, is_sub, select_index_range)
        return None if variant.VariantType in (VT.Null, VT.StatusCode) or variant.Value is None else variant

    def _subtype_check(self, candidate: ua.NodeId, ancestor: ua.NodeId) -> bool:
        assert self._aspace is not None
        return is_subtype(self._aspace, candidate, ancestor)

    def _event_type_attribute(self, event: Any, attribute: ua.AttributeIds) -> Value:
        event_type = getattr(event, "EventType", None)
        if self._aspace is None or not isinstance(event_type, ua.NodeId):
            return None
        dv = self._aspace.read_attribute_value(event_type, attribute)
        return None if dv.Value is None or dv.Value.Value is None else dv.Value


def _good() -> ua.StatusCode:
    return ua.StatusCode()


class EventFilterChecker:
    def __init__(self, aspace: AddressSpace) -> None:
        self._aspace = aspace
        self._all_event_types: list[ua.NodeId] | None = None

    def check(self, flt: ua.EventFilter) -> tuple[bool, ua.EventFilterResult]:
        result = ua.EventFilterResult()
        result.SelectClauseResults = [self.select_clause_status(clause) for clause in flt.SelectClauses]
        selects_ok = any(status.is_good() for status in result.SelectClauseResults)
        where_ok, result.WhereClauseResult = self.check_where(flt.WhereClause)
        return selects_ok and where_ok, result

    def select_clause_status(self, clause: Any) -> ua.StatusCode:
        return ua.StatusCode(self._select_clause_code(clause))

    def _select_clause_code(self, clause: Any) -> int:
        if not isinstance(clause, ua.uaprotocol_auto.SimpleAttributeOperand):
            return ua.StatusCodes.BadFilterOperandInvalid
        type_definition = clause.TypeDefinitionId
        if not type_definition.is_null() and not is_subtype(self._aspace, type_definition, BASE_EVENT_TYPE):
            return ua.StatusCodes.BadTypeDefinitionInvalid
        if any(not name.Name for name in clause.BrowsePath):
            return ua.StatusCodes.BadBrowseNameInvalid
        if clause.AttributeId not in tuple(ua.AttributeIds):
            return ua.StatusCodes.BadAttributeIdInvalid
        if len(clause.BrowsePath) == 0:
            return self._condition_id_code(clause)
        if clause.AttributeId != ua.AttributeIds.Value:
            return ua.StatusCodes.BadAttributeIdInvalid
        field = self._find_field(type_definition, clause.BrowsePath)
        if field is None:
            return ua.StatusCodes.BadNodeIdUnknown
        return self._index_range_code(clause, field)

    @staticmethod
    def _condition_id_code(clause: ua.SimpleAttributeOperand) -> int:
        if clause.AttributeId != ua.AttributeIds.NodeId:
            return ua.StatusCodes.BadAttributeIdInvalid
        return ua.StatusCodes.Good

    def _index_range_code(self, clause: ua.SimpleAttributeOperand, field: ua.NodeId) -> int:
        if not clause.IndexRange:
            return ua.StatusCodes.Good
        try:
            IndexRange.parse(clause.IndexRange)
        except BadIndexRangeInvalid:
            return ua.StatusCodes.BadIndexRangeInvalid
        rank = self._aspace.read_attribute_value(field, ua.AttributeIds.ValueRank)
        data_type = self._aspace.read_attribute_value(field, ua.AttributeIds.DataType)
        scalar = rank.Value is not None and rank.Value.Value == -1
        text_like = data_type.Value is not None and data_type.Value.Value in (
            ua.NodeId(ua.ObjectIds.String),
            ua.NodeId(ua.ObjectIds.ByteString),
        )
        return ua.StatusCodes.BadTypeMismatch if scalar and not text_like else ua.StatusCodes.Good

    def _event_types(self) -> list[ua.NodeId]:
        if self._all_event_types is None:
            found = [BASE_EVENT_TYPE]
            for node_id in found:
                data = self._aspace.get(node_id)
                if data is None:
                    continue
                for ref in data.references:
                    if ref.IsForward and ref.ReferenceTypeId == ua.NodeId(ua.ObjectIds.HasSubtype):
                        if ref.NodeId not in found:
                            found.append(ref.NodeId)
            self._all_event_types = found
        return self._all_event_types

    def _types_defining(self, type_definition: ua.NodeId) -> list[ua.NodeId]:
        if type_definition.is_null() or type_definition == BASE_EVENT_TYPE:
            return self._event_types()
        chain = [type_definition]
        for node_id in chain:
            data = self._aspace.get(node_id)
            if data is None:
                continue
            for ref in data.references:
                if not ref.IsForward and ref.ReferenceTypeId == ua.NodeId(ua.ObjectIds.HasSubtype):
                    if ref.NodeId not in chain:
                        chain.append(ref.NodeId)
        return chain

    def _find_field(self, type_definition: ua.NodeId, browse_path: list[ua.QualifiedName]) -> ua.NodeId | None:
        for type_id in self._types_defining(type_definition):
            current: ua.NodeId | None = type_id
            for name in browse_path:
                current = self._child(current, name.Name) if current is not None else None
            if current is not None:
                return current
        return None

    def _child(self, node_id: ua.NodeId, name: str | None) -> ua.NodeId | None:
        data = self._aspace.get(node_id)
        if data is None:
            return None
        for ref in data.references:
            if (
                ref.IsForward
                and ref.BrowseName.Name == name
                and is_subtype(self._aspace, ref.ReferenceTypeId, AGGREGATES)
            ):
                return ref.NodeId
        return None

    def check_where(self, where: ua.ContentFilter) -> tuple[bool, ua.ContentFilterResult]:
        result = ua.ContentFilterResult()
        if len(where.Elements) > MAX_FILTER_ELEMENTS:
            return False, result
        ok = True
        for index, element in enumerate(where.Elements):
            element_result = self._check_element(index, element, len(where.Elements))
            ok = ok and element_result.StatusCode.is_good()
            result.ElementResults.append(element_result)
        return ok, result

    def _check_element(self, index: int, element: ua.ContentFilterElement, count: int) -> ua.ContentFilterElementResult:
        result = ua.ContentFilterElementResult()
        operands = element.FilterOperands
        result.OperandStatusCodes = [self._operand_status(index, operand, count) for operand in operands]
        if element.FilterOperator not in OPERAND_COUNTS:
            result.StatusCode = ua.StatusCode(ua.StatusCodes.BadFilterOperatorInvalid)
        elif element.FilterOperator in UNSUPPORTED_OPERATORS:
            result.StatusCode = ua.StatusCode(ua.StatusCodes.BadFilterOperatorUnsupported)
        elif not self._count_fits(element):
            result.StatusCode = ua.StatusCode(ua.StatusCodes.BadFilterOperandCountMismatch)
        else:
            bad = next((code for code in result.OperandStatusCodes if not code.is_good()), None)
            result.StatusCode = bad if bad is not None else _good()
        return result

    @staticmethod
    def _count_fits(element: ua.ContentFilterElement) -> bool:
        low, high = OPERAND_COUNTS[element.FilterOperator]
        count = len(element.FilterOperands)
        return count >= low and (high is None or count <= high)

    def _operand_status(self, index: int, operand: Any, count: int) -> ua.StatusCode:
        if isinstance(operand, ua.uaprotocol_auto.ElementOperand):
            valid = index < operand.Index < count
            return _good() if valid else ua.StatusCode(ua.StatusCodes.BadFilterElementInvalid)
        if isinstance(operand, ua.uaprotocol_auto.LiteralOperand):
            return (
                _good()
                if isinstance(operand.Value, ua.Variant)
                else ua.StatusCode(ua.StatusCodes.BadFilterLiteralInvalid)
            )
        if isinstance(operand, ua.uaprotocol_auto.SimpleAttributeOperand):
            return self.select_clause_status(operand)
        return ua.StatusCode(ua.StatusCodes.BadFilterOperandInvalid)
