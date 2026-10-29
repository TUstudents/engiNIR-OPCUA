from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from typing import Any

import pytest

from enginir_opcua import Server, ua
from enginir_opcua.common.event_objects import BaseEvent
from enginir_opcua.common.events import Event
from enginir_opcua.server.content_filter import WhereClauseEvaluator
from tests.monitoring import create_items, item_request, make_server, modify_items, open_subscription, publish

"""EventFilter validation and results, WhereClause operators and the select clause operands."""


OP = ua.FilterOperator
BASE_EVENT = ua.NodeId(ua.ObjectIds.BaseEventType)
AUDIT_EVENT = ua.NodeId(ua.ObjectIds.AuditEventType)


@pytest.fixture(scope="module")
async def server() -> AsyncIterator[Server]:
    srv = await make_server()
    yield srv


def path(*names: str) -> list[ua.QualifiedName]:
    return [ua.QualifiedName(name, 0) for name in names]


def field(*names: str, type_definition: ua.NodeId = BASE_EVENT, index_range: str | None = None) -> Any:
    return ua.SimpleAttributeOperand(
        TypeDefinitionId=type_definition,
        BrowsePath=path(*names),
        AttributeId=ua.AttributeIds.Value,
        IndexRange=index_range,
    )


def lit(value: Any, vtype: ua.VariantType | None = None) -> Any:
    return ua.LiteralOperand(Value=ua.Variant(value, vtype))


def elem(index: int) -> Any:
    return ua.ElementOperand(Index=index)


def element(operator: ua.FilterOperator, *operands: Any) -> Any:
    return ua.ContentFilterElement(FilterOperator=operator, FilterOperands=list(operands))


def sample_event(**fields: tuple[Any, ua.VariantType]) -> Event:
    event = Event()
    event.add_property("EventType", AUDIT_EVENT, ua.VariantType.NodeId)
    for name, (value, vtype) in fields.items():
        event.add_property(name, value, vtype)
    return event


def evaluate(server: Server, event: Event, *elements: Any) -> bool:
    evaluator = WhereClauseEvaluator(
        logging.getLogger(__name__), server.iserver.aspace, ua.ContentFilter(Elements=list(elements))
    )
    return evaluator.eval(event)


I32 = ua.VariantType.Int32
STR = ua.VariantType.String


@pytest.mark.parametrize(
    "left, right, expected",
    [
        (lit(5, I32), lit(5.0, ua.VariantType.Double), True),
        (lit("5", STR), lit(5, I32), True),
        (lit("a", STR), lit("A", STR), False),
        (lit("abc", STR), lit(5, I32), False),
        (lit(True, ua.VariantType.Boolean), lit("1", STR), True),
        (field("Name"), lit("x", STR), True),
    ],
)
def test_srv14_equals_converts_to_the_type_with_the_higher_precedence(
    server: Server, left: Any, right: Any, expected: bool
) -> None:
    """Part 4, 7.7.3 (Equals, Table 121 and 122)."""
    event = sample_event(Name=("x", STR))
    assert evaluate(server, event, element(OP.Equals, left, right)) is expected


@pytest.mark.parametrize(
    "operator, left, right, expected",
    [
        (OP.GreaterThan, 5, 3, True),
        (OP.GreaterThan, 3, 5, False),
        (OP.LessThan, 3, 5, True),
        (OP.GreaterThanOrEqual, 5, 5, True),
        (OP.LessThanOrEqual, 6, 5, False),
    ],
)
def test_srv14_ordering_operators(
    server: Server, operator: ua.FilterOperator, left: int, right: int, expected: bool
) -> None:
    """Part 4, 7.7.3."""
    assert (
        evaluate(server, sample_event(), element(operator, lit(left, I32), lit(right, ua.VariantType.Double)))
        is expected
    )


@pytest.mark.parametrize("value, expected", [(5, True), (1, True), (10, True), (0, False), (11, False)])
def test_srv14_between_is_inclusive_on_both_ends(server: Server, value: int, expected: bool) -> None:
    """Part 4, 7.7.3 (Between)."""
    assert evaluate(server, sample_event(), element(OP.Between, lit(value, I32), lit(1, I32), lit(10, I32))) is expected


def test_srv14_in_list(server: Server) -> None:
    """Part 4, 7.7.3 (InList)."""
    event = sample_event(Number=(3, I32))
    assert evaluate(server, event, element(OP.InList, field("Number"), lit(1, I32), lit(3, I32)))
    assert not evaluate(server, event, element(OP.InList, field("Number"), lit(1, I32), lit(2, I32)))


@pytest.mark.parametrize(
    "text, pattern, expected",
    [
        ("That is fine", "Th[ia][ts]%", True),
        ("This as one", "Th[ia][ts]%", True),
        ("Thus", "Th[ia][ts]%", False),
        ("would", "_ould", True),
        ("5%", "5[%]", True),
        ("55", "5[%]", False),
        ("5_", "5[_]", True),
        ("abc4", "abc[13-68]", True),
        ("abc2", "abc[13-68]", False),
        ("ABC2", "ABC[^13-5]", True),
        ("ABC4", "ABC[^13-5]", False),
        ("100%", "100\\%", True),
        ("entail", "%en%", True),
        ("Main", "main%", False),
        ("", "%", True),
    ],
)
def test_srv14_like(server: Server, text: str, pattern: str, expected: bool) -> None:
    """Part 4, 7.7.3 (Like, Table 120)."""
    assert evaluate(server, sample_event(), element(OP.Like, lit(text, STR), lit(pattern, STR))) is expected


def test_srv14_like_does_not_take_exponential_time(server: Server) -> None:
    """Part 4, 7.7.3 (Like): a hostile pattern is matched in polynomial time."""
    event = sample_event(Text=("a" * 3000, STR))
    started = time.monotonic()
    assert not evaluate(server, event, element(OP.Like, field("Text"), lit("%a" * 12 + "b", STR)))
    assert time.monotonic() - started < 5


def test_srv14_like_on_a_non_string_is_false(server: Server) -> None:
    """Part 4, 7.7.3 (Like)."""
    assert not evaluate(server, sample_event(), element(OP.Like, lit(5, I32), lit("5", STR)))


@pytest.mark.parametrize(
    "value, target, expected",
    [
        (lit("12", STR), ua.ObjectIds.Int32, 12),
        (lit(3.5, ua.VariantType.Double), ua.ObjectIds.Int32, 4),
        (lit(1, I32), ua.ObjectIds.Boolean, True),
        (lit(7, I32), ua.ObjectIds.String, "7"),
        (lit("true", STR), ua.ObjectIds.Boolean, True),
    ],
)
def test_srv14_cast_converts_to_the_given_data_type(server: Server, value: Any, target: int, expected: Any) -> None:
    """Part 4, 7.7.3 (Cast, Table 121)."""
    cast = element(OP.Cast, value, lit(ua.NodeId(target), ua.VariantType.NodeId))
    assert evaluate(server, sample_event(), element(OP.Equals, elem(1), lit(expected)), cast) is True


@pytest.mark.parametrize(
    "value, target",
    [
        (lit(-1, I32), ua.ObjectIds.UInt32),
        (lit(300, I32), ua.ObjectIds.Byte),
        (lit("abc", STR), ua.ObjectIds.Int32),
        (lit("maybe", STR), ua.ObjectIds.Boolean),
        (lit(1, I32), ua.ObjectIds.Server),
    ],
)
def test_srv14_a_failing_cast_is_null(server: Server, value: Any, target: int) -> None:
    """Part 4, 7.7.3 (Cast): the result is NULL, which IsNull sees and a plain filter treats as FALSE."""
    cast = element(OP.Cast, value, lit(ua.NodeId(target), ua.VariantType.NodeId))
    assert evaluate(server, sample_event(), element(OP.IsNull, elem(1)), cast)
    assert not evaluate(server, sample_event(), cast)


def test_srv14_bitwise_operators(server: Server) -> None:
    """Part 4, 7.7.3 (BitwiseAnd, BitwiseOr)."""
    event = sample_event(Bits=(0b1010, I32))
    and_equals = [element(OP.Equals, elem(1), lit(2, I32)), element(OP.BitwiseAnd, field("Bits"), lit(0b0110, I32))]
    or_equals = [element(OP.Equals, elem(1), lit(0b1110, I32)), element(OP.BitwiseOr, field("Bits"), lit(0b0110, I32))]
    assert evaluate(server, event, *and_equals)
    assert evaluate(server, event, *or_equals)
    on_text = element(OP.BitwiseAnd, lit("x", STR), lit(1, I32))
    assert not evaluate(server, event, element(OP.Equals, elem(1), lit(1, I32)), on_text)


@pytest.mark.parametrize(
    "type_id, expected",
    [
        (ua.ObjectIds.AuditEventType, True),
        (ua.ObjectIds.BaseEventType, True),
        (ua.ObjectIds.AuditSecurityEventType, True),
        (ua.ObjectIds.ProgressEventType, False),
        (ua.ObjectIds.Server, False),
        (999999, False),
    ],
)
def test_srv14_of_type_includes_subtypes(server: Server, type_id: int, expected: bool) -> None:
    """Part 4, 7.7.3 (OfType): an event of AuditSecurityEventType is of its super types."""
    event = sample_event()
    event.add_property("EventType", ua.NodeId(ua.ObjectIds.AuditSecurityEventType), ua.VariantType.NodeId)
    assert evaluate(server, event, element(OP.OfType, lit(ua.NodeId(type_id), ua.VariantType.NodeId))) is expected


def test_srv14_three_valued_logic(server: Server) -> None:
    """Part 4, 7.7.3 (Tables 123 and 124): operands that cannot be resolved are NULL."""
    event = sample_event(Flag=(True, ua.VariantType.Boolean))
    missing_is_true = element(OP.Equals, field("Missing"), lit(1, I32))
    true = element(OP.Equals, lit(1, I32), lit(1, I32))
    false = element(OP.Equals, lit(1, I32), lit(2, I32))
    assert not evaluate(server, event, missing_is_true)
    assert evaluate(server, event, element(OP.IsNull, field("Missing")))
    assert not evaluate(server, event, element(OP.And, elem(1), elem(2)), missing_is_true, true)
    assert not evaluate(server, event, element(OP.And, elem(1), elem(2)), missing_is_true, false)
    assert evaluate(server, event, element(OP.Or, elem(1), elem(2)), missing_is_true, true)
    assert not evaluate(server, event, element(OP.Or, elem(1), elem(2)), missing_is_true, false)
    assert not evaluate(server, event, element(OP.Not, elem(1)), missing_is_true)
    assert evaluate(server, event, element(OP.Not, elem(1)), false)
    assert evaluate(server, event, element(OP.And, field("Flag"), elem(1)), true)


def test_srv67_a_where_operand_with_another_type_definition_is_null(server: Server) -> None:
    """Part 4, 7.7.4.5: a field of a type the event is not of is not selected."""
    event = sample_event(Number=(3, I32))
    event.add_property("EventType", BASE_EVENT, ua.VariantType.NodeId)
    other = field("Number", type_definition=AUDIT_EVENT)
    assert not evaluate(server, event, element(OP.Equals, other, lit(3, I32)))
    assert evaluate(server, event, element(OP.IsNull, other))
    assert evaluate(server, event, element(OP.Equals, field("Number"), lit(3, I32)))


def test_srv67_where_operand_applies_the_index_range(server: Server) -> None:
    """Part 4, 7.7.4.5 and 7.27."""
    event = sample_event(Name=("hello", STR))
    ranged = field("Name", index_range="0:1")
    assert evaluate(server, event, element(OP.Equals, ranged, lit("he", STR)))


def test_srv67_select_clauses_apply_type_definition_and_index_range(server: Server) -> None:
    """Part 4, 7.22.3: the select clause operand carries a TypeDefinitionId and an IndexRange."""
    event = sample_event(Name=("hello", STR), Number=(3, I32))
    event.add_property("EventType", BASE_EVENT, ua.VariantType.NodeId)
    from enginir_opcua.server.node_walk import is_subtype
    from enginir_opcua.ua.numeric_range import select_index_range

    def subtype(candidate: ua.NodeId, ancestor: ua.NodeId) -> bool:
        return is_subtype(server.iserver.aspace, candidate, ancestor)

    clauses = [
        field("Name", index_range="1:3"),
        field("Number", type_definition=AUDIT_EVENT),
        field("Name", index_range="10:12"),
        field("Number"),
    ]
    values = event.to_event_fields(clauses, subtype, select_index_range)
    assert values[0].Value == "ell"
    assert values[1].Value is None
    assert values[2].Value.value == ua.StatusCodes.BadIndexRangeNoData
    assert values[3].Value == 3


async def event_item(server: Server, flt: ua.EventFilter, **kw: Any) -> tuple[Any, Any, Any]:
    sub, wire = await open_subscription(server)
    request = item_request(ua.NodeId(ua.ObjectIds.Server), ua.AttributeIds.EventNotifier, queue=10, filter=flt, **kw)
    [result] = await create_items(server, sub, request)
    return sub, wire, result


async def test_srv14_an_event_item_returns_an_event_filter_result(server: Server) -> None:
    """Part 4, 7.22.3: the result has one status per select clause."""
    flt = ua.EventFilter(
        SelectClauses=[
            field("Message"),
            field("NoSuchField"),
            field("Severity", index_range="0:1"),
            field("Message", index_range="x"),
            ua.SimpleAttributeOperand(
                TypeDefinitionId=BASE_EVENT, BrowsePath=path("Message"), AttributeId=ua.AttributeIds.DisplayName
            ),
            ua.SimpleAttributeOperand(TypeDefinitionId=ua.NodeId(ua.ObjectIds.Server), BrowsePath=path("Message")),
            ua.SimpleAttributeOperand(
                TypeDefinitionId=BASE_EVENT,
                BrowsePath=[ua.QualifiedName(None, 0)],
                AttributeId=ua.AttributeIds.Value,
            ),
            field("Message", type_definition=AUDIT_EVENT),
            field("ClientUserId", type_definition=AUDIT_EVENT),
        ]
    )
    _, _, result = await event_item(server, flt)
    assert result.StatusCode.is_good()
    codes = [code.value for code in result.FilterResult.SelectClauseResults]
    assert codes == [
        ua.StatusCodes.Good,
        ua.StatusCodes.BadNodeIdUnknown,
        ua.StatusCodes.BadTypeMismatch,
        ua.StatusCodes.BadIndexRangeInvalid,
        ua.StatusCodes.BadAttributeIdInvalid,
        ua.StatusCodes.BadTypeDefinitionInvalid,
        ua.StatusCodes.BadBrowseNameInvalid,
        ua.StatusCodes.Good,
        ua.StatusCodes.Good,
    ]


async def test_srv14_an_event_item_with_no_usable_select_clause_fails(server: Server) -> None:
    """Part 4, 7.22.3: Bad_MonitoredItemFilterInvalid with the result saying why."""
    _, _, result = await event_item(server, ua.EventFilter(SelectClauses=[field("NoSuchField")]))
    assert result.StatusCode.value == ua.StatusCodes.BadMonitoredItemFilterInvalid
    assert result.FilterResult.SelectClauseResults[0].value == ua.StatusCodes.BadNodeIdUnknown


@pytest.mark.parametrize(
    "elements, status",
    [
        ([element(99, lit(1, I32))], ua.StatusCodes.BadFilterOperatorInvalid),
        ([element(OP.RelatedTo, *[lit(1, I32)] * 6)], ua.StatusCodes.BadFilterOperatorUnsupported),
        ([element(OP.InView, lit(1, I32))], ua.StatusCodes.BadFilterOperatorUnsupported),
        ([element(OP.Equals, lit(1, I32))], ua.StatusCodes.BadFilterOperandCountMismatch),
        ([element(OP.Not, elem(0))], ua.StatusCodes.BadFilterElementInvalid),
        ([element(OP.Not, elem(5))], ua.StatusCodes.BadFilterElementInvalid),
        ([element(OP.IsNull, ua.AttributeOperand())], ua.StatusCodes.BadFilterOperandInvalid),
        ([element(OP.IsNull, ua.LiteralOperand(Value="not a variant"))], ua.StatusCodes.BadFilterLiteralInvalid),
    ],
)
async def test_srv14_a_structurally_wrong_where_clause_fails_the_item(
    server: Server, elements: list[Any], status: int
) -> None:
    """Part 4, 7.7.2 and 7.22.3: the element result carries the reason."""
    flt = ua.EventFilter(SelectClauses=[field("Message")], WhereClause=ua.ContentFilter(Elements=elements))
    _, _, result = await event_item(server, flt)
    assert result.StatusCode.value == ua.StatusCodes.BadMonitoredItemFilterInvalid
    assert result.FilterResult.WhereClauseResult.ElementResults[0].StatusCode.value == status


async def test_srv14_a_valid_where_clause_has_good_element_results(server: Server) -> None:
    """Part 4, 7.7.2."""
    where = ua.ContentFilter(Elements=[element(OP.OfType, lit(BASE_EVENT, ua.VariantType.NodeId))])
    _, _, result = await event_item(server, ua.EventFilter(SelectClauses=[field("Message")], WhereClause=where))
    assert result.StatusCode.is_good()
    assert [r.StatusCode.value for r in result.FilterResult.WhereClauseResult.ElementResults] == [ua.StatusCodes.Good]


async def test_srv14_a_where_clause_with_more_than_100_elements_is_refused(server: Server) -> None:
    """Part 4, 7.7.2: Bad_ContentFilterInvalid."""
    elements = [element(OP.Equals, lit(1, I32), lit(1, I32)) for _ in range(101)]
    flt = ua.EventFilter(SelectClauses=[field("Message")], WhereClause=ua.ContentFilter(Elements=elements))
    _, _, result = await event_item(server, flt)
    assert result.StatusCode.value == ua.StatusCodes.BadContentFilterInvalid


async def test_srv14_modify_of_an_event_item_returns_the_filter_result_and_checks_the_filter(server: Server) -> None:
    """Part 4, 5.13.3.2."""
    flt = ua.EventFilter(SelectClauses=[field("Message")])
    sub, _, created = await event_item(server, flt)
    params = ua.MonitoringParameters(ClientHandle=1, QueueSize=10, DiscardOldest=True, Filter=flt)
    [good] = modify_items(server, sub, (created.MonitoredItemId, params))
    assert good.StatusCode.is_good()
    assert good.FilterResult.SelectClauseResults[0].value == ua.StatusCodes.Good
    bad = ua.MonitoringParameters(
        ClientHandle=1, QueueSize=10, DiscardOldest=True, Filter=ua.EventFilter(SelectClauses=[field("Nope")])
    )
    [refused] = modify_items(server, sub, (created.MonitoredItemId, bad))
    assert refused.StatusCode.value == ua.StatusCodes.BadMonitoredItemFilterInvalid
    [removed] = modify_items(
        server, sub, (created.MonitoredItemId, ua.MonitoringParameters(ClientHandle=1, QueueSize=10))
    )
    assert removed.StatusCode.value == ua.StatusCodes.BadMonitoredItemFilterInvalid


async def test_srv67_delivered_events_use_the_select_operand_type_definition_and_index_range(server: Server) -> None:
    """Part 4, 7.22.3 and 7.7.4.5, end to end."""
    flt = ua.EventFilter(
        SelectClauses=[
            field("Message"),
            field("SourceName", index_range="0:2"),
            field("ClientUserId", type_definition=AUDIT_EVENT),
        ]
    )
    sub, wire, result = await event_item(server, flt)
    assert result.StatusCode.is_good()
    generator = await server.get_event_generator()
    generator.event.SourceName = "abcdef"
    await generator.trigger(message="hi")
    [notification] = await publish(sub, wire)
    message, source_name, user = notification.EventFields
    assert message.Value.Text == "hi"
    assert source_name.Value == "abc"
    assert user.Value is None


async def test_srv14_where_clause_filters_delivery_by_event_type_including_subtypes(server: Server) -> None:
    """Part 4, 7.7.3 (OfType), end to end."""
    audit_only = ua.ContentFilter(Elements=[element(OP.OfType, lit(AUDIT_EVENT, ua.VariantType.NodeId))])
    sub, wire, result = await event_item(
        server, ua.EventFilter(SelectClauses=[field("Message")], WhereClause=audit_only)
    )
    assert result.StatusCode.is_good()
    plain = await server.get_event_generator()
    await plain.trigger(message="plain")
    audit = await server.get_event_generator(ua.ObjectIds.AuditSecurityEventType)
    await audit.trigger(message="audit")
    notifications = await publish(sub, wire)
    assert [n.EventFields[0].Value.Text for n in notifications] == ["audit"]


OVERFLOW_TYPE = ua.NodeId(ua.ObjectIds.EventQueueOverflowEventType)


async def overflow_item(server: Server, queue: int, discard_oldest: bool, where: Any = None) -> tuple[Any, Any]:
    flt = ua.EventFilter(
        SelectClauses=[field("Message"), field("EventType")],
        WhereClause=where if where is not None else ua.ContentFilter(),
    )
    sub, wire = await open_subscription(server)
    request = item_request(
        ua.NodeId(ua.ObjectIds.Server),
        ua.AttributeIds.EventNotifier,
        queue=queue,
        discard_oldest=discard_oldest,
        filter=flt,
    )
    [result] = await create_items(server, sub, request)
    assert result.StatusCode.is_good()
    return sub, wire


def labels(notifications: list[Any]) -> list[str]:
    return [
        "overflow" if n.EventFields[1].Value == OVERFLOW_TYPE else n.EventFields[0].Value.Text for n in notifications
    ]


@pytest.mark.parametrize(
    ("discard_oldest", "expected"),
    [
        pytest.param(
            True, ["overflow", "m3", "m4", "m5"], id="srv60_discard_oldest_puts_one_overflow_event_at_the_front"
        ),
        pytest.param(
            False, ["m1", "m2", "m5", "overflow"], id="srv60_discard_newest_puts_the_overflow_event_at_the_end"
        ),
    ],
)
async def test_srv60_queue_overflow_adds_one_overflow_event(
    server: Server, discard_oldest: bool, expected: list[str]
) -> None:
    """Part 4, 5.13.1.5: generated at the first discard, in addition to the queue size, at the front or at the end."""
    sub, wire = await overflow_item(server, 3, discard_oldest)
    generator = await server.get_event_generator()
    for number in range(1, 6):
        await generator.trigger(message=f"m{number}")
    assert labels(await publish(sub, wire)) == expected


async def test_srv60_a_new_overflow_event_follows_the_next_first_discard(server: Server) -> None:
    """Part 4, 5.13.1.5: once the queue was emptied, the next overflow is announced again."""
    sub, wire = await overflow_item(server, 2, True)
    generator = await server.get_event_generator()
    for number in range(1, 4):
        await generator.trigger(message=f"m{number}")
    assert labels(await publish(sub, wire)) == ["overflow", "m2", "m3"]
    for number in range(4, 7):
        await generator.trigger(message=f"m{number}")
    assert labels(await publish(sub, wire)) == ["overflow", "m5", "m6"]


async def test_srv60_the_overflow_event_ignores_the_where_clause(server: Server) -> None:
    """Part 4, 5.13.1.5 and 7.22.3."""
    audit_only = ua.ContentFilter(Elements=[element(OP.OfType, lit(AUDIT_EVENT, ua.VariantType.NodeId))])
    sub, wire = await overflow_item(server, 1, True, audit_only)
    generator = await server.get_event_generator(ua.ObjectIds.AuditSecurityEventType)
    for number in range(1, 3):
        await generator.trigger(message=f"a{number}")
    assert labels(await publish(sub, wire)) == ["overflow", "a2"]


async def test_srv60_overflow_event_content(server: Server) -> None:
    """Part 4, 5.13.1.5 and Part 5, 6.4.2: source, time, message and severity of the overflow event."""
    flt = ua.EventFilter(
        SelectClauses=[
            field("EventType"),
            field("SourceNode"),
            field("SourceName"),
            field("Severity"),
            field("Time"),
            field("ReceiveTime"),
            field("EventId"),
            field("Message"),
        ]
    )
    sub, wire = await open_subscription(server)
    request = item_request(ua.NodeId(ua.ObjectIds.Server), ua.AttributeIds.EventNotifier, queue=1, filter=flt)
    await create_items(server, sub, request)
    generator = await server.get_event_generator()
    await generator.trigger(message="one")
    await generator.trigger(message="two")
    notifications = await publish(sub, wire)
    overflow = notifications[0].EventFields
    assert overflow[0].Value == OVERFLOW_TYPE
    assert overflow[1].Value == ua.NodeId(ua.ObjectIds.Server)
    assert overflow[2].Value == "Server"
    assert overflow[3].Value == 1
    assert overflow[4].Value is not None and overflow[5].Value is not None
    assert len(overflow[6].Value) == 16
    assert overflow[7].Value.Text
    assert notifications[1].EventFields[7].Value.Text == "two"


def test_where_clause():
    cf = ua.ContentFilter()
    el = ua.ContentFilterElement()
    op = ua.SimpleAttributeOperand()
    op.AttributeId = ua.AttributeIds.Value
    op.BrowsePath.append(ua.QualifiedName("property", 2))
    el.FilterOperands.append(op)
    for i in range(10):
        op = ua.LiteralOperand(Value=ua.Variant(i))
        el.FilterOperands.append(op)
    el.FilterOperator = ua.FilterOperator.InList
    cf.Elements.append(el)
    wce = WhereClauseEvaluator(logging.getLogger(__name__), None, cf)
    ev = BaseEvent()
    ev._freeze = False
    ev.property = 3
    assert wce.eval(ev)


async def custom_event() -> tuple[Server, Any]:
    server = Server()
    await server.init()
    etype = await server.create_custom_event_type(
        2,
        "FieldDictEvent",
        ua.ObjectIds.BaseEventType,
        [("PropertyNum", ua.VariantType.Float), ("PropertyString", ua.VariantType.String)],
    )
    generator = await server.get_event_generator(etype)
    return server, generator.event


async def test_com27_field_dict_of_a_fresh_custom_event_does_not_raise() -> None:
    """Design: the field dict is the storage form of an event (events R19)."""
    server, event = await custom_event()
    fields = event.get_event_props_as_fields_dict()
    assert "_freeze" not in fields
    assert "PropertyNum" in fields
    assert "PropertyString" in fields
    assert "Message" in fields
    await server.stop()


async def test_com27_field_dict_round_trips() -> None:
    """Design: from_field_dict(field_dict(e)) has the same field dict."""
    server, event = await custom_event()
    event.PropertyNum = 2.5
    event.PropertyString = "text"
    fields = event.get_event_props_as_fields_dict()
    again = Event.from_field_dict(fields).get_event_props_as_fields_dict()
    assert again == fields
    assert again["PropertyNum"].Value == 2.5
    await server.stop()
