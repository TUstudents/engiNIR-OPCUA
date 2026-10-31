"""
Fire events from the server: build an event object of an event type and report it to the subscriptions.
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from enginir_opcua import ua
from enginir_opcua.server.internal_session import InternalSession

from ..common import Node, event_objects, events


def stamp_event(event: Any, time_attr: datetime | None = None) -> None:
    """
    Give an event a new EventId and set its Time, ReceiveTime and LocalTime.

    :param time_attr: The Time of the event; now if None.
    """
    event.EventId = ua.Variant(secrets.token_bytes(16), ua.VariantType.ByteString)
    event.Time = time_attr if time_attr else datetime.now(UTC)
    event.ReceiveTime = datetime.now(UTC)
    event.LocalTime = ua.uaprotocol_auto.TimeZoneDataType()
    localtime = time.localtime(event.Time.timestamp())
    event.LocalTime.Offset = localtime.tm_gmtoff // 60
    event.LocalTime.DaylightSavingInOffset = bool(localtime.tm_isdst > 0)


class EventGenerator:
    """
    Fires events of one event type from one emitting node.

    Create it with an InternalSession and call init() before trigger(). The event object in the
    event attribute has one member per field of the event type; set them before each trigger().
    """

    def __init__(self, isession: InternalSession) -> None:
        self.logger = logging.getLogger(__name__)
        self.isession = isession
        self.event: Any = None

    async def init(
        self,
        etype: event_objects.BaseEvent | Node | ua.NodeId | int | None = None,
        emitting_node: Node | ua.NodeId | int = ua.ObjectIds.Server,
        add_generates_event: bool = True,
    ) -> None:
        """
        Build the event object and prepare the emitting node.

        A Condition event gets a NodeId property for its ConditionId, which the ConditionType does not model as a
        component (OPC 10000-9 v1.05, 5.5.2). The emitting node gets the SubscribeToEvents bit and, with
        add_generates_event, a GeneratesEvent reference to the event type.

        :param etype: An event object, or the event type as Node, NodeId or numeric id; BaseEventType if None.
        :param emitting_node: The node the event is reported through, as Node, NodeId or numeric id.
        :param add_generates_event: Add the GeneratesEvent reference.
        """
        node = None
        if etype is None:
            etype = event_objects.BaseEvent()
        if isinstance(etype, event_objects.BaseEvent):
            self.event = etype
        elif isinstance(etype, Node):
            node = etype
        elif isinstance(etype, ua.NodeId):
            node = Node(self.isession, etype)
        else:
            node = Node(self.isession, ua.NodeId(etype))

        if node:
            self.event = await events.get_event_obj_from_type_node(node)
        if isinstance(self.event, event_objects.Condition):
            self.event.add_property("NodeId", None, ua.VariantType.NodeId)

        if isinstance(emitting_node, Node):
            pass
        elif isinstance(emitting_node, ua.NodeId):
            emitting_node = Node(self.isession, emitting_node)
        else:
            emitting_node = Node(self.isession, ua.NodeId(emitting_node))

        self.event.emitting_node = emitting_node.nodeid
        if not self.event.SourceNode:
            self.event.SourceNode = emitting_node.nodeid
        if not self.event.SourceName:
            self.event.SourceName = (await Node(self.isession, self.event.SourceNode).read_browse_name()).Name

        await self._set_subscribe_to_events(emitting_node)

        if add_generates_event:
            refs = []
            ref = ua.AddReferencesItem()
            ref.IsForward = True
            ref.ReferenceTypeId = ua.NodeId(ua.ObjectIds.GeneratesEvent)
            ref.SourceNodeId = emitting_node.nodeid
            ref.TargetNodeClass = ua.NodeClass.ObjectType
            ref.TargetNodeId = self.event.EventType
            refs.append(ref)
            results = await self.isession.add_references(refs)
            for result in results:
                result.check()

    async def _set_subscribe_to_events(self, emitting_node: Node) -> None:
        try:
            bits = await emitting_node.read_event_notifier()
        except ua.UaStatusCodeError as error:
            if error.code == ua.StatusCodes.BadAttributeIdInvalid:
                return
            raise
        if ua.EventNotifier.SubscribeToEvents not in bits:
            await emitting_node.set_event_notifier([*bits, ua.EventNotifier.SubscribeToEvents])

    def __str__(self) -> str:
        return (
            f"EventGenerator(Type:{self.event.EventType}, Emitting Node:{self.event.emitting_node.to_string()}, "
            f"Time:{self.event.Time}, Message: {self.event.Message})"
        )

    __repr__ = __str__

    async def trigger(
        self,
        time_attr: datetime | None = None,
        message: str | None = None,
        subscription_id: int | None = None,
    ) -> None:
        """
        Stamp the event and report it to the subscriptions.

        :param time_attr: The Time of the event; now if None.
        :param message: The Message; without one, an empty Message becomes the BrowseName of the SourceNode.
        :param subscription_id: Report only to this subscription.
        """
        stamp_event(self.event, time_attr)

        if message:
            self.event.Message = ua.LocalizedText(message)
        elif not self.event.Message or not getattr(self.event.Message, "Text", True):
            self.event.Message = ua.LocalizedText(
                (await Node(self.isession, self.event.SourceNode).read_browse_name()).Name
            )

        await self.isession.subscription_service.trigger_event(self.event, subscription_id=subscription_id)
