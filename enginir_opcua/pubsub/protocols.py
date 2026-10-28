"""
Protocols which are used to decouple components from pubsub
"""

from typing import Any, Protocol

from ..ua.uaprotocol_auto import PubSubState
from ..ua.uatypes import ExtensionObject, String
from .dataset import DataSetMeta, DataSetValue, PublishedDataSet
from .uadp import PublisherIdValue, UadpNetworkMessage


class PubSubSender(Protocol):
    """
    Implements sending Messages
    """

    def send_uadp(self, msgs: list[UadpNetworkMessage], destination: Any = None, max_size: int = 0) -> list[int]:
        """
        Sends UADP messages, to the destination if given and to the connection's address otherwise. Messages larger
        than max_size (when it is above 0) are not sent; their sizes are returned.
        """
        raise NotImplementedError

    async def resolve_destination(self, url: str) -> Any:
        """
        Resolves the address a WriterGroup sends to, once, before it starts publishing
        """
        raise NotImplementedError

    def get_publisher_id(self) -> PublisherIdValue | None:
        """
        Returns the publisher id, with its type, for creating messages
        """
        raise NotImplementedError


class IPubSub(Protocol):
    """
    Interface to glue PublishedDataSet and Connection together
    """

    def get_published_dataset(self, name: String) -> PublishedDataSet | None:
        raise NotImplementedError


class PubSubReceiver(Protocol):
    """
    Receiver for Pubsub Messages
    """

    async def got_uadp(self, msg: UadpNetworkMessage):
        """Called when a msg is received"""
        raise NotImplementedError


class SubscribedDataSet(Protocol):
    """Receiver for subscribed datasets"""

    async def on_dataset_received(self, meta: DataSetMeta, fields: list[DataSetValue]):
        """Called when a published dataset received an update"""
        raise NotImplementedError

    async def on_state_change(self, meta: DataSetMeta, state: PubSubState):
        """Called when a DataSet state changes"""
        raise NotImplementedError

    def get_subscribed_dataset(self) -> ExtensionObject:
        """
        Returns the ExtensionObject
        """
        raise NotImplementedError
