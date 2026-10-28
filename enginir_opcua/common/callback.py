"""
server side implementation of callback event
"""

import inspect
from collections.abc import Awaitable, Callable
from enum import Enum
from typing import Any


class CallbackType(Enum):
    """
    The possible types of a Callback type.

    Members: Null, ItemSubscriptionCreated, ItemSubscriptionModified, ItemSubscriptionDeleted,
    PreWrite, PostWrite, PreRead, PostRead.

    """

    Null = 0
    ItemSubscriptionCreated = 1
    ItemSubscriptionModified = 2
    ItemSubscriptionDeleted = 3
    PreWrite = 4
    PostWrite = 5
    PreRead = 6
    PostRead = 7


class Callback:
    def __init__(self) -> None:
        self.__name: str | None = None

    def setName(self, name: str | None) -> None:
        self.__name = name

    def getName(self) -> str | None:
        return self.__name


class ServerItemCallback(Callback):
    def __init__(self, request_params: Any, response_params: Any, user: Any = None, is_external: bool = False) -> None:
        super().__init__()
        self.request_params = request_params
        self.response_params = response_params
        self.is_external = is_external
        self.user = user


class CallbackSubscriberInterface:
    def getSubscribedEvents(self) -> dict[str, Any]:
        raise NotImplementedError()


Listener = Callable[[Callback, "CallbackService"], Awaitable[None] | None]


class CallbackService:
    def __init__(self) -> None:
        self._listeners: dict[str, list[tuple[int, int, Listener]]] = {}
        self._sequence = 0

    async def dispatch(self, eventName: str, event: Callback | None = None) -> Callback:
        if event is None:
            event = Callback()
        elif not isinstance(event, Callback):
            raise ValueError("Unexpected event type given")
        event.setName(eventName)
        for _, _, listener in list(self._listeners.get(eventName, [])):
            await self.call_listener(event, listener)
        return event

    async def call_listener(self, event: Callback, listener: Listener) -> None:
        result = listener(event, self)
        if inspect.isawaitable(result):
            await result

    def addListener(self, eventName: str, listener: Listener, priority: int = 0) -> None:
        self._sequence += 1
        entries = [*self._listeners.get(eventName, []), (priority, self._sequence, listener)]
        entries.sort(key=lambda entry: entry[:2])
        self._listeners[eventName] = entries

    def removeListener(self, eventName: str, listener: Listener | None = None) -> None:
        if eventName not in self._listeners:
            return
        if listener is None:
            del self._listeners[eventName]
        else:
            self._listeners[eventName] = [entry for entry in self._listeners[eventName] if entry[2] is not listener]

    def addSubscriber(self, subscriber: CallbackSubscriberInterface) -> None:
        if not isinstance(subscriber, CallbackSubscriberInterface):
            raise ValueError("Unexpected subscriber type given")
        for eventName, params in subscriber.getSubscribedEvents().items():
            if isinstance(params, str):
                self.addListener(eventName, getattr(subscriber, params))
            elif isinstance(params, list):
                if not params:
                    raise ValueError(f'Invalid params "{params!r}" for event "{eventName!s}"')
                if len(params) <= 2 and isinstance(params[0], str):
                    priority = params[1] if len(params) > 1 else 0
                    self.addListener(eventName, getattr(subscriber, params[0]), priority)
                else:
                    for listener in params:
                        priority = listener[1] if len(listener) > 1 else 0
                        self.addListener(eventName, getattr(subscriber, listener[0]), priority)
            else:
                raise ValueError(f'Invalid params for event "{eventName!s}"')
