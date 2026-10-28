====================
Observing the client
====================

An :class:`~enginir_opcua.observer.Observer` lets an application watch what a client does, without the library depending on a
metrics or tracing package. You give the client an observer; the library calls its methods when a request has finished, when
the connection state changes, and when something happens to a subscription. What the observer does with the calls (a log line,
a counter, a histogram, a trace span) is up to the application. Without an observer the library does nothing extra.

Using it
========

Subclass ``Observer``, override the hooks you need and hand an instance to the client:

.. code-block:: python

    from enginir_opcua import Client
    from enginir_opcua.observer import Observer, SubscriptionEvent

    class Metrics(Observer):
        def on_request(self, request_type, duration, error):
            record_latency(request_type, duration, failed=error is not None)

        def on_messages_lost(self, subscription_id, count):
            lost_counter.inc(count)

    client = Client(url, observer=Metrics())

``client.observer`` is also a property, so ``client.observer = Metrics()`` works; set it before ``connect()``. The sync
``Client`` takes the same ``observer`` argument. Hooks you do not override do nothing.

The hooks
=========

``on_request(request_type, duration, error)``
    A service request has finished. ``request_type`` is the name of the request class (``"ReadRequest"``), ``duration`` is in
    seconds, ``error`` is the exception that ended the request, or ``None``. A timed-out or cancelled request is reported with
    its exception. The duration includes the wait for a free slot when many requests are sent at once
    (``set_max_concurrent_requests``), and for the Publish requests it is the time the request was parked at the server,
    up to the publishing interval, so these are not round-trip times. Tell them apart by ``request_type``.

``on_state_change(state)``
    The connection state of the client changed to ``state``, an ``enginir_opcua.client.ua_client.UaClientState``. Each change is
    reported once, in order. While the client reconnects, only ``reconnecting`` and the final state are reported.

``on_subscription_event(subscription_id, event)``
    A subscription was ``created``, ``recreated`` (the server had lost it and the client made a new one, with a new id) or
    ``deleted``. ``event`` is a :class:`~enginir_opcua.observer.SubscriptionEvent`.

``on_notification(subscription_id, event_count)``
    A message from the server was processed. ``event_count`` is the number of events passed on to the handler or the iterator;
    0 means a keep-alive message (or a message that held nothing the client knew).

``on_messages_dropped(subscription_id, count)``
    The client dropped received messages because the application did not take them fast enough (the inbox of the subscription
    was full). Data was lost *in the client*. In the sync wrapper it is also called when the handler thread's queue
    overflows (``subscription_id`` is then ``None``).

``on_messages_lost(subscription_id, count)``
    Sequence numbers of messages are missing and the client could not fetch them again with Republish. Data was lost *between
    server and client*.

Rules for hooks
===============

- A hook runs on the event loop of the client, at the place where the event happens. A slow hook slows the client down and a
  blocking hook stops it. Increment a counter, append to a list or put the event on a queue; do the work elsewhere.
- An exception in a hook is logged and ignored; it never changes what the library does. Only ``Exception`` is caught.
- A hook gets names, counts and ids. It does not get node ids, values, credentials or certificates. The exception passed to
  ``on_request`` may contain a node id or a user name in its message; leave it out when you export it.
- Override the ``on_*`` hooks only. ``observe_request`` is the method that times a request and is not guarded against
  errors.
- There is no observer on the server side. For what a server does see the logs, ``INFO`` level of the ``enginir_opcua``
  loggers.

The classes are listed in the API reference under :mod:`enginir_opcua.observer`.
