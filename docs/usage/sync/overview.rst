=====================
Synchronous Interface
=====================

You don't like to work with ``asyncio`` and ``async`` / ``await`` or you need to integrate
the package in code which is not using ``asyncio``? The :mod:`enginir_opcua.sync` module provides
a convenient wrapper around the client and server and provides synchronous versions of
the node and subscription classes. It has the same methods, with the same parameters, as the
asynchronous classes; each call blocks until the result is there.

.. code-block:: python

    from enginir_opcua.sync import Client

    with Client("opc.tcp://localhost:4840/enginir-opcua/server/") as client:
        node = client.nodes.objects.get_child(["2:MyObject", "2:MyVariable"])
        print(node.read_value())

How it works
============

Every wrapper object talks to a :class:`~enginir_opcua.sync.ThreadLoop`: a thread that runs an event loop. A call hands a
coroutine to that loop and waits for the result. A ``Client`` or ``Server`` created without ``tloop=`` makes its own
ThreadLoop and stops it when you call ``disconnect()`` or ``stop()``. To share one thread between several objects, create
a ThreadLoop and pass it:

.. code-block:: python

    with ThreadLoop() as tloop:
        client = Client(url, tloop=tloop)
        server = Server(tloop=tloop)

``Server.quickstart(...)`` and ``Client.quickstart(...)`` take ``tloop=`` too, so a quick-setup server and client can
share one thread; ``client.init_pki()`` creates the client's certificate before ``connect()``.

A ThreadLoop you pass in is never stopped by the objects that use it. The thread is a daemon thread, so a program that
forgets to stop it still exits; clients that are still connected at that time are disconnected on a best-effort basis.

Reconnecting
------------

``connect()`` after ``disconnect()`` works: the ThreadLoop starts again, and the nodes you got before still work. The
reconnect settings of the async client are available: ``Client(url, auto_reconnect=True, reconnect_max_delay=30,
reconnect_request_timeout=60)``. ``client.state`` shows the connection state, and ``client.add_state_listener(callback)``
calls ``callback(state)`` on every change, on the handler thread.

Timeouts
========

A call waits at most ``sync_wrapper_timeout`` seconds (default 120; ``None`` waits without limit). When the time is up,
the call is cancelled, and ``TimeoutError`` is raised only after its cancellation has run, so the operation does not
continue in the background. A request that was already sent may still have been carried out by the server: after a
timeout of a write or a method call, read the state before you try again. ``Subscription.next_event(timeout)`` waits for its
own timeout and returns ``None`` when it expires; iterating over a subscription waits as long as it takes.

Subscription handlers
=====================

A handler object works as in the async API, but its methods are plain functions, and they run on a *handler thread*, not
on the event loop. A client has one handler thread, and it calls the handlers one after another in the order the events
arrived, for all subscriptions of that client. Because they do not run on the loop, handlers may call the synchronous API:

.. code-block:: python

    class Handler:
        def datachange_notification(self, node, value, data):
            print(node.read_browse_name(), value)

    subscription = client.create_subscription(500, Handler())
    subscription.subscribe_data_change(variable)

A slow handler delays the following handlers but never blocks the connection. At most ``handler_queue_maxsize`` calls
(default 1000) wait for the thread; when the queue is full, the oldest call is dropped, a warning is logged and the
observer's ``on_messages_dropped`` is called (see :doc:`../common/observer`). The same thread runs state listeners and
``connection_lost_callback``.

Alarms and conditions
---------------------

``Server.create_condition`` and ``Server.get_condition`` return a :class:`~enginir_opcua.sync.SyncCondition`, the
synchronous twin of the server's Condition handle: ``activate``, ``deactivate``, ``update_value``, ``acknowledge``,
``confirm``, ``add_comment``, ``shelve_timed``, ``shelve_one_shot``, ``unshelve`` and the other calls block until the
server has changed the state and published the events, and ``active``, ``acked``, ``severity``, ``shelving_state`` and
the other properties read the current state. ``Server.conditions`` lists them, and ``delete_condition`` and
``refresh_required`` are wrapped as well.

.. code-block:: python

    alarm = server.create_condition(tank, ua.NodeId(ua.ObjectIds.ExclusiveLevelAlarmType), "TankLevel",
                                    limits={"High": 70.0})
    alarm.update_value(75.0)
    alarm.acknowledge(alarm.last_event_id(), "seen")

Where the sync API must not be used
-----------------------------------

A call to the synchronous API from code that runs on the loop thread could only wait for itself. The wrapper raises
``RuntimeError`` instead of waiting. This happens, for example, in a callback that the server calls on the loop, such as
the one of ``set_attribute_value_callback``. In such a place use the asynchronous API, or hand the work to another thread.

Differences to the async API
============================

- Nodes are ``SyncNode`` objects; arguments of any kind may be ``SyncNode`` objects (also in lists, tuples and dicts), and
  results are converted back, with tuples staying tuples.
- Methods of the async classes that serve internal purposes are not offered, and ``Server.get_pubsub()`` is not
  wrapped: use PubSub through the async API.
- The extra parameters of the constructors are ``tloop``, ``sync_wrapper_timeout``, ``handler_queue_maxsize`` and, for the
  client, ``observer``.
