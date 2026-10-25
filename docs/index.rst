===========================
engiNIR-OPCUA Documentation
===========================

OPC UA / IEC 62541 client and server library for Python 3.10+ and PyPy, built on asyncio.

engiNIR-OPCUA is a modified version of `opcua-asyncio <https://github.com/FreeOpcUa/opcua-asyncio>`_ 2.1.0,
forked on 2026-10-25.

.. note:: This documentation is a work in progress. Documenting a project takes time, effort
   and loads of coffee. We are more than happy to get feedback and merge requests relating
   the documentation.

OPC-UA implementation is quasi complete and has been tested against many different OPC-UA stacks. API offers both a low level interface to send and receive all UA defined structures and high level classes allowing to write a server or a client in a few lines. It is easy to mix high level objects and low level UA calls in one application.

Most low-level code is generated from the OPC UA nodeset files.

- Source code: https://github.com/TUstudents/engiNIR-OPCUA
- Examples: https://github.com/TUstudents/engiNIR-OPCUA/tree/master/examples
- A simple GUI client, written for upstream opcua-asyncio: https://github.com/FreeOpcUa/opcua-client-gui


.. toctree::
   :maxdepth: 2
   :caption: Contents:
   :hidden:

   usage/index
   api/index



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
