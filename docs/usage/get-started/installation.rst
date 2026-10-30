========================
Installation & CLI Tools
========================

Package Installation
====================

engiNIR-OPCUA is published on `PyPI <https://pypi.org/project/enginir-opcua/>`_ as :code:`enginir-opcua`
and imported as :code:`enginir_opcua`. It needs Python 3.12 or newer. Add it to a project managed with
`uv <https://docs.astral.sh/uv/>`_:

.. code-block:: console

    uv add enginir-opcua

To install only the command line program, without a project:

.. code-block:: console

    uv tool install enginir-opcua

To use the current development version from the source repository:

.. code-block:: console

    uv add git+https://github.com/TUstudents/engiNIR-OPCUA

To check the installation, or to report the version in a bug report:

.. code-block:: console

    uv run python -c "import enginir_opcua; print(enginir_opcua.__version__)"

engiNIR-OPCUA is a fork of `FreeOpcUa/opcua-asyncio <https://github.com/FreeOpcUa/opcua-asyncio>`_ 2.1.0.
It can be installed next to the :code:`asyncua` package, because the import package and the command names differ;
:doc:`../../migration` lists what changes when you move an application over.


Command Line Tools
==================

The package installs one program, :code:`enginir-opcua`, with a subcommand for each job (also available as
:code:`python -m enginir_opcua`):

:code:`enginir-opcua read`:
    Read an attribute of a node, by default its value.

:code:`enginir-opcua write`:
    Write an attribute of a node, by default its value. Without :code:`--datatype` the text is converted to the DataType of
    the node.

:code:`enginir-opcua call`:
    Call a method of a node.

:code:`enginir-opcua ls` (also :code:`browse`):
    Browse below a node and print the result.

:code:`enginir-opcua subscribe`:
    Subscribe to data changes or events of a node and print them until stopped with Ctrl-C.

:code:`enginir-opcua history`:
    Read the history of a node.

:code:`enginir-opcua discover`:
    Perform discovery and print the servers and endpoints.

:code:`enginir-opcua server`:
    Run a demo server. It offers an endpoint **without security**, listens on 127.0.0.1 unless told otherwise and accepts
    only anonymous read-only sessions; it is for trying things out. By importing XML definitions and using
    :code:`enginir-opcua write` it is possible to expose data with it.

:code:`enginir-opcua shell`:
    Connect to a server and open a Python shell (IPython if installed) with :code:`client`, :code:`root`, :code:`objects` and,
    when :code:`-n` or :code:`-p` is given, :code:`mynode`.

:code:`enginir-opcua generate-structs`:
    Generate a Python module from a structure dictionary (pre-1.04 servers).

For the options of a command run:

.. code-block:: console

    enginir-opcua --help
    enginir-opcua read --help

Common to the commands that connect: :code:`-u URL`, :code:`--timeout SECONDS`, :code:`--security`, :code:`--pki-dir`,
:code:`--user` and :code:`--ask-password` (the password can also come from the environment variable
:code:`ENGINIR_OPCUA_PASSWORD`; there is no option that takes it on the command line). The commands that work on a node take
:code:`-n NODEID` and :code:`-p BROWSEPATH`. Errors are printed as one line on standard error, with exit status 1; a usage
error gives 2.

.. code-block:: console

    $ enginir-opcua ls -u opc.tcp://127.0.0.1:4840 -n i=85
    $ enginir-opcua read -u opc.tcp://127.0.0.1:4840 -p "0:Objects,2:MyObject,2:MyVariable"
    $ enginir-opcua write -u opc.tcp://admin@127.0.0.1:4840 -n "ns=2;i=3" 6.5
    $ enginir-opcua write --array -n "ns=2;i=4" "1.5,2.5"
    $ enginir-opcua call -n "ns=2;i=1" -m 2:Multiply 3 4

Values for :code:`write` and :code:`call`: :code:`--datatype` is one of guess, bool, sbyte, byte, int16, uint16, int32,
uint32, int64, uint64, float, double, string, datetime, guid, bytestring, xmlelement, nodeid, expandednodeid, qualifiedname,
localizedtext and statuscode (and auto for :code:`write`). A list needs :code:`--array`, which splits the value at
:code:`--separator` (default a comma); without it a comma is part of the text.

The older scripts :code:`enginir-uaread`, :code:`enginir-uawrite`, :code:`enginir-uacall`, :code:`enginir-uals`,
:code:`enginir-uabrowse`, :code:`enginir-uasubscribe`, :code:`enginir-uahistoryread`, :code:`enginir-uadiscover`,
:code:`enginir-uaserver`, :code:`enginir-uaclient` and :code:`enginir-uageneratestructs` still work, print a notice that they
are deprecated, and are removed in 4.0.0.
