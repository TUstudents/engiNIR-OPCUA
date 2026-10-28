=========================
Demo Server in Docker
=========================

The repository contains a ``Dockerfile`` that packages the demo server, ``enginir-opcua server``, as a container image.
The library doesn't need it. It's there to run a test server quickly, for example to try out a client or to run
integration tests from another project against it.

What it does
============

- It starts from ``python:3.14-slim``, copies the repository, and installs the package from that source.
- It exposes port ``4840`` and runs ``enginir-opcua server --url opc.tcp://0.0.0.0:4840``. The server listens on all
  interfaces of the container, because the container needs it, and offers the unencrypted ``NoSecurity`` endpoint.
  Use it on a test network only.
- ``.dockerignore`` keeps ``.git``, ``.venv``, build output, the ``nodeset`` submodule and the downloaded OPC UA
  specifications (``docs/opcua-spec/downloads``, which may not be redistributed) out of the image.

Usage
=====

.. code-block:: console

    docker build -t enginir-opcua-demo .
    docker run --rm -p 4840:4840 enginir-opcua-demo
    # connect from the host
    enginir-opcua ls -u opc.tcp://localhost:4840

Pass the command and its options after the image name, for example ``--populate`` to add a writable variable and a
callable method (repeat ``--url``, because the command replaces the one of the image):

.. code-block:: console

    docker run --rm -p 4840:4840 enginir-opcua-demo enginir-opcua server --url opc.tcp://0.0.0.0:4840 --populate

Maintenance
===========

Nothing builds this image automatically: CI doesn't run ``docker build``. Check that it still builds when
``pyproject.toml``, the command line tools or the supported Python versions change.
