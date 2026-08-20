Install
=======

To use JSON-RPC bindings for Delta Chat core you will need
a ``deltachat-rpc-server`` binary which provides Delta Chat core API over JSON-RPC
and a ``deltachat-rpc-client`` Python package which is a JSON-RPC client that starts ``deltachat-rpc-server`` process and uses JSON-RPC API.

`Create a virtual environment <https://docs.python.org/3/library/venv.html>`__ if you
don’t have one already and activate it::

   $ python -m venv venv
   $ . venv/bin/activate

Install ``deltachat-rpc-server``
--------------------------------

To get ``deltachat-rpc-server`` binary you have three options:

1. Install ``deltachat-rpc-server`` from PyPI using ``pip install deltachat-rpc-server``.
2. Build and install ``deltachat-rpc-server`` from source with ``cargo install --locked --git https://github.com/chatmail/core/ deltachat-rpc-server``.
3. Download prebuilt release from https://github.com/chatmail/core/releases and install it into ``PATH``.

Check that ``deltachat-rpc-server`` is installed and can run::

   $ deltachat-rpc-server --version
   1.131.4

Then install ``deltachat-rpc-client`` with ``pip install deltachat-rpc-client``.

Install ``deltachat-rpc-client``
--------------------------------

To get ``deltachat-rpc-client`` Python library you can:

1. Install ``deltachat-rpc-client`` from PyPI using ``pip install deltachat-rpc-client``.
2. Install ``deltachat-rpc-client`` from source with ``pip install git+https://github.com/chatmail/core.git@main#subdirectory=deltachat-rpc-client``.
