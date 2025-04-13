import sys

if sys.version_info >= (3, 8):
    from importlib.metadata import PackageNotFoundError, version
else:
    from importlib_metadata import PackageNotFoundError, version

from . import capi, events, hookspec  # noqa
from .account import Account, get_core_info  # noqa
from .capi import ffi  # noqa
from .chat import Chat  # noqa
from .contact import Contact  # noqa
from .hookspec import account_hookimpl, global_hookimpl  # noqa
from .message import Message  # noqa

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    # package is not installed
    __version__ = "0.0.0.dev0-unknown"


def register_global_plugin(plugin):
    """Register a global plugin which implements one or more
    of the :class:`deltachat.hookspec.Global` hooks.
    """
    gm = hookspec.Global._get_plugin_manager()
    gm.register(plugin)
    gm.check_pending()


def unregister_global_plugin(plugin):
    gm = hookspec.Global._get_plugin_manager()
    gm.unregister(plugin)


register_global_plugin(events)


def run_cmdline(argv=None, account_plugins=None):
    """Run a simple default command line app, registering the specified
    account plugins.
    """
    import argparse

    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(prog=argv[0] if argv else None)
    parser.add_argument("db", action="store", help="database file")
    parser.add_argument("--show-ffi", action="store_true", help="show low level ffi events")
    parser.add_argument("--email", action="store", help="email address")
    parser.add_argument("--password", action="store", help="password")

    args = parser.parse_args(argv[1:])

    ac = Account(args.db)
    qr = ac.get_setup_contact_qr()
    print(qr)

    ac.run_account(addr=args.email, password=args.password, account_plugins=account_plugins, show_ffi=args.show_ffi)

    addr = ac.get_config("addr")
    print(f"{addr}: waiting for message")

    ac.wait_shutdown()
