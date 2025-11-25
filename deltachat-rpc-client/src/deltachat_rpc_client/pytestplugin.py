"""Pytest plugin module."""

from __future__ import annotations

import os
import pathlib
import platform
import random
import subprocess
import sys
from typing import AsyncGenerator, Optional

import execnet
import py
import pytest

from . import Account, AttrDict, Bot, Chat, Client, DeltaChat, EventType, Message
from ._utils import futuremethod
from .rpc import Rpc

E2EE_INFO_MSGS = 1
"""
The number of info messages added to new e2ee chats.
Currently this is "End-to-end encryption available".
"""


def pytest_report_header():
    for base in os.get_exec_path():
        fn = pathlib.Path(base).joinpath(base, "deltachat-rpc-server")
        if fn.exists():
            proc = subprocess.Popen([str(fn), "--version"], stderr=subprocess.PIPE)
            proc.wait()
            version = proc.stderr.read().decode().strip()
            return f"deltachat-rpc-server: {fn} [{version}]"

    return None


class ACFactory:
    """Test account factory."""

    def __init__(self, deltachat: DeltaChat) -> None:
        self.deltachat = deltachat

    def get_unconfigured_account(self) -> Account:
        """Create a new unconfigured account."""
        return self.deltachat.add_account()

    def get_unconfigured_bot(self) -> Bot:
        """Create a new unconfigured bot."""
        return Bot(self.get_unconfigured_account())

    def get_credentials(self) -> (str, str):
        """Generate new credentials for chatmail account."""
        domain = os.getenv("CHATMAIL_DOMAIN")
        username = "ci-" + "".join(random.choice("2345789acdefghjkmnpqrstuvwxyz") for i in range(6))
        return f"{username}@{domain}", f"{username}${username}"

    def get_account_qr(self):
        """Return "dcaccount:" QR code for testing chatmail relay."""
        domain = os.getenv("CHATMAIL_DOMAIN")
        return f"dcaccount:{domain}"

    @futuremethod
    def new_configured_account(self):
        """Create a new configured account."""
        account = self.get_unconfigured_account()
        qr = self.get_account_qr()
        yield account.add_transport_from_qr.future(qr)

        assert account.is_configured()
        return account

    def new_configured_bot(self) -> Bot:
        """Create a new configured bot."""
        addr, password = self.get_credentials()
        bot = self.get_unconfigured_bot()
        bot.configure(addr, password)
        return bot

    @futuremethod
    def get_online_account(self):
        """Create a new account and start I/O."""
        account = yield self.new_configured_account.future()
        account.bring_online()
        return account

    def get_online_accounts(self, num: int) -> list[Account]:
        """Create multiple online accounts."""
        futures = [self.get_online_account.future() for _ in range(num)]
        return [f() for f in futures]

    def resetup_account(self, ac: Account) -> Account:
        """Resetup account from scratch, losing the encryption key."""
        ac.stop_io()
        transports = ac.list_transports()
        ac.remove()
        ac_clone = self.get_unconfigured_account()
        for transport in transports:
            ac_clone.add_or_update_transport(transport)
        ac_clone.bring_online()
        return ac_clone

    def get_accepted_chat(self, ac1: Account, ac2: Account) -> Chat:
        """Create a new 1:1 chat between ac1 and ac2 accepted on both sides.

        Returned chat is a chat with ac2 from ac1 point of view.
        """
        ac2.create_chat(ac1)
        return ac1.create_chat(ac2)

    def send_message(
        self,
        to_account: Account,
        from_account: Optional[Account] = None,
        text: Optional[str] = None,
        file: Optional[str] = None,
        group: Optional[str] = None,
    ) -> Message:
        """Send a message."""
        if not from_account:
            from_account = (self.get_online_accounts(1))[0]
        to_contact = from_account.create_contact(to_account)
        if group:
            to_chat = from_account.create_group(group)
            to_chat.add_contact(to_contact)
        else:
            to_chat = to_contact.create_chat()
        return to_chat.send_message(text=text, file=file)

    def process_message(
        self,
        to_client: Client,
        from_account: Optional[Account] = None,
        text: Optional[str] = None,
        file: Optional[str] = None,
        group: Optional[str] = None,
    ) -> AttrDict:
        """Send a message and wait until recipient processes it."""
        self.send_message(
            to_account=to_client.account,
            from_account=from_account,
            text=text,
            file=file,
            group=group,
        )

        return to_client.run_until(lambda e: e.kind == EventType.INCOMING_MSG)


@pytest.fixture
def rpc(tmp_path) -> AsyncGenerator:
    """RPC client fixture."""
    rpc_server = Rpc(accounts_dir=str(tmp_path / "accounts"))
    with rpc_server:
        yield rpc_server


@pytest.fixture
def dc(rpc) -> DeltaChat:
    """Return account manager."""
    return DeltaChat(rpc)


@pytest.fixture
def acfactory(dc) -> AsyncGenerator:
    """Return account factory fixture."""
    return ACFactory(dc)


@pytest.fixture
def data():
    """Test data."""

    class Data:
        def __init__(self) -> None:
            for path in reversed(py.path.local(__file__).parts()):
                datadir = path.join("test-data")
                if datadir.isdir():
                    self.path = datadir
                    return
            raise Exception("Data path cannot be found")

        def get_path(self, bn):
            """Return path of file or None if it doesn't exist."""
            fn = os.path.join(self.path, *bn.split("/"))
            assert os.path.exists(fn)
            return fn

        def read_path(self, bn, mode="r"):
            fn = self.get_path(bn)
            if fn is not None:
                with open(fn, mode) as f:
                    return f.read()
            return None

    return Data()


@pytest.fixture
def log():
    """Log printer fixture."""

    class Printer:
        def section(self, msg: str) -> None:
            print()
            print("=" * 10, msg, "=" * 10)

        def step(self, msg: str) -> None:
            print("-" * 5, "step " + msg, "-" * 5)

        def indent(self, msg: str) -> None:
            print("  " + msg)

    return Printer()


#
# support for testing against different deltachat-rpc-server/clients
# installed into a temporary virtualenv and connected via 'execnet' channels
#


def find_path(venv, name):
    is_windows = platform.system() == "Windows"
    bin = venv / ("bin" if not is_windows else "Scripts")

    tryadd = [""]
    if is_windows:
        tryadd += os.environ["PATHEXT"].split(os.pathsep)
    for ext in tryadd:
        p = bin.joinpath(name + ext)
        if p.exists():
            return str(p)

    return None


@pytest.fixture(scope="session")
def get_core_python_env(tmp_path_factory):
    """Return a factory to create virtualenv environments with rpc server/client packages
    installed.

    The factory takes a version and returns a (python_path, rpc_server_path) tuple
    of the respective binaries in the virtualenv.
    """

    envs = {}

    def get_versioned_venv(core_version):
        venv = envs.get(core_version)
        if not venv:
            venv = tmp_path_factory.mktemp(f"temp-{core_version}")
            subprocess.check_call([sys.executable, "-m", "venv", venv])

            python = find_path(venv, "python")
            pkgs = [f"deltachat-rpc-server=={core_version}", f"deltachat-rpc-client=={core_version}", "pytest"]
            subprocess.check_call([python, "-m", "pip", "install"] + pkgs)

            envs[core_version] = venv
        python = find_path(venv, "python")
        rpc_server_path = find_path(venv, "deltachat-rpc-server")
        print(f"python={python}\nrpc_server={rpc_server_path}")
        return python, rpc_server_path

    return get_versioned_venv


@pytest.fixture
def alice_and_remote_bob(tmp_path, acfactory, get_core_python_env):
    """return local Alice account, a contact to bob, and a remote 'eval' function for bob.

    The 'eval' function allows to remote-execute arbitrary expressions
    that can use the `bob` online account, and the `bob_contact_alice`.
    """

    def factory(core_version):
        python, rpc_server_path = get_core_python_env(core_version)
        gw = execnet.makegateway(f"popen//python={python}")

        accounts_dir = str(tmp_path.joinpath("account1_venv1"))
        channel = gw.remote_exec(remote_bob_loop)
        cm = os.environ.get("CHATMAIL_DOMAIN")

        # trigger getting an online account on bob's side
        channel.send((accounts_dir, str(rpc_server_path), cm))

        # meanwhile get a local alice account
        alice = acfactory.get_online_account()
        channel.send(alice.self_contact.make_vcard())

        # wait for bob to have started
        sysinfo = channel.receive()
        assert sysinfo == f"v{core_version}"
        bob_vcard = channel.receive()
        [alice_contact_bob] = alice.import_vcard(bob_vcard)

        def eval(eval_str):
            channel.send(eval_str)
            return channel.receive()

        return alice, alice_contact_bob, eval

    return factory


def remote_bob_loop(channel):
    # This function executes with versioned
    # deltachat-rpc-client/server packages
    # installed into the virtualenv.
    #
    # The "channel" argument is a send/receive pipe
    # to the process that runs the corresponding remote_exec(remote_bob_loop)

    import os

    from deltachat_rpc_client import DeltaChat, Rpc
    from deltachat_rpc_client.pytestplugin import ACFactory

    accounts_dir, rpc_server_path, chatmail_domain = channel.receive()
    os.environ["CHATMAIL_DOMAIN"] = chatmail_domain

    # older core versions don't support specifying rpc_server_path
    # so we can't just pass `rpc_server_path` argument to Rpc constructor
    basepath = os.path.dirname(rpc_server_path)
    os.environ["PATH"] = os.pathsep.join([basepath, os.environ["PATH"]])
    rpc = Rpc(accounts_dir=accounts_dir)

    with rpc:
        dc = DeltaChat(rpc)
        channel.send(dc.rpc.get_system_info()["deltachat_core_version"])
        acfactory = ACFactory(dc)
        bob = acfactory.get_online_account()
        alice_vcard = channel.receive()
        [alice_contact] = bob.import_vcard(alice_vcard)
        ns = {"bob": bob, "bob_contact_alice": alice_contact}
        channel.send(bob.self_contact.make_vcard())

        while 1:
            eval_str = channel.receive()
            res = eval(eval_str, ns)
            try:
                channel.send(res)
            except Exception:
                # some unserializable result
                channel.send(None)
