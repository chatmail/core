"""Pytest plugin module."""

from __future__ import annotations

import os
import random
from typing import AsyncGenerator, Optional

import py
import pytest

from . import Account, AttrDict, Bot, Chat, Client, DeltaChat, EventType, Message
from ._utils import futuremethod
from .rpc import Rpc


class ACFactory:
    """Test account factory."""

    def __init__(self, deltachat: DeltaChat) -> None:
        self.deltachat = deltachat

    def get_unconfigured_account(self) -> Account:
        """Create a new unconfigured account."""
        account = self.deltachat.add_account()
        account.set_config("verified_one_on_one_chats", "1")
        return account

    def get_unconfigured_bot(self) -> Bot:
        """Create a new unconfigured bot."""
        return Bot(self.get_unconfigured_account())

    def get_credentials(self) -> (str, str):
        """Generate new credentials for chatmail account."""
        domain = os.getenv("CHATMAIL_DOMAIN")
        username = "ci-" + "".join(random.choice("2345789acdefghjkmnpqrstuvwxyz") for i in range(6))
        return f"{username}@{domain}", f"{username}${username}"

    @futuremethod
    def new_configured_account(self):
        """Create a new configured account."""
        addr, password = self.get_credentials()
        account = self.get_unconfigured_account()
        params = {"addr": addr, "password": password}
        yield account.add_or_update_transport.future(params)

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
        ac_clone = self.get_unconfigured_account()
        for i in ["addr", "mail_pw"]:
            ac_clone.set_config(i, ac.get_config(i))
        ac.remove()
        ac_clone.configure()
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
def acfactory(rpc) -> AsyncGenerator:
    """Return account factory fixture."""
    return ACFactory(DeltaChat(rpc))


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
