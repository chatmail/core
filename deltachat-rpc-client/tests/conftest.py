from __future__ import annotations

import imaplib
import io
import pathlib
import ssl
from contextlib import contextmanager
from typing import TYPE_CHECKING

import pytest
from imap_tools import AND, Header, MailBox, MailMessage, MailMessageFlags, errors

if TYPE_CHECKING:
    from deltachat_rpc_client import Account

FLAGS = b"FLAGS"
FETCH = b"FETCH"
ALL = "1:*"


class DirectImap:
    """Internal Python-level IMAP handling."""

    def __init__(self, account: Account) -> None:
        self.account = account
        self.logid = account.get_config("displayname") or id(account)
        self._idling = False
        self.connect()

    def connect(self):
        # Assume the testing server supports TLS on port 993.
        host = self.account.get_config("configured_mail_server")
        port = 993

        user = self.account.get_config("addr")
        host = user.rsplit("@")[-1]
        pw = self.account.get_config("mail_pw")

        self.conn = MailBox(host, port, ssl_context=ssl.create_default_context())
        self.conn.login(user, pw)

        self.select_folder("INBOX")

    def shutdown(self):
        try:
            self.conn.logout()
        except (OSError, imaplib.IMAP4.abort):
            print("Could not logout direct_imap conn")

    def create_folder(self, foldername):
        try:
            self.conn.folder.create(foldername)
        except errors.MailboxFolderCreateError as e:
            print("Can't create", foldername, "probably it already exists:", str(e))

    def select_folder(self, foldername: str) -> tuple:
        assert not self._idling
        return self.conn.folder.set(foldername)

    def select_config_folder(self, config_name: str):
        """Return info about selected folder if it is
        configured, otherwise None.
        """
        if "_" not in config_name:
            config_name = f"configured_{config_name}_folder"
        foldername = self.account.get_config(config_name)
        if foldername:
            return self.select_folder(foldername)
        return None

    def list_folders(self) -> list[str]:
        """return list of all existing folder names."""
        assert not self._idling
        return [folder.name for folder in self.conn.folder.list()]

    def delete(self, uid_list: str, expunge=True):
        """delete a range of messages (imap-syntax).
        If expunge is true, perform the expunge-operation
        to make sure the messages are really gone and not
        just flagged as deleted.
        """
        self.conn.client.uid("STORE", uid_list, "+FLAGS", r"(\Deleted)")
        if expunge:
            self.conn.expunge()

    def get_all_messages(self) -> list[MailMessage]:
        assert not self._idling
        return list(self.conn.fetch(mark_seen=False))

    def get_unread_messages(self) -> list[str]:
        assert not self._idling
        return [msg.uid for msg in self.conn.fetch(AND(seen=False), mark_seen=False)]

    def mark_all_read(self):
        messages = self.get_unread_messages()
        if messages:
            res = self.conn.flag(messages, MailMessageFlags.SEEN, True)
            print("marked seen:", messages, res)

    def get_unread_cnt(self) -> int:
        return len(self.get_unread_messages())

    def dump_imap_structures(self, dir, logfile):
        assert not self._idling
        stream = io.StringIO()

        def log(*args, **kwargs):
            kwargs["file"] = stream
            print(*args, **kwargs)

        empty_folders = []
        for imapfolder in self.list_folders():
            self.select_folder(imapfolder)
            messages = list(self.get_all_messages())
            if not messages:
                empty_folders.append(imapfolder)
                continue

            log("---------", imapfolder, len(messages), "messages ---------")
            # get message content without auto-marking it as seen
            # fetching 'RFC822' would mark it as seen.
            for msg in self.conn.fetch(mark_seen=False):
                body = getattr(msg.obj, "text", None)
                if not body:
                    body = getattr(msg.obj, "html", None)
                if not body:
                    log("Message", msg.uid, "has empty body")
                    continue

                path = pathlib.Path(str(dir)).joinpath("IMAP", self.logid, imapfolder)
                path.mkdir(parents=True, exist_ok=True)
                fn = path.joinpath(str(msg.uid))
                fn.write_bytes(body)
                log("Message", msg.uid, fn)
                log(
                    "Message",
                    msg.uid,
                    msg.flags,
                    "Message-Id:",
                    msg.obj.get("Message-Id"),
                )

        if empty_folders:
            log("--------- EMPTY FOLDERS:", empty_folders)

        print(stream.getvalue(), file=logfile)

    @contextmanager
    def idle(self):
        """return Idle ContextManager."""
        idle_manager = IdleManager(self)
        try:
            yield idle_manager
        finally:
            idle_manager.done()

    def append(self, folder: str, msg: str):
        """Upload a message to *folder*.
        Trailing whitespace or a linebreak at the beginning will be removed automatically.
        """
        if msg.startswith("\n"):
            msg = msg[1:]
        msg = "\n".join([s.lstrip() for s in msg.splitlines()])
        self.conn.append(bytes(msg, encoding="ascii"), folder)

    def get_uid_by_message_id(self, message_id) -> str:
        msgs = [msg.uid for msg in self.conn.fetch(AND(header=Header("MESSAGE-ID", message_id)))]
        if len(msgs) == 0:
            raise Exception("Did not find message " + message_id + ", maybe you forgot to select the correct folder?")
        return msgs[0]


class IdleManager:
    def __init__(self, direct_imap) -> None:
        self.direct_imap = direct_imap
        # fetch latest messages before starting idle so that it only
        # returns messages that arrive anew
        self.direct_imap.conn.fetch("1:*")
        self.direct_imap.conn.idle.start()

    def check(self, timeout=None) -> list[bytes]:
        """(blocking) wait for next idle message from server."""
        return self.direct_imap.conn.idle.poll(timeout=timeout)

    def wait_for_new_message(self) -> bytes:
        while True:
            for item in self.check():
                if b"EXISTS" in item or b"RECENT" in item:
                    return item

    def wait_for_seen(self, timeout=None) -> int:
        """Return first message with SEEN flag from a running idle-stream."""
        while True:
            for item in self.check(timeout=timeout):
                if FETCH in item and FLAGS in item and rb"\Seen" in item:
                    return int(item.split(b" ")[1])

    def done(self):
        """send idle-done to server if we are currently in idle mode."""
        return self.direct_imap.conn.idle.stop()


@pytest.fixture
def direct_imap():
    return DirectImap
