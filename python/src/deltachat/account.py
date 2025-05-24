"""Account class implementation."""

import os
from array import array
from contextlib import contextmanager
from email.utils import parseaddr
from threading import Event
from typing import TYPE_CHECKING, Any, Dict, Generator, List, Optional, Union

from . import const, hookspec
from .capi import ffi, lib
from .chat import Chat
from .contact import Contact
from .cutil import (
    DCLot,
    as_dc_charpointer,
    from_dc_charpointer,
    from_optional_dc_charpointer,
    iter_array,
)
from .message import Message
from .tracker import ConfigureTracker, ImexTracker

if TYPE_CHECKING:
    from .events import FFIEventTracker


class MissingCredentials(ValueError):
    """Account is missing `addr` and `mail_pw` config values."""


def get_core_info():
    """get some system info."""
    from tempfile import NamedTemporaryFile

    with NamedTemporaryFile() as path:
        path.close()
        return get_dc_info_as_dict(
            ffi.gc(
                lib.dc_context_new(as_dc_charpointer(""), as_dc_charpointer(path.name), ffi.NULL),
                lib.dc_context_unref,
            ),
        )


def get_dc_info_as_dict(dc_context):
    lines = from_dc_charpointer(lib.dc_get_info(dc_context))
    info_dict = {}
    for line in lines.split("\n"):
        if not line.strip():
            continue
        key, value = line.split("=", 1)
        info_dict[key.lower()] = value
    return info_dict


class Account:
    """Each account is tied to a sqlite database file which is fully managed
    by the underlying deltachat core library.  All public Account methods are
    meant to be memory-safe and return memory-safe objects.
    """

    MissingCredentials = MissingCredentials

    _logid: str
    _evtracker: "FFIEventTracker"

    def __init__(self, db_path, os_name=None, logging=True, closed=False) -> None:
        from .events import EventThread

        """initialize account object.

        :param db_path: a path to the account database. The database
                        will be created if it doesn't exist.
        :param os_name: [Deprecated]
        :param logging: enable logging for this account
        :param closed: set to True to avoid automatically opening the account
                       after creation.
        """
        # initialize per-account plugin system
        self._pm = hookspec.PerAccount._make_plugin_manager()
        self._logging = logging

        self.add_account_plugin(self)

        self.db_path = db_path
        if hasattr(db_path, "encode"):
            db_path = db_path.encode("utf8")

        ptr = lib.dc_context_new_closed(db_path) if closed else lib.dc_context_new(ffi.NULL, db_path, ffi.NULL)
        if ptr == ffi.NULL:
            raise ValueError(f"Could not dc_context_new: {os_name} {db_path}")
        self._dc_context = ffi.gc(
            ptr,
            lib.dc_context_unref,
        )

        self._shutdown_event = Event()
        self._event_thread = EventThread(self)
        self._configkeys = self.get_config("sys.config_keys").split()
        hook = hookspec.Global._get_plugin_manager().hook
        hook.dc_account_init(account=self)

    def open(self, passphrase: Optional[str] = None) -> bool:
        """Open the account's database with the given passphrase.
        This can only be used on a closed account. If the account is new, this
        operation sets the database passphrase. For existing databases the passphrase
        should be the one used to encrypt the database the first time.

        :returns: True if the database is opened with this passphrase, False if the
                  passphrase is incorrect or an error occurred.
        """
        return bool(lib.dc_context_open(self._dc_context, as_dc_charpointer(passphrase)))

    def disable_logging(self) -> None:
        """disable logging."""
        self._logging = False

    def enable_logging(self) -> None:
        """re-enable logging."""
        self._logging = True

    def __repr__(self) -> str:
        return f"<Account path={self.db_path}>"

    # def __del__(self):
    #    self.shutdown()

    def log(self, msg):
        if self._logging:
            self._pm.hook.ac_log_line(message=msg)

    def _check_config_key(self, name: str) -> None:
        if name not in self._configkeys:
            raise KeyError(f"{name!r} not a valid config key, existing keys: {self._configkeys!r}")

    def get_info(self) -> Dict[str, str]:
        """return dictionary of built config parameters."""
        return get_dc_info_as_dict(self._dc_context)

    def dump_account_info(self, logfile):
        def log(*args, **kwargs):
            kwargs["file"] = logfile
            print(*args, **kwargs)

        log("=============== " + self.get_config("displayname") + " ===============")
        cursor = 0
        for name, val in self.get_info().items():
            entry = f"{name.upper()}={val}"
            if cursor + len(entry) > 80:
                log("")
                cursor = 0
            log(entry, end=" ")
            cursor += len(entry) + 1
        log("")

    def set_stock_translation(self, id: int, string: str) -> None:
        """set stock translation string.

        :param id: id of stock string (const.DC_STR_*)
        :param value: string to set as new translation
        :returns: None
        """
        bytestring = string.encode("utf8")
        res = lib.dc_set_stock_translation(self._dc_context, id, bytestring)
        if res == 0:
            raise ValueError("could not set translation string")

    def set_config(self, name: str, value: Optional[str]) -> None:
        """set configuration values.

        :param name: config key name (unicode)
        :param value: value to set (unicode)
        :returns: None
        """
        self._check_config_key(name)
        namebytes = name.encode("utf8")
        if isinstance(value, (int, bool)):
            value = str(int(value))
        valuebytes = value.encode("utf8") if value is not None else ffi.NULL
        lib.dc_set_config(self._dc_context, namebytes, valuebytes)

    def get_config(self, name: str) -> str:
        """return unicode string value.

        :param name: configuration key to lookup (eg "addr" or "mail_pw")
        :returns: unicode value
        :raises: KeyError if no config value was found.
        """
        if name != "sys.config_keys":
            self._check_config_key(name)
        namebytes = name.encode("utf8")
        res = lib.dc_get_config(self._dc_context, namebytes)
        assert res != ffi.NULL, f"config value not found for: {name!r}"
        return from_dc_charpointer(res)

    def _preconfigure_keypair(self, secret: str) -> None:
        """See dc_preconfigure_keypair() in deltachat.h.

        In other words, you don't need this.
        """
        res = lib.dc_preconfigure_keypair(
            self._dc_context,
            as_dc_charpointer(secret),
        )
        if res == 0:
            raise Exception("Failed to set key")

    def update_config(self, kwargs: Dict[str, Any]) -> None:
        """update config values.

        :param kwargs: name=value config settings for this account.
                       values need to be unicode.
        :returns: None
        """
        for key, value in kwargs.items():
            self.set_config(key, value)

    def is_configured(self) -> bool:
        """determine if the account is configured already; an initial connection
        to SMTP/IMAP has been verified.

        :returns: True if account is configured.
        """
        return bool(lib.dc_is_configured(self._dc_context))

    def is_open(self) -> bool:
        """Determine if account is open.

        :returns True if account is open.
        """
        return bool(lib.dc_context_is_open(self._dc_context))

    def set_avatar(self, img_path: Optional[str]) -> None:
        """Set self avatar.

        :raises ValueError: if profile image could not be set
        :returns: None
        """
        if img_path is None:
            self.set_config("selfavatar", None)
        else:
            assert os.path.exists(img_path), img_path
            self.set_config("selfavatar", img_path)

    def check_is_configured(self) -> None:
        """Raise ValueError if this account is not configured."""
        if not self.is_configured():
            raise ValueError("need to configure first")

    def get_latest_backupfile(self, backupdir) -> Optional[str]:
        """return the latest backup file in a given directory."""
        res = lib.dc_imex_has_backup(self._dc_context, as_dc_charpointer(backupdir))
        return from_optional_dc_charpointer(res)

    def get_blobdir(self) -> str:
        """return the directory for files.

        All sent files are copied to this directory if necessary.
        Place files there directly to avoid copying.
        """
        return from_dc_charpointer(lib.dc_get_blobdir(self._dc_context))

    def get_self_contact(self) -> Contact:
        """return this account's identity as a :class:`deltachat.contact.Contact`.

        :returns: :class:`deltachat.contact.Contact`
        """
        return Contact(self, const.DC_CONTACT_ID_SELF)

    def create_contact(self, obj, name: Optional[str] = None) -> Contact:
        """create a (new) Contact or return an existing one.

        Calling this method will always result in the same
        underlying contact id.  If there already is a Contact
        with that e-mail address, it is unblocked and its display
        `name` is updated if specified.

        :param obj: email-address, Account or Contact instance.
        :param name: (optional) display name for this contact
        :returns: :class:`deltachat.contact.Contact` instance.
        """
        if isinstance(obj, Account):
            if not obj.is_configured():
                raise ValueError("Can only add configured accounts as contacts")
            assert name is None
            vcard = obj.get_self_contact().make_vcard()
            return self.import_vcard(vcard)[0]
        (name, addr) = self.get_contact_addr_and_name(obj, name)
        name_c = as_dc_charpointer(name)
        addr_c = as_dc_charpointer(addr)
        contact_id = lib.dc_create_contact(self._dc_context, name_c, addr_c)
        return Contact(self, contact_id)

    def get_contact(self, obj) -> Optional[Contact]:
        if isinstance(obj, Account):
            return self.create_contact(obj)
        if isinstance(obj, Contact):
            return obj
        (_, addr) = self.get_contact_addr_and_name(obj)
        return self.get_contact_by_addr(addr)

    def get_contact_addr_and_name(self, obj, name: Optional[str] = None):
        if isinstance(obj, Account):
            if not obj.is_configured():
                raise ValueError("can only add addresses from configured accounts")
            addr, displayname = obj.get_config("addr"), obj.get_config("displayname")
        elif isinstance(obj, Contact):
            if obj.account != self:
                raise ValueError(f"account mismatch {obj}")
            addr, displayname = obj.addr, obj.name
        elif isinstance(obj, str):
            displayname, addr = parseaddr(obj)
        else:
            raise TypeError(f"don't know how to create chat for {obj!r}")

        if name is None and displayname:
            name = displayname
        return (name, addr)

    def delete_contact(self, contact: Contact) -> bool:
        """delete a Contact.

        :param contact: contact object obtained
        :returns: True if deletion succeeded (contact was deleted)
        """
        contact_id = contact.id
        assert contact.account == self
        assert contact_id > const.DC_CHAT_ID_LAST_SPECIAL
        return bool(lib.dc_delete_contact(self._dc_context, contact_id))

    def get_contact_by_addr(self, email: str) -> Optional[Contact]:
        """get a contact for the email address or None if it's blocked or doesn't exist."""
        _, addr = parseaddr(email)
        addr = as_dc_charpointer(addr)
        contact_id = lib.dc_lookup_contact_id_by_addr(self._dc_context, addr)
        if contact_id:
            return self.get_contact_by_id(contact_id)
        return None

    def get_contact_by_id(self, contact_id: int) -> Contact:
        """return Contact instance or raise an exception.
        :param contact_id: integer id of this contact.
        :returns: :class:`deltachat.contact.Contact` instance.
        """
        return Contact(self, contact_id)

    def get_blocked_contacts(self) -> List[Contact]:
        """return a list of all blocked contacts.

        :returns: list of :class:`deltachat.contact.Contact` objects.
        """
        dc_array = ffi.gc(lib.dc_get_blocked_contacts(self._dc_context), lib.dc_array_unref)
        return list(iter_array(dc_array, lambda x: Contact(self, x)))

    def get_contacts(
        self,
        query: Optional[str] = None,
        with_self: bool = False,
    ) -> List[Contact]:
        """get a (filtered) list of contacts.

        :param query: if a string is specified, only return contacts
                      whose name or e-mail matches query.
        :param with_self: if true the self-contact is also returned.
        :returns: list of :class:`deltachat.contact.Contact` objects.
        """
        flags = 0
        query_c = as_dc_charpointer(query)
        if with_self:
            flags |= const.DC_GCL_ADD_SELF
        dc_array = ffi.gc(lib.dc_get_contacts(self._dc_context, flags, query_c), lib.dc_array_unref)
        return list(iter_array(dc_array, lambda x: Contact(self, x)))

    def import_vcard(self, vcard):
        """Import a vCard and return an array of contacts."""
        dc_array = ffi.gc(lib.dc_import_vcard(self._dc_context, as_dc_charpointer(vcard)), lib.dc_array_unref)
        return list(iter_array(dc_array, lambda x: Contact(self, x)))

    def get_fresh_messages(self) -> Generator[Message, None, None]:
        """yield all fresh messages from all chats."""
        dc_array = ffi.gc(lib.dc_get_fresh_msgs(self._dc_context), lib.dc_array_unref)
        return (x for x in iter_array(dc_array, lambda x: Message.from_db(self, x)) if x is not None)

    def create_chat(self, obj) -> Chat:
        """Create a 1:1 chat with Account, Contact or e-mail address."""
        return self.create_contact(obj).create_chat()

    def create_group_chat(
        self,
        name: str,
        contacts: Optional[List[Contact]] = None,
        verified: bool = False,
    ) -> Chat:
        """create a new group chat object.

        Chats are unpromoted until the first message is sent.

        :param contacts: list of contacts to add
        :param verified: if true only verified contacts can be added.
        :returns: a :class:`deltachat.chat.Chat` object.
        """
        bytes_name = name.encode("utf8")
        chat_id = lib.dc_create_group_chat(self._dc_context, int(verified), bytes_name)
        chat = Chat(self, chat_id)
        if contacts is not None:
            for contact in contacts:
                chat.add_contact(contact)
        return chat

    def get_chats(self) -> List[Chat]:
        """return list of chats.

        :returns: a list of :class:`deltachat.chat.Chat` objects.
        """
        dc_chatlist = ffi.gc(lib.dc_get_chatlist(self._dc_context, 0, ffi.NULL, 0), lib.dc_chatlist_unref)

        assert dc_chatlist != ffi.NULL
        chatlist = []
        for i in range(lib.dc_chatlist_get_cnt(dc_chatlist)):
            chat_id = lib.dc_chatlist_get_chat_id(dc_chatlist, i)
            chatlist.append(Chat(self, chat_id))
        return chatlist

    def get_device_chat(self) -> Chat:
        return Contact(self, const.DC_CONTACT_ID_DEVICE).create_chat()

    def get_message_by_id(self, msg_id: int) -> Optional[Message]:
        """return Message instance.
        :param msg_id: integer id of this message.
        :returns: :class:`deltachat.message.Message` instance.
        """
        return Message.from_db(self, msg_id)

    def get_chat_by_id(self, chat_id: int) -> Chat:
        """return Chat instance.
        :param chat_id: integer id of this chat.
        :returns: :class:`deltachat.chat.Chat` instance.
        :raises: ValueError if chat does not exist.
        """
        res = lib.dc_get_chat(self._dc_context, chat_id)
        if res == ffi.NULL:
            raise ValueError(f"cannot get chat with id={chat_id}")
        lib.dc_chat_unref(res)
        return Chat(self, chat_id)

    def mark_seen_messages(self, messages: List[Union[int, Message]]) -> None:
        """mark the given set of messages as seen.

        :param messages: a list of message ids or Message instances.
        """
        arr = array("i")
        for msg in messages:
            if isinstance(msg, Message):
                arr.append(msg.id)
            else:
                arr.append(msg)
        msg_ids = ffi.cast("uint32_t*", ffi.from_buffer(arr))
        lib.dc_markseen_msgs(self._dc_context, msg_ids, len(messages))

    def forward_messages(self, messages: List[Message], chat: Chat) -> None:
        """Forward list of messages to a chat.

        :param messages: list of :class:`deltachat.message.Message` object.
        :param chat: :class:`deltachat.chat.Chat` object.
        :returns: None
        """
        msg_ids = [msg.id for msg in messages]
        lib.dc_forward_msgs(self._dc_context, msg_ids, len(msg_ids), chat.id)

    def resend_messages(self, messages: List[Message]) -> None:
        """Resend list of messages.

        :param messages: list of :class:`deltachat.message.Message` object.
        :returns: None
        """
        msg_ids = [msg.id for msg in messages]
        if lib.dc_resend_msgs(self._dc_context, msg_ids, len(msg_ids)) != 1:
            raise ValueError(f"could not resend messages {msg_ids}")

    def delete_messages(self, messages: List[Message]) -> None:
        """delete messages (local and remote).

        :param messages: list of :class:`deltachat.message.Message` object.
        :returns: None
        """
        msg_ids = [msg.id for msg in messages]
        lib.dc_delete_msgs(self._dc_context, msg_ids, len(msg_ids))

    def export_self_keys(self, path):
        """export public and private keys to the specified directory.

        Note that the account does not have to be started.
        """
        return self._export(path, imex_cmd=const.DC_IMEX_EXPORT_SELF_KEYS)

    def export_all(self, path: str, passphrase: Optional[str] = None) -> str:
        """Export a backup of all database state (chats, contacts, keys, media, ...).

        :param path: the directory where the backup will be stored.
        :param passphrase: the backup will be encrypted with the passphrase, if it is
                           None or empty string, the backup is not encrypted.
        :returns: path to the created backup.

        Note that the account has to be stopped; call stop_io() if necessary.
        """
        export_files = self._export(path, const.DC_IMEX_EXPORT_BACKUP, passphrase)
        if len(export_files) != 1:
            raise RuntimeError("found more than one new file")
        return export_files[0]

    def _export(self, path: str, imex_cmd: int, passphrase: Optional[str] = None) -> list:
        with self.temp_plugin(ImexTracker()) as imex_tracker:
            self.imex(path, imex_cmd, passphrase)
            return imex_tracker.wait_finish()

    def import_self_keys(self, path):
        """Import private keys found in the `path` directory.
        The last imported key is made the default keys unless its name
        contains the string legacy. Public keys are not imported.

        Note that the account does not have to be started.
        """
        self._import(path, imex_cmd=const.DC_IMEX_IMPORT_SELF_KEYS)

    def import_all(self, path: str, passphrase: Optional[str] = None) -> None:
        """Import Delta Chat state from the specified backup file.
        The account must be in unconfigured state for import to attempted.

        :param path: path to the backup file.
        :param passphrase: if not None or empty, the backup will be opened with the passphrase.
        """
        assert not self.is_configured(), "cannot import into configured account"
        self._import(path, imex_cmd=const.DC_IMEX_IMPORT_BACKUP, passphrase=passphrase)

    def _import(self, path: str, imex_cmd: int, passphrase: Optional[str] = None) -> None:
        with self.temp_plugin(ImexTracker()) as imex_tracker:
            self.imex(path, imex_cmd, passphrase)
            imex_tracker.wait_finish()

    def imex(self, path: str, imex_cmd: int, passphrase: Optional[str] = None) -> None:
        lib.dc_imex(self._dc_context, imex_cmd, as_dc_charpointer(path), as_dc_charpointer(passphrase))

    def initiate_key_transfer(self) -> str:
        """return setup code after a Autocrypt setup message
        has been successfully sent to our own e-mail address ("self-sent message").
        If sending out was unsuccessful, a RuntimeError is raised.
        """
        self.check_is_configured()
        res = lib.dc_initiate_key_transfer(self._dc_context)
        if res == ffi.NULL:
            raise RuntimeError("could not send out autocrypt setup message")
        return from_dc_charpointer(res)

    def get_setup_contact_qr(self) -> str:
        """get/create Setup-Contact QR Code as ascii-string.

        this string needs to be transferred to another DC account
        in a second channel (typically used by mobiles with QRcode-show + scan UX)
        where qr_setup_contact(qr) is called.
        """
        res = lib.dc_get_securejoin_qr(self._dc_context, 0)
        return from_dc_charpointer(res)

    def check_qr(self, qr):
        """check qr code and return :class:`ScannedQRCode` instance representing the result."""
        res = ffi.gc(lib.dc_check_qr(self._dc_context, as_dc_charpointer(qr)), lib.dc_lot_unref)
        lot = DCLot(res)
        if lot.state() == const.DC_QR_ERROR:
            raise ValueError(f"invalid or unknown QR code: {lot.text1()}")
        return ScannedQRCode(lot)

    def qr_setup_contact(self, qr):
        """setup contact and return a `Chat` instance after contact is established.

        This function triggers a network protocol in the background between
        the emitter of the QR code and this account.

        :param qr: valid "setup contact" QR code (all other QR codes will result in an exception)
        """
        assert self.check_qr(qr).is_ask_verifycontact()
        chat_id = lib.dc_join_securejoin(self._dc_context, as_dc_charpointer(qr))
        if chat_id == 0:
            raise ValueError("could not setup secure contact")
        return Chat(self, chat_id)

    def qr_join_chat(self, qr):
        """return a `Chat` instance for which the securejoin network
        protocol has been started.

        This function triggers a network protocol in the background between
        the emitter of the QR code and this account.

        :param qr: valid "join-group" QR code (all other QR codes will result in an exception)
        """
        assert self.check_qr(qr).is_ask_verifygroup()
        chat_id = lib.dc_join_securejoin(self._dc_context, as_dc_charpointer(qr))
        if chat_id == 0:
            raise ValueError("could not join group")
        return Chat(self, chat_id)

    def set_location(self, latitude: float = 0.0, longitude: float = 0.0, accuracy: float = 0.0) -> None:
        """set a new location. It effects all chats where we currently
        have enabled location streaming.

        :param latitude: float (use 0.0 if not known)
        :param longitude: float (use 0.0 if not known)
        :param accuracy: float (use 0.0 if not known)
        :raises: ValueError if no chat is currently streaming locations
        :returns: None
        """
        dc_res = lib.dc_set_location(self._dc_context, latitude, longitude, accuracy)
        if dc_res == 0:
            raise ValueError("no chat is streaming locations")

    #
    # meta API for start/stop and event based processing
    #

    def run_account(self, addr=None, password=None, account_plugins=None, show_ffi=False, displayname=None):
        """get the account running, configure it if necessary. add plugins if provided.

        :param addr: the email address of the account
        :param password: the password of the account
        :param account_plugins: a list of plugins to add
        :param show_ffi: show low level ffi events
        :param displayname: the display name of the account
        """
        from .events import FFIEventLogger

        if show_ffi:
            log = FFIEventLogger(self)
            self.add_account_plugin(log)

        for plugin in account_plugins or []:
            print("adding plugin", plugin)
            self.add_account_plugin(plugin)

        if not self.is_configured():
            assert addr and password, "you must specify email and password once to configure this database/account"
            self.set_config("addr", addr)
            self.set_config("mail_pw", password)
            self.set_config("bot", "1")
            configtracker = self.configure()
            configtracker.wait_finish()

        if displayname:
            self.set_config("displayname", displayname)
        # start IO threads and configure if necessary
        self.start_io()

    def add_account_plugin(self, plugin, name=None):
        """add an account plugin which implements one or more of
        the :class:`deltachat.hookspec.PerAccount` hooks.
        """
        if name and self._pm.has_plugin(name=name):
            self._pm.unregister(name=name)
        self._pm.register(plugin, name=name)
        self._pm.check_pending()
        return plugin

    def remove_account_plugin(self, plugin, name=None):
        """remove an account plugin."""
        self._pm.unregister(plugin, name=name)

    @contextmanager
    def temp_plugin(self, plugin):
        """run a with-block with the given plugin temporarily registered."""
        self._pm.register(plugin)
        yield plugin
        self._pm.unregister(plugin)

    def stop_ongoing(self):
        """Stop ongoing securejoin, configuration or other core jobs."""
        lib.dc_stop_ongoing_process(self._dc_context)

    def get_connectivity(self):
        return lib.dc_get_connectivity(self._dc_context)

    def get_connectivity_html(self) -> str:
        return from_dc_charpointer(lib.dc_get_connectivity_html(self._dc_context))

    def start_io(self):
        """start this account's IO scheduling (Rust-core async scheduler).

        If this account is not configured an Exception is raised.
        You need to call account.configure() and account.wait_configure_finish()
        before.

        You may call `stop_scheduler`, `wait_shutdown` or `shutdown` after the
        account is started.

        If you are using this from a test, you may want to call
        wait_all_initial_fetches() afterwards.

        :raises MissingCredentials: if `addr` and `mail_pw` values are not set.
        :raises ConfigureFailed: if the account could not be configured.

        :returns: None
        """
        if not self.is_configured():
            raise ValueError("account not configured, cannot start io")
        lib.dc_start_io(self._dc_context)

    def maybe_network(self):
        """This function should be called when there is a hint
        that the network is available again,
        e.g. as a response to system event reporting network availability.
        The library will try to send pending messages out immediately.

        Moreover, to have a reliable state
        when the app comes to foreground with network available,
        it may be reasonable to call the function also at that moment.

        It is okay to call the function unconditionally when there is
        network available, however, calling the function
        _without_ having network may interfere with the backoff algorithm
        and will led to let the jobs fail faster, with fewer retries
        and may avoid messages being sent out.

        Finally, if the context was created by the dc_accounts_t account manager
        (currently not implemented in the Python bindings),
        use dc_accounts_maybe_network() instead of this function
        """
        lib.dc_maybe_network(self._dc_context)

    def configure(self) -> ConfigureTracker:
        """Start configuration process and return a Configtracker instance
        on which you can block with wait_finish() to get a True/False success
        value for the configuration process.
        """
        if not self.get_config("addr") or not self.get_config("mail_pw"):
            raise MissingCredentials("addr or mail_pwd not set in config")
        configtracker = ConfigureTracker(self)
        self.add_account_plugin(configtracker)
        lib.dc_configure(self._dc_context)
        return configtracker

    def wait_shutdown(self) -> None:
        """wait until shutdown of this account has completed."""
        self._shutdown_event.wait()

    def stop_io(self) -> None:
        """stop core IO scheduler if it is running."""
        self.log("stop_ongoing")
        self.stop_ongoing()

        self.log("dc_stop_io (stop core IO scheduler)")
        lib.dc_stop_io(self._dc_context)

    def shutdown(self) -> None:
        """shutdown and destroy account (stop callback thread, close and remove
        underlying dc_context).
        """
        if self._dc_context is None:
            return

        # mark the event thread for shutdown (latest on next incoming event)
        self._event_thread.mark_shutdown()

        # stop_io also causes an info event which will wake up
        # the EventThread's inner loop and let it notice the shutdown marker.
        self.stop_io()

        self.log("wait for event thread to finish")
        try:
            self._event_thread.wait(timeout=5)
        except RuntimeError as e:
            self.log(f"Waiting for event thread failed: {e}")

        if self._event_thread.is_alive():
            self.log("WARN: event thread did not terminate yet, ignoring.")

        self.log("remove dc_context references, making the Account unusable")
        self._dc_context = None

        self._shutdown_event.set()

        hook = hookspec.Global._get_plugin_manager().hook
        hook.dc_account_after_shutdown(account=self)
        self.log("shutdown finished")


class ScannedQRCode:
    def __init__(self, dc_lot) -> None:
        self._dc_lot = dc_lot

    def is_ask_verifycontact(self):
        return self._dc_lot.state() == const.DC_QR_ASK_VERIFYCONTACT

    def is_ask_verifygroup(self):
        return self._dc_lot.state() == const.DC_QR_ASK_VERIFYGROUP

    @property
    def contact_id(self):
        return self._dc_lot.id()
