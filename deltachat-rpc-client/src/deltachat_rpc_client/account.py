"""Account module."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional, Union
from warnings import warn

from ._utils import AttrDict, futuremethod
from .chat import Chat
from .const import ChatlistFlag, ContactFlag, EventType, SpecialContactId
from .contact import Contact
from .message import Message

if TYPE_CHECKING:
    from .deltachat import DeltaChat
    from .rpc import Rpc


@dataclass
class Account:
    """Delta Chat account."""

    manager: "DeltaChat"
    id: int

    @property
    def _rpc(self) -> "Rpc":
        return self.manager.rpc

    def wait_for_event(self, event_type=None) -> AttrDict:
        """Wait until the next event and return it."""
        while True:
            next_event = AttrDict(self._rpc.wait_for_event(self.id))
            if event_type is None or next_event.kind == event_type:
                return next_event

    def clear_all_events(self):
        """Remove all queued-up events for a given account.

        Useful for tests.
        """
        self._rpc.clear_all_events(self.id)

    def remove(self) -> None:
        """Remove the account."""
        self._rpc.remove_account(self.id)

    def clone(self) -> "Account":
        """Clone given account.

        This uses backup-transfer via iroh, i.e. the 'Add second device' feature.
        """
        future = self._rpc.provide_backup.future(self.id)
        qr = self._rpc.get_backup_qr(self.id)
        new_account = self.manager.add_account()
        new_account._rpc.get_backup(new_account.id, qr)
        future()
        return new_account

    def start_io(self) -> None:
        """Start the account I/O."""
        self._rpc.start_io(self.id)

    def stop_io(self) -> None:
        """Stop the account I/O."""
        self._rpc.stop_io(self.id)

    def get_info(self) -> AttrDict:
        """Return dictionary of this account configuration parameters."""
        return AttrDict(self._rpc.get_info(self.id))

    def get_size(self) -> int:
        """Get the combined filesize of an account in bytes."""
        return self._rpc.get_account_file_size(self.id)

    def is_configured(self) -> bool:
        """Return True if this account is configured."""
        return self._rpc.is_configured(self.id)

    def set_config(self, key: str, value: Optional[str] = None) -> None:
        """Set configuration value."""
        self._rpc.set_config(self.id, key, value)

    def get_config(self, key: str) -> Optional[str]:
        """Get configuration value."""
        return self._rpc.get_config(self.id, key)

    def update_config(self, **kwargs) -> None:
        """Update config values."""
        for key, value in kwargs.items():
            self.set_config(key, value)

    def set_avatar(self, img_path: Optional[str] = None) -> None:
        """Set self avatar.

        Passing None will discard the currently set avatar.
        """
        self.set_config("selfavatar", img_path)

    def get_avatar(self) -> Optional[str]:
        """Get self avatar."""
        return self.get_config("selfavatar")

    def check_qr(self, qr):
        """Parse QR code contents.

        This function takes the raw text scanned
        and checks what can be done with it.
        """
        return self._rpc.check_qr(self.id, qr)

    def set_config_from_qr(self, qr: str):
        """Set configuration values from a QR code."""
        self._rpc.set_config_from_qr(self.id, qr)

    @futuremethod
    def configure(self):
        """Configure an account."""
        yield self._rpc.configure.future(self.id)

    @futuremethod
    def add_or_update_transport(self, params):
        """Add a new transport."""
        yield self._rpc.add_or_update_transport.future(self.id, params)

    @futuremethod
    def list_transports(self):
        """Return the list of all email accounts that are used as a transport in the current profile."""
        transports = yield self._rpc.list_transports.future(self.id)
        return transports

    def bring_online(self):
        """Start I/O and wait until IMAP becomes IDLE."""
        self.start_io()
        self.wait_for_event(EventType.IMAP_INBOX_IDLE)

    def create_contact(self, obj: Union[int, str, Contact, "Account"], name: Optional[str] = None) -> Contact:
        """Create a new Contact or return an existing one.

        Calling this method will always result in the same
        underlying contact id.  If there already is a Contact
        with that e-mail address, it is unblocked and its display
        name is updated if specified.

        :param obj: email-address, contact id or account.
        :param name: (optional) display name for this contact.
        """
        if isinstance(obj, Account):
            vcard = obj.self_contact.make_vcard()
            [contact] = self.import_vcard(vcard)
            if name:
                contact.set_name(name)
            return contact
        if isinstance(obj, int):
            obj = Contact(self, obj)
        if isinstance(obj, Contact):
            obj = obj.get_snapshot().address
        return Contact(self, self._rpc.create_contact(self.id, obj, name))

    def make_vcard(self, contacts: list[Contact]) -> str:
        """Create vCard with the given contacts."""
        assert all(contact.account == self for contact in contacts)
        contact_ids = [contact.id for contact in contacts]
        return self._rpc.make_vcard(self.id, contact_ids)

    def import_vcard(self, vcard: str) -> list[Contact]:
        """Import vCard.

        Return created or modified contacts in the order they appear in vCard.
        """
        contact_ids = self._rpc.import_vcard_contents(self.id, vcard)
        return [Contact(self, contact_id) for contact_id in contact_ids]

    def create_chat(self, account: "Account") -> Chat:
        """Create a 1:1 chat with another account."""
        return self.create_contact(account).create_chat()

    def get_device_chat(self) -> Chat:
        """Return device chat."""
        return self.device_contact.create_chat()

    def get_contact_by_id(self, contact_id: int) -> Contact:
        """Return Contact instance for the given contact ID."""
        return Contact(self, contact_id)

    def get_contact_by_addr(self, address: str) -> Optional[Contact]:
        """Check if an e-mail address belongs to a known and unblocked contact."""
        contact_id = self._rpc.lookup_contact_id_by_addr(self.id, address)
        return contact_id and Contact(self, contact_id)

    def get_blocked_contacts(self) -> list[AttrDict]:
        """Return a list with snapshots of all blocked contacts."""
        contacts = self._rpc.get_blocked_contacts(self.id)
        return [AttrDict(contact=Contact(self, contact["id"]), **contact) for contact in contacts]

    def get_chat_by_contact(self, contact: Union[int, Contact]) -> Optional[Chat]:
        """Return 1:1 chat for a contact if it exists."""
        if isinstance(contact, Contact):
            assert contact.account == self
            contact_id = contact.id
        elif isinstance(contact, int):
            contact_id = contact
        else:
            raise ValueError(f"{contact!r} is not a contact")
        chat_id = self._rpc.get_chat_id_by_contact_id(self.id, contact_id)
        if chat_id:
            return Chat(self, chat_id)
        return None

    def get_contacts(
        self,
        query: Optional[str] = None,
        *,
        with_self: bool = False,
        snapshot: bool = False,
    ) -> Union[list[Contact], list[AttrDict]]:
        """Get a filtered list of contacts.

        :param query: if a string is specified, only return contacts
                      whose name or e-mail matches query.
        :param with_self: if True the self-contact is also included if it matches the query.
        :param snapshot: If True return a list of contact snapshots instead of Contact instances.
        """
        flags = 0
        if with_self:
            flags |= ContactFlag.ADD_SELF

        if snapshot:
            contacts = self._rpc.get_contacts(self.id, flags, query)
            return [AttrDict(contact=Contact(self, contact["id"]), **contact) for contact in contacts]
        contacts = self._rpc.get_contact_ids(self.id, flags, query)
        return [Contact(self, contact_id) for contact_id in contacts]

    @property
    def self_contact(self) -> Contact:
        """Account's identity as a Contact."""
        return Contact(self, SpecialContactId.SELF)

    @property
    def device_contact(self) -> Chat:
        """Account's device contact."""
        return Contact(self, SpecialContactId.DEVICE)

    def get_chatlist(
        self,
        query: Optional[str] = None,
        contact: Optional[Contact] = None,
        archived_only: bool = False,
        for_forwarding: bool = False,
        no_specials: bool = False,
        alldone_hint: bool = False,
        snapshot: bool = False,
    ) -> Union[list[Chat], list[AttrDict]]:
        """Return list of chats.

        :param query: if a string is specified only chats matching this query are returned.
        :param contact: if a contact is specified only chats including this contact are returned.
        :param archived_only: if True only archived chats are returned.
        :param for_forwarding: if True the chat list is sorted with "Saved messages" at the top
                               and without "Device chat" and contact requests.
        :param no_specials: if True archive link is not added to the list.
        :param alldone_hint: if True the "all done hint" special chat will be added to the list
                             as needed.
        :param snapshot: If True return a list of chat snapshots instead of Chat instances.
        """
        flags = 0
        if archived_only:
            flags |= ChatlistFlag.ARCHIVED_ONLY
        if for_forwarding:
            flags |= ChatlistFlag.FOR_FORWARDING
        if no_specials:
            flags |= ChatlistFlag.NO_SPECIALS
        if alldone_hint:
            flags |= ChatlistFlag.ADD_ALLDONE_HINT

        entries = self._rpc.get_chatlist_entries(self.id, flags, query, contact and contact.id)
        if not snapshot:
            return [Chat(self, entry) for entry in entries]

        items = self._rpc.get_chatlist_items_by_entries(self.id, entries)
        chats = []
        for item in items.values():
            item["chat"] = Chat(self, item["id"])
            chats.append(AttrDict(item))
        return chats

    def create_group(self, name: str, protect: bool = False) -> Chat:
        """Create a new group chat.

        After creation, the group has only self-contact as member and is in unpromoted state.
        """
        return Chat(self, self._rpc.create_group_chat(self.id, name, protect))

    def get_chat_by_id(self, chat_id: int) -> Chat:
        """Return the Chat instance with the given ID."""
        return Chat(self, chat_id)

    def secure_join(self, qrdata: str) -> Chat:
        """Continue a Setup-Contact or Verified-Group-Invite protocol started on another device.

        The function returns immediately and the handshake runs in background, sending
        and receiving several messages.
        Subsequent calls of `secure_join()` will abort previous, unfinished handshakes.
        See https://securejoin.delta.chat/ for protocol details.

        :param qrdata: The text of the scanned QR code.
        """
        return Chat(self, self._rpc.secure_join(self.id, qrdata))

    def get_qr_code(self) -> str:
        """Get Setup-Contact QR Code text.

        This data needs to be transferred to another Delta Chat account
        in a second channel, typically used by mobiles with QRcode-show + scan UX.
        """
        return self._rpc.get_chat_securejoin_qr_code(self.id, None)

    def get_qr_code_svg(self) -> tuple[str, str]:
        """Get Setup-Contact QR code text and SVG."""
        return self._rpc.get_chat_securejoin_qr_code_svg(self.id, None)

    def get_message_by_id(self, msg_id: int) -> Message:
        """Return the Message instance with the given ID."""
        return Message(self, msg_id)

    def mark_seen_messages(self, messages: list[Message]) -> None:
        """Mark the given set of messages as seen."""
        self._rpc.markseen_msgs(self.id, [msg.id for msg in messages])

    def delete_messages(self, messages: list[Message]) -> None:
        """Delete messages (local and remote)."""
        self._rpc.delete_messages(self.id, [msg.id for msg in messages])

    def get_fresh_messages(self) -> list[Message]:
        """Return the list of fresh messages, newest messages first.

        This call is intended for displaying notifications.
        If you are writing a bot, use `get_fresh_messages_in_arrival_order()` instead,
        to process oldest messages first.
        """
        fresh_msg_ids = self._rpc.get_fresh_msgs(self.id)
        return [Message(self, msg_id) for msg_id in fresh_msg_ids]

    def get_next_messages(self) -> list[Message]:
        """Return a list of next messages."""
        next_msg_ids = self._rpc.get_next_msgs(self.id)
        return [Message(self, msg_id) for msg_id in next_msg_ids]

    def wait_next_messages(self) -> list[Message]:
        """Wait for new messages and return a list of them."""
        next_msg_ids = self._rpc.wait_next_msgs(self.id)
        return [Message(self, msg_id) for msg_id in next_msg_ids]

    def wait_for_incoming_msg_event(self):
        """Wait for incoming message event and return it."""
        return self.wait_for_event(EventType.INCOMING_MSG)

    def wait_for_msgs_changed_event(self):
        """Wait for messages changed event and return it."""
        return self.wait_for_event(EventType.MSGS_CHANGED)

    def wait_for_msgs_noticed_event(self):
        """Wait for messages noticed event and return it."""
        return self.wait_for_event(EventType.MSGS_NOTICED)

    def wait_for_incoming_msg(self):
        """Wait for incoming message and return it.

        Consumes all events before the next incoming message event.
        """
        return self.get_message_by_id(self.wait_for_incoming_msg_event().msg_id)

    def wait_for_securejoin_inviter_success(self):
        """Wait until SecureJoin process finishes successfully on the inviter side."""
        while True:
            event = self.wait_for_event()
            if event["kind"] == "SecurejoinInviterProgress" and event["progress"] == 1000:
                break

    def wait_for_securejoin_joiner_success(self):
        """Wait until SecureJoin process finishes successfully on the joiner side."""
        while True:
            event = self.wait_for_event()
            if event["kind"] == "SecurejoinJoinerProgress" and event["progress"] == 1000:
                break

    def wait_for_reactions_changed(self):
        """Wait for reaction change event."""
        return self.wait_for_event(EventType.REACTIONS_CHANGED)

    def get_fresh_messages_in_arrival_order(self) -> list[Message]:
        """Return fresh messages list sorted in the order of their arrival, with ascending IDs."""
        warn(
            "get_fresh_messages_in_arrival_order is deprecated, use get_next_messages instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        fresh_msg_ids = sorted(self._rpc.get_fresh_msgs(self.id))
        return [Message(self, msg_id) for msg_id in fresh_msg_ids]

    def export_backup(self, path, passphrase: str = "") -> None:
        """Export backup."""
        self._rpc.export_backup(self.id, str(path), passphrase)

    def import_backup(self, path, passphrase: str = "") -> None:
        """Import backup."""
        self._rpc.import_backup(self.id, str(path), passphrase)

    def export_self_keys(self, path) -> None:
        """Export keys."""
        passphrase = ""  # Setting passphrase is currently not supported.
        self._rpc.export_self_keys(self.id, str(path), passphrase)

    def import_self_keys(self, path) -> None:
        """Import keys."""
        passphrase = ""  # Importing passphrase-protected keys is currently not supported.
        self._rpc.import_self_keys(self.id, str(path), passphrase)

    def initiate_autocrypt_key_transfer(self) -> None:
        """Send Autocrypt Setup Message."""
        return self._rpc.initiate_autocrypt_key_transfer(self.id)
