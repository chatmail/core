"""Contact object."""

from datetime import date, datetime, timezone
from typing import Optional

from . import const, props
from .capi import ffi, lib
from .chat import Chat
from .cutil import from_dc_charpointer, from_optional_dc_charpointer


class Contact:
    """Delta-Chat Contact.

    You obtain instances of it through :class:`deltachat.account.Account`.
    """

    def __init__(self, account, id) -> None:
        from .account import Account

        assert isinstance(account, Account), repr(account)
        self.account = account
        self.id = id

    def __eq__(self, other) -> bool:
        if other is None:
            return False
        return self.account._dc_context == other.account._dc_context and self.id == other.id

    def __ne__(self, other) -> bool:
        return not self == other

    def __repr__(self) -> str:
        return f"<Contact id={self.id} addr={self.addr} dc_context={self.account._dc_context}>"

    @property
    def _dc_contact(self):
        return ffi.gc(lib.dc_get_contact(self.account._dc_context, self.id), lib.dc_contact_unref)

    @props.with_doc
    def addr(self) -> str:
        """normalized e-mail address for this account."""
        return from_dc_charpointer(lib.dc_contact_get_addr(self._dc_contact))

    @props.with_doc
    def name(self) -> str:
        """display name for this contact."""
        return from_dc_charpointer(lib.dc_contact_get_display_name(self._dc_contact))

    # deprecated alias
    display_name = name

    @props.with_doc
    def last_seen(self) -> date:
        """Last seen timestamp."""
        return datetime.fromtimestamp(lib.dc_contact_get_last_seen(self._dc_contact), timezone.utc)

    def is_blocked(self):
        """Return True if the contact is blocked."""
        return lib.dc_contact_is_blocked(self._dc_contact)

    def set_blocked(self, block=True):
        """[Deprecated, use block/unblock methods] Block or unblock a contact."""
        return lib.dc_block_contact(self.account._dc_context, self.id, block)

    def block(self):
        """Block this contact. Message will not be seen/retrieved from this contact."""
        return lib.dc_block_contact(self.account._dc_context, self.id, True)

    def unblock(self):
        """Unblock this contact. Messages from this contact will be retrieved (again)."""
        return lib.dc_block_contact(self.account._dc_context, self.id, False)

    def is_verified(self) -> bool:
        """Return True if the contact is verified."""
        return lib.dc_contact_is_verified(self._dc_contact) == 2

    def get_verifier(self, contact) -> Optional["Contact"]:
        """Return the address of the contact that verified the contact."""
        verifier_id = lib.dc_contact_get_verifier_id(contact._dc_contact)
        if verifier_id == 0:
            return None
        return Contact(self.account, verifier_id)

    def get_profile_image(self) -> Optional[str]:
        """Get contact profile image.

        :returns: path to profile image, None if no profile image exists.
        """
        dc_res = lib.dc_contact_get_profile_image(self._dc_contact)
        return from_optional_dc_charpointer(dc_res)

    def make_vcard(self) -> str:
        """Make a contact vCard.

        :returns: vCard
        """
        dc_context = self.account._dc_context
        return from_dc_charpointer(lib.dc_make_vcard(dc_context, self.id))

    @property
    def status(self):
        """Get contact status.

        :returns: contact status, empty string if it doesn't exist.
        """
        return from_dc_charpointer(lib.dc_contact_get_status(self._dc_contact))

    def create_chat(self):
        """create or get an existing 1:1 chat object for the specified contact or contact id.

        :param contact: chat_id (int) or contact object.
        :returns: a :class:`deltachat.chat.Chat` object.
        """
        dc_context = self.account._dc_context
        chat_id = lib.dc_create_chat_by_contact_id(dc_context, self.id)
        assert chat_id > const.DC_CHAT_ID_LAST_SPECIAL, chat_id
        return Chat(self.account, chat_id)

    # deprecated name
    get_chat = create_chat
