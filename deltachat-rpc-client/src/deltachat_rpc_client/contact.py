"""Contact module."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ._utils import AttrDict

if TYPE_CHECKING:
    from .account import Account
    from .chat import Chat
    from .rpc import Rpc


@dataclass
class Contact:
    """Contact API.

    Essentially a wrapper for RPC, account ID and a contact ID.
    """

    account: "Account"
    id: int

    @property
    def _rpc(self) -> "Rpc":
        return self.account._rpc

    def block(self) -> None:
        """Block contact."""
        self._rpc.block_contact(self.account.id, self.id)

    def unblock(self) -> None:
        """Unblock contact."""
        self._rpc.unblock_contact(self.account.id, self.id)

    def delete(self) -> None:
        """Delete contact."""
        self._rpc.delete_contact(self.account.id, self.id)

    def reset_encryption(self) -> None:
        """Reset contact encryption."""
        self._rpc.reset_contact_encryption(self.account.id, self.id)

    def set_name(self, name: str) -> None:
        """Change the name of this contact."""
        self._rpc.change_contact_name(self.account.id, self.id, name)

    def get_encryption_info(self) -> str:
        """Get a multi-line encryption info.

        Encryption info contains your fingerprint and the fingerprint of the contact.
        """
        return self._rpc.get_contact_encryption_info(self.account.id, self.id)

    def get_snapshot(self) -> AttrDict:
        """Return a dictionary with a snapshot of all contact properties."""
        snapshot = AttrDict(self._rpc.get_contact(self.account.id, self.id))
        snapshot["contact"] = self
        return snapshot

    def create_chat(self) -> "Chat":
        """Create or get an existing 1:1 chat for this contact."""
        from .chat import Chat

        return Chat(
            self.account,
            self._rpc.create_chat_by_contact_id(self.account.id, self.id),
        )

    def make_vcard(self) -> str:
        """Make a vCard for the contact."""
        return self.account.make_vcard([self])
