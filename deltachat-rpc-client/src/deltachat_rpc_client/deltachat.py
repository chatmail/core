"""Account manager module."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._utils import AttrDict
from .account import Account

if TYPE_CHECKING:
    from .rpc import Rpc


class DeltaChat:
    """Delta Chat accounts manager.

    This is the root of the object oriented API.
    """

    def __init__(self, rpc: "Rpc") -> None:
        """Initialize account manager."""
        self.rpc = rpc

    def add_account(self) -> Account:
        """Create a new account database."""
        account_id = self.rpc.add_account()
        return Account(self, account_id)

    def get_all_accounts(self) -> list[Account]:
        """Return a list of all available accounts."""
        account_ids = self.rpc.get_all_account_ids()
        return [Account(self, account_id) for account_id in account_ids]

    def start_io(self) -> None:
        """Start the I/O of all accounts."""
        self.rpc.start_io_for_all_accounts()

    def stop_io(self) -> None:
        """Stop the I/O of all accounts."""
        self.rpc.stop_io_for_all_accounts()

    def maybe_network(self) -> None:
        """Indicate that the network conditions might have changed."""
        self.rpc.maybe_network()

    def get_system_info(self) -> AttrDict:
        """Get information about the Delta Chat core in this system."""
        return AttrDict(self.rpc.get_system_info())

    def set_translations(self, translations: dict[str, str]) -> None:
        """Set stock translation strings."""
        self.rpc.set_stock_strings(translations)
