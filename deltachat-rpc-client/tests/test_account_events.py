from __future__ import annotations

from typing import TYPE_CHECKING

from deltachat_rpc_client import EventType

if TYPE_CHECKING:
    from deltachat_rpc_client.pytestplugin import ACFactory


def test_event_on_configuration(acfactory: ACFactory) -> None:
    """
    Test if ACCOUNTS_ITEM_CHANGED event is emitted on configure
    """

    addr, password = acfactory.get_credentials()
    account = acfactory.get_unconfigured_account()
    account.clear_all_events()
    assert not account.is_configured()
    future = account.add_or_update_transport.future({"addr": addr, "password": password})
    while True:
        event = account.wait_for_event()
        if event.kind == EventType.ACCOUNTS_ITEM_CHANGED:
            break
    assert account.is_configured()

    future()


# other tests are written in rust: src/tests/account_events.rs
