"""Shows the IO restart spawned by `sync_transports()` cancelling the
`receive_imf()` that is still processing the sync message,
losing the `configured_addr` update and its `TransportsModified` event.
"""

from queue import Empty

from deltachat_rpc_client import AttrDict, EventType

EVENT_TIMEOUT = 10


def next_event(account, timeout=EVENT_TIMEOUT):
    try:
        return AttrDict(account._rpc.get_queue(account.id).get(timeout=timeout))
    except Empty:
        return None


def drain_events(account, quiet=1):
    while next_event(account, quiet) is not None:
        pass


def wait_for_transports_modified(account):
    """Return True on TRANSPORTS_MODIFIED, False once IO restarted without it.

    Stopping IO awaits the inbox loop, so a completed restart means
    the message is not being processed anymore and no event is coming.
    """
    while True:
        event = next_event(account)
        if event is None:
            return False
        if event.kind == EventType.TRANSPORTS_MODIFIED:
            return True
        # ": starting IO" also excludes the "restarting IO" that precedes it
        if event.kind == EventType.INFO and event.msg.endswith(": starting IO"):
            return False


def test_wild_cancel_loses_primary_transport(acfactory):
    ac1 = acfactory.get_online_account()
    ac1_clone = ac1.clone()
    ac1_clone.bring_online()

    ac1.add_transport_from_qr(acfactory.get_account_qr())
    [transport1, transport2] = ac1.list_transports()
    assert wait_for_transports_modified(ac1_clone)
    assert ac1_clone.get_config("configured_addr") == transport1["addr"]
    drain_events(ac1_clone)

    new_addr = transport2["addr"]
    ac1.set_config("configured_addr", new_addr)
    assert wait_for_transports_modified(ac1_clone)
    second = wait_for_transports_modified(ac1_clone)
    configured_addr = ac1_clone.get_config("configured_addr")
    assert second, f"no second TRANSPORTS_MODIFIED, configured_addr={configured_addr!r}, expected {new_addr!r}"
    assert configured_addr == new_addr
