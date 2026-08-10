#!/usr/bin/env python3
"""
Testing webxdc iroh connectivity

If you want to debug iroh at rust-trace/log level set

    RUST_LOG=iroh_net=trace,iroh_gossip=trace
"""

import itertools
import logging
import os
import threading
from contextlib import contextmanager

import pytest

from deltachat_rpc_client import EventType


@pytest.fixture
def path_to_webxdc(request):
    p = request.path.parent.parent.parent.joinpath("test-data/webxdc/chess.xdc")
    assert p.exists()
    return str(p)


@pytest.fixture
def path_to_large_webxdc(request):
    p = request.path.parent.parent.parent.joinpath("test-data/webxdc/realtime-check.xdc")
    assert p.exists()
    return str(p)


def log(msg):
    logging.info(msg)


# payload used to probe/establish realtime connectivity, filtered out by tests
SETUP_DATA = b"realtime-setup"


def setup_realtime_webxdc(ac1, ac2, path_to_webxdc, wait=True):
    assert ac1.get_config("webxdc_realtime_enabled") == "1"
    assert ac2.get_config("webxdc_realtime_enabled") == "1"
    ac1_ac2_chat = ac1.create_chat(ac2)
    ac2.create_chat(ac1)

    # share a webxdc app between ac1 and ac2
    ac1_webxdc_msg = ac1_ac2_chat.send_message(text="play", file=path_to_webxdc)
    ac2_webxdc_msg = ac2.wait_for_incoming_msg()
    assert ac2_webxdc_msg.get_snapshot().text == "play"

    # send iroh announcements simultaneously
    log("sending ac1 -> ac2 realtime advertisement and additional message")
    ac1_webxdc_msg.send_webxdc_realtime_advertisement()

    log("sending ac2 -> ac1 realtime advertisement and additional message")
    ac2_webxdc_msg.send_webxdc_realtime_advertisement()
    if wait:
        wait_realtime_connected([(ac1_webxdc_msg, ac2_webxdc_msg)])
    return ac1_webxdc_msg, ac2_webxdc_msg


@contextmanager
def send_realtime_data_forever(msgs, data=None):
    stop = threading.Event()
    data = data or [SETUP_DATA] * len(msgs)

    def thread_run(msg, payload):
        for i in itertools.count():
            msg.send_webxdc_realtime_data(payload(i) if callable(payload) else payload)
            if stop.wait(1):
                return

    for msg_payload in zip(msgs, data, strict=True):
        threading.Thread(target=thread_run, args=msg_payload, daemon=True).start()
    try:
        yield data
    finally:
        stop.set()


def wait_realtime_connected(msg_pairs):
    with send_realtime_data_forever([sender for sender, _ in msg_pairs]):
        for _, receiver in msg_pairs:
            receiver.account.wait_for_realtime_data(receiver.id)


def test_realtime_sequentially(acfactory, path_to_webxdc):
    """Test two peers trying to establish connection sequentially."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.create_chat(ac2)
    ac2.create_chat(ac1)

    # share a webxdc app between ac1 and ac2
    ac1_webxdc_msg = acfactory.send_message(from_account=ac1, to_account=ac2, text="play", file=path_to_webxdc)
    ac2_webxdc_msg = ac2.wait_for_incoming_msg()
    snapshot = ac2_webxdc_msg.get_snapshot()
    assert snapshot.text == "play"

    # send iroh announcements sequentially
    log("sending ac1 -> ac2 realtime advertisement and additional message")
    ac1_webxdc_msg.send_webxdc_realtime_advertisement()
    acfactory.send_message(from_account=ac1, to_account=ac2, text="ping1")

    log("waiting for incoming message on ac2")
    snapshot = ac2.wait_for_incoming_msg().get_snapshot()
    assert snapshot.text == "ping1"

    log("sending ac2 -> ac1 realtime advertisement and additional message")
    ac2_webxdc_msg.send_webxdc_realtime_advertisement()
    acfactory.send_message(from_account=ac2, to_account=ac1, text="ping2")

    log("waiting for incoming message on ac1")
    snapshot = ac1.wait_for_incoming_msg().get_snapshot()
    assert snapshot.text == "ping2"

    log("sending realtime data ac1 -> ac2")
    # Test that 128 KB of data can be sent in a single message.
    data = os.urandom(128000)
    ac1_webxdc_msg.send_webxdc_realtime_data(data)

    assert ac2.wait_for_realtime_data(ac2_webxdc_msg.id) == data


def test_realtime_simultaneously(acfactory, path_to_webxdc):
    """Test two peers trying to establish connection simultaneously."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    setup_realtime_webxdc(ac1, ac2, path_to_webxdc)


def test_two_parallel_realtime_simultaneously(acfactory, path_to_webxdc):
    """Test two peers trying to establish connection simultaneously."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_webxdc_msg, ac2_webxdc_msg = setup_realtime_webxdc(ac1, ac2, path_to_webxdc, wait=False)
    ac1_webxdc_msg2, ac2_webxdc_msg2 = setup_realtime_webxdc(ac1, ac2, path_to_webxdc, wait=False)
    wait_realtime_connected([(ac1_webxdc_msg, ac2_webxdc_msg), (ac2_webxdc_msg, ac1_webxdc_msg)])
    wait_realtime_connected([(ac1_webxdc_msg2, ac2_webxdc_msg2), (ac2_webxdc_msg2, ac1_webxdc_msg2)])


def test_no_duplicate_messages(acfactory, path_to_webxdc):
    """Test that messages are received only once."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_ac2_chat = ac1.create_chat(ac2)

    ac1_webxdc_msg = ac1_ac2_chat.send_message(text="webxdc", file=path_to_webxdc)

    ac2_webxdc_msg = ac2.wait_for_incoming_msg()
    ac2_webxdc_msg.get_snapshot().chat.accept()
    assert ac2_webxdc_msg.get_snapshot().text == "webxdc"

    # Issue a "send" call in parallel with sending advertisement.
    # Previously due to a bug this caused subscribing to the channel twice.
    ac2_webxdc_msg.send_webxdc_realtime_data.future(b"foobar")
    ac2_webxdc_msg.send_webxdc_realtime_advertisement()

    with send_realtime_data_forever([ac1_webxdc_msg], data=[lambda i: str(i).encode()]):
        n = int(ac2.wait_for_realtime_data(ac2_webxdc_msg.id).decode())
        assert int(ac2.wait_for_realtime_data(ac2_webxdc_msg.id).decode()) > n


def test_no_reordering(acfactory, path_to_webxdc):
    """Test that sending a lot of realtime messages does not result in reordering."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_webxdc_msg, ac2_webxdc_msg = setup_realtime_webxdc(ac1, ac2, path_to_webxdc, wait=True)

    for i in range(200):
        ac1_webxdc_msg.send_webxdc_realtime_data([i])

    for i in range(200):
        # lingering SETUP_DATA payloads from the wait_realtime_connected() barrier may still arrive
        while (data := ac2.wait_for_realtime_data(ac2_webxdc_msg.id)) == SETUP_DATA:
            pass
        assert data == bytes([i]), "Reordering detected"


def test_advertisement_after_chatting(acfactory, path_to_webxdc):
    """Test that realtime advertisement is assigned to the correct message after chatting."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_ac2_chat = ac1.create_chat(ac2)
    ac1_webxdc_msg = ac1_ac2_chat.send_message(text="WebXDC", file=path_to_webxdc)
    ac2_webxdc_msg = ac2.wait_for_incoming_msg()
    ac2_webxdc_msg_snapshot = ac2_webxdc_msg.get_snapshot()
    assert ac2_webxdc_msg_snapshot.text == "WebXDC"
    ac2_webxdc_msg_snapshot.chat.accept()

    ac1_ac2_chat.send_text("Hello!")
    ac2_hello_msg = ac2.wait_for_incoming_msg()
    ac2_hello_msg_snapshot = ac2_hello_msg.get_snapshot()
    assert ac2_hello_msg_snapshot.text == "Hello!"
    ac2_hello_msg_snapshot.chat.accept()

    ac2_webxdc_msg.send_webxdc_realtime_advertisement()
    event = ac1.wait_for_event(EventType.WEBXDC_REALTIME_ADVERTISEMENT_RECEIVED)
    assert event.msg_id == ac1_webxdc_msg.id


def test_realtime_large_webxdc(acfactory, path_to_large_webxdc):
    """Tests initializing realtime channel on a large webxdc.

    This is a regression test for a bug that existed in version 2.42.0.
    Large webxdc is split into pre- and post- message,
    and this previously resulted in failure to initialize realtime.
    """
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2.create_chat(ac1)
    ac1_ac2_chat = ac1.create_chat(ac2)
    ac1_webxdc_msg = ac1_ac2_chat.send_message(text="realtime check", file=path_to_large_webxdc)

    # Receive pre-message.
    ac2_webxdc_msg = ac2.wait_for_incoming_msg()

    # Receive post-message.
    ac2_webxdc_msg = ac2.wait_for_msg(EventType.MSGS_CHANGED)

    ac2_webxdc_msg.send_webxdc_realtime_advertisement()
    event = ac1.wait_for_event(EventType.WEBXDC_REALTIME_ADVERTISEMENT_RECEIVED)
    assert event.msg_id == ac1_webxdc_msg.id
