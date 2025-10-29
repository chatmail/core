#!/usr/bin/env python3
"""
Testing webxdc iroh connectivity

If you want to debug iroh at rust-trace/log level set

    RUST_LOG=iroh_net=trace,iroh_gossip=trace
"""

import logging
import os
import threading
import time

import pytest

from deltachat_rpc_client import EventType


@pytest.fixture
def path_to_webxdc(request):
    p = request.path.parent.parent.parent.joinpath("test-data/webxdc/chess.xdc")
    assert p.exists()
    return str(p)


def log(msg):
    logging.info(msg)


def setup_realtime_webxdc(ac1, ac2, path_to_webxdc):
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

    return ac1_webxdc_msg, ac2_webxdc_msg


def setup_thread_send_realtime_data(msg, data):
    def thread_run():
        for _i in range(10):
            msg.send_webxdc_realtime_data(data)
            time.sleep(1)

    threading.Thread(target=thread_run, daemon=True).start()


def wait_receive_realtime_data(msg_data_list):
    account = msg_data_list[0][0].account
    msg_data_list = msg_data_list[:]

    log(f"account {account.id}: waiting for realtime data {msg_data_list}")
    while msg_data_list:
        event = account.wait_for_event()
        if event.kind == EventType.WEBXDC_REALTIME_DATA:
            for i, (msg, data) in enumerate(msg_data_list):
                if msg.id == event.msg_id:
                    assert list(data) == event.data
                    log(f"msg {msg.id}: got correct realtime data {data}")
                    del msg_data_list[i]
                    break


def test_realtime_sequentially(acfactory, path_to_webxdc):
    """Test two peers trying to establish connection sequentially."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.set_config("webxdc_realtime_enabled", "1")
    ac2.set_config("webxdc_realtime_enabled", "1")
    ac1.create_chat(ac2)
    ac2.create_chat(ac1)

    # share a webxdc app between ac1 and ac2
    ac1_webxdc_msg = acfactory.send_message(from_account=ac1, to_account=ac2, text="play", file=path_to_webxdc)
    ac2_webxdc_msg = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id)
    snapshot = ac2_webxdc_msg.get_snapshot()
    assert snapshot.text == "play"

    # send iroh announcements sequentially
    log("sending ac1 -> ac2 realtime advertisement and additional message")
    ac1_webxdc_msg.send_webxdc_realtime_advertisement()
    acfactory.send_message(from_account=ac1, to_account=ac2, text="ping1")

    log("waiting for incoming message on ac2")
    snapshot = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "ping1"

    log("sending ac2 -> ac1 realtime advertisement and additional message")
    ac2_webxdc_msg.send_webxdc_realtime_advertisement()
    acfactory.send_message(from_account=ac2, to_account=ac1, text="ping2")

    log("waiting for incoming message on ac1")
    snapshot = ac1.get_message_by_id(ac1.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "ping2"

    log("sending realtime data ac1 -> ac2")
    # Test that 128 KB of data can be sent in a single message.
    data = os.urandom(128000)
    ac1_webxdc_msg.send_webxdc_realtime_data(data)

    log("ac2: waiting for realtime data")
    while 1:
        event = ac2.wait_for_event()
        if event.kind == EventType.WEBXDC_REALTIME_DATA:
            assert event.data == list(data)
            break


def test_realtime_simultaneously(acfactory, path_to_webxdc):
    """Test two peers trying to establish connection simultaneously."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.set_config("webxdc_realtime_enabled", "1")
    ac2.set_config("webxdc_realtime_enabled", "1")

    ac1_webxdc_msg, ac2_webxdc_msg = setup_realtime_webxdc(ac1, ac2, path_to_webxdc)

    setup_thread_send_realtime_data(ac1_webxdc_msg, [10])
    wait_receive_realtime_data([(ac2_webxdc_msg, [10])])


def test_two_parallel_realtime_simultaneously(acfactory, path_to_webxdc):
    """Test two peers trying to establish connection simultaneously."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.set_config("webxdc_realtime_enabled", "1")
    ac2.set_config("webxdc_realtime_enabled", "1")

    ac1_webxdc_msg, ac2_webxdc_msg = setup_realtime_webxdc(ac1, ac2, path_to_webxdc)
    ac1_webxdc_msg2, ac2_webxdc_msg2 = setup_realtime_webxdc(ac1, ac2, path_to_webxdc)

    setup_thread_send_realtime_data(ac1_webxdc_msg, [10])
    setup_thread_send_realtime_data(ac1_webxdc_msg2, [20])
    setup_thread_send_realtime_data(ac2_webxdc_msg, [30])
    setup_thread_send_realtime_data(ac2_webxdc_msg2, [40])

    wait_receive_realtime_data([(ac1_webxdc_msg, [30]), (ac1_webxdc_msg2, [40])])
    wait_receive_realtime_data([(ac2_webxdc_msg, [10]), (ac2_webxdc_msg2, [20])])


def test_no_duplicate_messages(acfactory, path_to_webxdc):
    """Test that messages are received only once."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.set_config("webxdc_realtime_enabled", "1")
    ac2.set_config("webxdc_realtime_enabled", "1")

    ac1_ac2_chat = ac1.create_chat(ac2)

    ac1_webxdc_msg = ac1_ac2_chat.send_message(text="webxdc", file=path_to_webxdc)

    ac2_webxdc_msg = ac2.wait_for_incoming_msg()
    ac2_webxdc_msg.get_snapshot().chat.accept()
    assert ac2_webxdc_msg.get_snapshot().text == "webxdc"

    # Issue a "send" call in parallel with sending advertisement.
    # Previously due to a bug this caused subscribing to the channel twice.
    ac2_webxdc_msg.send_webxdc_realtime_data.future(b"foobar")
    ac2_webxdc_msg.send_webxdc_realtime_advertisement()

    def thread_run():
        for i in range(10):
            data = str(i).encode()
            ac1_webxdc_msg.send_webxdc_realtime_data(data)
            time.sleep(1)

    threading.Thread(target=thread_run, daemon=True).start()

    event = ac2.wait_for_event(EventType.WEBXDC_REALTIME_DATA)
    n = int(bytes(event.data).decode())

    event = ac2.wait_for_event(EventType.WEBXDC_REALTIME_DATA)
    assert int(bytes(event.data).decode()) > n


def test_no_reordering(acfactory, path_to_webxdc):
    """Test that sending a lot of realtime messages does not result in reordering."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.set_config("webxdc_realtime_enabled", "1")
    ac2.set_config("webxdc_realtime_enabled", "1")

    ac1_webxdc_msg, ac2_webxdc_msg = setup_realtime_webxdc(ac1, ac2, path_to_webxdc)

    setup_thread_send_realtime_data(ac1_webxdc_msg, b"hello")
    wait_receive_realtime_data([(ac2_webxdc_msg, b"hello")])

    for i in range(200):
        ac1_webxdc_msg.send_webxdc_realtime_data([i])

    for i in range(200):
        while 1:
            event = ac2.wait_for_event()
            if event.kind == EventType.WEBXDC_REALTIME_DATA and bytes(event.data) != b"hello":
                if event.data[0] == i:
                    break
                pytest.fail("Reordering detected")


def test_advertisement_after_chatting(acfactory, path_to_webxdc):
    """Test that realtime advertisement is assigned to the correct message after chatting."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.set_config("webxdc_realtime_enabled", "1")
    ac2.set_config("webxdc_realtime_enabled", "1")

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
