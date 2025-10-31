from __future__ import annotations

import base64
import os
from typing import TYPE_CHECKING

from deltachat_rpc_client import Account, EventType, const

if TYPE_CHECKING:
    from deltachat_rpc_client.pytestplugin import ACFactory


def wait_for_chatlist_and_specific_item(account, chat_id):
    first_event = ""
    while True:
        event = account.wait_for_event()
        if event.kind == EventType.CHATLIST_CHANGED:
            first_event = "change"
            break
        if event.kind == EventType.CHATLIST_ITEM_CHANGED and event.chat_id == chat_id:
            first_event = "item_change"
            break
    while True:
        event = account.wait_for_event()
        if event.kind == EventType.CHATLIST_CHANGED and first_event == "item_change":
            break
        if event.kind == EventType.CHATLIST_ITEM_CHANGED and event.chat_id == chat_id and first_event == "change":
            break


def wait_for_chatlist_specific_item(account, chat_id):
    while True:
        event = account.wait_for_event()
        if event.kind == EventType.CHATLIST_ITEM_CHANGED and event.chat_id == chat_id:
            break


def wait_for_chatlist(account):
    while True:
        event = account.wait_for_event()
        if event.kind == EventType.CHATLIST_CHANGED:
            break


def test_delivery_status(acfactory: ACFactory) -> None:
    """
    Test change status on chatlistitem when status changes (delivered, read)
    """
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()

    alice.clear_all_events()
    bob.stop_io()
    alice.stop_io()
    alice_chat_bob.send_text("hi")
    wait_for_chatlist_and_specific_item(alice, chat_id=alice_chat_bob.id)

    alice.clear_all_events()
    alice.start_io()
    wait_for_chatlist_specific_item(alice, chat_id=alice_chat_bob.id)

    bob.clear_all_events()
    bob.start_io()

    event = bob.wait_for_incoming_msg_event()
    msg = bob.get_message_by_id(event.msg_id)
    msg.get_snapshot().chat.accept()
    msg.mark_seen()

    chat_item = alice._rpc.get_chatlist_items_by_entries(alice.id, [alice_chat_bob.id])[str(alice_chat_bob.id)]
    assert chat_item["summaryStatus"] == const.MessageState.OUT_DELIVERED

    alice.clear_all_events()

    while True:
        event = alice.wait_for_event()
        if event.kind == EventType.MSG_READ:
            break

    wait_for_chatlist_specific_item(alice, chat_id=alice_chat_bob.id)
    chat_item = alice._rpc.get_chatlist_items_by_entries(alice.id, [alice_chat_bob.id])[str(alice_chat_bob.id)]
    assert chat_item["summaryStatus"] == const.MessageState.OUT_MDN_RCVD


def test_delivery_status_failed(acfactory: ACFactory) -> None:
    """
    Test change status on chatlistitem when status changes failed
    """
    (alice,) = acfactory.get_online_accounts(1)

    invalid_contact = alice.create_contact("example@example.com", "invalid address")
    invalid_chat = alice.get_chat_by_id(alice._rpc.create_chat_by_contact_id(alice.id, invalid_contact.id))

    alice.clear_all_events()

    failing_message = invalid_chat.send_text("test")

    wait_for_chatlist_and_specific_item(alice, invalid_chat.id)

    assert failing_message.get_snapshot().state == const.MessageState.OUT_PENDING

    while True:
        event = alice.wait_for_event()
        if event.kind == EventType.MSG_FAILED:
            break

    wait_for_chatlist_specific_item(alice, invalid_chat.id)

    assert failing_message.get_snapshot().state == const.MessageState.OUT_FAILED


def test_download_on_demand(acfactory: ACFactory) -> None:
    """
    Test if download on demand emits chatlist update events.
    This is only needed for last message in chat, but finding that out is too expensive, so it's always emitted
    """
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_text("hi")

    alice.set_config("download_limit", "1")

    msg = bob.wait_for_incoming_msg()
    chat_id = msg.get_snapshot().chat_id
    msg.get_snapshot().chat.accept()
    bob.get_chat_by_id(chat_id).send_message(
        "Hello World, this message is bigger than 5 bytes",
        html=base64.b64encode(os.urandom(300000)).decode("utf-8"),
    )

    message = alice.wait_for_incoming_msg()
    snapshot = message.get_snapshot()
    assert snapshot.download_state == const.DownloadState.AVAILABLE

    alice.clear_all_events()

    snapshot = message.get_snapshot()
    chat_id = snapshot.chat_id
    alice._rpc.download_full_message(alice.id, message.id)

    wait_for_chatlist_specific_item(alice, chat_id)


def get_multi_account_test_setup(acfactory: ACFactory) -> [Account, Account, Account]:
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_text("hi")

    bob.wait_for_incoming_msg_event()

    alice_second_device = alice.clone()
    alice_second_device.start_io()
    alice.clear_all_events()
    alice_second_device.clear_all_events()
    bob.clear_all_events()
    return [alice, alice_second_device, bob, alice_chat_bob]


def test_imap_sync_seen_msgs(acfactory: ACFactory) -> None:
    """
    Test that chatlist changed events are emitted for the second device
    when the message is marked as read on the first device
    """
    alice, alice_second_device, bob, alice_chat_bob = get_multi_account_test_setup(acfactory)

    bob.create_chat(alice)

    alice_chat_bob.send_text("hello")

    msg = bob.wait_for_incoming_msg()
    bob_chat_id = msg.get_snapshot().chat_id
    msg.get_snapshot().chat.accept()

    alice.clear_all_events()
    alice_second_device.clear_all_events()
    bob.get_chat_by_id(bob_chat_id).send_text("hello")

    # make sure alice_second_device already received the message
    alice_second_device.wait_for_incoming_msg_event()

    msg = alice.wait_for_incoming_msg()
    alice_second_device.clear_all_events()
    msg.mark_seen()

    wait_for_chatlist_specific_item(bob, bob_chat_id)
    wait_for_chatlist_specific_item(alice, alice_chat_bob.id)


def test_multidevice_sync_chat(acfactory: ACFactory) -> None:
    """
    Test multidevice sync: syncing chat visibility and muting across multiple devices
    """
    alice, alice_second_device, bob, alice_chat_bob = get_multi_account_test_setup(acfactory)

    alice_chat_bob.archive()
    wait_for_chatlist_specific_item(alice_second_device, alice_chat_bob.id)
    assert alice_second_device.get_chat_by_id(alice_chat_bob.id).get_basic_snapshot().archived

    alice_second_device.clear_all_events()
    alice_chat_bob.pin()
    wait_for_chatlist_specific_item(alice_second_device, alice_chat_bob.id)
    assert alice_second_device.get_chat_by_id(alice_chat_bob.id).get_basic_snapshot().pinned

    alice_second_device.clear_all_events()
    alice_chat_bob.mute()
    wait_for_chatlist_specific_item(alice_second_device, alice_chat_bob.id)
    assert alice_second_device.get_chat_by_id(alice_chat_bob.id).get_basic_snapshot().is_muted
