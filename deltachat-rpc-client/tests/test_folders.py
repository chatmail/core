import logging
import re
import time

import pytest
from imap_tools import AND, U

from deltachat_rpc_client import Contact, EventType, Message


def test_move_works(acfactory, direct_imap):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2_direct_imap = direct_imap(ac2)
    ac2_direct_imap.create_folder("DeltaChat")
    ac2.set_config("mvbox_move", "1")
    ac2.bring_online()

    chat = ac1.create_chat(ac2)
    chat.send_text("message1")

    # Message is moved to the movebox
    ac2.wait_for_event(EventType.IMAP_MESSAGE_MOVED)

    # Message is downloaded
    msg = ac2.wait_for_incoming_msg().get_snapshot()
    assert msg.text == "message1"


def test_reactions_for_a_reordering_move(acfactory, direct_imap):
    """When a batch of messages is moved from Inbox to DeltaChat folder with a single MOVE command,
    their UIDs may be reordered (e.g. Gmail is known for that) which led to that messages were
    processed by receive_imf in the wrong order, and, particularly, reactions were processed before
    messages they refer to and thus dropped.
    """
    (ac1,) = acfactory.get_online_accounts(1)

    addr, password = acfactory.get_credentials()
    ac2 = acfactory.get_unconfigured_account()
    ac2.add_or_update_transport({"addr": addr, "password": password})
    ac2_direct_imap = direct_imap(ac2)
    ac2_direct_imap.create_folder("DeltaChat")
    ac2.set_config("mvbox_move", "1")
    assert ac2.is_configured()

    ac2.bring_online()
    chat1 = acfactory.get_accepted_chat(ac1, ac2)
    ac2.stop_io()

    logging.info("sending message + reaction from ac1 to ac2")
    msg1 = chat1.send_text("hi")
    msg1.wait_until_delivered()
    # It's is sad, but messages must differ in their INTERNALDATEs to be processed in the correct
    # order by DC, and most (if not all) mail servers provide only seconds precision.
    time.sleep(1.1)
    react_str = "\N{THUMBS UP SIGN}"
    msg1.send_reaction(react_str).wait_until_delivered()

    logging.info("moving messages to ac2's DeltaChat folder in the reverse order")
    ac2_direct_imap = direct_imap(ac2)
    ac2_direct_imap.connect()
    for uid in sorted([m.uid for m in ac2_direct_imap.get_all_messages()], reverse=True):
        ac2_direct_imap.conn.move(uid, "DeltaChat")

    logging.info("receiving messages by ac2")
    ac2.start_io()
    msg2 = Message(ac2, ac2.wait_for_reactions_changed().msg_id)
    assert msg2.get_snapshot().text == msg1.get_snapshot().text
    reactions = msg2.get_reactions()
    contacts = [Contact(ac2, int(i)) for i in reactions.reactions_by_contact]
    assert len(contacts) == 1
    assert contacts[0].get_snapshot().address == ac1.get_config("addr")
    assert list(reactions.reactions_by_contact.values())[0] == [react_str]


def test_move_works_on_self_sent(acfactory, direct_imap):
    ac1, ac2 = acfactory.get_online_accounts(2)

    # Create and enable movebox.
    ac1_direct_imap = direct_imap(ac1)
    ac1_direct_imap.create_folder("DeltaChat")
    ac1.set_config("mvbox_move", "1")
    ac1.set_config("bcc_self", "1")
    ac1.bring_online()

    chat = ac1.create_chat(ac2)
    chat.send_text("message1")
    ac1.wait_for_event(EventType.IMAP_MESSAGE_MOVED)
    chat.send_text("message2")
    ac1.wait_for_event(EventType.IMAP_MESSAGE_MOVED)
    chat.send_text("message3")
    ac1.wait_for_event(EventType.IMAP_MESSAGE_MOVED)


def test_moved_markseen(acfactory, direct_imap):
    """Test that message already moved to DeltaChat folder is marked as seen."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2_direct_imap = direct_imap(ac2)
    ac2_direct_imap.create_folder("DeltaChat")
    ac2.set_config("mvbox_move", "1")
    ac2.set_config("delete_server_after", "0")
    ac2.set_config("sync_msgs", "0")  # Do not send a sync message when accepting a contact request.
    ac2.bring_online()

    ac2.stop_io()
    ac2_direct_imap = direct_imap(ac2)
    with ac2_direct_imap.idle() as idle2:
        ac1.create_chat(ac2).send_text("Hello!")
        idle2.wait_for_new_message()

    # Emulate moving of the message to DeltaChat folder by Sieve rule.
    ac2_direct_imap.conn.move(["*"], "DeltaChat")
    ac2_direct_imap.select_folder("DeltaChat")
    assert len(list(ac2_direct_imap.conn.fetch("*", mark_seen=False))) == 1

    with ac2_direct_imap.idle() as idle2:
        ac2.start_io()

        ev = ac2.wait_for_event(EventType.MSGS_CHANGED)
        msg = ac2.get_message_by_id(ev.msg_id)
        assert msg.get_snapshot().text == "Messages are end-to-end encrypted."

        ev = ac2.wait_for_event(EventType.INCOMING_MSG)
        msg = ac2.get_message_by_id(ev.msg_id)
        chat = ac2.get_chat_by_id(ev.chat_id)

        # Accept the contact request.
        chat.accept()
        msg.mark_seen()
        idle2.wait_for_seen()

    assert len(list(ac2_direct_imap.conn.fetch(AND(seen=True, uid=U(1, "*")), mark_seen=False))) == 1


@pytest.mark.parametrize("mvbox_move", [True, False])
def test_markseen_message_and_mdn(acfactory, direct_imap, mvbox_move):
    ac1, ac2 = acfactory.get_online_accounts(2)

    for ac in ac1, ac2:
        ac.set_config("delete_server_after", "0")
        if mvbox_move:
            ac_direct_imap = direct_imap(ac)
            ac_direct_imap.create_folder("DeltaChat")
            ac.set_config("mvbox_move", "1")
            ac.bring_online()

    # Do not send BCC to self, we only want to test MDN on ac1.
    ac1.set_config("bcc_self", "0")

    acfactory.get_accepted_chat(ac1, ac2).send_text("hi")
    msg = ac2.wait_for_incoming_msg()
    msg.mark_seen()

    if mvbox_move:
        rex = re.compile("Marked messages [0-9]+ in folder DeltaChat as seen.")
    else:
        rex = re.compile("Marked messages [0-9]+ in folder INBOX as seen.")

    for ac in ac1, ac2:
        while True:
            event = ac.wait_for_event()
            if event.kind == EventType.INFO and rex.search(event.msg):
                break

    folder = "mvbox" if mvbox_move else "inbox"
    ac1_direct_imap = direct_imap(ac1)
    ac2_direct_imap = direct_imap(ac2)

    ac1_direct_imap.select_config_folder(folder)
    ac2_direct_imap.select_config_folder(folder)

    # Check that the mdn is marked as seen
    assert len(list(ac1_direct_imap.conn.fetch(AND(seen=True), mark_seen=False))) == 1
    # Check original message is marked as seen
    assert len(list(ac2_direct_imap.conn.fetch(AND(seen=True), mark_seen=False))) == 1


def test_trash_multiple_messages(acfactory, direct_imap, log):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2.stop_io()

    ac2.set_config("delete_server_after", "0")
    ac2.set_config("sync_msgs", "0")

    ac2.start_io()
    chat12 = acfactory.get_accepted_chat(ac1, ac2)

    log.section("ac1: sending 3 messages")
    texts = ["first", "second", "third"]
    for text in texts:
        chat12.send_text(text)

    log.section("ac2: waiting for all messages on the other side")
    to_delete = []
    for text in texts:
        msg = ac2.wait_for_incoming_msg().get_snapshot()
        assert msg.text in texts
        if text != "second":
            to_delete.append(msg)

    log.section("ac2: deleting all messages except second")
    assert len(to_delete) == len(texts) - 1
    ac2.delete_messages(to_delete)

    log.section("ac2: test that only one message is left")
    ac2_direct_imap = direct_imap(ac2)
    while 1:
        ac2.wait_for_event(EventType.IMAP_MESSAGE_DELETED)
        ac2_direct_imap.select_config_folder("inbox")
        nr_msgs = len(ac2_direct_imap.get_all_messages())
        assert nr_msgs > 0
        if nr_msgs == 1:
            break
