import re

from imap_tools import AND, U

from deltachat_rpc_client import EventType


def test_moved_markseen(acfactory, direct_imap, log):
    """Test that message already moved to DeltaChat folder is marked as seen."""
    ac1 = acfactory.get_online_account()

    addr, password = acfactory.get_credentials()
    ac2 = acfactory.get_unconfigured_account()
    ac2.add_or_update_transport({"addr": addr, "password": password})
    ac2.bring_online()

    log.section("ac2: creating DeltaChat folder")
    ac2_direct_imap = direct_imap(ac2)
    ac2_direct_imap.create_folder("DeltaChat")
    # ac2.set_config("delete_server_after", "0")  # TODO check if this causes a test failure
    ac2.set_config("sync_msgs", "0")  # Do not send a sync message when accepting a contact request.

    ac2.add_or_update_transport({"addr": addr, "password": password, "imapFolder": "DeltaChat"})
    ac2.bring_online()

    ac2.stop_io()
    ac2_direct_imap = direct_imap(ac2)
    with ac2_direct_imap.idle() as idle2:
        ac1.create_chat(ac2).send_text("Hello!")
        idle2.wait_for_new_message()

    # Emulate moving of the message to DeltaChat folder by Sieve rule.
    log.section("ac2: moving message into DeltaChat folder")
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


def test_markseen_message_and_mdn(acfactory, direct_imap):
    ac1, ac2 = acfactory.get_online_accounts(2)

    for ac in ac1, ac2:
        # TODO check if this causes a test failure
        # ac.set_config("delete_server_after", "0")
        pass

    # Do not send BCC to self, we only want to test MDN on ac1.
    ac1.set_config("bcc_self", "0")

    acfactory.get_accepted_chat(ac1, ac2).send_text("hi")
    msg = ac2.wait_for_incoming_msg()
    msg.mark_seen()

    rex = re.compile("Marked messages [0-9]+ in folder INBOX as seen.")

    for ac in ac1, ac2:
        while True:
            event = ac.wait_for_event()
            if event.kind == EventType.INFO and rex.search(event.msg):
                break

    ac1_direct_imap = direct_imap(ac1)
    ac2_direct_imap = direct_imap(ac2)

    ac1_direct_imap.select_folder("INBOX")
    ac2_direct_imap.select_folder("INBOX")

    # Check that the mdn is marked as seen
    assert len(list(ac1_direct_imap.conn.fetch(AND(seen=True), mark_seen=False))) == 1
    # Check original message is marked as seen
    assert len(list(ac2_direct_imap.conn.fetch(AND(seen=True), mark_seen=False))) == 1


def test_trash_multiple_messages(acfactory, direct_imap, log):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2.stop_io()

    # TODO check if this causes a test failure: ac2.set_config("delete_server_after", "0")
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
