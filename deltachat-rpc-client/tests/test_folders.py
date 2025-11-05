import logging
import re
import time

import pytest
from imap_tools import AND, U

from deltachat_rpc_client import Contact, EventType, Message


def test_move_works(acfactory):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2.set_config("mvbox_move", "1")
    ac2.bring_online()

    chat = ac1.create_chat(ac2)
    chat.send_text("message1")

    # Message is moved to the movebox
    ac2.wait_for_event(EventType.IMAP_MESSAGE_MOVED)

    # Message is downloaded
    msg = ac2.wait_for_incoming_msg().get_snapshot()
    assert msg.text == "message1"


def test_move_avoids_loop(acfactory, direct_imap):
    """Test that the message is only moved from INBOX to DeltaChat.

    This is to avoid busy loop if moved message reappears in the Inbox
    or some scanned folder later.
    For example, this happens on servers that alias `INBOX.DeltaChat` to `DeltaChat` folder,
    so the message moved to `DeltaChat` appears as a new message in the `INBOX.DeltaChat` folder.
    We do not want to move this message from `INBOX.DeltaChat` to `DeltaChat` again.
    """
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2.set_config("mvbox_move", "1")
    ac2.set_config("delete_server_after", "0")
    ac2.bring_online()

    # Create INBOX.DeltaChat folder and make sure
    # it is detected by full folder scan.
    ac2_direct_imap = direct_imap(ac2)
    ac2_direct_imap.create_folder("INBOX.DeltaChat")
    ac2.stop_io()
    ac2.start_io()

    while True:
        event = ac2.wait_for_event()
        # Wait until the end of folder scan.
        if event.kind == EventType.INFO and "Found folders:" in event.msg:
            break

    ac1_chat = acfactory.get_accepted_chat(ac1, ac2)
    ac1_chat.send_text("Message 1")

    # Message is moved to the DeltaChat folder and downloaded.
    ac2_msg1 = ac2.wait_for_incoming_msg().get_snapshot()
    assert ac2_msg1.text == "Message 1"

    # Move the message to the INBOX.DeltaChat again.
    # We assume that test server uses "." as the delimiter.
    ac2_direct_imap.select_folder("DeltaChat")
    ac2_direct_imap.conn.move(["*"], "INBOX.DeltaChat")

    ac1_chat.send_text("Message 2")
    ac2_msg2 = ac2.wait_for_incoming_msg().get_snapshot()
    assert ac2_msg2.text == "Message 2"

    # Stop and start I/O to trigger folder scan.
    ac2.stop_io()
    ac2.start_io()
    while True:
        event = ac2.wait_for_event()
        # Wait until the end of folder scan.
        if event.kind == EventType.INFO and "Found folders:" in event.msg:
            break

    # Check that Message 1 is still in the INBOX.DeltaChat folder
    # and Message 2 is in the DeltaChat folder.
    ac2_direct_imap.select_folder("INBOX")
    assert len(ac2_direct_imap.get_all_messages()) == 0
    ac2_direct_imap.select_folder("DeltaChat")
    assert len(ac2_direct_imap.get_all_messages()) == 1
    ac2_direct_imap.select_folder("INBOX.DeltaChat")
    assert len(ac2_direct_imap.get_all_messages()) == 1


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


def test_delete_deltachat_folder(acfactory, direct_imap):
    """Test that DeltaChat folder is recreated if user deletes it manually."""
    ac1 = acfactory.new_configured_account()
    ac1.set_config("mvbox_move", "1")
    ac1.bring_online()

    ac1_direct_imap = direct_imap(ac1)
    ac1_direct_imap.conn.folder.delete("DeltaChat")
    assert "DeltaChat" not in ac1_direct_imap.list_folders()

    # Wait until new folder is created and UIDVALIDITY is updated.
    while True:
        event = ac1.wait_for_event()
        if event.kind == EventType.INFO and "transport 1: UID validity for folder DeltaChat changed from " in event.msg:
            break

    ac2 = acfactory.get_online_account()
    ac2.create_chat(ac1).send_text("hello")
    msg = ac1.wait_for_incoming_msg().get_snapshot()
    assert msg.text == "hello"

    assert "DeltaChat" in ac1_direct_imap.list_folders()


def test_dont_show_emails(acfactory, direct_imap, log):
    """Most mailboxes have a "Drafts" folder where constantly new emails appear but we don't actually want to show them.
    So: If it's outgoing AND there is no Received header, then ignore the email.

    If the draft email is sent out and received later (i.e. it's in "Inbox"), it must be shown.

    Also, test that unknown emails in the Spam folder are not shown."""
    ac1 = acfactory.new_configured_account()
    ac1.stop_io()
    ac1.set_config("show_emails", "2")

    ac1.create_contact("alice@example.org").create_chat()

    ac1_direct_imap = direct_imap(ac1)
    ac1_direct_imap.create_folder("Drafts")
    ac1_direct_imap.create_folder("Spam")
    ac1_direct_imap.create_folder("Junk")

    # Learn UID validity for all folders.
    ac1.set_config("scan_all_folders_debounce_secs", "0")
    ac1.start_io()
    ac1.wait_for_event(EventType.IMAP_INBOX_IDLE)
    ac1.stop_io()

    ac1_direct_imap.append(
        "Drafts",
        """
        From: ac1 <{}>
        Subject: subj
        To: alice@example.org
        Message-ID: <aepiors@example.org>
        Content-Type: text/plain; charset=utf-8

        message in Drafts received later
    """.format(
            ac1.get_config("configured_addr"),
        ),
    )
    ac1_direct_imap.append(
        "Spam",
        """
        From: unknown.address@junk.org
        Subject: subj
        To: {}
        Message-ID: <spam.message@junk.org>
        Content-Type: text/plain; charset=utf-8

        Unknown message in Spam
    """.format(
            ac1.get_config("configured_addr"),
        ),
    )
    ac1_direct_imap.append(
        "Spam",
        """
        From: unknown.address@junk.org, unkwnown.add@junk.org
        Subject: subj
        To: {}
        Message-ID: <spam.message2@junk.org>
        Content-Type: text/plain; charset=utf-8

        Unknown & malformed message in Spam
    """.format(
            ac1.get_config("configured_addr"),
        ),
    )
    ac1_direct_imap.append(
        "Spam",
        """
        From: delta<address: inbox@nhroy.com>
        Subject: subj
        To: {}
        Message-ID: <spam.message99@junk.org>
        Content-Type: text/plain; charset=utf-8

        Unknown & malformed message in Spam
    """.format(
            ac1.get_config("configured_addr"),
        ),
    )
    ac1_direct_imap.append(
        "Spam",
        """
        From: alice@example.org
        Subject: subj
        To: {}
        Message-ID: <spam.message3@junk.org>
        Content-Type: text/plain; charset=utf-8

        Actually interesting message in Spam
    """.format(
            ac1.get_config("configured_addr"),
        ),
    )
    ac1_direct_imap.append(
        "Junk",
        """
        From: unknown.address@junk.org
        Subject: subj
        To: {}
        Message-ID: <spam.message@junk.org>
        Content-Type: text/plain; charset=utf-8

        Unknown message in Junk
    """.format(
            ac1.get_config("configured_addr"),
        ),
    )

    ac1.set_config("scan_all_folders_debounce_secs", "0")
    log.section("All prepared, now let DC find the message")
    ac1.start_io()

    # Wait until each folder was scanned, this is necessary for this test to test what it should test:
    ac1.wait_for_event(EventType.IMAP_INBOX_IDLE)

    fresh_msgs = list(ac1.get_fresh_messages())
    msg = fresh_msgs[0].get_snapshot()
    chat_msgs = msg.chat.get_messages()
    assert len(chat_msgs) == 1
    assert msg.text == "subj – Actually interesting message in Spam"

    assert not any("unknown.address" in c.get_full_snapshot().name for c in ac1.get_chatlist())
    ac1_direct_imap.select_folder("Spam")
    assert ac1_direct_imap.get_uid_by_message_id("spam.message@junk.org")

    ac1.stop_io()
    log.section("'Send out' the draft by moving it to Inbox, and wait for DC to display it this time")
    ac1_direct_imap.select_folder("Drafts")
    uid = ac1_direct_imap.get_uid_by_message_id("aepiors@example.org")
    ac1_direct_imap.conn.move(uid, "Inbox")

    ac1.start_io()
    event = ac1.wait_for_event(EventType.MSGS_CHANGED)
    msg2 = Message(ac1, event.msg_id).get_snapshot()

    assert msg2.text == "subj – message in Drafts received later"
    assert len(msg.chat.get_messages()) == 2


def test_move_works_on_self_sent(acfactory):
    ac1, ac2 = acfactory.get_online_accounts(2)

    # Enable movebox and wait until it is created.
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


def test_mvbox_and_trash(acfactory, direct_imap, log):
    log.section("ac1: start with mvbox")
    ac1 = acfactory.get_online_account()
    ac1.set_config("mvbox_move", "1")
    ac1.bring_online()

    log.section("ac2: start without a mvbox")
    ac2 = acfactory.get_online_account()

    log.section("ac1: create trash")
    ac1_direct_imap = direct_imap(ac1)
    ac1_direct_imap.create_folder("Trash")
    ac1.set_config("scan_all_folders_debounce_secs", "0")
    ac1.stop_io()
    ac1.start_io()

    log.section("ac1: send message and wait for ac2 to receive it")
    acfactory.get_accepted_chat(ac1, ac2).send_text("message1")
    assert ac2.wait_for_incoming_msg().get_snapshot().text == "message1"

    assert ac1.get_config("configured_mvbox_folder") == "DeltaChat"
    while ac1.get_config("configured_trash_folder") != "Trash":
        ac1.wait_for_event(EventType.CONNECTIVITY_CHANGED)


@pytest.mark.parametrize(
    ("folder", "move", "expected_destination"),
    [
        (
            "xyz",
            False,
            "xyz",
        ),  # Test that emails aren't found in a random folder
        (
            "xyz",
            True,
            "xyz",
        ),  # ...emails are found in a random folder and downloaded without moving
        (
            "Spam",
            False,
            "INBOX",
        ),  # ...emails are moved from the spam folder to the Inbox
    ],
)
# Testrun.org does not support the CREATE-SPECIAL-USE capability, which means that we can't create a folder with
# the "\Junk" flag (see https://tools.ietf.org/html/rfc6154). So, we can't test spam folder detection by flag.
def test_scan_folders(acfactory, log, direct_imap, folder, move, expected_destination):
    """Delta Chat periodically scans all folders for new messages to make sure we don't miss any."""
    variant = folder + "-" + str(move) + "-" + expected_destination
    log.section("Testing variant " + variant)
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.set_config("delete_server_after", "0")
    if move:
        ac1.set_config("mvbox_move", "1")
        ac1.bring_online()

    ac1.stop_io()
    ac1_direct_imap = direct_imap(ac1)
    ac1_direct_imap.create_folder(folder)

    # Wait until each folder was selected once and we are IDLEing:
    ac1.start_io()
    ac1.bring_online()

    ac1.stop_io()
    assert folder in ac1_direct_imap.list_folders()

    log.section("Send a message from ac2 to ac1 and manually move it to `folder`")
    ac1_direct_imap.select_config_folder("inbox")
    with ac1_direct_imap.idle() as idle1:
        acfactory.get_accepted_chat(ac2, ac1).send_text("hello")
        idle1.wait_for_new_message()
    ac1_direct_imap.conn.move(["*"], folder)  # "*" means "biggest UID in mailbox"

    log.section("start_io() and see if DeltaChat finds the message (" + variant + ")")
    ac1.set_config("scan_all_folders_debounce_secs", "0")
    ac1.start_io()
    chat = ac1.create_chat(ac2)
    n_msgs = 1  # "Messages are end-to-end encrypted."
    if folder == "Spam":
        msg = ac1.wait_for_incoming_msg().get_snapshot()
        assert msg.text == "hello"
        n_msgs += 1
    else:
        ac1.wait_for_event(EventType.IMAP_INBOX_IDLE)
    assert len(chat.get_messages()) == n_msgs

    # The message has reached its destination.
    ac1_direct_imap.select_folder(expected_destination)
    assert len(ac1_direct_imap.get_all_messages()) == 1
    if folder != expected_destination:
        ac1_direct_imap.select_folder(folder)
        assert len(ac1_direct_imap.get_all_messages()) == 0


def test_trash_multiple_messages(acfactory, direct_imap, log):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2.stop_io()

    # Create the Trash folder on IMAP server and configure deletion to it. There was a bug that if
    # Trash wasn't configured initially, it can't be configured later, let's check this.
    log.section("Creating trash folder")
    ac2_direct_imap = direct_imap(ac2)
    ac2_direct_imap.create_folder("Trash")
    ac2.set_config("delete_server_after", "0")
    ac2.set_config("sync_msgs", "0")
    ac2.set_config("delete_to_trash", "1")

    log.section("Check that Trash can be configured initially as well")
    ac3 = ac2.clone()
    ac3.bring_online()
    assert ac3.get_config("configured_trash_folder")
    ac3.stop_io()

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
    # ac2 has received some messages, this is impossible w/o the trash folder configured, let's
    # check the configuration.
    assert ac2.get_config("configured_trash_folder") == "Trash"

    log.section("ac2: deleting all messages except second")
    assert len(to_delete) == len(texts) - 1
    ac2.delete_messages(to_delete)

    log.section("ac2: test that only one message is left")
    while 1:
        ac2.wait_for_event(EventType.IMAP_MESSAGE_MOVED)
        ac2_direct_imap.select_config_folder("inbox")
        nr_msgs = len(ac2_direct_imap.get_all_messages())
        assert nr_msgs > 0
        if nr_msgs == 1:
            break
