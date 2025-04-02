from imap_tools import AND

from deltachat_rpc_client import EventType


def test_one_account_send_bcc_setting(acfactory, log, direct_imap):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_clone = ac1.clone()
    ac1_clone.bring_online()

    log.section("send out message without bcc to ourselves")
    ac1.set_config("bcc_self", "0")
    chat = ac1.create_chat(ac2)
    self_addr = ac1.get_config("addr")
    other_addr = ac2.get_config("addr")

    msg_out = chat.send_text("message1")
    assert not msg_out.get_snapshot().is_forwarded

    # wait for send out (no BCC)
    ev = ac1.wait_for_event(EventType.SMTP_MESSAGE_SENT)
    assert ac1.get_config("bcc_self") == "0"

    assert self_addr not in ev.msg
    assert other_addr in ev.msg

    log.section("ac1: setting bcc_self=1")
    ac1.set_config("bcc_self", "1")

    log.section("send out message with bcc to ourselves")
    msg_out = chat.send_text("message2")

    # wait for send out (BCC)
    ev = ac1.wait_for_event(EventType.SMTP_MESSAGE_SENT)
    assert ac1.get_config("bcc_self") == "1"

    # Second client receives only second message, but not the first.
    ev_msg = ac1_clone.wait_for_event(EventType.MSGS_CHANGED)
    assert ac1_clone.get_message_by_id(ev_msg.msg_id).get_snapshot().text == msg_out.get_snapshot().text

    # now make sure we are sending message to ourselves too
    assert self_addr in ev.msg
    assert self_addr in ev.msg

    # BCC-self messages are marked as seen by the sender device.
    while True:
        event = ac1.wait_for_event()
        if event.kind == EventType.INFO and event.msg.endswith("Marked messages 1 in folder INBOX as seen."):
            break

    # Check that the message is marked as seen on IMAP.
    ac1_direct_imap = direct_imap(ac1)
    ac1_direct_imap.connect()
    ac1_direct_imap.select_folder("Inbox")
    assert len(list(ac1_direct_imap.conn.fetch(AND(seen=True)))) == 1
