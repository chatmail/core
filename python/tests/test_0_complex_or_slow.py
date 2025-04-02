import sys
import time

import deltachat as dc


class TestGroupStressTests:
    def test_group_many_members_add_leave_remove(self, acfactory, lp):
        accounts = acfactory.get_online_accounts(5)
        acfactory.introduce_each_other(accounts)
        ac1, ac5 = accounts.pop(), accounts.pop()

        lp.sec("ac1: creating group chat with 3 other members")
        chat = ac1.create_group_chat("title1", contacts=accounts)

        lp.sec("ac1: send message to new group chat")
        msg1 = chat.send_text("hello")
        assert msg1.is_encrypted()
        gossiped_timestamp = chat.get_summary()["gossiped_timestamp"]
        assert gossiped_timestamp > 0

        assert chat.num_contacts() == 3 + 1

        lp.sec("ac2: checking that the chat arrived correctly")
        ac2 = accounts[0]
        msg2 = ac2._evtracker.wait_next_incoming_message()
        assert msg2.text == "hello"
        print("chat is", msg2.chat)
        assert msg2.chat.num_contacts() == 4

        lp.sec("ac3: checking that 'ac4' is a known contact")
        ac3 = accounts[1]
        msg3 = ac3._evtracker.wait_next_incoming_message()
        assert msg3.text == "hello"
        ac3_contacts = ac3.get_contacts()
        assert len(ac3_contacts) == 4
        ac4_contacts = ac3.get_contacts(query=accounts[2].get_config("addr"))
        assert len(ac4_contacts) == 1

        lp.sec("ac2: removing one contact")
        to_remove = ac2.create_contact(accounts[-1])
        msg2.chat.remove_contact(to_remove)

        lp.sec("ac1: receiving system message about contact removal")
        sysmsg = ac1._evtracker.wait_next_incoming_message()
        assert to_remove.addr in sysmsg.text
        assert sysmsg.chat.num_contacts() == 3

        # Receiving message about removed contact does not reset gossip
        assert chat.get_summary()["gossiped_timestamp"] == gossiped_timestamp

        lp.sec("ac1: sending another message to the chat")
        chat.send_text("hello2")
        msg = ac2._evtracker.wait_next_incoming_message()
        assert msg.text == "hello2"
        assert chat.get_summary()["gossiped_timestamp"] == gossiped_timestamp

        lp.sec("ac1: adding fifth member to the chat")
        chat.add_contact(ac5)
        # Adding contact to chat resets gossiped_timestamp
        assert chat.get_summary()["gossiped_timestamp"] >= gossiped_timestamp

        lp.sec("ac2: receiving system message about contact addition")
        sysmsg = ac2._evtracker.wait_next_incoming_message()
        assert ac5.get_config("configured_addr") in sysmsg.text
        assert sysmsg.chat.num_contacts() == 4

        lp.sec("ac5: waiting for message about addition to the chat")
        sysmsg = ac5._evtracker.wait_next_incoming_message()
        msg = sysmsg.chat.send_text("hello!")
        # Message should be encrypted because keys of other members are gossiped
        assert msg.is_encrypted()

    def test_synchronize_member_list_on_group_rejoin(self, acfactory, lp):
        """
        Test that user recreates group member list when it joins the group again.
        ac1 creates a group with two other accounts: ac2 and ac3
        Then it removes ac2, removes ac3 and adds ac2 back.
        ac2 did not see that ac3 is removed, so it should rebuild member list from scratch.
        """
        lp.sec("setting up accounts, accepted with each other")
        accounts = acfactory.get_online_accounts(3)
        acfactory.introduce_each_other(accounts)
        ac1, ac2, ac3 = accounts

        lp.sec("ac1: creating group chat with 2 other members")
        chat = ac1.create_group_chat("title1", contacts=[ac2, ac3])
        assert not chat.is_promoted()

        lp.sec("ac1: send message to new group chat")
        msg = chat.send_text("hello")
        assert chat.is_promoted() and msg.is_encrypted()

        assert chat.num_contacts() == 3

        lp.sec("checking that the chat arrived correctly")
        for ac in accounts[1:]:
            msg = ac._evtracker.wait_next_incoming_message()
            assert msg.text == "hello"
            print("chat is", msg.chat)
            assert msg.chat.num_contacts() == 3

        lp.sec("ac1: removing ac2")
        chat.remove_contact(ac2)

        lp.sec("ac2: wait for a message about removal from the chat")
        msg = ac2._evtracker.wait_next_incoming_message()

        lp.sec("ac1: removing ac3")
        chat.remove_contact(ac3)

        lp.sec("ac1: adding ac2 back")
        # Group is promoted, message is sent automatically
        assert chat.is_promoted()
        chat.add_contact(ac2)

        lp.sec("ac2: check that ac3 is removed")
        msg = ac2._evtracker.wait_next_incoming_message()

        assert chat.num_contacts() == 2
        assert msg.chat.num_contacts() == 2
        acfactory.dump_imap_summary(sys.stdout)


def test_qr_verified_group_and_chatting(acfactory, lp):
    ac1, ac2, ac3 = acfactory.get_online_accounts(3)
    ac1_addr = ac1.get_self_contact().addr
    lp.sec("ac1: create verified-group QR, ac2 scans and joins")
    chat1 = ac1.create_group_chat("hello", verified=True)
    assert chat1.is_protected()
    qr = chat1.get_join_qr()
    lp.sec("ac2: start QR-code based join-group protocol")
    chat2 = ac2.qr_join_chat(qr)
    assert chat2.id >= 10
    ac1._evtracker.wait_securejoin_inviter_progress(1000)

    lp.sec("ac2: read member added message")
    msg = ac2._evtracker.wait_next_incoming_message()
    assert msg.is_encrypted()
    assert msg.is_system_message()
    assert "added" in msg.text.lower()

    assert any(
        m.is_system_message() and m.text == "Messages are guaranteed to be end-to-end encrypted from now on."
        for m in msg.chat.get_messages()
    )
    lp.sec("ac1: send message")
    msg_out = chat1.send_text("hello")
    assert msg_out.is_encrypted()

    lp.sec("ac2: read message and check that it's a verified chat")
    msg = ac2._evtracker.wait_next_incoming_message()
    assert msg.text == "hello"
    assert msg.chat.is_protected()
    assert msg.is_encrypted()

    lp.sec("ac2: Check that ac2 verified ac1")
    ac2_ac1_contact = ac2.get_contacts()[0]
    assert ac2.get_self_contact().get_verifier(ac2_ac1_contact).id == dc.const.DC_CONTACT_ID_SELF

    lp.sec("ac2: send message and let ac1 read it")
    chat2.send_text("world")
    msg = ac1._evtracker.wait_next_incoming_message()
    assert msg.text == "world"
    assert msg.is_encrypted()

    lp.sec("ac1: create QR code and let ac3 scan it, starting the securejoin")
    qr = ac1.get_setup_contact_qr()

    lp.sec("ac3: start QR-code based setup contact protocol")
    ch = ac3.qr_setup_contact(qr)
    assert ch.id >= 10
    ac1._evtracker.wait_securejoin_inviter_progress(1000)

    lp.sec("ac1: add ac3 to verified group")
    chat1.add_contact(ac3)
    msg = ac2._evtracker.wait_next_incoming_message()
    assert msg.is_encrypted()
    assert msg.is_system_message()
    assert not msg.error

    lp.sec("ac2: Check that ac1 verified ac3 for ac2")
    ac2_ac1_contact = ac2.get_contacts()[0]
    assert ac2.get_self_contact().get_verifier(ac2_ac1_contact).id == dc.const.DC_CONTACT_ID_SELF
    ac2_ac3_contact = ac2.get_contacts()[1]
    assert ac2.get_self_contact().get_verifier(ac2_ac3_contact).addr == ac1_addr

    lp.sec("ac2: send message and let ac3 read it")
    chat2.send_text("hi")
    # System message about the added member.
    msg = ac3._evtracker.wait_next_incoming_message()
    assert msg.is_system_message()
    msg = ac3._evtracker.wait_next_incoming_message()
    assert msg.text == "hi"
    assert msg.is_encrypted()


def test_undecipherable_group(acfactory, lp):
    """Test how group messages that cannot be decrypted are
    handled.

    Group name is encrypted and plaintext subject is set to "..." in
    this case, so we should assign the messages to existing chat
    instead of creating a new one. Since there is no existing group
    chat, the messages should be assigned to 1-1 chat with the sender
    of the message.
    """

    lp.sec("creating and configuring three accounts")
    ac1, ac2, ac3 = acfactory.get_online_accounts(3)

    acfactory.introduce_each_other([ac1, ac2, ac3])

    lp.sec("ac3 reinstalls DC and generates a new key")
    ac3.stop_io()
    acfactory.remove_preconfigured_keys()
    ac4 = acfactory.new_online_configuring_account(cloned_from=ac3)
    acfactory.wait_configured(ac4)
    # Create contacts to make sure incoming messages are not treated as contact requests
    chat41 = ac4.create_chat(ac1)
    chat42 = ac4.create_chat(ac2)
    ac4.start_io()
    ac4._evtracker.wait_idle_inbox_ready()

    lp.sec("ac1: creating group chat with 2 other members")
    chat = ac1.create_group_chat("title", contacts=[ac2, ac3])

    lp.sec("ac1: send message to new group chat")
    msg = chat.send_text("hello")

    lp.sec("ac2: checking that the chat arrived correctly")
    msg = ac2._evtracker.wait_next_incoming_message()
    assert msg.text == "hello"
    assert msg.is_encrypted(), "Message is not encrypted"

    # ac4 cannot decrypt the message.
    # Error message should be assigned to the chat with ac1.
    lp.sec("ac4: checking that message is assigned to the sender chat")
    error_msg = ac4._evtracker.wait_next_incoming_message()
    assert error_msg.error  # There is an error decrypting the message
    assert error_msg.chat == chat41

    lp.sec("ac2: sending a reply to the chat")
    msg.chat.send_text("reply")
    reply = ac1._evtracker.wait_next_incoming_message()
    assert reply.text == "reply"
    assert reply.is_encrypted(), "Reply is not encrypted"

    lp.sec("ac4: checking that reply is assigned to ac2 chat")
    error_reply = ac4._evtracker.wait_next_incoming_message()
    assert error_reply.error  # There is an error decrypting the message
    assert error_reply.chat == chat42

    # Test that ac4 replies to error messages don't appear in the
    # group chat on ac1 and ac2.
    lp.sec("ac4: replying to ac1 and ac2")

    # Otherwise reply becomes a contact request.
    chat41.send_text("I can't decrypt your message, ac1!")
    chat42.send_text("I can't decrypt your message, ac2!")

    msg = ac1._evtracker.wait_next_incoming_message()
    assert msg.error is None
    assert msg.text == "I can't decrypt your message, ac1!"
    assert msg.is_encrypted(), "Message is not encrypted"
    assert msg.chat == ac1.create_chat(ac3)

    msg = ac2._evtracker.wait_next_incoming_message()
    assert msg.error is None
    assert msg.text == "I can't decrypt your message, ac2!"
    assert msg.is_encrypted(), "Message is not encrypted"
    assert msg.chat == ac2.create_chat(ac4)


def test_ephemeral_timer(acfactory, lp):
    ac1, ac2 = acfactory.get_online_accounts(2)

    lp.sec("ac1: create chat with ac2")
    chat1 = ac1.create_chat(ac2)
    chat2 = ac2.create_chat(ac1)

    lp.sec("ac1: set ephemeral timer to 60")
    chat1.set_ephemeral_timer(60)

    lp.sec("ac1: check that ephemeral timer is set for chat")
    assert chat1.get_ephemeral_timer() == 60
    chat1_summary = chat1.get_summary()
    assert chat1_summary["ephemeral_timer"] == {"Enabled": {"duration": 60}}

    lp.sec("ac2: receive system message about ephemeral timer modification")
    ac2._evtracker.get_matching("DC_EVENT_CHAT_EPHEMERAL_TIMER_MODIFIED")
    system_message1 = ac2._evtracker.wait_next_incoming_message()
    assert chat2.get_ephemeral_timer() == 60
    assert system_message1.is_system_message()

    # Disabled until markers are implemented
    # assert "Ephemeral timer: 60\n" in system_message1.get_message_info()

    lp.sec("ac2: send message to ac1")
    sent_message = chat2.send_text("message")
    assert sent_message.ephemeral_timer == 60
    assert "Ephemeral timer: 60\n" in sent_message.get_message_info()

    # Timer is started immediately for sent messages
    assert sent_message.ephemeral_timestamp is not None
    assert "Expires: " in sent_message.get_message_info()

    lp.sec("ac1: waiting for message from ac2")
    text_message = ac1._evtracker.wait_next_incoming_message()
    assert text_message.text == "message"
    assert text_message.ephemeral_timer == 60
    assert "Ephemeral timer: 60\n" in text_message.get_message_info()

    # Timer should not start until message is displayed
    assert text_message.ephemeral_timestamp is None
    assert "Expires: " not in text_message.get_message_info()
    text_message.mark_seen()
    text_message = ac1.get_message_by_id(text_message.id)
    assert text_message.ephemeral_timestamp is not None
    assert "Expires: " in text_message.get_message_info()

    lp.sec("ac2: set ephemeral timer to 0")
    chat2.set_ephemeral_timer(0)
    ac2._evtracker.get_matching("DC_EVENT_CHAT_EPHEMERAL_TIMER_MODIFIED")

    lp.sec("ac1: receive system message about ephemeral timer modification")
    ac1._evtracker.get_matching("DC_EVENT_CHAT_EPHEMERAL_TIMER_MODIFIED")
    system_message2 = ac1._evtracker.wait_next_incoming_message()
    assert system_message2.ephemeral_timer is None
    assert "Ephemeral timer: " not in system_message2.get_message_info()
    assert chat1.get_ephemeral_timer() == 0


def test_see_new_verified_member_after_going_online(acfactory, tmp_path, lp):
    """The test for the bug #3836:
    - Alice has two devices, the second is offline.
    - Alice creates a verified group and sends a QR invitation to Bob.
    - Bob joins the group and sends a message there. Alice sees it.
    - Alice's second devices goes online, but doesn't see Bob in the group.
    """
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac2_addr = ac2.get_config("addr")
    acfactory.remove_preconfigured_keys()
    ac1_offl = acfactory.new_online_configuring_account(cloned_from=ac1)
    for ac in [ac1, ac1_offl]:
        ac.set_config("bcc_self", "1")
    acfactory.bring_accounts_online()
    dir = tmp_path / "exportdir"
    dir.mkdir()
    ac1.export_self_keys(str(dir))
    ac1_offl.import_self_keys(str(dir))
    ac1_offl.stop_io()

    lp.sec("ac1: create verified-group QR, ac2 scans and joins")
    chat = ac1.create_group_chat("hello", verified=True)
    assert chat.is_protected()
    qr = chat.get_join_qr()
    lp.sec("ac2: start QR-code based join-group protocol")
    chat2 = ac2.qr_join_chat(qr)
    ac1._evtracker.wait_securejoin_inviter_progress(1000)

    lp.sec("ac2: sending message")
    # Message can be sent only after a receipt of "vg-member-added" message. Just wait for
    # "Member Me (<addr>) added by <addr>." message.
    msg_in = ac2._evtracker.wait_next_incoming_message()
    assert msg_in.is_system_message()
    msg_out = chat2.send_text("hello")

    lp.sec("ac1: receiving message")
    msg_in = ac1._evtracker.wait_next_incoming_message()
    assert msg_in.text == msg_out.text
    assert msg_in.get_sender_contact().addr == ac2_addr

    lp.sec("ac1_offl: going online, receiving message")
    ac1_offl.start_io()
    ac1_offl._evtracker.wait_securejoin_inviter_progress(1000)
    msg_in = ac1_offl._evtracker.wait_next_incoming_message()
    assert msg_in.text == msg_out.text
    assert msg_in.get_sender_contact().addr == ac2_addr


def test_use_new_verified_group_after_going_online(acfactory, data, tmp_path, lp):
    """Another test for the bug #3836:
    - Bob has two devices, the second is offline.
    - Alice creates a verified group and sends a QR invitation to Bob.
    - Bob joins the group.
    - Bob's second devices goes online, but sees a contact request instead of the verified group.
    - The "member added" message is not a system message but a plain text message.
    - Bob's second device doesn't display the Alice's avatar (bug #5354).
    - Sending a message fails as the key is missing -- message info says "proper enc-key for <Alice>
      missing, cannot encrypt".
    """
    ac1, ac2 = acfactory.get_online_accounts(2)
    acfactory.remove_preconfigured_keys()
    ac2_offl = acfactory.new_online_configuring_account(cloned_from=ac2)
    for ac in [ac2, ac2_offl]:
        ac.set_config("bcc_self", "1")
    acfactory.bring_accounts_online()
    dir = tmp_path / "exportdir"
    dir.mkdir()
    ac2.export_self_keys(str(dir))
    ac2_offl.import_self_keys(str(dir))
    ac2_offl.stop_io()

    lp.sec("ac1: set avatar")
    avatar_path = data.get_path("d.png")
    ac1.set_avatar(avatar_path)

    lp.sec("ac1: create verified-group QR, ac2 scans and joins")
    chat = ac1.create_group_chat("hello", verified=True)
    assert chat.is_protected()
    qr = chat.get_join_qr()
    lp.sec("ac2: start QR-code based join-group protocol")
    ac2.qr_join_chat(qr)
    ac1._evtracker.wait_securejoin_inviter_progress(1000)

    lp.sec("ac2_offl: going online, checking the 'member added' message")
    ac2_offl.start_io()
    # Receive "Member Me (<addr>) added by <addr>." message.
    msg_in = ac2_offl._evtracker.wait_next_incoming_message()
    contact = msg_in.get_sender_contact()
    assert msg_in.is_system_message()
    assert contact.addr == ac1.get_config("addr")
    chat2 = msg_in.chat
    assert chat2.is_protected()
    assert chat2.get_messages()[0].text == "Messages are guaranteed to be end-to-end encrypted from now on."
    assert open(contact.get_profile_image(), "rb").read() == open(avatar_path, "rb").read()

    lp.sec("ac2_offl: sending message")
    msg_out = chat2.send_text("hello")

    lp.sec("ac1: receiving message")
    msg_in = ac1._evtracker.wait_next_incoming_message()
    assert msg_in.chat == chat
    assert msg_in.get_sender_contact().addr == ac2.get_config("addr")
    assert msg_in.text == msg_out.text


def test_verified_group_vs_delete_server_after(acfactory, tmp_path, lp):
    """Test for the issue #4346:
    - User is added to a verified group.
    - First device of the user downloads "member added" from the group.
    - First device removes "member added" from the server.
    - Some new messages are sent to the group.
    - Second device comes online, receives these new messages. The result is a verified group with unverified members.
    - First device re-gossips Autocrypt keys to the group.
    - Now the seconds device has all members verified.
    """
    ac1, ac2 = acfactory.get_online_accounts(2)
    acfactory.remove_preconfigured_keys()
    ac2_offl = acfactory.new_online_configuring_account(cloned_from=ac2)
    for ac in [ac2, ac2_offl]:
        ac.set_config("bcc_self", "1")
    ac2.set_config("delete_server_after", "1")
    ac2.set_config("gossip_period", "0")  # Re-gossip in every message
    acfactory.bring_accounts_online()
    dir = tmp_path / "exportdir"
    dir.mkdir()
    ac2.export_self_keys(str(dir))
    ac2_offl.import_self_keys(str(dir))
    ac2_offl.stop_io()

    lp.sec("ac1: create verified-group QR, ac2 scans and joins")
    chat1 = ac1.create_group_chat("hello", verified=True)
    assert chat1.is_protected()
    qr = chat1.get_join_qr()
    lp.sec("ac2: start QR-code based join-group protocol")
    chat2 = ac2.qr_join_chat(qr)
    ac1._evtracker.wait_securejoin_inviter_progress(1000)
    # Wait for "Member Me (<addr>) added by <addr>." message.
    msg_in = ac2._evtracker.wait_next_incoming_message()
    assert msg_in.is_system_message()

    lp.sec("ac2: waiting for 'member added' to be deleted on the server")
    ac2._evtracker.get_matching("DC_EVENT_IMAP_MESSAGE_DELETED")

    lp.sec("ac1: sending 'hi' to the group")
    ac2.set_config("delete_server_after", "0")
    chat1.send_text("hi")

    lp.sec("ac2_offl: going online, checking the 'hi' message")
    ac2_offl.start_io()
    msg_in = ac2_offl._evtracker.wait_next_incoming_message()
    assert not msg_in.is_system_message()
    assert msg_in.text.startswith("[The message was sent with non-verified encryption")
    ac2_offl_ac1_contact = msg_in.get_sender_contact()
    assert ac2_offl_ac1_contact.addr == ac1.get_config("addr")
    assert not ac2_offl_ac1_contact.is_verified()
    chat2_offl = msg_in.chat
    assert chat2_offl.is_protected()

    lp.sec("ac2: sending message re-gossiping Autocrypt keys")
    chat2.send_text("hi2")

    lp.sec("ac2_offl: receiving message")
    ev = ac2_offl._evtracker.get_matching("DC_EVENT_INCOMING_MSG|DC_EVENT_MSGS_CHANGED")
    msg_in = ac2_offl.get_message_by_id(ev.data2)
    assert msg_in.is_system_message()
    assert msg_in.text == "Messages are guaranteed to be end-to-end encrypted from now on."

    # We need to consume one event that has data2=0
    ev = ac2_offl._evtracker.get_matching("DC_EVENT_INCOMING_MSG|DC_EVENT_MSGS_CHANGED")
    assert ev.data2 == 0

    ev = ac2_offl._evtracker.get_matching("DC_EVENT_INCOMING_MSG|DC_EVENT_MSGS_CHANGED")
    msg_in = ac2_offl.get_message_by_id(ev.data2)
    assert not msg_in.is_system_message()
    assert msg_in.text == "hi2"
    assert msg_in.chat == chat2_offl
    assert msg_in.get_sender_contact().addr == ac2.get_config("addr")
    assert ac2_offl_ac1_contact.is_verified()


def test_deleted_msgs_dont_reappear(acfactory):
    ac1 = acfactory.new_online_configuring_account()
    acfactory.bring_accounts_online()
    ac1.set_config("bcc_self", "1")
    chat = ac1.get_self_contact().create_chat()
    msg = chat.send_text("hello")
    ac1._evtracker.get_matching("DC_EVENT_SMTP_MESSAGE_SENT")
    ac1.delete_messages([msg])
    ac1._evtracker.get_matching("DC_EVENT_MSG_DELETED")
    ac1._evtracker.get_matching("DC_EVENT_IMAP_MESSAGE_DELETED")
    time.sleep(5)
    assert len(chat.get_messages()) == 0
