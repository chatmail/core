import logging
import time

import pytest

from deltachat_rpc_client import Chat, EventType, SpecialContactId
from deltachat_rpc_client.rpc import JsonRpcError


def test_qr_setup_contact(acfactory, tmp_path) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    qr_code = alice.get_qr_code()
    bob.secure_join(qr_code)

    alice.wait_for_securejoin_inviter_success()

    # Test that Alice verified Bob's profile.
    alice_contact_bob = alice.get_contact_by_addr(bob.get_config("addr"))
    alice_contact_bob_snapshot = alice_contact_bob.get_snapshot()
    assert alice_contact_bob_snapshot.is_verified

    bob.wait_for_securejoin_joiner_success()

    # Test that Bob verified Alice's profile.
    bob_contact_alice = bob.get_contact_by_addr(alice.get_config("addr"))
    bob_contact_alice_snapshot = bob_contact_alice.get_snapshot()
    assert bob_contact_alice_snapshot.is_verified

    # Test that if Bob imports a key,
    # backwards verification is not lost
    # because default key is not changed.
    logging.info("Bob 2 is created")
    bob2 = acfactory.new_configured_account()
    bob2.export_self_keys(tmp_path)

    logging.info("Bob tries to import a key")
    # Importing a second key is not allowed.
    with pytest.raises(JsonRpcError):
        bob.import_self_keys(tmp_path)

    assert bob.get_config("key_id") == "1"
    bob_contact_alice_snapshot = bob_contact_alice.get_snapshot()
    assert bob_contact_alice_snapshot.is_verified


def test_qr_setup_contact_svg(acfactory) -> None:
    alice = acfactory.new_configured_account()
    _, _, domain = alice.get_config("addr").rpartition("@")

    _qr_code, svg = alice.get_qr_code_svg()

    alice.set_config("displayname", "Alice")

    # Test that display name is used
    # in SVG and no address is visible.
    _qr_code, svg = alice.get_qr_code_svg()
    assert domain not in svg
    assert "Alice" in svg


@pytest.mark.parametrize("protect", [True, False])
def test_qr_securejoin(acfactory, protect):
    alice, bob, fiona = acfactory.get_online_accounts(3)

    # Setup second device for Alice
    # to test observing securejoin protocol.
    alice2 = alice.clone()

    logging.info("Alice creates a group")
    alice_chat = alice.create_group("Group", protect=protect)
    assert alice_chat.get_basic_snapshot().is_protected == protect

    logging.info("Bob joins the group")
    qr_code = alice_chat.get_qr_code()
    bob.secure_join(qr_code)

    # Alice deletes "vg-request".
    alice.wait_for_event(EventType.IMAP_MESSAGE_DELETED)
    alice.wait_for_securejoin_inviter_success()
    # Bob deletes "vg-auth-required", Alice deletes "vg-request-with-auth".
    for ac in [alice, bob]:
        ac.wait_for_event(EventType.IMAP_MESSAGE_DELETED)
    bob.wait_for_securejoin_joiner_success()

    # Test that Alice verified Bob's profile.
    alice_contact_bob = alice.get_contact_by_addr(bob.get_config("addr"))
    alice_contact_bob_snapshot = alice_contact_bob.get_snapshot()
    assert alice_contact_bob_snapshot.is_verified

    snapshot = bob.get_message_by_id(bob.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Member Me added by {}.".format(alice.get_config("addr"))
    assert snapshot.chat.get_basic_snapshot().is_protected == protect

    # Test that Bob verified Alice's profile.
    bob_contact_alice = bob.get_contact_by_addr(alice.get_config("addr"))
    bob_contact_alice_snapshot = bob_contact_alice.get_snapshot()
    assert bob_contact_alice_snapshot.is_verified

    # Start second Alice device.
    # Alice observes securejoin protocol and verifies Bob on second device.
    alice2.start_io()
    alice2.wait_for_securejoin_inviter_success()
    alice2_contact_bob = alice2.get_contact_by_addr(bob.get_config("addr"))
    alice2_contact_bob_snapshot = alice2_contact_bob.get_snapshot()
    assert alice2_contact_bob_snapshot.is_verified

    # The QR code token is synced, so alice2 must be able to handle join requests.
    logging.info("Fiona joins the group via alice2")
    alice.stop_io()
    fiona.secure_join(qr_code)
    alice2.wait_for_securejoin_inviter_success()
    fiona.wait_for_securejoin_joiner_success()


def test_qr_securejoin_contact_request(acfactory) -> None:
    """Alice invites Bob to a group when Bob's chat with Alice is in a contact request mode."""
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_text("Hello!")

    snapshot = bob.get_message_by_id(bob.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Hello!"
    bob_chat_alice = snapshot.chat
    assert bob_chat_alice.get_basic_snapshot().is_contact_request

    alice_chat = alice.create_group("Verified group", protect=True)
    logging.info("Bob joins verified group")
    qr_code = alice_chat.get_qr_code()
    bob.secure_join(qr_code)
    while True:
        event = bob.wait_for_event()
        if event["kind"] == "SecurejoinJoinerProgress" and event["progress"] == 1000:
            break

    # Chat stays being a contact request.
    assert bob_chat_alice.get_basic_snapshot().is_contact_request


def test_qr_readreceipt(acfactory) -> None:
    alice, bob, charlie = acfactory.get_online_accounts(3)

    logging.info("Bob and Charlie setup contact with Alice")
    qr_code = alice.get_qr_code()

    bob.secure_join(qr_code)
    charlie.secure_join(qr_code)

    for joiner in [bob, charlie]:
        joiner.wait_for_securejoin_joiner_success()

    logging.info("Alice creates a verified group")
    group = alice.create_group("Group", protect=True)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_contact_charlie = alice.create_contact(charlie, "Charlie")

    group.add_contact(alice_contact_bob)
    group.add_contact(alice_contact_charlie)

    # Promote a group.
    group.send_message(text="Hello")

    logging.info("Bob and Charlie receive a group")

    bob_msg_id = bob.wait_for_incoming_msg_event().msg_id
    bob_message = bob.get_message_by_id(bob_msg_id)
    bob_snapshot = bob_message.get_snapshot()
    assert bob_snapshot.text == "Hello"

    # Charlie receives the same "Hello" message as Bob.
    charlie.wait_for_incoming_msg_event()

    logging.info("Bob sends a message to the group")

    bob_out_message = bob_snapshot.chat.send_message(text="Hi from Bob!")

    charlie_msg_id = charlie.wait_for_incoming_msg_event().msg_id
    charlie_message = charlie.get_message_by_id(charlie_msg_id)
    charlie_snapshot = charlie_message.get_snapshot()
    assert charlie_snapshot.text == "Hi from Bob!"

    bob_contact_charlie = bob.create_contact(charlie, "Charlie")
    assert not bob.get_chat_by_contact(bob_contact_charlie)

    logging.info("Charlie reads Bob's message")
    charlie_message.mark_seen()

    while True:
        event = bob.wait_for_event()
        if event["kind"] == "MsgRead" and event["msg_id"] == bob_out_message.id:
            break

    # Receiving a read receipt from Charlie
    # should not unblock hidden chat with Charlie for Bob.
    assert not bob.get_chat_by_contact(bob_contact_charlie)


def test_setup_contact_resetup(acfactory) -> None:
    """Tests that setup contact works after Alice resets the device and changes the key."""
    alice, bob = acfactory.get_online_accounts(2)

    qr_code = alice.get_qr_code()
    bob.secure_join(qr_code)
    bob.wait_for_securejoin_joiner_success()

    alice = acfactory.resetup_account(alice)

    qr_code = alice.get_qr_code()
    bob.secure_join(qr_code)
    bob.wait_for_securejoin_joiner_success()


def test_verified_group_recovery(acfactory) -> None:
    """Tests verified group recovery by reverifying a member and sending a message in a group."""
    ac1, ac2, ac3 = acfactory.get_online_accounts(3)

    logging.info("ac1 creates verified group")
    chat = ac1.create_group("Verified group", protect=True)
    assert chat.get_basic_snapshot().is_protected

    logging.info("ac2 joins verified group")
    qr_code = chat.get_qr_code()
    ac2.secure_join(qr_code)
    ac2.wait_for_securejoin_joiner_success()

    # ac1 has ac2 directly verified.
    ac1_contact_ac2 = ac1.get_contact_by_addr(ac2.get_config("addr"))
    assert ac1_contact_ac2.get_snapshot().verifier_id == SpecialContactId.SELF

    logging.info("ac3 joins verified group")
    ac3_chat = ac3.secure_join(qr_code)
    ac3.wait_for_securejoin_joiner_success()
    ac3.wait_for_incoming_msg_event()  # Member added

    logging.info("ac2 logs in on a new device")
    ac2 = acfactory.resetup_account(ac2)

    logging.info("ac2 reverifies with ac3")
    qr_code = ac3.get_qr_code()
    ac2.secure_join(qr_code)
    ac2.wait_for_securejoin_joiner_success()

    logging.info("ac3 sends a message to the group")
    assert len(ac3_chat.get_contacts()) == 3
    ac3_chat.send_text("Hi!")

    snapshot = ac1.get_message_by_id(ac1.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Hi!"

    msg_id = ac2.wait_for_incoming_msg_event().msg_id
    message = ac2.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.text == "Hi!"

    # ac1 contact is verified for ac2 because ac3 gossiped ac1 key in the "Hi!" message.
    ac1_contact = ac2.get_contact_by_addr(ac1.get_config("addr"))
    assert ac1_contact.get_snapshot().is_verified

    # ac2 can write messages to the group.
    snapshot.chat.send_text("Works again!")

    snapshot = ac3.get_message_by_id(ac3.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Works again!"

    snapshot = ac1.get_message_by_id(ac1.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Works again!"

    ac1_chat_messages = snapshot.chat.get_messages()
    ac2_addr = ac2.get_config("addr")
    assert ac1_chat_messages[-2].get_snapshot().text == f"Changed setup for {ac2_addr}"

    # ac2 is now verified by ac3 for ac1
    ac1_contact_ac3 = ac1.get_contact_by_addr(ac3.get_config("addr"))
    assert ac1_contact_ac2.get_snapshot().verifier_id == ac1_contact_ac3.id


def test_verified_group_member_added_recovery(acfactory) -> None:
    """Tests verified group recovery by reverifiying than removing and adding a member back."""
    ac1, ac2, ac3 = acfactory.get_online_accounts(3)

    logging.info("ac1 creates verified group")
    chat = ac1.create_group("Verified group", protect=True)
    assert chat.get_basic_snapshot().is_protected

    logging.info("ac2 joins verified group")
    qr_code = chat.get_qr_code()
    ac2.secure_join(qr_code)
    ac2.wait_for_securejoin_joiner_success()

    # ac1 has ac2 directly verified.
    ac1_contact_ac2 = ac1.get_contact_by_addr(ac2.get_config("addr"))
    assert ac1_contact_ac2.get_snapshot().verifier_id == SpecialContactId.SELF

    logging.info("ac3 joins verified group")
    ac3_chat = ac3.secure_join(qr_code)
    ac3.wait_for_securejoin_joiner_success()
    ac3.wait_for_incoming_msg_event()  # Member added

    logging.info("ac2 logs in on a new device")
    ac2 = acfactory.resetup_account(ac2)

    logging.info("ac2 reverifies with ac3")
    qr_code = ac3.get_qr_code()
    ac2.secure_join(qr_code)
    ac2.wait_for_securejoin_joiner_success()

    logging.info("ac3 sends a message to the group")
    assert len(ac3_chat.get_contacts()) == 3
    ac3_chat.send_text("Hi!")

    msg_id = ac2.wait_for_incoming_msg_event().msg_id
    message = ac2.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    logging.info("Received message %s", snapshot.text)
    assert snapshot.text == "Hi!"

    ac1.wait_for_incoming_msg_event()  # Hi!

    ac3_contact_ac2 = ac3.get_contact_by_addr(ac2.get_config("addr"))
    ac3_chat.remove_contact(ac3_contact_ac2)

    msg_id = ac2.wait_for_incoming_msg_event().msg_id
    message = ac2.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert "removed" in snapshot.text

    snapshot = ac1.get_message_by_id(ac1.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert "removed" in snapshot.text

    ac3_chat.add_contact(ac3_contact_ac2)

    event = ac2.wait_for_incoming_msg_event()
    msg_id = event.msg_id
    chat_id = event.chat_id
    message = ac2.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    logging.info("ac2 got event message: %s", snapshot.text)
    assert "added" in snapshot.text

    snapshot = ac1.get_message_by_id(ac1.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert "added" in snapshot.text

    chat = Chat(ac2, chat_id)
    chat.send_text("Works again!")

    msg_id = ac3.wait_for_incoming_msg_event().msg_id
    message = ac3.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.text == "Works again!"

    snapshot = ac1.get_message_by_id(ac1.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Works again!"

    ac1_contact_ac2 = ac1.get_contact_by_addr(ac2.get_config("addr"))
    ac1_contact_ac2_snapshot = ac1_contact_ac2.get_snapshot()
    assert ac1_contact_ac2_snapshot.is_verified
    assert ac1_contact_ac2_snapshot.verifier_id == ac1.get_contact_by_addr(ac3.get_config("addr")).id

    # ac2 is now verified by ac3 for ac1
    ac1_contact_ac3 = ac1.get_contact_by_addr(ac3.get_config("addr"))
    assert ac1_contact_ac2.get_snapshot().verifier_id == ac1_contact_ac3.id


def test_qr_join_chat_with_pending_bobstate_issue4894(acfactory):
    """Regression test for
    issue <https://github.com/deltachat/deltachat-core-rust/issues/4894>.
    """
    ac1, ac2, ac3, ac4 = acfactory.get_online_accounts(4)

    logging.info("ac3: verify with ac2")
    qr_code = ac2.get_qr_code()
    ac3.secure_join(qr_code)
    ac2.wait_for_securejoin_inviter_success()

    # in order for ac2 to have pending bobstate with a verified group
    # we first create a fully joined verified group, and then start
    # joining a second time but interrupt it, to create pending bob state

    logging.info("ac1: create verified group that ac2 fully joins")
    ch1 = ac1.create_group("Group", protect=True)
    qr_code = ch1.get_qr_code()
    ac2.secure_join(qr_code)
    ac1.wait_for_securejoin_inviter_success()

    # ensure ac1 can write and ac2 receives messages in verified chat
    ch1.send_text("ac1 says hello")
    while 1:
        snapshot = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id).get_snapshot()
        if snapshot.text == "ac1 says hello":
            assert snapshot.chat.get_basic_snapshot().is_protected
            break

    logging.info("ac1: let ac2 join again but shutoff ac1 in the middle of securejoin")
    qr_code = ch1.get_qr_code()
    ac2.secure_join(qr_code)
    ac1.remove()
    logging.info("ac2 now has pending bobstate but ac1 is shutoff")

    # we meanwhile expect ac3/ac2 verification started in the beginning to have completed
    assert ac3.get_contact_by_addr(ac2.get_config("addr")).get_snapshot().is_verified
    assert ac2.get_contact_by_addr(ac3.get_config("addr")).get_snapshot().is_verified

    logging.info("ac3: create a verified group VG with ac2")
    vg = ac3.create_group("ac3-created", protect=True)
    vg.add_contact(ac3.get_contact_by_addr(ac2.get_config("addr")))

    # ensure ac2 receives message in VG
    vg.send_text("hello")
    while 1:
        msg = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id).get_snapshot()
        if msg.text == "hello":
            assert msg.chat.get_basic_snapshot().is_protected
            break

    logging.info("ac3: create a join-code for group VG and let ac4 join, check that ac2 got it")
    qr_code = vg.get_qr_code()
    ac4.secure_join(qr_code)
    ac3.wait_for_securejoin_inviter_success()
    while 1:
        ev = ac2.wait_for_event()
        if "added by unrelated SecureJoin" in str(ev):
            return


def test_qr_new_group_unblocked(acfactory):
    """Regression test for a bug introduced in core v1.113.0.
    ac2 scans a verified group QR code created by ac1.
    This results in creation of a blocked 1:1 chat with ac1 on ac2,
    but ac1 contact is not blocked on ac2.
    Then ac1 creates a group, adds ac2 there and promotes it by sending a message.
    ac2 should receive a message and create a contact request for the group.
    Due to a bug previously ac2 created a blocked group.
    """

    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_chat = ac1.create_group("Group for joining", protect=True)
    qr_code = ac1_chat.get_qr_code()
    ac2.secure_join(qr_code)

    ac1.wait_for_securejoin_inviter_success()

    ac1_new_chat = ac1.create_group("Another group")
    ac1_new_chat.add_contact(ac1.get_contact_by_addr(ac2.get_config("addr")))
    # Receive "Member added" message.
    ac2.wait_for_incoming_msg_event()

    ac1_new_chat.send_text("Hello!")
    ac2_msg = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert ac2_msg.text == "Hello!"
    assert ac2_msg.chat.get_basic_snapshot().is_contact_request


@pytest.mark.skip(reason="AEAP is disabled for now")
def test_aeap_flow_verified(acfactory):
    """Test that a new address is added to a contact when it changes its address."""
    ac1, ac2 = acfactory.get_online_accounts(2)

    addr, password = acfactory.get_credentials()

    logging.info("ac1: create verified-group QR, ac2 scans and joins")
    chat = ac1.create_group("hello", protect=True)
    assert chat.get_basic_snapshot().is_protected
    qr_code = chat.get_qr_code()
    logging.info("ac2: start QR-code based join-group protocol")
    ac2.secure_join(qr_code)
    ac1.wait_for_securejoin_inviter_success()
    ac2.wait_for_securejoin_joiner_success()

    logging.info("sending first message")
    msg_out = chat.send_text("old address").get_snapshot()

    logging.info("receiving first message")
    ac2.wait_for_incoming_msg_event()  # member added message
    msg_in_1 = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert msg_in_1.text == msg_out.text

    logging.info("changing email account")
    ac1.set_config("addr", addr)
    ac1.set_config("mail_pw", password)
    ac1.stop_io()
    ac1.configure()
    ac1.start_io()

    logging.info("sending second message")
    msg_out = chat.send_text("changed address").get_snapshot()

    logging.info("receiving second message")
    msg_in_2 = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id)
    msg_in_2_snapshot = msg_in_2.get_snapshot()
    assert msg_in_2_snapshot.text == msg_out.text
    assert msg_in_2_snapshot.chat.id == msg_in_1.chat.id
    assert msg_in_2.get_sender_contact().get_snapshot().address == addr
    assert len(msg_in_2_snapshot.chat.get_contacts()) == 2
    assert addr in [contact.get_snapshot().address for contact in msg_in_2_snapshot.chat.get_contacts()]


def test_gossip_verification(acfactory) -> None:
    alice, bob, carol = acfactory.get_online_accounts(3)

    # Bob verifies Alice.
    qr_code = alice.get_qr_code()
    bob.secure_join(qr_code)
    bob.wait_for_securejoin_joiner_success()

    # Bob verifies Carol.
    qr_code = carol.get_qr_code()
    bob.secure_join(qr_code)
    bob.wait_for_securejoin_joiner_success()

    bob_contact_alice = bob.create_contact(alice, "Alice")
    bob_contact_carol = bob.create_contact(carol, "Carol")
    carol_contact_alice = carol.create_contact(alice, "Alice")

    logging.info("Bob creates an Autocrypt group")
    bob_group_chat = bob.create_group("Autocrypt Group")
    assert not bob_group_chat.get_basic_snapshot().is_protected
    bob_group_chat.add_contact(bob_contact_alice)
    bob_group_chat.add_contact(bob_contact_carol)
    bob_group_chat.send_message(text="Hello Autocrypt group")

    snapshot = carol.get_message_by_id(carol.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Hello Autocrypt group"
    assert snapshot.show_padlock

    # Autocrypt group does not propagate verification.
    carol_contact_alice_snapshot = carol_contact_alice.get_snapshot()
    assert not carol_contact_alice_snapshot.is_verified

    logging.info("Bob creates a Securejoin group")
    bob_group_chat = bob.create_group("Securejoin Group", protect=True)
    assert bob_group_chat.get_basic_snapshot().is_protected
    bob_group_chat.add_contact(bob_contact_alice)
    bob_group_chat.add_contact(bob_contact_carol)
    bob_group_chat.send_message(text="Hello Securejoin group")

    snapshot = carol.get_message_by_id(carol.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Hello Securejoin group"
    assert snapshot.show_padlock

    # Securejoin propagates verification.
    carol_contact_alice_snapshot = carol_contact_alice.get_snapshot()
    assert carol_contact_alice_snapshot.is_verified


def test_securejoin_after_contact_resetup(acfactory) -> None:
    """
    Regression test for a bug that prevented joining verified group with a QR code
    if the group is already created and contains
    a contact with inconsistent (Autocrypt and verified keys exist but don't match) key state.
    """
    ac1, ac2, ac3 = acfactory.get_online_accounts(3)

    # ac3 creates protected group with ac1.
    ac3_chat = ac3.create_group("Verified group", protect=True)

    # ac1 joins ac3 group.
    ac3_qr_code = ac3_chat.get_qr_code()
    ac1.secure_join(ac3_qr_code)
    ac1.wait_for_securejoin_joiner_success()

    # ac1 waits for member added message and creates a QR code.
    snapshot = ac1.get_message_by_id(ac1.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Member Me added by {}.".format(ac3.get_config("addr"))
    ac1_qr_code = snapshot.chat.get_qr_code()

    # ac2 verifies ac1
    qr_code = ac1.get_qr_code()
    ac2.secure_join(qr_code)
    ac2.wait_for_securejoin_joiner_success()

    # ac1 is verified for ac2.
    ac2_contact_ac1 = ac2.create_contact(ac1, "")
    assert ac2_contact_ac1.get_snapshot().is_verified

    # ac1 resetups the account.
    ac1 = acfactory.resetup_account(ac1)

    # Loop sending message from ac1 to ac2
    # until ac2 accepts new ac1 key.
    #
    # This may not happen immediately because resetup of ac1
    # rewinds "smeared timestamp" so Date: header for messages
    # sent by new ac1 are in the past compared to the last Date:
    # header sent by old ac1.
    while True:
        # ac1 sends a message to ac2.
        ac1_contact_ac2 = ac1.create_contact(ac2, "")
        ac1_chat_ac2 = ac1_contact_ac2.create_chat()
        ac1_chat_ac2.send_text("Hello!")

        # ac2 receives a message.
        snapshot = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id).get_snapshot()
        assert snapshot.text == "Hello!"
        logging.info("ac2 received Hello!")

        # ac1 is no longer verified for ac2 as new Autocrypt key is not the same as old verified key.
        logging.info("ac2 addr={}, ac1 addr={}".format(ac2.get_config("addr"), ac1.get_config("addr")))
        if not ac2_contact_ac1.get_snapshot().is_verified:
            break
        time.sleep(1)

    # ac1 goes offline.
    ac1.remove()

    # Scanning a QR code results in creating an unprotected group with an inviter.
    # In this case inviter is ac1 which has an inconsistent key state.
    # Normally inviter becomes verified as a result of Securejoin protocol
    # and then the group chat becomes verified when "Member added" is received,
    # but in this case ac1 is offline and this Securejoin process will never finish.
    logging.info("ac2 scans ac1 QR code, this is not expected to finish")
    ac2.secure_join(ac1_qr_code)

    logging.info("ac2 scans ac3 QR code")
    ac2.secure_join(ac3_qr_code)

    logging.info("ac2 waits for joiner success")
    ac2.wait_for_securejoin_joiner_success()

    # Wait for member added.
    logging.info("ac2 waits for member added message")
    snapshot = ac2.get_message_by_id(ac2.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.is_info
    ac2_chat = snapshot.chat
    assert ac2_chat.get_basic_snapshot().is_protected
    assert len(ac2_chat.get_contacts()) == 3

    # ac1 is still "not verified" for ac2 due to inconsistent state.
    assert not ac2_contact_ac1.get_snapshot().is_verified


def test_withdraw_securejoin_qr(acfactory):
    alice, bob = acfactory.get_online_accounts(2)

    logging.info("Alice creates a verified group")
    alice_chat = alice.create_group("Verified group", protect=True)
    assert alice_chat.get_basic_snapshot().is_protected
    logging.info("Bob joins verified group")

    qr_code = alice_chat.get_qr_code()
    bob_chat = bob.secure_join(qr_code)
    bob.wait_for_securejoin_joiner_success()

    alice.clear_all_events()

    snapshot = bob.get_message_by_id(bob.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Member Me added by {}.".format(alice.get_config("addr"))
    assert snapshot.chat.get_basic_snapshot().is_protected
    bob_chat.leave()

    snapshot = alice.get_message_by_id(alice.wait_for_msgs_changed_event().msg_id).get_snapshot()
    assert snapshot.text == "Group left by {}.".format(bob.get_config("addr"))

    logging.info("Alice withdraws QR code.")
    qr = alice.check_qr(qr_code)
    assert qr["kind"] == "withdrawVerifyGroup"
    alice.set_config_from_qr(qr_code)

    logging.info("Bob scans withdrawn QR code.")
    bob_chat = bob.secure_join(qr_code)

    logging.info("Bob scanned withdrawn QR code")
    while True:
        event = alice.wait_for_event()
        if (
            event.kind == EventType.WARNING
            and "Ignoring vg-request-with-auth message because of invalid auth code." in event.msg
        ):
            break
