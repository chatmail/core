import base64
import concurrent.futures
import json
import logging
import os
import socket
import subprocess
import time
from unittest.mock import MagicMock

import pytest

from deltachat_rpc_client import Contact, EventType, Message, events
from deltachat_rpc_client.const import DownloadState, MessageState
from deltachat_rpc_client.rpc import JsonRpcError


def test_system_info(rpc) -> None:
    system_info = rpc.get_system_info()
    assert "arch" in system_info
    assert "deltachat_core_version" in system_info


def test_sleep(rpc) -> None:
    """Test that long-running task does not block short-running task from completion."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        sleep_5_future = executor.submit(rpc.sleep, 5.0)
        sleep_3_future = executor.submit(rpc.sleep, 3.0)
        done, pending = concurrent.futures.wait(
            [sleep_5_future, sleep_3_future],
            return_when=concurrent.futures.FIRST_COMPLETED,
        )
        assert sleep_3_future in done
        assert sleep_5_future in pending


def test_email_address_validity(rpc) -> None:
    valid_addresses = [
        "email@example.com",
        "36aa165ae3406424e0c61af17700f397cad3fe8ab83d682d0bddf3338a5dd52e@yggmail@yggmail",
    ]
    invalid_addresses = ["email@", "example.com", "emai221"]

    for addr in valid_addresses:
        assert rpc.check_email_validity(addr)
    for addr in invalid_addresses:
        assert not rpc.check_email_validity(addr)


def test_acfactory(acfactory) -> None:
    account = acfactory.new_configured_account()
    while True:
        event = account.wait_for_event()
        if event.kind == EventType.CONFIGURE_PROGRESS:
            assert event.progress != 0  # Progress 0 indicates error.
            if event.progress == 1000:  # Success
                break
        else:
            logging.info(event)
    logging.info("Successful configuration")


def test_configure_starttls(acfactory) -> None:
    addr, password = acfactory.get_credentials()
    account = acfactory.get_unconfigured_account()
    account.add_or_update_transport(
        {
            "addr": addr,
            "password": password,
            "imapSecurity": "starttls",
            "smtpSecurity": "starttls",
        },
    )
    assert account.is_configured()


def test_lowercase_address(acfactory) -> None:
    addr, password = acfactory.get_credentials()
    addr_upper = addr.upper()
    account = acfactory.get_unconfigured_account()
    account.add_or_update_transport(
        {
            "addr": addr_upper,
            "password": password,
        },
    )
    assert account.is_configured()
    assert addr_upper != addr
    assert account.get_config("configured_addr") == addr
    assert account.list_transports()[0]["addr"] == addr

    for param in [
        account.get_info()["used_account_settings"],
        account.get_info()["entered_account_settings"],
    ]:
        assert addr in param
        assert addr_upper not in param


def test_configure_ip(acfactory) -> None:
    addr, password = acfactory.get_credentials()
    account = acfactory.get_unconfigured_account()
    ip_address = socket.gethostbyname(addr.rsplit("@")[-1])

    with pytest.raises(JsonRpcError):
        account.add_or_update_transport(
            {
                "addr": addr,
                "password": password,
                # This should fail TLS check.
                "imapServer": ip_address,
            },
        )


def test_configure_alternative_port(acfactory) -> None:
    """Test that configuration with alternative port 443 works."""
    addr, password = acfactory.get_credentials()
    account = acfactory.get_unconfigured_account()
    account.add_or_update_transport(
        {
            "addr": addr,
            "password": password,
            "imapPort": 443,
            "smtpPort": 443,
        },
    )
    assert account.is_configured()


def test_list_transports(acfactory) -> None:
    addr, password = acfactory.get_credentials()
    account = acfactory.get_unconfigured_account()
    account.add_or_update_transport(
        {
            "addr": addr,
            "password": password,
            "imapUser": addr,
        },
    )
    transports = account.list_transports()
    assert len(transports) == 1
    params = transports[0]
    assert params["addr"] == addr
    assert params["password"] == password
    assert params["imapUser"] == addr


def test_account(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    bob_addr = bob.get_config("addr")
    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_text("Hello!")

    event = bob.wait_for_incoming_msg_event()
    chat_id = event.chat_id
    msg_id = event.msg_id

    message = bob.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.chat_id == chat_id
    assert snapshot.text == "Hello!"
    bob.mark_seen_messages([message])

    assert alice != bob
    assert repr(alice)
    assert alice.get_info().level
    assert alice.get_size()
    assert alice.is_configured()
    assert not alice.get_avatar()
    assert alice.get_contact_by_addr(bob_addr) == alice_contact_bob
    assert alice.get_contacts()
    assert alice.get_contacts(snapshot=True)
    assert alice.self_contact
    assert alice.get_chatlist()
    assert alice.get_chatlist(snapshot=True)
    assert alice.get_qr_code()
    assert alice.get_fresh_messages()

    # Test sending empty message.
    assert len(bob.wait_next_messages()) == 0
    alice_chat_bob.send_text("")
    messages = bob.wait_next_messages()
    assert bob.get_next_messages() == messages
    assert len(messages) == 1
    message = messages[0]
    snapshot = message.get_snapshot()
    assert snapshot.text == ""
    bob.mark_seen_messages([message])

    group = alice.create_group("test group")
    group.add_contact(alice_contact_bob)
    group_msg = group.send_message(text="hello")
    assert group_msg == alice.get_message_by_id(group_msg.id)
    assert group == alice.get_chat_by_id(group.id)
    alice.delete_messages([group_msg])

    alice.set_config("selfstatus", "test")
    assert alice.get_config("selfstatus") == "test"
    alice.update_config(selfstatus="test2")
    assert alice.get_config("selfstatus") == "test2"

    assert not alice.get_blocked_contacts()
    alice_contact_bob.block()
    blocked_contacts = alice.get_blocked_contacts()
    assert blocked_contacts
    assert blocked_contacts[0].contact == alice_contact_bob

    bob.remove()
    alice.stop_io()


def test_chat(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_text("Hello!")

    event = bob.wait_for_incoming_msg_event()
    chat_id = event.chat_id
    msg_id = event.msg_id
    message = bob.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.chat_id == chat_id
    assert snapshot.text == "Hello!"
    bob_chat_alice = bob.get_chat_by_id(chat_id)

    assert alice_chat_bob != bob_chat_alice
    assert repr(alice_chat_bob)
    alice_chat_bob.delete()
    assert not bob_chat_alice.can_send()
    bob_chat_alice.accept()
    assert bob_chat_alice.can_send()
    bob_chat_alice.block()
    bob_chat_alice = snapshot.sender.create_chat()
    bob_chat_alice.mute()
    bob_chat_alice.unmute()
    bob_chat_alice.pin()
    bob_chat_alice.unpin()
    bob_chat_alice.archive()
    bob_chat_alice.unarchive()
    with pytest.raises(JsonRpcError):  # can't set name for 1:1 chats
        bob_chat_alice.set_name("test")
    bob_chat_alice.set_ephemeral_timer(300)
    bob_chat_alice.get_encryption_info()

    group = alice.create_group("test group")
    group.add_contact(alice_contact_bob)
    group.get_qr_code()

    snapshot = group.get_basic_snapshot()
    assert snapshot.name == "test group"
    group.set_name("new name")
    snapshot = group.get_full_snapshot()
    assert snapshot.name == "new name"

    msg = group.send_message(text="hi")
    assert (msg.get_snapshot()).text == "hi"
    group.forward_messages([msg])

    group.set_draft(text="test draft")
    draft = group.get_draft()
    assert draft.text == "test draft"
    group.remove_draft()
    assert not group.get_draft()

    assert group.get_messages()
    group.get_fresh_message_count()
    group.mark_noticed()
    assert group.get_contacts()
    assert group.get_past_contacts() == []
    group.remove_contact(alice_contact_bob)
    assert len(group.get_past_contacts()) == 1
    group.get_locations()


def test_contact(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    bob_addr = bob.get_config("addr")
    alice_contact_bob = alice.create_contact(bob, "Bob")

    assert alice_contact_bob == alice.get_contact_by_id(alice_contact_bob.id)
    assert repr(alice_contact_bob)
    alice_contact_bob.block()
    alice_contact_bob.unblock()
    alice_contact_bob.reset_encryption()
    alice_contact_bob.set_name("new name")
    alice_contact_bob.get_encryption_info()
    snapshot = alice_contact_bob.get_snapshot()
    assert snapshot.address == bob_addr
    alice_contact_bob.create_chat()


def test_message(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_text("Hello!")

    event = bob.wait_for_incoming_msg_event()
    chat_id = event.chat_id
    msg_id = event.msg_id

    message = bob.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.chat_id == chat_id
    assert snapshot.text == "Hello!"
    assert not snapshot.is_bot
    assert repr(message)

    with pytest.raises(JsonRpcError):  # chat is not accepted
        snapshot.chat.send_text("hi")
    snapshot.chat.accept()
    snapshot.chat.send_text("hi")

    message.mark_seen()
    message.send_reaction("😎")
    reactions = message.get_reactions()
    assert reactions
    snapshot = message.get_snapshot()
    assert reactions == snapshot.reactions


def test_selfavatar_sync(acfactory, data, log) -> None:
    alice = acfactory.get_online_account()

    log.section("Alice adds a second device")
    alice2 = alice.clone()

    log.section("Second device goes online")
    alice2.start_io()

    log.section("First device changes avatar")
    image = data.get_path("image/avatar1000x1000.jpg")
    alice.set_config("selfavatar", image)
    avatar_config = alice.get_config("selfavatar")
    avatar_hash = os.path.basename(avatar_config)
    print("Info: avatar hash is ", avatar_hash)

    log.section("First device receives avatar change")
    alice2.wait_for_event(EventType.SELFAVATAR_CHANGED)
    avatar_config2 = alice2.get_config("selfavatar")
    avatar_hash2 = os.path.basename(avatar_config2)
    print("Info: avatar hash on second device is ", avatar_hash2)
    assert avatar_hash == avatar_hash2
    assert avatar_config != avatar_config2


def test_reaction_seen_on_another_dev(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)
    alice2 = alice.clone()
    alice2.start_io()

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_text("Hello!")

    event = bob.wait_for_incoming_msg_event()
    msg_id = event.msg_id

    message = bob.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    snapshot.chat.accept()
    message.send_reaction("😎")
    for a in [alice, alice2]:
        a.wait_for_event(EventType.INCOMING_REACTION)

    alice2.clear_all_events()
    alice_chat_bob.mark_noticed()
    chat_id = alice2.wait_for_event(EventType.MSGS_NOTICED).chat_id
    alice2_chat_bob = alice2.create_chat(bob)
    assert chat_id == alice2_chat_bob.id


def test_is_bot(acfactory) -> None:
    """Test that we can recognize messages submitted by bots."""
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()

    # Alice becomes a bot.
    alice.set_config("bot", "1")
    alice_chat_bob.send_text("Hello!")

    event = bob.wait_for_incoming_msg_event()
    message = bob.get_message_by_id(event.msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.chat_id == event.chat_id
    assert snapshot.text == "Hello!"
    assert snapshot.is_bot


def test_bot(acfactory) -> None:
    mock = MagicMock()
    user = (acfactory.get_online_accounts(1))[0]
    bot = acfactory.new_configured_bot()
    bot2 = acfactory.new_configured_bot()

    assert bot.is_configured()
    assert bot.account.get_config("bot") == "1"

    hook = lambda e: mock.hook(e.msg_id) and None, events.RawEvent(EventType.INCOMING_MSG)
    bot.add_hook(*hook)
    event = acfactory.process_message(from_account=user, to_client=bot, text="Hello!")
    snapshot = bot.account.get_message_by_id(event.msg_id).get_snapshot()
    assert not snapshot.is_bot
    mock.hook.assert_called_once_with(event.msg_id)
    bot.remove_hook(*hook)

    def track(e):
        mock.hook(e.message_snapshot.id)

    mock.hook.reset_mock()
    hook = track, events.NewMessage(r"hello")
    bot.add_hook(*hook)
    bot.add_hook(track, events.NewMessage(command="/help"))
    event = acfactory.process_message(from_account=user, to_client=bot, text="hello")
    mock.hook.assert_called_with(event.msg_id)
    event = acfactory.process_message(from_account=user, to_client=bot, text="hello!")
    mock.hook.assert_called_with(event.msg_id)
    acfactory.process_message(from_account=bot2.account, to_client=bot, text="hello")
    assert len(mock.hook.mock_calls) == 2  # bot messages are ignored between bots
    acfactory.process_message(from_account=user, to_client=bot, text="hey!")
    assert len(mock.hook.mock_calls) == 2
    bot.remove_hook(*hook)

    mock.hook.reset_mock()
    acfactory.process_message(from_account=user, to_client=bot, text="hello")
    event = acfactory.process_message(from_account=user, to_client=bot, text="/help")
    mock.hook.assert_called_once_with(event.msg_id)


def test_wait_next_messages(acfactory) -> None:
    alice = acfactory.new_configured_account()

    # Create a bot account so it does not receive device messages in the beginning.
    addr, password = acfactory.get_credentials()
    bot = acfactory.get_unconfigured_account()
    bot.set_config("bot", "1")
    bot.add_or_update_transport({"addr": addr, "password": password})
    assert bot.is_configured()

    # There are no old messages and the call returns immediately.
    assert not bot.wait_next_messages()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        # Bot starts waiting for messages.
        next_messages_task = executor.submit(bot.wait_next_messages)

        alice_contact_bot = alice.create_contact(bot, "Bot")
        alice_chat_bot = alice_contact_bot.create_chat()
        alice_chat_bot.send_text("Hello!")

        next_messages = next_messages_task.result()
        assert len(next_messages) == 1
        snapshot = next_messages[0].get_snapshot()
        assert snapshot.text == "Hello!"


def test_import_export_backup(acfactory, tmp_path) -> None:
    alice = acfactory.new_configured_account()
    alice.export_backup(tmp_path)

    files = list(tmp_path.glob("*.tar"))
    alice2 = acfactory.get_unconfigured_account()
    alice2.import_backup(files[0])

    assert alice2.manager.get_system_info()


def test_import_export_keys(acfactory, tmp_path) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.send_text("Hello Bob!")

    snapshot = bob.get_message_by_id(bob.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Hello Bob!"

    # Alice resetups account, but keeps the key.
    alice_keys_path = tmp_path / "alice_keys"
    alice_keys_path.mkdir()
    alice.export_self_keys(alice_keys_path)
    alice = acfactory.resetup_account(alice)
    alice.import_self_keys(alice_keys_path)

    snapshot.chat.accept()
    snapshot.chat.send_text("Hello Alice!")
    snapshot = alice.get_message_by_id(alice.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "Hello Alice!"
    assert snapshot.show_padlock


def test_openrpc_command_line() -> None:
    """Test that "deltachat-rpc-server --openrpc" command returns an OpenRPC specification."""
    out = subprocess.run(["deltachat-rpc-server", "--openrpc"], capture_output=True, check=True).stdout
    openrpc = json.loads(out)
    assert "openrpc" in openrpc
    assert "methods" in openrpc


def test_provider_info(rpc) -> None:
    account_id = rpc.add_account()

    provider_info = rpc.get_provider_info(account_id, "example.org")
    assert provider_info["id"] == "example.com"

    provider_info = rpc.get_provider_info(account_id, "uep7oiw4ahtaizuloith.org")
    assert provider_info is None

    # Test MX record resolution.
    provider_info = rpc.get_provider_info(account_id, "github.com")
    assert provider_info["id"] == "gmail"

    # Disable MX record resolution.
    rpc.set_config(account_id, "proxy_enabled", "1")
    provider_info = rpc.get_provider_info(account_id, "github.com")
    assert provider_info is None


def test_mdn_doesnt_break_autocrypt(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")

    # Bob creates chat manually so chat with Alice is accepted.
    alice_chat_bob = alice_contact_bob.create_chat()

    # Alice sends a message to Bob.
    alice_chat_bob.send_text("Hello Bob!")
    event = bob.wait_for_incoming_msg_event()
    msg_id = event.msg_id
    message = bob.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()

    # Bob sends a message to Alice.
    bob_chat_alice = snapshot.chat
    bob_chat_alice.accept()
    bob_chat_alice.send_text("Hello Alice!")
    event = alice.wait_for_incoming_msg_event()
    msg_id = event.msg_id
    message = alice.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.show_padlock

    # Alice reads Bob's message.
    message.mark_seen()
    bob.wait_for_event(EventType.MSG_READ)

    # Bob sends a message to Alice, it should also be encrypted.
    bob_chat_alice.send_text("Hi Alice!")
    event = alice.wait_for_incoming_msg_event()
    msg_id = event.msg_id
    message = alice.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.show_padlock


def test_reaction_to_partially_fetched_msg(acfactory, tmp_path):
    """See https://github.com/deltachat/deltachat-core-rust/issues/3688 "Partially downloaded
    messages are received out of order".

    If the Inbox contains X small messages followed by Y large messages followed by Z small
    messages, Delta Chat first downloaded a batch of X+Z messages, and then a batch of Y messages.

    This bug was discovered by @Simon-Laux while testing reactions PR #3644 and can be reproduced
    with online test as follows:
    - Bob enables download limit and goes offline.
    - Alice sends a large message to Bob and reacts to this message with a thumbs-up.
    - Bob goes online
    - Bob first processes a reaction message and throws it away because there is no corresponding
      message, then processes a partially downloaded message.
    - As a result, Bob does not see a reaction
    """
    download_limit = 300000
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_addr = ac1.get_config("addr")
    chat = ac1.create_chat(ac2)
    ac2.set_config("download_limit", str(download_limit))
    ac2.stop_io()

    logging.info("sending small+large messages from ac1 to ac2")
    msgs = []
    msgs.append(chat.send_text("hi"))
    path = tmp_path / "large"
    path.write_bytes(os.urandom(download_limit + 1))
    msgs.append(chat.send_file(str(path)))
    for m in msgs:
        m.wait_until_delivered()

    logging.info("sending a reaction to the large message from ac1 to ac2")
    # TODO: Find the reason of an occasional message reordering on the server (so that the reaction
    # has a lower UID than the previous message). W/a is to sleep for some time to let the reaction
    # have a later INTERNALDATE.
    time.sleep(1.1)
    react_str = "\N{THUMBS UP SIGN}"
    msgs.append(msgs[-1].send_reaction(react_str))
    msgs[-1].wait_until_delivered()

    ac2.start_io()

    logging.info("wait for ac2 to receive a reaction")
    msg2 = Message(ac2, ac2.wait_for_reactions_changed().msg_id)
    assert msg2.get_sender_contact().get_snapshot().address == ac1_addr
    assert msg2.get_snapshot().download_state == DownloadState.AVAILABLE
    reactions = msg2.get_reactions()
    contacts = [Contact(ac2, int(i)) for i in reactions.reactions_by_contact]
    assert len(contacts) == 1
    assert contacts[0].get_snapshot().address == ac1_addr
    assert list(reactions.reactions_by_contact.values())[0] == [react_str]


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


@pytest.mark.parametrize("n_accounts", [3, 2])
def test_download_limit_chat_assignment(acfactory, tmp_path, n_accounts):
    download_limit = 300000

    alice, *others = acfactory.get_online_accounts(n_accounts)
    bob = others[0]

    alice_group = alice.create_group("test group")
    for account in others:
        chat = account.create_chat(alice)
        chat.send_text("Hello Alice!")
        assert alice.get_message_by_id(alice.wait_for_incoming_msg_event().msg_id).get_snapshot().text == "Hello Alice!"

        contact = alice.create_contact(account)
        alice_group.add_contact(contact)

    if n_accounts == 2:
        bob_chat_alice = bob.create_chat(alice)
    bob.set_config("download_limit", str(download_limit))

    alice_group.send_text("hi")
    snapshot = bob.get_message_by_id(bob.wait_for_incoming_msg_event().msg_id).get_snapshot()
    assert snapshot.text == "hi"
    bob_group = snapshot.chat

    path = tmp_path / "large"
    path.write_bytes(os.urandom(download_limit + 1))

    for i in range(10):
        logging.info("Sending message %s", i)
        alice_group.send_file(str(path))
        snapshot = bob.get_message_by_id(bob.wait_for_incoming_msg_event().msg_id).get_snapshot()
        assert snapshot.download_state == DownloadState.AVAILABLE
        if n_accounts > 2:
            assert snapshot.chat == bob_group
        else:
            # Group contains only Alice and Bob,
            # so partially downloaded messages are
            # hard to distinguish from private replies to group messages.
            #
            # Message may be a private reply, so we assign it to 1:1 chat with Alice.
            assert snapshot.chat == bob_chat_alice


def test_markseen_contact_request(acfactory):
    """
    Test that seen status is synchronized for contact request messages
    even though read receipt is not sent.
    """
    alice, bob = acfactory.get_online_accounts(2)

    # Bob sets up a second device.
    bob2 = bob.clone()
    bob2.start_io()

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.send_text("Hello Bob!")

    message = bob.get_message_by_id(bob.wait_for_incoming_msg_event().msg_id)
    message2 = bob2.get_message_by_id(bob2.wait_for_incoming_msg_event().msg_id)
    assert message2.get_snapshot().state == MessageState.IN_FRESH

    message.mark_seen()
    bob2.wait_for_event(EventType.MSGS_NOTICED)
    assert message2.get_snapshot().state == MessageState.IN_SEEN


def test_get_http_response(acfactory):
    alice = acfactory.new_configured_account()
    http_response = alice._rpc.get_http_response(alice.id, "https://example.org")
    assert http_response["mimetype"] == "text/html"
    assert b"<title>Example Domain</title>" in base64.b64decode((http_response["blob"] + "==").encode())


def test_configured_imap_certificate_checks(acfactory):
    alice = acfactory.new_configured_account()

    # Certificate checks should be configured (not None)
    assert "cert_automatic" in alice.get_info().used_account_settings

    # "cert_old_automatic" is the value old Delta Chat core versions used
    # to mean user entered "imap_certificate_checks=0" (Automatic)
    # and configuration failed to use strict TLS checks
    # so it switched strict TLS checks off.
    #
    # New versions of Delta Chat are not disabling TLS checks
    # unless users explicitly disables them
    # or provider database says provider has invalid certificates.
    #
    # Core 1.142.4, 1.142.5 and 1.142.6 saved this value due to bug.
    # This test is a regression test to prevent this happening again.
    assert "cert_old_automatic" not in alice.get_info().used_account_settings


def test_no_old_msg_is_fresh(acfactory):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_clone = ac1.clone()
    ac1_clone.start_io()

    ac1.create_chat(ac2)
    ac1_clone_chat = ac1_clone.create_chat(ac2)

    ac1.get_device_chat().mark_noticed()

    logging.info("Send a first message from ac2 to ac1 and check that it's 'fresh'")
    first_msg = ac2.create_chat(ac1).send_text("Hi")
    ac1.wait_for_incoming_msg_event()
    assert ac1.create_chat(ac2).get_fresh_message_count() == 1
    assert len(list(ac1.get_fresh_messages())) == 1

    ac1.wait_for_event(EventType.IMAP_INBOX_IDLE)

    logging.info("Send a message from ac1_clone to ac2 and check that ac1 marks the first message as 'noticed'")
    ac1_clone_chat.send_text("Hi back")
    ev = ac1.wait_for_msgs_noticed_event()

    assert ev.chat_id == first_msg.get_snapshot().chat_id
    assert ac1.create_chat(ac2).get_fresh_message_count() == 0
    assert len(list(ac1.get_fresh_messages())) == 0


def test_rename_synchronization(acfactory):
    """Test synchronization of contact renaming."""
    alice, bob = acfactory.get_online_accounts(2)
    alice2 = alice.clone()
    alice2.bring_online()

    bob.set_config("displayname", "Bob")
    bob.create_chat(alice).send_text("Hello!")
    alice_msg = alice.wait_for_incoming_msg().get_snapshot()
    alice2_msg = alice2.wait_for_incoming_msg().get_snapshot()

    assert alice2_msg.sender.get_snapshot().display_name == "Bob"
    alice_msg.sender.set_name("Bobby")
    alice2.wait_for_event(EventType.CONTACTS_CHANGED)
    assert alice2_msg.sender.get_snapshot().display_name == "Bobby"


def test_rename_group(acfactory):
    """Test renaming the group."""
    alice, bob = acfactory.get_online_accounts(2)

    alice_group = alice.create_group("Test group")
    alice_contact_bob = alice.create_contact(bob)
    alice_group.add_contact(alice_contact_bob)
    alice_group.send_text("Hello!")

    bob_msg = bob.wait_for_incoming_msg()
    bob_chat = bob_msg.get_snapshot().chat
    assert bob_chat.get_basic_snapshot().name == "Test group"

    for name in ["Baz", "Foo bar", "Xyzzy"]:
        alice_group.set_name(name)
        bob.wait_for_incoming_msg_event()
        assert bob_chat.get_basic_snapshot().name == name


def test_get_all_accounts_deadlock(rpc):
    """Regression test for get_all_accounts deadlock."""
    for _ in range(100):
        all_accounts = rpc.get_all_accounts.future()
        rpc.add_account()
        all_accounts()


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
        if event.kind == EventType.INFO and "uid/validity change folder DeltaChat" in event.msg:
            break

    ac2 = acfactory.get_online_account()
    ac2.create_chat(ac1).send_text("hello")
    msg = ac1.wait_for_incoming_msg().get_snapshot()
    assert msg.text == "hello"

    assert "DeltaChat" in ac1_direct_imap.list_folders()
