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
from deltachat_rpc_client.pytestplugin import E2EE_INFO_MSGS
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

    param = account.get_info()["used_transport_settings"]
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
    # get_contact_by_addr() can lookup a key contact by address:
    bob_contact = alice.get_contact_by_addr(bob_addr).get_snapshot()
    assert bob_contact.display_name == "Bob"
    assert bob_contact.is_key_contact
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
    to_resend = group.send_text("will be resent")
    group.add_contact(alice_contact_bob)
    group.get_qr_code()

    snapshot = group.get_basic_snapshot()
    assert snapshot.name == "test group"
    group.set_name("new name")
    snapshot = group.get_full_snapshot()
    assert snapshot.name == "new name"

    msg = group.send_message(text="hi")
    assert (msg.get_snapshot()).text == "hi"
    group.resend_messages([to_resend])
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


def test_receive_imf_failure(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)
    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()

    bob.set_config("fail_on_receiving_full_msg", "1")
    alice_chat_bob.send_text("Hello!")
    event = bob.wait_for_event(EventType.MSGS_CHANGED)
    assert event.chat_id == bob.get_device_chat().id
    msg_id = event.msg_id
    message = bob.get_message_by_id(msg_id)
    snapshot = message.get_snapshot()
    version = bob.get_info()["deltachat_core_version"]
    assert (
        snapshot.text == "❌ Failed to receive a message:"
        " Condition failed: `!context.get_config_bool(Config::FailOnReceivingFullMsg).await?`."
        f" Core version {version}."
        " Please report this bug to delta@merlinux.eu or https://support.delta.chat/."
    )

    # The failed message doesn't break the IMAP loop.
    bob.set_config("fail_on_receiving_full_msg", "0")
    alice_chat_bob.send_text("Hello again!")
    message = bob.wait_for_incoming_msg()
    snapshot = message.get_snapshot()
    assert snapshot.text == "Hello again!"
    assert snapshot.download_state == DownloadState.DONE
    assert snapshot.error is None


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

    snapshot = bob.wait_for_incoming_msg().get_snapshot()
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
    alice = acfactory.get_online_account()

    # Create a bot account so it does not receive device messages in the beginning.
    addr, password = acfactory.get_credentials()
    bot = acfactory.get_unconfigured_account()
    bot.set_config("bot", "1")
    bot.add_or_update_transport({"addr": addr, "password": password})
    assert bot.is_configured()
    bot.bring_online()

    # There are no old messages and the call returns immediately.
    assert not bot.wait_next_messages()

    # Bot starts waiting for messages.
    next_messages_task = bot.wait_next_messages.future()

    alice_contact_bot = alice.create_contact(bot, "Bot")
    alice_chat_bot = alice_contact_bot.create_chat()
    alice_chat_bot.send_text("Hello!")

    next_messages = next_messages_task()

    if len(next_messages) == E2EE_INFO_MSGS:
        next_messages += bot.wait_next_messages()

    assert len(next_messages) == 1 + E2EE_INFO_MSGS
    snapshot = next_messages[0 + E2EE_INFO_MSGS].get_snapshot()
    assert snapshot.text == "Hello!"


def test_import_export_backup(acfactory, tmp_path) -> None:
    alice = acfactory.new_configured_account()
    alice.export_backup(tmp_path)

    files = list(tmp_path.glob("*.tar"))
    alice2 = acfactory.get_unconfigured_account()
    alice2.import_backup(files[0])

    assert alice2.manager.get_system_info()


def test_import_export_online_all(acfactory, tmp_path, data, log) -> None:
    (ac1, some1) = acfactory.get_online_accounts(2)

    log.section("create some chat content")
    some1_addr = some1.get_config("addr")
    chat1 = ac1.create_contact(some1).create_chat()
    chat1.send_text("msg1")
    assert len(ac1.get_contacts()) == 1

    original_image_path = data.get_path("image/avatar64x64.png")
    chat1.send_file(str(original_image_path))

    # Add another 100KB file that ensures that the progress is smooth enough
    path = tmp_path / "attachment.txt"
    with path.open("w") as file:
        file.truncate(100000)
    chat1.send_file(str(path))

    def assert_account_is_proper(ac):
        contacts = ac.get_contacts()
        assert len(contacts) == 1
        contact2 = contacts[0]
        assert contact2.get_snapshot().address == some1_addr
        chat2 = contact2.create_chat()
        messages = chat2.get_messages()
        assert len(messages) == 3 + E2EE_INFO_MSGS
        assert messages[0 + E2EE_INFO_MSGS].get_snapshot().text == "msg1"
        snapshot = messages[1 + E2EE_INFO_MSGS].get_snapshot()
        assert snapshot.file_mime == "image/png"
        assert os.stat(snapshot.file).st_size == os.stat(original_image_path).st_size
        ac.set_config("displayname", "new displayname")
        assert ac.get_config("displayname") == "new displayname"

    assert_account_is_proper(ac1)

    backupdir = tmp_path / "backup"
    backupdir.mkdir()

    log.section(f"export all to {backupdir}")
    ac1.stop_io()
    ac1.export_backup(backupdir)
    progress = 0
    files_written = []
    while True:
        event = ac1.wait_for_event()
        if event.kind == EventType.IMEX_PROGRESS:
            assert event.progress > 0  # Progress 0 indicates error.
            assert event.progress < progress + 250
            progress = event.progress
            if progress == 1000:
                break
        elif event.kind == EventType.IMEX_FILE_WRITTEN:
            files_written.append(event.path)
        else:
            logging.info(event)
    assert len(files_written) == 1
    assert os.path.exists(files_written[0])
    ac1.start_io()

    log.section("get fresh empty account")
    ac2 = acfactory.get_unconfigured_account()

    log.section("import backup and check it's proper")
    ac2.import_backup(files_written[0])
    progress = 0
    while True:
        event = ac2.wait_for_event()
        if event.kind == EventType.IMEX_PROGRESS:
            assert event.progress > 0  # Progress 0 indicates error.
            assert event.progress < progress + 250
            progress = event.progress
            if progress == 1000:
                break
        else:
            logging.info(event)
    assert_account_is_proper(ac1)
    assert_account_is_proper(ac2)

    log.section(f"Second-time export all to {backupdir}")
    ac1.stop_io()
    ac1.export_backup(backupdir)
    while True:
        event = ac1.wait_for_event()
        if event.kind == EventType.IMEX_PROGRESS:
            assert event.progress > 0
            if event.progress == 1000:
                break
        elif event.kind == EventType.IMEX_FILE_WRITTEN:
            files_written.append(event.path)
        else:
            logging.info(event)
    assert len(files_written) == 2
    assert os.path.exists(files_written[1])
    assert files_written[1] != files_written[0]
    assert len(list(backupdir.glob("*.tar"))) == 2


def test_import_export_keys(acfactory, tmp_path) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.send_text("Hello Bob!")

    snapshot = bob.wait_for_incoming_msg().get_snapshot()
    assert snapshot.text == "Hello Bob!"

    # Alice resetups account, but keeps the key.
    alice_keys_path = tmp_path / "alice_keys"
    alice_keys_path.mkdir()
    alice.export_self_keys(alice_keys_path)
    alice = acfactory.resetup_account(alice)
    alice.import_self_keys(alice_keys_path)

    snapshot.chat.accept()
    snapshot.chat.send_text("Hello Alice!")
    snapshot = alice.wait_for_incoming_msg().get_snapshot()
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
    # This previously resulted in Gmail provider
    # because MX record pointed to google.com domain,
    # but MX record resolution has been removed.
    provider_info = rpc.get_provider_info(account_id, "github.com")
    assert provider_info is None

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
    snapshot = bob.wait_for_incoming_msg().get_snapshot()

    # Bob sends a message to Alice.
    bob_chat_alice = snapshot.chat
    bob_chat_alice.accept()
    bob_chat_alice.send_text("Hello Alice!")
    message = alice.wait_for_incoming_msg()
    snapshot = message.get_snapshot()
    assert snapshot.show_padlock

    # Alice reads Bob's message.
    message.mark_seen()
    bob.wait_for_event(EventType.MSG_READ)

    # Bob sends a message to Alice, it should also be encrypted.
    bob_chat_alice.send_text("Hi Alice!")
    snapshot = alice.wait_for_incoming_msg().get_snapshot()
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


@pytest.mark.parametrize("n_accounts", [3, 2])
def test_download_limit_chat_assignment(acfactory, tmp_path, n_accounts):
    download_limit = 300000

    alice, *others = acfactory.get_online_accounts(n_accounts)
    bob = others[0]

    alice_group = alice.create_group("test group")
    for account in others:
        chat = account.create_chat(alice)
        chat.send_text("Hello Alice!")
        assert alice.wait_for_incoming_msg().get_snapshot().text == "Hello Alice!"

        contact = alice.create_contact(account)
        alice_group.add_contact(contact)

    bob.set_config("download_limit", str(download_limit))

    alice_group.send_text("hi")
    snapshot = bob.wait_for_incoming_msg().get_snapshot()
    assert snapshot.text == "hi"
    bob_group = snapshot.chat

    path = tmp_path / "large"
    path.write_bytes(os.urandom(download_limit + 1))

    for i in range(10):
        logging.info("Sending message %s", i)
        alice_group.send_file(str(path))
        snapshot = bob.wait_for_incoming_msg().get_snapshot()
        assert snapshot.download_state == DownloadState.AVAILABLE
        assert snapshot.chat == bob_group


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

    message = bob.wait_for_incoming_msg()
    message2 = bob2.wait_for_incoming_msg()
    assert message2.get_snapshot().state == MessageState.IN_FRESH

    message.mark_seen()
    bob2.wait_for_event(EventType.MSGS_NOTICED)
    assert message2.get_snapshot().state == MessageState.IN_SEEN


def test_read_receipt(acfactory):
    """
    Test sending a read receipt and ensure it is attributed to the correct contact.
    """
    alice, bob = acfactory.get_online_accounts(2)

    alice_chat_bob = alice.create_chat(bob)
    alice_contact_bob = alice.create_contact(bob)
    bob.create_chat(alice)  # Accept the chat

    alice_chat_bob.send_text("Hello Bob!")
    msg = bob.wait_for_incoming_msg()
    msg.mark_seen()

    read_msg = alice.wait_for_msg(EventType.MSG_READ)
    read_receipts = read_msg.get_read_receipts()
    assert len(read_receipts) == 1
    assert read_receipts[0].contact_id == alice_contact_bob.id


def test_get_http_response(acfactory):
    alice = acfactory.new_configured_account()
    http_response = alice._rpc.get_http_response(alice.id, "https://example.org")
    assert http_response["mimetype"] == "text/html"
    assert b"<title>Example Domain</title>" in base64.b64decode((http_response["blob"] + "==").encode())


def test_configured_imap_certificate_checks(acfactory):
    alice = acfactory.new_configured_account()

    # Certificate checks should be configured (not None)
    assert "cert_strict" in alice.get_info().used_transport_settings

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
    assert "cert_old_automatic" not in alice.get_info().used_transport_settings


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
    bob.wait_for_event(EventType.CHATLIST_ITEM_CHANGED)

    for name in ["Baz", "Foo bar", "Xyzzy"]:
        alice_group.set_name(name)
        bob.wait_for_event(EventType.CHATLIST_ITEM_CHANGED)
        bob.wait_for_event(EventType.CHATLIST_ITEM_CHANGED)
        assert bob_chat.get_basic_snapshot().name == name


def test_get_all_accounts_deadlock(rpc):
    """Regression test for get_all_accounts deadlock."""
    for _ in range(100):
        all_accounts = rpc.get_all_accounts.future()
        rpc.add_account()
        all_accounts()


@pytest.mark.parametrize("all_devices_online", [True, False])
def test_leave_broadcast(acfactory, all_devices_online):
    alice, bob = acfactory.get_online_accounts(2)

    bob2 = bob.clone()

    if all_devices_online:
        bob2.start_io()

    logging.info("===================== Alice creates a broadcast =====================")
    alice_chat = alice.create_broadcast("Broadcast channel!")

    logging.info("===================== Bob joins the broadcast =====================")
    qr_code = alice_chat.get_qr_code()
    bob.secure_join(qr_code)
    alice.wait_for_securejoin_inviter_success()
    bob.wait_for_securejoin_joiner_success()

    alice_bob_contact = alice.create_contact(bob)
    alice_contacts = alice_chat.get_contacts()
    assert len(alice_contacts) == 1  # 1 recipient
    assert alice_contacts[0].id == alice_bob_contact.id

    member_added_msg = bob.wait_for_incoming_msg()
    assert member_added_msg.get_snapshot().text == "You joined the channel."

    def get_broadcast(ac):
        chat = ac.get_chatlist(query="Broadcast channel!")[0]
        assert chat.get_basic_snapshot().name == "Broadcast channel!"
        return chat

    def check_account(ac, contact, inviter_side, please_wait_info_msg=False):
        chat = get_broadcast(ac)
        contact_snapshot = contact.get_snapshot()
        chat_msgs = chat.get_messages()

        encrypted_msg = chat_msgs.pop(0).get_snapshot()
        assert encrypted_msg.text == "Messages are end-to-end encrypted."
        assert encrypted_msg.is_info

        if please_wait_info_msg:
            first_msg = chat_msgs.pop(0).get_snapshot()
            assert "invited you to join this channel" in first_msg.text
            assert first_msg.is_info

        member_added_msg = chat_msgs.pop(0).get_snapshot()
        if inviter_side:
            assert member_added_msg.text == f"Member {contact_snapshot.display_name} added."
        else:
            assert member_added_msg.text == "You joined the channel."
        assert member_added_msg.is_info

        if not inviter_side:
            leave_msg = chat_msgs.pop(0).get_snapshot()
            assert leave_msg.text == "You left the channel."

        assert len(chat_msgs) == 0

        chat_snapshot = chat.get_full_snapshot()

        # On Alice's side, SELF is not in the list of contact ids
        # because OutBroadcast chats never contain SELF in the list.
        # On Bob's side, SELF is not in the list because he left.
        if inviter_side:
            assert len(chat_snapshot.contact_ids) == 0
        else:
            assert chat_snapshot.contact_ids == [contact.id]

    logging.info("===================== Bob leaves the broadcast =====================")
    bob_chat = get_broadcast(bob)
    assert bob_chat.get_full_snapshot().self_in_group
    assert len(bob_chat.get_contacts()) == 2  # Alice and Bob

    bob_chat.leave()
    assert not bob_chat.get_full_snapshot().self_in_group
    # After Bob left, only Alice will be left in Bob's memberlist
    assert len(bob_chat.get_contacts()) == 1

    check_account(bob, bob.create_contact(alice), inviter_side=False, please_wait_info_msg=True)

    logging.info("===================== Test Alice's device =====================")
    while len(alice_chat.get_contacts()) != 0:  # After Bob left, there will be 0 recipients
        alice.wait_for_event(EventType.CHAT_MODIFIED)

    check_account(alice, alice.create_contact(bob), inviter_side=True)

    logging.info("===================== Test Bob's second device =====================")
    # Start second Bob device, if it wasn't started already.
    bob2.start_io()

    member_added_msg = bob2.wait_for_incoming_msg()
    assert member_added_msg.get_snapshot().text == "You joined the channel."

    bob2_chat = get_broadcast(bob2)

    # After Bob left, only Alice will be left in Bob's memberlist
    while len(bob2_chat.get_contacts()) != 1:
        bob2.wait_for_event(EventType.CHAT_MODIFIED)

    check_account(bob2, bob2.create_contact(alice), inviter_side=False)


def test_immediate_autodelete(acfactory, direct_imap, log):
    ac1, ac2 = acfactory.get_online_accounts(2)

    # "1" means delete immediately, while "0" means do not delete
    ac2.set_config("delete_server_after", "1")

    log.section("ac1: create chat with ac2")
    chat1 = ac1.create_chat(ac2)
    ac2.create_chat(ac1)

    log.section("ac1: send message to ac2")
    sent_msg = chat1.send_text("hello")

    msg = ac2.wait_for_incoming_msg()
    assert msg.get_snapshot().text == "hello"

    log.section("ac2: wait for close/expunge on autodelete")
    ac2.wait_for_event(EventType.IMAP_MESSAGE_DELETED)
    while True:
        event = ac2.wait_for_event()
        if event.kind == EventType.INFO and "Close/expunge succeeded." in event.msg:
            break

    log.section("ac2: check that message was autodeleted on server")
    ac2_direct_imap = direct_imap(ac2)
    assert len(ac2_direct_imap.get_all_messages()) == 0

    log.section("ac2: Mark deleted message as seen and check that read receipt arrives")
    msg.mark_seen()
    ev = ac1.wait_for_event(EventType.MSG_READ)
    assert ev.chat_id == chat1.id
    assert ev.msg_id == sent_msg.id


def test_background_fetch(acfactory, dc):
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1.stop_io()

    ac1_chat = ac1.create_chat(ac2)

    ac2_chat = ac2.create_chat(ac1)
    ac2_chat.send_text("Hello!")

    while True:
        dc.background_fetch(300)
        messages = ac1_chat.get_messages()
        snapshot = messages[-1].get_snapshot()
        if snapshot.text == "Hello!":
            break

    # Stopping background fetch immediately after starting
    # does not result in any errors.
    background_fetch_future = dc.background_fetch.future(300)
    dc.stop_background_fetch()
    background_fetch_future()

    # Starting background fetch with zero timeout is ok,
    # it should terminate immediately.
    dc.background_fetch(0)

    # Background fetch can still be used to send and receive messages.
    ac2_chat.send_text("Hello again!")

    while True:
        dc.background_fetch(300)
        messages = ac1_chat.get_messages()
        snapshot = messages[-1].get_snapshot()
        if snapshot.text == "Hello again!":
            break


def test_message_exists(acfactory):
    ac1, ac2 = acfactory.get_online_accounts(2)
    chat = ac1.create_chat(ac2)
    message1 = chat.send_text("Hello!")
    message2 = chat.send_text("Hello again!")
    assert message1.exists()
    assert message2.exists()

    ac1.delete_messages([message1])
    assert not message1.exists()
    assert message2.exists()

    # There is no error when checking if
    # the message exists for deleted account.
    ac1.remove()
    assert not message1.exists()
    assert not message2.exists()


def test_synchronize_member_list_on_group_rejoin(acfactory, log):
    """
    Test that user recreates group member list when it joins the group again.
    ac1 creates a group with two other accounts: ac2 and ac3
    Then it removes ac2, removes ac3 and adds ac2 back.
    ac2 did not see that ac3 is removed, so it should rebuild member list from scratch.
    """
    log.section("setting up accounts, accepted with each other")
    ac1, ac2, ac3 = accounts = acfactory.get_online_accounts(3)

    log.section("ac1: creating group chat with 2 other members")
    chat = ac1.create_group("title1")
    chat.add_contact(ac2)
    chat.add_contact(ac3)

    log.section("ac1: send message to new group chat")
    msg = chat.send_text("hello")
    assert chat.num_contacts() == 3

    log.section("checking that the chat arrived correctly")
    for ac in accounts[1:]:
        msg = ac.wait_for_incoming_msg().get_snapshot()
        assert msg.text == "hello"
        assert msg.chat.num_contacts() == 3
        msg.chat.accept()

    log.section("ac1: removing ac2")
    chat.remove_contact(ac2)

    log.section("ac2: wait for a message about removal from the chat")
    ac2.wait_for_incoming_msg()
    log.section("ac1: removing ac3")
    chat.remove_contact(ac3)

    log.section("ac1: adding ac2 back")
    chat.add_contact(ac2)

    log.section("ac2: check that ac3 is removed")
    msg = ac2.wait_for_incoming_msg()

    assert chat.num_contacts() == 2
    assert msg.get_snapshot().chat.num_contacts() == 2
