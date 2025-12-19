import pytest

from deltachat_rpc_client import EventType
from deltachat_rpc_client.rpc import JsonRpcError


def test_add_second_address(acfactory) -> None:
    account = acfactory.new_configured_account()
    assert len(account.list_transports()) == 1

    # When the first transport is created,
    # mvbox_move and only_fetch_mvbox should be disabled.
    assert account.get_config("mvbox_move") == "0"
    assert account.get_config("only_fetch_mvbox") == "0"
    assert account.get_config("show_emails") == "2"

    qr = acfactory.get_account_qr()
    account.add_transport_from_qr(qr)
    assert len(account.list_transports()) == 2

    account.add_transport_from_qr(qr)
    assert len(account.list_transports()) == 3

    first_addr = account.list_transports()[0]["addr"]
    second_addr = account.list_transports()[1]["addr"]

    # Cannot delete the first address.
    with pytest.raises(JsonRpcError):
        account.delete_transport(first_addr)

    account.delete_transport(second_addr)
    assert len(account.list_transports()) == 2

    # Enabling mvbox_move or only_fetch_mvbox
    # is not allowed when multi-transport is enabled.
    for option in ["mvbox_move", "only_fetch_mvbox"]:
        with pytest.raises(JsonRpcError):
            account.set_config(option, "1")

    with pytest.raises(JsonRpcError):
        account.set_config("show_emails", "0")


@pytest.mark.parametrize("key", ["mvbox_move", "only_fetch_mvbox"])
def test_no_second_transport_with_mvbox(acfactory, key) -> None:
    """Test that second transport cannot be configured if mvbox is used."""
    account = acfactory.new_configured_account()
    assert len(account.list_transports()) == 1

    assert account.get_config("mvbox_move") == "0"
    assert account.get_config("only_fetch_mvbox") == "0"

    qr = acfactory.get_account_qr()
    account.set_config(key, "1")

    with pytest.raises(JsonRpcError):
        account.add_transport_from_qr(qr)


def test_no_second_transport_without_classic_emails(acfactory) -> None:
    """Test that second transport cannot be configured if classic emails are not fetched."""
    account = acfactory.new_configured_account()
    assert len(account.list_transports()) == 1

    assert account.get_config("show_emails") == "2"

    qr = acfactory.get_account_qr()
    account.set_config("show_emails", "0")

    with pytest.raises(JsonRpcError):
        account.add_transport_from_qr(qr)


def test_change_address(acfactory) -> None:
    """Test Alice configuring a second transport and setting it as a primary one."""
    alice, bob = acfactory.get_online_accounts(2)

    bob_addr = bob.get_config("configured_addr")
    bob.create_chat(alice)

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.send_text("Hello!")

    msg1 = bob.wait_for_incoming_msg().get_snapshot()
    sender_addr1 = msg1.sender.get_snapshot().address

    alice.stop_io()
    old_alice_addr = alice.get_config("configured_addr")
    alice_vcard = alice.self_contact.make_vcard()
    assert old_alice_addr in alice_vcard
    qr = acfactory.get_account_qr()
    alice.add_transport_from_qr(qr)
    new_alice_addr = alice.list_transports()[1]["addr"]
    with pytest.raises(JsonRpcError):
        # Cannot use the address that is not
        # configured for any transport.
        alice.set_config("configured_addr", bob_addr)

    # Load old address so it is cached.
    assert alice.get_config("configured_addr") == old_alice_addr
    alice.set_config("configured_addr", new_alice_addr)
    # Make sure that setting `configured_addr` invalidated the cache.
    assert alice.get_config("configured_addr") == new_alice_addr

    alice_vcard = alice.self_contact.make_vcard()
    assert old_alice_addr not in alice_vcard
    assert new_alice_addr in alice_vcard
    with pytest.raises(JsonRpcError):
        alice.delete_transport(new_alice_addr)
    alice.start_io()

    alice_chat_bob.send_text("Hello again!")

    msg2 = bob.wait_for_incoming_msg().get_snapshot()
    sender_addr2 = msg2.sender.get_snapshot().address

    assert msg1.sender == msg2.sender
    assert sender_addr1 != sender_addr2
    assert sender_addr1 == old_alice_addr
    assert sender_addr2 == new_alice_addr


@pytest.mark.parametrize("is_chatmail", ["0", "1"])
def test_mvbox_move_first_transport(acfactory, is_chatmail) -> None:
    """Test that mvbox_move is disabled by default even for non-chatmail accounts.
    Disabling mvbox_move is required to be able to setup a second transport.
    """
    account = acfactory.get_unconfigured_account()

    account.set_config("fix_is_chatmail", "1")
    account.set_config("is_chatmail", is_chatmail)

    # The default value when the setting is unset is "1".
    # This is not changed for compatibility with old databases
    # imported from backups.
    assert account.get_config("mvbox_move") == "1"

    qr = acfactory.get_account_qr()
    account.add_transport_from_qr(qr)

    # Once the first transport is set up,
    # mvbox_move is disabled.
    assert account.get_config("mvbox_move") == "0"
    assert account.get_config("is_chatmail") == is_chatmail


def test_reconfigure_transport(acfactory) -> None:
    """Test that reconfiguring the transport works
    even if settings not supported for multi-transport
    like mvbox_move are enabled."""
    account = acfactory.get_online_account()
    account.set_config("mvbox_move", "1")

    [transport] = account.list_transports()
    account.add_or_update_transport(transport)

    # Reconfiguring the transport should not reset
    # the settings as if when configuring the first transport.
    assert account.get_config("mvbox_move") == "1"


def test_transport_synchronization(acfactory, log) -> None:
    """Test synchronization of transports between devices."""
    ac1, ac2 = acfactory.get_online_accounts(2)
    ac1_clone = ac1.clone()
    ac1_clone.bring_online()

    qr = acfactory.get_account_qr()

    ac1.add_transport_from_qr(qr)
    ac1_clone.wait_for_event(EventType.TRANSPORTS_MODIFIED)
    assert len(ac1.list_transports()) == 2
    assert len(ac1_clone.list_transports()) == 2

    ac1_clone.add_transport_from_qr(qr)
    ac1.wait_for_event(EventType.TRANSPORTS_MODIFIED)
    assert len(ac1.list_transports()) == 3
    assert len(ac1_clone.list_transports()) == 3

    log.section("ac1 clone removes second transport")
    [transport1, transport2, transport3] = ac1_clone.list_transports()
    addr3 = transport3["addr"]
    ac1_clone.delete_transport(transport2["addr"])

    ac1.wait_for_event(EventType.TRANSPORTS_MODIFIED)
    [transport1, transport3] = ac1.list_transports()

    log.section("ac1 changes the primary transport")
    ac1.set_config("configured_addr", transport3["addr"])

    ac1_clone.wait_for_event(EventType.TRANSPORTS_MODIFIED)
    [transport1, transport3] = ac1_clone.list_transports()
    assert ac1_clone.get_config("configured_addr") == addr3

    log.section("ac1 removes the first transport")
    ac1.delete_transport(transport1["addr"])

    ac1_clone.wait_for_event(EventType.TRANSPORTS_MODIFIED)
    [transport3] = ac1_clone.list_transports()
    assert transport3["addr"] == addr3
    assert ac1_clone.get_config("configured_addr") == addr3

    ac2_chat = ac2.create_chat(ac1)
    ac2_chat.send_text("Hello!")

    assert ac1.wait_for_incoming_msg().get_snapshot().text == "Hello!"
    assert ac1_clone.wait_for_incoming_msg().get_snapshot().text == "Hello!"


def test_recognize_self_address(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    bob_chat = bob.create_chat(alice)

    qr = acfactory.get_account_qr()
    alice.add_transport_from_qr(qr)

    new_alice_addr = alice.list_transports()[1]["addr"]
    alice.set_config("configured_addr", new_alice_addr)

    bob_chat.send_text("Hello!")
    msg = alice.wait_for_incoming_msg().get_snapshot()
    assert msg.chat == alice.create_chat(bob)


def test_transport_limit(acfactory) -> None:
    """Test transports limit."""
    account = acfactory.get_online_account()
    qr = acfactory.get_account_qr()

    limit = 5

    for _ in range(1, limit):
        account.add_transport_from_qr(qr)

    assert len(account.list_transports()) == limit

    with pytest.raises(JsonRpcError):
        account.add_transport_from_qr(qr)

    second_addr = account.list_transports()[1]["addr"]
    account.delete_transport(second_addr)

    # test that adding a transport after deleting one works again
    account.add_transport_from_qr(qr)


def test_message_info_imap_urls(acfactory, log) -> None:
    """Test that message info contains IMAP URLs of where the message was received."""
    alice, bob = acfactory.get_online_accounts(2)

    log.section("Alice adds ac1 clone removes second transport")
    qr = acfactory.get_account_qr()
    for i in range(3):
        alice.add_transport_from_qr(qr)
        # Wait for all transports to go IDLE after adding each one.
        for _ in range(i + 1):
            alice.bring_online()

    new_alice_addr = alice.list_transports()[2]["addr"]
    alice.set_config("configured_addr", new_alice_addr)

    # Enable multi-device mode so messages are not deleted immediately.
    alice.set_config("bcc_self", "1")

    # Bob creates chat, learning about Alice's currently selected transport.
    # This is where he will send the message.
    bob_chat = bob.create_chat(alice)

    # Alice changes the transport again.
    alice.set_config("configured_addr", alice.list_transports()[3]["addr"])

    bob_chat.send_text("Hello!")

    msg = alice.wait_for_incoming_msg()
    for alice_transport in alice.list_transports():
        addr = alice_transport["addr"]
        assert (addr == new_alice_addr) == (addr in msg.get_info())
