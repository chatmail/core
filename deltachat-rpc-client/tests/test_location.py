def test_set_location(dc, acfactory) -> None:
    # Try setting location without any accounts.
    assert not dc.set_location(1.0, 2.0, 0.1)

    # Create one account that does not stream,
    # set location.
    acfactory.new_configured_account()
    assert not dc.set_location(3.0, 4.0, 0.1)


def test_send_locations_to_chat(dc, acfactory):
    alice, bob = acfactory.get_online_accounts(2)

    assert not alice.is_sending_locations()
    alice_chat_bob = alice.create_chat(bob)
    assert not alice_chat_bob.is_sending_locations()

    # Test starting and stopping location streaming in a chat.
    alice_chat_bob.send_locations(3600)
    assert alice.is_sending_locations()
    assert alice_chat_bob.is_sending_locations()
    alice_chat_bob.send_locations(0)
    assert not alice.is_sending_locations()
    assert not alice_chat_bob.is_sending_locations()

    # Test stop_sending_locations() for all accounts and chats.
    alice_chat_bob.send_locations(3600)
    assert alice.is_sending_locations()
    assert alice_chat_bob.is_sending_locations()
    dc.stop_sending_locations()
    assert not alice.is_sending_locations()
    assert not alice_chat_bob.is_sending_locations()
