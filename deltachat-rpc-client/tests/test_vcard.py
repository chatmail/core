def test_vcard(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_contact_charlie = alice.create_contact("charlie@example.org", "Charlie")

    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_contact(alice_contact_charlie)

    event = bob.wait_for_incoming_msg_event()
    message = bob.get_message_by_id(event.msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.vcard_contact
    assert snapshot.vcard_contact.addr == "charlie@example.org"
