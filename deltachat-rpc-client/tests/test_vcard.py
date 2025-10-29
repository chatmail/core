def test_vcard(acfactory) -> None:
    alice, bob, fiona = acfactory.get_online_accounts(3)

    bob.create_chat(alice)
    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_contact_charlie = alice.create_contact("charlie@example.org", "Charlie")
    alice_contact_charlie_snapshot = alice_contact_charlie.get_snapshot()
    alice_contact_fiona = alice.create_contact(fiona, "Fiona")
    alice_contact_fiona_snapshot = alice_contact_fiona.get_snapshot()

    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.send_contact(alice_contact_charlie)

    event = bob.wait_for_incoming_msg_event()
    message = bob.get_message_by_id(event.msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.vcard_contact
    assert snapshot.vcard_contact.addr == "charlie@example.org"
    assert snapshot.vcard_contact.color == alice_contact_charlie_snapshot.color

    alice_chat_bob.send_contact(alice_contact_fiona)
    event = bob.wait_for_incoming_msg_event()
    message = bob.get_message_by_id(event.msg_id)
    snapshot = message.get_snapshot()
    assert snapshot.vcard_contact
    assert snapshot.vcard_contact.key
    assert snapshot.vcard_contact.color == alice_contact_fiona_snapshot.color
