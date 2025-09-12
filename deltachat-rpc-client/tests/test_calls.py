from deltachat_rpc_client import EventType, Message


def test_calls(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    place_call_info = "offer"
    accept_call_info = "answer"

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    outgoing_call_message = alice_chat_bob.place_outgoing_call(place_call_info)

    incoming_call_event = bob.wait_for_event(EventType.INCOMING_CALL)
    assert incoming_call_event.place_call_info == place_call_info
    incoming_call_message = Message(bob, incoming_call_event.msg_id)

    incoming_call_message.accept_incoming_call(accept_call_info)
    outgoing_call_accepted_event = alice.wait_for_event(EventType.OUTGOING_CALL_ACCEPTED)
    assert outgoing_call_accepted_event.accept_call_info == accept_call_info

    outgoing_call_message.end_call()

    end_call_event = bob.wait_for_event(EventType.CALL_ENDED)
    assert end_call_event.msg_id == outgoing_call_message.id
