from deltachat_rpc_client import EventType, Message


def test_calls(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    place_call_info = "offer"
    accept_call_info = "answer"

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    bob.create_chat(alice)  # Accept the chat so incoming call causes a notification.
    outgoing_call_message = alice_chat_bob.place_outgoing_call(place_call_info, has_video_initially=True)
    assert outgoing_call_message.get_call_info().state.kind == "Alerting"

    incoming_call_event = bob.wait_for_event(EventType.INCOMING_CALL)
    assert incoming_call_event.place_call_info == place_call_info
    assert incoming_call_event.has_video
    incoming_call_message = Message(bob, incoming_call_event.msg_id)
    assert incoming_call_message.get_call_info().state.kind == "Alerting"
    assert incoming_call_message.get_call_info().has_video

    incoming_call_message.accept_incoming_call(accept_call_info)
    assert incoming_call_message.get_call_info().sdp_offer == place_call_info
    assert incoming_call_message.get_call_info().state.kind == "Active"
    outgoing_call_accepted_event = alice.wait_for_event(EventType.OUTGOING_CALL_ACCEPTED)
    assert outgoing_call_accepted_event.accept_call_info == accept_call_info
    assert outgoing_call_message.get_call_info().state.kind == "Active"

    outgoing_call_message.end_call()
    assert outgoing_call_message.get_call_info().state.kind == "Completed"

    end_call_event = bob.wait_for_event(EventType.CALL_ENDED)
    assert end_call_event.msg_id == outgoing_call_message.id
    assert incoming_call_message.get_call_info().state.kind == "Completed"


def test_video_call(acfactory) -> None:
    # Example from <https://datatracker.ietf.org/doc/rfc9143/>
    # with `s= ` replaced with `s=-`.
    #
    # `s=` cannot be empty according to RFC 3264,
    # so it is more clear as `s=-`.

    alice, bob = acfactory.get_online_accounts(2)

    bob.create_chat(alice)  # Accept the chat so incoming call causes a notification.
    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.place_outgoing_call("offer", has_video_initially=True)

    incoming_call_event = bob.wait_for_event(EventType.INCOMING_CALL)
    assert incoming_call_event.place_call_info == "offer"
    assert incoming_call_event.has_video

    incoming_call_message = Message(bob, incoming_call_event.msg_id)
    assert incoming_call_message.get_call_info().has_video


def test_audio_call(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    bob.create_chat(alice)  # Accept the chat so incoming call causes a notification.
    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.place_outgoing_call("offer", has_video_initially=False)

    incoming_call_event = bob.wait_for_event(EventType.INCOMING_CALL)
    assert incoming_call_event.place_call_info == "offer"
    assert not incoming_call_event.has_video

    incoming_call_message = Message(bob, incoming_call_event.msg_id)
    assert not incoming_call_message.get_call_info().has_video


def test_ice_servers(acfactory) -> None:
    alice = acfactory.get_online_account()

    ice_servers = alice.ice_servers()
    assert len(ice_servers) == 1


def test_no_contact_request_call(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.place_outgoing_call("offer", has_video_initially=True)
    alice_chat_bob.send_text("Hello!")

    # Notification for "Hello!" message should arrive
    # without the call ringing.
    while True:
        event = bob.wait_for_event()

        # There should be no incoming call notification.
        assert event.kind != EventType.INCOMING_CALL

        if event.kind == EventType.MSGS_CHANGED:
            msg = bob.get_message_by_id(event.msg_id)
            if msg.get_snapshot().text == "Hello!":
                break


def test_who_can_call_me_nobody(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    # Bob sets "who can call me" to "nobody" (2)
    bob.set_config("who_can_call_me", "2")

    # Bob even accepts Alice in advance so the chat does not appear as contact request.
    bob.create_chat(alice)

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.place_outgoing_call("offer", has_video_initially=True)
    alice_chat_bob.send_text("Hello!")

    # Notification for "Hello!" message should arrive
    # without the call ringing.
    while True:
        event = bob.wait_for_event()

        # There should be no incoming call notification.
        assert event.kind != EventType.INCOMING_CALL

        if event.kind == EventType.INCOMING_MSG:
            msg = bob.get_message_by_id(event.msg_id)
            if msg.get_snapshot().text == "Hello!":
                break


def test_who_can_call_me_everybody(acfactory) -> None:
    """Test that if "who can call me" setting is set to "everybody", calls arrive even in contact request chats."""
    alice, bob = acfactory.get_online_accounts(2)

    # Bob sets "who can call me" to "nobody" (0)
    bob.set_config("who_can_call_me", "0")

    alice_chat_bob = alice.create_chat(bob)
    alice_chat_bob.place_outgoing_call("offer", has_video_initially=True)
    incoming_call_event = bob.wait_for_event(EventType.INCOMING_CALL)

    incoming_call_message = Message(bob, incoming_call_event.msg_id)

    # Even with the call arriving, the chat is still in the contact request mode.
    incoming_chat = incoming_call_message.get_snapshot().chat
    assert incoming_chat.get_basic_snapshot().is_contact_request
