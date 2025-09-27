from deltachat_rpc_client import EventType, Message


def test_calls(acfactory) -> None:
    alice, bob = acfactory.get_online_accounts(2)

    place_call_info = "offer"
    accept_call_info = "answer"

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    outgoing_call_message = alice_chat_bob.place_outgoing_call(place_call_info)
    assert outgoing_call_message.get_call_info().state.kind == "Alerting"

    incoming_call_event = bob.wait_for_event(EventType.INCOMING_CALL)
    assert incoming_call_event.place_call_info == place_call_info
    assert not incoming_call_event.has_video  # Cannot be parsed as SDP, so false by default
    incoming_call_message = Message(bob, incoming_call_event.msg_id)
    assert incoming_call_message.get_call_info().state.kind == "Alerting"
    assert not incoming_call_message.get_call_info().has_video

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
    place_call_info = """v=0\r
o=alice 2890844526 2890844526 IN IP6 2001:db8::3\r
s=-\r
c=IN IP6 2001:db8::3\r
t=0 0\r
a=group:BUNDLE foo bar\r
\r
m=audio 10000 RTP/AVP 0 8 97\r
b=AS:200\r
a=mid:foo\r
a=rtcp-mux\r
a=rtpmap:0 PCMU/8000\r
a=rtpmap:8 PCMA/8000\r
a=rtpmap:97 iLBC/8000\r
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r
\r
m=video 10002 RTP/AVP 31 32\r
b=AS:1000\r
a=mid:bar\r
a=rtcp-mux\r
a=rtpmap:31 H261/90000\r
a=rtpmap:32 MPV/90000\r
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r
"""

    alice, bob = acfactory.get_online_accounts(2)

    alice_contact_bob = alice.create_contact(bob, "Bob")
    alice_chat_bob = alice_contact_bob.create_chat()
    alice_chat_bob.place_outgoing_call(place_call_info)

    incoming_call_event = bob.wait_for_event(EventType.INCOMING_CALL)
    assert incoming_call_event.place_call_info == place_call_info
    assert incoming_call_event.has_video

    incoming_call_message = Message(bob, incoming_call_event.msg_id)
    assert incoming_call_message.get_call_info().has_video


def test_ice_servers(acfactory) -> None:
    alice = acfactory.get_online_account()

    ice_servers = alice.ice_servers()
    assert len(ice_servers) == 1
