use super::*;
use crate::config::Config;
use crate::test_utils::{TestContext, TestContextManager};

struct CallSetup {
    pub alice: TestContext,
    pub alice2: TestContext,
    pub alice_call: Message,
    pub alice2_call: Message,
    pub bob: TestContext,
    pub bob2: TestContext,
    pub bob_call: Message,
    pub bob2_call: Message,
}

async fn assert_text(t: &TestContext, call_id: MsgId, text: &str) -> Result<()> {
    assert_eq!(Message::load_from_db(t, call_id).await?.text, text);
    Ok(())
}

// Offer and answer examples from <https://www.rfc-editor.org/rfc/rfc3264>
const PLACE_INFO: &str = "v=0\r\no=alice 2890844526 2890844526 IN IP4 host.anywhere.com\r\ns=-\r\nc=IN IP4 host.anywhere.com\r\nt=0 0\r\nm=audio 62986 RTP/AVP 0 4 18\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:4 G723/8000\r\na=rtpmap:18 G729/8000\r\na=inactive\r\n";
const ACCEPT_INFO: &str = "v=0\r\no=bob 2890844730 2890844731 IN IP4 host.example.com\r\ns=\r\nc=IN IP4 host.example.com\r\nt=0 0\r\nm=audio 54344 RTP/AVP 0 4\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:4 G723/8000\r\na=inactive\r\n";

/// Example from <https://datatracker.ietf.org/doc/rfc9143/>
/// with `s= ` replaced with `s=-`.
///
/// `s=` cannot be empty according to RFC 3264,
/// so it is more clear as `s=-`.
const PLACE_INFO_VIDEO: &str = "v=0\r\no=alice 2890844526 2890844526 IN IP6 2001:db8::3\r\ns=-\r\nc=IN IP6 2001:db8::3\r\nt=0 0\r\na=group:BUNDLE foo bar\r\n\r\nm=audio 10000 RTP/AVP 0 8 97\r\nb=AS:200\r\na=mid:foo\r\na=rtcp-mux\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:97 iLBC/8000\r\na=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\r\nm=video 10002 RTP/AVP 31 32\r\nb=AS:1000\r\na=mid:bar\r\na=rtcp-mux\r\na=rtpmap:31 H261/90000\r\na=rtpmap:32 MPV/90000\r\na=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n";

async fn setup_call() -> Result<CallSetup> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let alice2 = tcm.alice().await;
    let bob = tcm.bob().await;
    let bob2 = tcm.bob().await;
    for t in [&alice, &alice2, &bob, &bob2] {
        t.set_config_bool(Config::SyncMsgs, true).await?;
    }

    // Alice creates a chat with Bob and places an outgoing call there.
    // Alice's other device sees the same message as an outgoing call.
    let alice_chat = alice.create_chat(&bob).await;
    let test_msg_id = alice
        .place_outgoing_call(alice_chat.id, PLACE_INFO.to_string())
        .await?;
    let sent1 = alice.pop_sent_msg().await;
    assert_eq!(sent1.sender_msg_id, test_msg_id);
    let alice_call = Message::load_from_db(&alice, sent1.sender_msg_id).await?;
    let alice2_call = alice2.recv_msg(&sent1).await;
    for (t, m) in [(&alice, &alice_call), (&alice2, &alice2_call)] {
        assert!(!m.is_info());
        assert_eq!(m.viewtype, Viewtype::Call);
        let info = t.load_call_by_id(m.id).await?;
        assert!(!info.is_incoming());
        assert!(!info.is_accepted());
        assert_eq!(info.place_call_info, PLACE_INFO);
        assert_text(t, m.id, "Outgoing call").await?;
    }

    // Bob receives the message referring to the call on two devices;
    // it is an incoming call from the view of Bob
    let bob_call = bob.recv_msg(&sent1).await;
    let bob2_call = bob2.recv_msg(&sent1).await;
    for (t, m) in [(&bob, &bob_call), (&bob2, &bob2_call)] {
        assert!(!m.is_info());
        assert_eq!(m.viewtype, Viewtype::Call);
        t.evtracker
            .get_matching(|evt| matches!(evt, EventType::IncomingCall { .. }))
            .await;
        let info = t.load_call_by_id(m.id).await?;
        assert!(info.is_incoming());
        assert!(!info.is_accepted());
        assert_eq!(info.place_call_info, PLACE_INFO);
        assert_text(t, m.id, "Incoming call").await?;
    }

    Ok(CallSetup {
        alice,
        alice2,
        alice_call,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
    })
}

async fn accept_call() -> Result<CallSetup> {
    let CallSetup {
        alice,
        alice2,
        alice_call,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
    } = setup_call().await?;

    // Bob accepts the incoming call
    bob.accept_incoming_call(bob_call.id, ACCEPT_INFO.to_string())
        .await?;
    assert_text(&bob, bob_call.id, "Incoming call").await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::IncomingCallAccepted { .. }))
        .await;
    let sent2 = bob.pop_sent_msg().await;
    let info = bob.load_call_by_id(bob_call.id).await?;
    assert!(info.is_accepted());
    assert_eq!(info.place_call_info, PLACE_INFO);

    bob2.recv_msg_trash(&sent2).await;
    assert_text(&bob, bob_call.id, "Incoming call").await?;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::IncomingCallAccepted { .. }))
        .await;
    let info = bob2.load_call_by_id(bob2_call.id).await?;
    assert!(info.is_accepted());

    // Alice receives the acceptance message
    alice.recv_msg_trash(&sent2).await;
    assert_text(&alice, alice_call.id, "Outgoing call").await?;
    let ev = alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::OutgoingCallAccepted { .. }))
        .await;
    assert_eq!(
        ev,
        EventType::OutgoingCallAccepted {
            msg_id: alice2_call.id,
            accept_call_info: ACCEPT_INFO.to_string()
        }
    );
    let info = alice.load_call_by_id(alice_call.id).await?;
    assert!(info.is_accepted());
    assert_eq!(info.place_call_info, PLACE_INFO);

    alice2.recv_msg_trash(&sent2).await;
    assert_text(&alice2, alice2_call.id, "Outgoing call").await?;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::OutgoingCallAccepted { .. }))
        .await;

    Ok(CallSetup {
        alice,
        alice2,
        alice_call,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_accept_call_callee_ends() -> Result<()> {
    // Alice calls Bob, Bob accepts
    let CallSetup {
        alice,
        alice_call,
        alice2,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
        ..
    } = accept_call().await?;

    // Bob has accepted the call and also ends it
    bob.end_call(bob_call.id).await?;
    assert_text(&bob, bob_call.id, "Incoming call\n<1 minute").await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = bob.pop_sent_msg().await;

    bob2.recv_msg_trash(&sent3).await;
    assert_text(&bob2, bob2_call.id, "Incoming call\n<1 minute").await?;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Alice receives the ending message
    alice.recv_msg_trash(&sent3).await;
    assert_text(&alice, alice_call.id, "Outgoing call\n<1 minute").await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    alice2.recv_msg_trash(&sent3).await;
    assert_text(&alice2, alice2_call.id, "Outgoing call\n<1 minute").await?;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_accept_call_caller_ends() -> Result<()> {
    // Alice calls Bob, Bob accepts
    let CallSetup {
        alice,
        alice_call,
        alice2,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
        ..
    } = accept_call().await?;

    // Bob has accepted the call but Alice ends it
    alice.end_call(alice_call.id).await?;
    assert_text(&alice, alice_call.id, "Outgoing call\n<1 minute").await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = alice.pop_sent_msg().await;

    alice2.recv_msg_trash(&sent3).await;
    assert_text(&alice2, alice2_call.id, "Outgoing call\n<1 minute").await?;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Bob receives the ending message
    bob.recv_msg_trash(&sent3).await;
    assert_text(&bob, bob_call.id, "Incoming call\n<1 minute").await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    bob2.recv_msg_trash(&sent3).await;
    assert_text(&bob2, bob2_call.id, "Incoming call\n<1 minute").await?;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_callee_rejects_call() -> Result<()> {
    // Alice calls Bob
    let CallSetup {
        alice,
        alice2,
        alice_call,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
        ..
    } = setup_call().await?;

    // Bob has accepted Alice before, but does not want to talk with Alice
    bob_call.chat_id.accept(&bob).await?;
    bob.end_call(bob_call.id).await?;
    assert_text(&bob, bob_call.id, "Declined call").await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = bob.pop_sent_msg().await;

    bob2.recv_msg_trash(&sent3).await;
    assert_text(&bob2, bob2_call.id, "Declined call").await?;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Alice receives decline message
    alice.recv_msg_trash(&sent3).await;
    assert_text(&alice, alice_call.id, "Declined call").await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    alice2.recv_msg_trash(&sent3).await;
    assert_text(&alice2, alice2_call.id, "Declined call").await?;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_caller_cancels_call() -> Result<()> {
    // Alice calls Bob
    let CallSetup {
        alice,
        alice2,
        alice_call,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
        ..
    } = setup_call().await?;

    // Alice changes their mind before Bob picks up
    alice.end_call(alice_call.id).await?;
    assert_text(&alice, alice_call.id, "Cancelled call").await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = alice.pop_sent_msg().await;

    alice2.recv_msg_trash(&sent3).await;
    assert_text(&alice2, alice2_call.id, "Cancelled call").await?;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Bob receives the ending message
    bob.recv_msg_trash(&sent3).await;
    assert_text(&bob, bob_call.id, "Missed call").await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    bob2.recv_msg_trash(&sent3).await;
    assert_text(&bob2, bob2_call.id, "Missed call").await?;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_is_stale_call() -> Result<()> {
    // a call started now is not stale
    let call_info = CallInfo {
        msg: Message {
            timestamp_sent: time(),
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(!call_info.is_stale());
    let remaining_seconds = call_info.remaining_ring_seconds();
    assert!(remaining_seconds == RINGING_SECONDS || remaining_seconds == RINGING_SECONDS - 1);

    // call started 5 seconds ago, this is not stale as well
    let call_info = CallInfo {
        msg: Message {
            timestamp_sent: time() - 5,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(!call_info.is_stale());
    let remaining_seconds = call_info.remaining_ring_seconds();
    assert!(remaining_seconds == RINGING_SECONDS - 5 || remaining_seconds == RINGING_SECONDS - 6);

    // a call started one hour ago is clearly stale
    let call_info = CallInfo {
        msg: Message {
            timestamp_sent: time() - 3600,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(call_info.is_stale());
    assert_eq!(call_info.remaining_ring_seconds(), 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mark_calls() -> Result<()> {
    let CallSetup {
        alice, alice_call, ..
    } = setup_call().await?;

    let mut call_info: CallInfo = alice.load_call_by_id(alice_call.id).await?;
    assert!(!call_info.is_accepted());
    assert!(!call_info.is_ended());
    call_info.mark_as_accepted(&alice).await?;
    assert!(call_info.is_accepted());
    assert!(!call_info.is_ended());

    let mut call_info: CallInfo = alice.load_call_by_id(alice_call.id).await?;
    assert!(call_info.is_accepted());
    assert!(!call_info.is_ended());

    call_info.mark_as_ended(&alice).await?;
    assert!(call_info.is_accepted());
    assert!(call_info.is_ended());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_update_call_text() -> Result<()> {
    let CallSetup {
        alice, alice_call, ..
    } = setup_call().await?;

    let call_info = alice.load_call_by_id(alice_call.id).await?;
    call_info.update_text(&alice, "foo bar").await?;

    let alice_call = Message::load_from_db(&alice, alice_call.id).await?;
    assert_eq!(alice_call.get_text(), "foo bar");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sdp_has_video() {
    assert!(sdp_has_video("foobar").is_err());
    assert_eq!(sdp_has_video(PLACE_INFO).unwrap(), false);
    assert_eq!(sdp_has_video(PLACE_INFO_VIDEO).unwrap(), true);
}
