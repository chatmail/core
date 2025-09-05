use super::*;
use crate::config::Config;
use crate::test_utils::{TestContext, TestContextManager, sync};

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
        .place_outgoing_call(alice_chat.id, "place_info".to_string())
        .await?;
    let sent1 = alice.pop_sent_msg().await;
    assert_eq!(sent1.sender_msg_id, test_msg_id);
    let alice_call = Message::load_from_db(&alice, sent1.sender_msg_id).await?;
    let alice2_call = alice2.recv_msg(&sent1).await;
    for (t, m) in [(&alice, &alice_call), (&alice2, &alice2_call)] {
        assert!(!m.is_info());
        assert_eq!(m.viewtype, Viewtype::Call);
        let info = t.load_call_by_id(m.id).await?;
        assert!(!info.is_incoming);
        assert!(!info.is_accepted);
        assert_eq!(info.place_call_info, "place_info");
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
        assert!(info.is_incoming);
        assert!(!info.is_accepted);
        assert_eq!(info.place_call_info, "place_info");
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
    bob.accept_incoming_call(bob_call.id, "accepted_info".to_string())
        .await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::IncomingCallAccepted { .. }))
        .await;
    let sent2 = bob.pop_sent_msg().await;
    let info = bob.load_call_by_id(bob_call.id).await?;
    assert!(info.is_accepted);
    assert_eq!(info.place_call_info, "place_info");
    assert_eq!(info.accept_call_info, "accepted_info");

    bob2.recv_msg_trash(&sent2).await;
    assert_eq!(
        Message::load_from_db(&bob, bob_call.id).await?.text,
        "Call accepted"
    );
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::IncomingCallAccepted { .. }))
        .await;
    let info = bob2.load_call_by_id(bob2_call.id).await?;
    assert!(!info.is_accepted); // "accepted" is only true on the device that does the call

    // Alice receives the acceptance message
    alice.recv_msg_trash(&sent2).await;
    assert_eq!(
        Message::load_from_db(&alice, alice_call.id).await?.text,
        "Call accepted"
    );
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::OutgoingCallAccepted { .. }))
        .await;
    let info = alice.load_call_by_id(alice_call.id).await?;
    assert!(info.is_accepted);
    assert_eq!(info.place_call_info, "place_info");
    assert_eq!(info.accept_call_info, "accepted_info");

    alice2.recv_msg_trash(&sent2).await;
    assert_eq!(
        Message::load_from_db(&alice2, alice2_call.id).await?.text,
        "Call accepted"
    );
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

async fn assert_is_call_ended(t: &TestContext, call_id: MsgId) -> Result<()> {
    assert_eq!(Message::load_from_db(t, call_id).await?.text, "Call ended");
    Ok(())
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
    assert_is_call_ended(&bob, bob_call.id).await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = bob.pop_sent_msg().await;

    bob2.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&bob2, bob2_call.id).await?;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Alice receives the ending message
    alice.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&alice, alice_call.id).await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    alice2.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&alice2, alice2_call.id).await?;
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
        alice2,
        alice2_call,
        bob,
        bob2,
        bob_call,
        bob2_call,
        ..
    } = accept_call().await?;

    // Bob has accepted the call but Alice ends it
    alice.end_call(bob_call.id).await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = alice.pop_sent_msg().await;

    alice2.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&alice2, alice2_call.id).await?;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Bob receives the ending message
    bob.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&bob, bob_call.id).await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    bob2.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&bob2, bob2_call.id).await?;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_callee_rejects_call() -> Result<()> {
    // Alice calls Bob
    let CallSetup {
        bob,
        bob2,
        bob_call,
        bob2_call,
        ..
    } = setup_call().await?;

    // Bob does not want to talk with Alice.
    // To protect Bob's privacy, no message is sent to Alice (who will time out).
    // To let Bob close the call window on all devices, a sync message is used instead.
    bob.end_call(bob_call.id).await?;
    assert_is_call_ended(&bob, bob_call.id).await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    sync(&bob, &bob2).await;
    assert_is_call_ended(&bob2, bob2_call.id).await?;
    bob2.evtracker
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
    assert_is_call_ended(&alice, alice_call.id).await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = alice.pop_sent_msg().await;

    alice2.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&alice2, alice2_call.id).await?;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Bob receives the ending message
    bob.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&bob, bob_call.id).await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    bob2.recv_msg_trash(&sent3).await;
    assert_is_call_ended(&bob2, bob2_call.id).await?;
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
    assert!(!call_info.is_stale_call());
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
    assert!(!call_info.is_stale_call());
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
    assert!(call_info.is_stale_call());
    assert_eq!(call_info.remaining_ring_seconds(), 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mark_call_as_accepted() -> Result<()> {
    let CallSetup {
        alice, alice_call, ..
    } = setup_call().await?;
    assert!(!alice_call.is_call_accepted()?);

    let mut alice_call = Message::load_from_db(&alice, alice_call.id).await?;
    assert!(!alice_call.is_call_accepted()?);
    alice_call
        .mark_call_as_accepted(&alice, "accepted_info".to_string())
        .await?;
    assert!(alice_call.is_call_accepted()?);

    let alice_call = Message::load_from_db(&alice, alice_call.id).await?;
    assert!(alice_call.is_call_accepted()?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_udpate_call_text() -> Result<()> {
    let CallSetup {
        alice, alice_call, ..
    } = setup_call().await?;

    let call_info = alice.load_call_by_id(alice_call.id).await?;
    call_info.update_text(&alice, "foo bar").await?;

    let alice_call = Message::load_from_db(&alice, alice_call.id).await?;
    assert_eq!(alice_call.get_text(), "foo bar");

    Ok(())
}
