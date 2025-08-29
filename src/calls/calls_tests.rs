use super::*;
use crate::config::Config;
use crate::test_utils::{TestContext, TestContextManager, sync};

async fn setup_call() -> Result<(
    TestContext, // Alice's 1st device
    TestContext, // Alice's 2nd device
    Message,     // Call message from view of Alice's 1st device
    TestContext, // Bob's 1st device
    TestContext, // Bob's 2nd device
    Message,     // Call message from view of Bob
    Message,     // Call message from view of Bob's 2nd device
)> {
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
    let alice_call = Message::load_from_db(&alice, sent1.sender_msg_id).await?;
    assert_eq!(sent1.sender_msg_id, test_msg_id);
    assert!(alice_call.is_info());
    assert_eq!(alice_call.get_info_type(), SystemMessage::OutgoingCall);
    let info = alice.load_call_by_id(alice_call.id).await?;
    assert!(!info.is_accepted);
    assert_eq!(info.place_call_info, "place_info");

    let alice2_call = alice2.recv_msg(&sent1).await;
    assert!(alice2_call.is_info());
    assert_eq!(alice2_call.get_info_type(), SystemMessage::OutgoingCall);
    let info = alice2.load_call_by_id(alice2_call.id).await?;
    assert!(!info.is_accepted);
    assert_eq!(info.place_call_info, "place_info");

    // Bob receives the message referring to the call on two devices;
    // it is an incoming call from the view of Bob
    let bob_call = bob.recv_msg(&sent1).await;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::IncomingCall { .. }))
        .await;
    assert!(bob_call.is_info());
    assert_eq!(bob_call.get_info_type(), SystemMessage::IncomingCall);
    let info = bob.load_call_by_id(bob_call.id).await?;
    assert!(!info.is_accepted);
    assert_eq!(info.place_call_info, "place_info");

    let bob2_call = bob2.recv_msg(&sent1).await;
    assert!(bob2_call.is_info());
    assert_eq!(bob2_call.get_info_type(), SystemMessage::IncomingCall);
    let info = bob2.load_call_by_id(bob2_call.id).await?;
    assert!(!info.is_accepted);
    assert_eq!(info.place_call_info, "place_info");

    Ok((alice, alice2, alice_call, bob, bob2, bob_call, bob2_call))
}

async fn accept_call() -> Result<(
    TestContext,
    TestContext,
    Message,
    TestContext,
    TestContext,
    Message,
)> {
    let (alice, alice2, alice_call, bob, bob2, bob_call, bob2_call) = setup_call().await?;

    // Bob accepts the incoming call, this does not add an additional message to the chat
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

    bob2.recv_msg(&sent2).await;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::IncomingCallAccepted { .. }))
        .await;
    let info = bob2.load_call_by_id(bob2_call.id).await?;
    assert!(!info.is_accepted); // "accepted" is only true on the device that does the call

    // Alice receives the acceptance message
    alice.recv_msg(&sent2).await;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::OutgoingCallAccepted { .. }))
        .await;
    let info = alice.load_call_by_id(alice_call.id).await?;
    assert!(info.is_accepted);
    assert_eq!(info.place_call_info, "place_info");
    assert_eq!(info.accept_call_info, "accepted_info");

    alice2.recv_msg(&sent2).await;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::OutgoingCallAccepted { .. }))
        .await;

    Ok((alice, alice2, alice_call, bob, bob2, bob_call))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_accept_call_callee_ends() -> Result<()> {
    // Alice calls Bob, Bob accepts
    let (alice, alice2, _alice_call, bob, bob2, bob_call) = accept_call().await?;

    // Bob has accepted the call and also ends it
    bob.end_call(bob_call.id).await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = bob.pop_sent_msg().await;

    bob2.recv_msg(&sent3).await;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Alice receives the ending message
    alice.recv_msg(&sent3).await;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    alice2.recv_msg(&sent3).await;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_accept_call_caller_ends() -> Result<()> {
    // Alice calls Bob, Bob accepts
    let (alice, alice2, _alice_call, bob, bob2, bob_call) = accept_call().await?;

    // Bob has accepted the call but Alice ends it
    alice.end_call(bob_call.id).await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = alice.pop_sent_msg().await;

    alice2.recv_msg(&sent3).await;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Bob receives the ending message
    bob.recv_msg(&sent3).await;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    bob2.recv_msg(&sent3).await;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_callee_rejects_call() -> Result<()> {
    // Alice calls Bob
    let (_alice, _alice2, _alice_call, bob, bob2, bob_call, _bob2_call) = setup_call().await?;

    // Bob does not want to talk with Alice.
    // To protect Bob's privacy, no message is sent to Alice (who will time out).
    // To let Bob close the call window on all devices, a sync message is used instead.
    bob.end_call(bob_call.id).await?;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    sync(&bob, &bob2).await;
    bob2.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_caller_cancels_call() -> Result<()> {
    // Alice calls Bob
    let (alice, alice2, alice_call, bob, bob2, _bob_call, _bob2_call) = setup_call().await?;

    // Alice changes their mind before Bob picks up
    alice.end_call(alice_call.id).await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;
    let sent3 = alice.pop_sent_msg().await;

    alice2.recv_msg(&sent3).await;
    alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    // Bob receives the ending message
    bob.recv_msg(&sent3).await;
    bob.evtracker
        .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
        .await;

    bob2.recv_msg(&sent3).await;
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
    assert_eq!(call_info.remaining_ring_seconds(), RINGING_SECONDS);

    // call started 5 seconds ago, this is not stale as well
    let call_info = CallInfo {
        msg: Message {
            timestamp_sent: time() - 5,
            ..Default::default()
        },
        ..Default::default()
    };
    assert!(!call_info.is_stale_call());
    assert_eq!(call_info.remaining_ring_seconds(), RINGING_SECONDS - 5);

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
    let (alice, _alice2, alice_call, _bob, _bob2, _bob_call, _bob2_call) = setup_call().await?;
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
    let (alice, _alice2, alice_call, _bob, _bob2, _bob_call, _bob2_call) = setup_call().await?;

    let call_info = alice.load_call_by_id(alice_call.id).await?;
    call_info.update_text(&alice, "foo bar").await?;

    let alice_call = Message::load_from_db(&alice, alice_call.id).await?;
    assert_eq!(alice_call.get_text(), "foo bar");

    Ok(())
}
