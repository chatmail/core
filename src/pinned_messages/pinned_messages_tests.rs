use super::*;
use crate::chat::{ChatItem, add_info_msg, create_broadcast, get_chat_msgs};
use crate::config::Config;
use crate::ephemeral;
use crate::message;
use crate::securejoin::get_securejoin_qr;
use crate::test_utils::{TestContext, TestContextManager, sync};
use crate::tools::{SystemTime, time};
use std::time::Duration;

/// Waits for a PinnedMessagesChanged for a given `chat_id`.
///
/// Panics if event arrives for the wrong `chat_id`.
async fn expect_pinned_message_event(context: &TestContext, chat_id: ChatId) {
    let EventType::PinnedMessagesChanged {
        chat_id: event_chat_id,
    } = context
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::PinnedMessagesChanged { .. }))
        .await
    else {
        unreachable!();
    };
    assert_eq!(event_chat_id, chat_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pinned_messages() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await; // Alice's second device
    let bob = &tcm.bob().await;

    alice.set_config_bool(Config::SyncMsgs, true).await?;
    alice2.set_config_bool(Config::SyncMsgs, true).await?;

    // Alice creates all chat types upfront, with Bob as member if possible
    let single_chat_id = alice.create_chat(bob).await.id;
    let group_chat_id = alice.create_group_with_members("Group", &[bob]).await;
    let broadcast_chat_id = create_broadcast(alice, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(broadcast_chat_id)).await?;
    tcm.exec_securejoin_qr(bob, alice, &qr).await;
    let self_chat_id = alice.get_self_chat().await.id;
    sync(alice, alice2).await;

    for alice_chat_id in [
        single_chat_id,
        group_chat_id,
        broadcast_chat_id,
        self_chat_id,
    ] {
        let pinned = get_pinned_messages(alice, alice_chat_id).await?;
        assert!(pinned.is_empty());

        // Alice sends message "Foo" and pins it
        let sent1 = alice.send_text(alice_chat_id, "Foo").await;
        let msg1 = sent1.load_from_db().await;
        assert!(!msg1.is_pinned());

        set_pinned_state(alice, msg1.id, true).await?;
        let sent2 = alice.pop_sent_msg().await;
        expect_pinned_message_event(alice, msg1.chat_id).await;
        assert!(sent1.load_from_db().await.is_pinned());

        let info_msg = sent2.load_from_db().await;
        assert!(info_msg.is_info());
        assert!(!info_msg.hidden);
        assert_eq!(info_msg.get_info_type(), SystemMessage::MessagePinned);
        assert!(info_msg.get_info_contact_id(alice).await?.is_none()); // contact not needed, tapping shall jump to message

        let pinned = get_pinned_messages(alice, alice_chat_id).await?;
        assert_eq!(pinned.len(), 1);
        assert_eq!(pinned[0], msg1.id);

        // Pinning an info message does not work
        assert!(set_pinned_state(alice, info_msg.id, true).await.is_err());

        // Unpin the initially pinned message.
        // Before, send another message "Bar". To test, no visible info message is added this time,
        let sent3 = alice.send_text(alice_chat_id, "Bar").await;

        set_pinned_state(alice, msg1.id, false).await?;
        let sent4 = alice.pop_sent_msg().await;
        assert!(!sent1.load_from_db().await.is_pinned());
        expect_pinned_message_event(alice, msg1.chat_id).await;

        let pinned = get_pinned_messages(alice, alice_chat_id).await?;
        assert!(pinned.is_empty());

        let msg3 = sent3.load_from_db().await;
        assert!(!msg3.is_info());
        assert!(!msg3.is_pinned());
        assert_eq!(alice.get_last_msg_id_in(msg3.chat_id).await, msg3.id); // last message is still "Bar", not an info message

        if alice_chat_id != self_chat_id {
            // Bob receives message "Foo"
            let msg1 = bob.recv_msg(&sent1).await;
            assert!(!msg1.is_pinned());
            let pinned = get_pinned_messages(bob, msg1.chat_id).await?;
            assert!(pinned.is_empty());

            // Bob receives info message to pin "Foo"
            bob.recv_msg(&sent2).await;
            expect_pinned_message_event(bob, msg1.chat_id).await;
            assert!(Message::load_from_db(bob, msg1.id).await?.is_pinned());

            let pinned = get_pinned_messages(bob, msg1.chat_id).await?;
            assert_eq!(pinned.len(), 1);
            assert_eq!(pinned[0], msg1.id);

            let info_msg =
                Message::load_from_db(bob, bob.get_last_msg_id_in(msg1.chat_id).await).await?;
            assert!(info_msg.is_info());
            assert!(!info_msg.hidden);
            assert_eq!(info_msg.get_info_type(), SystemMessage::MessagePinned);
            assert!(info_msg.get_info_contact_id(bob).await?.is_none());

            // Bob receives message "Bar" and hidden message to unpin message "Foo"
            bob.recv_msg(&sent3).await;
            bob.recv_msg_trash(&sent4).await;
            expect_pinned_message_event(bob, msg1.chat_id).await;
            assert!(!Message::load_from_db(bob, msg1.id).await?.is_pinned());

            let pinned = get_pinned_messages(bob, msg1.chat_id).await?;
            assert!(pinned.is_empty());

            let no_info_msg =
                Message::load_from_db(bob, bob.get_last_msg_id_in(msg1.chat_id).await).await?;
            assert!(!no_info_msg.is_info());
            assert_eq!(no_info_msg.text, "Bar");
        }

        // Alice's second device receives all four messages and ends up in the same state
        let msg1 = alice2.recv_msg(&sent1).await;
        alice2.recv_msg(&sent2).await;
        expect_pinned_message_event(alice2, msg1.chat_id).await;
        assert!(Message::load_from_db(alice2, msg1.id).await?.is_pinned());

        alice2.recv_msg(&sent3).await;
        alice2.recv_msg_trash(&sent4).await;
        expect_pinned_message_event(alice2, msg1.chat_id).await;
        assert!(!Message::load_from_db(alice2, msg1.id).await?.is_pinned());

        let no_info_msg =
            Message::load_from_db(alice2, alice2.get_last_msg_id_in(msg1.chat_id).await).await?;
        assert!(!no_info_msg.is_info());
        assert_eq!(no_info_msg.text, "Bar");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_pinned_messages_order() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let chat_id = alice.get_self_chat().await.id;
    let boilerplate_msg_count = get_chat_msgs(alice, chat_id).await?.len();

    // create three messages, sent1 and sent2 have different timestamp, sent2 and sent3 may differ by ID only
    let sent1 = alice.send_text(chat_id, "1").await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let sent2 = alice.send_text(chat_id, "2").await;
    let sent3 = alice.send_text(chat_id, "3").await;

    // get_chat_msgs() start with the oldest message
    let chat_msgs = get_chat_msgs(alice, chat_id).await?;
    let msg_ids: Vec<_> = chat_msgs
        .into_iter()
        .filter_map(|item| match item {
            ChatItem::Message { msg_id } => Some(msg_id),
            ChatItem::DayMarker { .. } => None,
        })
        .collect();
    assert_eq!(
        &msg_ids[boilerplate_msg_count..],
        &[
            sent1.sender_msg_id,
            sent2.sender_msg_id,
            sent3.sender_msg_id
        ]
    );

    // get_pinned_messages() has the same order, also starting with the oldest message
    set_pinned_state(alice, sent1.sender_msg_id, true).await?;
    set_pinned_state(alice, sent2.sender_msg_id, true).await?;
    set_pinned_state(alice, sent3.sender_msg_id, true).await?;
    let pinned = get_pinned_messages(alice, chat_id).await?;
    assert_eq!(pinned.len(), 3);
    assert_eq!(pinned[0], sent1.sender_msg_id);
    assert_eq!(pinned[1], sent2.sender_msg_id);
    assert_eq!(pinned[2], sent3.sender_msg_id);

    // order of pinning does not affect the order of pinned messages.
    // this is to keep scrolling direction of chat bubbles and pinned banner scrollbar in sync,
    // and not jumping wildly around.
    // this is also what most other messengers are doing.
    set_pinned_state(alice, sent1.sender_msg_id, false).await?;
    set_pinned_state(alice, sent2.sender_msg_id, false).await?;
    set_pinned_state(alice, sent3.sender_msg_id, false).await?;
    let pinned = get_pinned_messages(alice, chat_id).await?;
    assert_eq!(pinned.len(), 0);

    set_pinned_state(alice, sent3.sender_msg_id, true).await?;
    set_pinned_state(alice, sent2.sender_msg_id, true).await?;
    set_pinned_state(alice, sent1.sender_msg_id, true).await?;
    let pinned = get_pinned_messages(alice, chat_id).await?;
    assert_eq!(pinned.len(), 3);
    assert_eq!(pinned[0], sent1.sender_msg_id);
    assert_eq!(pinned[1], sent2.sender_msg_id);
    assert_eq!(pinned[2], sent3.sender_msg_id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_handle_pinned_state_from_wire() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let chat_id = alice.get_self_chat().await.id;

    let sent1 = alice.send_text(chat_id, "pinnable").await;
    let msg1 = sent1.load_from_db().await;
    assert!(is_pinnable(&msg1));
    assert!(
        handle_pinned_state_from_wire(alice, &msg1, true)
            .await
            .is_ok()
    );

    // For not-pinnable messages, handle_pinned_state_from_wire() logs a warning and returns "ok".
    // otherwise if there is an incompatibility in which messages are treated as "pinnable",
    // this error will bubble up and user will get a device message saying "please report a bug".
    let msg2_id = add_info_msg(alice, chat_id, "not pinnable").await?;
    let msg2 = Message::load_from_db(alice, msg2_id).await?;
    assert!(!is_pinnable(&msg2));
    assert!(
        handle_pinned_state_from_wire(alice, &msg2, true)
            .await
            .is_ok()
    );
    alice.assert_warn("Message is not pinnable").await;

    Ok(())
}

/// Tests that disappearing pinned message expires and emits `PinnedMessagesChanged` event.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_pinned_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat_id = alice.create_chat_id(bob).await;

    // Alice sends ephemeral timer in single chat with Bob.
    alice_chat_id
        .set_ephemeral_timer(alice, ephemeral::Timer::from_u32(60))
        .await?;
    let sent = alice.pop_sent_msg().await;
    bob.recv_msg(&sent).await;

    // Alice sends "Hello!" message to Bob.
    let bob_msg = tcm.send_recv_accept(alice, bob, "Hello!").await;
    let bob_chat_id = bob_msg.chat_id;

    // Bob reads the message, so the timer starts.
    message::markseen_msgs(bob, vec![bob_msg.id]).await?;

    // Bob pins "Hello!" message received from Alice.
    set_pinned_state(bob, bob_msg.id, true).await?;
    expect_pinned_message_event(bob, bob_chat_id).await;
    let pinned = get_pinned_messages(bob, bob_chat_id).await?;
    assert_eq!(pinned.len(), 1);

    // Wait until the message expires.
    SystemTime::shift(Duration::from_secs(100));
    ephemeral::delete_expired_messages(bob, time()).await?;

    expect_pinned_message_event(bob, bob_chat_id).await;
    let pinned = get_pinned_messages(bob, bob_chat_id).await?;
    assert!(pinned.is_empty());

    Ok(())
}

/// Tests that `PinnedMessagesChanged` event is emitted when pinned message is deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_pinned_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let bob_msg = tcm.send_recv_accept(alice, bob, "Hello!").await;
    let bob_chat_id = bob_msg.chat_id;

    // Bob pins "Hello!" message received from Alice.
    set_pinned_state(bob, bob_msg.id, true).await?;
    expect_pinned_message_event(bob, bob_chat_id).await;
    let pinned = get_pinned_messages(bob, bob_chat_id).await?;
    assert_eq!(pinned.len(), 1);

    message::delete_msgs(bob, &[bob_msg.id]).await?;
    expect_pinned_message_event(bob, bob_chat_id).await;
    let pinned = get_pinned_messages(bob, bob_chat_id).await?;
    assert!(pinned.is_empty());

    Ok(())
}
