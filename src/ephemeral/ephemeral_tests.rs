use super::*;
use crate::chat::{
    add_contact_to_chat, marknoticed_chat, remove_contact_from_chat, set_muted, ChatVisibility,
    MuteDuration,
};
use crate::config::Config;
use crate::constants::DC_CHAT_ID_ARCHIVED_LINK;
use crate::download::DownloadState;
use crate::location;
use crate::message::markseen_msgs;
use crate::receive_imf::receive_imf;
use crate::test_utils::{TestContext, TestContextManager};
use crate::timesmearing::MAX_SECONDS_TO_LEND_FROM_FUTURE;
use crate::{
    chat::{self, create_group_chat, send_text_msg, Chat, ChatItem, ProtectionStatus},
    tools::IsNoneOrEmpty,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stock_ephemeral_messages() {
    let context = TestContext::new().await;

    assert_eq!(
        stock_ephemeral_timer_changed(&context, Timer::Disabled, ContactId::SELF).await,
        "You disabled message deletion timer."
    );

    assert_eq!(
        stock_ephemeral_timer_changed(&context, Timer::Enabled { duration: 1 }, ContactId::SELF)
            .await,
        "You set message deletion timer to 1 s."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(&context, Timer::Enabled { duration: 30 }, ContactId::SELF)
            .await,
        "You set message deletion timer to 30 s."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(&context, Timer::Enabled { duration: 60 }, ContactId::SELF)
            .await,
        "You set message deletion timer to 1 minute."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(&context, Timer::Enabled { duration: 90 }, ContactId::SELF)
            .await,
        "You set message deletion timer to 1.5 minutes."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(
            &context,
            Timer::Enabled { duration: 30 * 60 },
            ContactId::SELF
        )
        .await,
        "You set message deletion timer to 30 minutes."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(
            &context,
            Timer::Enabled { duration: 60 * 60 },
            ContactId::SELF
        )
        .await,
        "You set message deletion timer to 1 hour."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(&context, Timer::Enabled { duration: 5400 }, ContactId::SELF)
            .await,
        "You set message deletion timer to 1.5 hours."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(
            &context,
            Timer::Enabled {
                duration: 2 * 60 * 60
            },
            ContactId::SELF
        )
        .await,
        "You set message deletion timer to 2 hours."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(
            &context,
            Timer::Enabled {
                duration: 24 * 60 * 60
            },
            ContactId::SELF
        )
        .await,
        "You set message deletion timer to 1 day."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(
            &context,
            Timer::Enabled {
                duration: 2 * 24 * 60 * 60
            },
            ContactId::SELF
        )
        .await,
        "You set message deletion timer to 2 days."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(
            &context,
            Timer::Enabled {
                duration: 7 * 24 * 60 * 60
            },
            ContactId::SELF
        )
        .await,
        "You set message deletion timer to 1 week."
    );
    assert_eq!(
        stock_ephemeral_timer_changed(
            &context,
            Timer::Enabled {
                duration: 4 * 7 * 24 * 60 * 60
            },
            ContactId::SELF
        )
        .await,
        "You set message deletion timer to 4 weeks."
    );
}

/// Test enabling and disabling ephemeral timer remotely.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_enable_disable() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let chat_alice = alice.create_chat(&bob).await.id;
    let chat_bob = bob.create_chat(&alice).await.id;

    chat_alice
        .set_ephemeral_timer(&alice.ctx, Timer::Enabled { duration: 60 })
        .await?;
    let sent = alice.pop_sent_msg().await;
    bob.recv_msg(&sent).await;
    assert_eq!(
        chat_bob.get_ephemeral_timer(&bob.ctx).await?,
        Timer::Enabled { duration: 60 }
    );

    chat_alice
        .set_ephemeral_timer(&alice.ctx, Timer::Disabled)
        .await?;
    let sent = alice.pop_sent_msg().await;
    bob.recv_msg(&sent).await;
    assert_eq!(
        chat_bob.get_ephemeral_timer(&bob.ctx).await?,
        Timer::Disabled
    );

    Ok(())
}

/// Test that enabling ephemeral timer in unpromoted group does not send a message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_unpromoted() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "Group name").await?;

    // Group is unpromoted, the timer can be changed without sending a message.
    assert!(chat_id.is_unpromoted(&alice).await?);
    chat_id
        .set_ephemeral_timer(&alice, Timer::Enabled { duration: 60 })
        .await?;
    let sent = alice.pop_sent_msg_opt(Duration::from_secs(1)).await;
    assert!(sent.is_none());
    assert_eq!(
        chat_id.get_ephemeral_timer(&alice).await?,
        Timer::Enabled { duration: 60 }
    );

    // Promote the group.
    send_text_msg(&alice, chat_id, "hi!".to_string()).await?;
    assert!(chat_id.is_promoted(&alice).await?);
    let sent = alice.pop_sent_msg_opt(Duration::from_secs(1)).await;
    assert!(sent.is_some());

    chat_id
        .set_ephemeral_timer(&alice.ctx, Timer::Disabled)
        .await?;
    let sent = alice.pop_sent_msg_opt(Duration::from_secs(1)).await;
    assert!(sent.is_some());
    assert_eq!(chat_id.get_ephemeral_timer(&alice).await?, Timer::Disabled);

    Ok(())
}

/// Test that timer is enabled even if the message explicitly enabling the timer is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_enable_lost() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let chat_alice = alice.create_chat(&bob).await.id;
    let chat_bob = bob.create_chat(&alice).await.id;

    // Alice enables the timer.
    chat_alice
        .set_ephemeral_timer(&alice.ctx, Timer::Enabled { duration: 60 })
        .await?;
    assert_eq!(
        chat_alice.get_ephemeral_timer(&alice.ctx).await?,
        Timer::Enabled { duration: 60 }
    );
    // The message enabling the timer is lost.
    let _sent = alice.pop_sent_msg().await;
    assert_eq!(
        chat_bob.get_ephemeral_timer(&bob.ctx).await?,
        Timer::Disabled,
    );

    // Alice sends a text message.
    let mut msg = Message::new(Viewtype::Text);
    chat::send_msg(&alice.ctx, chat_alice, &mut msg).await?;
    let sent = alice.pop_sent_msg().await;

    // Bob receives text message and enables the timer, even though explicit timer update was
    // lost previously.
    bob.recv_msg(&sent).await;
    assert_eq!(
        chat_bob.get_ephemeral_timer(&bob.ctx).await?,
        Timer::Enabled { duration: 60 }
    );

    Ok(())
}

/// Test that Alice replying to the chat without a timer at the same time as Bob enables the
/// timer does not result in disabling the timer on the Bob's side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_timer_rollback() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let chat_alice = alice.create_chat(&bob).await.id;
    let chat_bob = bob.create_chat(&alice).await.id;

    // Alice sends message to Bob
    let mut msg = Message::new(Viewtype::Text);
    chat::send_msg(&alice.ctx, chat_alice, &mut msg).await?;
    let sent = alice.pop_sent_msg().await;
    bob.recv_msg(&sent).await;

    // Alice sends second message to Bob, with no timer
    let mut msg = Message::new(Viewtype::Text);
    chat::send_msg(&alice.ctx, chat_alice, &mut msg).await?;
    let sent = alice.pop_sent_msg().await;

    assert_eq!(
        chat_bob.get_ephemeral_timer(&bob.ctx).await?,
        Timer::Disabled
    );

    // Bob sets ephemeral timer and sends a message about timer change
    chat_bob
        .set_ephemeral_timer(&bob.ctx, Timer::Enabled { duration: 60 })
        .await?;
    let sent_timer_change = bob.pop_sent_msg().await;

    assert_eq!(
        chat_bob.get_ephemeral_timer(&bob.ctx).await?,
        Timer::Enabled { duration: 60 }
    );

    // Bob receives message from Alice.
    // Alice message has no timer. However, Bob should not disable timer,
    // because Alice replies to old message.
    bob.recv_msg(&sent).await;

    assert_eq!(
        chat_alice.get_ephemeral_timer(&alice.ctx).await?,
        Timer::Disabled
    );
    assert_eq!(
        chat_bob.get_ephemeral_timer(&bob.ctx).await?,
        Timer::Enabled { duration: 60 }
    );

    // Alice receives message from Bob
    alice.recv_msg(&sent_timer_change).await;

    assert_eq!(
        chat_alice.get_ephemeral_timer(&alice.ctx).await?,
        Timer::Enabled { duration: 60 }
    );

    // Bob disables the chat timer.
    // Note that the last message in the Bob's chat is from Alice and has no timer,
    // but the chat timer is enabled.
    chat_bob
        .set_ephemeral_timer(&bob.ctx, Timer::Disabled)
        .await?;
    alice.recv_msg(&bob.pop_sent_msg().await).await;
    assert_eq!(
        chat_alice.get_ephemeral_timer(&alice.ctx).await?,
        Timer::Disabled
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_delete_msgs() -> Result<()> {
    let t = TestContext::new_alice().await;
    let self_chat = t.get_self_chat().await;

    assert_eq!(next_expiration_timestamp(&t).await, None);

    t.send_text(self_chat.id, "Saved message, which we delete manually")
        .await;
    let msg = t.get_last_msg_in(self_chat.id).await;
    msg.id.trash(&t, false).await?;
    check_msg_is_deleted(&t, &self_chat, msg.id).await;

    self_chat
        .id
        .set_ephemeral_timer(&t, Timer::Enabled { duration: 3600 })
        .await
        .unwrap();

    // Send a saved message which will be deleted after 3600s
    let now = time();
    let msg = t.send_text(self_chat.id, "Message text").await;

    check_msg_will_be_deleted(&t, msg.sender_msg_id, &self_chat, now + 3599, time() + 3601)
        .await
        .unwrap();

    // Set DeleteDeviceAfter to 1800s. Then send a saved message which will
    // still be deleted after 3600s because DeleteDeviceAfter doesn't apply to saved messages.
    t.set_config(Config::DeleteDeviceAfter, Some("1800"))
        .await?;

    let now = time();
    let msg = t.send_text(self_chat.id, "Message text").await;

    check_msg_will_be_deleted(&t, msg.sender_msg_id, &self_chat, now + 3559, time() + 3601)
        .await
        .unwrap();

    // Send a message to Bob which will be deleted after 1800s because of DeleteDeviceAfter.
    let bob_chat = t.create_chat_with_contact("", "bob@example.net").await;
    let now = time();
    let msg = t.send_text(bob_chat.id, "Message text").await;

    check_msg_will_be_deleted(
        &t,
        msg.sender_msg_id,
        &bob_chat,
        now + 1799,
        // The message may appear to be sent MAX_SECONDS_TO_LEND_FROM_FUTURE later and
        // therefore be deleted MAX_SECONDS_TO_LEND_FROM_FUTURE later.
        time() + 1801 + MAX_SECONDS_TO_LEND_FROM_FUTURE,
    )
    .await
    .unwrap();

    // Enable ephemeral messages with Bob -> message will be deleted after 60s.
    // This tests that the message is deleted at min(ephemeral deletion time, DeleteDeviceAfter deletion time).
    bob_chat
        .id
        .set_ephemeral_timer(&t, Timer::Enabled { duration: 60 })
        .await?;

    let now = time();
    let msg = t.send_text(bob_chat.id, "Message text").await;

    check_msg_will_be_deleted(&t, msg.sender_msg_id, &bob_chat, now + 59, time() + 61)
        .await
        .unwrap();

    Ok(())
}

async fn check_msg_will_be_deleted(
    t: &TestContext,
    msg_id: MsgId,
    chat: &Chat,
    not_deleted_at: i64,
    deleted_at: i64,
) -> Result<()> {
    let next_expiration = next_expiration_timestamp(t).await.unwrap();

    assert!(next_expiration > not_deleted_at);
    delete_expired_messages(t, not_deleted_at).await?;

    let loaded = Message::load_from_db(t, msg_id).await?;
    assert!(!loaded.text.is_empty());
    assert_eq!(loaded.chat_id, chat.id);

    assert!(next_expiration < deleted_at);
    delete_expired_messages(t, deleted_at).await?;
    t.evtracker
        .get_matching(|evt| {
            if let EventType::MsgDeleted {
                msg_id: event_msg_id,
                ..
            } = evt
            {
                *event_msg_id == msg_id
            } else {
                false
            }
        })
        .await;

    let loaded = Message::load_from_db_optional(t, msg_id).await?;
    assert!(loaded.is_none());

    // Check that the msg was deleted locally.
    check_msg_is_deleted(t, chat, msg_id).await;

    Ok(())
}

async fn check_msg_is_deleted(t: &TestContext, chat: &Chat, msg_id: MsgId) {
    let chat_items = chat::get_chat_msgs(t, chat.id).await.unwrap();
    // Check that the chat is empty except for possibly info messages:
    for item in &chat_items {
        if let ChatItem::Message { msg_id } = item {
            let msg = Message::load_from_db(t, *msg_id).await.unwrap();
            assert!(msg.is_info())
        }
    }

    // Check that if there is a message left, the text and metadata are gone
    if let Ok(msg) = Message::load_from_db(t, msg_id).await {
        assert_eq!(msg.from_id, ContactId::UNDEFINED);
        assert_eq!(msg.to_id, ContactId::UNDEFINED);
        assert_eq!(msg.text, "");
        let rawtxt: Option<String> = t
            .sql
            .query_get_value("SELECT txt_raw FROM msgs WHERE id=?;", (msg_id,))
            .await
            .unwrap();
        assert!(rawtxt.is_none_or_empty(), "{rawtxt:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_expired_imap_messages() -> Result<()> {
    let t = TestContext::new_alice().await;
    const HOUR: i64 = 60 * 60;
    let now = time();
    for (id, timestamp, ephemeral_timestamp) in &[
        (900, now - 2 * HOUR, 0),
        (1000, now - 23 * HOUR - MIN_DELETE_SERVER_AFTER, 0),
        (1010, now - 23 * HOUR, 0),
        (1020, now - 21 * HOUR, 0),
        (1030, now - 19 * HOUR, 0),
        (2000, now - 18 * HOUR, now - HOUR),
        (2020, now - 17 * HOUR, now + HOUR),
        (3000, now + HOUR, 0),
    ] {
        let message_id = id.to_string();
        t.sql
               .execute(
                   "INSERT INTO msgs (id, rfc724_mid, timestamp, ephemeral_timestamp) VALUES (?,?,?,?);",
                   (id, &message_id, timestamp, ephemeral_timestamp),
               )
               .await?;
        t.sql
            .execute(
                "INSERT INTO imap (rfc724_mid, folder, uid, target) VALUES (?,'INBOX',?, 'INBOX');",
                (&message_id, id),
            )
            .await?;
    }

    async fn test_marked_for_deletion(context: &Context, id: u32) -> Result<()> {
        assert_eq!(
            context
                .sql
                .count(
                    "SELECT COUNT(*) FROM imap WHERE target='' AND rfc724_mid=?",
                    (id.to_string(),),
                )
                .await?,
            1
        );
        Ok(())
    }

    async fn remove_uid(context: &Context, id: u32) -> Result<()> {
        context
            .sql
            .execute("DELETE FROM imap WHERE rfc724_mid=?", (id.to_string(),))
            .await?;
        Ok(())
    }

    // This should mark message 2000 for deletion.
    delete_expired_imap_messages(&t).await?;
    test_marked_for_deletion(&t, 2000).await?;
    remove_uid(&t, 2000).await?;
    // No other messages are marked for deletion.
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM imap WHERE target=''", ())
            .await?,
        0
    );

    t.set_config(Config::DeleteServerAfter, Some(&*(25 * HOUR).to_string()))
        .await?;
    delete_expired_imap_messages(&t).await?;
    test_marked_for_deletion(&t, 1000).await?;

    MsgId::new(1000)
        .update_download_state(&t, DownloadState::Available)
        .await?;
    t.sql
        .execute("UPDATE imap SET target=folder WHERE rfc724_mid='1000'", ())
        .await?;
    delete_expired_imap_messages(&t).await?;
    test_marked_for_deletion(&t, 1000).await?; // Delete downloadable anyway.
    remove_uid(&t, 1000).await?;

    t.set_config(Config::DeleteServerAfter, Some(&*(22 * HOUR).to_string()))
        .await?;
    delete_expired_imap_messages(&t).await?;
    test_marked_for_deletion(&t, 1010).await?;
    t.sql
        .execute("UPDATE imap SET target=folder WHERE rfc724_mid='1010'", ())
        .await?;

    MsgId::new(1010)
        .update_download_state(&t, DownloadState::Available)
        .await?;
    delete_expired_imap_messages(&t).await?;
    // Keep downloadable for now.
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM imap WHERE target=''", ())
            .await?,
        0
    );

    t.set_config(Config::DeleteServerAfter, Some("1")).await?;
    delete_expired_imap_messages(&t).await?;
    test_marked_for_deletion(&t, 3000).await?;

    Ok(())
}

// Regression test for a bug in the timer rollback protection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_timer_references() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Message with Message-ID <first@example.com> and no timer is received.
    receive_imf(
        &alice,
        b"From: Bob <bob@example.com>\n\
                    To: Alice <alice@example.org>\n\
                    Chat-Version: 1.0\n\
                    Subject: Subject\n\
                    Message-ID: <first@example.com>\n\
                    Date: Sun, 22 Mar 2020 00:10:00 +0000\n\
                    \n\
                    hello\n",
        false,
    )
    .await?;

    let msg = alice.get_last_msg().await;
    let chat_id = msg.chat_id;
    assert_eq!(chat_id.get_ephemeral_timer(&alice).await?, Timer::Disabled);

    // Message with Message-ID <second@example.com> is received.
    receive_imf(
        &alice,
        b"From: Bob <bob@example.com>\n\
                    To: Alice <alice@example.org>\n\
                    Chat-Version: 1.0\n\
                    Subject: Subject\n\
                    Message-ID: <second@example.com>\n\
                    Date: Sun, 22 Mar 2020 00:11:00 +0000\n\
                    Ephemeral-Timer: 60\n\
                    \n\
                    second message\n",
        false,
    )
    .await?;
    assert_eq!(
        chat_id.get_ephemeral_timer(&alice).await?,
        Timer::Enabled { duration: 60 }
    );
    let msg = alice.get_last_msg().await;

    // Message is deleted when its timer expires.
    msg.id.trash(&alice, false).await?;

    // Message with Message-ID <third@example.com>, referencing <first@example.com> and
    // <second@example.com>, is received.  The message <second@example.come> is not in the
    // database anymore, so the timer should be applied unconditionally without rollback
    // protection.
    //
    // Previously Delta Chat fallen back to using <first@example.com> in this case and
    // compared received timer value to the timer value of the <first@example.com>. Because
    // their timer values are the same ("disabled"), Delta Chat assumed that the timer was not
    // changed explicitly and the change should be ignored.
    //
    // The message also contains a quote of the first message to test that only References:
    // header and not In-Reply-To: is consulted by the rollback protection.
    receive_imf(
        &alice,
        b"From: Bob <bob@example.com>\n\
                    To: Alice <alice@example.org>\n\
                    Chat-Version: 1.0\n\
                    Subject: Subject\n\
                    Message-ID: <third@example.com>\n\
                    Date: Sun, 22 Mar 2020 00:12:00 +0000\n\
                    References: <first@example.com> <second@example.com>\n\
                    In-Reply-To: <first@example.com>\n\
                    \n\
                    > hello\n",
        false,
    )
    .await?;

    let msg = alice.get_last_msg().await;
    assert_eq!(
        msg.chat_id.get_ephemeral_timer(&alice).await?,
        Timer::Disabled
    );

    Ok(())
}

// Tests that if we are offline for a time longer than the ephemeral timer duration, the message
// is deleted from the chat but is still in the "smtp" table, i.e. will be sent upon a
// successful reconnection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_msg_offline() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let chat = alice
        .create_chat_with_contact("Bob", "bob@example.org")
        .await;
    let duration = 60;
    chat.id
        .set_ephemeral_timer(&alice, Timer::Enabled { duration })
        .await?;
    let mut msg = Message::new_text("hi".to_string());
    assert!(chat::send_msg_sync(&alice, chat.id, &mut msg)
        .await
        .is_err());
    let stmt = "SELECT COUNT(*) FROM smtp WHERE msg_id=?";
    assert!(alice.sql.exists(stmt, (msg.id,)).await?);
    let now = time();
    check_msg_will_be_deleted(&alice, msg.id, &chat, now, now + i64::from(duration) + 1).await?;
    assert!(alice.sql.exists(stmt, (msg.id,)).await?);

    Ok(())
}

/// Tests that POI location is deleted when ephemeral message expires.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_poi_location() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat = alice.create_chat(bob).await;

    let duration = 60;
    chat.id
        .set_ephemeral_timer(alice, Timer::Enabled { duration })
        .await?;
    let sent = alice.pop_sent_msg().await;
    bob.recv_msg(&sent).await;

    let mut poi_msg = Message::new_text("Here".to_string());
    poi_msg.set_location(10.0, 20.0);

    let alice_sent_message = alice.send_msg(chat.id, &mut poi_msg).await;
    let bob_received_message = bob.recv_msg(&alice_sent_message).await;
    markseen_msgs(bob, vec![bob_received_message.id]).await?;

    for account in [alice, bob] {
        let locations = location::get_range(account, None, None, 0, 0).await?;
        assert_eq!(locations.len(), 1);
    }

    SystemTime::shift(Duration::from_secs(100));

    for account in [alice, bob] {
        delete_expired_messages(account, time()).await?;
        let locations = location::get_range(account, None, None, 0, 0).await?;
        assert_eq!(locations.len(), 0);
    }

    Ok(())
}

/// Tests that `.get_ephemeral_timer()` returns an error for invalid chat ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_ephemeral_timer_wrong_chat_id() -> Result<()> {
    let context = TestContext::new().await;
    let chat_id = ChatId::new(12345);
    assert!(chat_id.get_ephemeral_timer(&context).await.is_err());

    Ok(())
}

/// Tests that ephemeral timer is started when the chat is noticed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_noticed_ephemeral_timer() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat = alice.create_chat(bob).await;
    let duration = 60;
    chat.id
        .set_ephemeral_timer(alice, Timer::Enabled { duration })
        .await?;
    let bob_received_message = tcm.send_recv(alice, bob, "Hello!").await;

    marknoticed_chat(bob, bob_received_message.chat_id).await?;
    SystemTime::shift(Duration::from_secs(100));

    delete_expired_messages(bob, time()).await?;

    assert!(Message::load_from_db_optional(bob, bob_received_message.id)
        .await?
        .is_none());
    Ok(())
}

/// Tests that archiving the chat starts ephemeral timer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_archived_ephemeral_timer() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat = alice.create_chat(bob).await;
    let duration = 60;
    chat.id
        .set_ephemeral_timer(alice, Timer::Enabled { duration })
        .await?;
    let bob_received_message = tcm.send_recv(alice, bob, "Hello!").await;

    bob_received_message
        .chat_id
        .set_visibility(bob, ChatVisibility::Archived)
        .await?;
    SystemTime::shift(Duration::from_secs(100));

    delete_expired_messages(bob, time()).await?;

    assert!(Message::load_from_db_optional(bob, bob_received_message.id)
        .await?
        .is_none());

    // Bob mutes the chat so it is not unarchived.
    set_muted(bob, bob_received_message.chat_id, MuteDuration::Forever).await?;

    // Now test that for already archived chat
    // timer is started if all archived chats are marked as noticed.
    let bob_received_message_2 = tcm.send_recv(alice, bob, "Hello again!").await;
    assert_eq!(bob_received_message_2.state, MessageState::InFresh);

    marknoticed_chat(bob, DC_CHAT_ID_ARCHIVED_LINK).await?;
    SystemTime::shift(Duration::from_secs(100));

    delete_expired_messages(bob, time()).await?;

    assert!(
        Message::load_from_db_optional(bob, bob_received_message_2.id)
            .await?
            .is_none()
    );

    Ok(())
}

/// Tests that non-members cannot change ephemeral timer settings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ephemeral_timer_non_member() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    let alice_chat_id =
        create_group_chat(alice, ProtectionStatus::Unprotected, "Group name").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    send_text_msg(alice, alice_chat_id, "Hi!".to_string()).await?;

    let sent = alice.pop_sent_msg().await;
    let bob_chat_id = bob.recv_msg(&sent).await.chat_id;

    // Bob wants to modify the timer.
    bob_chat_id.accept(bob).await?;
    bob_chat_id
        .set_ephemeral_timer(bob, Timer::Enabled { duration: 60 })
        .await?;
    let sent_ephemeral_timer_change = bob.pop_sent_msg().await;

    // Alice removes Bob before receiving the timer change.
    remove_contact_from_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    alice.recv_msg(&sent_ephemeral_timer_change).await;

    // Timer is not changed because Bob is not a member.
    assert_eq!(
        alice_chat_id.get_ephemeral_timer(alice).await?,
        Timer::Disabled
    );

    Ok(())
}
