use crate::{EventType, chat::ChatId, contact::ContactId, context::Context};

/// order or content of chatlist changes (chat ids, not the actual chatlist item)
pub(crate) fn emit_chatlist_changed(context: &Context) {
    context.emit_event(EventType::ChatlistChanged);
}

/// Chatlist item of a specific chat changed
pub(crate) fn emit_chatlist_item_changed(context: &Context, chat_id: ChatId) {
    context.emit_event(EventType::ChatlistItemChanged {
        chat_id: Some(chat_id),
    });
}

/// Used when you don't know which chatlist items changed, this reloads all cached chatlist items in the UI
///
/// Avoid calling this when you can find out the affected chat ids easialy (without extra expensive db queries).
///
/// This method is not public, so you have to define and document your new case here in this file.
fn emit_unknown_chatlist_items_changed(context: &Context) {
    context.emit_event(EventType::ChatlistItemChanged { chat_id: None });
}

/// update event for the 1:1 chat with the contact
/// used when recently seen changes and when profile image changes
pub(crate) async fn emit_chatlist_item_changed_for_contact_chat(
    context: &Context,
    contact_id: ContactId,
) {
    match ChatId::lookup_by_contact(context, contact_id).await {
        Ok(Some(chat_id)) => self::emit_chatlist_item_changed(context, chat_id),
        Ok(None) => {}
        Err(error) => context.emit_event(EventType::Error(format!(
            "failed to find chat id for contact for chatlist event: {error:?}"
        ))),
    }
}

/// update items for chats that have the contact
/// used when contact changes their name or did AEAP for example
///
/// The most common case is that the contact changed their name
/// and their name should be updated in the chatlistitems for the chats
/// where they sent the last message as there their name is shown in the summary on those
pub(crate) fn emit_chatlist_items_changed_for_contact(context: &Context, _contact_id: ContactId) {
    // note:(treefit): it is too expensive to find the right chats
    // so we'll just tell ui to reload every loaded item
    emit_unknown_chatlist_items_changed(context)
    // note:(treefit): in the future we could instead emit an extra event for this and also store contact id in the chatlistitems
    // (contact id for dm chats and contact id of contact that wrote the message in the summary)
    // the ui could then look for this info in the cache and only reload the needed chats.
}

/// Tests for chatlist events
///
/// Only checks if the events are emitted,
/// does not check for excess/too-many events
#[cfg(test)]
mod test_chatlist_events {

    use std::{
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };

    use crate::{
        EventType,
        chat::{
            self, ChatId, ChatVisibility, MuteDuration, ProtectionStatus, create_broadcast,
            create_group_chat, set_muted,
        },
        config::Config,
        constants::*,
        contact::Contact,
        message::{self, Message, MessageState},
        reaction,
        receive_imf::receive_imf,
        securejoin::{get_securejoin_qr, join_securejoin},
        test_utils::{TestContext, TestContextManager},
    };

    use crate::tools::SystemTime;
    use anyhow::Result;

    async fn wait_for_chatlist_and_specific_item(context: &TestContext, chat_id: ChatId) {
        let first_event_is_item = AtomicBool::new(false);
        context
            .evtracker
            .get_matching(|evt| match evt {
                EventType::ChatlistItemChanged {
                    chat_id: Some(ev_chat_id),
                } => {
                    if ev_chat_id == &chat_id {
                        first_event_is_item.store(true, Ordering::Relaxed);
                        true
                    } else {
                        false
                    }
                }
                EventType::ChatlistChanged => true,
                _ => false,
            })
            .await;
        if first_event_is_item.load(Ordering::Relaxed) {
            wait_for_chatlist(context).await;
        } else {
            wait_for_chatlist_specific_item(context, chat_id).await;
        }
    }

    async fn wait_for_chatlist_specific_item(context: &TestContext, chat_id: ChatId) {
        context
            .evtracker
            .get_matching(|evt| match evt {
                EventType::ChatlistItemChanged {
                    chat_id: Some(ev_chat_id),
                } => ev_chat_id == &chat_id,
                _ => false,
            })
            .await;
    }

    async fn wait_for_chatlist_all_items(context: &TestContext) {
        context
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::ChatlistItemChanged { chat_id: None }))
            .await;
    }

    async fn wait_for_chatlist(context: &TestContext) {
        context
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::ChatlistChanged))
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_change_chat_visibility() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat_id = create_group_chat(
            &alice,
            crate::chat::ProtectionStatus::Unprotected,
            "my_group",
        )
        .await?;

        chat_id
            .set_visibility(&alice, ChatVisibility::Pinned)
            .await?;
        wait_for_chatlist_and_specific_item(&alice, chat_id).await;

        chat_id
            .set_visibility(&alice, ChatVisibility::Archived)
            .await?;
        wait_for_chatlist_and_specific_item(&alice, chat_id).await;

        chat_id
            .set_visibility(&alice, ChatVisibility::Normal)
            .await?;
        wait_for_chatlist_and_specific_item(&alice, chat_id).await;

        Ok(())
    }

    /// mute a chat, archive it, then use another account to send a message to it, the counter on the archived chatlist item should change
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_archived_counter_increases_for_muted_chats() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;

        let chat = alice.create_chat(&bob).await;
        let sent_msg = alice.send_text(chat.id, "moin").await;
        bob.recv_msg(&sent_msg).await;

        let bob_chat = bob.create_chat(&alice).await;
        bob_chat
            .id
            .set_visibility(&bob, ChatVisibility::Archived)
            .await?;
        set_muted(&bob, bob_chat.id, MuteDuration::Forever).await?;

        bob.evtracker.clear_events();

        let sent_msg = alice.send_text(chat.id, "moin2").await;
        bob.recv_msg(&sent_msg).await;

        bob.evtracker
            .get_matching(|evt| match evt {
                EventType::ChatlistItemChanged {
                    chat_id: Some(chat_id),
                } => chat_id.is_archived_link(),
                _ => false,
            })
            .await;

        Ok(())
    }

    /// Mark noticed on archive-link chatlistitem should update the unread counter on it
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_archived_counter_update_on_mark_noticed() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let chat = alice.create_chat(&bob).await;
        let sent_msg = alice.send_text(chat.id, "moin").await;
        bob.recv_msg(&sent_msg).await;
        let bob_chat = bob.create_chat(&alice).await;
        bob_chat
            .id
            .set_visibility(&bob, ChatVisibility::Archived)
            .await?;
        set_muted(&bob, bob_chat.id, MuteDuration::Forever).await?;
        let sent_msg = alice.send_text(chat.id, "moin2").await;
        bob.recv_msg(&sent_msg).await;

        bob.evtracker.clear_events();
        chat::marknoticed_chat(&bob, DC_CHAT_ID_ARCHIVED_LINK).await?;
        wait_for_chatlist_specific_item(&bob, DC_CHAT_ID_ARCHIVED_LINK).await;

        Ok(())
    }

    /// Contact name update - expect all chats to update
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_contact_name_update() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let alice_to_bob_chat = alice.create_chat(&bob).await;
        let sent_msg = alice.send_text(alice_to_bob_chat.id, "hello").await;
        bob.recv_msg(&sent_msg).await;

        bob.evtracker.clear_events();
        // set alice name then receive messagefrom her with bob
        alice.set_config(Config::Displayname, Some("Alice")).await?;
        let sent_msg = alice
            .send_text(alice_to_bob_chat.id, "hello, I set a displayname")
            .await;
        bob.recv_msg(&sent_msg).await;
        let alice_on_bob = bob.add_or_lookup_contact(&alice).await;
        assert!(alice_on_bob.get_display_name() == "Alice");

        wait_for_chatlist_all_items(&bob).await;

        bob.evtracker.clear_events();
        // set name
        alice_on_bob.id.set_name(&bob, "Alice2").await?;
        assert!(bob.add_or_lookup_contact(&alice).await.get_display_name() == "Alice2");

        wait_for_chatlist_all_items(&bob).await;

        Ok(())
    }

    /// Contact changed avatar
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_contact_changed_avatar() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let alice_to_bob_chat = alice.create_chat(&bob).await;
        let sent_msg = alice.send_text(alice_to_bob_chat.id, "hello").await;
        bob.recv_msg(&sent_msg).await;

        bob.evtracker.clear_events();
        // set alice avatar then receive messagefrom her with bob
        let file = alice.dir.path().join("avatar.png");
        let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
        tokio::fs::write(&file, bytes).await?;
        alice
            .set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
            .await?;
        let sent_msg = alice
            .send_text(alice_to_bob_chat.id, "hello, I have a new avatar")
            .await;
        bob.recv_msg(&sent_msg).await;
        let alice_on_bob = bob.add_or_lookup_contact(&alice).await;
        assert!(alice_on_bob.get_profile_image(&bob).await?.is_some());

        wait_for_chatlist_specific_item(&bob, bob.create_chat(&alice).await.id).await;
        Ok(())
    }

    /// Delete chat
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_delete_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;

        alice.evtracker.clear_events();
        chat.delete(&alice).await?;
        wait_for_chatlist(&alice).await;
        Ok(())
    }

    /// Create group chat
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_create_group_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        alice.evtracker.clear_events();
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;
        wait_for_chatlist_and_specific_item(&alice, chat).await;
        Ok(())
    }

    /// Create broadcast channel
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_create_broadcast() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        alice.evtracker.clear_events();
        create_broadcast(&alice, "Channel".to_string()).await?;
        wait_for_chatlist(&alice).await;
        Ok(())
    }

    /// Mute chat
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mute_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;

        alice.evtracker.clear_events();
        chat::set_muted(&alice, chat, MuteDuration::Forever).await?;
        wait_for_chatlist_specific_item(&alice, chat).await;

        alice.evtracker.clear_events();
        chat::set_muted(&alice, chat, MuteDuration::NotMuted).await?;
        wait_for_chatlist_specific_item(&alice, chat).await;

        Ok(())
    }

    /// Expiry of mute should also trigger an event
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "does not work yet"]
    async fn test_mute_chat_expired() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;

        let mute_duration = MuteDuration::Until(
            std::time::SystemTime::now()
                .checked_add(Duration::from_secs(2))
                .unwrap(),
        );
        chat::set_muted(&alice, chat, mute_duration).await?;
        alice.evtracker.clear_events();
        SystemTime::shift(Duration::from_secs(3));
        wait_for_chatlist_specific_item(&alice, chat).await;

        Ok(())
    }

    /// Change chat name
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_change_chat_name() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;

        alice.evtracker.clear_events();
        chat::set_chat_name(&alice, chat, "New Name").await?;
        wait_for_chatlist_specific_item(&alice, chat).await;

        Ok(())
    }

    /// Change chat profile image
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_change_chat_profile_image() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;

        alice.evtracker.clear_events();
        let file = alice.dir.path().join("avatar.png");
        let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
        tokio::fs::write(&file, bytes).await?;
        chat::set_chat_profile_image(&alice, chat, file.to_str().unwrap()).await?;
        wait_for_chatlist_specific_item(&alice, chat).await;

        Ok(())
    }

    /// Receive group and receive name change
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receiving_group_and_group_changes() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let chat = alice
            .create_group_with_members(ProtectionStatus::Unprotected, "My Group", &[&bob])
            .await;

        let sent_msg = alice.send_text(chat, "Hello").await;
        let chat_id_for_bob = bob.recv_msg(&sent_msg).await.chat_id;
        wait_for_chatlist_specific_item(&bob, chat_id_for_bob).await;
        chat_id_for_bob.accept(&bob).await?;

        bob.evtracker.clear_events();
        chat::set_chat_name(&alice, chat, "New Name").await?;
        let sent_msg = alice.send_text(chat, "Hello").await;
        bob.recv_msg(&sent_msg).await;
        wait_for_chatlist_specific_item(&bob, chat_id_for_bob).await;

        Ok(())
    }

    /// Accept contact request
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accept_contact_request() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let chat = alice
            .create_group_with_members(ProtectionStatus::Unprotected, "My Group", &[&bob])
            .await;
        let sent_msg = alice.send_text(chat, "Hello").await;
        let chat_id_for_bob = bob.recv_msg(&sent_msg).await.chat_id;

        bob.evtracker.clear_events();
        chat_id_for_bob.accept(&bob).await?;
        wait_for_chatlist_specific_item(&bob, chat_id_for_bob).await;

        Ok(())
    }

    /// Block contact request
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_block_contact_request() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let chat = alice
            .create_group_with_members(ProtectionStatus::Unprotected, "My Group", &[&bob])
            .await;
        let sent_msg = alice.send_text(chat, "Hello").await;
        let chat_id_for_bob = bob.recv_msg(&sent_msg).await.chat_id;

        bob.evtracker.clear_events();
        chat_id_for_bob.block(&bob).await?;
        wait_for_chatlist(&bob).await;

        Ok(())
    }

    /// Delete message
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_delete_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;
        let message = chat::send_text_msg(&alice, chat, "Hello World".to_owned()).await?;

        alice.evtracker.clear_events();
        message::delete_msgs(&alice, &[message]).await?;
        wait_for_chatlist_specific_item(&alice, chat).await;

        Ok(())
    }

    /// Click on chat should remove the unread count (on msgs noticed)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_msgs_noticed_on_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;

        let chat = alice
            .create_group_with_members(ProtectionStatus::Unprotected, "My Group", &[&bob])
            .await;
        let sent_msg = alice.send_text(chat, "Hello").await;
        let chat_id_for_bob = bob.recv_msg(&sent_msg).await.chat_id;
        chat_id_for_bob.accept(&bob).await?;

        let sent_msg = alice.send_text(chat, "New Message").await;
        let chat_id_for_bob = bob.recv_msg(&sent_msg).await.chat_id;
        assert!(chat_id_for_bob.get_fresh_msg_cnt(&bob).await? >= 1);

        bob.evtracker.clear_events();
        chat::marknoticed_chat(&bob, chat_id_for_bob).await?;
        wait_for_chatlist_specific_item(&bob, chat_id_for_bob).await;

        Ok(())
    }

    // Block and Unblock contact
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unblock_contact() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let contact_id = Contact::create(&alice, "example", "example@example.com").await?;
        let _ = ChatId::create_for_contact(&alice, contact_id).await;

        alice.evtracker.clear_events();
        Contact::block(&alice, contact_id).await?;
        wait_for_chatlist(&alice).await;

        alice.evtracker.clear_events();
        Contact::unblock(&alice, contact_id).await?;
        wait_for_chatlist(&alice).await;

        Ok(())
    }

    /// Tests that expired disappearing message
    /// produces events about chatlist being modified.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_update_after_ephemeral_messages() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;
        chat.set_ephemeral_timer(&alice, crate::ephemeral::Timer::Enabled { duration: 60 })
            .await?;
        alice
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::ChatEphemeralTimerModified { .. }))
            .await;

        let _ = chat::send_text_msg(&alice, chat, "Hello".to_owned()).await?;
        wait_for_chatlist_and_specific_item(&alice, chat).await;

        SystemTime::shift(Duration::from_secs(70));
        crate::ephemeral::delete_expired_messages(&alice, crate::tools::time()).await?;
        wait_for_chatlist_and_specific_item(&alice, chat).await;

        Ok(())
    }

    /// AdHoc (Groups without a group ID.) group receiving
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_adhoc_group() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let mime = br#"Subject: First thread
Message-ID: first@example.org
To: Alice <alice@example.org>, Bob <bob@example.net>
From: Claire <claire@example.org>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

First thread."#;

        alice.evtracker.clear_events();
        receive_imf(&alice, mime, false).await?;
        wait_for_chatlist(&alice).await;

        Ok(())
    }

    /// Test both direction of securejoin
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_secure_join_group() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;

        let alice_chatid =
            chat::create_group_chat(&alice.ctx, ProtectionStatus::Protected, "the chat").await?;

        // Step 1: Generate QR-code, secure-join implied by chatid
        let qr = get_securejoin_qr(&alice.ctx, Some(alice_chatid)).await?;

        // Step 2: Bob scans QR-code, sends vg-request
        bob.evtracker.clear_events();
        let bob_chatid = join_securejoin(&bob.ctx, &qr).await?;
        wait_for_chatlist(&bob).await;

        let sent = bob.pop_sent_msg().await;

        // Step 3: Alice receives vg-request, sends vg-auth-required
        alice.evtracker.clear_events();
        alice.recv_msg_trash(&sent).await;

        let sent = alice.pop_sent_msg().await;

        // Step 4: Bob receives vg-auth-required, sends vg-request-with-auth
        bob.evtracker.clear_events();
        bob.recv_msg_trash(&sent).await;
        wait_for_chatlist_and_specific_item(&bob, bob_chatid).await;

        let sent = bob.pop_sent_msg().await;

        // Step 5+6: Alice receives vg-request-with-auth, sends vg-member-added
        alice.evtracker.clear_events();
        alice.recv_msg_trash(&sent).await;
        wait_for_chatlist_and_specific_item(&alice, alice_chatid).await;

        let sent = alice.pop_sent_msg().await;

        // Step 7: Bob receives vg-member-added
        bob.evtracker.clear_events();
        bob.recv_msg(&sent).await;
        wait_for_chatlist_and_specific_item(&bob, bob_chatid).await;

        Ok(())
    }

    /// Call Resend on message
    ///
    /// (the event is technically only needed if it is the last message in the chat, but checking that would be too expensive so the event is always emitted)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_resend_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;

        let msg_id = chat::send_text_msg(&alice, chat, "Hello".to_owned()).await?;
        let _ = alice.pop_sent_msg().await;

        let message = Message::load_from_db(&alice, msg_id).await?;
        assert_eq!(message.get_state(), MessageState::OutDelivered);

        alice.evtracker.clear_events();
        chat::resend_msgs(&alice, &[msg_id]).await?;
        wait_for_chatlist_specific_item(&alice, chat).await;

        Ok(())
    }

    /// test that setting a reaction emits chatlistitem update event
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reaction() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let chat = create_group_chat(&alice, ProtectionStatus::Protected, "My Group").await?;
        let msg_id = chat::send_text_msg(&alice, chat, "Hello".to_owned()).await?;
        let _ = alice.pop_sent_msg().await;

        alice.evtracker.clear_events();
        reaction::send_reaction(&alice, msg_id, "👍").await?;
        let _ = alice.pop_sent_msg().await;
        wait_for_chatlist_specific_item(&alice, chat).await;

        Ok(())
    }
}
