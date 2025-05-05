use num_traits::FromPrimitive;

use super::*;
use crate::chat::{
    self, add_contact_to_chat, forward_msgs, marknoticed_chat, save_msgs, send_text_msg, ChatItem,
    ProtectionStatus,
};
use crate::chatlist::Chatlist;
use crate::config::Config;
use crate::reaction::send_reaction;
use crate::receive_imf::receive_imf;
use crate::test_utils;
use crate::test_utils::{TestContext, TestContextManager};

#[test]
fn test_guess_msgtype_from_suffix() {
    assert_eq!(
        guess_msgtype_from_path_suffix(Path::new("foo/bar-sth.mp3")),
        Some((Viewtype::Audio, "audio/mpeg"))
    );
    assert_eq!(
        guess_msgtype_from_path_suffix(Path::new("foo/file.html")),
        Some((Viewtype::File, "text/html"))
    );
    assert_eq!(
        guess_msgtype_from_path_suffix(Path::new("foo/file.xdc")),
        Some((Viewtype::Webxdc, "application/webxdc+zip"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_webrtc_instance() {
    let (webrtc_type, url) = Message::parse_webrtc_instance("basicwebrtc:https://foo/bar");
    assert_eq!(webrtc_type, VideochatType::BasicWebrtc);
    assert_eq!(url, "https://foo/bar");

    let (webrtc_type, url) = Message::parse_webrtc_instance("bAsIcwEbrTc:url");
    assert_eq!(webrtc_type, VideochatType::BasicWebrtc);
    assert_eq!(url, "url");

    let (webrtc_type, url) = Message::parse_webrtc_instance("https://foo/bar?key=val#key=val");
    assert_eq!(webrtc_type, VideochatType::Unknown);
    assert_eq!(url, "https://foo/bar?key=val#key=val");

    let (webrtc_type, url) = Message::parse_webrtc_instance("jitsi:https://j.si/foo");
    assert_eq!(webrtc_type, VideochatType::Jitsi);
    assert_eq!(url, "https://j.si/foo");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_webrtc_instance() {
    // webrtc_instance may come from an input field of the ui, be pretty tolerant on input
    let instance = Message::create_webrtc_instance("https://meet.jit.si/", "123");
    assert_eq!(instance, "https://meet.jit.si/123");

    let instance = Message::create_webrtc_instance("https://meet.jit.si", "456");
    assert_eq!(instance, "https://meet.jit.si/456");

    let instance = Message::create_webrtc_instance("meet.jit.si", "789");
    assert_eq!(instance, "https://meet.jit.si/789");

    let instance = Message::create_webrtc_instance("bla.foo?", "123");
    assert_eq!(instance, "https://bla.foo?123");

    let instance = Message::create_webrtc_instance("jitsi:bla.foo#", "456");
    assert_eq!(instance, "jitsi:https://bla.foo#456");

    let instance = Message::create_webrtc_instance("bla.foo#room=", "789");
    assert_eq!(instance, "https://bla.foo#room=789");

    let instance = Message::create_webrtc_instance("https://bla.foo#room", "123");
    assert_eq!(instance, "https://bla.foo#room/123");

    let instance = Message::create_webrtc_instance("bla.foo#room$ROOM", "123");
    assert_eq!(instance, "https://bla.foo#room123");

    let instance = Message::create_webrtc_instance("bla.foo#room=$ROOM&after=cont", "234");
    assert_eq!(instance, "https://bla.foo#room=234&after=cont");

    let instance = Message::create_webrtc_instance("  meet.jit .si ", "789");
    assert_eq!(instance, "https://meet.jit.si/789");

    let instance = Message::create_webrtc_instance(" basicwebrtc: basic . stuff\n ", "12345ab");
    assert_eq!(instance, "basicwebrtc:https://basic.stuff/12345ab");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_webrtc_instance_noroom() {
    // webrtc_instance may come from an input field of the ui, be pretty tolerant on input
    let instance = Message::create_webrtc_instance("bla.foo$NOROOM", "123");
    assert_eq!(instance, "https://bla.foo");

    let instance = Message::create_webrtc_instance(" bla . foo $NOROOM ", "456");
    assert_eq!(instance, "https://bla.foo");

    let instance = Message::create_webrtc_instance(" $NOROOM bla . foo  ", "789");
    assert_eq!(instance, "https://bla.foo");

    let instance = Message::create_webrtc_instance(" bla.foo  / $NOROOM ? a = b ", "123");
    assert_eq!(instance, "https://bla.foo/?a=b");

    // $ROOM has a higher precedence
    let instance = Message::create_webrtc_instance("bla.foo/?$NOROOM=$ROOM", "123");
    assert_eq!(instance, "https://bla.foo/?$NOROOM=123");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_width_height() {
    let t = TestContext::new().await;

    // test that get_width() and get_height() are returning some dimensions for images;
    // (as the device-chat contains a welcome-images, we check that)
    t.update_device_chats().await.ok();
    let device_chat_id = ChatId::get_for_contact(&t, ContactId::DEVICE)
        .await
        .unwrap();

    let mut has_image = false;
    let chatitems = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    for chatitem in chatitems {
        if let ChatItem::Message { msg_id } = chatitem {
            if let Ok(msg) = Message::load_from_db(&t, msg_id).await {
                if msg.get_viewtype() == Viewtype::Image {
                    has_image = true;
                    // just check that width/height are inside some reasonable ranges
                    assert!(msg.get_width() > 100);
                    assert!(msg.get_height() > 100);
                    assert!(msg.get_width() < 4000);
                    assert!(msg.get_height() < 4000);
                }
            }
        }
    }
    assert!(has_image);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_quote_basic() {
    let d = TestContext::new().await;
    let ctx = &d.ctx;

    ctx.set_config(Config::ConfiguredAddr, Some("self@example.com"))
        .await
        .unwrap();

    let chat = d.create_chat_with_contact("", "dest@example.com").await;
    let mut msg = Message::new_text("Quoted message".to_string());

    // Message has to be sent such that it gets saved to db.
    chat::send_msg(ctx, chat.id, &mut msg).await.unwrap();
    assert!(!msg.rfc724_mid.is_empty());

    let mut msg2 = Message::new(Viewtype::Text);
    msg2.set_quote(ctx, Some(&msg))
        .await
        .expect("can't set quote");
    assert_eq!(msg2.quoted_text().unwrap(), msg.get_text());

    let quoted_msg = msg2
        .quoted_message(ctx)
        .await
        .expect("error while retrieving quoted message")
        .expect("quoted message not found");
    assert_eq!(quoted_msg.get_text(), msg2.quoted_text().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_quote() {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.send_recv_accept(alice, bob, "Hi!").await;
    let msg = tcm
        .send_recv(
            alice,
            bob,
            "On 2024-08-28, Alice wrote:\n> A quote.\nNot really.",
        )
        .await;

    assert!(msg.quoted_text().is_none());
    assert!(msg.quoted_message(bob).await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unencrypted_quote_encrypted_message() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_group = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "Group chat", &[bob])
        .await;
    let sent = alice.send_text(alice_group, "Hi! I created a group").await;
    let bob_received_message = bob.recv_msg(&sent).await;

    let bob_group = bob_received_message.chat_id;
    bob_group.accept(bob).await?;
    let sent = bob.send_text(bob_group, "Encrypted message").await;
    let alice_received_message = alice.recv_msg(&sent).await;
    assert!(alice_received_message.get_showpadlock());

    // Alice adds contact without key so chat becomes unencrypted.
    let alice_flubby_contact_id = Contact::create(alice, "Flubby", "flubby@example.org").await?;
    add_contact_to_chat(alice, alice_group, alice_flubby_contact_id).await?;

    // Alice quotes encrypted message in unencrypted chat.
    let mut msg = Message::new_text("unencrypted".to_string());
    msg.set_quote(alice, Some(&alice_received_message)).await?;
    chat::send_msg(alice, alice_group, &mut msg).await?;

    let bob_received_message = bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert_eq!(bob_received_message.quoted_text().unwrap(), "...");
    assert_eq!(bob_received_message.get_showpadlock(), false);

    // Alice replaces a quote of encrypted message with a quote of unencrypted one.
    let mut msg1 = Message::new(Viewtype::Text);
    msg1.set_quote(alice, Some(&alice_received_message)).await?;
    msg1.set_quote(alice, Some(&msg)).await?;
    chat::send_msg(alice, alice_group, &mut msg1).await?;

    let bob_received_message = bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert_eq!(bob_received_message.quoted_text().unwrap(), "unencrypted");
    assert_eq!(bob_received_message.get_showpadlock(), false);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_chat_id() {
    // Alice receives a message that pops up as a contact request
    let alice = TestContext::new_alice().await;
    receive_imf(
        &alice,
        b"From: Bob <bob@example.com>\n\
                    To: alice@example.org\n\
                    Chat-Version: 1.0\n\
                    Message-ID: <123@example.com>\n\
                    Date: Fri, 29 Jan 2021 21:37:55 +0000\n\
                    \n\
                    hello\n",
        false,
    )
    .await
    .unwrap();

    // check chat-id of this message
    let msg = alice.get_last_msg().await;
    assert!(!msg.get_chat_id().is_special());
    assert_eq!(msg.get_text(), "hello".to_string());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_override_sender_name() {
    // send message with overridden sender name
    let alice = TestContext::new_alice().await;
    let alice2 = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let chat = alice.create_chat(&bob).await;
    let contact_id = *chat::get_chat_contacts(&alice, chat.id)
        .await
        .unwrap()
        .first()
        .unwrap();
    let contact = Contact::get_by_id(&alice, contact_id).await.unwrap();

    let mut msg = Message::new_text("bla blubb".to_string());
    msg.set_override_sender_name(Some("over ride".to_string()));
    assert_eq!(
        msg.get_override_sender_name(),
        Some("over ride".to_string())
    );
    assert_eq!(msg.get_sender_name(&contact), "over ride".to_string());
    assert_ne!(contact.get_display_name(), "over ride".to_string());
    chat::send_msg(&alice, chat.id, &mut msg).await.unwrap();
    let sent_msg = alice.pop_sent_msg().await;

    // bob receives that message
    let chat = bob.create_chat(&alice).await;
    let contact_id = *chat::get_chat_contacts(&bob, chat.id)
        .await
        .unwrap()
        .first()
        .unwrap();
    let contact = Contact::get_by_id(&bob, contact_id).await.unwrap();
    let msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, chat.id);
    assert_eq!(msg.text, "bla blubb");
    assert_eq!(
        msg.get_override_sender_name(),
        Some("over ride".to_string())
    );
    assert_eq!(msg.get_sender_name(&contact), "over ride".to_string());
    assert_ne!(contact.get_display_name(), "over ride".to_string());

    // explicitly check that the message does not create a mailing list
    // (mailing lists may also use `Sender:`-header)
    let chat = Chat::load_from_db(&bob, msg.chat_id).await.unwrap();
    assert_ne!(chat.typ, Chattype::Mailinglist);

    // Alice receives message on another device.
    let msg = alice2.recv_msg(&sent_msg).await;
    assert_eq!(
        msg.get_override_sender_name(),
        Some("over ride".to_string())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_original_msg_id() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    // normal sending of messages does not have an original ID
    let one2one_chat = alice.create_chat(&bob).await;
    let sent = alice.send_text(one2one_chat.id, "foo").await;
    let orig_msg = Message::load_from_db(&alice, sent.sender_msg_id).await?;
    assert!(orig_msg.get_original_msg_id(&alice).await?.is_none());
    assert!(orig_msg.parent(&alice).await?.is_none());
    assert!(orig_msg.quoted_message(&alice).await?.is_none());

    // forwarding to "Saved Messages", the message gets the original ID attached
    let self_chat = alice.get_self_chat().await;
    save_msgs(&alice, &[sent.sender_msg_id]).await?;
    let saved_msg = alice.get_last_msg_in(self_chat.get_id()).await;
    assert_ne!(saved_msg.get_id(), orig_msg.get_id());
    assert_eq!(
        saved_msg.get_original_msg_id(&alice).await?.unwrap(),
        orig_msg.get_id()
    );
    assert!(saved_msg.parent(&alice).await?.is_none());
    assert!(saved_msg.quoted_message(&alice).await?.is_none());

    // forwarding from "Saved Messages" back to another chat, detaches original ID
    forward_msgs(&alice, &[saved_msg.get_id()], one2one_chat.get_id()).await?;
    let forwarded_msg = alice.get_last_msg_in(one2one_chat.get_id()).await;
    assert_ne!(forwarded_msg.get_id(), saved_msg.get_id());
    assert_ne!(forwarded_msg.get_id(), orig_msg.get_id());
    assert!(forwarded_msg.get_original_msg_id(&alice).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_markseen_msgs() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let mut msg = Message::new_text("this is the text!".to_string());

    // alice sends to bob,
    assert_eq!(Chatlist::try_load(&bob, 0, None, None).await?.len(), 0);
    let sent1 = alice.send_msg(alice_chat.id, &mut msg).await;
    let msg1 = bob.recv_msg(&sent1).await;
    let bob_chat_id = msg1.chat_id;
    let mut msg = Message::new_text("this is the text!".to_string());
    let sent2 = alice.send_msg(alice_chat.id, &mut msg).await;
    let msg2 = bob.recv_msg(&sent2).await;
    assert_eq!(msg1.chat_id, msg2.chat_id);
    let chats = Chatlist::try_load(&bob, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let msgs = chat::get_chat_msgs(&bob, bob_chat_id).await?;
    assert_eq!(msgs.len(), 2);
    assert_eq!(bob.get_fresh_msgs().await?.len(), 0);

    // that has no effect in contact request
    markseen_msgs(&bob, vec![msg1.id, msg2.id]).await?;

    assert_eq!(Chatlist::try_load(&bob, 0, None, None).await?.len(), 1);
    let bob_chat = Chat::load_from_db(&bob, bob_chat_id).await?;
    assert_eq!(bob_chat.blocked, Blocked::Request);

    let msgs = chat::get_chat_msgs(&bob, bob_chat_id).await?;
    assert_eq!(msgs.len(), 2);
    bob_chat_id.accept(&bob).await.unwrap();

    // bob sends to alice,
    // alice knows bob and messages appear in normal chat
    let mut msg = Message::new_text("this is the text!".to_string());
    let msg1 = alice
        .recv_msg(&bob.send_msg(bob_chat_id, &mut msg).await)
        .await;
    let mut msg = Message::new_text("this is the text!".to_string());
    let msg2 = alice
        .recv_msg(&bob.send_msg(bob_chat_id, &mut msg).await)
        .await;
    let chats = Chatlist::try_load(&alice, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats.get_chat_id(0)?, alice_chat.id);
    assert_eq!(chats.get_chat_id(0)?, msg1.chat_id);
    assert_eq!(chats.get_chat_id(0)?, msg2.chat_id);
    assert_eq!(alice_chat.id.get_fresh_msg_cnt(&alice).await?, 2);
    assert_eq!(alice.get_fresh_msgs().await?.len(), 2);

    // no message-ids, that should have no effect
    markseen_msgs(&alice, vec![]).await?;

    // bad message-id, that should have no effect
    markseen_msgs(&alice, vec![MsgId::new(123456)]).await?;

    assert_eq!(alice_chat.id.get_fresh_msg_cnt(&alice).await?, 2);
    assert_eq!(alice.get_fresh_msgs().await?.len(), 2);

    // mark the most recent as seen
    markseen_msgs(&alice, vec![msg2.id]).await?;

    assert_eq!(alice_chat.id.get_fresh_msg_cnt(&alice).await?, 1);
    assert_eq!(alice.get_fresh_msgs().await?.len(), 1);

    // user scrolled up - mark both as seen
    markseen_msgs(&alice, vec![msg1.id, msg2.id]).await?;

    assert_eq!(alice_chat.id.get_fresh_msg_cnt(&alice).await?, 0);
    assert_eq!(alice.get_fresh_msgs().await?.len(), 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_markseen_not_downloaded_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    alice.set_config(Config::DownloadLimit, Some("1")).await?;
    let bob = &tcm.bob().await;
    let bob_chat_id = tcm.send_recv_accept(alice, bob, "hi").await.chat_id;

    let file_bytes = include_bytes!("../../test-data/image/screenshot.png");
    let mut msg = Message::new(Viewtype::Image);
    msg.set_file_from_bytes(bob, "a.jpg", file_bytes, None)?;
    let sent_msg = bob.send_msg(bob_chat_id, &mut msg).await;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert!(!msg.param.get_bool(Param::WantsMdn).unwrap_or_default());
    assert_eq!(msg.state, MessageState::InFresh);
    markseen_msgs(alice, vec![msg.id]).await?;
    // A not downloaded message can be seen only if it's seen on another device.
    assert_eq!(msg.id.get_state(alice).await?, MessageState::InNoticed);
    // Marking the message as seen again is a no op.
    markseen_msgs(alice, vec![msg.id]).await?;
    assert_eq!(msg.id.get_state(alice).await?, MessageState::InNoticed);

    msg.id
        .update_download_state(alice, DownloadState::InProgress)
        .await?;
    markseen_msgs(alice, vec![msg.id]).await?;
    assert_eq!(msg.id.get_state(alice).await?, MessageState::InNoticed);
    msg.id
        .update_download_state(alice, DownloadState::Failure)
        .await?;
    markseen_msgs(alice, vec![msg.id]).await?;
    assert_eq!(msg.id.get_state(alice).await?, MessageState::InNoticed);
    msg.id
        .update_download_state(alice, DownloadState::Undecipherable)
        .await?;
    markseen_msgs(alice, vec![msg.id]).await?;
    assert_eq!(msg.id.get_state(alice).await?, MessageState::InNoticed);

    assert!(
        !alice
            .sql
            .exists("SELECT COUNT(*) FROM smtp_mdns", ())
            .await?
    );

    alice.set_config(Config::DownloadLimit, None).await?;
    // Let's assume that Alice and Bob resolved the problem with encryption.
    let old_msg = msg;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, old_msg.chat_id);
    assert_eq!(msg.download_state, DownloadState::Done);
    assert!(msg.param.get_bool(Param::WantsMdn).unwrap_or_default());
    assert!(msg.get_showpadlock());
    // The message state mustn't be downgraded to `InFresh`.
    assert_eq!(msg.state, MessageState::InNoticed);
    markseen_msgs(alice, vec![msg.id]).await?;
    let msg = Message::load_from_db(alice, msg.id).await?;
    assert_eq!(msg.state, MessageState::InSeen);
    assert_eq!(
        alice
            .sql
            .count("SELECT COUNT(*) FROM smtp_mdns", ())
            .await?,
        1
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_seen_on_imap_when_downloaded() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    alice.set_config(Config::DownloadLimit, Some("1")).await?;
    let bob = &tcm.bob().await;
    let bob_chat_id = tcm.send_recv_accept(alice, bob, "hi").await.chat_id;

    let file_bytes = include_bytes!("../../test-data/image/screenshot.png");
    let mut msg = Message::new(Viewtype::Image);
    msg.set_file_from_bytes(bob, "a.jpg", file_bytes, None)?;
    let sent_msg = bob.send_msg(bob_chat_id, &mut msg).await;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_eq!(msg.state, MessageState::InFresh);

    alice.set_config(Config::DownloadLimit, None).await?;
    let seen = true;
    let rcvd_msg = receive_imf(alice, sent_msg.payload().as_bytes(), seen)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rcvd_msg.chat_id, msg.chat_id);
    let msg = Message::load_from_db(alice, *rcvd_msg.msg_ids.last().unwrap())
        .await
        .unwrap();
    assert_eq!(msg.download_state, DownloadState::Done);
    assert!(msg.param.get_bool(Param::WantsMdn).unwrap_or_default());
    assert!(msg.get_showpadlock());
    assert_eq!(msg.state, MessageState::InSeen);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_state() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    // check both get_state() functions,
    // the one requiring a id and the one requiring an object
    async fn assert_state(t: &Context, msg_id: MsgId, state: MessageState) {
        assert_eq!(msg_id.get_state(t).await.unwrap(), state);
        assert_eq!(
            Message::load_from_db(t, msg_id).await.unwrap().get_state(),
            state
        );
    }

    // check outgoing messages states on sender side
    let mut alice_msg = Message::new_text("hi!".to_string());
    assert_eq!(alice_msg.get_state(), MessageState::Undefined); // message not yet in db, assert_state() won't work

    alice_chat
        .id
        .set_draft(&alice, Some(&mut alice_msg))
        .await?;
    let mut alice_msg = alice_chat.id.get_draft(&alice).await?.unwrap();
    assert_state(&alice, alice_msg.id, MessageState::OutDraft).await;

    let msg_id = chat::send_msg(&alice, alice_chat.id, &mut alice_msg).await?;
    assert_eq!(msg_id, alice_msg.id);
    assert_state(&alice, alice_msg.id, MessageState::OutPending).await;

    let payload = alice.pop_sent_msg().await;
    assert_state(&alice, alice_msg.id, MessageState::OutDelivered).await;

    set_msg_failed(&alice, &mut alice_msg, "badly failed").await?;
    assert_state(&alice, alice_msg.id, MessageState::OutFailed).await;

    // check incoming message states on receiver side
    let bob_msg = bob.recv_msg(&payload).await;
    assert_eq!(bob_chat.id, bob_msg.chat_id);
    assert_state(&bob, bob_msg.id, MessageState::InFresh).await;

    marknoticed_chat(&bob, bob_msg.chat_id).await?;
    assert_state(&bob, bob_msg.id, MessageState::InNoticed).await;

    markseen_msgs(&bob, vec![bob_msg.id]).await?;
    assert_state(&bob, bob_msg.id, MessageState::InSeen).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_is_bot() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Alice receives an auto-generated non-chat message.
    //
    // This could be a holiday notice,
    // in which case the message should be marked as bot-generated,
    // but the contact should not.
    receive_imf(
        &alice,
        b"From: Claire <claire@example.com>\n\
                    To: alice@example.org\n\
                    Message-ID: <789@example.com>\n\
                    Auto-Submitted: auto-generated\n\
                    Date: Fri, 29 Jan 2021 21:37:55 +0000\n\
                    \n\
                    hello\n",
        false,
    )
    .await?;
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.get_text(), "hello".to_string());
    assert!(msg.is_bot());
    let contact = Contact::get_by_id(&alice, msg.from_id).await?;
    assert!(!contact.is_bot());

    // Alice receives a message from Bob the bot.
    receive_imf(
        &alice,
        b"From: Bob <bob@example.com>\n\
                    To: alice@example.org\n\
                    Chat-Version: 1.0\n\
                    Message-ID: <123@example.com>\n\
                    Auto-Submitted: auto-generated\n\
                    Date: Fri, 29 Jan 2021 21:37:55 +0000\n\
                    \n\
                    hello\n",
        false,
    )
    .await?;
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.get_text(), "hello".to_string());
    assert!(msg.is_bot());
    let contact = Contact::get_by_id(&alice, msg.from_id).await?;
    assert!(contact.is_bot());

    // Alice receives a message from Bob who is not the bot anymore.
    receive_imf(
        &alice,
        b"From: Bob <bob@example.com>\n\
                    To: alice@example.org\n\
                    Chat-Version: 1.0\n\
                    Message-ID: <456@example.com>\n\
                    Date: Fri, 29 Jan 2021 21:37:55 +0000\n\
                    \n\
                    hello again\n",
        false,
    )
    .await?;
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.get_text(), "hello again".to_string());
    assert!(!msg.is_bot());
    let contact = Contact::get_by_id(&alice, msg.from_id).await?;
    assert!(!contact.is_bot());

    Ok(())
}

#[test]
fn test_viewtype_derive_display_works_as_expected() {
    assert_eq!(format!("{}", Viewtype::Audio), "Audio");
}

#[test]
fn test_viewtype_values() {
    // values may be written to disk and must not change
    assert_eq!(Viewtype::Unknown, Viewtype::default());
    assert_eq!(Viewtype::Unknown, Viewtype::from_i32(0).unwrap());
    assert_eq!(Viewtype::Text, Viewtype::from_i32(10).unwrap());
    assert_eq!(Viewtype::Image, Viewtype::from_i32(20).unwrap());
    assert_eq!(Viewtype::Gif, Viewtype::from_i32(21).unwrap());
    assert_eq!(Viewtype::Sticker, Viewtype::from_i32(23).unwrap());
    assert_eq!(Viewtype::Audio, Viewtype::from_i32(40).unwrap());
    assert_eq!(Viewtype::Voice, Viewtype::from_i32(41).unwrap());
    assert_eq!(Viewtype::Video, Viewtype::from_i32(50).unwrap());
    assert_eq!(Viewtype::File, Viewtype::from_i32(60).unwrap());
    assert_eq!(
        Viewtype::VideochatInvitation,
        Viewtype::from_i32(70).unwrap()
    );
    assert_eq!(Viewtype::Webxdc, Viewtype::from_i32(80).unwrap());
    assert_eq!(Viewtype::Vcard, Viewtype::from_i32(90).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_quotes() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let chat = alice.create_chat(&bob).await;

    let sent = alice.send_text(chat.id, "> First quote").await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.text, "> First quote");
    assert!(received.quoted_text().is_none());
    assert!(received.quoted_message(&bob).await?.is_none());

    let sent = alice.send_text(chat.id, "> Second quote").await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.text, "> Second quote");
    assert!(received.quoted_text().is_none());
    assert!(received.quoted_message(&bob).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_message_summary_text() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat = t.get_self_chat().await;
    let msg_id = send_text_msg(&t, chat.id, "foo".to_string()).await?;
    let msg = Message::load_from_db(&t, msg_id).await?;
    let summary = msg.get_summary(&t, None).await?;
    assert_eq!(summary.text, "foo");

    // message summary does not change when reactions are applied (in contrast to chatlist summary)
    send_reaction(&t, msg_id, "🫵").await?;
    let msg = Message::load_from_db(&t, msg_id).await?;
    let summary = msg.get_summary(&t, None).await?;
    assert_eq!(summary.text, "foo");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_format_flowed_round_trip() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let chat = alice.create_chat(&bob).await;

    let text = "  Foo bar";
    let sent = alice.send_text(chat.id, text).await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.text, text);

    let text = "Foo                         bar                                                             baz";
    let sent = alice.send_text(chat.id, text).await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.text, text);

    let text = "> xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx > A";
    let sent = alice.send_text(chat.id, text).await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.text, text);

    let python_program = "\
def hello():
    return 'Hello, world!'";
    let sent = alice.send_text(chat.id, python_program).await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.text, python_program);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_msgs_offline() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let chat = alice
        .create_chat_with_contact("Bob", "bob@example.org")
        .await;
    let mut msg = Message::new_text("hi".to_string());
    assert!(chat::send_msg_sync(&alice, chat.id, &mut msg)
        .await
        .is_err());
    let stmt = "SELECT COUNT(*) FROM smtp WHERE msg_id=?";
    assert!(alice.sql.exists(stmt, (msg.id,)).await?);
    delete_msgs(&alice, &[msg.id]).await?;
    assert!(!alice.sql.exists(stmt, (msg.id,)).await?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_msgs_sync() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat_id = alice.create_chat(bob).await.id;

    alice.set_config_bool(Config::SyncMsgs, true).await?;
    alice2.set_config_bool(Config::SyncMsgs, true).await?;
    bob.set_config_bool(Config::SyncMsgs, true).await?;

    // Alice sends a messsage and receives it on the other device
    let sent1 = alice.send_text(alice_chat_id, "foo").await;
    assert_eq!(alice_chat_id.get_msg_cnt(alice).await?, 1);

    let msg = alice2.recv_msg(&sent1).await;
    let alice2_chat_id = msg.chat_id;
    assert_eq!(alice2.get_last_msg_in(alice2_chat_id).await.id, msg.id);
    assert_eq!(alice2_chat_id.get_msg_cnt(alice2).await?, 1);

    // Alice deletes the message; this should happen on both devices as well
    delete_msgs(alice, &[sent1.sender_msg_id]).await?;
    assert_eq!(alice_chat_id.get_msg_cnt(alice).await?, 0);

    test_utils::sync(alice, alice2).await;
    assert_eq!(alice2_chat_id.get_msg_cnt(alice2).await?, 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sanitize_filename_message() -> Result<()> {
    let t = &TestContext::new().await;
    let mut msg = Message::new(Viewtype::File);

    // Even if some of these characters may be valid on one platform,
    // they need to be removed in case a backup is transferred to another platform
    // and the UI there tries to copy the blob to a file with the original name
    // before passing it to an external program.
    msg.set_file_from_bytes(t, "/\\:ee.tx*T ", b"hallo", None)?;
    assert_eq!(msg.get_filename().unwrap(), "ee.txT");

    let blob = msg.param.get_file_blob(t)?.unwrap();
    assert_eq!(blob.suffix().unwrap(), "txt");

    // The filename shouldn't be empty if there were only illegal characters:
    msg.set_file_from_bytes(t, "/\\:.txt", b"hallo", None)?;
    assert_eq!(msg.get_filename().unwrap(), "file.txt");

    msg.set_file_from_bytes(t, "/\\:", b"hallo", None)?;
    assert_eq!(msg.get_filename().unwrap(), "file");

    msg.set_file_from_bytes(t, ".txt", b"hallo", None)?;
    assert_eq!(msg.get_filename().unwrap(), "file.txt");

    Ok(())
}
