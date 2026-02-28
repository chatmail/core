//! Tests about receiving Pre-Messages and Post-Message
use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::EventType;
use crate::chat;
use crate::contact;
use crate::download::{DownloadState, PRE_MSG_ATTACHMENT_SIZE_THRESHOLD, PostMsgMetadata};
use crate::message::{Message, MessageState, Viewtype, delete_msgs, markseen_msgs};
use crate::mimeparser::MimeMessage;
use crate::param::Param;
use crate::reaction::{get_msg_reactions, send_reaction};
use crate::summary::assert_summary_texts;
use crate::test_utils::TestContextManager;
use crate::tests::pre_messages::util::{
    send_large_file_message, send_large_image_message, send_large_webxdc_message,
};
use crate::webxdc::StatusUpdateSerial;

/// Test that mimeparser can correctly detect and parse pre-messages and Post-Messages
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_pre_message_and_post_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, post_message, _alice_msg_id) =
        send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
            .await?;

    let parsed_pre_message = MimeMessage::from_bytes(bob, pre_message.payload.as_bytes()).await?;
    let parsed_post_message = MimeMessage::from_bytes(bob, post_message.payload.as_bytes()).await?;

    assert_eq!(
        parsed_post_message.pre_message,
        crate::mimeparser::PreMessageMode::Post,
    );

    assert_eq!(
        parsed_pre_message.pre_message,
        crate::mimeparser::PreMessageMode::Pre {
            post_msg_rfc724_mid: parsed_post_message.get_rfc724_mid().unwrap(),
            metadata: Some(PostMsgMetadata {
                size: 1_000_000,
                viewtype: Viewtype::File,
                filename: "test.bin".to_string(),
                wh: None,
                duration: None
            })
        }
    );

    Ok(())
}

/// Test receiving pre-messages and creation of the placeholder message with the metadata
/// for file attachment
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_pre_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, _post_message, _alice_msg_id) =
        send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
            .await?;

    let msg = bob.recv_msg(&pre_message).await;

    assert_eq!(msg.download_state(), DownloadState::Available);
    assert_eq!(msg.viewtype, Viewtype::Text);
    assert_eq!(msg.text, "test".to_owned());

    // test that metadata is correctly returned by methods
    assert_eq!(msg.get_filebytes(bob).await?, Some(1_000_000));
    assert_eq!(msg.get_post_message_viewtype(), Some(Viewtype::File));
    assert_eq!(msg.get_filename(), Some("test.bin".to_owned()));
    assert_summary_texts(&msg, bob, "📎 test.bin – test").await;

    // Webxdc w/o manifest.
    let (pre_message, ..) = send_large_webxdc_message(alice, alice_group_id).await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_summary_texts(&msg, bob, "📱 test.xdc – test").await;

    let (pre_message, ..) = send_large_file_message(
        alice,
        alice_group_id,
        Viewtype::Webxdc,
        include_bytes!("../../../test-data/webxdc/timetracking-v0.10.1.xdc"),
    )
    .await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_summary_texts(&msg, bob, "📱 TimeTracking – test").await;

    let (pre_message, ..) = send_large_file_message(
        alice,
        alice_group_id,
        Viewtype::Vcard,
        format!(
            "BEGIN:VCARD\r\n\
             VERSION:4.0\r\n\
             EMAIL:alice@example.org\r\n\
             FN:Alice\r\n\
             NOTE:{}\r\n\
             END:VCARD\r\n",
            String::from_utf8(vec![97u8; 1_000_000])?,
        )
        .as_bytes(),
    )
    .await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_summary_texts(&msg, bob, "👤 test").await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_webxdc() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("", &[bob]).await;

    let (pre_msg, post_msg, _) = send_large_file_message(
        alice,
        alice_group_id,
        Viewtype::Webxdc,
        include_bytes!("../../../test-data/webxdc/timetracking-v0.10.1.xdc"),
    )
    .await?;
    let msg = bob.recv_msg(&pre_msg).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_summary_texts(&msg, bob, "📱 TimeTracking – test").await;
    assert_eq!(msg.get_filename().unwrap(), "TimeTracking");

    bob.recv_msg_trash(&post_msg).await;
    let msg = Message::load_from_db(bob, msg.id).await?;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_summary_texts(&msg, bob, "📱 TimeTracking – test").await;
    assert_eq!(msg.get_filename().unwrap(), "test.xdc");
    Ok(())
}

/// Test receiving the Post-Message after receiving the pre-message
/// for file attachment
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_pre_message_and_dl_post_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, post_message, _alice_msg_id) =
        send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
            .await?;

    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state(), DownloadState::Available);
    assert_eq!(msg.viewtype, Viewtype::Text);
    assert!(msg.param.exists(Param::PostMessageViewtype));
    assert!(msg.param.exists(Param::PostMessageFileBytes));
    assert_eq!(msg.text, "test".to_owned());
    let _ = bob.recv_msg_trash(&post_message).await;
    let msg = Message::load_from_db(bob, msg.id).await?;
    assert_eq!(msg.download_state(), DownloadState::Done);
    assert_eq!(msg.viewtype, Viewtype::File);
    assert_eq!(msg.param.exists(Param::PostMessageViewtype), false);
    assert_eq!(msg.param.exists(Param::PostMessageFileBytes), false);
    assert_eq!(msg.text, "test".to_owned());
    Ok(())
}

/// Test out of order receiving. Post-Message is received & downloaded before pre-message.
/// In that case pre-message shall be trashed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_out_of_order_receiving() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, post_message, _alice_msg_id) =
        send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
            .await?;

    let msg = bob.recv_msg(&post_message).await;
    assert_eq!(msg.download_state(), DownloadState::Done);
    assert_eq!(msg.viewtype, Viewtype::File);
    let _ = bob.recv_msg_trash(&pre_message).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lost_pre_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat_id = alice.create_group_with_members("foos", &[bob]).await;

    let file_bytes = include_bytes!("../../../test-data/image/screenshot.gif");
    let mut msg = Message::new(Viewtype::Image);
    msg.set_file_from_bytes(alice, "a.jpg", file_bytes, None)?;
    msg.set_text("populate".to_string());
    let full_msg = alice.send_msg(alice_chat_id, &mut msg).await;
    let _pre_msg = alice.pop_sent_msg().await;
    let msg = bob.recv_msg(&full_msg).await;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_eq!(msg.text, "");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_post_msg_bad_sender() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let chat_id_alice = alice.create_group_with_members("", &[bob, fiona]).await;
    let file_bytes = include_bytes!("../../../test-data/image/screenshot.gif");

    let mut msg_alice = Message::new(Viewtype::Image);
    msg_alice.set_file_from_bytes(alice, "a.jpg", file_bytes, None)?;
    let post_msg_alice = alice.send_msg(chat_id_alice, &mut msg_alice).await;
    let pre_msg_alice = alice.pop_sent_msg().await;
    let msg_bob = bob.recv_msg(&pre_msg_alice).await;
    assert_eq!(msg_bob.download_state, DownloadState::Available);
    let msg_cnt_bob = msg_bob.chat_id.get_msg_cnt(bob).await?;

    let chat_id_fiona = fiona.recv_msg(&pre_msg_alice).await.chat_id;
    chat_id_fiona.accept(fiona).await?;
    let mut msg_fiona = Message::new(Viewtype::Image);
    msg_fiona.rfc724_mid = msg_alice.rfc724_mid.clone();
    msg_fiona.set_file_from_bytes(fiona, "a.jpg", file_bytes, None)?;
    let post_msg_fiona = fiona.send_msg(chat_id_fiona, &mut msg_fiona).await;
    let _pre_msg = fiona.pop_sent_msg().await;
    bob.recv_msg_trash(&post_msg_fiona).await;
    let msg_bob = Message::load_from_db(bob, msg_bob.id).await?;
    assert_eq!(msg_bob.download_state, DownloadState::Available);
    assert_eq!(msg_bob.chat_id.get_msg_cnt(bob).await?, msg_cnt_bob);

    bob.recv_msg_trash(&post_msg_alice).await;
    let msg_bob = Message::load_from_db(bob, msg_bob.id).await?;
    assert_eq!(msg_bob.download_state, DownloadState::Done);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lost_pre_msg_vs_new_member() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let chat_id_alice = alice.create_group_with_members("", &[bob, fiona]).await;
    let file_bytes = include_bytes!("../../../test-data/image/screenshot.gif");

    let mut msg_alice = Message::new(Viewtype::Image);
    msg_alice.set_file_from_bytes(alice, "a.jpg", file_bytes, None)?;
    let post_msg_alice = alice.send_msg(chat_id_alice, &mut msg_alice).await;
    let _pre_msg = alice.pop_sent_msg().await;
    let msg_bob = bob.recv_msg(&post_msg_alice).await;
    assert_eq!(msg_bob.download_state, DownloadState::Done);
    let chat_id_bob = msg_bob.chat_id;
    assert_eq!(chat::get_chat_contacts(bob, chat_id_bob).await?.len(), 3);

    chat_id_bob.accept(bob).await?;
    let sent = bob.send_text(chat_id_bob, "Hi all").await;
    alice.recv_msg(&sent).await;
    fiona.recv_msg_trash(&sent).await; // Undecryptable message
    Ok(())
}

/// Test receiving the Post-Message after receiving an edit after receiving the pre-message
/// for file attachment
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_pre_message_then_edit_and_then_dl_post_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, post_message, alice_msg_id) =
        send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
            .await?;

    chat::send_edit_request(alice, alice_msg_id, "new_text".to_owned()).await?;
    let edit_request = alice.pop_sent_msg().await;

    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state(), DownloadState::Available);
    assert_eq!(msg.text, "test".to_owned());
    let _ = bob.recv_msg_trash(&edit_request).await;
    let msg = Message::load_from_db(bob, msg.id).await?;
    assert_eq!(msg.download_state(), DownloadState::Available);
    assert_eq!(msg.text, "new_text".to_owned());
    let _ = bob.recv_msg_trash(&post_message).await;
    let msg = Message::load_from_db(bob, msg.id).await?;
    assert_eq!(msg.download_state(), DownloadState::Done);
    assert_eq!(msg.viewtype, Viewtype::File);
    assert_eq!(msg.text, "new_text".to_owned());
    Ok(())
}

/// Process normal message with file attachment (neither post nor pre message)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_normal_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_from_bytes(
        alice,
        "test.bin",
        &vec![0u8; (PRE_MSG_ATTACHMENT_SIZE_THRESHOLD - 10_000) as usize],
        None,
    )?;
    msg.set_text("test".to_owned());
    let msg_id = chat::send_msg(alice, alice_group_id, &mut msg).await?;

    let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;
    assert_eq!(smtp_rows.len(), 1);
    let message = smtp_rows.first().expect("message exists");

    let msg = bob.recv_msg(message).await;
    assert_eq!(msg.download_state(), DownloadState::Done);
    assert_eq!(msg.viewtype, Viewtype::File);
    assert_eq!(msg.text, "test".to_owned());
    Ok(())
}

/// Test receiving pre-messages and creation of the placeholder message with the metadata
/// for image attachment
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_pre_message_image() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, _post_message, _alice_msg_id) =
        send_large_image_message(alice, alice_group_id).await?;

    let msg = bob.recv_msg(&pre_message).await;

    assert_eq!(msg.download_state(), DownloadState::Available);
    assert_eq!(msg.viewtype, Viewtype::Text);
    assert_eq!(msg.text, "test".to_owned());

    // test that metadata is correctly returned by methods
    assert_eq!(msg.get_post_message_viewtype(), Some(Viewtype::Image));
    // recoded image dimensions
    assert_eq!(msg.get_filebytes(bob).await?, Some(149632));
    assert_eq!(msg.get_height(), 1280);
    assert_eq!(msg.get_width(), 720);

    Ok(())
}

/// Test receiving reaction on pre-message
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reaction_on_pre_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, post_message, alice_msg_id) =
        send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
            .await?;

    // Bob receives pre-message
    let bob_msg = bob.recv_msg(&pre_message).await;
    assert_eq!(bob_msg.download_state(), DownloadState::Available);

    // Alice sends reaction to her own message
    send_reaction(alice, alice_msg_id, "👍").await?;

    // Bob receives the reaction
    bob.recv_msg_hidden(&alice.pop_sent_msg().await).await;

    // Test if Bob sees reaction
    let reactions = get_msg_reactions(bob, bob_msg.id).await?;
    assert_eq!(reactions.to_string(), "👍1");

    // Bob downloads Post-Message
    bob.recv_msg_trash(&post_message).await;
    let msg = Message::load_from_db(bob, bob_msg.id).await?;
    assert_eq!(msg.download_state(), DownloadState::Done);

    // Test if Bob still sees reaction
    let reactions = get_msg_reactions(bob, bob_msg.id).await?;
    assert_eq!(reactions.to_string(), "👍1");

    Ok(())
}

/// Tests that fully downloading the message
/// works but does not reappear when it was already deleted
/// (as in the Message-ID already exists in the database
/// and is assigned to the trash chat).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_full_download_after_trashed() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let bob_group_id = bob.create_group_with_members("test group", &[alice]).await;

    let (pre_message, post_message, _bob_msg_id) =
        send_large_file_message(bob, bob_group_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;

    // Download message from Bob partially.
    let alice_msg = alice.recv_msg(&pre_message).await;

    // Delete the received message.
    // Note that it remains in the database in the trash chat.
    delete_msgs(alice, &[alice_msg.id]).await?;

    // Fully download message after deletion.
    alice.recv_msg_trash(&post_message).await;

    // The message does not reappear.
    let msg = Message::load_from_db_optional(bob, alice_msg.id).await?;
    assert!(msg.is_none());

    Ok(())
}

/// Test that webxdc updates are received for pre-messages
/// and available when the Post-Message is downloaded
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_update_for_not_downloaded_instance() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    // Alice sends a larger instance and an update
    let (pre_message, post_message, alice_sent_instance_msg_id) =
        send_large_webxdc_message(alice, alice_group_id).await?;
    alice
        .send_webxdc_status_update(
            alice_sent_instance_msg_id,
            r#"{"payload": 7, "summary":"sum", "document":"doc"}"#,
        )
        .await?;
    alice.flush_status_updates().await?;
    let webxdc_update = alice.pop_sent_msg().await;

    // Bob does not download instance but already receives update
    let bob_instance = bob.recv_msg(&pre_message).await;
    assert_eq!(bob_instance.download_state, DownloadState::Available);
    bob.recv_msg_trash(&webxdc_update).await;

    // Bob downloads instance, updates should be assigned correctly
    bob.recv_msg_trash(&post_message).await;

    let bob_instance = bob.get_last_msg().await;
    assert_eq!(bob_instance.viewtype, Viewtype::Webxdc);
    assert_eq!(bob_instance.download_state, DownloadState::Done);
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial::new(0))
            .await?,
        r#"[{"payload":7,"document":"doc","summary":"sum","serial":1,"max_serial":1}]"#
    );
    let info = bob_instance.get_webxdc_info(bob).await?;
    assert_eq!(info.document, "doc");
    assert_eq!(info.summary, "sum");

    Ok(())
}

/// Test mark seen pre-message
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_markseen_pre_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let bob_chat_id = bob.create_chat(alice).await.id;
    alice.create_chat(bob).await; // Make sure the chat is accepted.

    tcm.section("Bob sends a large message to Alice");
    let (pre_message, post_message, _bob_msg_id) =
        send_large_file_message(bob, bob_chat_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;

    tcm.section("Alice receives a pre-message message from Bob");
    let msg = alice.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert!(msg.param.get_bool(Param::WantsMdn).unwrap_or_default());
    assert_eq!(msg.state, MessageState::InFresh);

    tcm.section("Alice marks the pre-message as read and sends a MDN");
    markseen_msgs(alice, vec![msg.id]).await?;
    assert_eq!(msg.id.get_state(alice).await?, MessageState::InSeen);
    assert_eq!(
        alice
            .sql
            .count("SELECT COUNT(*) FROM smtp_mdns", ())
            .await?,
        1
    );

    tcm.section("Alice downloads message");
    alice.recv_msg_trash(&post_message).await;
    let msg = Message::load_from_db(alice, msg.id).await?;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert!(msg.param.get_bool(Param::WantsMdn).unwrap_or_default());
    assert_eq!(
        msg.state,
        MessageState::InSeen,
        "The message state mustn't be downgraded to `InFresh`"
    );

    Ok(())
}

/// Test that pre-message can start a chat
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pre_msg_can_start_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("establishing a DM chat between alice and bob");
    let bob_alice_dm_chat_id = bob.create_chat(alice).await.id;
    alice.create_chat(bob).await; // Make sure the chat is accepted.

    tcm.section("Alice prepares chat");
    let chat_id = chat::create_group(alice, "my group").await?;
    let contacts = contact::Contact::get_all(alice, 0, None).await?;
    let alice_bob_id = contacts.first().expect("contact exists");
    chat::add_contact_to_chat(alice, chat_id, *alice_bob_id).await?;

    tcm.section("Alice sends large message to promote/start chat");
    let (pre_message, _post_message, _alice_msg_id) =
        send_large_file_message(alice, chat_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;

    tcm.section("Bob receives the pre-message message from Alice");
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_ne!(msg.chat_id, bob_alice_dm_chat_id);
    let chat = chat::Chat::load_from_db(bob, msg.chat_id).await?;
    assert_eq!(chat.name, "my group");

    Ok(())
}

/// Test that Post-Message can start a chat
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_post_msg_can_start_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("establishing a DM chat between alice and bob");
    let bob_alice_dm_chat_id = bob.create_chat(alice).await.id;
    alice.create_chat(bob).await; // Make sure the chat is accepted.

    tcm.section("Alice prepares chat");
    let chat_id = chat::create_group(alice, "my group").await?;
    let contacts = contact::Contact::get_all(alice, 0, None).await?;
    let alice_bob_id = contacts.first().expect("contact exists");
    chat::add_contact_to_chat(alice, chat_id, *alice_bob_id).await?;

    tcm.section("Alice sends large message to promote/start chat");
    let (_pre_message, post_message, _bob_msg_id) =
        send_large_file_message(alice, chat_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;

    tcm.section("Bob receives the pre-message message from Alice");
    let msg = bob.recv_msg(&post_message).await;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_ne!(msg.chat_id, bob_alice_dm_chat_id);
    let chat = chat::Chat::load_from_db(bob, msg.chat_id).await?;
    assert_eq!(chat.name, "my group");

    Ok(())
}

/// Test that message ordering is still correct after downloading
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_download_later_keeps_message_order() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section(
        "establishing a DM chat between alice and bob and bob sends large message to alice",
    );
    let bob_alice_dm_chat = bob.create_chat(alice).await.id;
    alice.create_chat(bob).await; // Make sure the chat is accepted.
    let (pre_message, post_message, _bob_msg_id) = send_large_file_message(
        bob,
        bob_alice_dm_chat,
        Viewtype::File,
        &vec![0u8; 1_000_000],
    )
    .await?;

    tcm.section("Alice downloads pre-message");
    let msg = alice.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_eq!(msg.state, MessageState::InFresh);
    assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, msg.id);

    tcm.section("Bob sends hi to Alice");
    let hi_msg = tcm.send_recv(bob, alice, "hi").await;
    assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, hi_msg.id);

    tcm.section("Alice downloads Post-Message");
    alice.recv_msg_trash(&post_message).await;
    let msg = Message::load_from_db(alice, msg.id).await?;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, hi_msg.id);
    assert!(msg.timestamp_sort <= hi_msg.timestamp_sort);

    Ok(())
}

/// Test that ChatlistItemChanged event is emitted when downloading Post-Message
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chatlist_event_on_post_msg_download() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section(
        "establishing a DM chat between alice and bob and bob sends large message to alice",
    );
    let bob_alice_dm_chat = bob.create_chat(alice).await.id;
    alice.create_chat(bob).await; // Make sure the chat is accepted.
    let (pre_message, post_message, _bob_msg_id) = send_large_file_message(
        bob,
        bob_alice_dm_chat,
        Viewtype::File,
        &vec![0u8; 1_000_000],
    )
    .await?;

    tcm.section("Alice downloads pre-message");
    let msg = alice.recv_msg(&pre_message).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_eq!(msg.state, MessageState::InFresh);
    assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, msg.id);

    tcm.section("Alice downloads Post-Message and waits for ChatlistItemChanged event ");
    alice.evtracker.clear_events();
    alice.recv_msg_trash(&post_message).await;
    let msg = Message::load_from_db(alice, msg.id).await?;
    assert_eq!(msg.download_state, DownloadState::Done);
    alice
        .evtracker
        .get_matching(|e| {
            e == &EventType::ChatlistItemChanged {
                chat_id: Some(msg.chat_id),
            }
        })
        .await;

    Ok(())
}
