//! Tests about sending pre-messages
//! - When to send a pre-message and post-message instead of a normal message
//! - Test that sent pre- and post-message contain the right Headers
//!   and that they are send in the correct order (pre-message is sent first.)
use anyhow::Result;
use mailparse::MailHeaderMap;
use tokio::fs;

use crate::chat::{self, create_group, send_msg};
use crate::config::Config;
use crate::download::PRE_MSG_ATTACHMENT_SIZE_THRESHOLD;
use crate::headerdef::{HeaderDef, HeaderDefMap};
use crate::message::{Message, Viewtype};
use crate::test_utils::{self, TestContext, TestContextManager};
/// Tests that Pre-Message is sent for attachment larger than `PRE_MSG_ATTACHMENT_SIZE_THRESHOLD`
/// Also test that Pre-Message is sent first, before the Post-Message
/// And that Autocrypt-gossip and selfavatar never go into Post-Messages
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sending_pre_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let group_id = alice
        .create_group_with_members("test group", &[bob, fiona])
        .await;

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_from_bytes(alice, "test.bin", &[0u8; 300_000], None)?;
    msg.set_text("test".to_owned());

    // assert that test attachment is bigger than limit
    assert!(msg.get_filebytes(alice).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

    let msg_id = chat::send_msg(alice, group_id, &mut msg).await?;
    let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

    //   Pre-Message and Post-Message should be present
    //   and test that correct headers are present on both messages
    assert_eq!(smtp_rows.len(), 2);
    let pre_message = smtp_rows.first().expect("first element exists");
    let pre_message_parsed = mailparse::parse_mail(pre_message.payload.as_bytes())?;
    let post_message = smtp_rows.get(1).expect("second element exists");
    let post_message_parsed = mailparse::parse_mail(post_message.payload.as_bytes())?;

    assert!(
        pre_message_parsed
            .headers
            .get_first_header(HeaderDef::ChatIsPostMessage.get_headername())
            .is_none()
    );
    assert!(
        post_message_parsed
            .headers
            .get_first_header(HeaderDef::ChatIsPostMessage.get_headername())
            .is_some()
    );

    assert_eq!(
        post_message_parsed
            .headers
            .get_header_value(HeaderDef::MessageId),
        Some(format!("<{}>", msg.rfc724_mid)),
        "Post-Message should have the rfc message id of the database message"
    );

    assert_ne!(
        pre_message_parsed
            .headers
            .get_header_value(HeaderDef::MessageId),
        post_message_parsed
            .headers
            .get_header_value(HeaderDef::MessageId),
        "message ids of Pre-Message and Post-Message should be different"
    );

    let decrypted_post_message = bob.parse_msg(post_message).await;
    assert_eq!(decrypted_post_message.decrypting_failed, false);
    assert_eq!(
        decrypted_post_message.header_exists(HeaderDef::ChatPostMessageId),
        false
    );

    let decrypted_pre_message = bob.parse_msg(pre_message).await;
    assert_eq!(
        decrypted_pre_message
            .get_header(HeaderDef::ChatPostMessageId)
            .map(String::from),
        post_message_parsed
            .headers
            .get_header_value(HeaderDef::MessageId)
    );
    assert!(
        pre_message_parsed
            .headers
            .get_header_value(HeaderDef::ChatPostMessageId)
            .is_none(),
        "no Chat-Post-Message-ID header in unprotected headers of Pre-Message"
    );

    Ok(())
}

/// Tests that Pre-Message has autocrypt gossip headers and self avatar
/// and Post-Message doesn't have these headers
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_selfavatar_and_autocrypt_gossip_goto_pre_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let group_id = alice
        .create_group_with_members("test group", &[bob, fiona])
        .await;

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_from_bytes(alice, "test.bin", &[0u8; 300_000], None)?;
    msg.set_text("test".to_owned());

    // assert that test attachment is bigger than limit
    assert!(msg.get_filebytes(alice).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

    // simulate conditions for sending self avatar
    let avatar_src = alice.get_blobdir().join("avatar.png");
    fs::write(&avatar_src, test_utils::AVATAR_900x900_BYTES).await?;
    alice
        .set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
        .await?;

    let msg_id = chat::send_msg(alice, group_id, &mut msg).await?;
    let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

    assert_eq!(smtp_rows.len(), 2);
    let pre_message = smtp_rows.first().expect("first element exists");
    let post_message = smtp_rows.get(1).expect("second element exists");
    let post_message_parsed = mailparse::parse_mail(post_message.payload.as_bytes())?;

    let decrypted_pre_message = bob.parse_msg(pre_message).await;
    assert!(
        decrypted_pre_message
            .get_header(HeaderDef::ChatPostMessageId)
            .is_some(),
        "tested message is not a pre-message, sending order may be broken"
    );
    assert_ne!(decrypted_pre_message.gossiped_keys.len(), 0);
    assert_ne!(decrypted_pre_message.user_avatar, None);

    let decrypted_post_message = bob.parse_msg(post_message).await;
    assert!(
        post_message_parsed
            .headers
            .get_first_header(HeaderDef::ChatIsPostMessage.get_headername())
            .is_some(),
        "tested message is not a Post-Message, sending order may be broken"
    );
    assert_eq!(decrypted_post_message.gossiped_keys.len(), 0);
    assert_eq!(decrypted_post_message.user_avatar, None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unecrypted_gets_no_pre_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;

    let chat = alice
        .create_chat_with_contact("example", "email@example.org")
        .await;

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_from_bytes(alice, "test.bin", &vec![0u8; 300_000], None)?;
    msg.set_text("test".to_owned());

    let msg_id = chat::send_msg(alice, chat.id, &mut msg).await?;
    let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

    assert_eq!(smtp_rows.len(), 1);
    let message_bytes = smtp_rows
        .first()
        .expect("first element exists")
        .payload
        .as_bytes();
    let message = mailparse::parse_mail(message_bytes)?;
    assert!(
        message
            .headers
            .get_first_header(HeaderDef::ChatIsPostMessage.get_headername())
            .is_none(),
    );
    Ok(())
}

/// Tests that no pre message is sent for normal message
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_not_sending_pre_message_no_attachment() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let chat = alice.create_chat(bob).await;

    // send normal text message
    let mut msg = Message::new(Viewtype::Text);
    msg.set_text("test".to_owned());
    let msg_id = chat::send_msg(alice, chat.id, &mut msg).await.unwrap();
    let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

    assert_eq!(smtp_rows.len(), 1, "only one message should be sent");

    let msg = smtp_rows.first().expect("first element exists");
    let mail = mailparse::parse_mail(msg.payload.as_bytes())?;

    assert!(
        mail.headers
            .get_first_header(HeaderDef::ChatIsPostMessage.get_headername())
            .is_none(),
        "no 'Chat-Is-Post-Message'-header should be present"
    );
    assert!(
        mail.headers
            .get_first_header(HeaderDef::ChatPostMessageId.get_headername())
            .is_none(),
        "no 'Chat-Post-Message-ID'-header should be present in clear text headers"
    );
    let decrypted_message = bob.parse_msg(msg).await;
    assert!(
        !decrypted_message.header_exists(HeaderDef::ChatPostMessageId),
        "no 'Chat-Post-Message-ID'-header should be present"
    );

    // test that pre message is not send for large large text
    let mut msg = Message::new(Viewtype::Text);
    let long_text = String::from_utf8(vec![b'a'; 300_000])?;
    assert!(long_text.len() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD.try_into().unwrap());
    msg.set_text(long_text);
    let msg_id = chat::send_msg(alice, chat.id, &mut msg).await.unwrap();
    let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

    assert_eq!(smtp_rows.len(), 1, "only one message should be sent");

    let msg = smtp_rows.first().expect("first element exists");
    let mail = mailparse::parse_mail(msg.payload.as_bytes())?;

    assert!(
        mail.headers
            .get_first_header(HeaderDef::ChatIsPostMessage.get_headername())
            .is_none()
    );
    assert!(
        mail.headers
            .get_first_header(HeaderDef::ChatPostMessageId.get_headername())
            .is_none(),
        "no 'Chat-Post-Message-ID'-header should be present in clear text headers"
    );
    let decrypted_message = bob.parse_msg(msg).await;
    assert!(
        !decrypted_message.header_exists(HeaderDef::ChatPostMessageId),
        "no 'Chat-Post-Message-ID'-header should be present"
    );
    Ok(())
}

/// Tests that no pre message is sent for attachment smaller than `PRE_MSG_ATTACHMENT_SIZE_THRESHOLD`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_not_sending_pre_message_for_small_attachment() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let chat = alice.create_chat(bob).await;

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_from_bytes(alice, "test.bin", &vec![0u8; 100_000], None)?;
    msg.set_text("test".to_owned());

    // assert that test attachment is smaller than limit
    assert!(msg.get_filebytes(alice).await?.unwrap() < PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

    let msg_id = chat::send_msg(alice, chat.id, &mut msg).await.unwrap();
    let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

    //   only one message and no "is Post-Message" header should be present
    assert_eq!(smtp_rows.len(), 1);

    let msg = smtp_rows.first().expect("first element exists");
    let mail = mailparse::parse_mail(msg.payload.as_bytes())?;

    assert!(
        mail.headers
            .get_first_header(HeaderDef::ChatIsPostMessage.get_headername())
            .is_none()
    );
    assert!(
        mail.headers
            .get_first_header(HeaderDef::ChatPostMessageId.get_headername())
            .is_none(),
        "no 'Chat-Post-Message-ID'-header should be present in clear text headers"
    );
    let decrypted_message = bob.parse_msg(msg).await;
    assert!(
        !decrypted_message.header_exists(HeaderDef::ChatPostMessageId),
        "no 'Chat-Post-Message-ID'-header should be present"
    );

    Ok(())
}

/// Tests that pre message is not send for large webxdc updates
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_render_webxdc_status_update_object_range() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group(&t, "a chat").await?;

    let instance = {
        let mut instance = Message::new(Viewtype::File);
        instance.set_file_from_bytes(
            &t,
            "minimal.xdc",
            include_bytes!("../../../test-data/webxdc/minimal.xdc"),
            None,
        )?;
        let instance_msg_id = send_msg(&t, chat_id, &mut instance).await?;
        assert_eq!(instance.viewtype, Viewtype::Webxdc);
        Message::load_from_db(&t, instance_msg_id).await
    }
    .unwrap();

    t.pop_sent_msg().await;
    assert_eq!(t.sql.count("SELECT COUNT(*) FROM smtp", ()).await?, 0);

    let long_text = String::from_utf8(vec![b'a'; 300_000])?;
    assert!(long_text.len() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD.try_into().unwrap());
    t.send_webxdc_status_update(instance.id, &format!("{{\"payload\": \"{long_text}\"}}"))
        .await?;
    t.flush_status_updates().await?;

    assert_eq!(t.sql.count("SELECT COUNT(*) FROM smtp", ()).await?, 1);
    Ok(())
}
