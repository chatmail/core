//! Tests about forwarding and saving Pre-Messages
use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::chat::{self};
use crate::chat::{forward_msgs, save_msgs};
use crate::chatlist::get_last_message_for_chat;
use crate::download::{DownloadState, PRE_MSG_ATTACHMENT_SIZE_THRESHOLD};
use crate::message::{Message, Viewtype};
use crate::test_utils::TestContextManager;

/// Test that forwarding Pre-Message should forward additional text to not be empty
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forwarding_pre_message_empty_text() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let pre_message = {
        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "test.bin", &vec![0u8; 1_000_000], None)?;
        assert!(msg.get_filebytes(alice).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);
        let msg_id = chat::send_msg(alice, alice_group_id, &mut msg).await?;
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;
        assert_eq!(smtp_rows.len(), 2);
        smtp_rows.first().expect("Pre-Message exists").to_owned()
    };

    let bob_msg = bob.recv_msg(&pre_message).await;
    assert_eq!(bob_msg.download_state, DownloadState::Available);
    bob_msg.chat_id.accept(bob).await?;
    tcm.section("forward pre message and check it on bobs side");
    forward_msgs(bob, &[bob_msg.id], bob_msg.chat_id).await?;
    let forwarded_msg_id = get_last_message_for_chat(bob, bob_msg.chat_id)
        .await?
        .unwrap();
    let forwarded_msg = Message::load_from_db(bob, forwarded_msg_id).await?;
    assert_eq!(forwarded_msg.is_forwarded(), true);
    assert_eq!(forwarded_msg.download_state(), DownloadState::Done);
    assert_eq!(
        forwarded_msg
            .param
            .exists(crate::param::Param::PostMessageFileBytes),
        false,
        "PostMessageFileBytes not set"
    );
    assert_eq!(
        forwarded_msg
            .param
            .exists(crate::param::Param::PostMessageViewtype),
        false,
        "PostMessageViewtype not set"
    );
    assert_eq!(
        forwarded_msg.get_text(),
        " [test.bin – 976.56 KiB]".to_owned()
    );
    assert_eq!(forwarded_msg.get_viewtype(), Viewtype::Text);
    assert!(forwarded_msg.additional_text.is_empty());
    tcm.section("check it on alices side");
    let sent_forward_msg = bob.pop_sent_msg().await;
    let alice_forwarded_msg = alice.recv_msg(&sent_forward_msg).await;
    assert!(alice_forwarded_msg.additional_text.is_empty());
    assert_eq!(alice_forwarded_msg.is_forwarded(), true);
    assert_eq!(alice_forwarded_msg.download_state(), DownloadState::Done);
    assert_eq!(
        alice_forwarded_msg
            .param
            .exists(crate::param::Param::PostMessageFileBytes),
        false,
        "PostMessageFileBytes not set"
    );
    assert_eq!(
        alice_forwarded_msg
            .param
            .exists(crate::param::Param::PostMessageViewtype),
        false,
        "PostMessageViewtype not set"
    );
    assert_eq!(
        alice_forwarded_msg.get_text(),
        " [test.bin – 976.56 KiB]".to_owned()
    );

    Ok(())
}

/// Test that forwarding Pre-Message should forward additional text to not be empty
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_saving_pre_message_empty_text() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let pre_message = {
        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "test.bin", &vec![0u8; 1_000_000], None)?;
        assert!(msg.get_filebytes(alice).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);
        let msg_id = chat::send_msg(alice, alice_group_id, &mut msg).await?;
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;
        assert_eq!(smtp_rows.len(), 2);
        smtp_rows.first().expect("Pre-Message exists").to_owned()
    };

    let bob_msg = bob.recv_msg(&pre_message).await;
    assert_eq!(bob_msg.download_state, DownloadState::Available);
    bob_msg.chat_id.accept(bob).await?;
    tcm.section("save pre message and check it");
    save_msgs(bob, &[bob_msg.id]).await?;
    let saved_msg_id = get_last_message_for_chat(bob, bob.get_self_chat().await.id)
        .await?
        .unwrap();
    let saved_msg = Message::load_from_db(bob, saved_msg_id).await?;
    assert!(saved_msg.additional_text.is_empty());
    assert!(saved_msg.get_original_msg_id(bob).await?.is_some());
    assert_eq!(saved_msg.download_state(), DownloadState::Done);
    assert_eq!(saved_msg.get_text(), " [test.bin – 976.56 KiB]".to_owned());

    Ok(())
}
