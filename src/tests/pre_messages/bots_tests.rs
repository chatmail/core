use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::EventType;
use crate::config::Config;
use crate::download::DownloadState;
use crate::message::Viewtype;
use crate::receive_imf::receive_imf;
use crate::test_utils::TestContextManager;
use crate::tests::pre_messages::util::send_large_file_message;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_bot_pre_message_notifications() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    // Configure Bob as a bot
    bob.set_config_bool(Config::Bot, true).await?;

    let alice_group_id = alice.create_group_with_members("test group", &[&bob]).await;

    let (pre_message, post_message, _alice_msg_id) = send_large_file_message(
        &alice,
        alice_group_id,
        Viewtype::File,
        &vec![0u8; 1_000_000],
    )
    .await?;

    // Bob receives pre-message
    bob.evtracker.clear_events();
    receive_imf(&bob, pre_message.payload().as_bytes(), false).await?;

    // Verify Bob does NOT get an IncomingMsg event for the pre-message
    assert!(
        bob.evtracker
            .get_matching_opt(&bob, |e| matches!(e, EventType::IncomingMsg { .. }))
            .await
            .is_none()
    );

    // Bob receives post-message
    receive_imf(&bob, post_message.payload().as_bytes(), false).await?;

    // Verify Bob DOES get an IncomingMsg event for the complete message
    bob.evtracker
        .get_matching(|e| matches!(e, EventType::IncomingMsg { .. }))
        .await;

    let msg = bob.get_last_msg().await;
    assert_eq!(msg.download_state, DownloadState::Done);

    Ok(())
}
