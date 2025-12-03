use anyhow::Result;
use async_zip::{Compression, ZipEntryBuilder, tokio::write::ZipFileWriter};
use futures::io::Cursor as FuturesCursor;
use pretty_assertions::assert_eq;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

use crate::EventType;
use crate::config::Config;
use crate::imex::{ImexMode, has_backup, imex};
use crate::message::{Message, Viewtype};
use crate::test_utils::{TestContextManager, create_test_image};
use crate::tests::pre_messages::receiving::send_large_file_message;

/// Test the addition of the download info to message text
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_additional_text_on_different_viewtypes() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let a_group_id = alice.create_group_with_members("test group", &[bob]).await;

    tcm.section("Test metadata preview text for File");
    let (pre_message, _, _) =
        send_large_file_message(alice, a_group_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.text, "test".to_owned());
    assert_eq!(msg.get_text(), "test [test.bin - 976.56 KiB]".to_owned());

    tcm.section("Test metadata preview text for webxdc app");
    let futures_cursor = FuturesCursor::new(Vec::new());
    let mut buffer = futures_cursor.compat_write();
    let mut writer = ZipFileWriter::with_tokio(&mut buffer);
    writer
        .write_entry_whole(
            ZipEntryBuilder::new("index.html".into(), Compression::Stored),
            &[0u8; 1_000_000],
        )
        .await?;
    writer.close().await?;
    let big_webxdc_app = buffer.into_inner().into_inner();

    // Alice sends a larger instance and an update
    let (pre_message, _, _) =
        send_large_file_message(alice, a_group_id, Viewtype::Webxdc, &big_webxdc_app).await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.text, "test".to_owned());
    assert_eq!(msg.get_post_message_viewtype(), Some(Viewtype::Webxdc));
    assert_eq!(msg.get_text(), "test [Mini App - 976.68 KiB]".to_owned());

    tcm.section("Test metadata preview text for Image");
    let (width, height) = (1080, 1920);
    let test_img = create_test_image(width, height)?;
    let (pre_message, _, _) =
        send_large_file_message(alice, a_group_id, Viewtype::Image, &test_img).await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.text, "test".to_owned());
    assert_eq!(msg.get_text(), "test [Image - 146.12 KiB]".to_owned());

    Ok(())
}

/// Test that disabling the addition of the download info works
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_disable_additional_text() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

    let (pre_message, _post_message, _alice_msg_id) =
        send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
            .await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.get_text(), "test [test.bin - 976.56 KiB]".to_owned());

    bob.set_config_bool(Config::HidePreMessageMetadataText, true)
        .await?;

    let msg = Message::load_from_db(bob, msg.id).await?;
    assert_eq!(msg.get_text(), "test".to_owned());
    Ok(())
}

/// Test that disabling the addition of the download info works
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_disable_option_is_exluded_from_backup() -> Result<()> {
    let backup_dir = tempfile::tempdir()?;
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;

    tcm.section("set config option");
    alice
        .set_config_bool(Config::HidePreMessageMetadataText, true)
        .await?;
    assert_eq!(
        alice
            .get_config_bool(Config::HidePreMessageMetadataText)
            .await?,
        true
    );

    tcm.section("export backup");
    imex(alice, ImexMode::ExportBackup, backup_dir.path(), None).await?;
    let _event = alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::ImexProgress(1000)))
        .await;

    tcm.section("import backup");
    let alice2 = &tcm.unconfigured().await;
    let backup = has_backup(alice2, backup_dir.path()).await?;
    imex(alice2, ImexMode::ImportBackup, backup.as_ref(), None).await?;
    let _event = alice2
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::ImexProgress(1000)))
        .await;
    assert_eq!(
        alice.get_primary_self_addr().await?,
        alice2.get_primary_self_addr().await?,
        "address should be the same"
    );

    tcm.section("test if config is reset as expected");
    assert_eq!(
        alice2
            .get_config_bool(Config::HidePreMessageMetadataText)
            .await?,
        false
    );

    Ok(())
}
