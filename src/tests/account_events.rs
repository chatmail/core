//! contains tests for account (list) events

use std::time::Duration;

use anyhow::Result;
use tempfile::tempdir;

use crate::EventType;
use crate::accounts::Accounts;
use crate::config::Config;
use crate::imex::{BackupProvider, ImexMode, get_backup, has_backup, imex};
use crate::test_utils::{EventTracker, TestContext, TestContextManager, sync};

async fn wait_for_item_changed(context: &TestContext) {
    context
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::AccountsItemChanged))
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_account_event() -> Result<()> {
    let dir = tempdir().unwrap();
    let mut manager = Accounts::new(dir.path().join("accounts"), true).await?;
    let tracker = EventTracker::new(manager.get_event_emitter());

    // create account
    tracker.clear_events();
    let account_id = manager.add_account().await?;
    tracker
        .get_matching(|evt| matches!(evt, EventType::AccountsChanged))
        .await;

    // remove account
    tracker.clear_events();
    manager.remove_account(account_id).await?;
    tracker
        .get_matching(|evt| matches!(evt, EventType::AccountsChanged))
        .await;

    // create closed account
    tracker.clear_events();
    manager.add_closed_account().await?;
    tracker
        .get_matching(|evt| matches!(evt, EventType::AccountsChanged))
        .await;

    Ok(())
}

// configuration is tested by python tests in deltachat-rpc-client/tests/test_account_events.py

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_displayname() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let context = tcm.alice().await;
    context.evtracker.clear_events();
    context
        .set_config(crate::config::Config::Displayname, Some("🐰 Alice"))
        .await?;
    wait_for_item_changed(&context).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_selfavatar() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let context = tcm.alice().await;
    let file = context.dir.path().join("avatar.jpg");
    let bytes = include_bytes!("../../test-data/image/avatar1000x1000.jpg");
    tokio::fs::write(&file, bytes).await?;
    context.evtracker.clear_events();
    context
        .set_config(
            crate::config::Config::Selfavatar,
            Some(file.to_str().unwrap()),
        )
        .await?;
    wait_for_item_changed(&context).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_private_tag() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let context = tcm.alice().await;
    context.evtracker.clear_events();
    context
        .set_config(crate::config::Config::PrivateTag, Some("Wonderland"))
        .await?;
    wait_for_item_changed(&context).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_backup() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let context1 = tcm.alice().await;
    let backup_dir = tempfile::tempdir().unwrap();
    assert!(
        imex(&context1, ImexMode::ExportBackup, backup_dir.path(), None)
            .await
            .is_ok()
    );

    let context2 = TestContext::new().await;
    assert!(!context2.is_configured().await?);
    context2.evtracker.clear_events();
    let backup = has_backup(&context2, backup_dir.path()).await?;
    imex(&context2, ImexMode::ImportBackup, backup.as_ref(), None).await?;
    assert!(context2.is_configured().await?);
    wait_for_item_changed(&context2).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_backup() {
    let mut tcm = TestContextManager::new();
    // Create first device.
    let ctx0 = tcm.alice().await;
    // Prepare to transfer backup.
    let provider = BackupProvider::prepare(&ctx0).await.unwrap();
    // Set up second device.
    let ctx1 = tcm.unconfigured().await;

    ctx1.evtracker.clear_events();
    get_backup(&ctx1, provider.qr()).await.unwrap();

    // Make sure the provider finishes without an error.
    tokio::time::timeout(Duration::from_secs(30), provider)
        .await
        .expect("timed out")
        .expect("error in provider");

    wait_for_item_changed(&ctx1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync() -> Result<()> {
    let alice0 = TestContext::new_alice().await;
    let alice1 = TestContext::new_alice().await;
    for a in [&alice0, &alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    let new_name = "new name";
    alice0
        .set_config(Config::Displayname, Some(new_name))
        .await?;
    alice1.evtracker.clear_events();
    sync(&alice0, &alice1).await;
    wait_for_item_changed(&alice1).await;
    assert_eq!(
        alice1.get_config(Config::Displayname).await?,
        Some(new_name.to_owned())
    );

    assert!(alice0.get_config(Config::Selfavatar).await?.is_none());
    let file = alice0.dir.path().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await?;
    alice0
        .set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
        .await?;
    alice1.evtracker.clear_events();
    sync(&alice0, &alice1).await;
    wait_for_item_changed(&alice1).await;

    Ok(())
}
