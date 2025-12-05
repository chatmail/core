use num_traits::FromPrimitive;

use super::*;
use crate::test_utils::{TestContext, TestContextManager, sync};

#[test]
fn test_to_string() {
    assert_eq!(Config::MailServer.to_string(), "mail_server");
    assert_eq!(Config::from_str("mail_server"), Ok(Config::MailServer));

    assert_eq!(Config::SysConfigKeys.to_string(), "sys.config_keys");
    assert_eq!(
        Config::from_str("sys.config_keys"),
        Ok(Config::SysConfigKeys)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_config_addr() {
    let t = TestContext::new().await;

    // Test that uppercase address get lowercased.
    assert!(
        t.set_config(Config::Addr, Some("Foobar@eXample.oRg"))
            .await
            .is_ok()
    );
    assert_eq!(
        t.get_config(Config::Addr).await.unwrap().unwrap(),
        "foobar@example.org"
    );
}

/// Tests that "bot" config can only be set to "0" or "1".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_config_bot() {
    let t = TestContext::new().await;

    assert!(t.set_config(Config::Bot, None).await.is_ok());
    assert!(t.set_config(Config::Bot, Some("0")).await.is_ok());
    assert!(t.set_config(Config::Bot, Some("1")).await.is_ok());
    assert!(t.set_config(Config::Bot, Some("2")).await.is_err());
    assert!(t.set_config(Config::Bot, Some("Foobar")).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_media_quality_config_option() {
    let t = TestContext::new().await;
    let media_quality = t.get_config_int(Config::MediaQuality).await.unwrap();
    assert_eq!(media_quality, 0);
    let media_quality = constants::MediaQuality::from_i32(media_quality).unwrap_or_default();
    assert_eq!(media_quality, constants::MediaQuality::Balanced);

    t.set_config(Config::MediaQuality, Some("1")).await.unwrap();

    let media_quality = t.get_config_int(Config::MediaQuality).await.unwrap();
    assert_eq!(media_quality, 1);
    assert_eq!(constants::MediaQuality::Worse as i32, 1);
    let media_quality = constants::MediaQuality::from_i32(media_quality).unwrap_or_default();
    assert_eq!(media_quality, constants::MediaQuality::Worse);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ui_config() -> Result<()> {
    let t = TestContext::new().await;

    assert_eq!(t.get_ui_config("ui.desktop.linux.systray").await?, None);

    t.set_ui_config("ui.android.screen_security", Some("safe"))
        .await?;
    assert_eq!(
        t.get_ui_config("ui.android.screen_security").await?,
        Some("safe".to_string())
    );

    t.set_ui_config("ui.android.screen_security", None).await?;
    assert_eq!(t.get_ui_config("ui.android.screen_security").await?, None);

    assert!(t.set_ui_config("configured", Some("bar")).await.is_err());

    Ok(())
}

/// Regression test for https://github.com/deltachat/deltachat-core-rust/issues/3012
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_config_bool() -> Result<()> {
    let t = TestContext::new().await;

    // We need some config that defaults to true
    let c = Config::MdnsEnabled;
    assert_eq!(t.get_config_bool(c).await?, true);
    t.set_config_bool(c, false).await?;
    assert_eq!(t.get_config_bool(c).await?, false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mdns_default_behaviour() -> Result<()> {
    let t = &TestContext::new_alice().await;
    assert!(t.should_request_mdns().await?);
    assert!(t.should_send_mdns().await?);
    assert!(t.get_config_bool_opt(Config::MdnsEnabled).await?.is_none());
    // The setting should be displayed correctly.
    assert!(t.get_config_bool(Config::MdnsEnabled).await?);

    t.set_config_bool(Config::Bot, true).await?;
    assert!(!t.should_request_mdns().await?);
    assert!(t.should_send_mdns().await?);
    assert!(t.get_config_bool_opt(Config::MdnsEnabled).await?.is_none());
    assert!(t.get_config_bool(Config::MdnsEnabled).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_server_after_default() -> Result<()> {
    let t = &TestContext::new_alice().await;

    // Check that the settings are displayed correctly.
    assert_eq!(t.get_config(Config::BccSelf).await?, Some("1".to_string()));
    assert_eq!(
        t.get_config(Config::DeleteServerAfter).await?,
        Some("0".to_string())
    );

    // Leaving emails on the server even w/o `BccSelf` is a good default at least because other
    // MUAs do so even if the server doesn't save sent messages to some sentbox (like Gmail
    // does).
    t.set_config_bool(Config::BccSelf, false).await?;
    assert_eq!(
        t.get_config(Config::DeleteServerAfter).await?,
        Some("0".to_string())
    );
    Ok(())
}

const SAVED_MESSAGES_DEDUPLICATED_FILE: &str = "969142cb84015bc135767bc2370934a.png";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync() -> Result<()> {
    let alice0 = TestContext::new_alice().await;
    let alice1 = TestContext::new_alice().await;
    for a in [&alice0, &alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    let mdns_enabled = alice0.get_config_bool(Config::MdnsEnabled).await?;
    // Alice1 has a different config value.
    alice1
        .set_config_bool(Config::MdnsEnabled, !mdns_enabled)
        .await?;
    // This changes nothing, but still sends a sync message.
    alice0
        .set_config_bool(Config::MdnsEnabled, mdns_enabled)
        .await?;
    sync(&alice0, &alice1).await;
    assert_eq!(
        alice1.get_config_bool(Config::MdnsEnabled).await?,
        mdns_enabled
    );

    // Reset to default. Test that it's not synced because defaults may differ across client
    // versions.
    alice0.set_config(Config::MdnsEnabled, None).await?;
    alice0.set_config_bool(Config::MdnsEnabled, false).await?;
    sync(&alice0, &alice1).await;
    assert_eq!(alice1.get_config_bool(Config::MdnsEnabled).await?, false);

    for key in [Config::ShowEmails, Config::MvboxMove] {
        let val = alice0.get_config_bool(key).await?;
        alice0.set_config_bool(key, !val).await?;
        sync(&alice0, &alice1).await;
        assert_eq!(alice1.get_config_bool(key).await?, !val);
    }

    // `Config::SyncMsgs` mustn't be synced.
    alice0.set_config_bool(Config::SyncMsgs, false).await?;
    alice0.set_config_bool(Config::SyncMsgs, true).await?;
    alice0.set_config_bool(Config::MdnsEnabled, true).await?;
    sync(&alice0, &alice1).await;
    assert!(alice1.get_config_bool(Config::MdnsEnabled).await?);

    // Usual sync scenario.
    async fn test_config_str(
        alice0: &TestContext,
        alice1: &TestContext,
        key: Config,
        val: &str,
    ) -> Result<()> {
        alice0.set_config(key, Some(val)).await?;
        sync(alice0, alice1).await;
        assert_eq!(alice1.get_config(key).await?, Some(val.to_string()));
        Ok(())
    }
    test_config_str(&alice0, &alice1, Config::Displayname, "Alice Sync").await?;
    test_config_str(&alice0, &alice1, Config::Selfstatus, "My status").await?;

    assert!(alice0.get_config(Config::Selfavatar).await?.is_none());
    let file = alice0.dir.path().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await?;
    alice0
        .set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
        .await?;
    sync(&alice0, &alice1).await;
    // There was a bug that a sync message creates the self-chat with the user avatar instead of
    // the special icon and that remains so when the self-chat becomes user-visible. Let's check
    // this.
    let self_chat = alice0.get_self_chat().await;
    let self_chat_avatar_path = self_chat.get_profile_image(&alice0).await?.unwrap();
    assert_eq!(
        self_chat_avatar_path,
        alice0.get_blobdir().join(SAVED_MESSAGES_DEDUPLICATED_FILE)
    );
    assert!(
        alice1
            .get_config(Config::Selfavatar)
            .await?
            .filter(|path| path.ends_with(".png"))
            .is_some()
    );
    alice0.set_config(Config::Selfavatar, None).await?;
    sync(&alice0, &alice1).await;
    assert!(alice1.get_config(Config::Selfavatar).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_sync_on_self_sent_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    let status = "Sent via usual message";
    alice0.set_config(Config::Selfstatus, Some(status)).await?;
    alice0.send_sync_msg().await?;
    alice0.pop_sent_sync_msg().await;
    let status1 = "Synced via sync message";
    alice1.set_config(Config::Selfstatus, Some(status1)).await?;
    tcm.send_recv(alice0, alice1, "hi Alice!").await;
    assert_eq!(
        alice1.get_config(Config::Selfstatus).await?,
        Some(status1.to_string())
    );
    sync(alice1, alice0).await;
    assert_eq!(
        alice0.get_config(Config::Selfstatus).await?,
        Some(status1.to_string())
    );

    // Need a chat with another contact to send self-avatar.
    let bob = &tcm.bob().await;
    let a0b_chat_id = tcm.send_recv_accept(bob, alice0, "hi").await.chat_id;
    let file = alice0.dir.path().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await?;
    alice0
        .set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
        .await?;
    alice0.send_sync_msg().await?;
    alice0.pop_sent_sync_msg().await;
    let file = alice1.dir.path().join("avatar.jpg");
    let bytes = include_bytes!("../../test-data/image/avatar1000x1000.jpg");
    tokio::fs::write(&file, bytes).await?;
    alice1
        .set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
        .await?;
    let sent_msg = alice0.send_text(a0b_chat_id, "hi").await;
    alice1.recv_msg(&sent_msg).await;
    assert!(
        alice1
            .get_config(Config::Selfavatar)
            .await?
            .filter(|path| path.ends_with(".jpg"))
            .is_some()
    );
    sync(alice1, alice0).await;
    assert!(
        alice0
            .get_config(Config::Selfavatar)
            .await?
            .filter(|path| path.ends_with(".jpg"))
            .is_some()
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_event_config_synced() -> Result<()> {
    let alice0 = TestContext::new_alice().await;
    let alice1 = TestContext::new_alice().await;
    for a in [&alice0, &alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    alice0
        .set_config(Config::Displayname, Some("Alice Sync"))
        .await?;
    alice0
        .evtracker
        .get_matching(|e| {
            matches!(
                e,
                EventType::ConfigSynced {
                    key: Config::Displayname
                }
            )
        })
        .await;
    sync(&alice0, &alice1).await;
    assert_eq!(
        alice1.get_config(Config::Displayname).await?,
        Some("Alice Sync".to_string())
    );
    alice1
        .evtracker
        .get_matching(|e| {
            matches!(
                e,
                EventType::ConfigSynced {
                    key: Config::Displayname
                }
            )
        })
        .await;

    alice0.set_config(Config::Displayname, None).await?;
    alice0
        .evtracker
        .get_matching(|e| {
            matches!(
                e,
                EventType::ConfigSynced {
                    key: Config::Displayname
                }
            )
        })
        .await;

    Ok(())
}
