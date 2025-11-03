use std::time::Duration;

use super::*;
use crate::chat::{
    Chat, create_broadcast, create_group, create_group_unencrypted, get_chat_contacts,
};
use crate::mimeparser::SystemMessage;
use crate::qr::check_qr;
use crate::securejoin::{get_securejoin_qr, join_securejoin, join_securejoin_with_ux_info};
use crate::test_utils::{TestContext, TestContextManager, get_chat_msg};
use crate::tools::SystemTime;
use pretty_assertions::assert_eq;
use serde_json::{Number, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_send_stats() -> Result<()> {
    let alice = &TestContext::new_alice().await;

    // Can't use `set_config()` here, because this would directly send the statistics,
    // and we wouldn't know the chat id
    alice
        .set_config_internal(Config::StatsSending, Some("1"))
        .await?;

    let chat_id = maybe_send_stats(alice).await?.unwrap();
    let msg = get_chat_msg(alice, chat_id, 0, 2).await;
    assert_eq!(msg.get_info_type(), SystemMessage::ChatE2ee);

    let chat = Chat::load_from_db(alice, chat_id).await?;
    assert!(chat.is_encrypted(alice).await?);
    let contacts = get_chat_contacts(alice, chat_id).await?;
    assert_eq!(contacts.len(), 1);
    let contact = Contact::get_by_id(alice, contacts[0]).await?;
    assert!(contact.is_verified(alice).await?);

    let msg = get_chat_msg(alice, chat_id, 1, 2).await;
    assert_eq!(msg.get_filename().unwrap(), "statistics.txt");

    let stats = tokio::fs::read(msg.get_file(alice).unwrap()).await?;
    let stats = std::str::from_utf8(&stats)?;
    println!("\nEmpty account:\n{stats}\n");
    assert!(stats.contains(r#""contact_stats": []"#));

    let r: serde_json::Value = serde_json::from_str(stats)?;
    assert_eq!(
        r.get("contact_stats").unwrap(),
        &serde_json::Value::Array(vec![])
    );
    assert_eq!(r.get("core_version").unwrap(), get_version_str());

    assert_eq!(maybe_send_stats(alice).await?, None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rewound_time() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    alice.set_config_bool(Config::StatsSending, true).await?;

    // Enabling StatsSending directly sends the first statistics,
    // so that the user immediately sees the result of enabling it:
    assert!(maybe_send_stats(alice).await?.is_none());
    let sent = alice.pop_sent_msg().await;
    assert_eq!(
        sent.load_from_db().await.get_filename().unwrap(),
        "statistics.txt"
    );

    const EIGHT_DAYS: Duration = Duration::from_secs(3600 * 24 * 14);
    SystemTime::shift(EIGHT_DAYS);

    maybe_send_stats(alice).await?.unwrap();

    // The system's time is rewound
    SystemTime::shift_back(EIGHT_DAYS);

    assert!(maybe_send_stats(alice).await?.is_none());

    // After eight days pass again, stats are sent again
    SystemTime::shift(EIGHT_DAYS);
    maybe_send_stats(alice).await?.unwrap();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_one_contact() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::StatsSending, true).await?;

    let stats = get_stats(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&stats)?;

    tcm.send_recv_accept(bob, alice, "Hi!").await;

    let stats = get_stats(alice).await?;
    println!("\nWith Bob:\n{stats}\n");
    let r2: serde_json::Value = serde_json::from_str(&stats)?;

    assert_eq!(
        r.get("key_create_timestamps").unwrap(),
        r2.get("key_create_timestamps").unwrap()
    );
    assert_eq!(r.get("stats_id").unwrap(), r2.get("stats_id").unwrap());
    let contact_stats = r2.get("contact_stats").unwrap().as_array().unwrap();
    assert_eq!(contact_stats.len(), 1);
    let contact_info = &contact_stats[0];
    assert!(contact_info.get("bot").is_none());
    assert_eq!(
        contact_info.get("direct_chat").unwrap(),
        &serde_json::Value::Bool(true)
    );
    assert!(contact_info.get("transitive_chain").is_none(),);
    assert_eq!(
        contact_info.get("verified").unwrap(),
        &serde_json::Value::String("Opportunistic".to_string())
    );
    assert_eq!(
        contact_info.get("new").unwrap(),
        &serde_json::Value::Bool(true)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_message_stats() -> Result<()> {
    #[track_caller]
    fn check_stats(stats: &str, expected: &BTreeMap<Chattype, MessageStats>) {
        let actual: serde_json::Value = serde_json::from_str(stats).unwrap();
        let actual = &actual["message_stats"];

        let expected = serde_json::to_string_pretty(&expected).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(actual, &expected);
    }

    async fn update_get_stats(context: &Context) -> String {
        update_message_stats(context).await.unwrap();
        get_stats(context).await.unwrap()
    }

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    // Can't use `set_config()` here, because this would directly send the statistics
    alice
        .set_config_internal(Config::StatsSending, Some("1"))
        .await?;
    let email_chat = alice.create_email_chat(bob).await;
    let encrypted_chat = alice.create_chat(bob).await;

    let mut expected: BTreeMap<Chattype, MessageStats> = BTreeMap::from_iter([
        (Chattype::Single, MessageStats::default()),
        (Chattype::Group, MessageStats::default()),
        (Chattype::OutBroadcast, MessageStats::default()),
    ]);

    check_stats(&update_get_stats(alice).await, &expected);

    alice.send_text(email_chat.id, "foo").await;
    expected.get_mut(&Chattype::Single).unwrap().unencrypted += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    alice.send_text(encrypted_chat.id, "foo").await;
    expected
        .get_mut(&Chattype::Single)
        .unwrap()
        .unverified_encrypted += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    alice.send_text(encrypted_chat.id, "foo").await;
    expected
        .get_mut(&Chattype::Single)
        .unwrap()
        .unverified_encrypted += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    let group = alice.create_group_with_members("Pizza", &[bob]).await;
    alice.send_text(group, "foo").await;
    expected
        .get_mut(&Chattype::Group)
        .unwrap()
        .unverified_encrypted += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    tcm.execute_securejoin(alice, bob).await;
    check_stats(&update_get_stats(alice).await, &expected);

    alice.send_text(alice.get_self_chat().await.id, "foo").await;
    expected.get_mut(&Chattype::Single).unwrap().only_to_self += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    let empty_group = create_group(alice, "Notes").await?;
    alice.send_text(empty_group, "foo").await;
    expected.get_mut(&Chattype::Group).unwrap().only_to_self += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    let empty_unencrypted = create_group_unencrypted(alice, "Email thread").await?;
    alice.send_text(empty_unencrypted, "foo").await;
    expected.get_mut(&Chattype::Group).unwrap().only_to_self += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    let group = alice.create_group_with_members("Pizza 2", &[bob]).await;
    alice.send_text(group, "foo").await;
    expected.get_mut(&Chattype::Group).unwrap().verified += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    let empty_broadcast = create_broadcast(alice, "Channel".to_string()).await?;
    alice.send_text(empty_broadcast, "foo").await;
    expected
        .get_mut(&Chattype::OutBroadcast)
        .unwrap()
        .only_to_self += 1;
    check_stats(&update_get_stats(alice).await, &expected);

    // Incoming messages are not counted:
    let rcvd = tcm.send_recv(bob, alice, "bar").await;
    check_stats(&update_get_stats(alice).await, &expected);

    // Reactions are not counted:
    crate::reaction::send_reaction(alice, rcvd.id, "👍")
        .await
        .unwrap();
    check_stats(&update_get_stats(alice).await, &expected);

    let before_sending = get_stats(alice).await.unwrap();

    let stats = send_and_read_stats(alice).await;
    // The stats are supposed not to have changed yet
    assert_eq!(before_sending, stats);

    // Shift by 8 days so that the next stats-sending is due:
    SystemTime::shift(Duration::from_secs(8 * 24 * 3600));

    let stats = send_and_read_stats(alice).await;
    assert_eq!(before_sending, stats);

    check_stats(&stats, &expected);

    SystemTime::shift(Duration::from_secs(8 * 24 * 3600));
    tcm.send_recv(alice, bob, "Hi").await;
    expected.get_mut(&Chattype::Single).unwrap().verified += 1;
    update_message_stats(alice).await?;
    update_message_stats(alice).await?;
    tcm.send_recv(alice, bob, "Hi").await;
    expected.get_mut(&Chattype::Single).unwrap().verified += 1;
    tcm.send_recv(alice, bob, "Hi").await;
    expected.get_mut(&Chattype::Single).unwrap().verified += 1;

    check_stats(&send_and_read_stats(alice).await, &expected);

    Ok(())
}

async fn send_and_read_stats(context: &TestContext) -> String {
    let chat_id = maybe_send_stats(context).await.unwrap().unwrap();
    let msg = context.get_last_msg_in(chat_id).await;
    assert_eq!(msg.get_filename().unwrap(), "statistics.txt");

    let stats = tokio::fs::read(msg.get_file(context).unwrap())
        .await
        .unwrap();
    String::from_utf8(stats).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_securejoin_sources() -> Result<()> {
    async fn check_stats(context: &TestContext, expected: &SecurejoinSources) {
        let stats = get_stats(context).await.unwrap();
        let actual: serde_json::Value = serde_json::from_str(&stats).unwrap();
        let actual = &actual["securejoin_sources"];

        let expected = serde_json::to_string_pretty(&expected).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(actual, &expected);
    }

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::StatsSending, true).await?;

    let mut expected = SecurejoinSources {
        unknown: 0,
        external_link: 0,
        internal_link: 0,
        clipboard: 0,
        image_loaded: 0,
        scan: 0,
    };

    check_stats(alice, &expected).await;

    let qr = get_securejoin_qr(bob, None).await?;

    join_securejoin(alice, &qr).await?;
    expected.unknown += 1;
    check_stats(alice, &expected).await;

    join_securejoin(alice, &qr).await?;
    expected.unknown += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Clipboard), None).await?;
    expected.clipboard += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::ExternalLink), None).await?;
    expected.external_link += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::InternalLink), None).await?;
    expected.internal_link += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::ImageLoaded), None).await?;
    expected.image_loaded += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Scan), None).await?;
    expected.scan += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Clipboard), None).await?;
    expected.clipboard += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Clipboard), None).await?;
    expected.clipboard += 1;
    check_stats(alice, &expected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_securejoin_uipaths() -> Result<()> {
    async fn check_stats(context: &TestContext, expected: &SecurejoinUiPaths) {
        let stats = get_stats(context).await.unwrap();
        let actual: serde_json::Value = serde_json::from_str(&stats).unwrap();
        let actual = &actual["securejoin_uipaths"];

        let expected = serde_json::to_string_pretty(&expected).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(actual, &expected);
    }

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::StatsSending, true).await?;

    let mut expected = SecurejoinUiPaths {
        other: 0,
        qr_icon: 0,
        new_contact: 0,
    };

    check_stats(alice, &expected).await;

    let qr = get_securejoin_qr(bob, None).await?;

    join_securejoin(alice, &qr).await?;
    expected.other += 1;
    check_stats(alice, &expected).await;

    join_securejoin(alice, &qr).await?;
    expected.other += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, None, Some(SecurejoinUiPath::NewContact)).await?;
    expected.new_contact += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, None, Some(SecurejoinUiPath::NewContact)).await?;
    expected.new_contact += 1;
    check_stats(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, None, Some(SecurejoinUiPath::QrIcon)).await?;
    expected.qr_icon += 1;
    check_stats(alice, &expected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_securejoin_invites() -> Result<()> {
    async fn check_stats(context: &TestContext, expected: &[JoinedInvite]) {
        let stats = get_stats(context).await.unwrap();
        let actual: serde_json::Value = serde_json::from_str(&stats).unwrap();
        let actual = &actual["securejoin_invites"];

        let expected = serde_json::to_string_pretty(&expected).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(actual, &expected);
    }

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;
    alice.set_config_bool(Config::StatsSending, true).await?;
    let _first_sent_stats = alice.pop_sent_msg().await;

    let mut expected = vec![];

    check_stats(alice, &expected).await;

    let qr = get_securejoin_qr(bob, None).await?;

    // The UI will call `check_qr()` first, which must not make the stats wrong:
    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        already_existed: false,
        already_verified: false,
        typ: "contact".to_string(),
    });
    check_stats(alice, &expected).await;

    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        already_existed: true,
        already_verified: true,
        typ: "contact".to_string(),
    });
    check_stats(alice, &expected).await;

    let group_id = create_group(bob, "Group chat").await?;
    let qr = get_securejoin_qr(bob, Some(group_id)).await?;

    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        already_existed: true,
        already_verified: true,
        typ: "group".to_string(),
    });
    check_stats(alice, &expected).await;

    // A contact with Charlie exists already:
    alice.add_or_lookup_contact(charlie).await;
    let group_id = create_group(charlie, "Group chat 2").await?;
    let qr = get_securejoin_qr(charlie, Some(group_id)).await?;

    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        already_existed: true,
        already_verified: false,
        typ: "group".to_string(),
    });
    check_stats(alice, &expected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_is_chatmail() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    alice.set_config_bool(Config::StatsSending, true).await?;

    let r = get_stats(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&r)?;
    assert_eq!(r.get("is_chatmail").unwrap().as_bool().unwrap(), false);

    alice.set_config_bool(Config::IsChatmail, true).await?;

    let r = get_stats(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&r)?;
    assert_eq!(r.get("is_chatmail").unwrap().as_bool().unwrap(), true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_key_creation_timestamp() -> Result<()> {
    // Alice uses a pregenerated key. It was created at this timestamp:
    const ALICE_KEY_CREATION_TIME: u128 = 1582855645;

    let alice = &TestContext::new_alice().await;
    alice.set_config_bool(Config::StatsSending, true).await?;

    let r = get_stats(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&r)?;
    let key_create_timestamps = r.get("key_create_timestamps").unwrap().as_array().unwrap();
    assert_eq!(
        key_create_timestamps,
        &vec![Value::Number(
            Number::from_u128(ALICE_KEY_CREATION_TIME).unwrap()
        )]
    );

    Ok(())
}

/// We record the timestamp when StatsSending is enabled.
/// If it's disabled and then enabled again, we also record these timestamps.
/// This test enables, disables, and reenables StatsSending,
/// and checks that the timestamps are recorded correctly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stats_enable_disable_timestamps() -> Result<()> {
    async fn get_timestamps(context: &TestContext) -> (Vec<i64>, Vec<i64>) {
        let stats = get_stats(context).await.unwrap();
        let stats: serde_json::Value = serde_json::from_str(&stats).unwrap();
        let enabled_ts = &stats["sending_enabled_timestamps"];
        let disabled_ts = &stats["sending_disabled_timestamps"];

        let enabled_ts = enabled_ts
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();
        let disabled_ts = disabled_ts
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_i64().unwrap())
            .collect();

        (enabled_ts, disabled_ts)
    }

    let alice = &TestContext::new_alice().await;

    // ============================== Enable the setting, and check corresponding timestamp ==============================
    let enabled_min = time();
    alice.set_config_bool(Config::StatsSending, true).await?;
    let enabled_max = time();

    let (enabled_ts, disabled_ts) = get_timestamps(alice).await;

    // The enabling timestamp was inbetween `enabled_min` and `enabled_max`:
    assert_eq!(enabled_ts.len(), 1);
    assert!(enabled_ts[0] >= enabled_min);
    assert!(enabled_ts[0] <= enabled_max);

    assert!(disabled_ts.is_empty());

    // Enabling again should not make a difference
    alice.set_config_bool(Config::StatsSending, true).await?;
    SystemTime::shift(Duration::from_secs(10));
    alice.set_config_bool(Config::StatsSending, true).await?;
    assert_eq!(
        get_timestamps(alice).await,
        (enabled_ts.clone(), disabled_ts.clone())
    );

    // ============================== Disable the setting, and check corresponding timestamp ==============================
    let disabled_min = time();
    alice.set_config_bool(Config::StatsSending, false).await?;
    let disabled_max = time();

    let (new_enabled_ts, new_disabled_ts) = get_timestamps(alice).await;

    assert_eq!(new_enabled_ts, enabled_ts); // The timestamp of enabling didn't change

    // The disabling timestamp was inbetween `disabled_min` and `disabled_max`:
    assert_eq!(new_disabled_ts.len(), 1);
    assert!(new_disabled_ts[0] >= disabled_min);
    assert!(new_disabled_ts[0] <= disabled_max);

    // The time should have advanced in the meantime (because of SystemTime::shift()):
    assert_ne!(new_disabled_ts[0], enabled_ts[0]);

    // ============================== Enable the setting again ==============================
    SystemTime::shift(Duration::from_secs(10));
    let enabled_min = time();
    alice.set_config_bool(Config::StatsSending, true).await?;
    let enabled_max = time();

    let (newer_enabled_ts, newer_disabled_ts) = get_timestamps(alice).await;

    // The timestamp of disabling didn't change:
    assert_eq!(newer_disabled_ts, new_disabled_ts);

    // The enabling timestamp was inbetween `enabled_min` and `enabled_max`:
    assert_eq!(newer_enabled_ts.len(), 2);
    assert!(newer_enabled_ts[1] >= enabled_min);
    assert!(newer_enabled_ts[1] <= enabled_max);
    assert_eq!(newer_enabled_ts[0], new_enabled_ts[0]);

    // The time should have advanced in the meantime (because of SystemTime::shift()):
    assert_ne!(newer_disabled_ts[0], newer_enabled_ts[1]);

    Ok(())
}
