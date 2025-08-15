use std::time::Duration;

use super::*;
use crate::chat::{Chat, create_broadcast, create_group_chat, create_group_ex};
use crate::mimeparser::SystemMessage;
use crate::qr::check_qr;
use crate::securejoin::{get_securejoin_qr, join_securejoin, join_securejoin_with_ux_info};
use crate::test_utils::{TestContext, TestContextManager, get_chat_msg};
use crate::tools::SystemTime;
use pretty_assertions::assert_eq;
use serde_json::{Number, Value};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_send_statistics() -> Result<()> {
    let alice = &TestContext::new_alice().await;

    alice.set_config_bool(Config::SendStatistics, true).await?;

    let chat_id = maybe_send_statistics(&alice).await?.unwrap();
    let msg = get_chat_msg(&alice, chat_id, 0, 2).await;
    assert_eq!(msg.get_info_type(), SystemMessage::ChatProtectionEnabled);

    let chat = Chat::load_from_db(&alice, chat_id).await?;
    assert!(chat.is_protected());

    let msg = get_chat_msg(&alice, chat_id, 1, 2).await;
    assert_eq!(msg.get_filename().unwrap(), "statistics.txt");

    let stats = tokio::fs::read(msg.get_file(&alice).unwrap()).await?;
    let stats = std::str::from_utf8(&stats)?;
    println!("\nEmpty account:\n{}\n", stats);
    assert!(stats.contains(r#""contact_stats": []"#));

    let r: serde_json::Value = serde_json::from_str(&stats)?;
    assert_eq!(
        r.get("contact_stats").unwrap(),
        &serde_json::Value::Array(vec![])
    );
    assert_eq!(r.get("core_version").unwrap(), get_version_str());

    assert_eq!(maybe_send_statistics(alice).await?, None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_statistics_one_contact() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::SendStatistics, true).await?;

    let stats = get_statistics(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&stats)?;

    tcm.send_recv_accept(bob, alice, "Hi!").await;

    let stats = get_statistics(alice).await?;
    println!("\nWith Bob:\n{stats}\n");
    let r2: serde_json::Value = serde_json::from_str(&stats)?;

    assert_eq!(
        r.get("key_created").unwrap(),
        r2.get("key_created").unwrap()
    );
    assert_eq!(
        r.get("statistics_id").unwrap(),
        r2.get("statistics_id").unwrap()
    );
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
    fn check_statistics(
        stats: &str,
        expected_one_one: &MessageStats,
        expected_multi_user: &MessageStats,
    ) {
        let actual: serde_json::Value = serde_json::from_str(&stats).unwrap();

        for (expected, key) in [
            (expected_one_one, "message_stats_one_one"),
            (expected_multi_user, "message_stats_multi_user"),
        ] {
            let actual = &actual[key];

            let expected = serde_json::to_string_pretty(&expected).unwrap();
            let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

            assert_eq!(actual, &expected, "Wrong {key}");
        }
    }

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::SendStatistics, true).await?;
    let email_chat = alice.create_email_chat(bob).await;
    let encrypted_chat = alice.create_chat(bob).await;

    let mut one_one = MessageStats {
        to_verified: 0,
        unverified_encrypted: 0,
        unencrypted: 0,
        only_to_self: 0,
    };
    let mut multi_user = MessageStats {
        to_verified: 0,
        unverified_encrypted: 0,
        unencrypted: 0,
        only_to_self: 0,
    };

    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    alice.send_text(email_chat.id, "foo").await;
    one_one.unencrypted += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    alice.send_text(encrypted_chat.id, "foo").await;
    one_one.unverified_encrypted += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    alice.send_text(encrypted_chat.id, "foo").await;
    one_one.unverified_encrypted += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    let group = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "Pizza", &[bob])
        .await;
    alice.send_text(group, "foo").await;
    multi_user.unverified_encrypted += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    tcm.execute_securejoin(alice, bob).await;
    one_one.to_verified = one_one.unverified_encrypted;
    one_one.unverified_encrypted = 0;
    multi_user.to_verified = multi_user.unverified_encrypted;
    multi_user.unverified_encrypted = 0;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    alice.send_text(alice.get_self_chat().await.id, "foo").await;
    one_one.only_to_self += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    let empty_group = create_group_chat(alice, ProtectionStatus::Unprotected, "Notes").await?;
    alice.send_text(empty_group, "foo").await;
    multi_user.only_to_self += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    let empty_unencrypted = create_group_ex(alice, None, "Email thread").await?;
    alice.send_text(empty_unencrypted, "foo").await;
    multi_user.only_to_self += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    let group = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "Pizza 2", &[bob])
        .await;
    alice.send_text(group, "foo").await;
    multi_user.to_verified += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    let empty_broadcast = create_broadcast(alice, "Channel".to_string()).await?;
    alice.send_text(empty_broadcast, "foo").await;
    multi_user.only_to_self += 1;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    // Incoming messages are not counted:
    let rcvd = tcm.send_recv(bob, alice, "bar").await;
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    // Reactions are not counted:
    crate::reaction::send_reaction(alice, rcvd.id, "👍")
        .await
        .unwrap();
    check_statistics(&get_statistics(alice).await?, &one_one, &multi_user);

    tcm.section("Test that after actually sending statistics, the message numbers are reset.");
    let before_sending = get_statistics(alice).await.unwrap();

    let stats = send_and_read_statistics(alice).await;
    // The statistics are supposed not to have changed yet
    assert_eq!(before_sending, stats);

    // Shift by 8 days so that the next statistics-sending is due:
    SystemTime::shift(Duration::from_secs(8 * 24 * 3600));

    let stats = send_and_read_statistics(alice).await;
    assert_ne!(before_sending, stats);

    one_one = MessageStats {
        to_verified: 0,
        unverified_encrypted: 0,
        unencrypted: 0,
        only_to_self: 0,
    };
    multi_user = MessageStats {
        to_verified: 0,
        unverified_encrypted: 0,
        unencrypted: 0,
        only_to_self: 0,
    };
    check_statistics(&stats, &one_one, &multi_user);

    tcm.section(
        "Test that after sending a message again, the message statistics start to fill again.",
    );
    SystemTime::shift(Duration::from_secs(8 * 24 * 3600));
    tcm.send_recv(alice, bob, "Hi").await;
    one_one.to_verified += 1;
    check_statistics(
        &send_and_read_statistics(alice).await,
        &one_one,
        &multi_user,
    );

    Ok(())
}

async fn send_and_read_statistics(context: &TestContext) -> String {
    let chat_id = maybe_send_statistics(&context).await.unwrap().unwrap();
    let msg = context.get_last_msg_in(chat_id).await;
    assert_eq!(msg.get_filename().unwrap(), "statistics.txt");

    let stats = tokio::fs::read(msg.get_file(&context).unwrap())
        .await
        .unwrap();
    String::from_utf8(stats).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_statistics_securejoin_sources() -> Result<()> {
    async fn check_statistics(context: &TestContext, expected: &SecurejoinSources) {
        let statistics = get_statistics(context).await.unwrap();
        let actual: serde_json::Value = serde_json::from_str(&statistics).unwrap();
        let actual = &actual["securejoin_sources"];

        let expected = serde_json::to_string_pretty(&expected).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(actual, &expected);
    }

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::SendStatistics, true).await?;

    let mut expected = SecurejoinSources {
        unknown: 0,
        external_link: 0,
        internal_link: 0,
        clipboard: 0,
        image_loaded: 0,
        scan: 0,
    };

    check_statistics(alice, &expected).await;

    let qr = get_securejoin_qr(bob, None).await?;

    join_securejoin(alice, &qr).await?;
    expected.unknown += 1;
    check_statistics(alice, &expected).await;

    join_securejoin(alice, &qr).await?;
    expected.unknown += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Clipboard as u32), None)
        .await?;
    expected.clipboard += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(
        alice,
        &qr,
        Some(SecurejoinSource::ExternalLink as u32),
        None,
    )
    .await?;
    expected.external_link += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(
        alice,
        &qr,
        Some(SecurejoinSource::InternalLink as u32),
        None,
    )
    .await?;
    expected.internal_link += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::ImageLoaded as u32), None)
        .await?;
    expected.image_loaded += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Scan as u32), None).await?;
    expected.scan += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Clipboard as u32), None)
        .await?;
    expected.clipboard += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(SecurejoinSource::Clipboard as u32), None)
        .await?;
    expected.clipboard += 1;
    check_statistics(alice, &expected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_statistics_securejoin_uipaths() -> Result<()> {
    async fn check_statistics(context: &TestContext, expected: &SecurejoinUIPaths) {
        let stats = get_statistics(context).await.unwrap();
        let actual: serde_json::Value = serde_json::from_str(&stats).unwrap();
        let actual = &actual["securejoin_uipaths"];

        let expected = serde_json::to_string_pretty(&expected).unwrap();
        let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

        assert_eq!(actual, &expected);
    }

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::SendStatistics, true).await?;

    let mut expected = SecurejoinUIPaths {
        other: 0,
        qr_icon: 0,
        new_contact: 0,
    };

    check_statistics(alice, &expected).await;

    let qr = get_securejoin_qr(bob, None).await?;

    join_securejoin(alice, &qr).await?;
    expected.other += 1;
    check_statistics(alice, &expected).await;

    join_securejoin(alice, &qr).await?;
    expected.other += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(
        alice,
        &qr,
        Some(0),
        Some(SecurejoinUIPath::NewContact as u32),
    )
    .await?;
    expected.new_contact += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(
        alice,
        &qr,
        Some(0),
        Some(SecurejoinUIPath::NewContact as u32),
    )
    .await?;
    expected.new_contact += 1;
    check_statistics(alice, &expected).await;

    join_securejoin_with_ux_info(alice, &qr, Some(0), Some(SecurejoinUIPath::QrIcon as u32))
        .await?;
    expected.qr_icon += 1;
    check_statistics(alice, &expected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_statistics_securejoin_invites() -> Result<()> {
    async fn check_statistics(context: &TestContext, expected: &[JoinedInvite]) {
        let stats = get_statistics(context).await.unwrap();
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
    alice.set_config_bool(Config::SendStatistics, true).await?;

    let mut expected = vec![];

    check_statistics(alice, &expected).await;

    let qr = get_securejoin_qr(bob, None).await?;

    // The UI will call `check_qr()` first, which must not make the statistics wrong:
    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        contact_created: true,
        already_verified: false,
        typ: "contact".to_string(),
    });
    check_statistics(alice, &expected).await;

    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        contact_created: false,
        already_verified: true,
        typ: "contact".to_string(),
    });
    check_statistics(alice, &expected).await;

    let group_id = create_group_chat(bob, ProtectionStatus::Unprotected, "Group chat").await?;
    let qr = get_securejoin_qr(bob, Some(group_id)).await?;

    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        contact_created: false,
        already_verified: true,
        typ: "group".to_string(),
    });
    check_statistics(alice, &expected).await;

    // A contact with Charlie exists already:
    alice.add_or_lookup_contact(charlie).await;
    let group_id =
        create_group_chat(charlie, ProtectionStatus::Unprotected, "Group chat 2").await?;
    let qr = get_securejoin_qr(charlie, Some(group_id)).await?;

    check_qr(alice, &qr).await?;
    tcm.exec_securejoin_qr(alice, bob, &qr).await;
    expected.push(JoinedInvite {
        contact_created: false,
        already_verified: false,
        typ: "group".to_string(),
    });
    check_statistics(alice, &expected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_statistics_is_chatmail() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    alice.set_config_bool(Config::SendStatistics, true).await?;

    let r = get_statistics(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&r)?;
    assert_eq!(r.get("is_chatmail").unwrap().as_bool().unwrap(), false);

    alice.set_config_bool(Config::IsChatmail, true).await?;

    let r = get_statistics(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&r)?;
    assert_eq!(r.get("is_chatmail").unwrap().as_bool().unwrap(), true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_statistics_key_creation_timestamp() -> Result<()> {
    // Alice uses a pregenerated key. It was created at this timestamp:
    const ALICE_KEY_CREATION_TIME: u128 = 1582855645;

    let alice = &TestContext::new_alice().await;
    alice.set_config_bool(Config::SendStatistics, true).await?;

    let r = get_statistics(alice).await?;
    let r: serde_json::Value = serde_json::from_str(&r)?;
    let key_created = r.get("key_created").unwrap().as_array().unwrap();
    assert_eq!(
        key_created,
        &vec![Value::Number(
            Number::from_u128(ALICE_KEY_CREATION_TIME).unwrap()
        )]
    );

    Ok(())
}
