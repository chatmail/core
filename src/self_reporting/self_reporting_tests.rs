use super::*;
use crate::chat::Chat;
use crate::mimeparser::SystemMessage;
use crate::securejoin::{get_securejoin_qr, join_securejoin, join_securejoin_with_source};
use crate::test_utils::{TestContext, TestContextManager, get_chat_msg};
use pretty_assertions::assert_eq;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_self_report() -> Result<()> {
    let alice = &TestContext::new_alice().await;

    alice.set_config_bool(Config::SelfReporting, true).await?;

    let chat_id = maybe_send_self_report(&alice).await?.unwrap();
    let msg = get_chat_msg(&alice, chat_id, 0, 2).await;
    assert_eq!(msg.get_info_type(), SystemMessage::ChatProtectionEnabled);

    let chat = Chat::load_from_db(&alice, chat_id).await?;
    assert!(chat.is_protected());

    let msg = get_chat_msg(&alice, chat_id, 1, 2).await;
    assert_eq!(msg.get_filename().unwrap(), "statistics.txt");

    let report = tokio::fs::read(msg.get_file(&alice).unwrap()).await?;
    let report = std::str::from_utf8(&report)?;
    println!("\nEmpty account:\n{}\n", report);
    assert!(report.contains(r#""contact_stats": []"#));

    let r: serde_json::Value = serde_json::from_str(&report)?;
    assert_eq!(
        r.get("contact_stats").unwrap(),
        &serde_json::Value::Array(vec![])
    );
    assert_eq!(r.get("core_version").unwrap(), get_version_str());

    assert_eq!(maybe_send_self_report(alice).await?, None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_self_report_one_contact() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::SelfReporting, true).await?;

    let report = get_self_report(alice, 0).await?;
    let r: serde_json::Value = serde_json::from_str(&report)?;

    tcm.send_recv_accept(bob, alice, "Hi!").await;

    let report = get_self_report(alice, 0).await?;
    println!("\nWith Bob:\n{report}\n");
    let r2: serde_json::Value = serde_json::from_str(&report)?;

    assert_eq!(
        r.get("key_created").unwrap(),
        r2.get("key_created").unwrap()
    );
    assert_eq!(
        r.get("self_reporting_id").unwrap(),
        r2.get("self_reporting_id").unwrap()
    );
    let contact_stats = r2.get("contact_stats").unwrap().as_array().unwrap();
    assert_eq!(contact_stats.len(), 1);
    let contact_info = &contact_stats[0];
    assert_eq!(
        contact_info.get("bot").unwrap(),
        &serde_json::Value::Bool(false)
    );
    assert_eq!(
        contact_info.get("direct_chat").unwrap(),
        &serde_json::Value::Bool(true)
    );
    assert!(contact_info.get("transitive_chain").is_none(),);
    assert_eq!(
        contact_info.get("verified").unwrap(),
        &serde_json::Value::String("Opportunistic".to_string())
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_self_report_securejoin_source_stats() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::SelfReporting, true).await?;

    let mut expected = SecurejoinSourceStats {
        unknown: 0,
        external_link: 0,
        internal_link: 0,
        clipboard: 0,
        image_loaded: 0,
        scan: 0,
    };

    check_securejoin_report(alice, &expected).await;

    let qr = get_securejoin_qr(bob, None).await?;

    join_securejoin(alice, &qr).await?;
    expected.unknown += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin(alice, &qr).await?;
    expected.unknown += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin_with_source(alice, &qr, Some(SecurejoinSource::Clipboard as u32)).await?;
    expected.clipboard += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin_with_source(alice, &qr, Some(SecurejoinSource::ExternalLink as u32)).await?;
    expected.external_link += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin_with_source(alice, &qr, Some(SecurejoinSource::InternalLink as u32)).await?;
    expected.internal_link += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin_with_source(alice, &qr, Some(SecurejoinSource::ImageLoaded as u32)).await?;
    expected.image_loaded += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin_with_source(alice, &qr, Some(SecurejoinSource::Scan as u32)).await?;
    expected.scan += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin_with_source(alice, &qr, Some(SecurejoinSource::Clipboard as u32)).await?;
    expected.clipboard += 1;
    check_securejoin_report(alice, &expected).await;

    join_securejoin_with_source(alice, &qr, Some(SecurejoinSource::Clipboard as u32)).await?;
    expected.clipboard += 1;
    check_securejoin_report(alice, &expected).await;

    Ok(())
}

async fn check_securejoin_report(context: &TestContext, expected: &SecurejoinSourceStats) {
    let report = get_self_report(context, 0).await.unwrap();
    let actual: serde_json::Value = serde_json::from_str(&report).unwrap();
    let actual = &actual["securejoin_source_stats"];

    let expected = serde_json::to_string_pretty(&expected).unwrap();
    let expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

    assert_eq!(&expected, actual);
}
