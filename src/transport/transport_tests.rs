use std::collections::BTreeSet;
use std::time::Duration;

use crate::imap::prefetch_should_download;
use crate::tools::SystemTime;
use crate::transport::add_pseudo_transport;

use super::*;
use crate::test_utils::TestContext;
use crate::test_utils::TestContextManager;
use crate::tools::time;

#[test]
fn test_configured_certificate_checks_display() {
    use std::string::ToString;

    assert_eq!(
        "accept_invalid_certificates".to_string(),
        ConfiguredCertificateChecks::AcceptInvalidCertificates.to_string()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_save_load_login_param() -> Result<()> {
    let t = TestContext::new().await;

    let param = ConfiguredLoginParam {
        addr: "alice@example.org".to_string(),
        imap: vec![ConfiguredServerLoginParam {
            connection: ConnectionCandidate {
                host: "imap.example.com".to_string(),
                port: 123,
                security: ConnectionSecurity::Starttls,
            },
            user: "alice".to_string(),
        }],
        imap_folder: Some("Folder".to_string()),
        imap_user: "".to_string(),
        imap_password: "foo".to_string(),
        smtp: vec![ConfiguredServerLoginParam {
            connection: ConnectionCandidate {
                host: "smtp.example.com".to_string(),
                port: 456,
                security: ConnectionSecurity::Tls,
            },
            user: "alice@example.org".to_string(),
        }],
        smtp_user: "".to_string(),
        smtp_password: "bar".to_string(),
        certificate_checks: ConfiguredCertificateChecks::Strict,
    };

    param
        .clone()
        .save_to_transports_table(&t, &EnteredLoginParam::default(), time())
        .await?;
    let expected_param = r#"{"addr":"alice@example.org","imap":[{"connection":{"host":"imap.example.com","port":123,"security":"Starttls"},"user":"alice"}],"imap_folder":"Folder","imap_user":"","imap_password":"foo","smtp":[{"connection":{"host":"smtp.example.com","port":456,"security":"Tls"},"user":"alice@example.org"}],"smtp_user":"","smtp_password":"bar","certificate_checks":"Strict","oauth2":false}"#;
    assert_eq!(
        t.sql
            .query_get_value::<String>("SELECT configured_param FROM transports", ())
            .await?
            .unwrap(),
        expected_param
    );
    assert_eq!(t.is_configured().await?, true);
    let (_transport_id, loaded) = ConfiguredLoginParam::load(&t).await?.unwrap();
    assert_eq!(param, loaded);

    let formatted = format!(" {loaded}");
    assert!(formatted.contains(" ***@example.org"));
    assert!(formatted.contains(" imap:[imap.example.com:123:starttls]"));
    assert!(formatted.contains(" folder:\"Folder\""));
    assert!(formatted.contains(" smtp:[smtp.example.com:456:tls]"));
    assert!(formatted.contains(" cert_strict"));

    // Legacy ConfiguredImapCertificateChecks config is ignored
    t.set_config(Config::ConfiguredImapCertificateChecks, Some("999"))
        .await?;
    assert!(ConfiguredLoginParam::load(&t).await.is_ok());

    // Test that we don't panic on unknown ConfiguredImapCertificateChecks values.
    let wrong_param = expected_param.replace("Strict", "Stricct");
    assert_ne!(expected_param, wrong_param);
    t.sql
        .execute("UPDATE transports SET configured_param=?", (wrong_param,))
        .await?;
    assert!(ConfiguredLoginParam::load(&t).await.is_err());

    Ok(())
}

fn dummy_configured_login_param(addr: &str) -> ConfiguredLoginParam {
    ConfiguredLoginParam {
        addr: addr.to_string(),
        imap: vec![ConfiguredServerLoginParam {
            connection: ConnectionCandidate {
                host: "example.org".to_string(),
                port: 100,
                security: ConnectionSecurity::Tls,
            },
            user: addr.to_string(),
        }],
        imap_folder: None,
        imap_user: addr.to_string(),
        imap_password: "foobarbaz".to_string(),
        smtp: vec![ConfiguredServerLoginParam {
            connection: ConnectionCandidate {
                host: "example.org".to_string(),
                port: 100,
                security: ConnectionSecurity::Tls,
            },
            user: addr.to_string(),
        }],
        smtp_user: addr.to_string(),
        smtp_password: "foobarbaz".to_string(),
        certificate_checks: ConfiguredCertificateChecks::Automatic,
    }
}

fn dummy_transport_data(addr: &str, is_published: bool) -> TransportData {
    TransportData {
        configured: dummy_configured_login_param(addr).into(),
        entered: EnteredLoginParam {
            addr: addr.to_string(),
            ..Default::default()
        },
        timestamp: time(),
        is_published,
    }
}

async fn add_dummy_transport(t: &TestContext, addr: &str) -> Result<()> {
    dummy_configured_login_param(addr)
        .save_to_transports_table(
            t,
            &EnteredLoginParam {
                addr: addr.to_string(),
                ..Default::default()
            },
            time(),
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_is_published_flag() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    for a in [alice, alice2] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
        a.set_config_bool(Config::BccSelf, true).await?;
    }
    let bob = &tcm.bob().await;

    check_addrs(
        alice,
        alice2,
        bob,
        Addresses {
            primary: "alice@example.org",
            secondary_published: &[],
            secondary_unpublished: &[],
        },
    )
    .await;

    add_dummy_transport(alice, "alice@otherprovider.com").await?;
    send_sync_transports(alice).await?;
    sync_and_check_recipients(alice, alice2, "alice@otherprovider.com alice@example.org").await;

    check_addrs(
        alice,
        alice2,
        bob,
        Addresses {
            primary: "alice@example.org",
            secondary_published: &["alice@otherprovider.com"],
            secondary_unpublished: &[],
        },
    )
    .await;

    assert_eq!(
        alice
            .set_transport_unpublished("alice@example.org", true)
            .await
            .unwrap_err()
            .to_string(),
        "Can't set primary relay as unpublished"
    );

    // Make sure that the newly generated key has a newer timestamp,
    // so that it is recognized by Bob:
    SystemTime::shift(Duration::from_secs(2));

    alice
        .set_transport_unpublished("alice@otherprovider.com", true)
        .await?;
    sync_and_check_recipients(alice, alice2, "alice@example.org").await;

    check_addrs(
        alice,
        alice2,
        bob,
        Addresses {
            primary: "alice@example.org",
            secondary_published: &[],
            secondary_unpublished: &["alice@otherprovider.com"],
        },
    )
    .await;

    SystemTime::shift(Duration::from_secs(2));

    promote_transport_and_sync(alice, alice2, "alice@otherprovider.com").await?;

    alice2
        .set_config(Config::ConfiguredAddr, Some("alice@otherprovider.com"))
        .await?;

    check_addrs(
        alice,
        alice2,
        bob,
        Addresses {
            primary: "alice@otherprovider.com",
            secondary_published: &["alice@example.org"],
            secondary_unpublished: &[],
        },
    )
    .await;

    Ok(())
}

/// Tests that promoting a transport bumps its `add_timestamp` on other devices
/// even if it was added within the same second.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_promote_transport_same_second() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    for a in [alice, alice2] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
        a.set_config_bool(Config::BccSelf, true).await?;
    }

    add_dummy_transport(alice, "alice@otherprovider.com").await?;
    send_sync_transports(alice).await?;
    sync_and_check_recipients(alice, alice2, "alice@otherprovider.com alice@example.org").await;

    promote_transport_and_sync(alice, alice2, "alice@otherprovider.com").await
}

/// Tests that `sync_transports()` requests an IO restart
/// if and only if it modified anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_transports_requests_io_restart() -> Result<()> {
    let alice = &TestContext::new_alice().await;

    let data = dummy_transport_data("alice@otherprovider.com", true);
    let data = std::slice::from_ref(&data);
    sync_transports(alice, data, &[]).await?;
    assert!(alice.restart_io_after_fetch.swap(false, Ordering::Relaxed));

    // Applying the same data again modifies nothing.
    sync_transports(alice, data, &[]).await?;
    assert!(!alice.restart_io_after_fetch.load(Ordering::Relaxed));

    Ok(())
}

/// Promotes `addr` on `alice` and syncs the transport update to `alice2`,
/// whose own primary transport must stay unchanged.
async fn promote_transport_and_sync(
    alice: &TestContext,
    alice2: &TestContext,
    addr: &str,
) -> Result<()> {
    let old_timestamp = add_timestamp(alice2, addr).await;
    let alice2_primary = alice2.get_config(Config::ConfiguredAddr).await?;
    alice.set_config(Config::ConfiguredAddr, Some(addr)).await?;
    assert!(add_timestamp(alice, addr).await > old_timestamp);

    alice.send_sync_msg().await?.unwrap();
    let sync_msg = alice.pop_sent_msg().await;
    assert_eq!(sync_msg.recipients, format!("alice@example.org {addr}"));
    // The sync message comes from the new primary,
    // which must not make `alice2` adopt it as its own primary.
    assert!(sync_msg.payload.contains(&format!("From: <{addr}>")));
    alice2.recv_msg_trash(&sync_msg).await;

    // add_timestamp must monotonically increase because
    // other devices ignore the change otherwise.
    assert!(add_timestamp(alice2, addr).await > old_timestamp);
    assert_eq!(
        alice2.get_config(Config::ConfiguredAddr).await?,
        alice2_primary
    );
    Ok(())
}

async fn add_timestamp(t: &TestContext, addr: &str) -> i64 {
    t.sql
        .query_get_value("SELECT add_timestamp FROM transports WHERE addr=?", (addr,))
        .await
        .unwrap()
        .unwrap()
}

/// Tests that the local primary transport is re-elected
/// if a synced change unpublished or removed it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reelect_local_primary() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    add_dummy_transport(alice, "alice@otherprovider.com").await?;

    // Another device unpublished the primary transport.
    let unpublished = dummy_transport_data("alice@example.org", false);
    sync_transports(alice, std::slice::from_ref(&unpublished), &[]).await?;
    assert_eq!(
        alice.get_config(Config::ConfiguredAddr).await?.as_deref(),
        Some("alice@otherprovider.com")
    );

    // Another device removed the new primary transport.
    let removed = RemovedTransportData {
        addr: "alice@otherprovider.com".to_string(),
        timestamp: time(),
    };
    sync_transports(alice, &[], std::slice::from_ref(&removed)).await?;
    assert_eq!(
        alice.get_config(Config::ConfiguredAddr).await?.as_deref(),
        Some("alice@example.org")
    );
    Ok(())
}

/// Tests which transport is elected as the local primary one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_reelect_local_primary() -> Result<()> {
    let t = &TestContext::new_alice().await;

    // The only transport is kept even if it is unpublished.
    t.sql
        .execute("UPDATE transports SET is_published=0", ())
        .await?;
    assert_eq!(t.sql.transaction(maybe_reelect_local_primary).await?, None);

    // A published primary transport is kept even if newer transports exist.
    t.sql
        .execute("UPDATE transports SET is_published=1", ())
        .await?;
    add_dummy_transport(t, "alice@one.com").await?;
    assert_eq!(t.sql.transaction(maybe_reelect_local_primary).await?, None);

    // The most recently added published transport is elected.
    SystemTime::shift(Duration::from_secs(2));
    add_dummy_transport(t, "alice@two.com").await?;
    t.sql
        .execute(
            "UPDATE transports SET is_published=0 WHERE addr=?",
            ("alice@example.org",),
        )
        .await?;
    assert_eq!(
        t.sql
            .transaction(maybe_reelect_local_primary)
            .await?
            .as_deref(),
        Some("alice@two.com")
    );
    Ok(())
}

struct Addresses {
    primary: &'static str,
    secondary_published: &'static [&'static str],
    secondary_unpublished: &'static [&'static str],
}

async fn check_addrs(
    alice: &TestContext,
    alice2: &TestContext,
    bob: &TestContext,
    addresses: Addresses,
) {
    fn assert_eq(left: Vec<String>, right: Vec<&'static str>) {
        assert_eq!(
            left.iter().map(|s| s.as_str()).collect::<BTreeSet<_>>(),
            right.into_iter().collect::<BTreeSet<_>>(),
        )
    }

    let published_self_addrs = concat(&[addresses.secondary_published, &[addresses.primary]]);
    for a in [alice2, alice] {
        assert_eq(
            a.get_all_self_addrs().await.unwrap(),
            concat(&[
                addresses.secondary_published,
                addresses.secondary_unpublished,
                &[addresses.primary],
            ]),
        );
        assert_eq(
            a.get_published_self_addrs().await.unwrap(),
            published_self_addrs.clone(),
        );
        assert_eq(
            a.get_published_secondary_self_addrs().await.unwrap(),
            concat(&[addresses.secondary_published]),
        );
        for transport in a.list_transports().await.unwrap() {
            if addresses.primary == transport.param.addr
                || addresses
                    .secondary_published
                    .contains(&transport.param.addr.as_str())
            {
                assert_eq!(transport.is_unpublished, false);
            } else if addresses
                .secondary_unpublished
                .contains(&transport.param.addr.as_str())
            {
                assert_eq!(transport.is_unpublished, true);
            } else {
                panic!("Unexpected transport {transport:?}");
            }
        }

        let alice_bob_chat_id = a.create_chat_id(bob).await;
        let sent = a.send_text(alice_bob_chat_id, "hi").await;
        assert_eq!(
            sent.recipients,
            format!("bob@example.net {}", published_self_addrs.join(" ")),
            "{} is sending to the wrong set of recipients",
            a.name()
        );
        let bob_alice_chat_id = bob.recv_msg(&sent).await.chat_id;
        bob_alice_chat_id.accept(bob).await.unwrap();
        let answer = bob.send_text(bob_alice_chat_id, "hi back").await;
        assert_eq(
            answer.recipients.split(' ').map(Into::into).collect(),
            concat(&[&published_self_addrs, &["bob@example.net"]]),
        );
    }
}

fn concat(slices: &[&[&'static str]]) -> Vec<&'static str> {
    let mut res = vec![];
    for s in slices {
        res.extend(*s);
    }
    res
}

pub async fn sync_and_check_recipients(from: &TestContext, to: &TestContext, recipients: &str) {
    from.send_sync_msg().await.unwrap();
    let sync_msg = from.pop_sent_msg().await;
    assert_eq!(sync_msg.recipients, recipients);
    to.recv_msg_trash(&sync_msg).await;
}
