use std::collections::BTreeSet;
use std::time::Duration;

use crate::tools::SystemTime;

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
    let expected_param = r#"{"addr":"alice@example.org","imap":[{"connection":{"host":"imap.example.com","port":123,"security":"Starttls"},"user":"alice"}],"imap_folder":"Folder","imap_user":"","imap_password":"foo","smtp":[{"connection":{"host":"smtp.example.com","port":456,"security":"Tls"},"user":"alice@example.org"}],"smtp_user":"","smtp_password":"bar","certificate_checks":"Strict"}"#;
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

    dummy_configured_login_param("alice@otherprovider.com")
        .save_to_transports_table(
            alice,
            &EnteredLoginParam {
                addr: "alice@otherprovider.com".to_string(),
                ..Default::default()
            },
            time(),
        )
        .await?;
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

    alice
        .set_config(Config::ConfiguredAddr, Some("alice@otherprovider.com"))
        .await?;
    sync_and_check_recipients(alice, alice2, "alice@example.org alice@otherprovider.com").await;

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
