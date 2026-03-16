use super::*;
use crate::log::LogExt as _;
use crate::provider::get_provider_by_id;
use crate::test_utils::TestContext;
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
        provider: None,
        certificate_checks: ConfiguredCertificateChecks::Strict,
        oauth2: false,
    };

    param
        .clone()
        .save_to_transports_table(&t, &EnteredLoginParam::default(), time())
        .await?;
    let expected_param = r#"{"addr":"alice@example.org","imap":[{"connection":{"host":"imap.example.com","port":123,"security":"Starttls"},"user":"alice"}],"imap_user":"","imap_password":"foo","smtp":[{"connection":{"host":"smtp.example.com","port":456,"security":"Tls"},"user":"alice@example.org"}],"smtp_user":"","smtp_password":"bar","provider_id":null,"certificate_checks":"Strict","oauth2":false}"#;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_posteo_alias() -> Result<()> {
    let t = TestContext::new().await;

    let user = "alice@posteo.de";

    // Alice has old config with "alice@posteo.at" address
    // and "alice@posteo.de" username.
    t.set_config(Config::Configured, Some("1")).await?;
    t.set_config(Config::ConfiguredProvider, Some("posteo"))
        .await?;
    t.sql
        .set_raw_config(Config::ConfiguredAddr.as_ref(), Some("alice@posteo.at"))
        .await?;
    t.set_config(Config::ConfiguredMailServer, Some("posteo.de"))
        .await?;
    t.set_config(Config::ConfiguredMailPort, Some("993"))
        .await?;
    t.set_config(Config::ConfiguredMailSecurity, Some("1"))
        .await?; // TLS
    t.set_config(Config::ConfiguredMailUser, Some(user)).await?;
    t.set_config(Config::ConfiguredMailPw, Some("foobarbaz"))
        .await?;
    t.set_config(Config::ConfiguredImapCertificateChecks, Some("1"))
        .await?; // Strict
    t.set_config(Config::ConfiguredSendServer, Some("posteo.de"))
        .await?;
    t.set_config(Config::ConfiguredSendPort, Some("465"))
        .await?;
    t.set_config(Config::ConfiguredSendSecurity, Some("1"))
        .await?; // TLS
    t.set_config(Config::ConfiguredSendUser, Some(user)).await?;
    t.set_config(Config::ConfiguredSendPw, Some("foobarbaz"))
        .await?;
    t.set_config(Config::ConfiguredSmtpCertificateChecks, Some("1"))
        .await?; // Strict
    t.set_config(Config::ConfiguredServerFlags, Some("0"))
        .await?;

    let param = ConfiguredLoginParam {
        addr: "alice@posteo.at".to_string(),
        imap: vec![
            ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: "posteo.de".to_string(),
                    port: 993,
                    security: ConnectionSecurity::Tls,
                },
                user: user.to_string(),
            },
            ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: "posteo.de".to_string(),
                    port: 143,
                    security: ConnectionSecurity::Starttls,
                },
                user: user.to_string(),
            },
        ],
        imap_user: "alice@posteo.de".to_string(),
        imap_password: "foobarbaz".to_string(),
        smtp: vec![
            ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: "posteo.de".to_string(),
                    port: 465,
                    security: ConnectionSecurity::Tls,
                },
                user: user.to_string(),
            },
            ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: "posteo.de".to_string(),
                    port: 587,
                    security: ConnectionSecurity::Starttls,
                },
                user: user.to_string(),
            },
        ],
        smtp_user: "alice@posteo.de".to_string(),
        smtp_password: "foobarbaz".to_string(),
        provider: get_provider_by_id("posteo"),
        certificate_checks: ConfiguredCertificateChecks::Strict,
        oauth2: false,
    };

    let loaded = ConfiguredLoginParam::load_legacy(&t).await?.unwrap();
    assert_eq!(loaded, param);

    migrate_configured_login_param(&t).await;
    let (_transport_id, loaded) = ConfiguredLoginParam::load(&t).await?.unwrap();
    assert_eq!(loaded, param);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_empty_server_list_legacy() -> Result<()> {
    // Find a provider that does not have server list set.
    //
    // There is at least one such provider in the provider database.
    let (domain, provider) = crate::provider::data::PROVIDER_DATA
        .iter()
        .find(|(_domain, provider)| provider.server.is_empty())
        .unwrap();

    let t = TestContext::new().await;

    let addr = format!("alice@{domain}");

    t.set_config(Config::Configured, Some("1")).await?;
    t.set_config(Config::ConfiguredProvider, Some(provider.id))
        .await?;
    t.sql
        .set_raw_config(Config::ConfiguredAddr.as_ref(), Some(&addr))
        .await?;
    t.set_config(Config::ConfiguredMailPw, Some("foobarbaz"))
        .await?;
    t.set_config(Config::ConfiguredImapCertificateChecks, Some("1"))
        .await?; // Strict
    t.set_config(Config::ConfiguredSendPw, Some("foobarbaz"))
        .await?;
    t.set_config(Config::ConfiguredSmtpCertificateChecks, Some("1"))
        .await?; // Strict
    t.set_config(Config::ConfiguredServerFlags, Some("0"))
        .await?;

    let loaded = ConfiguredLoginParam::load_legacy(&t).await?.unwrap();
    assert_eq!(loaded.provider, Some(*provider));
    assert_eq!(loaded.imap.is_empty(), false);
    assert_eq!(loaded.smtp.is_empty(), false);

    migrate_configured_login_param(&t).await;

    let (_transport_id, loaded) = ConfiguredLoginParam::load(&t).await?.unwrap();
    assert_eq!(loaded.provider, Some(*provider));
    assert_eq!(loaded.imap.is_empty(), false);
    assert_eq!(loaded.smtp.is_empty(), false);

    Ok(())
}

async fn migrate_configured_login_param(t: &TestContext) {
    t.sql.execute("DROP TABLE transports;", ()).await.unwrap();
    t.sql.set_raw_config_int("dbversion", 130).await.unwrap();
    t.sql.run_migrations(t).await.log_err(t).ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_empty_server_list() -> Result<()> {
    // Find a provider that does not have server list set.
    //
    // There is at least one such provider in the provider database.
    let (domain, provider) = crate::provider::data::PROVIDER_DATA
        .iter()
        .find(|(_domain, provider)| provider.server.is_empty())
        .unwrap();

    let t = TestContext::new().await;

    let addr = format!("alice@{domain}");

    ConfiguredLoginParam {
        addr: addr.clone(),
        imap: vec![ConfiguredServerLoginParam {
            connection: ConnectionCandidate {
                host: "example.org".to_string(),
                port: 100,
                security: ConnectionSecurity::Tls,
            },
            user: addr.clone(),
        }],
        imap_user: addr.clone(),
        imap_password: "foobarbaz".to_string(),
        smtp: vec![ConfiguredServerLoginParam {
            connection: ConnectionCandidate {
                host: "example.org".to_string(),
                port: 100,
                security: ConnectionSecurity::Tls,
            },
            user: addr.clone(),
        }],
        smtp_user: addr.clone(),
        smtp_password: "foobarbaz".to_string(),
        provider: Some(provider),
        certificate_checks: ConfiguredCertificateChecks::Automatic,
        oauth2: false,
    }
    .save_to_transports_table(&t, &EnteredLoginParam::default(), time())
    .await?;

    let (_transport_id, loaded) = ConfiguredLoginParam::load(&t).await?.unwrap();
    assert_eq!(loaded.provider, Some(*provider));
    assert_eq!(loaded.imap.is_empty(), false);
    assert_eq!(loaded.smtp.is_empty(), false);
    assert_eq!(t.get_configured_provider().await?, Some(*provider));

    Ok(())
}
