//! # Message transport.
//!
//! A transport represents a single IMAP+SMTP configuration
//! that is known to work at least once in the past.
//!
//! Transports are stored in the `transports` SQL table.
//! Each transport is uniquely identified by its email address.
//! The table stores both the login parameters entered by the user
//! and configured list of connection candidates.

use std::fmt;

use anyhow::{Context as _, Result, bail, ensure, format_err};
use deltachat_contact_tools::{EmailAddress, addr_cmp, addr_normalize};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::configure::server_params::{ServerParams, expand_param_vector};
use crate::constants::{DC_LP_AUTH_FLAGS, DC_LP_AUTH_OAUTH2};
use crate::context::Context;
use crate::login_param::EnteredLoginParam;
use crate::net::load_connection_timestamp;
use crate::provider::{Protocol, Provider, Socket, UsernamePattern, get_provider_by_id};
use crate::sql::Sql;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum ConnectionSecurity {
    /// Implicit TLS.
    Tls,

    // STARTTLS.
    Starttls,

    /// Plaintext.
    Plain,
}

impl fmt::Display for ConnectionSecurity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls => write!(f, "tls")?,
            Self::Starttls => write!(f, "starttls")?,
            Self::Plain => write!(f, "plain")?,
        }
        Ok(())
    }
}

impl TryFrom<Socket> for ConnectionSecurity {
    type Error = anyhow::Error;

    fn try_from(socket: Socket) -> Result<Self> {
        match socket {
            Socket::Automatic => Err(format_err!("Socket security is not configured")),
            Socket::Ssl => Ok(Self::Tls),
            Socket::Starttls => Ok(Self::Starttls),
            Socket::Plain => Ok(Self::Plain),
        }
    }
}

/// Values saved into `imap_certificate_checks`.
#[derive(
    Copy, Clone, Debug, Display, FromPrimitive, ToPrimitive, PartialEq, Eq, Serialize, Deserialize,
)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum ConfiguredCertificateChecks {
    /// Use configuration from the provider database.
    /// If there is no provider database setting for certificate checks,
    /// accept invalid certificates.
    ///
    /// Must not be saved by new versions.
    ///
    /// Previous Delta Chat versions before core 1.133.0
    /// stored this in `configured_imap_certificate_checks`
    /// if Automatic configuration
    /// was selected, configuration with strict TLS checks failed
    /// and configuration without strict TLS checks succeeded.
    OldAutomatic = 0,

    /// Ensure that TLS certificate is valid for the server hostname.
    Strict = 1,

    /// Accept certificates that are expired, self-signed
    /// or otherwise not valid for the server hostname.
    AcceptInvalidCertificates = 2,

    /// Accept certificates that are expired, self-signed
    /// or otherwise not valid for the server hostname.
    ///
    /// Alias to `AcceptInvalidCertificates` for compatibility.
    AcceptInvalidCertificates2 = 3,

    /// Use configuration from the provider database.
    /// If there is no provider database setting for certificate checks,
    /// apply strict checks to TLS certificates.
    Automatic = 4,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConnectionCandidate {
    /// Server hostname or IP address.
    pub host: String,

    /// Server port.
    pub port: u16,

    /// Transport layer security.
    pub security: ConnectionSecurity,
}

impl fmt::Display for ConnectionCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", &self.host, self.port, self.security)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ConfiguredServerLoginParam {
    pub connection: ConnectionCandidate,

    /// Username.
    pub user: String,
}

impl fmt::Display for ConfiguredServerLoginParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.connection, &self.user)?;
        Ok(())
    }
}

pub(crate) async fn prioritize_server_login_params(
    sql: &Sql,
    params: &[ConfiguredServerLoginParam],
    alpn: &str,
) -> Result<Vec<ConfiguredServerLoginParam>> {
    let mut res: Vec<(Option<i64>, ConfiguredServerLoginParam)> = Vec::with_capacity(params.len());
    for param in params {
        let timestamp = load_connection_timestamp(
            sql,
            alpn,
            &param.connection.host,
            param.connection.port,
            None,
        )
        .await?;
        res.push((timestamp, param.clone()));
    }
    res.sort_by_key(|(ts, _param)| std::cmp::Reverse(*ts));
    Ok(res.into_iter().map(|(_ts, param)| param).collect())
}

/// Login parameters saved to the database
/// after successful configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfiguredLoginParam {
    /// `From:` address that was used at the time of configuration.
    pub addr: String,

    pub imap: Vec<ConfiguredServerLoginParam>,

    // Custom IMAP user.
    //
    // This overwrites autoconfig from the provider database
    // if non-empty.
    pub imap_user: String,

    pub imap_password: String,

    pub smtp: Vec<ConfiguredServerLoginParam>,

    // Custom SMTP user.
    //
    // This overwrites autoconfig from the provider database
    // if non-empty.
    pub smtp_user: String,

    pub smtp_password: String,

    pub provider: Option<&'static Provider>,

    /// TLS options: whether to allow invalid certificates and/or
    /// invalid hostnames
    pub certificate_checks: ConfiguredCertificateChecks,

    /// If true, login via OAUTH2 (not recommended anymore)
    pub oauth2: bool,
}

/// The representation of ConfiguredLoginParam in the database,
/// saved as Json.
#[derive(Debug, Serialize, Deserialize)]
struct ConfiguredLoginParamJson {
    pub addr: String,
    pub imap: Vec<ConfiguredServerLoginParam>,
    pub imap_user: String,
    pub imap_password: String,
    pub smtp: Vec<ConfiguredServerLoginParam>,
    pub smtp_user: String,
    pub smtp_password: String,
    pub provider_id: Option<String>,
    pub certificate_checks: ConfiguredCertificateChecks,
    pub oauth2: bool,
}

impl fmt::Display for ConfiguredLoginParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr = &self.addr;
        let provider_id = match self.provider {
            Some(provider) => provider.id,
            None => "none",
        };
        let certificate_checks = self.certificate_checks;
        write!(f, "{addr} imap:[")?;
        let mut first = true;
        for imap in &self.imap {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{imap}")?;
            first = false;
        }
        write!(f, "] smtp:[")?;
        let mut first = true;
        for smtp in &self.smtp {
            if !first {
                write!(f, ", ")?;
            }
            write!(f, "{smtp}")?;
            first = false;
        }
        write!(f, "] provider:{provider_id} cert_{certificate_checks}")?;
        Ok(())
    }
}

impl ConfiguredLoginParam {
    /// Load configured account settings from the database.
    ///
    /// Returns `None` if account is not configured.
    pub(crate) async fn load(context: &Context) -> Result<Option<Self>> {
        let Some(self_addr) = context.get_config(Config::ConfiguredAddr).await? else {
            return Ok(None);
        };

        let json: Option<String> = context
            .sql
            .query_get_value(
                "SELECT configured_param FROM transports WHERE addr=?",
                (&self_addr,),
            )
            .await?;
        if let Some(json) = json {
            Ok(Some(Self::from_json(&json)?))
        } else {
            bail!("Self address {self_addr} doesn't have a corresponding transport");
        }
    }

    /// Loads legacy configured param. Only used for tests and the migration.
    pub(crate) async fn load_legacy(context: &Context) -> Result<Option<Self>> {
        if !context.get_config_bool(Config::Configured).await? {
            return Ok(None);
        }

        let addr = context
            .get_config(Config::ConfiguredAddr)
            .await?
            .unwrap_or_default()
            .trim()
            .to_string();

        let certificate_checks: ConfiguredCertificateChecks = if let Some(certificate_checks) =
            context
                .get_config_parsed::<i32>(Config::ConfiguredImapCertificateChecks)
                .await?
        {
            num_traits::FromPrimitive::from_i32(certificate_checks)
                .context("Invalid configured_imap_certificate_checks value")?
        } else {
            // This is true for old accounts configured using C core
            // which did not check TLS certificates.
            ConfiguredCertificateChecks::OldAutomatic
        };

        let send_pw = context
            .get_config(Config::ConfiguredSendPw)
            .await?
            .context("SMTP password is not configured")?;
        let mail_pw = context
            .get_config(Config::ConfiguredMailPw)
            .await?
            .context("IMAP password is not configured")?;

        let server_flags = context
            .get_config_parsed::<i32>(Config::ConfiguredServerFlags)
            .await?
            .unwrap_or_default();
        let oauth2 = matches!(server_flags & DC_LP_AUTH_FLAGS, DC_LP_AUTH_OAUTH2);

        let provider = context.get_configured_provider().await?;

        let imap;
        let smtp;

        let mail_user = context
            .get_config(Config::ConfiguredMailUser)
            .await?
            .unwrap_or_default();
        let send_user = context
            .get_config(Config::ConfiguredSendUser)
            .await?
            .unwrap_or_default();

        if let Some(provider) = provider {
            let parsed_addr = EmailAddress::new(&addr).context("Bad email-address")?;
            let addr_localpart = parsed_addr.local;

            if provider.server.is_empty() {
                let servers = vec![
                    ServerParams {
                        protocol: Protocol::Imap,
                        hostname: context
                            .get_config(Config::ConfiguredMailServer)
                            .await?
                            .unwrap_or_default(),
                        port: context
                            .get_config_parsed::<u16>(Config::ConfiguredMailPort)
                            .await?
                            .unwrap_or_default(),
                        socket: context
                            .get_config_parsed::<i32>(Config::ConfiguredMailSecurity)
                            .await?
                            .and_then(num_traits::FromPrimitive::from_i32)
                            .unwrap_or_default(),
                        username: mail_user.clone(),
                    },
                    ServerParams {
                        protocol: Protocol::Smtp,
                        hostname: context
                            .get_config(Config::ConfiguredSendServer)
                            .await?
                            .unwrap_or_default(),
                        port: context
                            .get_config_parsed::<u16>(Config::ConfiguredSendPort)
                            .await?
                            .unwrap_or_default(),
                        socket: context
                            .get_config_parsed::<i32>(Config::ConfiguredSendSecurity)
                            .await?
                            .and_then(num_traits::FromPrimitive::from_i32)
                            .unwrap_or_default(),
                        username: send_user.clone(),
                    },
                ];
                let servers = expand_param_vector(servers, &addr, &parsed_addr.domain);
                imap = servers
                    .iter()
                    .filter_map(|params| {
                        let Ok(security) = params.socket.try_into() else {
                            return None;
                        };
                        if params.protocol == Protocol::Imap {
                            Some(ConfiguredServerLoginParam {
                                connection: ConnectionCandidate {
                                    host: params.hostname.clone(),
                                    port: params.port,
                                    security,
                                },
                                user: params.username.clone(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
                smtp = servers
                    .iter()
                    .filter_map(|params| {
                        let Ok(security) = params.socket.try_into() else {
                            return None;
                        };
                        if params.protocol == Protocol::Smtp {
                            Some(ConfiguredServerLoginParam {
                                connection: ConnectionCandidate {
                                    host: params.hostname.clone(),
                                    port: params.port,
                                    security,
                                },
                                user: params.username.clone(),
                            })
                        } else {
                            None
                        }
                    })
                    .collect();
            } else {
                imap = provider
                    .server
                    .iter()
                    .filter_map(|server| {
                        if server.protocol != Protocol::Imap {
                            return None;
                        }

                        let Ok(security) = server.socket.try_into() else {
                            return None;
                        };

                        Some(ConfiguredServerLoginParam {
                            connection: ConnectionCandidate {
                                host: server.hostname.to_string(),
                                port: server.port,
                                security,
                            },
                            user: if !mail_user.is_empty() {
                                mail_user.clone()
                            } else {
                                match server.username_pattern {
                                    UsernamePattern::Email => addr.to_string(),
                                    UsernamePattern::Emaillocalpart => addr_localpart.clone(),
                                }
                            },
                        })
                    })
                    .collect();
                smtp = provider
                    .server
                    .iter()
                    .filter_map(|server| {
                        if server.protocol != Protocol::Smtp {
                            return None;
                        }

                        let Ok(security) = server.socket.try_into() else {
                            return None;
                        };

                        Some(ConfiguredServerLoginParam {
                            connection: ConnectionCandidate {
                                host: server.hostname.to_string(),
                                port: server.port,
                                security,
                            },
                            user: if !send_user.is_empty() {
                                send_user.clone()
                            } else {
                                match server.username_pattern {
                                    UsernamePattern::Email => addr.to_string(),
                                    UsernamePattern::Emaillocalpart => addr_localpart.clone(),
                                }
                            },
                        })
                    })
                    .collect();
            }
        } else if let (Some(configured_mail_servers), Some(configured_send_servers)) = (
            context.get_config(Config::ConfiguredImapServers).await?,
            context.get_config(Config::ConfiguredSmtpServers).await?,
        ) {
            imap = serde_json::from_str(&configured_mail_servers)
                .context("Failed to parse configured IMAP servers")?;
            smtp = serde_json::from_str(&configured_send_servers)
                .context("Failed to parse configured SMTP servers")?;
        } else {
            // Load legacy settings storing a single IMAP and single SMTP server.
            let mail_server = context
                .get_config(Config::ConfiguredMailServer)
                .await?
                .unwrap_or_default();
            let mail_port = context
                .get_config_parsed::<u16>(Config::ConfiguredMailPort)
                .await?
                .unwrap_or_default();

            let mail_security: Socket = context
                .get_config_parsed::<i32>(Config::ConfiguredMailSecurity)
                .await?
                .and_then(num_traits::FromPrimitive::from_i32)
                .unwrap_or_default();

            let send_server = context
                .get_config(Config::ConfiguredSendServer)
                .await?
                .context("SMTP server is not configured")?;
            let send_port = context
                .get_config_parsed::<u16>(Config::ConfiguredSendPort)
                .await?
                .unwrap_or_default();
            let send_security: Socket = context
                .get_config_parsed::<i32>(Config::ConfiguredSendSecurity)
                .await?
                .and_then(num_traits::FromPrimitive::from_i32)
                .unwrap_or_default();

            imap = vec![ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: mail_server,
                    port: mail_port,
                    security: mail_security.try_into()?,
                },
                user: mail_user.clone(),
            }];
            smtp = vec![ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: send_server,
                    port: send_port,
                    security: send_security.try_into()?,
                },
                user: send_user.clone(),
            }];
        }

        Ok(Some(ConfiguredLoginParam {
            addr,
            imap,
            imap_user: mail_user,
            imap_password: mail_pw,
            smtp,
            smtp_user: send_user,
            smtp_password: send_pw,
            certificate_checks,
            provider,
            oauth2,
        }))
    }

    pub(crate) async fn save_to_transports_table(
        self,
        context: &Context,
        entered_param: &EnteredLoginParam,
    ) -> Result<()> {
        let addr = addr_normalize(&self.addr);
        let provider_id = self.provider.map(|provider| provider.id);
        let configured_addr = context.get_config(Config::ConfiguredAddr).await?;
        if let Some(configured_addr) = &configured_addr {
            ensure!(
                addr_cmp(configured_addr, &addr),
                "Adding a second transport is not supported right now."
            );
        }
        context
            .sql
            .execute(
                "INSERT INTO transports (addr, entered_param, configured_param)
                VALUES (?, ?, ?)
                ON CONFLICT (addr)
                DO UPDATE SET entered_param=excluded.entered_param, configured_param=excluded.configured_param",
                (
                    self.addr.clone(),
                    serde_json::to_string(entered_param)?,
                    self.into_json()?,
                ),
            )
            .await?;
        if configured_addr.is_none() {
            // If there is no transport yet, set the new transport as the primary one
            context
                .sql
                .set_raw_config(Config::ConfiguredProvider.as_ref(), provider_id)
                .await?;
            context
                .sql
                .set_raw_config(Config::ConfiguredAddr.as_ref(), Some(&addr))
                .await?;
        }
        Ok(())
    }

    pub(crate) fn from_json(json: &str) -> Result<Self> {
        let json: ConfiguredLoginParamJson = serde_json::from_str(json)?;

        let provider = json.provider_id.and_then(|id| get_provider_by_id(&id));

        Ok(ConfiguredLoginParam {
            addr: json.addr,
            imap: json.imap,
            imap_user: json.imap_user,
            imap_password: json.imap_password,
            smtp: json.smtp,
            smtp_user: json.smtp_user,
            smtp_password: json.smtp_password,
            provider,
            certificate_checks: json.certificate_checks,
            oauth2: json.oauth2,
        })
    }

    pub(crate) fn into_json(self) -> Result<String> {
        let json = ConfiguredLoginParamJson {
            addr: self.addr,
            imap: self.imap,
            imap_user: self.imap_user,
            imap_password: self.imap_password,
            smtp: self.smtp,
            smtp_user: self.smtp_user,
            smtp_password: self.smtp_password,
            provider_id: self.provider.map(|p| p.id.to_string()),
            certificate_checks: self.certificate_checks,
            oauth2: self.oauth2,
        };
        Ok(serde_json::to_string(&json)?)
    }

    pub(crate) fn strict_tls(&self, connected_through_proxy: bool) -> bool {
        let provider_strict_tls = self.provider.map(|provider| provider.opt.strict_tls);
        match self.certificate_checks {
            ConfiguredCertificateChecks::OldAutomatic => {
                provider_strict_tls.unwrap_or(connected_through_proxy)
            }
            ConfiguredCertificateChecks::Automatic => provider_strict_tls.unwrap_or(true),
            ConfiguredCertificateChecks::Strict => true,
            ConfiguredCertificateChecks::AcceptInvalidCertificates
            | ConfiguredCertificateChecks::AcceptInvalidCertificates2 => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::LogExt as _;
    use crate::provider::get_provider_by_id;
    use crate::test_utils::TestContext;

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
            .save_to_transports_table(&t, &EnteredLoginParam::default())
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
        let loaded = ConfiguredLoginParam::load(&t).await?.unwrap();
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
        let loaded = ConfiguredLoginParam::load(&t).await?.unwrap();
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

        let loaded = ConfiguredLoginParam::load(&t).await?.unwrap();
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
        .save_to_transports_table(&t, &EnteredLoginParam::default())
        .await?;

        let loaded = ConfiguredLoginParam::load(&t).await?.unwrap();
        assert_eq!(loaded.provider, Some(*provider));
        assert_eq!(loaded.imap.is_empty(), false);
        assert_eq!(loaded.smtp.is_empty(), false);
        assert_eq!(t.get_configured_provider().await?, Some(*provider));

        Ok(())
    }
}
