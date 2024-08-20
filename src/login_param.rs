//! # Login parameters.

use std::fmt;

use anyhow::{format_err, Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::constants::{DC_LP_AUTH_FLAGS, DC_LP_AUTH_NORMAL, DC_LP_AUTH_OAUTH2};
use crate::context::Context;
use crate::net::load_connection_timestamp;
use crate::provider::{get_provider_by_id, Protocol, Provider, Socket, UsernamePattern};
use crate::socks::Socks5Config;
use crate::sql::Sql;

/// User-entered setting for certificate checks.
///
/// Should be saved into `imap_certificate_checks` before running configuration.
#[derive(Copy, Clone, Debug, Default, Display, FromPrimitive, ToPrimitive, PartialEq, Eq)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub enum EnteredCertificateChecks {
    /// `Automatic` means that provider database setting should be taken.
    /// If there is no provider database setting for certificate checks,
    /// check certificates strictly.
    #[default]
    Automatic = 0,

    /// Ensure that TLS certificate is valid for the server hostname.
    Strict = 1,

    /// Accept certificates that are expired, self-signed
    /// or otherwise not valid for the server hostname.
    AcceptInvalidCertificates = 2,

    /// Alias for `AcceptInvalidCertificates`
    /// for API compatibility.
    AcceptInvalidCertificates2 = 3,
}

/// Values saved into `imap_certificate_checks`.
#[derive(Copy, Clone, Debug, Display, FromPrimitive, ToPrimitive, PartialEq, Eq)]
#[repr(u32)]
#[strum(serialize_all = "snake_case")]
pub enum ConfiguredCertificateChecks {
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

/// Login parameters for a single server, either IMAP or SMTP
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnteredServerLoginParam {
    /// Server hostname or IP address.
    pub server: String,

    /// Server port.
    ///
    /// 0 if not specified.
    pub port: u16,

    /// Socket security.
    pub security: Socket,

    /// Username.
    ///
    /// Empty string if not specified.
    pub user: String,

    /// Password.
    pub password: String,
}

/// Login parameters entered by the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnteredLoginParam {
    /// Email address.
    pub addr: String,

    /// IMAP settings.
    pub imap: EnteredServerLoginParam,

    /// SMTP settings.
    pub smtp: EnteredServerLoginParam,

    /// TLS options: whether to allow invalid certificates and/or
    /// invalid hostnames
    pub certificate_checks: EnteredCertificateChecks,

    pub socks5_config: Option<Socks5Config>,

    pub oauth2: bool,
}

impl EnteredLoginParam {
    /// Loads entered account settings.
    pub async fn load(context: &Context) -> Result<Self> {
        let sql = &context.sql;

        let addr = sql
            .get_raw_config("addr")
            .await?
            .unwrap_or_default()
            .trim()
            .to_string();

        let mail_server = sql.get_raw_config("mail_server").await?.unwrap_or_default();
        let mail_port = sql
            .get_raw_config_int("mail_port")
            .await?
            .unwrap_or_default();
        let mail_security = sql
            .get_raw_config_int("mail_security")
            .await?
            .and_then(num_traits::FromPrimitive::from_i32)
            .unwrap_or_default();
        let mail_user = sql.get_raw_config("mail_user").await?.unwrap_or_default();
        let mail_pw = sql.get_raw_config("mail_pw").await?.unwrap_or_default();

        // The setting is named `imap_certificate_checks`
        // for backwards compatibility,
        // but now it is a global setting applied to all protocols,
        // while `smtp_certificate_checks` is ignored.
        let certificate_checks = if let Some(certificate_checks) =
            sql.get_raw_config_int("imap_ceritifacte_checks").await?
        {
            num_traits::FromPrimitive::from_i32(certificate_checks).unwrap()
        } else {
            Default::default()
        };

        let send_server = sql.get_raw_config("send_server").await?.unwrap_or_default();
        let send_port = sql
            .get_raw_config_int("send_port")
            .await?
            .unwrap_or_default();
        let send_security = sql
            .get_raw_config_int("send_security")
            .await?
            .and_then(num_traits::FromPrimitive::from_i32)
            .unwrap_or_default();
        let send_user = sql.get_raw_config("send_user").await?.unwrap_or_default();
        let send_pw = sql.get_raw_config("send_pw").await?.unwrap_or_default();

        let server_flags = sql
            .get_raw_config_int("server_flags")
            .await?
            .unwrap_or_default();
        let oauth2 = matches!(server_flags & DC_LP_AUTH_FLAGS, DC_LP_AUTH_OAUTH2);

        let socks5_config = Socks5Config::from_database(&context.sql).await?;

        Ok(EnteredLoginParam {
            addr,
            imap: EnteredServerLoginParam {
                server: mail_server,
                port: mail_port as u16,
                security: mail_security,
                user: mail_user,
                password: mail_pw,
            },
            smtp: EnteredServerLoginParam {
                server: send_server,
                port: send_port as u16,
                security: send_security,
                user: send_user,
                password: send_pw,
            },
            certificate_checks,
            socks5_config,
            oauth2,
        })
    }
}

impl fmt::Display for EnteredLoginParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let unset = "0";
        let pw = "***";

        write!(
            f,
            "{} imap:{}:{}:{}:{}:{}:{} smtp:{}:{}:{}:{}:{}:{} cert_{}",
            unset_empty(&self.addr),
            unset_empty(&self.imap.user),
            if !self.imap.password.is_empty() {
                pw
            } else {
                unset
            },
            unset_empty(&self.imap.server),
            self.imap.port,
            self.imap.security,
            if self.oauth2 { "OAUTH2" } else { "AUTH_NORMAL" },
            unset_empty(&self.smtp.user),
            if !self.smtp.password.is_empty() {
                pw
            } else {
                unset
            },
            unset_empty(&self.smtp.server),
            self.smtp.port,
            self.smtp.security,
            if self.oauth2 { "OAUTH2" } else { "AUTH_NORMAL" },
            self.certificate_checks
        )
    }
}

fn unset_empty(s: &str) -> &str {
    if s.is_empty() {
        "unset"
    } else {
        s
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfiguredServerLoginParam {
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
pub struct ConfiguredLoginParam {
    /// `From:` address that was used at the time of configuration.
    pub addr: String,

    pub imap: Vec<ConfiguredServerLoginParam>,

    pub imap_password: String,

    pub smtp: Vec<ConfiguredServerLoginParam>,

    pub smtp_password: String,

    pub socks5_config: Option<Socks5Config>,

    pub provider: Option<&'static Provider>,

    /// TLS options: whether to allow invalid certificates and/or
    /// invalid hostnames
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
                write!(f, ",")?;
            }
            write!(f, "{imap}")?;
            first = false;
        }
        write!(f, "] smtp:")?;
        let mut first = true;
        for smtp in &self.smtp {
            if !first {
                write!(f, ",")?;
            }
            write!(f, "{smtp}")?;
            first = false;
        }
        write!(f, "provider:{provider_id} cert_{certificate_checks}")?;
        Ok(())
    }
}

impl ConfiguredLoginParam {
    /// Load configured account settings from the database.
    ///
    /// Returns `None` if account is not configured.
    pub async fn load(context: &Context) -> Result<Option<Self>> {
        let sql = &context.sql;

        if !context.get_config_bool(Config::Configured).await? {
            return Ok(None);
        }

        let addr = sql
            .get_raw_config("configured_addr")
            .await?
            .unwrap_or_default()
            .trim()
            .to_string();

        let certificate_checks: ConfiguredCertificateChecks = if let Some(certificate_checks) = sql
            .get_raw_config_int("configured_imap_certificate_checks")
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

        let server_flags = sql
            .get_raw_config_int("configured_server_flags")
            .await?
            .unwrap_or_default();
        let oauth2 = matches!(server_flags & DC_LP_AUTH_FLAGS, DC_LP_AUTH_OAUTH2);

        let provider = context
            .get_config(Config::ConfiguredProvider)
            .await?
            .and_then(|provider_id| get_provider_by_id(&provider_id));

        let imap;
        let smtp;

        let legacy_mail_user = sql.get_raw_config("configured_mail_user").await?;
        let legacy_send_user = sql.get_raw_config("configured_send_user").await?;

        if let Some(provider) = provider {
            let addr_localpart = if let Some(at) = addr.find('@') {
                addr.split_at(at).0.to_string()
            } else {
                addr.to_string()
            };
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
                        user: if let Some(legacy_mail_user) = &legacy_mail_user {
                            legacy_mail_user.clone()
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
                        user: if let Some(legacy_send_user) = &legacy_send_user {
                            legacy_send_user.clone()
                        } else {
                            match server.username_pattern {
                                UsernamePattern::Email => addr.to_string(),
                                UsernamePattern::Emaillocalpart => addr_localpart.clone(),
                            }
                        },
                    })
                })
                .collect();
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
            let mail_server = sql
                .get_raw_config("configured_mail_server")
                .await?
                .unwrap_or_default();
            let mail_port = sql
                .get_raw_config_int("configured_mail_port")
                .await?
                .unwrap_or_default();

            let mail_user = legacy_mail_user.unwrap_or_default();
            let mail_security: Socket = sql
                .get_raw_config_int("configured_mail_security")
                .await?
                .and_then(num_traits::FromPrimitive::from_i32)
                .unwrap_or_default();

            let send_server = context
                .get_config(Config::ConfiguredSendServer)
                .await?
                .context("SMTP server is not configured")?;
            let send_port = sql
                .get_raw_config_int("configured_send_port")
                .await?
                .unwrap_or_default();
            let send_user = legacy_send_user.unwrap_or_default();
            let send_security: Socket = sql
                .get_raw_config_int("configured_send_security")
                .await?
                .and_then(num_traits::FromPrimitive::from_i32)
                .unwrap_or_default();

            imap = vec![ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: mail_server,
                    port: mail_port as u16,
                    security: mail_security.try_into()?,
                },
                user: mail_user,
            }];
            smtp = vec![ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: send_server,
                    port: send_port as u16,
                    security: send_security.try_into()?,
                },
                user: send_user,
            }];
        }

        let socks5_config = Socks5Config::from_database(&context.sql).await?;

        Ok(Some(ConfiguredLoginParam {
            addr,
            imap,
            imap_password: mail_pw,
            smtp,
            smtp_password: send_pw,
            certificate_checks,
            provider,
            socks5_config,
            oauth2,
        }))
    }

    /// Save this loginparam to the database.
    pub async fn save_as_configured_params(&self, context: &Context) -> Result<()> {
        let sql = &context.sql;

        context.set_primary_self_addr(&self.addr).await?;

        context
            .set_config(
                Config::ConfiguredImapServers,
                Some(&serde_json::to_string(&self.imap)?),
            )
            .await?;
        context
            .set_config(
                Config::ConfiguredSmtpServers,
                Some(&serde_json::to_string(&self.smtp)?),
            )
            .await?;

        context
            .set_config(Config::ConfiguredMailPw, Some(&self.imap_password))
            .await?;
        context
            .set_config(Config::ConfiguredSendPw, Some(&self.smtp_password))
            .await?;

        sql.set_raw_config_int(
            "configured_imap_certificate_checks",
            self.certificate_checks as i32,
        )
        .await?;
        sql.set_raw_config_int(
            "configured_smtp_certificate_checks",
            self.certificate_checks as i32,
        )
        .await?;

        // Remove legacy settings.
        context
            .set_config(Config::ConfiguredMailServer, None)
            .await?;
        context.set_config(Config::ConfiguredMailPort, None).await?;
        context
            .set_config(Config::ConfiguredMailSecurity, None)
            .await?;
        context.set_config(Config::ConfiguredMailUser, None).await?;
        context
            .set_config(Config::ConfiguredSendServer, None)
            .await?;
        context.set_config(Config::ConfiguredSendPort, None).await?;
        context
            .set_config(Config::ConfiguredSendSecurity, None)
            .await?;
        context.set_config(Config::ConfiguredSendUser, None).await?;

        let server_flags = match self.oauth2 {
            true => DC_LP_AUTH_OAUTH2,
            false => DC_LP_AUTH_NORMAL,
        };
        sql.set_raw_config_int("configured_server_flags", server_flags)
            .await?;

        sql.set_raw_config(
            "configured_provider",
            self.provider.map(|provider| provider.id),
        )
        .await?;

        Ok(())
    }

    pub fn strict_tls(&self) -> bool {
        let provider_strict_tls = self.provider.map(|provider| provider.opt.strict_tls);
        match self.certificate_checks {
            ConfiguredCertificateChecks::OldAutomatic => {
                provider_strict_tls.unwrap_or(self.socks5_config.is_some())
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
    use crate::test_utils::TestContext;

    #[test]
    fn test_certificate_checks_display() {
        use std::string::ToString;

        assert_eq!(
            "accept_invalid_certificates".to_string(),
            EnteredCertificateChecks::AcceptInvalidCertificates.to_string()
        );

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
            imap_password: "foo".to_string(),
            smtp: vec![ConfiguredServerLoginParam {
                connection: ConnectionCandidate {
                    host: "smtp.example.com".to_string(),
                    port: 456,
                    security: ConnectionSecurity::Tls,
                },
                user: "alice@example.org".to_string(),
            }],
            smtp_password: "bar".to_string(),
            // socks5_config is not saved by `save_to_database`, using default value
            socks5_config: None,
            provider: None,
            certificate_checks: ConfiguredCertificateChecks::Strict,
            oauth2: false,
        };

        param.save_as_configured_params(&t).await?;
        assert_eq!(
            t.get_config(Config::ConfiguredImapServers).await?.unwrap(),
            r#"[{"connection":{"host":"imap.example.com","port":123,"security":"Starttls"},"user":"alice"}]"#
        );
        t.set_config(Config::Configured, Some("1")).await?;
        let loaded = ConfiguredLoginParam::load(&t).await?.unwrap();
        assert_eq!(param, loaded);

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
        t.set_config(Config::ConfiguredAddr, Some("alice@posteo.at"))
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
            smtp_password: "foobarbaz".to_string(),
            socks5_config: None,
            provider: get_provider_by_id("posteo"),
            certificate_checks: ConfiguredCertificateChecks::Strict,
            oauth2: false,
        };

        let loaded = ConfiguredLoginParam::load(&t).await?.unwrap();
        assert_eq!(loaded, param);

        Ok(())
    }
}
