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
use std::pin::Pin;

use anyhow::{Context as _, Result, bail, format_err};
use deltachat_contact_tools::{EmailAddress, addr_normalize};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::configure::server_params::{ServerParams, expand_param_vector};
use crate::constants::{DC_LP_AUTH_FLAGS, DC_LP_AUTH_OAUTH2};
use crate::context::Context;
use crate::events::EventType;
use crate::login_param::EnteredLoginParam;
use crate::net::load_connection_timestamp;
use crate::provider::{Protocol, Provider, Socket, UsernamePattern, get_provider_by_id};
use crate::sql::Sql;
use crate::sync::{RemovedTransportData, SyncData, TransportData};

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

/// JSON representation of ConfiguredLoginParam
/// for the database and sync messages.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ConfiguredLoginParamJson {
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
    /// Returns transport ID and configured parameters
    /// of the current primary transport.
    /// Returns `None` if account is not configured.
    pub(crate) async fn load(context: &Context) -> Result<Option<(u32, Self)>> {
        let Some(self_addr) = context.get_config(Config::ConfiguredAddr).await? else {
            return Ok(None);
        };

        let Some((id, json)) = context
            .sql
            .query_row_optional(
                "SELECT id, configured_param FROM transports WHERE addr=?",
                (&self_addr,),
                |row| {
                    let id: u32 = row.get(0)?;
                    let json: String = row.get(1)?;
                    Ok((id, json))
                },
            )
            .await?
        else {
            bail!("Self address {self_addr} doesn't have a corresponding transport");
        };
        Ok(Some((id, Self::from_json(&json)?)))
    }

    /// Loads configured login parameters for all transports.
    ///
    /// Returns a vector of all transport IDs
    /// paired with the configured parameters for the transports.
    pub(crate) async fn load_all(context: &Context) -> Result<Vec<(u32, Self)>> {
        context
            .sql
            .query_map_vec("SELECT id, configured_param FROM transports", (), |row| {
                let id: u32 = row.get(0)?;
                let json: String = row.get(1)?;
                let param = Self::from_json(&json)?;
                Ok((id, param))
            })
            .await
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

        let provider = context
            .get_config(Config::ConfiguredProvider)
            .await?
            .and_then(|cfg| get_provider_by_id(&cfg));

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
        timestamp: i64,
    ) -> Result<()> {
        let is_published = true;
        save_transport(
            context,
            entered_param,
            &self.into(),
            timestamp,
            is_published,
        )
        .await?;
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
        let json: ConfiguredLoginParamJson = self.into();
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

impl From<ConfiguredLoginParam> for ConfiguredLoginParamJson {
    fn from(configured_login_param: ConfiguredLoginParam) -> Self {
        Self {
            addr: configured_login_param.addr,
            imap: configured_login_param.imap,
            imap_user: configured_login_param.imap_user,
            imap_password: configured_login_param.imap_password,
            smtp: configured_login_param.smtp,
            smtp_user: configured_login_param.smtp_user,
            smtp_password: configured_login_param.smtp_password,
            provider_id: configured_login_param.provider.map(|p| p.id.to_string()),
            certificate_checks: configured_login_param.certificate_checks,
            oauth2: configured_login_param.oauth2,
        }
    }
}

/// Saves transport to the database.
/// Returns whether transports are modified.
pub(crate) async fn save_transport(
    context: &Context,
    entered_param: &EnteredLoginParam,
    configured: &ConfiguredLoginParamJson,
    add_timestamp: i64,
    is_published: bool,
) -> Result<bool> {
    let addr = addr_normalize(&configured.addr);
    let configured_addr = context.get_config(Config::ConfiguredAddr).await?;

    let mut modified = context
        .sql
        .execute(
            "INSERT INTO transports (addr, entered_param, configured_param, add_timestamp, is_published)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT (addr)
             DO UPDATE SET entered_param=excluded.entered_param,
                           configured_param=excluded.configured_param,
                           add_timestamp=excluded.add_timestamp,
                           is_published=excluded.is_published
             WHERE entered_param != excluded.entered_param
                 OR configured_param != excluded.configured_param
                 OR add_timestamp < excluded.add_timestamp
                 OR is_published != excluded.is_published",
            (
                &addr,
                serde_json::to_string(entered_param)?,
                serde_json::to_string(configured)?,
                add_timestamp,
                is_published,
            ),
        )
        .await?
        > 0;

    if configured_addr.is_none() {
        // If there is no transport yet, set the new transport as the primary one
        context
            .sql
            .set_raw_config(Config::ConfiguredAddr.as_ref(), Some(&addr))
            .await?;
        modified = true;
    }
    Ok(modified)
}

/// Sends a sync message to synchronize transports across devices.
pub(crate) async fn send_sync_transports(context: &Context) -> Result<()> {
    info!(context, "Sending transport synchronization message.");

    // Regenerate public key to include all transports.
    context.self_public_key.lock().await.take();

    // Synchronize all transport configurations.
    //
    // Transport with ID 1 is never synchronized
    // because it can only be created during initial configuration.
    // This also guarantees that credentials for the first
    // transport are never sent in sync messages,
    // so this is not worse than when not using multi-transport.
    // If transport ID 1 is reconfigured,
    // likely because the password has changed,
    // user has to reconfigure it manually on all devices.
    let transports = context
        .sql
        .query_map_vec(
            "SELECT entered_param, configured_param, add_timestamp, is_published
             FROM transports WHERE id>1",
            (),
            |row| {
                let entered_json: String = row.get(0)?;
                let entered: EnteredLoginParam = serde_json::from_str(&entered_json)?;
                let configured_json: String = row.get(1)?;
                let configured: ConfiguredLoginParamJson = serde_json::from_str(&configured_json)?;
                let timestamp: i64 = row.get(2)?;
                let is_published: bool = row.get(3)?;
                Ok(TransportData {
                    configured,
                    entered,
                    timestamp,
                    is_published,
                })
            },
        )
        .await?;
    let removed_transports = context
        .sql
        .query_map_vec(
            "SELECT addr, remove_timestamp FROM removed_transports",
            (),
            |row| {
                let addr: String = row.get(0)?;
                let timestamp: i64 = row.get(1)?;
                Ok(RemovedTransportData { addr, timestamp })
            },
        )
        .await?;
    context
        .add_sync_item(SyncData::Transports {
            transports,
            removed_transports,
        })
        .await?;
    context.scheduler.interrupt_smtp().await;

    Ok(())
}

/// Process received data for transport synchronization.
pub(crate) async fn sync_transports(
    context: &Context,
    transports: &[TransportData],
    removed_transports: &[RemovedTransportData],
) -> Result<()> {
    let mut modified = false;
    for TransportData {
        configured,
        entered,
        timestamp,
        is_published,
    } in transports
    {
        modified |= save_transport(context, entered, configured, *timestamp, *is_published).await?;
    }

    context
        .sql
        .transaction(|transaction| {
            for RemovedTransportData { addr, timestamp } in removed_transports {
                modified |= transaction.execute(
                    "DELETE FROM transports
                     WHERE addr=? AND add_timestamp<=?",
                    (addr, timestamp),
                )? > 0;
                transaction.execute(
                    "INSERT INTO removed_transports (addr, remove_timestamp)
                     VALUES (?, ?)
                     ON CONFLICT (addr) DO
                     UPDATE SET remove_timestamp = excluded.remove_timestamp
                     WHERE excluded.remove_timestamp > remove_timestamp",
                    (addr, timestamp),
                )?;
            }
            Ok(())
        })
        .await?;

    if modified {
        context.self_public_key.lock().await.take();
        tokio::task::spawn(restart_io_if_running_boxed(context.clone()));
        context.emit_event(EventType::TransportsModified);
    }
    Ok(())
}

/// Same as `context.restart_io_if_running()`, but `Box::pin`ed and with a `+ Send` bound,
/// so that it can be called recursively.
fn restart_io_if_running_boxed(context: Context) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    Box::pin(async move { context.restart_io_if_running().await })
}

/// Adds transport entry to the `transports` table with empty configuration.
pub(crate) async fn add_pseudo_transport(context: &Context, addr: &str) -> Result<()> {
    context.sql
        .execute(
            "INSERT INTO transports (addr, entered_param, configured_param) VALUES (?, ?, ?)",
            (
                addr,
                serde_json::to_string(&EnteredLoginParam{addr: addr.to_string(), ..Default::default()})?,
                format!(r#"{{"addr":"{addr}","imap":[],"imap_user":"","imap_password":"","smtp":[],"smtp_user":"","smtp_password":"","certificate_checks":"Automatic","oauth2":false}}"#)
            ),
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod transport_tests;
