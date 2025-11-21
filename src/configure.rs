//! # Email accounts autoconfiguration process.
//!
//! The module provides automatic lookup of configuration
//! for email providers based on the built-in [provider database],
//! [Mozilla Thunderbird Autoconfiguration protocol]
//! and [Outlook's Autodiscover].
//!
//! [provider database]: crate::provider
//! [Mozilla Thunderbird Autoconfiguration protocol]: auto_mozilla
//! [Outlook's Autodiscover]: auto_outlook

mod auto_mozilla;
mod auto_outlook;
pub(crate) mod server_params;

use anyhow::{Context as _, Result, bail, ensure, format_err};
use auto_mozilla::moz_autoconfigure;
use auto_outlook::outlk_autodiscover;
use deltachat_contact_tools::{EmailAddress, addr_normalize};
use futures::FutureExt;
use futures_lite::FutureExt as _;
use percent_encoding::utf8_percent_encode;
use server_params::{ServerParams, expand_param_vector};
use tokio::task;

use crate::config::{self, Config};
use crate::constants::NON_ALPHANUMERIC_WITHOUT_DOT;
use crate::context::Context;
use crate::imap::Imap;
use crate::log::warn;
use crate::login_param::EnteredCertificateChecks;
pub use crate::login_param::EnteredLoginParam;
use crate::message::Message;
use crate::net::proxy::ProxyConfig;
use crate::oauth2::get_oauth2_addr;
use crate::provider::{Protocol, Provider, Socket, UsernamePattern};
use crate::qr::{login_param_from_account_qr, login_param_from_login_qr};
use crate::smtp::Smtp;
use crate::sync::Sync::*;
use crate::tools::time;
use crate::transport::{
    ConfiguredCertificateChecks, ConfiguredLoginParam, ConfiguredServerLoginParam,
    ConnectionCandidate, send_sync_transports,
};
use crate::{EventType, stock_str};
use crate::{chat, provider};

macro_rules! progress {
    ($context:tt, $progress:expr, $comment:expr) => {
        assert!(
            $progress <= 1000,
            "value in range 0..1000 expected with: 0=error, 1..999=progress, 1000=success"
        );
        $context.emit_event($crate::events::EventType::ConfigureProgress {
            progress: $progress,
            comment: $comment,
        });
    };
    ($context:tt, $progress:expr) => {
        progress!($context, $progress, None);
    };
}

impl Context {
    /// Checks if the context is already configured.
    pub async fn is_configured(&self) -> Result<bool> {
        self.sql.exists("SELECT COUNT(*) FROM transports", ()).await
    }

    /// Configures this account with the currently provided parameters.
    ///
    /// Deprecated since 2025-02; use `add_transport_from_qr()`
    /// or `add_or_update_transport()` instead.
    pub async fn configure(&self) -> Result<()> {
        let mut param = EnteredLoginParam::load(self).await?;

        self.add_transport_inner(&mut param).await
    }

    /// Configures a new email account using the provided parameters
    /// and adds it as a transport.
    ///
    /// If the email address is the same as an existing transport,
    /// then this existing account will be reconfigured instead of a new one being added.
    ///
    /// This function stops and starts IO as needed.
    ///
    /// Usually it will be enough to only set `addr` and `imap.password`,
    /// and all the other settings will be autoconfigured.
    ///
    /// During configuration, ConfigureProgress events are emitted;
    /// they indicate a successful configuration as well as errors
    /// and may be used to create a progress bar.
    /// This function will return after configuration is finished.
    ///
    /// If configuration is successful,
    /// the working server parameters will be saved
    /// and used for connecting to the server.
    /// The parameters entered by the user will be saved separately
    /// so that they can be prefilled when the user opens the server-configuration screen again.
    ///
    /// See also:
    /// - [Self::is_configured()] to check whether there is
    ///   at least one working transport.
    /// - [Self::add_transport_from_qr()] to add a transport
    ///   from a server encoded in a QR code.
    /// - [Self::list_transports()] to get a list of all configured transports.
    /// - [Self::delete_transport()] to remove a transport.
    pub async fn add_or_update_transport(&self, param: &mut EnteredLoginParam) -> Result<()> {
        self.stop_io().await;
        let result = self.add_transport_inner(param).await;
        if result.is_err() {
            if let Ok(true) = self.is_configured().await {
                self.start_io().await;
            }
            return result;
        }
        self.start_io().await;
        Ok(())
    }

    pub(crate) async fn add_transport_inner(&self, param: &mut EnteredLoginParam) -> Result<()> {
        ensure!(
            !self.scheduler.is_running().await,
            "cannot configure, already running"
        );
        ensure!(
            self.sql.is_open().await,
            "cannot configure, database not opened."
        );
        param.addr = addr_normalize(&param.addr);
        let cancel_channel = self.alloc_ongoing().await?;

        let res = self
            .inner_configure(param)
            .race(cancel_channel.recv().map(|_| Err(format_err!("Canceled"))))
            .await;

        self.free_ongoing().await;

        if let Err(err) = res.as_ref() {
            // We are using Anyhow's .context() and to show the
            // inner error, too, we need the {:#}:
            let error_msg = stock_str::configuration_failed(self, &format!("{err:#}")).await;
            progress!(self, 0, Some(error_msg.clone()));
            bail!(error_msg);
        } else {
            param.save(self).await?;
            progress!(self, 1000);
        }

        res
    }

    /// Adds a new email account as a transport
    /// using the server encoded in the QR code.
    /// See [Self::add_or_update_transport].
    pub async fn add_transport_from_qr(&self, qr: &str) -> Result<()> {
        self.stop_io().await;

        let result = async move {
            let mut param = match crate::qr::check_qr(self, qr).await? {
                crate::qr::Qr::Account { .. } => login_param_from_account_qr(self, qr).await?,
                crate::qr::Qr::Login { address, options } => {
                    login_param_from_login_qr(&address, options)?
                }
                _ => bail!("QR code does not contain account"),
            };
            self.add_transport_inner(&mut param).await?;
            Ok(())
        }
        .await;

        if result.is_err() {
            if let Ok(true) = self.is_configured().await {
                self.start_io().await;
            }
            return result;
        }
        self.start_io().await;
        Ok(())
    }

    /// Returns the list of all email accounts that are used as a transport in the current profile.
    /// Use [Self::add_or_update_transport()] to add or change a transport
    /// and [Self::delete_transport()] to delete a transport.
    pub async fn list_transports(&self) -> Result<Vec<EnteredLoginParam>> {
        let transports = self
            .sql
            .query_map_vec("SELECT entered_param FROM transports", (), |row| {
                let entered_param: String = row.get(0)?;
                let transport: EnteredLoginParam = serde_json::from_str(&entered_param)?;
                Ok(transport)
            })
            .await?;

        Ok(transports)
    }

    /// Returns the number of configured transports.
    pub async fn count_transports(&self) -> Result<usize> {
        self.sql.count("SELECT COUNT(*) FROM transports", ()).await
    }

    /// Removes the transport with the specified email address
    /// (i.e. [EnteredLoginParam::addr]).
    pub async fn delete_transport(&self, addr: &str) -> Result<()> {
        let now = time();
        self.sql
            .transaction(|transaction| {
                let primary_addr = transaction.query_row(
                    "SELECT value FROM config WHERE keyname='configured_addr'",
                    (),
                    |row| {
                        let addr: String = row.get(0)?;
                        Ok(addr)
                    },
                )?;

                if primary_addr == addr {
                    bail!("Cannot delete primary transport");
                }
                let (transport_id, add_timestamp) = transaction.query_row(
                    "DELETE FROM transports WHERE addr=? RETURNING id, add_timestamp",
                    (addr,),
                    |row| {
                        let id: u32 = row.get(0)?;
                        let add_timestamp: i64 = row.get(1)?;
                        Ok((id, add_timestamp))
                    },
                )?;
                transaction.execute("DELETE FROM imap WHERE transport_id=?", (transport_id,))?;
                transaction.execute(
                    "DELETE FROM imap_sync WHERE transport_id=?",
                    (transport_id,),
                )?;

                // Removal timestamp should not be lower than addition timestamp
                // to be accepted by other devices when synced.
                let remove_timestamp = std::cmp::max(now, add_timestamp);

                transaction.execute(
                    "INSERT INTO removed_transports (addr, remove_timestamp)
                     VALUES (?, ?)
                     ON CONFLICT (addr)
                     DO UPDATE SET remove_timestamp = excluded.remove_timestamp",
                    (addr, remove_timestamp),
                )?;

                Ok(())
            })
            .await?;
        send_sync_transports(self).await?;

        Ok(())
    }

    async fn inner_configure(&self, param: &EnteredLoginParam) -> Result<()> {
        info!(self, "Configure ...");

        let old_addr = self.get_config(Config::ConfiguredAddr).await?;
        if old_addr.is_some()
            && !self
                .sql
                .exists(
                    "SELECT COUNT(*) FROM transports WHERE addr=?",
                    (&param.addr,),
                )
                .await?
        {
            if self.get_config(Config::MvboxMove).await?.as_deref() != Some("0") {
                bail!("Cannot use multi-transport with mvbox_move enabled.");
            }
            if self.get_config(Config::OnlyFetchMvbox).await?.as_deref() != Some("0") {
                bail!("Cannot use multi-transport with only_fetch_mvbox enabled.");
            }
            if self.get_config(Config::ShowEmails).await?.as_deref() != Some("2") {
                bail!("Cannot use multi-transport with disabled fetching of classic emails.");
            }
        }

        let provider = configure(self, param).await?;
        self.set_config_internal(Config::NotifyAboutWrongPw, Some("1"))
            .await?;
        on_configure_completed(self, provider).await?;
        Ok(())
    }
}

async fn on_configure_completed(
    context: &Context,
    provider: Option<&'static Provider>,
) -> Result<()> {
    if let Some(provider) = provider {
        if let Some(config_defaults) = provider.config_defaults {
            for def in config_defaults {
                if !context.config_exists(def.key).await? {
                    info!(context, "apply config_defaults {}={}", def.key, def.value);
                    context
                        .set_config_ex(Nosync, def.key, Some(def.value))
                        .await?;
                } else {
                    info!(
                        context,
                        "skip already set config_defaults {}={}", def.key, def.value
                    );
                }
            }
        }

        if !provider.after_login_hint.is_empty() {
            let mut msg = Message::new_text(provider.after_login_hint.to_string());
            if chat::add_device_msg(context, Some("core-provider-info"), Some(&mut msg))
                .await
                .is_err()
            {
                warn!(context, "cannot add after_login_hint as core-provider-info");
            }
        }
    }

    Ok(())
}

/// Retrieves data from autoconfig and provider database
/// to transform user-entered login parameters into complete configuration.
async fn get_configured_param(
    ctx: &Context,
    param: &EnteredLoginParam,
) -> Result<ConfiguredLoginParam> {
    ensure!(!param.addr.is_empty(), "Missing email address.");

    ensure!(!param.imap.password.is_empty(), "Missing (IMAP) password.");

    // SMTP password is an "advanced" setting. If unset, use the same password as for IMAP.
    let smtp_password = if param.smtp.password.is_empty() {
        param.imap.password.clone()
    } else {
        param.smtp.password.clone()
    };

    let mut addr = param.addr.clone();
    if param.oauth2 {
        // the used oauth2 addr may differ, check this.
        // if get_oauth2_addr() is not available in the oauth2 implementation, just use the given one.
        progress!(ctx, 10);
        if let Some(oauth2_addr) = get_oauth2_addr(ctx, &param.addr, &param.imap.password)
            .await?
            .and_then(|e| e.parse().ok())
        {
            info!(ctx, "Authorized address is {}", oauth2_addr);
            addr = oauth2_addr;
            ctx.sql
                .set_raw_config("addr", Some(param.addr.as_str()))
                .await?;
        }
        progress!(ctx, 20);
    }
    // no oauth? - just continue it's no error

    let parsed = EmailAddress::new(&param.addr).context("Bad email-address")?;
    let param_domain = parsed.domain;

    progress!(ctx, 200);

    let provider;
    let param_autoconfig;
    if param.imap.server.is_empty()
        && param.imap.port == 0
        && param.imap.security == Socket::Automatic
        && param.imap.user.is_empty()
        && param.smtp.server.is_empty()
        && param.smtp.port == 0
        && param.smtp.security == Socket::Automatic
        && param.smtp.user.is_empty()
    {
        // no advanced parameters entered by the user: query provider-database or do Autoconfig
        info!(
            ctx,
            "checking internal provider-info for offline autoconfig"
        );

        provider = provider::get_provider_info(&param_domain);
        if let Some(provider) = provider {
            if provider.server.is_empty() {
                info!(ctx, "Offline autoconfig found, but no servers defined.");
                param_autoconfig = None;
            } else {
                info!(ctx, "Offline autoconfig found.");
                let servers = provider
                    .server
                    .iter()
                    .map(|s| ServerParams {
                        protocol: s.protocol,
                        socket: s.socket,
                        hostname: s.hostname.to_string(),
                        port: s.port,
                        username: match s.username_pattern {
                            UsernamePattern::Email => param.addr.to_string(),
                            UsernamePattern::Emaillocalpart => {
                                if let Some(at) = param.addr.find('@') {
                                    param.addr.split_at(at).0.to_string()
                                } else {
                                    param.addr.to_string()
                                }
                            }
                        },
                    })
                    .collect();

                param_autoconfig = Some(servers)
            }
        } else {
            // Try receiving autoconfig
            info!(ctx, "No offline autoconfig found.");
            param_autoconfig = get_autoconfig(ctx, param, &param_domain).await;
        }
    } else {
        provider = None;
        param_autoconfig = None;
    }

    progress!(ctx, 500);

    let mut servers = param_autoconfig.unwrap_or_default();
    if !servers
        .iter()
        .any(|server| server.protocol == Protocol::Imap)
    {
        servers.push(ServerParams {
            protocol: Protocol::Imap,
            hostname: param.imap.server.clone(),
            port: param.imap.port,
            socket: param.imap.security,
            username: param.imap.user.clone(),
        })
    }
    if !servers
        .iter()
        .any(|server| server.protocol == Protocol::Smtp)
    {
        servers.push(ServerParams {
            protocol: Protocol::Smtp,
            hostname: param.smtp.server.clone(),
            port: param.smtp.port,
            socket: param.smtp.security,
            username: param.smtp.user.clone(),
        })
    }

    let servers = expand_param_vector(servers, &param.addr, &param_domain);

    let configured_login_param = ConfiguredLoginParam {
        addr,
        imap: servers
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
            .collect(),
        imap_user: param.imap.user.clone(),
        imap_password: param.imap.password.clone(),
        smtp: servers
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
            .collect(),
        smtp_user: param.smtp.user.clone(),
        smtp_password,
        provider,
        certificate_checks: match param.certificate_checks {
            EnteredCertificateChecks::Automatic => ConfiguredCertificateChecks::Automatic,
            EnteredCertificateChecks::Strict => ConfiguredCertificateChecks::Strict,
            EnteredCertificateChecks::AcceptInvalidCertificates
            | EnteredCertificateChecks::AcceptInvalidCertificates2 => {
                ConfiguredCertificateChecks::AcceptInvalidCertificates
            }
        },
        oauth2: param.oauth2,
    };
    Ok(configured_login_param)
}

async fn configure(ctx: &Context, param: &EnteredLoginParam) -> Result<Option<&'static Provider>> {
    progress!(ctx, 1);

    let ctx2 = ctx.clone();
    let update_device_chats_handle = task::spawn(async move { ctx2.update_device_chats().await });

    let configured_param = get_configured_param(ctx, param).await?;
    let proxy_config = ProxyConfig::load(ctx).await?;
    let strict_tls = configured_param.strict_tls(proxy_config.is_some());

    progress!(ctx, 550);

    // Spawn SMTP configuration task
    // to try SMTP while connecting to IMAP.
    let context_smtp = ctx.clone();
    let smtp_param = configured_param.smtp.clone();
    let smtp_password = configured_param.smtp_password.clone();
    let smtp_addr = configured_param.addr.clone();

    let proxy_config2 = proxy_config.clone();
    let smtp_config_task = task::spawn(async move {
        let mut smtp = Smtp::new();
        smtp.connect(
            &context_smtp,
            &smtp_param,
            &smtp_password,
            &proxy_config2,
            &smtp_addr,
            strict_tls,
            configured_param.oauth2,
        )
        .await?;

        Ok::<(), anyhow::Error>(())
    });

    progress!(ctx, 600);

    // Configure IMAP

    let transport_id = 0;
    let (_s, r) = async_channel::bounded(1);
    let mut imap = Imap::new(ctx, transport_id, configured_param.clone(), r).await?;
    let configuring = true;
    if let Err(err) = imap.connect(ctx, configuring).await {
        bail!(
            "{}",
            nicer_configuration_error(ctx, format!("{err:#}")).await
        );
    };

    progress!(ctx, 850);

    // Wait for SMTP configuration
    smtp_config_task.await??;

    progress!(ctx, 900);

    let is_configured = ctx.is_configured().await?;
    if !is_configured {
        ctx.sql.set_raw_config("mvbox_move", Some("0")).await?;
        ctx.sql.set_raw_config("only_fetch_mvbox", None).await?;
    }

    drop(imap);

    progress!(ctx, 910);

    let provider = configured_param.provider;
    configured_param
        .clone()
        .save_to_transports_table(ctx, param, time())
        .await?;
    send_sync_transports(ctx).await?;

    ctx.set_config_internal(Config::ConfiguredTimestamp, Some(&time().to_string()))
        .await?;

    progress!(ctx, 920);

    ctx.set_config_internal(Config::FetchedExistingMsgs, config::from_bool(false))
        .await?;
    ctx.scheduler.interrupt_inbox().await;

    progress!(ctx, 940);
    update_device_chats_handle.await??;

    ctx.sql.set_raw_config_bool("configured", true).await?;
    ctx.emit_event(EventType::AccountsItemChanged);

    Ok(provider)
}

/// Retrieve available autoconfigurations.
///
/// A. Search configurations from the domain used in the email-address
/// B. If we have no configuration yet, search configuration in Thunderbird's central database
async fn get_autoconfig(
    ctx: &Context,
    param: &EnteredLoginParam,
    param_domain: &str,
) -> Option<Vec<ServerParams>> {
    // Make sure to not encode `.` as `%2E` here.
    // Some servers like murena.io on 2024-11-01 produce incorrect autoconfig XML
    // when address is encoded.
    // E.g.
    // <https://autoconfig.murena.io/mail/config-v1.1.xml?emailaddress=foobar%40example%2Eorg>
    // produced XML file with `<username>foobar@example%2Eorg</username>`
    // resulting in failure to log in.
    let param_addr_urlencoded =
        utf8_percent_encode(&param.addr, NON_ALPHANUMERIC_WITHOUT_DOT).to_string();

    if let Ok(res) = moz_autoconfigure(
        ctx,
        &format!(
            "https://autoconfig.{param_domain}/mail/config-v1.1.xml?emailaddress={param_addr_urlencoded}"
        ),
        &param.addr,
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 300);

    if let Ok(res) = moz_autoconfigure(
        ctx,
        // the doc does not mention `emailaddress=`, however, Thunderbird adds it, see <https://releases.mozilla.org/pub/thunderbird/>,  which makes some sense
        &format!(
            "https://{}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress={}",
            &param_domain, &param_addr_urlencoded
        ),
        &param.addr,
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 310);

    // Outlook uses always SSL but different domains (this comment describes the next two steps)
    if let Ok(res) = outlk_autodiscover(
        ctx,
        format!("https://{}/autodiscover/autodiscover.xml", &param_domain),
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 320);

    if let Ok(res) = outlk_autodiscover(
        ctx,
        format!(
            "https://autodiscover.{}/autodiscover/autodiscover.xml",
            &param_domain
        ),
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 330);

    // always SSL for Thunderbird's database
    if let Ok(res) = moz_autoconfigure(
        ctx,
        &format!("https://autoconfig.thunderbird.net/v1.1/{}", &param_domain),
        &param.addr,
    )
    .await
    {
        return Some(res);
    }

    None
}

async fn nicer_configuration_error(context: &Context, e: String) -> String {
    if e.to_lowercase().contains("could not resolve")
        || e.to_lowercase().contains("connection attempts")
        || e.to_lowercase()
            .contains("temporary failure in name resolution")
        || e.to_lowercase().contains("name or service not known")
        || e.to_lowercase()
            .contains("failed to lookup address information")
    {
        return stock_str::error_no_network(context).await;
    }

    e
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid email address: {0:?}")]
    InvalidEmailAddress(String),

    #[error("XML error at position {position}: {error}")]
    InvalidXml {
        position: u64,
        #[source]
        error: quick_xml::Error,
    },

    #[error("Number of redirection is exceeded")]
    Redirection,

    #[error("{0:#}")]
    Other(#[from] anyhow::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::login_param::EnteredServerLoginParam;
    use crate::test_utils::TestContext;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_no_panic_on_bad_credentials() {
        let t = TestContext::new().await;
        t.set_config(Config::Addr, Some("probably@unexistant.addr"))
            .await
            .unwrap();
        t.set_config(Config::MailPw, Some("123456")).await.unwrap();
        assert!(t.configure().await.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_configured_param() -> Result<()> {
        let t = &TestContext::new().await;
        let entered_param = EnteredLoginParam {
            addr: "alice@example.org".to_string(),

            imap: EnteredServerLoginParam {
                user: "alice@example.net".to_string(),
                password: "foobar".to_string(),
                ..Default::default()
            },

            ..Default::default()
        };
        let configured_param = get_configured_param(t, &entered_param).await?;
        assert_eq!(configured_param.imap_user, "alice@example.net");
        assert_eq!(configured_param.smtp_user, "");
        Ok(())
    }
}
