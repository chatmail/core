//! # Email accounts autoconfiguration process.
//!
//! The module provides automatic lookup of configuration for email providers
//! using [Mozilla Thunderbird Autoconfiguration protocol]
//! and [Outlook's Autodiscover].
//!
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
use rusqlite::OptionalExtension;
use server_params::{ServerParams, expand_param_vector};
use tokio::task;

use crate::config::Config;
use crate::constants::NON_ALPHANUMERIC_WITHOUT_DOT;
use crate::context::Context;
use crate::imap::Imap;
use crate::log::warn;
use crate::login_param::EnteredCertificateChecks;
pub use crate::login_param::EnteredLoginParam;
use crate::net::proxy::ProxyConfig;
use crate::provider::{self, Protocol, Socket};
use crate::qr::{login_param_from_account_qr, login_param_from_login_qr};
use crate::smtp::Smtp;
use crate::sync::Sync::Nosync;
use crate::tools::time;
use crate::transport::{
    ConfiguredCertificateChecks, ConfiguredLoginParam, ConfiguredServerLoginParam,
    ConnectionCandidate, delete_transport_row, maybe_update_sending_transport,
    purge_transport_caches, send_sync_transports, transport_addrs,
};
use crate::{EventType, stock_str};

/// Maximum number of relays.
///
/// See <https://github.com/chatmail/core/issues/7608>.
pub(crate) const MAX_RELAYS: usize = 5;

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
        let mut param = EnteredLoginParam::load_legacy(self).await?;

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
        match self.add_transport_unreported(param).await {
            Ok(()) => {
                progress!(self, 1000);
                Ok(())
            }
            Err(err) => {
                // We are using Anyhow's .context() and to show the
                // inner error, too, we need the {:#}:
                let error_msg = stock_str::configuration_failed(self, &format!("{err:#}"));
                progress!(self, 0, Some(error_msg.clone()));
                bail!(error_msg);
            }
        }
    }

    /// Adds a transport without reporting the outcome.
    async fn add_transport_unreported(&self, param: &mut EnteredLoginParam) -> Result<()> {
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
        res?;

        param.save_legacy(self).await
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
        self.sql
            .query_map_vec("SELECT entered_param FROM transports", (), |row| {
                let param: String = row.get(0)?;
                Ok(serde_json::from_str(&param)?)
            })
            .await
    }

    /// Returns the number of configured transports.
    pub async fn count_transports(&self) -> Result<usize> {
        self.sql.count("SELECT COUNT(*) FROM transports", ()).await
    }

    /// Removes a transport.
    /// UIs should call this function when the user removes a relay.
    ///
    /// The last transport cannot be removed.
    /// If the removed transport was the one used for sending,
    /// another one is chosen automatically.
    pub async fn delete_transport(&self, addr: &str) -> Result<()> {
        let now = time();
        let (removed_transport_id, reelected) = self
            .sql
            .transaction(|transaction| {
                if transport_addrs(transaction)?.len() <= 1 {
                    bail!("Cannot remove the last transport");
                }
                let add_timestamp: i64 = transaction
                    .query_row(
                        "SELECT add_timestamp FROM transports WHERE addr=?",
                        (addr,),
                        |row| row.get(0),
                    )
                    .optional()?
                    .context("Transport does not exist")?;
                // Removal timestamp should not be lower than addition timestamp
                // to be accepted by other devices when synced.
                let remove_timestamp = std::cmp::max(now, add_timestamp);
                let transport_id = delete_transport_row(transaction, addr, remove_timestamp)?
                    .context("Transport disappeared")?;
                let reelected = maybe_update_sending_transport(transaction)?;
                Ok((transport_id, reelected))
            })
            .await?;
        if let Some(new_addr) = reelected {
            info!(self, "Using transport {new_addr:?} for sending now.");
            self.sql.uncache_raw_config("configured_addr").await;
        }
        send_sync_transports(self).await?;
        purge_transport_caches(self, removed_transport_id).await;
        // Restarting all IO also stops the removed transport's IMAP loop.
        // Scheduler reconciliation would stop only that one loop,
        // see https://github.com/chatmail/core/issues/8513
        self.restart_io_if_running().await;

        Ok(())
    }

    async fn inner_configure(&self, param: &EnteredLoginParam) -> Result<()> {
        info!(self, "Configure ...");

        if !self
            .sql
            .exists(
                "SELECT COUNT(*) FROM transports WHERE addr=?",
                (&param.addr,),
            )
            .await?
        {
            self.check_relay_limit().await?;
        }

        let skip_network = false;
        if let Err(error) = configure(self, param, skip_network).await {
            // Log entered and actual params
            let configured_param = get_configured_param(self, param, skip_network).await;
            warn!(
                self,
                "configure failed: Entered params: {}. Used params: {}. Error: {error}.",
                param.to_string(),
                configured_param
                    .map(|param| param.to_string())
                    .unwrap_or("error".to_owned())
            );
            return Err(error);
        };
        if provider::legacy_settings_for_addr(&param.addr)?.worse_media_quality
            && !self.config_exists(Config::MediaQuality).await?
        {
            self.set_config_ext(Nosync, Config::MediaQuality, Some("1"))
                .await?;
        }
        Ok(())
    }

    async fn check_relay_limit(&self) -> Result<()> {
        ensure!(
            self.count_transports().await? < MAX_RELAYS,
            "You have reached the maximum number of relays ({MAX_RELAYS})"
        );
        Ok(())
    }
}

/// Retrieves data from autoconfig
/// to transform user-entered login parameters into complete configuration.
async fn get_configured_param(
    ctx: &Context,
    param: &EnteredLoginParam,
    skip_network: bool,
) -> Result<ConfiguredLoginParam> {
    ensure!(!param.addr.is_empty(), "Missing email address.");

    ensure!(!param.imap.password.is_empty(), "Missing (IMAP) password.");

    // SMTP password is an "advanced" setting. If unset, use the same password as for IMAP.
    let smtp_password = if param.smtp.password.is_empty() {
        param.imap.password.clone()
    } else {
        param.smtp.password.clone()
    };

    let addr = param.addr.clone();

    let parsed = EmailAddress::new(&param.addr).context("Bad email-address")?;
    let param_domain = parsed.domain;

    progress!(ctx, 200);

    let param_autoconfig = if param.imap.server.is_empty()
        && param.imap.port == 0
        && param.imap.security == Socket::Automatic
        && param.imap.user.is_empty()
        && param.smtp.server.is_empty()
        && param.smtp.port == 0
        && param.smtp.security == Socket::Automatic
        && param.smtp.user.is_empty()
        && !skip_network
    {
        // No advanced parameters entered by the user:
        // do Autoconfig unless the domain has hard-coded legacy servers.
        match provider::legacy_settings_for_addr(&param.addr)?.autoconfig_servers {
            Some(servers) => Some(servers),
            None => get_autoconfig(ctx, param, &param_domain).await,
        }
    } else {
        None
    };

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
        imap_folder: Some(param.imap.folder.clone()).filter(|folder| !folder.is_empty()),
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
        certificate_checks: match param.certificate_checks {
            EnteredCertificateChecks::Automatic => ConfiguredCertificateChecks::Automatic,
            EnteredCertificateChecks::Strict => ConfiguredCertificateChecks::Strict,
            EnteredCertificateChecks::AcceptInvalidCertificates
            | EnteredCertificateChecks::AcceptInvalidCertificates2 => {
                ConfiguredCertificateChecks::AcceptInvalidCertificates
            }
        },
    };
    Ok(configured_login_param)
}

pub(crate) async fn configure(
    ctx: &Context,
    param: &EnteredLoginParam,
    skip_network: bool,
) -> Result<()> {
    progress!(ctx, 1);

    let configured_param = get_configured_param(ctx, param, skip_network).await?;
    let proxy_config = ProxyConfig::load(ctx).await?;
    let strict_tls = configured_param.strict_tls(proxy_config.is_some())?;

    progress!(ctx, 550);

    if !skip_network {
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
            )
            .await?;

            Ok::<(), anyhow::Error>(())
        });

        progress!(ctx, 600);

        // Configure IMAP

        let transport_id = 0;
        let (_s, r) = async_channel::bounded(1);
        let mut imap = Imap::new(ctx, transport_id, configured_param.clone(), r).await?;
        let imap_session = match imap.connect(ctx).await {
            Ok(imap_session) => imap_session,
            Err(err) => {
                bail!("{}", nicer_configuration_error(ctx, format!("{err:#}")));
            }
        };

        progress!(ctx, 850);

        // Wait for SMTP configuration
        smtp_config_task.await??;

        progress!(ctx, 900);

        let is_configured = ctx.is_configured().await?;
        if !ctx.get_config_bool(Config::FixIsChatmail).await? {
            if imap_session.is_chatmail() {
                ctx.sql.set_raw_config("is_chatmail", Some("1")).await?;
            } else if !is_configured {
                // Reset the setting that may have been set
                // during failed configuration.
                ctx.sql.set_raw_config("is_chatmail", Some("0")).await?;
            }
        }

        // Drop the imap connection explicitly
        // to make sure that it's not forgotten in a future refactoring
        drop(imap_session);
        drop(imap);
    }

    progress!(ctx, 910);

    configured_param
        .clone()
        .save_to_transports_table(ctx, param, time())
        .await?;
    send_sync_transports(ctx).await?;

    ctx.set_config_internal(Config::ConfiguredTimestamp, Some(&time().to_string()))
        .await?;

    progress!(ctx, 920);

    ctx.scheduler.interrupt_inbox().await;

    progress!(ctx, 940);
    ctx.update_device_chats()
        .await
        .context("Failed to update device chats")?;

    ctx.sql.set_raw_config_bool("configured", true).await?;
    ctx.emit_event(EventType::AccountsItemChanged);

    Ok(())
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
    let accept_invalid_certificates = param.certificate_checks.accept_invalid_certificates();

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
        accept_invalid_certificates,
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 300);

    // `?emailaddress=` query string is excluded on purpose.
    // It is not part of the URL according to <https://datatracker.ietf.org/doc/draft-ietf-mailmaint-autoconfig/06/>.
    // Related discussion confirming this is at <https://github.com/benbucksch/autoconfig-spec/issues/17>.
    if let Ok(res) = moz_autoconfigure(
        ctx,
        &format!("https://{param_domain}/.well-known/autoconfig/mail/config-v1.1.xml"),
        &param.addr,
        accept_invalid_certificates,
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 310);

    // Outlook uses always SSL but different domains (this comment describes the next two steps)
    if let Ok(res) = outlk_autodiscover(
        ctx,
        format!("https://{param_domain}/autodiscover/autodiscover.xml"),
        accept_invalid_certificates,
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 320);

    if let Ok(res) = outlk_autodiscover(
        ctx,
        format!("https://autodiscover.{param_domain}/autodiscover/autodiscover.xml",),
        accept_invalid_certificates,
    )
    .await
    {
        return Some(res);
    }
    progress!(ctx, 330);

    // always SSL for Thunderbird's database
    if let Ok(res) = moz_autoconfigure(
        ctx,
        &format!("https://autoconfig.thunderbird.net/v1.1/{param_domain}"),
        &param.addr,
        accept_invalid_certificates,
    )
    .await
    {
        return Some(res);
    }

    None
}

fn nicer_configuration_error(context: &Context, e: String) -> String {
    if e.to_lowercase().contains("could not resolve")
        || e.to_lowercase().contains("connection attempts")
        || e.to_lowercase()
            .contains("temporary failure in name resolution")
        || e.to_lowercase().contains("name or service not known")
        || e.to_lowercase()
            .contains("failed to lookup address information")
    {
        return stock_str::error_no_network(context);
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
    use crate::autorelay::login_param_from_host;
    use crate::config::Config;
    use crate::login_param::EnteredImapLoginParam;
    use crate::test_utils::{TestContext, TestContextManager};
    use crate::transport::add_pseudo_transport;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_no_panic_on_bad_credentials() {
        let t = TestContext::new().await;
        t.set_config(Config::Addr, Some("probably@unexistant.addr"))
            .await
            .unwrap();
        t.set_config(Config::MailPw, Some("123456")).await.unwrap();
        assert!(t.configure().await.is_err());

        t.assert_warns_or_errors(&["DNS resolution"]).await;
    }

    /// Tests that a configuration failing
    /// before the first login attempt is still reported as a failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_early_configure_failure_is_reported() -> Result<()> {
        let t = TestContext::new().await;
        let mut param = login_param_from_host("example.org");

        // An ongoing process, e.g. a backup import,
        // makes configuration fail without ever contacting a relay.
        let _ongoing = t.alloc_ongoing().await?;
        assert!(t.add_or_update_transport(&mut param).await.is_err());

        let event = t
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::ConfigureProgress { .. }))
            .await;
        assert!(matches!(
            event,
            EventType::ConfigureProgress { progress: 0, .. }
        ));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_configured_param() -> Result<()> {
        let t = &TestContext::new().await;
        let entered_param = EnteredLoginParam {
            addr: "alice@example.org".to_string(),

            imap: EnteredImapLoginParam {
                user: "alice@example.net".to_string(),
                password: "foobar".to_string(),
                ..Default::default()
            },

            ..Default::default()
        };
        let skip_network = false;
        let configured_param = get_configured_param(t, &entered_param, skip_network).await?;
        assert_eq!(configured_param.imap_user, "alice@example.net");
        assert_eq!(configured_param.smtp_user, "");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_relay_limit() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let t = &tcm.unconfigured().await;

        // Setting ConfiguredAddr on an unconfigured account creates a pseudo transport
        t.set_config(Config::ConfiguredAddr, Some("primary@example.org"))
            .await?;
        assert_eq!(t.count_transports().await?, 1);
        t.check_relay_limit().await?;

        for i in 0..(MAX_RELAYS - 1) {
            add_pseudo_transport(t, &format!("transport{i}@example.org")).await?;
        }
        assert_eq!(t.count_transports().await?, MAX_RELAYS);
        assert_eq!(
            t.check_relay_limit().await.unwrap_err().to_string(),
            format!("You have reached the maximum number of relays ({MAX_RELAYS})")
        );

        t.delete_transport("transport0@example.org").await?;
        t.check_relay_limit().await?;

        Ok(())
    }

    /// Tests that if Alice adds maximum number of transports,
    /// Bob sends messages to all of them.
    ///
    /// This way we don't need to care about the order
    /// of addresses advertised in the public key.
    /// Previously the number of addresses
    /// taken from the key was less than the maximum
    /// number of advertised addresses.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_can_send_to_max_relays() -> Result<()> {
        let mut tcm = TestContextManager::new();

        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        // One relay is added already by default.
        for i in 1..MAX_RELAYS {
            add_pseudo_transport(alice, &format!("transport{i}@example.org")).await?;
        }
        assert_eq!(alice.count_transports().await?, MAX_RELAYS);

        let bob_chat_id = bob.create_chat_id(alice).await;

        bob.set_config_bool(Config::BccSelf, false).await?;
        let sent = bob.send_text(bob_chat_id, "Hello!").await;
        assert_eq!(
            sent.recipients.split(' ').count(),
            MAX_RELAYS,
            "List of recipients is {}",
            sent.recipients
        );

        Ok(())
    }
}
