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
use server_params::{ServerParams, expand_param_vector};
use tokio::task;

use crate::config::Config;
use crate::constants::NON_ALPHANUMERIC_WITHOUT_DOT;
use crate::context::Context;
use crate::imap::Imap;
use crate::log::warn;
pub use crate::login_param::EnteredLoginParam;
use crate::login_param::{EnteredCertificateChecks, TransportListEntry};
use crate::net::proxy::ProxyConfig;
use crate::provider::{self, Protocol, Socket};
use crate::qr::{login_param_from_account_qr, login_param_from_login_qr};
use crate::smtp::Smtp;
use crate::sync::Sync::Nosync;
use crate::tools::time;
use crate::transport::{
    ConfiguredCertificateChecks, ConfiguredLoginParam, ConfiguredServerLoginParam,
    ConnectionCandidate, send_sync_transports,
};
use crate::{EventType, stock_str};

/// Maximum number of relays.
///
/// See <https://github.com/chatmail/core/issues/7608>.
pub(crate) const MAX_RELAYS: usize = 5;

/// Hard-coded candidates for default relays.
/// In the future, we want to use it during onboarding;
/// note that before onboarding automatically on any of these,
/// we need to ask the admins whether their relay is able to handle this.
/// For now, this is just the first 6 relays from chatmail.at/relays.
#[allow(unused)]
const DEFAULT_RELAY_CANDIDATES: &[&str] = &[
    "mehl.cloud",
    "mailchat.pl",
    "chatmail.woodpeckersnest.space",
    "chatmail.culturanerd.it",
    "tarpit.fun",
    "d.gaufr.es",
];

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
    /// - [Self::set_transport_unpublished()] to set whether contacts see this transport.
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
            let error_msg = stock_str::configuration_failed(self, &format!("{err:#}"));
            progress!(self, 0, Some(error_msg.clone()));
            bail!(error_msg);
        } else {
            param.save_legacy(self).await?;
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
    pub async fn list_transports(&self) -> Result<Vec<TransportListEntry>> {
        let transports = self
            .sql
            .query_map_vec(
                "SELECT entered_param, is_published FROM transports",
                (),
                |row| {
                    let param: String = row.get(0)?;
                    let param: EnteredLoginParam = serde_json::from_str(&param)?;
                    let is_published: bool = row.get(1)?;
                    Ok(TransportListEntry {
                        param,
                        is_unpublished: !is_published,
                    })
                },
            )
            .await?;

        Ok(transports)
    }

    /// Returns the number of configured transports.
    pub async fn count_transports(&self) -> Result<usize> {
        self.sql.count("SELECT COUNT(*) FROM transports", ()).await
    }

    /// Immediately deletes a transport, potentially causing messages not to arrive.
    /// This must ONLY be used internally and by the automated tests.
    /// UI implementations must use [`Self::set_transport_unpublished`] instead.
    pub async fn delete_transport(&self, addr: &str) -> Result<()> {
        let now = time();
        let removed_transport_id = self
            .sql
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

                Ok(transport_id)
            })
            .await?;
        send_sync_transports(self).await?;
        self.quota.write().await.remove(&removed_transport_id);
        self.restart_io_if_running().await;

        Ok(())
    }

    /// Change whether the transport is unpublished.
    /// UIs should call this function when the user clicks on "Remove".
    /// Core will keep listening on this transport for some time,
    /// and automatically remove it once it is no longer needed.
    ///
    /// Unpublished transports are not advertised to contacts,
    /// and self-sent messages are not sent there,
    /// so that we don't cause extra messages to the corresponding inbox,
    /// but can still receive messages from contacts who don't know our new transport addresses yet.
    ///
    /// When more transports are added by [`Self::add_or_update_transport()`] or [`Self::add_transport_from_qr`],
    /// the least recently needed unpublished transport is automatically removed
    /// if this is necessary in order to stay below the maximum number of allowed relays.
    /// Also, unpublished transports that are not used to receive any new messages for a time defined by
    /// `UNPUBLISHED_TRANSPORT_KEEP_TIME` are automatically removed.
    pub async fn set_transport_unpublished(&self, addr: &str, unpublished: bool) -> Result<()> {
        self.sql
            .transaction(|trans| {
                let primary_addr: String = trans
                    .query_row(
                        "SELECT value FROM config WHERE keyname='configured_addr'",
                        (),
                        |row| row.get(0),
                    )
                    .context("Select primary address")?;
                if primary_addr == addr && unpublished {
                    bail!("Can't set primary relay as unpublished");
                }
                // We need to update the timestamp so that the key's timestamp changes
                // and is recognized as newer by our peers
                trans
                    .execute(
                        "UPDATE transports SET is_published=?, add_timestamp=? WHERE addr=? AND is_published!=?1",
                        (!unpublished, time(), addr),
                    )
                    .context("Update transports")?;
                Ok(())
            })
            .await?;
        send_sync_transports(self).await?;
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
            self.try_make_space_for_new_relay().await?;
        }

        if let Err(error) = configure(self, param).await {
            // Log entered and actual params
            let configured_param = get_configured_param(self, param).await;
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
        self.set_config_internal(Config::NotifyAboutWrongPw, Some("1"))
            .await?;
        apply_legacy_domain_config_defaults(self, &param.addr).await?;
        Ok(())
    }

    /// This function is called before adding a new relay.
    /// If the maximum number of relays ([`MAX_RELAYS`]) is already reached,
    /// then it tries to make space by removing an unpublished relay.
    /// If there are multiple unpublished relays,
    /// the one that hasn't received a message for longest is removed.
    /// If there are no unpublished relays, an error is returned.
    ///
    /// Note that eviction happens before we know that a new relay works,
    /// which is a trade-off we made in favor of implementation complexity.
    async fn try_make_space_for_new_relay(&self) -> Result<()> {
        if self.count_transports().await? >= MAX_RELAYS {
            // Try to automatically remove the unpublished transport that wasn't used for the longest time:
            if let Some(addr) = self
                .sql
                .query_get_value::<String>(
                    "SELECT addr FROM transports WHERE is_published=0
                    ORDER BY last_rcvd_timestamp, add_timestamp LIMIT 1",
                    (),
                )
                .await?
            {
                info!(
                    self,
                    "Auto-deleting relay {addr} to make space for new relay."
                );
                self.delete_transport(&addr).await?;
            }

            if self.count_transports().await? >= MAX_RELAYS {
                // Apparently, all the transports are published
                bail!("You have reached the maximum number of relays ({MAX_RELAYS})");
            }
        };
        Ok(())
    }
}

/// Applies a few select non-default config values that used to come from provider database.
async fn apply_legacy_domain_config_defaults(context: &Context, addr: &str) -> Result<()> {
    let settings = provider::legacy_settings_for_addr(addr);

    if settings.disable_mdns && !context.config_exists(Config::MdnsEnabled).await? {
        context
            .set_config_ex(Nosync, Config::MdnsEnabled, Some("0"))
            .await?;
    }

    if settings.worse_media_quality && !context.config_exists(Config::MediaQuality).await? {
        context
            .set_config_ex(Nosync, Config::MediaQuality, Some("1"))
            .await?;
    }
    Ok(())
}

/// Retrieves data from autoconfig
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
    {
        // no advanced parameters entered by the user: do Autoconfig
        // except for a few known legacy-domain overrides.
        let legacy_servers = provider::legacy_settings_for_addr(&param.addr).autoconfig_servers;
        if legacy_servers.is_some() {
            legacy_servers
        } else {
            get_autoconfig(ctx, param, &param_domain).await
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

async fn configure(ctx: &Context, param: &EnteredLoginParam) -> Result<()> {
    progress!(ctx, 1);

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
    let imap_session = match imap.connect(ctx, configuring).await {
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

    drop(imap_session);
    drop(imap);

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
    use crate::tools::SystemTime;

    use super::*;
    use crate::config::Config;
    use crate::login_param::EnteredImapLoginParam;
    use crate::sql::update_transport_last_rcvd_timestamp;
    use crate::test_utils::TestContext;
    use crate::transport::add_pseudo_transport;

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

            imap: EnteredImapLoginParam {
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_try_make_place_for_new_relay() -> Result<()> {
        let t = TestContext::new().await;

        // Setting ConfiguredAddr on an unconfigured account creates a pseudo primary transport
        t.set_config(Config::ConfiguredAddr, Some("primary@example.org"))
            .await?;

        // Test that try_make_place_for_new_relay() doesn't do anything when we're below the limit
        assert_eq!(t.count_transports().await?, 1);
        t.try_make_space_for_new_relay().await?;
        assert_eq!(t.count_transports().await?, 1);

        for i in 0..(MAX_RELAYS - 2) {
            add_pseudo_transport(&t, &format!("transport{i}@example.org")).await?;
        }
        assert_eq!(t.count_transports().await?, MAX_RELAYS - 1);
        t.try_make_space_for_new_relay().await?;
        assert_eq!(t.count_transports().await?, MAX_RELAYS - 1);

        // Test that try_make_place_for_new_relay() removes the unpublished transport
        // when we're at the limit
        add_pseudo_transport(&t, "unpublished@example.org").await?;
        t.set_transport_unpublished("unpublished@example.org", true)
            .await?;
        assert_eq!(t.count_transports().await?, MAX_RELAYS);
        t.try_make_space_for_new_relay().await?;
        assert_eq!(t.count_transports().await?, MAX_RELAYS - 1);
        assert_eq!(
            t.sql
                .exists(
                    "SELECT COUNT(*) FROM transports WHERE addr=?",
                    ("unpublished@example.org",),
                )
                .await?,
            false
        );

        // Test that if there are multiple unpublished relays,
        // the one that was used least recently is removed
        t.set_transport_unpublished("transport0@example.org", true)
            .await?;
        add_pseudo_transport(&t, "other_unpublished@example.org").await?;
        t.set_transport_unpublished("other_unpublished@example.org", true)
            .await?;
        assert_eq!(t.count_transports().await?, MAX_RELAYS);

        let transport0_id: u32 = t
            .sql
            .query_get_value(
                "SELECT id FROM transports WHERE addr=?",
                ("transport0@example.org",),
            )
            .await?
            .unwrap();
        let other_unpublished_id: u32 = t
            .sql
            .query_get_value(
                "SELECT id FROM transports WHERE addr=?",
                ("other_unpublished@example.org",),
            )
            .await?
            .unwrap();

        update_transport_last_rcvd_timestamp(&t, transport0_id).await?;
        SystemTime::shift(std::time::Duration::from_secs(10));
        update_transport_last_rcvd_timestamp(&t, other_unpublished_id).await?;

        // Test that try_make_place_for_new_relay()
        // removes the relay with the oldest last_rcvd_timestamp
        t.try_make_space_for_new_relay().await?;
        assert_eq!(t.count_transports().await?, MAX_RELAYS - 1);
        assert_eq!(
            t.sql
                .exists(
                    "SELECT COUNT(*) FROM transports WHERE addr=?",
                    ("transport0@example.org",),
                )
                .await?,
            false
        );
        assert_eq!(
            t.sql
                .exists(
                    "SELECT COUNT(*) FROM transports WHERE addr=?",
                    ("other_unpublished@example.org",),
                )
                .await?,
            true
        );

        // Test that try_make_place_for_new_relay() fails
        // if there are MAX_RELAYS published transports
        add_pseudo_transport(&t, "published_extra@example.org").await?;
        t.set_transport_unpublished("other_unpublished@example.org", false)
            .await?;
        assert_eq!(t.count_transports().await?, MAX_RELAYS);
        assert!(t.try_make_space_for_new_relay().await.is_err());
        assert_eq!(t.count_transports().await?, MAX_RELAYS);

        Ok(())
    }
}
