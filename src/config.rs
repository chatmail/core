//! # Key-value configuration management.

use std::env;
use std::path::Path;
use std::str::FromStr;

use anyhow::{bail, ensure, Context as _, Result};
use base64::Engine as _;
use deltachat_contact_tools::{addr_cmp, sanitize_single_line};
use serde::{Deserialize, Serialize};
use strum::{EnumProperty, IntoEnumIterator};
use strum_macros::{AsRefStr, Display, EnumIter, EnumString};
use tokio::fs;

use crate::blob::BlobObject;
use crate::configure::EnteredLoginParam;
use crate::constants;
use crate::context::Context;
use crate::events::EventType;
use crate::log::LogExt;
use crate::login_param::ConfiguredLoginParam;
use crate::mimefactory::RECOMMENDED_FILE_SIZE;
use crate::provider::{get_provider_by_id, Provider};
use crate::sync::{self, Sync::*, SyncData};
use crate::tools::get_abs_path;

/// The available configuration keys.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Display,
    EnumString,
    AsRefStr,
    EnumIter,
    EnumProperty,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
)]
#[strum(serialize_all = "snake_case")]
pub enum Config {
    /// Email address, used in the `From:` field.
    Addr,

    /// IMAP server hostname.
    MailServer,

    /// IMAP server username.
    MailUser,

    /// IMAP server password.
    MailPw,

    /// IMAP server port.
    MailPort,

    /// IMAP server security (e.g. TLS, STARTTLS).
    MailSecurity,

    /// How to check TLS certificates.
    ///
    /// "IMAP" in the name is for compatibility,
    /// this actually applies to both IMAP and SMTP connections.
    ImapCertificateChecks,

    /// SMTP server hostname.
    SendServer,

    /// SMTP server username.
    SendUser,

    /// SMTP server password.
    SendPw,

    /// SMTP server port.
    SendPort,

    /// SMTP server security (e.g. TLS, STARTTLS).
    SendSecurity,

    /// Deprecated option for backwards compatibility.
    ///
    /// Certificate checks for SMTP are actually controlled by `imap_certificate_checks` config.
    SmtpCertificateChecks,

    /// Whether to use OAuth 2.
    ///
    /// Historically contained other bitflags, which are now deprecated.
    /// Should not be extended in the future, create new config keys instead.
    ServerFlags,

    /// True if proxy is enabled.
    ///
    /// Can be used to disable proxy without erasing known URLs.
    ProxyEnabled,

    /// Proxy URL.
    ///
    /// Supported URLs schemes are `http://` (HTTP), `https://` (HTTPS),
    /// `socks5://` (SOCKS5) and `ss://` (Shadowsocks).
    ///
    /// May contain multiple URLs separated by newline, in which case the first one is used.
    ProxyUrl,

    /// True if SOCKS5 is enabled.
    ///
    /// Can be used to disable SOCKS5 without erasing SOCKS5 configuration.
    ///
    /// Deprecated in favor of `ProxyEnabled`.
    Socks5Enabled,

    /// SOCKS5 proxy server hostname or address.
    ///
    /// Deprecated in favor of `ProxyUrl`.
    Socks5Host,

    /// SOCKS5 proxy server port.
    ///
    /// Deprecated in favor of `ProxyUrl`.
    Socks5Port,

    /// SOCKS5 proxy server username.
    ///
    /// Deprecated in favor of `ProxyUrl`.
    Socks5User,

    /// SOCKS5 proxy server password.
    ///
    /// Deprecated in favor of `ProxyUrl`.
    Socks5Password,

    /// Own name to use in the `From:` field when sending messages.
    Displayname,

    /// Own status to display, sent in message footer.
    Selfstatus,

    /// Own avatar filename.
    Selfavatar,

    /// Send BCC copy to self.
    ///
    /// Should be enabled for multidevice setups.
    /// Default is 0 for chatmail accounts, 1 otherwise.
    ///
    /// This is automatically enabled when importing/exporting a backup,
    /// setting up a second device, or receiving a sync message.
    BccSelf,

    /// True if encryption is preferred according to Autocrypt standard.
    #[strum(props(default = "1"))]
    E2eeEnabled,

    /// True if Message Delivery Notifications (read receipts) should
    /// be sent and requested.
    #[strum(props(default = "1"))]
    MdnsEnabled,

    /// True if "Sent" folder should be watched for changes.
    #[strum(props(default = "0"))]
    SentboxWatch,

    /// True if chat messages should be moved to a separate folder. Auto-sent messages like sync
    /// ones are moved there anyway.
    #[strum(props(default = "1"))]
    MvboxMove,

    /// Watch for new messages in the "Mvbox" (aka DeltaChat folder) only.
    ///
    /// This will not entirely disable other folders, e.g. the spam folder will also still
    /// be watched for new messages.
    #[strum(props(default = "0"))]
    OnlyFetchMvbox,

    /// Whether to show classic emails or only chat messages.
    #[strum(props(default = "2"))] // also change ShowEmails.default() on changes
    ShowEmails,

    /// Quality of the media files to send.
    #[strum(props(default = "0"))] // also change MediaQuality.default() on changes
    MediaQuality,

    /// If set to "1", then existing messages are considered to be already fetched.
    /// This flag is reset after successful configuration.
    #[strum(props(default = "1"))]
    FetchedExistingMsgs,

    /// Timer in seconds after which the message is deleted from the
    /// server.
    ///
    /// 0 means messages are never deleted by Delta Chat.
    ///
    /// Value 1 is treated as "delete at once": messages are deleted
    /// immediately, without moving to DeltaChat folder.
    ///
    /// Default is 1 for chatmail accounts without `BccSelf`, 0 otherwise.
    DeleteServerAfter,

    /// Timer in seconds after which the message is deleted from the
    /// device.
    ///
    /// Equals to 0 by default, which means the message is never
    /// deleted.
    #[strum(props(default = "0"))]
    DeleteDeviceAfter,

    /// Move messages to the Trash folder instead of marking them "\Deleted". Overrides
    /// `ProviderOptions::delete_to_trash`.
    DeleteToTrash,

    /// The primary email address. Also see `SecondaryAddrs`.
    ConfiguredAddr,

    /// List of configured IMAP servers as a JSON array.
    ConfiguredImapServers,

    /// Configured IMAP server hostname.
    ///
    /// This is replaced by `configured_imap_servers` for new configurations.
    ConfiguredMailServer,

    /// Configured IMAP server port.
    ///
    /// This is replaced by `configured_imap_servers` for new configurations.
    ConfiguredMailPort,

    /// Configured IMAP server security (e.g. TLS, STARTTLS).
    ///
    /// This is replaced by `configured_imap_servers` for new configurations.
    ConfiguredMailSecurity,

    /// Configured IMAP server username.
    ///
    /// This is set if user has configured username manually.
    ConfiguredMailUser,

    /// Configured IMAP server password.
    ConfiguredMailPw,

    /// Configured TLS certificate checks.
    /// This option is saved on successful configuration
    /// and should not be modified manually.
    ///
    /// This actually applies to both IMAP and SMTP connections,
    /// but has "IMAP" in the name for backwards compatibility.
    ConfiguredImapCertificateChecks,

    /// List of configured SMTP servers as a JSON array.
    ConfiguredSmtpServers,

    /// Configured SMTP server hostname.
    ///
    /// This is replaced by `configured_smtp_servers` for new configurations.
    ConfiguredSendServer,

    /// Configured SMTP server port.
    ///
    /// This is replaced by `configured_smtp_servers` for new configurations.
    ConfiguredSendPort,

    /// Configured SMTP server security (e.g. TLS, STARTTLS).
    ///
    /// This is replaced by `configured_smtp_servers` for new configurations.
    ConfiguredSendSecurity,

    /// Configured SMTP server username.
    ///
    /// This is set if user has configured username manually.
    ConfiguredSendUser,

    /// Configured SMTP server password.
    ConfiguredSendPw,

    /// Deprecated, stored for backwards compatibility.
    ///
    /// ConfiguredImapCertificateChecks is actually used.
    ConfiguredSmtpCertificateChecks,

    /// Whether OAuth 2 is used with configured provider.
    ConfiguredServerFlags,

    /// Configured folder for incoming messages.
    ConfiguredInboxFolder,

    /// Configured folder for chat messages.
    ConfiguredMvboxFolder,

    /// Configured "Sent" folder.
    ConfiguredSentboxFolder,

    /// Configured "Trash" folder.
    ConfiguredTrashFolder,

    /// Unix timestamp of the last successful configuration.
    ConfiguredTimestamp,

    /// ID of the configured provider from the provider database.
    ConfiguredProvider,

    /// True if account is configured.
    Configured,

    /// True if account is a chatmail account.
    IsChatmail,

    /// True if `IsChatmail` mustn't be autoconfigured. For tests.
    FixIsChatmail,

    /// True if account is muted.
    IsMuted,

    /// Optional tag as "Work", "Family".
    /// Meant to help profile owner to differ between profiles with similar names.
    PrivateTag,

    /// All secondary self addresses separated by spaces
    /// (`addr1@example.org addr2@example.org addr3@example.org`)
    SecondaryAddrs,

    /// Read-only core version string.
    #[strum(serialize = "sys.version")]
    SysVersion,

    /// Maximal recommended attachment size in bytes.
    #[strum(serialize = "sys.msgsize_max_recommended")]
    SysMsgsizeMaxRecommended,

    /// Space separated list of all config keys available.
    #[strum(serialize = "sys.config_keys")]
    SysConfigKeys,

    /// True if it is a bot account.
    Bot,

    /// True when to skip initial start messages in groups.
    #[strum(props(default = "0"))]
    SkipStartMessages,

    /// Whether we send a warning if the password is wrong (set to false when we send a warning
    /// because we do not want to send a second warning)
    #[strum(props(default = "0"))]
    NotifyAboutWrongPw,

    /// If a warning about exceeding quota was shown recently,
    /// this is the percentage of quota at the time the warning was given.
    /// Unset, when quota falls below minimal warning threshold again.
    QuotaExceeding,

    /// address to webrtc instance to use for videochats
    WebrtcInstance,

    /// Timestamp of the last time housekeeping was run
    LastHousekeeping,

    /// Timestamp of the last `CantDecryptOutgoingMsgs` notification.
    LastCantDecryptOutgoingMsgs,

    /// To how many seconds to debounce scan_all_folders. Used mainly in tests, to disable debouncing completely.
    #[strum(props(default = "60"))]
    ScanAllFoldersDebounceSecs,

    /// Whether to avoid using IMAP IDLE even if the server supports it.
    ///
    /// This is a developer option for testing "fake idle".
    #[strum(props(default = "0"))]
    DisableIdle,

    /// Defines the max. size (in bytes) of messages downloaded automatically.
    /// 0 = no limit.
    #[strum(props(default = "0"))]
    DownloadLimit,

    /// Enable sending and executing (applying) sync messages. Sending requires `BccSelf` to be set
    /// and `Bot` unset.
    ///
    /// On real devices, this is usually always enabled and `BccSelf` is the only setting
    /// that controls whether sync messages are sent.
    ///
    /// In tests, this is usually disabled.
    #[strum(props(default = "1"))]
    SyncMsgs,

    /// Space-separated list of all the authserv-ids which we believe
    /// may be the one of our email server.
    ///
    /// See `crate::authres::update_authservid_candidates`.
    AuthservIdCandidates,

    /// Make all outgoing messages with Autocrypt header "multipart/signed".
    SignUnencrypted,

    /// Enable header protection for `Autocrypt` header.
    ///
    /// This is an experimental setting not compatible to other MUAs
    /// and older Delta Chat versions (core version <= v1.149.0).
    ProtectAutocrypt,

    /// Let the core save all events to the database.
    /// This value is used internally to remember the MsgId of the logging xdc
    #[strum(props(default = "0"))]
    DebugLogging,

    /// Last message processed by the bot.
    LastMsgId,

    /// How often to gossip Autocrypt keys in chats with multiple recipients, in seconds. 2 days by
    /// default.
    ///
    /// This is not supposed to be changed by UIs and only used for testing.
    #[strum(props(default = "172800"))]
    GossipPeriod,

    /// Feature flag for verified 1:1 chats; the UI should set it
    /// to 1 if it supports verified 1:1 chats.
    /// Regardless of this setting, `chat.is_protected()` returns true while the key is verified,
    /// and when the key changes, an info message is posted into the chat.
    /// 0=Nothing else happens when the key changes.
    /// 1=After the key changed, `can_send()` returns false and `is_protection_broken()` returns true
    /// until `chat_id.accept()` is called.
    #[strum(props(default = "0"))]
    VerifiedOneOnOneChats,

    /// Row ID of the key in the `keypairs` table
    /// used for signatures, encryption to self and included in `Autocrypt` header.
    KeyId,

    /// This key is sent to the self_reporting bot so that the bot can recognize the user
    /// without storing the email address
    SelfReportingId,

    /// MsgId of webxdc map integration.
    WebxdcIntegration,

    /// Enable webxdc realtime features.
    #[strum(props(default = "1"))]
    WebxdcRealtimeEnabled,

    /// Last device token stored on the chatmail server.
    ///
    /// If it has not changed, we do not store
    /// the device token again.
    DeviceToken,

    /// Device token encrypted with OpenPGP.
    ///
    /// We store encrypted token next to `device_token`
    /// to avoid encrypting it differently and
    /// storing the same token multiple times on the server.
    EncryptedDeviceToken,
}

impl Config {
    /// Whether the config option is synced across devices.
    ///
    /// This must be checked on both sides so that if there are different client versions, the
    /// synchronisation of a particular option is either done or not done in both directions.
    /// Moreover, receivers of a config value need to check if a key can be synced because if it is
    /// a file path, it could otherwise lead to exfiltration of files from a receiver's
    /// device if we assume an attacker to have control of a device in a multi-device setting or if
    /// multiple users are sharing an account. Another example is `Self::SyncMsgs` itself which
    /// mustn't be controlled by other devices.
    pub(crate) fn is_synced(&self) -> bool {
        matches!(
            self,
            Self::Displayname
                | Self::MdnsEnabled
                | Self::MvboxMove
                | Self::ShowEmails
                | Self::Selfavatar
                | Self::Selfstatus,
        )
    }

    /// Whether the config option needs an IO scheduler restart to take effect.
    pub(crate) fn needs_io_restart(&self) -> bool {
        matches!(
            self,
            Config::MvboxMove | Config::OnlyFetchMvbox | Config::SentboxWatch
        )
    }
}

impl Context {
    /// Returns true if configuration value is set in the db for the given key.
    ///
    /// NB: Don't use this to check if the key is configured because this doesn't look into
    /// environment. The proper use of this function is e.g. checking a key before setting it.
    pub(crate) async fn config_exists(&self, key: Config) -> Result<bool> {
        Ok(self.sql.get_raw_config(key.as_ref()).await?.is_some())
    }

    /// Get a config key value. Returns `None` if no value is set.
    pub(crate) async fn get_config_opt(&self, key: Config) -> Result<Option<String>> {
        let env_key = format!("DELTACHAT_{}", key.as_ref().to_uppercase());
        if let Ok(value) = env::var(env_key) {
            return Ok(Some(value));
        }

        let value = match key {
            Config::Selfavatar => {
                let rel_path = self.sql.get_raw_config(key.as_ref()).await?;
                rel_path.map(|p| {
                    get_abs_path(self, Path::new(&p))
                        .to_string_lossy()
                        .into_owned()
                })
            }
            Config::SysVersion => Some((*constants::DC_VERSION_STR).clone()),
            Config::SysMsgsizeMaxRecommended => Some(format!("{RECOMMENDED_FILE_SIZE}")),
            Config::SysConfigKeys => Some(get_config_keys_string()),
            _ => self.sql.get_raw_config(key.as_ref()).await?,
        };
        Ok(value)
    }

    /// Get a config key value if set, or a default value. Returns `None` if no value exists.
    pub async fn get_config(&self, key: Config) -> Result<Option<String>> {
        let value = self.get_config_opt(key).await?;
        if value.is_some() {
            return Ok(value);
        }

        // Default values
        let val = match key {
            Config::BccSelf => match Box::pin(self.is_chatmail()).await? {
                false => Some("1".to_string()),
                true => Some("0".to_string()),
            },
            Config::ConfiguredInboxFolder => Some("INBOX".to_string()),
            Config::DeleteServerAfter => {
                match !Box::pin(self.get_config_bool(Config::BccSelf)).await?
                    && Box::pin(self.is_chatmail()).await?
                {
                    true => Some("1".to_string()),
                    false => Some("0".to_string()),
                }
            }
            Config::Addr => {
                warn!(self, "It looks like you are using `Config::Addr` to get the configured address. You should use `Config::ConfiguredAddr` instead.");
                self.get_config_opt(Config::ConfiguredAddr).await?
            }
            _ => key.get_str("default").map(|s| s.to_string()),
        };
        Ok(val)
    }

    /// Returns Some(T) if a value for the given key is set and was successfully parsed.
    /// Returns None if could not parse.
    pub(crate) async fn get_config_opt_parsed<T: FromStr>(&self, key: Config) -> Result<Option<T>> {
        self.get_config_opt(key)
            .await
            .map(|s: Option<String>| s.and_then(|s| s.parse().ok()))
    }

    /// Returns Some(T) if a value for the given key exists (incl. default value) and was
    /// successfully parsed.
    /// Returns None if could not parse.
    pub async fn get_config_parsed<T: FromStr>(&self, key: Config) -> Result<Option<T>> {
        self.get_config(key)
            .await
            .map(|s: Option<String>| s.and_then(|s| s.parse().ok()))
    }

    /// Returns 32-bit signed integer configuration value for the given key.
    pub async fn get_config_int(&self, key: Config) -> Result<i32> {
        Ok(self.get_config_parsed(key).await?.unwrap_or_default())
    }

    /// Returns 32-bit unsigned integer configuration value for the given key.
    pub async fn get_config_u32(&self, key: Config) -> Result<u32> {
        Ok(self.get_config_parsed(key).await?.unwrap_or_default())
    }

    /// Returns 64-bit signed integer configuration value for the given key.
    pub async fn get_config_i64(&self, key: Config) -> Result<i64> {
        Ok(self.get_config_parsed(key).await?.unwrap_or_default())
    }

    /// Returns 64-bit unsigned integer configuration value for the given key.
    pub async fn get_config_u64(&self, key: Config) -> Result<u64> {
        Ok(self.get_config_parsed(key).await?.unwrap_or_default())
    }

    /// Returns boolean configuration value (if set) for the given key.
    pub(crate) async fn get_config_bool_opt(&self, key: Config) -> Result<Option<bool>> {
        Ok(self
            .get_config_opt_parsed::<i32>(key)
            .await?
            .map(|x| x != 0))
    }

    /// Returns boolean configuration value for the given key.
    pub async fn get_config_bool(&self, key: Config) -> Result<bool> {
        Ok(self
            .get_config_parsed::<i32>(key)
            .await?
            .map(|x| x != 0)
            .unwrap_or_default())
    }

    /// Returns true if movebox ("DeltaChat" folder) should be watched.
    pub(crate) async fn should_watch_mvbox(&self) -> Result<bool> {
        Ok(self.get_config_bool(Config::MvboxMove).await?
            || self.get_config_bool(Config::OnlyFetchMvbox).await?
            || !self.get_config_bool(Config::IsChatmail).await?)
    }

    /// Returns true if sentbox ("Sent" folder) should be watched.
    pub(crate) async fn should_watch_sentbox(&self) -> Result<bool> {
        Ok(self.get_config_bool(Config::SentboxWatch).await?
            && self
                .get_config(Config::ConfiguredSentboxFolder)
                .await?
                .is_some())
    }

    /// Returns true if sync messages should be sent.
    pub(crate) async fn should_send_sync_msgs(&self) -> Result<bool> {
        Ok(self.get_config_bool(Config::SyncMsgs).await?
            && self.get_config_bool(Config::BccSelf).await?
            && !self.get_config_bool(Config::Bot).await?)
    }

    /// Returns whether sync messages should be uploaded to the mvbox.
    pub(crate) async fn should_move_sync_msgs(&self) -> Result<bool> {
        Ok(self.get_config_bool(Config::MvboxMove).await?
            || !self.get_config_bool(Config::IsChatmail).await?)
    }

    /// Returns whether MDNs should be requested.
    pub(crate) async fn should_request_mdns(&self) -> Result<bool> {
        match self.get_config_bool_opt(Config::MdnsEnabled).await? {
            Some(val) => Ok(val),
            None => Ok(!self.get_config_bool(Config::Bot).await?),
        }
    }

    /// Returns whether MDNs should be sent.
    pub(crate) async fn should_send_mdns(&self) -> Result<bool> {
        self.get_config_bool(Config::MdnsEnabled).await
    }

    /// Gets configured "delete_server_after" value.
    ///
    /// `None` means never delete the message, `Some(0)` means delete
    /// at once, `Some(x)` means delete after `x` seconds.
    pub async fn get_config_delete_server_after(&self) -> Result<Option<i64>> {
        let val = match self
            .get_config_parsed::<i64>(Config::DeleteServerAfter)
            .await?
            .unwrap_or(0)
        {
            0 => None,
            1 => Some(0),
            x => Some(x),
        };
        Ok(val)
    }

    /// Gets the configured provider, as saved in the `configured_provider` value.
    ///
    /// The provider is determined by `get_provider_info()` during configuration and then saved
    /// to the db in `param.save_to_database()`, together with all the other `configured_*` values.
    pub async fn get_configured_provider(&self) -> Result<Option<&'static Provider>> {
        if let Some(cfg) = self.get_config(Config::ConfiguredProvider).await? {
            return Ok(get_provider_by_id(&cfg));
        }
        Ok(None)
    }

    /// Gets configured "delete_device_after" value.
    ///
    /// `None` means never delete the message, `Some(x)` means delete
    /// after `x` seconds.
    pub async fn get_config_delete_device_after(&self) -> Result<Option<i64>> {
        match self.get_config_int(Config::DeleteDeviceAfter).await? {
            0 => Ok(None),
            x => Ok(Some(i64::from(x))),
        }
    }

    /// Executes [`SyncData::Config`] item sent by other device.
    pub(crate) async fn sync_config(&self, key: &Config, value: &str) -> Result<()> {
        let config_value;
        let value = match key {
            Config::Selfavatar if value.is_empty() => None,
            Config::Selfavatar => {
                config_value = BlobObject::store_from_base64(self, value)?;
                Some(config_value.as_str())
            }
            _ => Some(value),
        };
        match key.is_synced() {
            true => self.set_config_ex(Nosync, *key, value).await,
            false => Ok(()),
        }
    }

    fn check_config(key: Config, value: Option<&str>) -> Result<()> {
        match key {
            Config::Socks5Enabled
            | Config::ProxyEnabled
            | Config::BccSelf
            | Config::E2eeEnabled
            | Config::MdnsEnabled
            | Config::SentboxWatch
            | Config::MvboxMove
            | Config::OnlyFetchMvbox
            | Config::DeleteToTrash
            | Config::Configured
            | Config::Bot
            | Config::NotifyAboutWrongPw
            | Config::SyncMsgs
            | Config::SignUnencrypted
            | Config::DisableIdle => {
                ensure!(
                    matches!(value, None | Some("0") | Some("1")),
                    "Boolean value must be either 0 or 1"
                );
            }
            _ => (),
        }
        Ok(())
    }

    /// Set the given config key and make it effective.
    /// This may restart the IO scheduler. If `None` is passed as a value the value is cleared and
    /// set to the default if there is one.
    pub async fn set_config(&self, key: Config, value: Option<&str>) -> Result<()> {
        Self::check_config(key, value)?;

        let _pause = match key.needs_io_restart() {
            true => self.scheduler.pause(self.clone()).await?,
            _ => Default::default(),
        };
        self.set_config_internal(key, value).await?;
        if key == Config::SentboxWatch {
            self.last_full_folder_scan.lock().await.take();
        }
        Ok(())
    }

    pub(crate) async fn set_config_internal(&self, key: Config, value: Option<&str>) -> Result<()> {
        self.set_config_ex(Sync, key, value).await
    }

    pub(crate) async fn set_config_ex(
        &self,
        sync: sync::Sync,
        key: Config,
        mut value: Option<&str>,
    ) -> Result<()> {
        Self::check_config(key, value)?;
        let sync = sync == Sync && key.is_synced() && self.is_configured().await?;
        let better_value;

        match key {
            Config::Selfavatar => {
                self.sql
                    .execute("UPDATE contacts SET selfavatar_sent=0;", ())
                    .await?;
                match value {
                    Some(path) => {
                        let path = get_abs_path(self, Path::new(path));
                        let mut blob = BlobObject::create_and_deduplicate(self, &path, &path)?;
                        blob.recode_to_avatar_size(self).await?;
                        self.sql
                            .set_raw_config(key.as_ref(), Some(blob.as_name()))
                            .await?;
                        if sync {
                            let buf = fs::read(blob.to_abs_path()).await?;
                            better_value = base64::engine::general_purpose::STANDARD.encode(buf);
                            value = Some(&better_value);
                        }
                    }
                    None => {
                        self.sql.set_raw_config(key.as_ref(), None).await?;
                        if sync {
                            better_value = String::new();
                            value = Some(&better_value);
                        }
                    }
                }
                self.emit_event(EventType::SelfavatarChanged);
            }
            Config::DeleteDeviceAfter => {
                let ret = self.sql.set_raw_config(key.as_ref(), value).await;
                // Interrupt ephemeral loop to delete old messages immediately.
                self.scheduler.interrupt_ephemeral_task().await;
                ret?
            }
            Config::Displayname => {
                if let Some(v) = value {
                    better_value = sanitize_single_line(v);
                    value = Some(&better_value);
                }
                self.sql.set_raw_config(key.as_ref(), value).await?;
            }
            Config::Addr => {
                self.sql
                    .set_raw_config(key.as_ref(), value.map(|s| s.to_lowercase()).as_deref())
                    .await?;
            }
            Config::MvboxMove => {
                self.sql.set_raw_config(key.as_ref(), value).await?;
                self.sql
                    .set_raw_config(constants::DC_FOLDERS_CONFIGURED_KEY, None)
                    .await?;
            }
            Config::ConfiguredAddr => {
                if self.is_configured().await? {
                    bail!("Cannot change ConfiguredSelfAddr");
                }
                if let Some(addr) = value {
                    info!(self, "Creating a pseudo configured account which will not be able to send or receive messages. ONLY MEANT FOR TESTS.");
                    ConfiguredLoginParam::from_json(&format!(
                        r#"{{"addr":"{addr}","imap":[],"imap_user":"","imap_password":"","smtp":[],"smtp_user":"","smtp_password":"","certificate_checks":"Automatic","oauth2":false}}"#
                    ))?
                    .save_to_transports_table(self, &EnteredLoginParam::default())
                    .await?;
                }
            }
            _ => {
                self.sql.set_raw_config(key.as_ref(), value).await?;
            }
        }
        if matches!(
            key,
            Config::Displayname | Config::Selfavatar | Config::PrivateTag
        ) {
            self.emit_event(EventType::AccountsItemChanged);
        }
        if key.is_synced() {
            self.emit_event(EventType::ConfigSynced { key });
        }
        if !sync {
            return Ok(());
        }
        let Some(val) = value else {
            return Ok(());
        };
        let val = val.to_string();
        if self
            .add_sync_item(SyncData::Config { key, val })
            .await
            .log_err(self)
            .is_err()
        {
            return Ok(());
        }
        self.scheduler.interrupt_inbox().await;
        Ok(())
    }

    /// Set the given config to an unsigned 32-bit integer value.
    pub async fn set_config_u32(&self, key: Config, value: u32) -> Result<()> {
        self.set_config(key, Some(&value.to_string())).await?;
        Ok(())
    }

    /// Set the given config to a boolean value.
    pub async fn set_config_bool(&self, key: Config, value: bool) -> Result<()> {
        self.set_config(key, from_bool(value)).await?;
        Ok(())
    }

    /// Sets an ui-specific key-value pair.
    /// Keys must be prefixed by `ui.`
    /// and should be followed by the name of the system and maybe subsystem,
    /// eg. `ui.desktop.linux.foo`, `ui.desktop.macos.bar`, `ui.ios.foobar`.
    pub async fn set_ui_config(&self, key: &str, value: Option<&str>) -> Result<()> {
        ensure!(key.starts_with("ui."), "set_ui_config(): prefix missing.");
        self.sql.set_raw_config(key, value).await
    }

    /// Gets an ui-specific value set by set_ui_config().
    pub async fn get_ui_config(&self, key: &str) -> Result<Option<String>> {
        ensure!(key.starts_with("ui."), "get_ui_config(): prefix missing.");
        self.sql.get_raw_config(key).await
    }
}

/// Returns a value for use in `Context::set_config_*()` for the given `bool`.
pub(crate) fn from_bool(val: bool) -> Option<&'static str> {
    Some(if val { "1" } else { "0" })
}

// Separate impl block for self address handling
impl Context {
    /// Determine whether the specified addr maps to the/a self addr.
    /// Returns `false` if no addresses are configured.
    pub(crate) async fn is_self_addr(&self, addr: &str) -> Result<bool> {
        Ok(self
            .get_config(Config::ConfiguredAddr)
            .await?
            .iter()
            .any(|a| addr_cmp(addr, a))
            || self
                .get_secondary_self_addrs()
                .await?
                .iter()
                .any(|a| addr_cmp(addr, a)))
    }

    /// Sets `primary_new` as the new primary self address and saves the old
    /// primary address (if exists) as a secondary address.
    ///
    /// This should only be used by test code and during configure.
    #[cfg(test)] // AEAP is disabled, but there are still tests for it
    pub(crate) async fn set_primary_self_addr(&self, primary_new: &str) -> Result<()> {
        self.quota.write().await.take();

        // add old primary address (if exists) to secondary addresses
        let mut secondary_addrs = self.get_all_self_addrs().await?;
        // never store a primary address also as a secondary
        secondary_addrs.retain(|a| !addr_cmp(a, primary_new));
        self.set_config_internal(
            Config::SecondaryAddrs,
            Some(secondary_addrs.join(" ").as_str()),
        )
        .await?;

        self.sql
            .set_raw_config(Config::ConfiguredAddr.as_ref(), Some(primary_new))
            .await?;
        self.emit_event(EventType::ConnectivityChanged);
        Ok(())
    }

    /// Returns all primary and secondary self addresses.
    pub(crate) async fn get_all_self_addrs(&self) -> Result<Vec<String>> {
        let primary_addrs = self.get_config(Config::ConfiguredAddr).await?.into_iter();
        let secondary_addrs = self.get_secondary_self_addrs().await?.into_iter();

        Ok(primary_addrs.chain(secondary_addrs).collect())
    }

    /// Returns all secondary self addresses.
    pub(crate) async fn get_secondary_self_addrs(&self) -> Result<Vec<String>> {
        let secondary_addrs = self
            .get_config(Config::SecondaryAddrs)
            .await?
            .unwrap_or_default();
        Ok(secondary_addrs
            .split_ascii_whitespace()
            .map(|s| s.to_string())
            .collect())
    }

    /// Returns the primary self address.
    /// Returns an error if no self addr is configured.
    pub async fn get_primary_self_addr(&self) -> Result<String> {
        self.get_config(Config::ConfiguredAddr)
            .await?
            .context("No self addr configured")
    }
}

/// Returns all available configuration keys concated together.
fn get_config_keys_string() -> String {
    let keys = Config::iter().fold(String::new(), |mut acc, key| {
        acc += key.as_ref();
        acc += " ";
        acc
    });

    format!(" {keys} ")
}

#[cfg(test)]
mod config_tests;
