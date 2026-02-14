//! Context module.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, OnceLock, Weak};
use std::time::Duration;

use anyhow::{Result, bail, ensure};
use async_channel::{self as channel, Receiver, Sender};
use ratelimit::Ratelimit;
use tokio::sync::{Mutex, Notify, RwLock};

use crate::chat::{ChatId, get_chat_cnt};
use crate::config::Config;
use crate::constants::{self, DC_BACKGROUND_FETCH_QUOTA_CHECK_RATELIMIT, DC_VERSION_STR};
use crate::contact::{Contact, ContactId};
use crate::debug_logging::DebugLogging;
use crate::events::{Event, EventEmitter, EventType, Events};
use crate::imap::{FolderMeaning, Imap, ServerMetadata};
use crate::key::self_fingerprint;
use crate::log::warn;
use crate::logged_debug_assert;
use crate::message::{self, MessageState, MsgId};
use crate::net::tls::TlsSessionStore;
use crate::peer_channels::Iroh;
use crate::push::PushSubscriber;
use crate::quota::QuotaInfo;
use crate::scheduler::{ConnectivityStore, SchedulerState, convert_folder_meaning};
use crate::sql::Sql;
use crate::stock_str::StockStrings;
use crate::timesmearing::SmearedTimestamp;
use crate::tools::{self, duration_to_str, time, time_elapsed};
use crate::transport::ConfiguredLoginParam;
use crate::{chatlist_events, stats};

pub use crate::scheduler::connectivity::Connectivity;

/// Builder for the [`Context`].
///
/// Many arguments to the [`Context`] are kind of optional and only needed to handle
/// multiple contexts, for which the [account manager](crate::accounts::Accounts) should be
/// used.  This builder makes creating a new context simpler, especially for the
/// standalone-context case.
///
/// # Examples
///
/// Creating a new database:
///
/// ```
/// # let rt = tokio::runtime::Runtime::new().unwrap();
/// # rt.block_on(async move {
/// use deltachat::context::ContextBuilder;
///
/// let dir = tempfile::tempdir().unwrap();
/// let context = ContextBuilder::new(dir.path().join("db"))
///      .open()
///      .await
///      .unwrap();
/// drop(context);
/// # });
/// ```
#[derive(Clone, Debug)]
pub struct ContextBuilder {
    dbfile: PathBuf,
    id: u32,
    events: Events,
    stock_strings: StockStrings,
    password: Option<String>,

    push_subscriber: Option<PushSubscriber>,
}

impl ContextBuilder {
    /// Create the builder using the given database file.
    ///
    /// The *dbfile* should be in a dedicated directory and this directory must exist.  The
    /// [`Context`] will create other files and folders in the same directory as the
    /// database file used.
    pub fn new(dbfile: PathBuf) -> Self {
        ContextBuilder {
            dbfile,
            id: rand::random(),
            events: Events::new(),
            stock_strings: StockStrings::new(),
            password: None,
            push_subscriber: None,
        }
    }

    /// Sets the context ID.
    ///
    /// This identifier is used e.g. in [`Event`]s to identify which [`Context`] an event
    /// belongs to.  The only real limit on it is that it should not conflict with any other
    /// [`Context`]s you currently have open.  So if you handle multiple [`Context`]s you
    /// may want to use this.
    ///
    /// Note that the [account manager](crate::accounts::Accounts) is designed to handle the
    /// common case for using multiple [`Context`] instances.
    pub fn with_id(mut self, id: u32) -> Self {
        self.id = id;
        self
    }

    /// Sets the event channel for this [`Context`].
    ///
    /// Mostly useful when using multiple [`Context`]s, this allows creating one [`Events`]
    /// channel and passing it to all [`Context`]s so all events are received on the same
    /// channel.
    ///
    /// Note that the [account manager](crate::accounts::Accounts) is designed to handle the
    /// common case for using multiple [`Context`] instances.
    pub fn with_events(mut self, events: Events) -> Self {
        self.events = events;
        self
    }

    /// Sets the [`StockStrings`] map to use for this [`Context`].
    ///
    /// This is useful in order to share the same translation strings in all [`Context`]s.
    /// The mapping may be empty when set, it will be populated by
    /// [`Context::set_stock_translation`] or [`Accounts::set_stock_translation`] calls.
    ///
    /// Note that the [account manager](crate::accounts::Accounts) is designed to handle the
    /// common case for using multiple [`Context`] instances.
    ///
    /// [`Accounts::set_stock_translation`]: crate::accounts::Accounts::set_stock_translation
    pub fn with_stock_strings(mut self, stock_strings: StockStrings) -> Self {
        self.stock_strings = stock_strings;
        self
    }

    /// Sets the password to unlock the database.
    /// Deprecated 2025-11:
    /// - Db encryption does nothing with blobs, so fs/disk encryption is recommended.
    /// - Isolation from other apps is needed anyway.
    ///
    /// If an encrypted database is used it must be opened with a password.  Setting a
    /// password on a new database will enable encryption.
    #[deprecated(since = "TBD")]
    pub fn with_password(mut self, password: String) -> Self {
        self.password = Some(password);
        self
    }

    /// Sets push subscriber.
    pub(crate) fn with_push_subscriber(mut self, push_subscriber: PushSubscriber) -> Self {
        self.push_subscriber = Some(push_subscriber);
        self
    }

    /// Builds the [`Context`] without opening it.
    pub async fn build(self) -> Result<Context> {
        let push_subscriber = self.push_subscriber.unwrap_or_default();
        let context = Context::new_closed(
            &self.dbfile,
            self.id,
            self.events,
            self.stock_strings,
            push_subscriber,
        )
        .await?;
        Ok(context)
    }

    /// Builds the [`Context`] and opens it.
    ///
    /// Returns error if context cannot be opened.
    pub async fn open(self) -> Result<Context> {
        let password = self.password.clone().unwrap_or_default();
        let context = self.build().await?;
        match context.open(password).await? {
            true => Ok(context),
            false => bail!("database could not be decrypted, incorrect or missing password"),
        }
    }
}

/// The context for a single DeltaChat account.
///
/// This contains all the state for a single DeltaChat account, including background tasks
/// running in Tokio to operate the account.  The [`Context`] can be cheaply cloned.
///
/// Each context, and thus each account, must be associated with an directory where all the
/// state is kept.  This state is also preserved between restarts.
///
/// To use multiple accounts it is best to look at the [accounts
/// manager][crate::accounts::Accounts] which handles storing multiple accounts in a single
/// directory structure and handles loading them all concurrently.
#[derive(Clone, Debug)]
pub struct Context {
    pub(crate) inner: Arc<InnerContext>,
}

impl Deref for Context {
    type Target = InnerContext;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// A weak reference to a [`Context`]
///
/// Can be used to obtain a [`Context`]. An existing weak reference does not prevent the corresponding [`Context`] from being dropped.
#[derive(Clone, Debug)]
pub(crate) struct WeakContext {
    inner: Weak<InnerContext>,
}

impl WeakContext {
    /// Returns the [`Context`] if it is still available.
    pub(crate) fn upgrade(&self) -> Result<Context> {
        let inner = self
            .inner
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("Inner struct has been dropped"))?;
        Ok(Context { inner })
    }
}

/// Actual context, expensive to clone.
#[derive(Debug)]
pub struct InnerContext {
    /// Blob directory path
    pub(crate) blobdir: PathBuf,
    pub(crate) sql: Sql,
    pub(crate) smeared_timestamp: SmearedTimestamp,
    /// The global "ongoing" process state.
    ///
    /// This is a global mutex-like state for operations which should be modal in the
    /// clients.
    running_state: RwLock<RunningState>,
    /// Mutex to avoid generating the key for the user more than once.
    pub(crate) generating_key_mutex: Mutex<()>,
    /// Mutex to enforce only a single running oauth2 is running.
    pub(crate) oauth2_mutex: Mutex<()>,
    /// Mutex to prevent a race condition when a "your pw is wrong" warning is sent, resulting in multiple messages being sent.
    pub(crate) wrong_pw_warning_mutex: Mutex<()>,
    pub(crate) translated_stockstrings: StockStrings,
    pub(crate) events: Events,

    pub(crate) scheduler: SchedulerState,
    pub(crate) ratelimit: RwLock<Ratelimit>,

    /// Recently loaded quota information for each trasnport, if any.
    /// If quota was never tried to load, then the transport doesn't have an entry in the BTreeMap.
    pub(crate) quota: RwLock<BTreeMap<u32, QuotaInfo>>,

    /// Notify about new messages.
    ///
    /// This causes [`Context::wait_next_msgs`] to wake up.
    pub(crate) new_msgs_notify: Notify,

    /// Server ID response if ID capability is supported
    /// and the server returned non-NIL on the inbox connection.
    /// <https://datatracker.ietf.org/doc/html/rfc2971>
    pub(crate) server_id: RwLock<Option<HashMap<String, String>>>,

    /// IMAP METADATA.
    pub(crate) metadata: RwLock<Option<ServerMetadata>>,

    /// ID for this `Context` in the current process.
    ///
    /// This allows for multiple `Context`s open in a single process where each context can
    /// be identified by this ID.
    pub(crate) id: u32,

    creation_time: tools::Time,

    /// The text of the last error logged and emitted as an event.
    /// If the ui wants to display an error after a failure,
    /// `last_error` should be used to avoid races with the event thread.
    pub(crate) last_error: parking_lot::RwLock<String>,

    /// It's not possible to emit migration errors as an event,
    /// because at the time of the migration, there is no event emitter yet.
    /// So, this holds the error that happened during migration, if any.
    /// This is necessary for the possibly-failible PGP migration,
    /// which happened 2025-05, and can be removed a few releases later.
    pub(crate) migration_error: parking_lot::RwLock<Option<String>>,

    /// If debug logging is enabled, this contains all necessary information
    ///
    /// Standard RwLock instead of [`tokio::sync::RwLock`] is used
    /// because the lock is used from synchronous [`Context::emit_event`].
    pub(crate) debug_logging: std::sync::RwLock<Option<DebugLogging>>,

    /// Push subscriber to store device token
    /// and register for heartbeat notifications.
    pub(crate) push_subscriber: PushSubscriber,

    /// True if account has subscribed to push notifications via IMAP.
    pub(crate) push_subscribed: AtomicBool,

    /// TLS session resumption cache.
    pub(crate) tls_session_store: TlsSessionStore,

    /// Iroh for realtime peer channels.
    pub(crate) iroh: Arc<RwLock<Option<Iroh>>>,

    /// The own fingerprint, if it was computed already.
    /// tokio::sync::OnceCell would be possible to use, but overkill for our usecase;
    /// the standard library's OnceLock is enough, and it's a lot smaller in memory.
    pub(crate) self_fingerprint: OnceLock<String>,

    /// `Connectivity` values for mailboxes, unordered. Used to compute the aggregate connectivity,
    /// see [`Context::get_connectivity()`].
    pub(crate) connectivities: parking_lot::Mutex<Vec<ConnectivityStore>>,

    #[expect(clippy::type_complexity)]
    /// Transforms the root of the cryptographic payload before encryption.
    pub(crate) pre_encrypt_mime_hook: parking_lot::Mutex<
        Option<
            for<'a> fn(
                &Context,
                mail_builder::mime::MimePart<'a>,
            ) -> mail_builder::mime::MimePart<'a>,
        >,
    >,
}

/// The state of ongoing process.
#[derive(Debug, Default)]
enum RunningState {
    /// Ongoing process is allocated.
    Running { cancel_sender: Sender<()> },

    /// Cancel signal has been sent, waiting for ongoing process to be freed.
    ShallStop { request: tools::Time },

    /// There is no ongoing process, a new one can be allocated.
    #[default]
    Stopped,
}

/// Return some info about deltachat-core
///
/// This contains information mostly about the library itself, the
/// actual keys and their values which will be present are not
/// guaranteed.  Calling [Context::get_info] also includes information
/// about the context on top of the information here.
#[expect(clippy::arithmetic_side_effects)]
pub fn get_info() -> BTreeMap<&'static str, String> {
    let mut res = BTreeMap::new();

    #[cfg(debug_assertions)]
    res.insert(
        "debug_assertions",
        "On - DO NOT RELEASE THIS BUILD".to_string(),
    );
    #[cfg(not(debug_assertions))]
    res.insert("debug_assertions", "Off".to_string());

    res.insert("deltachat_core_version", format!("v{DC_VERSION_STR}"));
    res.insert("sqlite_version", rusqlite::version().to_string());
    res.insert("arch", (std::mem::size_of::<usize>() * 8).to_string());
    res.insert("num_cpus", num_cpus::get().to_string());
    res.insert("level", "awesome".into());
    res
}

impl Context {
    /// Creates new context and opens the database.
    pub async fn new(
        dbfile: &Path,
        id: u32,
        events: Events,
        stock_strings: StockStrings,
    ) -> Result<Context> {
        let context =
            Self::new_closed(dbfile, id, events, stock_strings, Default::default()).await?;

        // Open the database if is not encrypted.
        if context.check_passphrase("".to_string()).await? {
            context.sql.open(&context, "".to_string()).await?;
        }
        Ok(context)
    }

    /// Creates new context without opening the database.
    pub async fn new_closed(
        dbfile: &Path,
        id: u32,
        events: Events,
        stockstrings: StockStrings,
        push_subscriber: PushSubscriber,
    ) -> Result<Context> {
        let mut blob_fname = OsString::new();
        blob_fname.push(dbfile.file_name().unwrap_or_default());
        blob_fname.push("-blobs");
        let blobdir = dbfile.with_file_name(blob_fname);
        if !blobdir.exists() {
            tokio::fs::create_dir_all(&blobdir).await?;
        }
        let context = Context::with_blobdir(
            dbfile.into(),
            blobdir,
            id,
            events,
            stockstrings,
            push_subscriber,
        )?;
        Ok(context)
    }

    /// Returns a weak reference to this [`Context`].
    pub(crate) fn get_weak_context(&self) -> WeakContext {
        WeakContext {
            inner: Arc::downgrade(&self.inner),
        }
    }

    /// Opens the database with the given passphrase.
    /// NB: Db encryption is deprecated, so `passphrase` should be empty normally. See
    /// [`ContextBuilder::with_password()`] for reasoning.
    ///
    /// Returns true if passphrase is correct, false is passphrase is not correct. Fails on other
    /// errors.
    #[deprecated(since = "TBD")]
    pub async fn open(&self, passphrase: String) -> Result<bool> {
        if self.sql.check_passphrase(passphrase.clone()).await? {
            self.sql.open(self, passphrase).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Changes encrypted database passphrase.
    /// Deprecated 2025-11, see [`ContextBuilder::with_password()`] for reasoning.
    pub async fn change_passphrase(&self, passphrase: String) -> Result<()> {
        self.sql.change_passphrase(passphrase).await?;
        Ok(())
    }

    /// Returns true if database is open.
    pub async fn is_open(&self) -> bool {
        self.sql.is_open().await
    }

    /// Tests the database passphrase.
    ///
    /// Returns true if passphrase is correct.
    ///
    /// Fails if database is already open.
    pub(crate) async fn check_passphrase(&self, passphrase: String) -> Result<bool> {
        self.sql.check_passphrase(passphrase).await
    }

    pub(crate) fn with_blobdir(
        dbfile: PathBuf,
        blobdir: PathBuf,
        id: u32,
        events: Events,
        stockstrings: StockStrings,
        push_subscriber: PushSubscriber,
    ) -> Result<Context> {
        ensure!(
            blobdir.is_dir(),
            "Blobdir does not exist: {}",
            blobdir.display()
        );

        let new_msgs_notify = Notify::new();
        // Notify once immediately to allow processing old messages
        // without starting I/O.
        new_msgs_notify.notify_one();

        let inner = InnerContext {
            id,
            blobdir,
            running_state: RwLock::new(Default::default()),
            sql: Sql::new(dbfile),
            smeared_timestamp: SmearedTimestamp::new(),
            generating_key_mutex: Mutex::new(()),
            oauth2_mutex: Mutex::new(()),
            wrong_pw_warning_mutex: Mutex::new(()),
            translated_stockstrings: stockstrings,
            events,
            scheduler: SchedulerState::new(),
            ratelimit: RwLock::new(Ratelimit::new(Duration::new(3, 0), 3.0)), // Allow at least 1 message every second + a burst of 3.
            quota: RwLock::new(BTreeMap::new()),
            new_msgs_notify,
            server_id: RwLock::new(None),
            metadata: RwLock::new(None),
            creation_time: tools::Time::now(),
            last_error: parking_lot::RwLock::new("".to_string()),
            migration_error: parking_lot::RwLock::new(None),
            debug_logging: std::sync::RwLock::new(None),
            push_subscriber,
            push_subscribed: AtomicBool::new(false),
            tls_session_store: TlsSessionStore::new(),
            iroh: Arc::new(RwLock::new(None)),
            self_fingerprint: OnceLock::new(),
            connectivities: parking_lot::Mutex::new(Vec::new()),
            pre_encrypt_mime_hook: None.into(),
        };

        let ctx = Context {
            inner: Arc::new(inner),
        };

        Ok(ctx)
    }

    /// Starts the IO scheduler.
    pub async fn start_io(&self) {
        if !self.is_configured().await.unwrap_or_default() {
            warn!(self, "can not start io on a context that is not configured");
            return;
        }

        // The next line is mainly for iOS:
        // iOS starts a separate process for receiving notifications and if the user concurrently
        // starts the app, the UI process opens the database but waits with calling start_io()
        // until the notifications process finishes.
        // Now, some configs may have changed, so, we need to invalidate the cache.
        self.sql.config_cache.write().await.clear();

        self.scheduler.start(self).await;
    }

    /// Stops the IO scheduler.
    pub async fn stop_io(&self) {
        self.scheduler.stop(self).await;
        if let Some(iroh) = self.iroh.write().await.take() {
            // Close all QUIC connections.

            // Spawn into a separate task,
            // because Iroh calls `wait_idle()` internally
            // and it may take time, especially if the network
            // has become unavailable.
            tokio::spawn(async move {
                // We do not log the error because we do not want the task
                // to hold the reference to Context.
                let _ = tokio::time::timeout(Duration::from_secs(60), iroh.close()).await;
            });
        }
    }

    /// Restarts the IO scheduler if it was running before
    /// when it is not running this is an no-op
    pub async fn restart_io_if_running(&self) {
        self.scheduler.restart(self).await;
    }

    /// Indicate that the network likely has come back.
    pub async fn maybe_network(&self) {
        if let Some(ref iroh) = *self.iroh.read().await {
            iroh.network_change().await;
        }
        self.scheduler.maybe_network().await;
    }

    /// Returns true if an account is on a chatmail server.
    pub async fn is_chatmail(&self) -> Result<bool> {
        self.get_config_bool(Config::IsChatmail).await
    }

    /// Returns maximum number of recipients the provider allows to send a single email to.
    pub(crate) async fn get_max_smtp_rcpt_to(&self) -> Result<usize> {
        let is_chatmail = self.is_chatmail().await?;
        let val = self
            .get_configured_provider()
            .await?
            .and_then(|provider| provider.opt.max_smtp_rcpt_to)
            .map_or_else(
                || match is_chatmail {
                    true => constants::DEFAULT_CHATMAIL_MAX_SMTP_RCPT_TO,
                    false => constants::DEFAULT_MAX_SMTP_RCPT_TO,
                },
                usize::from,
            );
        Ok(val)
    }

    /// Does a single round of fetching from IMAP and returns.
    ///
    /// Can be used even if I/O is currently stopped.
    /// If I/O is currently stopped, starts a new IMAP connection
    /// and fetches from Inbox and DeltaChat folders.
    pub async fn background_fetch(&self) -> Result<()> {
        if !(self.is_configured().await?) {
            return Ok(());
        }

        let address = self.get_primary_self_addr().await?;
        let time_start = tools::Time::now();
        info!(self, "background_fetch started fetching {address}.");

        if self.scheduler.is_running().await {
            self.scheduler.maybe_network().await;
            self.wait_for_all_work_done().await;
        } else {
            // Pause the scheduler to ensure another connection does not start
            // while we are fetching on a dedicated connection.
            let _pause_guard = self.scheduler.pause(self).await?;

            // Start a new dedicated connection.
            let mut connection = Imap::new_configured(self, channel::bounded(1).1).await?;
            let mut session = connection.prepare(self).await?;

            // Fetch IMAP folders.
            // Inbox is fetched before Mvbox because fetching from Inbox
            // may result in moving some messages to Mvbox.
            for folder_meaning in [FolderMeaning::Inbox, FolderMeaning::Mvbox] {
                if let Some((_folder_config, watch_folder)) =
                    convert_folder_meaning(self, folder_meaning).await?
                {
                    connection
                        .fetch_move_delete(self, &mut session, &watch_folder, folder_meaning)
                        .await?;
                }
            }

            // Update quota (to send warning if full) - but only check it once in a while.
            // note: For now this only checks quota of primary transport,
            // because background check only checks primary transport at the moment
            if self
                .quota_needs_update(
                    session.transport_id(),
                    DC_BACKGROUND_FETCH_QUOTA_CHECK_RATELIMIT,
                )
                .await
                && let Err(err) = self.update_recent_quota(&mut session).await
            {
                warn!(self, "Failed to update quota: {err:#}.");
            }
        }

        info!(
            self,
            "background_fetch done for {address} took {:?}.",
            time_elapsed(&time_start),
        );

        Ok(())
    }

    /// Returns a reference to the underlying SQL instance.
    ///
    /// Warning: this is only here for testing, not part of the public API.
    #[cfg(feature = "internals")]
    pub fn sql(&self) -> &Sql {
        &self.inner.sql
    }

    /// Returns database file path.
    pub fn get_dbfile(&self) -> &Path {
        self.sql.dbfile.as_path()
    }

    /// Returns blob directory path.
    pub fn get_blobdir(&self) -> &Path {
        self.blobdir.as_path()
    }

    /// Emits a single event.
    pub fn emit_event(&self, event: EventType) {
        {
            let lock = self.debug_logging.read().expect("RwLock is poisoned");
            if let Some(debug_logging) = &*lock {
                debug_logging.log_event(event.clone());
            }
        }
        self.events.emit(Event {
            id: self.id,
            typ: event,
        });
    }

    /// Emits a generic MsgsChanged event (without chat or message id)
    pub fn emit_msgs_changed_without_ids(&self) {
        self.emit_event(EventType::MsgsChanged {
            chat_id: ChatId::new(0),
            msg_id: MsgId::new(0),
        });
    }

    /// Emits a MsgsChanged event with specified chat and message ids
    ///
    /// If IDs are unset, [`Self::emit_msgs_changed_without_ids`]
    /// or [`Self::emit_msgs_changed_without_msg_id`] should be used
    /// instead of this function.
    pub fn emit_msgs_changed(&self, chat_id: ChatId, msg_id: MsgId) {
        logged_debug_assert!(
            self,
            !chat_id.is_unset(),
            "emit_msgs_changed: chat_id is unset."
        );
        logged_debug_assert!(
            self,
            !msg_id.is_unset(),
            "emit_msgs_changed: msg_id is unset."
        );

        self.emit_event(EventType::MsgsChanged { chat_id, msg_id });
        chatlist_events::emit_chatlist_changed(self);
        chatlist_events::emit_chatlist_item_changed(self, chat_id);
    }

    /// Emits a MsgsChanged event with specified chat and without message id.
    pub fn emit_msgs_changed_without_msg_id(&self, chat_id: ChatId) {
        logged_debug_assert!(
            self,
            !chat_id.is_unset(),
            "emit_msgs_changed_without_msg_id: chat_id is unset."
        );

        self.emit_event(EventType::MsgsChanged {
            chat_id,
            msg_id: MsgId::new(0),
        });
        chatlist_events::emit_chatlist_changed(self);
        chatlist_events::emit_chatlist_item_changed(self, chat_id);
    }

    /// Emits an IncomingMsg event with specified chat and message ids
    pub fn emit_incoming_msg(&self, chat_id: ChatId, msg_id: MsgId) {
        debug_assert!(!chat_id.is_unset());
        debug_assert!(!msg_id.is_unset());

        self.emit_event(EventType::IncomingMsg { chat_id, msg_id });
        chatlist_events::emit_chatlist_changed(self);
        chatlist_events::emit_chatlist_item_changed(self, chat_id);
    }

    /// Emits an LocationChanged event and a WebxdcStatusUpdate in case there is a maps integration
    pub async fn emit_location_changed(&self, contact_id: Option<ContactId>) -> Result<()> {
        self.emit_event(EventType::LocationChanged(contact_id));

        if let Some(msg_id) = self
            .get_config_parsed::<u32>(Config::WebxdcIntegration)
            .await?
        {
            self.emit_event(EventType::WebxdcStatusUpdate {
                msg_id: MsgId::new(msg_id),
                status_update_serial: Default::default(),
            })
        }

        Ok(())
    }

    /// Returns a receiver for emitted events.
    ///
    /// Multiple emitters can be created, but note that in this case each emitted event will
    /// only be received by one of the emitters, not by all of them.
    pub fn get_event_emitter(&self) -> EventEmitter {
        self.events.get_emitter()
    }

    /// Get the ID of this context.
    pub fn get_id(&self) -> u32 {
        self.id
    }

    // Ongoing process allocation/free/check

    /// Tries to acquire the global UI "ongoing" mutex.
    ///
    /// This is for modal operations during which no other user actions are allowed.  Only
    /// one such operation is allowed at any given time.
    ///
    /// The return value is a cancel token, which will release the ongoing mutex when
    /// dropped.
    pub(crate) async fn alloc_ongoing(&self) -> Result<Receiver<()>> {
        let mut s = self.running_state.write().await;
        ensure!(
            matches!(*s, RunningState::Stopped),
            "There is already another ongoing process running."
        );

        let (sender, receiver) = channel::bounded(1);
        *s = RunningState::Running {
            cancel_sender: sender,
        };

        Ok(receiver)
    }

    pub(crate) async fn free_ongoing(&self) {
        let mut s = self.running_state.write().await;
        if let RunningState::ShallStop { request } = *s {
            info!(self, "Ongoing stopped in {:?}", time_elapsed(&request));
        }
        *s = RunningState::Stopped;
    }

    /// Signal an ongoing process to stop.
    pub async fn stop_ongoing(&self) {
        let mut s = self.running_state.write().await;
        match &*s {
            RunningState::Running { cancel_sender } => {
                if let Err(err) = cancel_sender.send(()).await {
                    warn!(self, "could not cancel ongoing: {:#}", err);
                }
                info!(self, "Signaling the ongoing process to stop ASAP.",);
                *s = RunningState::ShallStop {
                    request: tools::Time::now(),
                };
            }
            RunningState::ShallStop { .. } | RunningState::Stopped => {
                info!(self, "No ongoing process to stop.",);
            }
        }
    }

    #[allow(unused)]
    pub(crate) async fn shall_stop_ongoing(&self) -> bool {
        match &*self.running_state.read().await {
            RunningState::Running { .. } => false,
            RunningState::ShallStop { .. } | RunningState::Stopped => true,
        }
    }

    /*******************************************************************************
     * UI chat/message related API
     ******************************************************************************/

    /// Returns information about the context as key-value pairs.
    pub async fn get_info(&self) -> Result<BTreeMap<&'static str, String>> {
        let secondary_addrs = self.get_secondary_self_addrs().await?.join(", ");
        let all_transports: Vec<String> = ConfiguredLoginParam::load_all(self)
            .await?
            .into_iter()
            .map(|(transport_id, param)| format!("{transport_id}: {param}"))
            .collect();
        let all_transports = if all_transports.is_empty() {
            "Not configured".to_string()
        } else {
            all_transports.join(",")
        };
        let chats = get_chat_cnt(self).await?;
        let unblocked_msgs = message::get_unblocked_msg_cnt(self).await;
        let request_msgs = message::get_request_msg_cnt(self).await;
        let contacts = Contact::get_real_cnt(self).await?;
        let proxy_enabled = self.get_config_int(Config::ProxyEnabled).await?;
        let dbversion = self
            .sql
            .get_raw_config_int("dbversion")
            .await?
            .unwrap_or_default();
        let journal_mode = self
            .sql
            .query_get_value("PRAGMA journal_mode;", ())
            .await?
            .unwrap_or_else(|| "unknown".to_string());
        let mdns_enabled = self.get_config_int(Config::MdnsEnabled).await?;
        let bcc_self = self.get_config_int(Config::BccSelf).await?;
        let sync_msgs = self.get_config_int(Config::SyncMsgs).await?;
        let disable_idle = self.get_config_bool(Config::DisableIdle).await?;

        let prv_key_cnt = self.sql.count("SELECT COUNT(*) FROM keypairs;", ()).await?;

        let pub_key_cnt = self
            .sql
            .count("SELECT COUNT(*) FROM public_keys;", ())
            .await?;
        let fingerprint_str = match self_fingerprint(self).await {
            Ok(fp) => fp.to_string(),
            Err(err) => format!("<key failure: {err}>"),
        };

        let mvbox_move = self.get_config_int(Config::MvboxMove).await?;
        let only_fetch_mvbox = self.get_config_int(Config::OnlyFetchMvbox).await?;
        let folders_configured = self
            .sql
            .get_raw_config_int(constants::DC_FOLDERS_CONFIGURED_KEY)
            .await?
            .unwrap_or_default();

        let configured_inbox_folder = self
            .get_config(Config::ConfiguredInboxFolder)
            .await?
            .unwrap_or_else(|| "<unset>".to_string());
        let configured_mvbox_folder = self
            .get_config(Config::ConfiguredMvboxFolder)
            .await?
            .unwrap_or_else(|| "<unset>".to_string());

        let mut res = get_info();

        // insert values
        res.insert("bot", self.get_config_int(Config::Bot).await?.to_string());
        res.insert("number_of_chats", chats.to_string());
        res.insert("number_of_chat_messages", unblocked_msgs.to_string());
        res.insert("messages_in_contact_requests", request_msgs.to_string());
        res.insert("number_of_contacts", contacts.to_string());
        res.insert("database_dir", self.get_dbfile().display().to_string());
        res.insert("database_version", dbversion.to_string());
        res.insert(
            "database_encrypted",
            self.sql
                .is_encrypted()
                .await
                .map_or_else(|| "closed".to_string(), |b| b.to_string()),
        );
        res.insert("journal_mode", journal_mode);
        res.insert("blobdir", self.get_blobdir().display().to_string());
        res.insert(
            "selfavatar",
            self.get_config(Config::Selfavatar)
                .await?
                .unwrap_or_else(|| "<unset>".to_string()),
        );
        res.insert("proxy_enabled", proxy_enabled.to_string());
        res.insert("used_transport_settings", all_transports);

        if let Some(server_id) = &*self.server_id.read().await {
            res.insert("imap_server_id", format!("{server_id:?}"));
        }

        res.insert("is_chatmail", self.is_chatmail().await?.to_string());
        res.insert(
            "fix_is_chatmail",
            self.get_config_bool(Config::FixIsChatmail)
                .await?
                .to_string(),
        );
        res.insert(
            "is_muted",
            self.get_config_bool(Config::IsMuted).await?.to_string(),
        );
        res.insert(
            "private_tag",
            self.get_config(Config::PrivateTag)
                .await?
                .unwrap_or_else(|| "<unset>".to_string()),
        );

        if let Some(metadata) = &*self.metadata.read().await {
            if let Some(comment) = &metadata.comment {
                res.insert("imap_server_comment", format!("{comment:?}"));
            }

            if let Some(admin) = &metadata.admin {
                res.insert("imap_server_admin", format!("{admin:?}"));
            }
        }

        res.insert("secondary_addrs", secondary_addrs);
        res.insert(
            "show_emails",
            self.get_config_int(Config::ShowEmails).await?.to_string(),
        );
        res.insert(
            "who_can_call_me",
            self.get_config_int(Config::WhoCanCallMe).await?.to_string(),
        );
        res.insert(
            "download_limit",
            self.get_config_int(Config::DownloadLimit)
                .await?
                .to_string(),
        );
        res.insert("mvbox_move", mvbox_move.to_string());
        res.insert("only_fetch_mvbox", only_fetch_mvbox.to_string());
        res.insert(
            constants::DC_FOLDERS_CONFIGURED_KEY,
            folders_configured.to_string(),
        );
        res.insert("configured_inbox_folder", configured_inbox_folder);
        res.insert("configured_mvbox_folder", configured_mvbox_folder);
        res.insert("mdns_enabled", mdns_enabled.to_string());
        res.insert("bcc_self", bcc_self.to_string());
        res.insert("sync_msgs", sync_msgs.to_string());
        res.insert("disable_idle", disable_idle.to_string());
        res.insert("private_key_count", prv_key_cnt.to_string());
        res.insert("public_key_count", pub_key_cnt.to_string());
        res.insert("fingerprint", fingerprint_str);
        res.insert(
            "media_quality",
            self.get_config_int(Config::MediaQuality).await?.to_string(),
        );
        res.insert(
            "delete_device_after",
            self.get_config_int(Config::DeleteDeviceAfter)
                .await?
                .to_string(),
        );
        res.insert(
            "delete_server_after",
            self.get_config_int(Config::DeleteServerAfter)
                .await?
                .to_string(),
        );
        res.insert(
            "last_housekeeping",
            self.get_config_int(Config::LastHousekeeping)
                .await?
                .to_string(),
        );
        res.insert(
            "last_cant_decrypt_outgoing_msgs",
            self.get_config_int(Config::LastCantDecryptOutgoingMsgs)
                .await?
                .to_string(),
        );
        res.insert(
            "quota_exceeding",
            self.get_config_int(Config::QuotaExceeding)
                .await?
                .to_string(),
        );
        res.insert(
            "authserv_id_candidates",
            self.get_config(Config::AuthservIdCandidates)
                .await?
                .unwrap_or_default(),
        );
        res.insert(
            "sign_unencrypted",
            self.get_config_int(Config::SignUnencrypted)
                .await?
                .to_string(),
        );
        res.insert(
            "debug_logging",
            self.get_config_int(Config::DebugLogging).await?.to_string(),
        );
        res.insert(
            "last_msg_id",
            self.get_config_int(Config::LastMsgId).await?.to_string(),
        );
        res.insert(
            "gossip_period",
            self.get_config_int(Config::GossipPeriod).await?.to_string(),
        );
        res.insert(
            "webxdc_realtime_enabled",
            self.get_config_bool(Config::WebxdcRealtimeEnabled)
                .await?
                .to_string(),
        );
        res.insert(
            "donation_request_next_check",
            self.get_config_i64(Config::DonationRequestNextCheck)
                .await?
                .to_string(),
        );
        res.insert(
            "first_key_contacts_msg_id",
            self.sql
                .get_raw_config("first_key_contacts_msg_id")
                .await?
                .unwrap_or_default(),
        );
        res.insert(
            "stats_id",
            self.get_config(Config::StatsId)
                .await?
                .unwrap_or_else(|| "<unset>".to_string()),
        );
        res.insert(
            "stats_sending",
            stats::should_send_stats(self).await?.to_string(),
        );
        res.insert(
            "stats_last_sent",
            self.get_config_i64(Config::StatsLastSent)
                .await?
                .to_string(),
        );
        res.insert(
            "test_hooks",
            self.sql
                .get_raw_config("test_hooks")
                .await?
                .unwrap_or_default(),
        );
        res.insert(
            "std_header_protection_composing",
            self.sql
                .get_raw_config("std_header_protection_composing")
                .await?
                .unwrap_or_default(),
        );
        res.insert(
            "team_profile",
            self.get_config_bool(Config::TeamProfile).await?.to_string(),
        );

        let elapsed = time_elapsed(&self.creation_time);
        res.insert("uptime", duration_to_str(elapsed));

        Ok(res)
    }

    /// Get a list of fresh, unmuted messages in unblocked chats.
    ///
    /// The list starts with the most recent message
    /// and is typically used to show notifications.
    /// Moreover, the number of returned messages
    /// can be used for a badge counter on the app icon.
    pub async fn get_fresh_msgs(&self) -> Result<Vec<MsgId>> {
        let list = self
            .sql
            .query_map_vec(
                "SELECT m.id
FROM msgs m
LEFT JOIN contacts ct
    ON m.from_id=ct.id
LEFT JOIN chats c
    ON m.chat_id=c.id
WHERE m.state=?
AND m.hidden=0
AND m.chat_id>9
AND ct.blocked=0
AND c.blocked=0
AND NOT(c.muted_until=-1 OR c.muted_until>?)
ORDER BY m.timestamp DESC,m.id DESC",
                (MessageState::InFresh, time()),
                |row| {
                    let msg_id: MsgId = row.get(0)?;
                    Ok(msg_id)
                },
            )
            .await?;
        Ok(list)
    }

    /// Returns a list of messages with database ID higher than requested.
    ///
    /// Blocked contacts and chats are excluded,
    /// but self-sent messages and contact requests are included in the results.
    pub async fn get_next_msgs(&self) -> Result<Vec<MsgId>> {
        let last_msg_id = match self.get_config(Config::LastMsgId).await? {
            Some(s) => MsgId::new(s.parse()?),
            None => {
                // If `last_msg_id` is not set yet,
                // subtract 1 from the last id,
                // so a single message is returned and can
                // be marked as seen.
                self.sql
                    .query_row(
                        "SELECT IFNULL((SELECT MAX(id) - 1 FROM msgs), 0)",
                        (),
                        |row| {
                            let msg_id: MsgId = row.get(0)?;
                            Ok(msg_id)
                        },
                    )
                    .await?
            }
        };

        let list = self
            .sql
            .query_map_vec(
                "SELECT m.id
                     FROM msgs m
                     LEFT JOIN contacts ct
                            ON m.from_id=ct.id
                     LEFT JOIN chats c
                            ON m.chat_id=c.id
                     WHERE m.id>?
                       AND m.hidden=0
                       AND m.chat_id>9
                       AND ct.blocked=0
                       AND c.blocked!=1
                     ORDER BY m.id ASC",
                (
                    last_msg_id.to_u32(), // Explicitly convert to u32 because 0 is allowed.
                ),
                |row| {
                    let msg_id: MsgId = row.get(0)?;
                    Ok(msg_id)
                },
            )
            .await?;
        Ok(list)
    }

    /// Returns a list of messages with database ID higher than last marked as seen.
    ///
    /// This function is supposed to be used by bot to request messages
    /// that are not processed yet.
    ///
    /// Waits for notification and returns a result.
    /// Note that the result may be empty if the message is deleted
    /// shortly after notification or notification is manually triggered
    /// to interrupt waiting.
    /// Notification may be manually triggered by calling [`Self::stop_io`].
    pub async fn wait_next_msgs(&self) -> Result<Vec<MsgId>> {
        self.new_msgs_notify.notified().await;
        let list = self.get_next_msgs().await?;
        Ok(list)
    }

    /// Searches for messages containing the query string case-insensitively.
    ///
    /// If `chat_id` is provided this searches only for messages in this chat, if `chat_id`
    /// is `None` this searches messages from all chats.
    ///
    /// NB: Wrt the search in long messages which are shown truncated with the "Show Full Message…"
    /// button, we only look at the first several kilobytes. Let's not fix this -- one can send a
    /// dictionary in the message that matches any reasonable search request, but the user won't see
    /// the match because they should tap on "Show Full Message…" for that. Probably such messages
    /// would only clutter search results.
    pub async fn search_msgs(&self, chat_id: Option<ChatId>, query: &str) -> Result<Vec<MsgId>> {
        let real_query = query.trim().to_lowercase();
        if real_query.is_empty() {
            return Ok(Vec::new());
        }
        let str_like_in_text = format!("%{real_query}%");

        let list = if let Some(chat_id) = chat_id {
            self.sql
                .query_map_vec(
                    "SELECT m.id AS id
                 FROM msgs m
                 LEFT JOIN contacts ct
                        ON m.from_id=ct.id
                 WHERE m.chat_id=?
                   AND m.hidden=0
                   AND ct.blocked=0
                   AND IFNULL(txt_normalized, txt) LIKE ?
                 ORDER BY m.timestamp,m.id;",
                    (chat_id, str_like_in_text),
                    |row| {
                        let msg_id: MsgId = row.get("id")?;
                        Ok(msg_id)
                    },
                )
                .await?
        } else {
            // For performance reasons results are sorted only by `id`, that is in the order of
            // message reception.
            //
            // Unlike chat view, sorting by `timestamp` is not necessary but slows down the query by
            // ~25% according to benchmarks.
            //
            // To speed up incremental search, where queries for few characters usually return lots
            // of unwanted results that are discarded moments later, we added `LIMIT 1000`.
            // According to some tests, this limit speeds up eg. 2 character searches by factor 10.
            // The limit is documented and UI may add a hint when getting 1000 results.
            self.sql
                .query_map_vec(
                    "SELECT m.id AS id
                 FROM msgs m
                 LEFT JOIN contacts ct
                        ON m.from_id=ct.id
                 LEFT JOIN chats c
                        ON m.chat_id=c.id
                 WHERE m.chat_id>9
                   AND m.hidden=0
                   AND c.blocked!=1
                   AND ct.blocked=0
                   AND IFNULL(txt_normalized, txt) LIKE ?
                 ORDER BY m.id DESC LIMIT 1000",
                    (str_like_in_text,),
                    |row| {
                        let msg_id: MsgId = row.get("id")?;
                        Ok(msg_id)
                    },
                )
                .await?
        };

        Ok(list)
    }

    /// Returns true if given folder name is the name of the "DeltaChat" folder.
    pub async fn is_mvbox(&self, folder_name: &str) -> Result<bool> {
        let mvbox = self.get_config(Config::ConfiguredMvboxFolder).await?;
        Ok(mvbox.as_deref() == Some(folder_name))
    }

    pub(crate) fn derive_blobdir(dbfile: &Path) -> PathBuf {
        let mut blob_fname = OsString::new();
        blob_fname.push(dbfile.file_name().unwrap_or_default());
        blob_fname.push("-blobs");
        dbfile.with_file_name(blob_fname)
    }

    pub(crate) fn derive_walfile(dbfile: &Path) -> PathBuf {
        let mut wal_fname = OsString::new();
        wal_fname.push(dbfile.file_name().unwrap_or_default());
        wal_fname.push("-wal");
        dbfile.with_file_name(wal_fname)
    }
}

#[cfg(test)]
mod context_tests;
