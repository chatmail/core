//! # Account manager module.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail, ensure};
use async_channel::{self, Receiver, Sender};
use futures::FutureExt as _;
use futures_lite::FutureExt as _;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::task::{JoinHandle, JoinSet};
use uuid::Uuid;

#[cfg(not(target_os = "ios"))]
use tokio::sync::oneshot;
#[cfg(not(target_os = "ios"))]
use tokio::time::{Duration, sleep};

use crate::context::{Context, ContextBuilder};
use crate::events::{Event, EventEmitter, EventType, Events};
use crate::log::warn;
use crate::push::PushSubscriber;
use crate::stock_str::StockStrings;

/// Account manager, that can handle multiple accounts in a single place.
#[derive(Debug)]
pub struct Accounts {
    dir: PathBuf,
    config: Config,
    /// Map from account ID to the account.
    accounts: BTreeMap<u32, Context>,

    /// Event channel to emit account manager errors.
    events: Events,

    /// Stock string translations shared by all created contexts.
    ///
    /// This way changing a translation for one context automatically
    /// changes it for all other contexts.
    pub(crate) stockstrings: StockStrings,

    /// Push notification subscriber shared between accounts.
    push_subscriber: PushSubscriber,

    /// Channel sender to cancel ongoing background_fetch().
    ///
    /// If background_fetch() is not running, this is `None`.
    /// New background_fetch() should not be started if this
    /// contains `Some`.
    background_fetch_interrupt_sender: Arc<parking_lot::Mutex<Option<Sender<()>>>>,
}

impl Accounts {
    /// Loads or creates an accounts folder at the given `dir`.
    pub async fn new(dir: PathBuf, writable: bool) -> Result<Self> {
        if writable && !dir.exists() {
            Accounts::create(&dir).await?;
        }
        let events = Events::new();
        Accounts::open(events, dir, writable).await
    }

    /// Loads or creates an accounts folder at the given `dir`.
    /// Uses an existing events channel.
    pub async fn new_with_events(dir: PathBuf, writable: bool, events: Events) -> Result<Self> {
        if writable && !dir.exists() {
            Accounts::create(&dir).await?;
        }

        Accounts::open(events, dir, writable).await
    }

    /// Get the ID used to log events.
    ///
    /// Account manager logs events with ID 0
    /// which is not used by any accounts.
    fn get_id(&self) -> u32 {
        0
    }

    /// Creates a new default structure.
    async fn create(dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)
            .await
            .context("failed to create folder")?;

        Config::new(dir).await?;

        Ok(())
    }

    /// Opens an existing accounts structure. Will error if the folder doesn't exist,
    /// no account exists and no config exists.
    async fn open(events: Events, dir: PathBuf, writable: bool) -> Result<Self> {
        ensure!(dir.exists(), "directory does not exist");

        let config_file = dir.join(CONFIG_NAME);
        ensure!(config_file.exists(), "{config_file:?} does not exist");

        let config = Config::from_file(config_file, writable).await?;

        let stockstrings = StockStrings::new();
        let push_subscriber = PushSubscriber::new();
        let accounts = config
            .load_accounts(&events, &stockstrings, push_subscriber.clone(), &dir)
            .await
            .context("failed to load accounts")?;

        Ok(Self {
            dir,
            config,
            accounts,
            events,
            stockstrings,
            push_subscriber,
            background_fetch_interrupt_sender: Default::default(),
        })
    }

    /// Returns an account by its `id`:
    pub fn get_account(&self, id: u32) -> Option<Context> {
        self.accounts.get(&id).cloned()
    }

    /// Returns the currently selected account.
    pub fn get_selected_account(&self) -> Option<Context> {
        let id = self.config.get_selected_account();
        self.accounts.get(&id).cloned()
    }

    /// Returns the currently selected account's id or None if no account is selected.
    pub fn get_selected_account_id(&self) -> Option<u32> {
        match self.config.get_selected_account() {
            0 => None,
            id => Some(id),
        }
    }

    /// Selects the given account.
    pub async fn select_account(&mut self, id: u32) -> Result<()> {
        self.config.select_account(id).await?;

        Ok(())
    }

    /// Adds a new account and opens it.
    ///
    /// Returns account ID.
    pub async fn add_account(&mut self) -> Result<u32> {
        let account_config = self.config.new_account().await?;
        let dbfile = account_config.dbfile(&self.dir);

        let ctx = ContextBuilder::new(dbfile)
            .with_id(account_config.id)
            .with_events(self.events.clone())
            .with_stock_strings(self.stockstrings.clone())
            .with_push_subscriber(self.push_subscriber.clone())
            .build()
            .await?;
        // Try to open without a passphrase,
        // but do not return an error if account is passphare-protected.
        ctx.open("".to_string()).await?;

        self.accounts.insert(account_config.id, ctx);
        self.emit_event(EventType::AccountsChanged);

        Ok(account_config.id)
    }

    /// Adds a new closed account.
    pub async fn add_closed_account(&mut self) -> Result<u32> {
        let account_config = self.config.new_account().await?;
        let dbfile = account_config.dbfile(&self.dir);

        let ctx = ContextBuilder::new(dbfile)
            .with_id(account_config.id)
            .with_events(self.events.clone())
            .with_stock_strings(self.stockstrings.clone())
            .with_push_subscriber(self.push_subscriber.clone())
            .build()
            .await?;
        self.accounts.insert(account_config.id, ctx);
        self.emit_event(EventType::AccountsChanged);

        Ok(account_config.id)
    }

    /// Removes an account.
    pub async fn remove_account(&mut self, id: u32) -> Result<()> {
        let ctx = self
            .accounts
            .remove(&id)
            .with_context(|| format!("no account with id {id}"))?;
        ctx.stop_io().await;

        // Explicitly close the database
        // to make sure the database file is closed
        // and can be removed on Windows.
        // If some spawned task tries to use the database afterwards,
        // it will fail.
        //
        // Previously `stop_io()` aborted the tasks without awaiting them
        // and this resulted in keeping `Context` clones inside
        // `Future`s that were not dropped. This bug is fixed now,
        // but explicitly closing the database ensures that file is freed
        // even if not all `Context` references are dropped.
        ctx.sql.close().await;
        drop(ctx);

        if let Some(cfg) = self.config.get_account(id) {
            let account_path = self.dir.join(cfg.dir);

            try_many_times(|| fs::remove_dir_all(&account_path))
                .await
                .context("failed to remove account data")?;
        }
        self.config.remove_account(id).await?;
        self.emit_event(EventType::AccountsChanged);

        Ok(())
    }

    /// Migrates an existing account into this structure.
    ///
    /// Returns the ID of new account.
    pub async fn migrate_account(&mut self, dbfile: PathBuf) -> Result<u32> {
        let blobdir = Context::derive_blobdir(&dbfile);
        let walfile = Context::derive_walfile(&dbfile);

        ensure!(dbfile.exists(), "no database found: {}", dbfile.display());
        ensure!(blobdir.exists(), "no blobdir found: {}", blobdir.display());

        let old_id = self.config.get_selected_account();

        // create new account
        let account_config = self
            .config
            .new_account()
            .await
            .context("failed to create new account")?;

        let new_dbfile = account_config.dbfile(&self.dir);
        let new_blobdir = Context::derive_blobdir(&new_dbfile);
        let new_walfile = Context::derive_walfile(&new_dbfile);

        let res = {
            fs::create_dir_all(self.dir.join(&account_config.dir))
                .await
                .context("failed to create dir")?;
            try_many_times(|| fs::rename(&dbfile, &new_dbfile))
                .await
                .context("failed to rename dbfile")?;
            try_many_times(|| fs::rename(&blobdir, &new_blobdir))
                .await
                .context("failed to rename blobdir")?;
            if walfile.exists() {
                fs::rename(&walfile, &new_walfile)
                    .await
                    .context("failed to rename walfile")?;
            }
            Ok(())
        };

        match res {
            Ok(_) => {
                let ctx = Context::new(
                    &new_dbfile,
                    account_config.id,
                    self.events.clone(),
                    self.stockstrings.clone(),
                )
                .await?;
                self.accounts.insert(account_config.id, ctx);
                Ok(account_config.id)
            }
            Err(err) => {
                let account_path = std::path::PathBuf::from(&account_config.dir);
                try_many_times(|| fs::remove_dir_all(&account_path))
                    .await
                    .context("failed to remove account data")?;
                self.config.remove_account(account_config.id).await?;

                // set selection back
                self.select_account(old_id).await?;

                Err(err)
            }
        }
    }

    /// Gets a list of all account ids in the user-configured order.
    pub fn get_all(&self) -> Vec<u32> {
        let mut ordered_ids = Vec::new();
        let mut all_ids: BTreeSet<u32> = self.accounts.keys().copied().collect();

        // First, add accounts in the configured order
        for &id in &self.config.inner.accounts_order {
            if all_ids.remove(&id) {
                ordered_ids.push(id);
            }
        }

        // Then add any accounts not in the order list (newly added accounts)
        for id in all_ids {
            ordered_ids.push(id);
        }

        ordered_ids
    }

    /// Sets the order of accounts.
    ///
    /// The provided list should contain all account IDs in the desired order.
    /// If an account ID is missing from the list, it will be appended at the end.
    /// If the list contains non-existent account IDs, they will be ignored.
    pub async fn set_accounts_order(&mut self, order: Vec<u32>) -> Result<()> {
        let existing_ids: BTreeSet<u32> = self.accounts.keys().copied().collect();

        // Filter out non-existent account IDs
        let mut filtered_order: Vec<u32> = order
            .into_iter()
            .filter(|id| existing_ids.contains(id))
            .collect();

        // Add any missing account IDs at the end
        for &id in &existing_ids {
            if !filtered_order.contains(&id) {
                filtered_order.push(id);
            }
        }

        self.config.inner.accounts_order = filtered_order;
        self.config.sync().await?;
        self.emit_event(EventType::AccountsChanged);
        Ok(())
    }

    /// Starts background tasks such as IMAP and SMTP loops for all accounts.
    pub async fn start_io(&mut self) {
        for account in self.accounts.values_mut() {
            account.start_io().await;
        }
    }

    /// Stops background tasks for all accounts.
    pub async fn stop_io(&self) {
        // Sending an event here wakes up event loop even
        // if there are no accounts.
        info!(self, "Stopping IO for all accounts.");
        for account in self.accounts.values() {
            account.stop_io().await;
        }
    }

    /// Notifies all accounts that the network may have become available.
    pub async fn maybe_network(&self) {
        for account in self.accounts.values() {
            account.scheduler.maybe_network().await;
        }
    }

    /// Notifies all accounts that the network connection may have been lost.
    pub async fn maybe_network_lost(&self) {
        for account in self.accounts.values() {
            account.scheduler.maybe_network_lost(account).await;
        }
    }

    /// Performs a background fetch for all accounts in parallel.
    ///
    /// This is an auxiliary function and not part of public API.
    /// Use [Accounts::background_fetch] instead.
    ///
    /// This function is cancellation-safe.
    /// It is intended to be cancellable,
    /// either because of the timeout or because background
    /// fetch was explicitly cancelled.
    async fn background_fetch_no_timeout(accounts: Vec<Context>, events: Events) {
        let n_accounts = accounts.len();
        events.emit(Event {
            id: 0,
            typ: EventType::Info(format!(
                "Starting background fetch for {n_accounts} accounts."
            )),
        });
        ::tracing::event!(
            ::tracing::Level::INFO,
            account_id = 0,
            "Starting background fetch for {n_accounts} accounts."
        );
        let mut set = JoinSet::new();
        for account in accounts {
            set.spawn(async move {
                if let Err(error) = account.background_fetch().await {
                    warn!(account, "{error:#}");
                }
            });
        }
        set.join_all().await;
        events.emit(Event {
            id: 0,
            typ: EventType::Info(format!(
                "Finished background fetch for {n_accounts} accounts."
            )),
        });
        ::tracing::event!(
            ::tracing::Level::INFO,
            account_id = 0,
            "Finished background fetch for {n_accounts} accounts."
        );
    }

    /// Auxiliary function for [Accounts::background_fetch].
    ///
    /// Runs `background_fetch` until it finishes
    /// or until the timeout.
    ///
    /// Produces `AccountsBackgroundFetchDone` event in every case
    /// and clears [`Self::background_fetch_interrupt_sender`]
    /// so a new background fetch can be started.
    ///
    /// This function is not cancellation-safe.
    /// Cancelling it before it returns may result
    /// in not being able to run any new background fetch
    /// if interrupt sender was not cleared.
    async fn background_fetch_with_timeout(
        accounts: Vec<Context>,
        events: Events,
        timeout: std::time::Duration,
        interrupt_sender: Arc<parking_lot::Mutex<Option<Sender<()>>>>,
        interrupt_receiver: Option<Receiver<()>>,
    ) {
        let Some(interrupt_receiver) = interrupt_receiver else {
            // Nothing to do if we got no interrupt receiver.
            return;
        };
        if let Err(_err) = tokio::time::timeout(
            timeout,
            Self::background_fetch_no_timeout(accounts, events.clone())
                .race(interrupt_receiver.recv().map(|_| ())),
        )
        .await
        {
            events.emit(Event {
                id: 0,
                typ: EventType::Warning("Background fetch timed out.".to_string()),
            });
            ::tracing::event!(
                ::tracing::Level::WARN,
                account_id = 0,
                "Background fetch timed out."
            );
        }
        events.emit(Event {
            id: 0,
            typ: EventType::AccountsBackgroundFetchDone,
        });
        (*interrupt_sender.lock()) = None;
    }

    /// Performs a background fetch for all accounts in parallel with a timeout.
    ///
    /// Ongoing background fetch can also be cancelled manually
    /// by calling `stop_background_fetch()`, in which case it will
    /// return immediately even before the timeout expiration
    /// or finishing fetching.
    ///
    /// The `AccountsBackgroundFetchDone` event is emitted at the end,
    /// process all events until you get this one and you can safely return to the background
    /// without forgetting to create notifications caused by timing race conditions.
    ///
    /// Returns a future that resolves when background fetch is done,
    /// but does not capture `&self`.
    pub fn background_fetch(
        &self,
        timeout: std::time::Duration,
    ) -> impl Future<Output = ()> + use<> {
        let accounts: Vec<Context> = self.accounts.values().cloned().collect();
        let events = self.events.clone();
        let (sender, receiver) = async_channel::bounded(1);
        let receiver = {
            let mut lock = self.background_fetch_interrupt_sender.lock();
            if (*lock).is_some() {
                // Another background_fetch() is already running,
                // return immeidately.
                None
            } else {
                *lock = Some(sender);
                Some(receiver)
            }
        };
        Self::background_fetch_with_timeout(
            accounts,
            events,
            timeout,
            self.background_fetch_interrupt_sender.clone(),
            receiver,
        )
    }

    /// Interrupts ongoing background_fetch() call,
    /// making it return early.
    ///
    /// This method allows to cancel background_fetch() early,
    /// e.g. on Android, when `Service.onTimeout` is called.
    ///
    /// If there is no ongoing background_fetch(), does nothing.
    pub fn stop_background_fetch(&self) {
        let mut lock = self.background_fetch_interrupt_sender.lock();
        if let Some(sender) = lock.take() {
            sender.try_send(()).ok();
        }
    }

    /// Emits a single event.
    pub fn emit_event(&self, event: EventType) {
        self.events.emit(Event { id: 0, typ: event })
    }

    /// Returns event emitter.
    pub fn get_event_emitter(&self) -> EventEmitter {
        self.events.get_emitter()
    }

    /// Sets notification token for Apple Push Notification service.
    pub async fn set_push_device_token(&self, token: &str) -> Result<()> {
        self.push_subscriber.set_device_token(token).await;
        Ok(())
    }
}

/// Configuration file name.
const CONFIG_NAME: &str = "accounts.toml";

/// Lockfile name.
#[cfg(not(target_os = "ios"))]
const LOCKFILE_NAME: &str = "accounts.lock";

/// Database file name.
const DB_NAME: &str = "dc.db";

/// Account manager configuration file.
#[derive(Debug)]
struct Config {
    file: PathBuf,
    inner: InnerConfig,
    // We lock the lockfile in the Config constructors to protect also from having multiple Config
    // objects for the same config file.
    lock_task: Option<JoinHandle<anyhow::Result<()>>>,
}

/// Account manager configuration file contents.
///
/// This is serialized into TOML.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct InnerConfig {
    /// The currently selected account.
    pub selected_account: u32,
    pub next_id: u32,
    pub accounts: Vec<AccountConfig>,
    /// Ordered list of account IDs, representing the user's preferred order.
    /// If an account ID is not in this list, it will be appended at the end.
    #[serde(default)]
    pub accounts_order: Vec<u32>,
}

impl Drop for Config {
    fn drop(&mut self) {
        if let Some(lock_task) = self.lock_task.take() {
            lock_task.abort();
        }
    }
}

impl Config {
    #[cfg(target_os = "ios")]
    async fn create_lock_task(_dir: PathBuf) -> Result<Option<JoinHandle<anyhow::Result<()>>>> {
        // Do not lock accounts.toml on iOS.
        // This results in 0xdead10cc crashes on suspend.
        // iOS itself ensures that multiple instances of Delta Chat are not running.
        Ok(None)
    }

    #[cfg(not(target_os = "ios"))]
    #[expect(clippy::arithmetic_side_effects)]
    async fn create_lock_task(dir: PathBuf) -> Result<Option<JoinHandle<anyhow::Result<()>>>> {
        let lockfile = dir.join(LOCKFILE_NAME);
        let mut lock = fd_lock::RwLock::new(fs::File::create(lockfile).await?);
        let (locked_tx, locked_rx) = oneshot::channel();
        let lock_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
            let mut timeout = Duration::from_millis(100);
            let _guard = loop {
                match lock.try_write() {
                    Ok(guard) => break Ok(guard),
                    Err(err) => {
                        if timeout.as_millis() > 1600 {
                            break Err(err);
                        }
                        // We need to wait for the previous lock_task to be aborted thus unlocking
                        // the lockfile. We don't open configs for writing often outside of the
                        // tests, so this adds delays to the tests, but otherwise ok.
                        sleep(timeout).await;
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            timeout *= 2;
                        }
                    }
                }
            }?;
            locked_tx
                .send(())
                .ok()
                .context("Cannot notify about lockfile locking")?;
            let (_tx, rx) = oneshot::channel();
            rx.await?;
            Ok(())
        });
        if locked_rx.await.is_err() {
            bail!(
                "Delta Chat is already running. To use Delta Chat, you must first close the existing Delta Chat process, or restart your device. (accounts.lock file is already locked)"
            );
        };
        Ok(Some(lock_task))
    }

    /// Creates a new Config for `file`, but doesn't open/sync it.
    async fn new_nosync(file: PathBuf, lock: bool) -> Result<Self> {
        let dir = file.parent().context("Cannot get config file directory")?;
        let inner = InnerConfig {
            accounts: Vec::new(),
            selected_account: 0,
            next_id: 1,
            accounts_order: Vec::new(),
        };
        if !lock {
            let cfg = Self {
                file,
                inner,
                lock_task: None,
            };
            return Ok(cfg);
        }
        let lock_task = Self::create_lock_task(dir.to_path_buf()).await?;
        let cfg = Self {
            file,
            inner,
            lock_task,
        };
        Ok(cfg)
    }

    /// Creates a new configuration file in the given account manager directory.
    pub async fn new(dir: &Path) -> Result<Self> {
        let lock = true;
        let mut cfg = Self::new_nosync(dir.join(CONFIG_NAME), lock).await?;
        cfg.sync().await?;

        Ok(cfg)
    }

    /// Sync the inmemory representation to disk.
    /// Takes a mutable reference because the saved file is a part of the `Config` state. This
    /// protects from parallel calls resulting to a wrong file contents.
    async fn sync(&mut self) -> Result<()> {
        #[cfg(not(target_os = "ios"))]
        ensure!(
            !self
                .lock_task
                .as_ref()
                .context("Config is read-only")?
                .is_finished()
        );

        let tmp_path = self.file.with_extension("toml.tmp");
        let mut file = fs::File::create(&tmp_path)
            .await
            .context("failed to create a tmp config")?;
        file.write_all(toml::to_string_pretty(&self.inner)?.as_bytes())
            .await
            .context("failed to write a tmp config")?;
        file.sync_data()
            .await
            .context("failed to sync a tmp config")?;
        drop(file);
        fs::rename(&tmp_path, &self.file)
            .await
            .context("failed to rename config")?;
        Ok(())
    }

    /// Read a configuration from the given file into memory.
    pub async fn from_file(file: PathBuf, writable: bool) -> Result<Self> {
        let mut config = Self::new_nosync(file, writable).await?;
        let bytes = fs::read(&config.file)
            .await
            .context("Failed to read file")?;
        let s = std::str::from_utf8(&bytes)?;
        config.inner = toml::from_str(s).context("Failed to parse config")?;

        // Previous versions of the core stored absolute paths in account config.
        // Convert them to relative paths.
        let mut modified = false;
        for account in &mut config.inner.accounts {
            if account.dir.is_absolute()
                && let Some(old_path_parent) = account.dir.parent()
                && let Ok(new_path) = account.dir.strip_prefix(old_path_parent)
            {
                account.dir = new_path.to_path_buf();
                modified = true;
            }
        }
        if modified && writable {
            config.sync().await?;
        }

        Ok(config)
    }

    /// Loads all accounts defined in the configuration file.
    ///
    /// Created contexts share the same event channel and stock string
    /// translations.
    pub async fn load_accounts(
        &self,
        events: &Events,
        stockstrings: &StockStrings,
        push_subscriber: PushSubscriber,
        dir: &Path,
    ) -> Result<BTreeMap<u32, Context>> {
        let mut accounts = BTreeMap::new();

        for account_config in &self.inner.accounts {
            let dbfile = account_config.dbfile(dir);
            let ctx = ContextBuilder::new(dbfile.clone())
                .with_id(account_config.id)
                .with_events(events.clone())
                .with_stock_strings(stockstrings.clone())
                .with_push_subscriber(push_subscriber.clone())
                .build()
                .await
                .with_context(|| format!("failed to create context from file {:?}", &dbfile))?;
            // Try to open without a passphrase,
            // but do not return an error if account is passphare-protected.
            ctx.open("".to_string()).await?;

            accounts.insert(account_config.id, ctx);
        }

        Ok(accounts)
    }

    /// Creates a new account in the account manager directory.
    #[expect(clippy::arithmetic_side_effects)]
    async fn new_account(&mut self) -> Result<AccountConfig> {
        let id = {
            let id = self.inner.next_id;
            let uuid = Uuid::new_v4();
            let target_dir = PathBuf::from(uuid.to_string());

            self.inner.accounts.push(AccountConfig {
                id,
                dir: target_dir,
                uuid,
            });
            self.inner.next_id += 1;

            // Add new account to the end of the order list
            self.inner.accounts_order.push(id);

            id
        };

        self.sync().await?;

        self.select_account(id)
            .await
            .context("failed to select just added account")?;
        let cfg = self
            .get_account(id)
            .context("failed to get just added account")?;
        Ok(cfg)
    }

    /// Removes an existing account entirely.
    pub async fn remove_account(&mut self, id: u32) -> Result<()> {
        {
            if let Some(idx) = self.inner.accounts.iter().position(|e| e.id == id) {
                // remove account from the configs
                self.inner.accounts.remove(idx);
            }

            // Remove from order list as well
            self.inner.accounts_order.retain(|&x| x != id);

            if self.inner.selected_account == id {
                // reset selected account
                self.inner.selected_account = self
                    .inner
                    .accounts
                    .first()
                    .map(|e| e.id)
                    .unwrap_or_default();
            }
        }

        self.sync().await
    }

    /// Returns configuration file section for the given account ID.
    fn get_account(&self, id: u32) -> Option<AccountConfig> {
        self.inner.accounts.iter().find(|e| e.id == id).cloned()
    }

    /// Returns the ID of selected account.
    pub fn get_selected_account(&self) -> u32 {
        self.inner.selected_account
    }

    /// Changes selected account ID.
    pub async fn select_account(&mut self, id: u32) -> Result<()> {
        {
            ensure!(
                self.inner.accounts.iter().any(|e| e.id == id),
                "invalid account id: {id}"
            );

            self.inner.selected_account = id;
        }

        self.sync().await?;
        Ok(())
    }
}

/// Spend up to 1 minute trying to do the operation.
///
/// Even if Delta Chat itself does not hold the file lock,
/// there may be other processes such as antivirus,
/// or the filesystem may be network-mounted.
///
/// Without this workaround removing account may fail on Windows with an error
/// "The process cannot access the file because it is being used by another process. (os error 32)".
#[expect(clippy::arithmetic_side_effects)]
async fn try_many_times<F, Fut, T>(f: F) -> std::result::Result<(), T>
where
    F: Fn() -> Fut,
    Fut: Future<Output = std::result::Result<(), T>>,
{
    let mut counter = 0;
    loop {
        counter += 1;

        if let Err(err) = f().await {
            if counter > 60 {
                return Err(err);
            }

            // Wait 1 second and try again.
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        } else {
            break;
        }
    }
    Ok(())
}

/// Configuration of a single account.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
struct AccountConfig {
    /// Unique id.
    pub id: u32,

    /// Root directory for all data for this account.
    ///
    /// The path is relative to the account manager directory.
    pub dir: std::path::PathBuf,

    /// Universally unique account identifier.
    pub uuid: Uuid,
}

impl AccountConfig {
    /// Get the canonical dbfile name for this configuration.
    pub fn dbfile(&self, accounts_dir: &Path) -> std::path::PathBuf {
        accounts_dir.join(&self.dir).join(DB_NAME)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stock_str::{self, StockMessage};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_account_new_open() {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts1");

        {
            let writable = true;
            let mut accounts = Accounts::new(p.clone(), writable).await.unwrap();
            accounts.add_account().await.unwrap();

            assert_eq!(accounts.accounts.len(), 1);
            assert_eq!(accounts.config.get_selected_account(), 1);
        }
        for writable in [true, false] {
            let accounts = Accounts::new(p.clone(), writable).await.unwrap();

            assert_eq!(accounts.accounts.len(), 1);
            assert_eq!(accounts.config.get_selected_account(), 1);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_account_new_open_conflict() {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts");
        let writable = true;
        let _accounts = Accounts::new(p.clone(), writable).await.unwrap();

        let writable = true;
        assert!(Accounts::new(p.clone(), writable).await.is_err());

        let writable = false;
        let accounts = Accounts::new(p, writable).await.unwrap();
        assert_eq!(accounts.accounts.len(), 0);
        assert_eq!(accounts.config.get_selected_account(), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_account_new_add_remove() {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts");

        let writable = true;
        let mut accounts = Accounts::new(p.clone(), writable).await.unwrap();
        assert_eq!(accounts.accounts.len(), 0);
        assert_eq!(accounts.config.get_selected_account(), 0);

        let id = accounts.add_account().await.unwrap();
        assert_eq!(id, 1);
        assert_eq!(accounts.accounts.len(), 1);
        assert_eq!(accounts.config.get_selected_account(), 1);

        let id = accounts.add_account().await.unwrap();
        assert_eq!(id, 2);
        assert_eq!(accounts.config.get_selected_account(), id);
        assert_eq!(accounts.accounts.len(), 2);

        accounts.select_account(1).await.unwrap();
        assert_eq!(accounts.config.get_selected_account(), 1);

        accounts.remove_account(1).await.unwrap();
        assert_eq!(accounts.config.get_selected_account(), 2);
        assert_eq!(accounts.accounts.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accounts_remove_last() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let p: PathBuf = dir.path().join("accounts");

        let writable = true;
        let mut accounts = Accounts::new(p.clone(), writable).await?;
        assert!(accounts.get_selected_account().is_none());
        assert_eq!(accounts.config.get_selected_account(), 0);

        let id = accounts.add_account().await?;
        assert!(accounts.get_selected_account().is_some());
        assert_eq!(id, 1);
        assert_eq!(accounts.accounts.len(), 1);
        assert_eq!(accounts.config.get_selected_account(), id);

        accounts.remove_account(id).await?;
        assert!(accounts.get_selected_account().is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_migrate_account() {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts");

        let writable = true;
        let mut accounts = Accounts::new(p.clone(), writable).await.unwrap();
        assert_eq!(accounts.accounts.len(), 0);
        assert_eq!(accounts.config.get_selected_account(), 0);

        let extern_dbfile: PathBuf = dir.path().join("other");
        let ctx = Context::new(&extern_dbfile, 0, Events::new(), StockStrings::new())
            .await
            .unwrap();
        ctx.set_config(crate::config::Config::Addr, Some("me@mail.com"))
            .await
            .unwrap();

        drop(ctx);

        accounts
            .migrate_account(extern_dbfile.clone())
            .await
            .unwrap();
        assert_eq!(accounts.accounts.len(), 1);
        assert_eq!(accounts.config.get_selected_account(), 1);

        let ctx = accounts.get_selected_account().unwrap();
        assert_eq!(
            "me@mail.com",
            ctx.get_config(crate::config::Config::Addr)
                .await
                .unwrap()
                .unwrap()
        );
    }

    /// Tests that accounts are sorted by ID.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accounts_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts");

        let writable = true;
        let mut accounts = Accounts::new(p.clone(), writable).await.unwrap();

        for expected_id in 1..10 {
            let id = accounts.add_account().await.unwrap();
            assert_eq!(id, expected_id);
        }

        let ids = accounts.get_all();
        for (i, expected_id) in (1..10).enumerate() {
            assert_eq!(ids.get(i), Some(&expected_id));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accounts_ids_unique_increasing_and_persisted() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let p: PathBuf = dir.path().join("accounts");
        let dummy_accounts = 10;

        let (id0, id1, id2) = {
            let writable = true;
            let mut accounts = Accounts::new(p.clone(), writable).await?;
            accounts.add_account().await?;
            let ids = accounts.get_all();
            assert_eq!(ids.len(), 1);

            let id0 = *ids.first().unwrap();
            let ctx = accounts.get_account(id0).unwrap();
            ctx.set_config(crate::config::Config::Addr, Some("one@example.org"))
                .await?;

            let id1 = accounts.add_account().await?;
            let ctx = accounts.get_account(id1).unwrap();
            ctx.set_config(crate::config::Config::Addr, Some("two@example.org"))
                .await?;

            // add and remove some accounts and force a gap (ids must not be reused)
            for _ in 0..dummy_accounts {
                let to_delete = accounts.add_account().await?;
                accounts.remove_account(to_delete).await?;
            }

            let id2 = accounts.add_account().await?;
            let ctx = accounts.get_account(id2).unwrap();
            ctx.set_config(crate::config::Config::Addr, Some("three@example.org"))
                .await?;

            accounts.select_account(id1).await?;

            (id0, id1, id2)
        };
        assert!(id0 > 0);
        assert!(id1 > id0);
        assert!(id2 > id1 + dummy_accounts);

        let (id0_reopened, id1_reopened, id2_reopened) = {
            let writable = false;
            let accounts = Accounts::new(p.clone(), writable).await?;
            let ctx = accounts.get_selected_account().unwrap();
            assert_eq!(
                ctx.get_config(crate::config::Config::Addr).await?,
                Some("two@example.org".to_string())
            );

            let ids = accounts.get_all();
            assert_eq!(ids.len(), 3);

            let id0 = *ids.first().unwrap();
            let ctx = accounts.get_account(id0).unwrap();
            assert_eq!(
                ctx.get_config(crate::config::Config::Addr).await?,
                Some("one@example.org".to_string())
            );

            let id1 = *ids.get(1).unwrap();
            let t = accounts.get_account(id1).unwrap();
            assert_eq!(
                t.get_config(crate::config::Config::Addr).await?,
                Some("two@example.org".to_string())
            );

            let id2 = *ids.get(2).unwrap();
            let ctx = accounts.get_account(id2).unwrap();
            assert_eq!(
                ctx.get_config(crate::config::Config::Addr).await?,
                Some("three@example.org".to_string())
            );

            (id0, id1, id2)
        };
        assert_eq!(id0, id0_reopened);
        assert_eq!(id1, id1_reopened);
        assert_eq!(id2, id2_reopened);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_no_accounts_event_emitter() -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts");

        let writable = true;
        let accounts = Accounts::new(p.clone(), writable).await?;

        // Make sure there are no accounts.
        assert_eq!(accounts.accounts.len(), 0);

        // Create event emitter.
        let event_emitter = accounts.get_event_emitter();

        // Test that event emitter does not return `None` immediately.
        let duration = std::time::Duration::from_millis(1);
        assert!(
            tokio::time::timeout(duration, event_emitter.recv())
                .await
                .is_err()
        );

        // When account manager is dropped, event emitter is exhausted.
        drop(accounts);
        assert_eq!(event_emitter.recv().await, None);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_encrypted_account() -> Result<()> {
        let dir = tempfile::tempdir().context("failed to create tempdir")?;
        let p: PathBuf = dir.path().join("accounts");

        let writable = true;
        let mut accounts = Accounts::new(p.clone(), writable)
            .await
            .context("failed to create accounts manager")?;

        assert_eq!(accounts.accounts.len(), 0);
        let account_id = accounts
            .add_closed_account()
            .await
            .context("failed to add closed account")?;
        let account = accounts
            .get_selected_account()
            .context("failed to get account")?;
        assert_eq!(account.id, account_id);
        let passphrase_set_success = account
            .open("foobar".to_string())
            .await
            .context("failed to set passphrase")?;
        assert!(passphrase_set_success);
        drop(accounts);

        let writable = false;
        let accounts = Accounts::new(p.clone(), writable)
            .await
            .context("failed to create second accounts manager")?;
        let account = accounts
            .get_selected_account()
            .context("failed to get account")?;
        assert_eq!(account.is_open().await, false);

        // Try wrong passphrase.
        assert_eq!(account.open("barfoo".to_string()).await?, false);
        assert_eq!(account.open("".to_string()).await?, false);

        assert_eq!(account.open("foobar".to_string()).await?, true);
        assert_eq!(account.is_open().await, true);

        Ok(())
    }

    /// Tests that accounts share stock string translations.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accounts_share_translations() -> Result<()> {
        let dir = tempfile::tempdir().unwrap();
        let p: PathBuf = dir.path().join("accounts");

        let writable = true;
        let mut accounts = Accounts::new(p.clone(), writable).await?;
        accounts.add_account().await?;
        accounts.add_account().await?;

        let account1 = accounts.get_account(1).context("failed to get account 1")?;
        let account2 = accounts.get_account(2).context("failed to get account 2")?;

        assert_eq!(stock_str::no_messages(&account1).await, "No messages.");
        assert_eq!(stock_str::no_messages(&account2).await, "No messages.");
        account1
            .set_stock_translation(StockMessage::NoMessages, "foobar".to_string())
            .await?;
        assert_eq!(stock_str::no_messages(&account1).await, "foobar");
        assert_eq!(stock_str::no_messages(&account2).await, "foobar");

        Ok(())
    }
}
