use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::Arc;
use std::time::Duration;
use std::{collections::HashMap, str::FromStr};

use anyhow::{anyhow, bail, ensure, Context, Result};
pub use deltachat::accounts::Accounts;
use deltachat::blob::BlobObject;
use deltachat::calls::ice_servers;
use deltachat::chat::{
    self, add_contact_to_chat, forward_msgs, forward_msgs_2ctx, get_chat_media, get_chat_msgs,
    get_chat_msgs_ex, marknoticed_chat, remove_contact_from_chat, Chat, ChatId, ChatItem,
    MessageListOptions,
};
use deltachat::chatlist::Chatlist;
use deltachat::config::Config;
use deltachat::constants::DC_MSG_ID_DAYMARKER;
use deltachat::contact::{may_be_valid_addr, Contact, ContactId, Origin};
use deltachat::context::get_info;
use deltachat::ephemeral::Timer;
use deltachat::imex;
use deltachat::location;
use deltachat::message::{
    self, delete_msgs_ex, get_existing_msg_ids, get_msg_read_receipts, markseen_msgs, Message,
    MessageState, MsgId, Viewtype,
};
use deltachat::peer_channels::{
    leave_webxdc_realtime, send_webxdc_realtime_advertisement, send_webxdc_realtime_data,
};
use deltachat::provider::get_provider_info;
use deltachat::qr::{self, Qr};
use deltachat::qr_code_generator::{generate_backup_qr, get_securejoin_qr_svg};
use deltachat::reaction::{get_msg_reactions, send_reaction};
use deltachat::securejoin;
use deltachat::stock_str::StockMessage;
use deltachat::storage_usage::get_storage_usage;
use deltachat::webxdc::StatusUpdateSerial;
use deltachat::EventEmitter;
use sanitize_filename::is_sanitized;
use tokio::fs;
use tokio::sync::{watch, Mutex, RwLock};
use types::login_param::EnteredLoginParam;
use walkdir::WalkDir;
use yerpc::rpc;

pub mod types;

use num_traits::FromPrimitive;
use types::account::Account;
use types::calls::JsonrpcCallInfo;
use types::chat::FullChat;
use types::contact::{ContactObject, VcardContact};
use types::events::Event;
use types::http::HttpResponse;
use types::message::{MessageData, MessageObject, MessageReadReceipt};
use types::notify_state::JsonrpcNotifyState;
use types::provider_info::ProviderInfo;
use types::reactions::JsonrpcReactions;
use types::webxdc::WebxdcMessageInfo;

use self::types::message::{MessageInfo, MessageLoadResult};
use self::types::{
    chat::{BasicChat, JsonrpcChatVisibility, MuteDuration},
    location::JsonrpcLocation,
    message::{
        JsonrpcMessageListItem, MessageNotificationInfo, MessageSearchResult, MessageViewtype,
    },
};
use crate::api::types::chat_list::{get_chat_list_item_by_id, ChatListItemFetchResult};
use crate::api::types::qr::{QrObject, SecurejoinSource, SecurejoinUiPath};

#[derive(Debug)]
struct AccountState {
    /// The Qr code for current [`CommandApi::provide_backup`] call.
    ///
    /// If there is currently is a call to [`CommandApi::provide_backup`] this will be
    /// `Some`, otherwise `None`.
    backup_provider_qr: watch::Sender<Option<Qr>>,
}

impl Default for AccountState {
    fn default() -> Self {
        let tx = watch::Sender::new(None);
        Self {
            backup_provider_qr: tx,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CommandApi {
    pub(crate) accounts: Arc<RwLock<Accounts>>,

    /// Receiver side of the event channel.
    ///
    /// Events from it can be received by calling
    /// [`CommandApi::get_next_event`] method.
    event_emitter: Arc<EventEmitter>,

    states: Arc<Mutex<BTreeMap<u32, AccountState>>>,
}

impl CommandApi {
    pub fn new(accounts: Accounts) -> Self {
        let event_emitter = Arc::new(accounts.get_event_emitter());
        CommandApi {
            accounts: Arc::new(RwLock::new(accounts)),
            event_emitter,
            states: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    #[allow(dead_code)]
    pub async fn from_arc(accounts: Arc<RwLock<Accounts>>) -> Self {
        let event_emitter = Arc::new(accounts.read().await.get_event_emitter());
        CommandApi {
            accounts,
            event_emitter,
            states: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    async fn get_context_opt(&self, id: u32) -> Option<deltachat::context::Context> {
        self.accounts.read().await.get_account(id)
    }

    async fn get_context(&self, id: u32) -> Result<deltachat::context::Context> {
        self.get_context_opt(id)
            .await
            .ok_or_else(|| anyhow!("account with id {id} not found"))
    }

    async fn with_state<F, T>(&self, id: u32, with_state: F) -> T
    where
        F: FnOnce(&AccountState) -> T,
    {
        let mut states = self.states.lock().await;
        let state = states.entry(id).or_insert_with(Default::default);
        with_state(state)
    }

    async fn inner_get_backup_qr(&self, account_id: u32) -> Result<Qr> {
        let mut receiver = self
            .with_state(account_id, |state| state.backup_provider_qr.subscribe())
            .await;

        loop {
            if let Some(qr) = receiver.borrow_and_update().clone() {
                return Ok(qr);
            }
            if receiver.changed().await.is_err() {
                bail!("No backup being provided (account state dropped)");
            }
        }
    }
}

#[rpc(all_positional, ts_outdir = "typescript/generated")]
impl CommandApi {
    /// Test function.
    async fn sleep(&self, delay: f64) {
        tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await
    }

    // ---------------------------------------------
    //  Misc top level functions
    // ---------------------------------------------

    /// Checks if an email address is valid.
    async fn check_email_validity(&self, email: String) -> bool {
        may_be_valid_addr(&email)
    }

    /// Returns general system info.
    async fn get_system_info(&self) -> BTreeMap<&'static str, String> {
        get_info()
    }

    /// Get the next event, and remove it from the event queue.
    ///
    /// If no events have happened since the last `get_next_event`
    /// (i.e. if the event queue is empty), the response will be returned
    /// only when a new event fires.
    ///
    /// Note that if you are using the `BaseDeltaChat` JavaScript class
    /// or the `Rpc` Python class, this function will be invoked
    /// by those classes internally and should not be used manually.
    async fn get_next_event(&self) -> Result<Event> {
        self.event_emitter
            .recv()
            .await
            .map(|event| event.into())
            .context("event channel is closed")
    }

    // ---------------------------------------------
    // Account Management
    // ---------------------------------------------

    async fn add_account(&self) -> Result<u32> {
        self.accounts.write().await.add_account().await
    }

    /// Imports/migrated an existing account from a database path into this account manager.
    /// Returns the ID of new account.
    async fn migrate_account(&self, path_to_db: String) -> Result<u32> {
        self.accounts
            .write()
            .await
            .migrate_account(std::path::PathBuf::from(path_to_db))
            .await
    }

    async fn remove_account(&self, account_id: u32) -> Result<()> {
        self.accounts
            .write()
            .await
            .remove_account(account_id)
            .await?;
        self.states.lock().await.remove(&account_id);
        Ok(())
    }

    async fn get_all_account_ids(&self) -> Vec<u32> {
        self.accounts.read().await.get_all()
    }

    /// Select account in account manager, this saves the last used account to accounts.toml
    async fn select_account(&self, id: u32) -> Result<()> {
        self.accounts.write().await.select_account(id).await
    }

    /// Get the selected account from the account manager (on startup it is read from accounts.toml)
    async fn get_selected_account_id(&self) -> Option<u32> {
        self.accounts.read().await.get_selected_account_id()
    }

    /// Set the order of accounts.
    /// The provided list should contain all account IDs in the desired order.
    /// If an account ID is missing from the list, it will be appended at the end.
    /// If the list contains non-existent account IDs, they will be ignored.
    async fn set_accounts_order(&self, order: Vec<u32>) -> Result<()> {
        self.accounts.write().await.set_accounts_order(order).await
    }

    /// Get a list of all configured accounts.
    async fn get_all_accounts(&self) -> Result<Vec<Account>> {
        let mut accounts = Vec::new();
        let accounts_lock = self.accounts.read().await;
        for id in accounts_lock.get_all() {
            let context_option = accounts_lock.get_account(id);
            if let Some(ctx) = context_option {
                accounts.push(Account::from_context(&ctx, id).await?)
            }
        }
        Ok(accounts)
    }

    /// Starts background tasks for all accounts.
    async fn start_io_for_all_accounts(&self) -> Result<()> {
        self.accounts.write().await.start_io().await;
        Ok(())
    }

    /// Stops background tasks for all accounts.
    async fn stop_io_for_all_accounts(&self) -> Result<()> {
        self.accounts.write().await.stop_io().await;
        Ok(())
    }

    /// Performs a background fetch for all accounts in parallel with a timeout.
    ///
    /// The `AccountsBackgroundFetchDone` event is emitted at the end even in case of timeout.
    /// Process all events until you get this one and you can safely return to the background
    /// without forgetting to create notifications caused by timing race conditions.
    async fn background_fetch(&self, timeout_in_seconds: f64) -> Result<()> {
        let future = {
            let lock = self.accounts.read().await;
            lock.background_fetch(std::time::Duration::from_secs_f64(timeout_in_seconds))
        };
        // At this point account manager is not locked anymore.
        future.await;
        Ok(())
    }

    async fn stop_background_fetch(&self) -> Result<()> {
        self.accounts.read().await.stop_background_fetch();
        Ok(())
    }

    // ---------------------------------------------
    // Methods that work on individual accounts
    // ---------------------------------------------

    /// Starts background tasks for a single account.
    async fn start_io(&self, account_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.start_io().await;
        Ok(())
    }

    /// Stops background tasks for a single account.
    async fn stop_io(&self, account_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.stop_io().await;
        Ok(())
    }

    /// Get top-level info for an account.
    async fn get_account_info(&self, account_id: u32) -> Result<Account> {
        let context_option = self.accounts.read().await.get_account(account_id);
        if let Some(ctx) = context_option {
            Ok(Account::from_context(&ctx, account_id).await?)
        } else {
            Err(anyhow!(
                "account with id {account_id} doesn't exist anymore"
            ))
        }
    }

    /// Get the current push notification state.
    async fn get_push_state(&self, account_id: u32) -> Result<JsonrpcNotifyState> {
        let ctx = self.get_context(account_id).await?;
        Ok(ctx.push_state().await.into())
    }

    /// Get the combined filesize of an account in bytes
    async fn get_account_file_size(&self, account_id: u32) -> Result<u64> {
        let ctx = self.get_context(account_id).await?;
        let dbfile = ctx.get_dbfile().metadata()?.len();
        let total_size = WalkDir::new(ctx.get_blobdir())
            .max_depth(2)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.metadata().ok())
            .filter(|metadata| metadata.is_file())
            .fold(0, |acc, m| acc + m.len());

        Ok(dbfile + total_size)
    }

    /// Returns provider for the given domain.
    ///
    /// This function looks up domain in offline database.
    ///
    /// For compatibility, email address can be passed to this function
    /// instead of the domain.
    async fn get_provider_info(
        &self,
        _account_id: u32,
        email: String,
    ) -> Result<Option<ProviderInfo>> {
        let provider_info = get_provider_info(email.split('@').next_back().unwrap_or(""));
        Ok(ProviderInfo::from_dc_type(provider_info))
    }

    /// Checks if the context is already configured.
    async fn is_configured(&self, account_id: u32) -> Result<bool> {
        let ctx = self.get_context(account_id).await?;
        ctx.is_configured().await
    }

    /// Get system info for an account.
    async fn get_info(&self, account_id: u32) -> Result<BTreeMap<&'static str, String>> {
        let ctx = self.get_context(account_id).await?;
        ctx.get_info().await
    }

    /// Get storage usage report as formatted string
    async fn get_storage_usage_report_string(&self, account_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        let storage_usage = get_storage_usage(&ctx).await?;
        Ok(storage_usage.to_string())
    }

    /// Get the blob dir.
    async fn get_blob_dir(&self, account_id: u32) -> Result<Option<String>> {
        let ctx = self.get_context(account_id).await?;
        Ok(ctx.get_blobdir().to_str().map(|s| s.to_owned()))
    }

    /// If there was an error while the account was opened
    /// and migrated to the current version,
    /// then this function returns it.
    ///
    /// This function is useful because the key-contacts migration could fail due to bugs
    /// and then the account will not work properly.
    ///
    /// After opening an account, the UI should call this function
    /// and show the error string if one is returned.
    async fn get_migration_error(&self, account_id: u32) -> Result<Option<String>> {
        let ctx = self.get_context(account_id).await?;
        Ok(ctx.get_migration_error())
    }

    /// Copy file to blob dir.
    async fn copy_to_blob_dir(&self, account_id: u32, path: String) -> Result<PathBuf> {
        let ctx = self.get_context(account_id).await?;
        let file = Path::new(&path);
        Ok(BlobObject::create_and_deduplicate(&ctx, file, file)?.to_abs_path())
    }

    /// Sets the given configuration key.
    async fn set_config(&self, account_id: u32, key: String, value: Option<String>) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        set_config(&ctx, &key, value.as_deref()).await
    }

    /// Updates a batch of configuration values.
    async fn batch_set_config(
        &self,
        account_id: u32,
        config: HashMap<String, Option<String>>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        for (key, value) in config.into_iter() {
            set_config(&ctx, &key, value.as_deref())
                .await
                .with_context(|| format!("Can't set {key} to {value:?}"))?;
        }
        Ok(())
    }

    /// Set configuration values from a QR code. (technically from the URI that is stored in the qrcode)
    /// Before this function is called, `checkQr()` should confirm the type of the
    /// QR code is `account` or `webrtcInstance`.
    ///
    /// Internally, the function will call dc_set_config() with the appropriate keys,
    async fn set_config_from_qr(&self, account_id: u32, qr_content: String) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        qr::set_config_from_qr(&ctx, &qr_content).await
    }

    async fn check_qr(&self, account_id: u32, qr_content: String) -> Result<QrObject> {
        let ctx = self.get_context(account_id).await?;
        let qr = qr::check_qr(&ctx, &qr_content).await?;
        let qr_object = QrObject::from(qr);
        Ok(qr_object)
    }

    /// Returns configuration value for the given key.
    async fn get_config(&self, account_id: u32, key: String) -> Result<Option<String>> {
        let ctx = self.get_context(account_id).await?;
        get_config(&ctx, &key).await
    }

    async fn batch_get_config(
        &self,
        account_id: u32,
        keys: Vec<String>,
    ) -> Result<HashMap<String, Option<String>>> {
        let ctx = self.get_context(account_id).await?;
        let mut result: HashMap<String, Option<String>> = HashMap::new();
        for key in keys {
            result.insert(key.clone(), get_config(&ctx, &key).await?);
        }
        Ok(result)
    }

    async fn set_stock_strings(&self, strings: HashMap<u32, String>) -> Result<()> {
        let accounts = self.accounts.read().await;
        for (stock_id, stock_message) in strings {
            if let Some(stock_id) = StockMessage::from_u32(stock_id) {
                accounts
                    .set_stock_translation(stock_id, stock_message)
                    .await?;
            }
        }
        Ok(())
    }

    /// Configures this account with the currently set parameters.
    /// Setup the credential config before calling this.
    ///
    /// Deprecated as of 2025-02; use `add_transport_from_qr()`
    /// or `add_or_update_transport()` instead.
    async fn configure(&self, account_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.stop_io().await;
        let result = ctx.configure().await;
        if result.is_err() {
            if let Ok(true) = ctx.is_configured().await {
                ctx.start_io().await;
            }
            return result;
        }
        ctx.start_io().await;
        Ok(())
    }

    /// Configures a new email account using the provided parameters
    /// and adds it as a transport.
    ///
    /// If the email address is the same as an existing transport,
    /// then this existing account will be reconfigured instead of a new one being added.
    ///
    /// This function stops and starts IO as needed.
    ///
    /// Usually it will be enough to only set `addr` and `password`,
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
    async fn add_or_update_transport(
        &self,
        account_id: u32,
        param: EnteredLoginParam,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.add_or_update_transport(&mut param.try_into()?).await
    }

    /// Deprecated 2025-04. Alias for [Self::add_or_update_transport()].
    async fn add_transport(&self, account_id: u32, param: EnteredLoginParam) -> Result<()> {
        self.add_or_update_transport(account_id, param).await
    }

    /// Adds a new email account as a transport
    /// using the server encoded in the QR code.
    /// See [Self::add_or_update_transport].
    async fn add_transport_from_qr(&self, account_id: u32, qr: String) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.add_transport_from_qr(&qr).await
    }

    /// Returns the list of all email accounts that are used as a transport in the current profile.
    /// Use [Self::add_or_update_transport()] to add or change a transport
    /// and [Self::delete_transport()] to delete a transport.
    async fn list_transports(&self, account_id: u32) -> Result<Vec<EnteredLoginParam>> {
        let ctx = self.get_context(account_id).await?;
        let res = ctx
            .list_transports()
            .await?
            .into_iter()
            .map(|t| t.into())
            .collect();
        Ok(res)
    }

    /// Removes the transport with the specified email address
    /// (i.e. [EnteredLoginParam::addr]).
    async fn delete_transport(&self, account_id: u32, addr: String) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.delete_transport(&addr).await
    }

    /// Signal an ongoing process to stop.
    async fn stop_ongoing_process(&self, account_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.stop_ongoing().await;
        Ok(())
    }

    async fn export_self_keys(
        &self,
        account_id: u32,
        path: String,
        passphrase: Option<String>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        imex::imex(
            &ctx,
            imex::ImexMode::ExportSelfKeys,
            path.as_ref(),
            passphrase,
        )
        .await
    }

    async fn import_self_keys(
        &self,
        account_id: u32,
        path: String,
        passphrase: Option<String>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        imex::imex(
            &ctx,
            imex::ImexMode::ImportSelfKeys,
            path.as_ref(),
            passphrase,
        )
        .await
    }

    /// Returns the message IDs of all _fresh_ messages of any chat.
    /// Typically used for implementing notification summaries
    /// or badge counters e.g. on the app icon.
    /// The list is already sorted and starts with the most recent fresh message.
    ///
    /// Messages belonging to muted chats or to the contact requests are not returned;
    /// these messages should not be notified
    /// and also badge counters should not include these messages.
    ///
    /// To get the number of fresh messages for a single chat, muted or not,
    /// use `get_fresh_msg_cnt()`.
    async fn get_fresh_msgs(&self, account_id: u32) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        Ok(ctx
            .get_fresh_msgs()
            .await?
            .iter()
            .map(|msg_id| msg_id.to_u32())
            .collect())
    }

    /// Get the number of _fresh_ messages in a chat.
    /// Typically used to implement a badge with a number in the chatlist.
    ///
    /// If the specified chat is muted,
    /// the UI should show the badge counter "less obtrusive",
    /// e.g. using "gray" instead of "red" color.
    async fn get_fresh_msg_cnt(&self, account_id: u32, chat_id: u32) -> Result<usize> {
        let ctx = self.get_context(account_id).await?;
        ChatId::new(chat_id).get_fresh_msg_cnt(&ctx).await
    }

    /// Gets messages to be processed by the bot and returns their IDs.
    ///
    /// Only messages with database ID higher than `last_msg_id` config value
    /// are returned. After processing the messages, the bot should
    /// update `last_msg_id` by calling [`markseen_msgs`]
    /// or manually updating the value to avoid getting already
    /// processed messages.
    ///
    /// [`markseen_msgs`]: Self::markseen_msgs
    async fn get_next_msgs(&self, account_id: u32) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let msg_ids = ctx
            .get_next_msgs()
            .await?
            .iter()
            .map(|msg_id| msg_id.to_u32())
            .collect();
        Ok(msg_ids)
    }

    /// Waits for messages to be processed by the bot and returns their IDs.
    ///
    /// This function is similar to [`get_next_msgs`],
    /// but waits for internal new message notification before returning.
    /// New message notification is sent when new message is added to the database,
    /// on initialization, when I/O is started and when I/O is stopped.
    /// This allows bots to use `wait_next_msgs` in a loop to process
    /// old messages after initialization and during the bot runtime.
    /// To shutdown the bot, stopping I/O can be used to interrupt
    /// pending or next `wait_next_msgs` call.
    ///
    /// [`get_next_msgs`]: Self::get_next_msgs
    async fn wait_next_msgs(&self, account_id: u32) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let msg_ids = ctx
            .wait_next_msgs()
            .await?
            .iter()
            .map(|msg_id| msg_id.to_u32())
            .collect();
        Ok(msg_ids)
    }

    /// Estimate the number of messages that will be deleted
    /// by the set_config()-options `delete_device_after` or `delete_server_after`.
    /// This is typically used to show the estimated impact to the user
    /// before actually enabling deletion of old messages.
    async fn estimate_auto_deletion_count(
        &self,
        account_id: u32,
        from_server: bool,
        seconds: i64,
    ) -> Result<usize> {
        let ctx = self.get_context(account_id).await?;
        message::estimate_deletion_cnt(&ctx, from_server, seconds).await
    }

    // ---------------------------------------------
    //  autocrypt
    // ---------------------------------------------

    async fn initiate_autocrypt_key_transfer(&self, account_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        deltachat::imex::initiate_key_transfer(&ctx).await
    }

    async fn continue_autocrypt_key_transfer(
        &self,
        account_id: u32,
        message_id: u32,
        setup_code: String,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        deltachat::imex::continue_key_transfer(&ctx, MsgId::new(message_id), &setup_code).await
    }

    // ---------------------------------------------
    //   chat list
    // ---------------------------------------------

    async fn get_chatlist_entries(
        &self,
        account_id: u32,
        list_flags: Option<u32>,
        query_string: Option<String>,
        query_contact_id: Option<u32>,
    ) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let list = Chatlist::try_load(
            &ctx,
            list_flags.unwrap_or(0) as usize,
            query_string.as_deref(),
            query_contact_id.map(ContactId::new),
        )
        .await?;
        let mut l: Vec<u32> = Vec::with_capacity(list.len());
        for i in 0..list.len() {
            l.push(list.get_chat_id(i)?.to_u32());
        }
        Ok(l)
    }

    /// Returns chats similar to the given one.
    ///
    /// Experimental API, subject to change without notice.
    async fn get_similar_chat_ids(&self, account_id: u32, chat_id: u32) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let chat_id = ChatId::new(chat_id);
        let list = chat_id
            .get_similar_chat_ids(&ctx)
            .await?
            .into_iter()
            .map(|(chat_id, _metric)| chat_id.to_u32())
            .collect();
        Ok(list)
    }

    async fn get_chatlist_items_by_entries(
        &self,
        account_id: u32,
        entries: Vec<u32>,
    ) -> Result<HashMap<u32, ChatListItemFetchResult>> {
        let ctx = self.get_context(account_id).await?;
        let mut result: HashMap<u32, ChatListItemFetchResult> =
            HashMap::with_capacity(entries.len());
        for &entry in entries.iter() {
            result.insert(
                entry,
                match get_chat_list_item_by_id(&ctx, entry).await {
                    Ok(res) => res,
                    Err(err) => ChatListItemFetchResult::Error {
                        id: entry,
                        error: format!("{err:#}"),
                    },
                },
            );
        }
        Ok(result)
    }

    // ---------------------------------------------
    //  chat
    // ---------------------------------------------

    async fn get_full_chat_by_id(&self, account_id: u32, chat_id: u32) -> Result<FullChat> {
        let ctx = self.get_context(account_id).await?;
        FullChat::try_from_dc_chat_id(&ctx, chat_id).await
    }

    /// get basic info about a chat,
    /// use chatlist_get_full_chat_by_id() instead if you need more information
    async fn get_basic_chat_info(&self, account_id: u32, chat_id: u32) -> Result<BasicChat> {
        let ctx = self.get_context(account_id).await?;
        BasicChat::try_from_dc_chat_id(&ctx, chat_id).await
    }

    async fn accept_chat(&self, account_id: u32, chat_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ChatId::new(chat_id).accept(&ctx).await
    }

    async fn block_chat(&self, account_id: u32, chat_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ChatId::new(chat_id).block(&ctx).await
    }

    /// Delete a chat.
    ///
    /// Messages are deleted from the device and the chat database entry is deleted.
    /// After that, the event #DC_EVENT_MSGS_CHANGED is posted.
    ///
    /// Things that are _not done_ implicitly:
    ///
    /// - Messages are **not deleted from the server**.
    /// - The chat or the contact is **not blocked**, so new messages from the user/the group may appear as a contact request
    ///   and the user may create the chat again.
    /// - **Groups are not left** - this would
    ///   be unexpected as (1) deleting a normal chat also does not prevent new mails
    ///   from arriving, (2) leaving a group requires sending a message to
    ///   all group members - especially for groups not used for a longer time, this is
    ///   really unexpected when deletion results in contacting all members again,
    ///   (3) only leaving groups is also a valid usecase.
    ///
    /// To leave a chat explicitly, use leave_group()
    async fn delete_chat(&self, account_id: u32, chat_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ChatId::new(chat_id).delete(&ctx).await
    }

    /// Get encryption info for a chat.
    /// Get a multi-line encryption info, containing encryption preferences of all members.
    /// Can be used to find out why messages sent to group are not encrypted.
    ///
    /// returns Multi-line text
    async fn get_chat_encryption_info(&self, account_id: u32, chat_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        ChatId::new(chat_id).get_encryption_info(&ctx).await
    }

    /// Get QR code text that will offer a [SecureJoin](https://securejoin.delta.chat/) invitation.
    ///
    /// If `chat_id` is a group chat ID, SecureJoin QR code for the group is returned.
    /// If `chat_id` is unset, setup contact QR code is returned.
    async fn get_chat_securejoin_qr_code(
        &self,
        account_id: u32,
        chat_id: Option<u32>,
    ) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        let chat = chat_id.map(ChatId::new);
        let qr = securejoin::get_securejoin_qr(&ctx, chat).await?;
        Ok(qr)
    }

    /// Get QR code (text and SVG) that will offer a Setup-Contact or Verified-Group invitation.
    /// The QR code is compatible to the OPENPGP4FPR format
    /// so that a basic fingerprint comparison also works e.g. with OpenKeychain.
    ///
    /// The scanning device will pass the scanned content to `checkQr()` then;
    /// if `checkQr()` returns `askVerifyContact` or `askVerifyGroup`
    /// an out-of-band-verification can be joined using `secure_join()`
    ///
    /// chat_id: If set to a group-chat-id,
    ///     the Verified-Group-Invite protocol is offered in the QR code;
    ///     works for protected groups as well as for normal groups.
    ///     If not set, the Setup-Contact protocol is offered in the QR code.
    ///     See https://securejoin.delta.chat/ for details about both protocols.
    ///
    /// return format: `[code, svg]`
    async fn get_chat_securejoin_qr_code_svg(
        &self,
        account_id: u32,
        chat_id: Option<u32>,
    ) -> Result<(String, String)> {
        let ctx = self.get_context(account_id).await?;
        let chat = chat_id.map(ChatId::new);
        let qr = securejoin::get_securejoin_qr(&ctx, chat).await?;
        let svg = get_securejoin_qr_svg(&ctx, chat).await?;
        Ok((qr, svg))
    }

    /// Continue a Setup-Contact or Verified-Group-Invite protocol
    /// started on another device with `get_chat_securejoin_qr_code_svg()`.
    /// This function is typically called when `check_qr()` returns
    /// type=AskVerifyContact or type=AskVerifyGroup.
    ///
    /// The function returns immediately and the handshake runs in background,
    /// sending and receiving several messages.
    /// During the handshake, info messages are added to the chat,
    /// showing progress, success or errors.
    ///
    /// Subsequent calls of `secure_join()` will abort previous, unfinished handshakes.
    ///
    /// See https://securejoin.delta.chat/ for details about both protocols.
    ///
    /// **qr**: The text of the scanned QR code. Typically, the same string as given
    ///     to `check_qr()`.
    ///
    /// **returns**: The chat ID of the joined chat, the UI may redirect to the this chat.
    ///         A returned chat ID does not guarantee that the chat is protected or the belonging contact is verified.
    ///
    async fn secure_join(&self, account_id: u32, qr: String) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        let chat_id = securejoin::join_securejoin(&ctx, &qr).await?;
        Ok(chat_id.to_u32())
    }

    /// Like `secure_join()`, but allows to pass a source and a UI-path.
    /// You only need this if your UI has an option to send statistics
    /// to Delta Chat's developers.
    ///
    /// **source**: The source where the QR code came from.
    /// E.g. a link that was clicked inside or outside Delta Chat,
    /// the "Paste from Clipboard" action,
    /// the "Load QR code as image" action,
    /// or a QR code scan.
    ///
    /// **uipath**: Which UI path did the user use to arrive at the QR code screen.
    /// If the SecurejoinSource was ExternalLink or InternalLink,
    /// pass `None` here, because the QR code screen wasn't even opened.
    /// ```
    async fn secure_join_with_ux_info(
        &self,
        account_id: u32,
        qr: String,
        source: Option<SecurejoinSource>,
        uipath: Option<SecurejoinUiPath>,
    ) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        let chat_id = securejoin::join_securejoin_with_ux_info(
            &ctx,
            &qr,
            source.map(Into::into),
            uipath.map(Into::into),
        )
        .await?;
        Ok(chat_id.to_u32())
    }

    async fn leave_group(&self, account_id: u32, chat_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        remove_contact_from_chat(&ctx, ChatId::new(chat_id), ContactId::SELF).await
    }

    /// Remove a member from a group.
    ///
    /// If the group is already _promoted_ (any message was sent to the group),
    /// all group members are informed by a special status message that is sent automatically by this function.
    ///
    /// Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
    async fn remove_contact_from_chat(
        &self,
        account_id: u32,
        chat_id: u32,
        contact_id: u32,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        remove_contact_from_chat(&ctx, ChatId::new(chat_id), ContactId::new(contact_id)).await
    }

    /// Add a member to a group.
    ///
    /// If the group is already _promoted_ (any message was sent to the group),
    /// all group members are informed by a special status message that is sent automatically by this function.
    ///
    /// If the group has group protection enabled, only verified contacts can be added to the group.
    ///
    /// Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
    async fn add_contact_to_chat(
        &self,
        account_id: u32,
        chat_id: u32,
        contact_id: u32,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        add_contact_to_chat(&ctx, ChatId::new(chat_id), ContactId::new(contact_id)).await
    }

    /// Get the contact IDs belonging to a chat.
    ///
    /// - for normal chats, the function always returns exactly one contact,
    ///   DC_CONTACT_ID_SELF is returned only for SELF-chats.
    ///
    /// - for group chats all members are returned, DC_CONTACT_ID_SELF is returned
    ///   explicitly as it may happen that oneself gets removed from a still existing
    ///   group
    ///
    /// - for broadcast channels, all recipients are returned, DC_CONTACT_ID_SELF is not included
    ///
    /// - for mailing lists, the behavior is not documented currently, we will decide on that later.
    ///   for now, the UI should not show the list for mailing lists.
    ///   (we do not know all members and there is not always a global mailing list address,
    ///   so we could return only SELF or the known members; this is not decided yet)
    async fn get_chat_contacts(&self, account_id: u32, chat_id: u32) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let contacts = chat::get_chat_contacts(&ctx, ChatId::new(chat_id)).await?;
        Ok(contacts.iter().map(|id| id.to_u32()).collect::<Vec<u32>>())
    }

    /// Returns contact IDs of the past chat members.
    async fn get_past_chat_contacts(&self, account_id: u32, chat_id: u32) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let contacts = chat::get_past_chat_contacts(&ctx, ChatId::new(chat_id)).await?;
        Ok(contacts.iter().map(|id| id.to_u32()).collect::<Vec<u32>>())
    }

    /// Create a new encrypted group chat (with key-contacts).
    ///
    /// After creation,
    /// the group has one member with the ID DC_CONTACT_ID_SELF
    /// and is in _unpromoted_ state.
    /// This means, you can add or remove members, change the name,
    /// the group image and so on without messages being sent to all group members.
    ///
    /// This changes as soon as the first message is sent to the group members
    /// and the group becomes _promoted_.
    /// After that, all changes are synced with all group members
    /// by sending status message.
    ///
    /// To check, if a chat is still unpromoted, you can look at the `is_unpromoted` property of `BasicChat` or `FullChat`.
    /// This may be useful if you want to show some help for just created groups.
    ///
    /// `protect` argument is deprecated as of 2025-10-22 and is left for compatibility.
    /// Pass `false` here.
    async fn create_group_chat(
        &self,
        account_id: u32,
        name: String,
        _protect: bool,
    ) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        chat::create_group(&ctx, &name).await.map(|id| id.to_u32())
    }

    /// Create a new unencrypted group chat.
    ///
    /// Same as [`Self::create_group_chat`], but the chat is unencrypted and can only have
    /// address-contacts.
    async fn create_group_chat_unencrypted(&self, account_id: u32, name: String) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        chat::create_group_unencrypted(&ctx, &name)
            .await
            .map(|id| id.to_u32())
    }

    /// Deprecated 2025-07 in favor of create_broadcast().
    async fn create_broadcast_list(&self, account_id: u32) -> Result<u32> {
        self.create_broadcast(account_id, "Channel".to_string())
            .await
    }

    /// Create a new, outgoing **broadcast channel**
    /// (called "Channel" in the UI).
    ///
    /// Broadcast channels are similar to groups on the sending device,
    /// however, recipients get the messages in a read-only chat
    /// and will not see who the other members are.
    ///
    /// Called `broadcast` here rather than `channel`,
    /// because the word "channel" already appears a lot in the code,
    /// which would make it hard to grep for it.
    ///
    /// After creation, the chat contains no recipients and is in _unpromoted_ state;
    /// see [`CommandApi::create_group_chat`] for more information on the unpromoted state.
    ///
    /// Returns the created chat's id.
    async fn create_broadcast(&self, account_id: u32, chat_name: String) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        chat::create_broadcast(&ctx, chat_name)
            .await
            .map(|id| id.to_u32())
    }

    /// Set group name.
    ///
    /// If the group is already _promoted_ (any message was sent to the group),
    /// all group members are informed by a special status message that is sent automatically by this function.
    ///
    /// Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
    async fn set_chat_name(&self, account_id: u32, chat_id: u32, new_name: String) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        chat::set_chat_name(&ctx, ChatId::new(chat_id), &new_name).await
    }

    /// Set group profile image.
    ///
    /// If the group is already _promoted_ (any message was sent to the group),
    /// all group members are informed by a special status message that is sent automatically by this function.
    ///
    /// Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
    ///
    /// To find out the profile image of a chat, use dc_chat_get_profile_image()
    ///
    /// @param image_path Full path of the image to use as the group image. The image will immediately be copied to the
    ///     `blobdir`; the original image will not be needed anymore.
    ///      If you pass null here, the group image is deleted (for promoted groups, all members are informed about
    ///      this change anyway).
    async fn set_chat_profile_image(
        &self,
        account_id: u32,
        chat_id: u32,
        image_path: Option<String>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        chat::set_chat_profile_image(&ctx, ChatId::new(chat_id), &image_path.unwrap_or_default())
            .await
    }

    async fn set_chat_visibility(
        &self,
        account_id: u32,
        chat_id: u32,
        visibility: JsonrpcChatVisibility,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;

        ChatId::new(chat_id)
            .set_visibility(&ctx, visibility.into_core_type())
            .await
    }

    async fn set_chat_ephemeral_timer(
        &self,
        account_id: u32,
        chat_id: u32,
        timer: u32,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ChatId::new(chat_id)
            .set_ephemeral_timer(&ctx, Timer::from_u32(timer))
            .await
    }

    async fn get_chat_ephemeral_timer(&self, account_id: u32, chat_id: u32) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        Ok(ChatId::new(chat_id)
            .get_ephemeral_timer(&ctx)
            .await?
            .to_u32())
    }

    /// Add a message to the device-chat.
    /// Device-messages usually contain update information
    /// and some hints that are added during the program runs, multi-device etc.
    /// The device-message may be defined by a label;
    /// if a message with the same label was added or skipped before,
    /// the message is not added again, even if the message was deleted in between.
    /// If needed, the device-chat is created before.
    ///
    /// Sends the `MsgsChanged` event on success.
    ///
    /// Setting msg to None will prevent the device message with this label from being added in the future.
    async fn add_device_message(
        &self,
        account_id: u32,
        label: String,
        msg: Option<MessageData>,
    ) -> Result<Option<u32>> {
        let ctx = self.get_context(account_id).await?;
        if let Some(msg) = msg {
            let mut message = msg.create_message(&ctx).await?;
            let message_id =
                deltachat::chat::add_device_msg(&ctx, Some(&label), Some(&mut message)).await?;
            if !message_id.is_unset() {
                return Ok(Some(message_id.to_u32()));
            }
        } else {
            deltachat::chat::add_device_msg(&ctx, Some(&label), None).await?;
        }
        Ok(None)
    }

    ///  Mark all messages in a chat as _noticed_.
    ///  _Noticed_ messages are no longer _fresh_ and do not count as being unseen
    ///  but are still waiting for being marked as "seen" using markseen_msgs()
    ///  (IMAP/MDNs is not done for noticed messages).
    ///
    ///  Calling this function usually results in the event #DC_EVENT_MSGS_NOTICED.
    ///  See also markseen_msgs().
    async fn marknoticed_chat(&self, account_id: u32, chat_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        marknoticed_chat(&ctx, ChatId::new(chat_id)).await
    }

    /// Returns the message that is immediately followed by the last seen
    /// message.
    /// From the point of view of the user this is effectively
    /// "first unread", but in reality in the database a seen message
    /// _can_ be followed by a fresh (unseen) message
    /// if that message has not been individually marked as seen.
    async fn get_first_unread_message_of_chat(
        &self,
        account_id: u32,
        chat_id: u32,
    ) -> Result<Option<u32>> {
        let ctx = self.get_context(account_id).await?;

        // TODO: implement this in core with an SQL query, that will be way faster
        let messages = get_chat_msgs(&ctx, ChatId::new(chat_id)).await?;
        let mut first_unread_message_id = None;
        for item in messages.into_iter().rev() {
            if let ChatItem::Message { msg_id } = item {
                match msg_id.get_state(&ctx).await? {
                    MessageState::InSeen => break,
                    MessageState::InFresh | MessageState::InNoticed => {
                        first_unread_message_id = Some(msg_id)
                    }
                    _ => continue,
                }
            }
        }
        Ok(first_unread_message_id.map(|id| id.to_u32()))
    }

    /// Set mute duration of a chat.
    ///
    /// The UI can then call is_chat_muted() when receiving a new message
    /// to decide whether it should trigger an notification.
    ///
    /// Muted chats should not sound or vibrate
    /// and should not show a visual notification in the system area.
    /// Moreover, muted chats should be excluded from global badge counter
    /// (get_fresh_msgs() skips muted chats therefore)
    /// and the in-app, per-chat badge counter should use a less obtrusive color.
    ///
    /// Sends out #DC_EVENT_CHAT_MODIFIED.
    async fn set_chat_mute_duration(
        &self,
        account_id: u32,
        chat_id: u32,
        duration: MuteDuration,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        chat::set_muted(&ctx, ChatId::new(chat_id), duration.try_into_core_type()?).await
    }

    /// Check whether the chat is currently muted (can be changed by set_chat_mute_duration()).
    ///
    /// This is available as a standalone function outside of fullchat, because it might be only needed for notification
    async fn is_chat_muted(&self, account_id: u32, chat_id: u32) -> Result<bool> {
        let ctx = self.get_context(account_id).await?;
        Ok(Chat::load_from_db(&ctx, ChatId::new(chat_id))
            .await?
            .is_muted())
    }

    // ---------------------------------------------
    // message list
    // ---------------------------------------------

    /// Mark messages as presented to the user.
    /// Typically, UIs call this function on scrolling through the message list,
    /// when the messages are presented at least for a little moment.
    /// The concrete action depends on the type of the chat and on the users settings
    /// (dc_msgs_presented() may be a better name therefore, but well. :)
    ///
    /// - For normal chats, the IMAP state is updated, MDN is sent
    ///   (if set_config()-options `mdns_enabled` is set)
    ///   and the internal state is changed to @ref DC_STATE_IN_SEEN to reflect these actions.
    ///
    /// - For contact requests, no IMAP or MDNs is done
    ///   and the internal state is not changed therefore.
    ///   See also marknoticed_chat().
    ///
    /// Moreover, timer is started for incoming ephemeral messages.
    /// This also happens for contact requests chats.
    ///
    /// This function updates `last_msg_id` configuration value
    /// to the maximum of the current value and IDs passed to this function.
    /// Bots which mark messages as seen can rely on this side effect
    /// to avoid updating `last_msg_id` value manually.
    ///
    /// One #DC_EVENT_MSGS_NOTICED event is emitted per modified chat.
    async fn markseen_msgs(&self, account_id: u32, msg_ids: Vec<u32>) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        markseen_msgs(&ctx, msg_ids.into_iter().map(MsgId::new).collect()).await
    }

    /// Returns all messages of a particular chat.
    ///
    /// * `add_daymarker` - If `true`, add day markers as `DC_MSG_ID_DAYMARKER` to the result,
    ///   e.g. [1234, 1237, 9, 1239]. The day marker timestamp is the midnight one for the
    ///   corresponding (following) day in the local timezone.
    async fn get_message_ids(
        &self,
        account_id: u32,
        chat_id: u32,
        info_only: bool,
        add_daymarker: bool,
    ) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let msg = get_chat_msgs_ex(
            &ctx,
            ChatId::new(chat_id),
            MessageListOptions {
                info_only,
                add_daymarker,
            },
        )
        .await?;
        Ok(msg
            .iter()
            .map(|chat_item| -> u32 {
                match chat_item {
                    deltachat::chat::ChatItem::Message { msg_id } => msg_id.to_u32(),
                    deltachat::chat::ChatItem::DayMarker { .. } => DC_MSG_ID_DAYMARKER,
                }
            })
            .collect())
    }

    /// Checks if the messages with given IDs exist.
    ///
    /// Returns IDs of existing messages.
    async fn get_existing_msg_ids(&self, account_id: u32, msg_ids: Vec<u32>) -> Result<Vec<u32>> {
        if let Some(context) = self.get_context_opt(account_id).await {
            let msg_ids: Vec<MsgId> = msg_ids.into_iter().map(MsgId::new).collect();
            let existing_msg_ids = get_existing_msg_ids(&context, &msg_ids).await?;
            Ok(existing_msg_ids
                .into_iter()
                .map(|msg_id| msg_id.to_u32())
                .collect())
        } else {
            // Account does not exist, so messages do not exist either,
            // but this is not an error.
            Ok(Vec::new())
        }
    }

    async fn get_message_list_items(
        &self,
        account_id: u32,
        chat_id: u32,
        info_only: bool,
        add_daymarker: bool,
    ) -> Result<Vec<JsonrpcMessageListItem>> {
        let ctx = self.get_context(account_id).await?;
        let msg = get_chat_msgs_ex(
            &ctx,
            ChatId::new(chat_id),
            MessageListOptions {
                info_only,
                add_daymarker,
            },
        )
        .await?;
        Ok(msg
            .iter()
            .map(|chat_item| (*chat_item).into())
            .collect::<Vec<JsonrpcMessageListItem>>())
    }

    async fn get_message(&self, account_id: u32, msg_id: u32) -> Result<MessageObject> {
        let ctx = self.get_context(account_id).await?;
        let msg_id = MsgId::new(msg_id);
        let message_object = MessageObject::from_msg_id(&ctx, msg_id)
            .await
            .with_context(|| format!("Failed to load message {msg_id} for account {account_id}"))?
            .with_context(|| format!("Message {msg_id} does not exist for account {account_id}"))?;
        Ok(message_object)
    }

    async fn get_message_html(&self, account_id: u32, message_id: u32) -> Result<Option<String>> {
        let ctx = self.get_context(account_id).await?;
        MsgId::new(message_id).get_html(&ctx).await
    }

    /// get multiple messages in one call,
    /// if loading one message fails the error is stored in the result object in it's place.
    ///
    /// this is the batch variant of [get_message]
    async fn get_messages(
        &self,
        account_id: u32,
        message_ids: Vec<u32>,
    ) -> Result<HashMap<u32, MessageLoadResult>> {
        let ctx = self.get_context(account_id).await?;
        let mut messages: HashMap<u32, MessageLoadResult> = HashMap::new();
        for message_id in message_ids {
            let message_result = MessageObject::from_msg_id(&ctx, MsgId::new(message_id)).await;
            messages.insert(
                message_id,
                match message_result {
                    Ok(Some(message)) => MessageLoadResult::Message(message),
                    Ok(None) => MessageLoadResult::LoadingError {
                        error: "Message does not exist".to_string(),
                    },
                    Err(error) => MessageLoadResult::LoadingError {
                        error: format!("{error:#}"),
                    },
                },
            );
        }
        Ok(messages)
    }

    /// Fetch info desktop needs for creating a notification for a message
    async fn get_message_notification_info(
        &self,
        account_id: u32,
        message_id: u32,
    ) -> Result<MessageNotificationInfo> {
        let ctx = self.get_context(account_id).await?;
        MessageNotificationInfo::from_msg_id(&ctx, MsgId::new(message_id)).await
    }

    /// Delete messages. The messages are deleted on the current device and
    /// on the IMAP server.
    async fn delete_messages(&self, account_id: u32, message_ids: Vec<u32>) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let msgs: Vec<MsgId> = message_ids.into_iter().map(MsgId::new).collect();
        delete_msgs_ex(&ctx, &msgs, false).await
    }

    /// Delete messages. The messages are deleted on the current device,
    /// on the IMAP server and also for all chat members
    async fn delete_messages_for_all(&self, account_id: u32, message_ids: Vec<u32>) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let msgs: Vec<MsgId> = message_ids.into_iter().map(MsgId::new).collect();
        delete_msgs_ex(&ctx, &msgs, true).await
    }

    /// Get an informational text for a single message. The text is multiline and may
    /// contain e.g. the raw text of the message.
    ///
    /// The max. text returned is typically longer (about 100000 characters) than the
    /// max. text returned by dc_msg_get_text() (about 30000 characters).
    async fn get_message_info(&self, account_id: u32, message_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        MsgId::new(message_id).get_info(&ctx).await
    }

    /// Returns additional information for single message.
    async fn get_message_info_object(
        &self,
        account_id: u32,
        message_id: u32,
    ) -> Result<MessageInfo> {
        let ctx = self.get_context(account_id).await?;
        MessageInfo::from_msg_id(&ctx, MsgId::new(message_id)).await
    }

    /// Returns contacts that sent read receipts and the time of reading.
    async fn get_message_read_receipts(
        &self,
        account_id: u32,
        message_id: u32,
    ) -> Result<Vec<MessageReadReceipt>> {
        let ctx = self.get_context(account_id).await?;
        let receipts = get_msg_read_receipts(&ctx, MsgId::new(message_id))
            .await?
            .iter()
            .map(|(contact_id, ts)| MessageReadReceipt {
                contact_id: contact_id.to_u32(),
                timestamp: *ts,
            })
            .collect();
        Ok(receipts)
    }

    /// Asks the core to start downloading a message fully.
    /// This function is typically called when the user hits the "Download" button
    /// that is shown by the UI in case `download_state` is `'Available'` or `'Failure'`
    ///
    /// On success, the @ref DC_MSG "view type of the message" may change
    /// or the message may be replaced completely by one or more messages with other message IDs.
    /// That may happen e.g. in cases where the message was encrypted
    /// and the type could not be determined without fully downloading.
    /// Downloaded content can be accessed as usual after download.
    ///
    /// To reflect these changes a @ref DC_EVENT_MSGS_CHANGED event will be emitted.
    async fn download_full_message(&self, account_id: u32, message_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        MsgId::new(message_id).download_full(&ctx).await
    }

    /// Search messages containing the given query string.
    /// Searching can be done globally (chat_id=None) or in a specified chat only (chat_id set).
    ///
    /// Global search results are typically displayed using dc_msg_get_summary(), chat
    /// search results may just highlight the corresponding messages and present a
    /// prev/next button.
    ///
    /// For the global search, the result is limited to 1000 messages,
    /// this allows an incremental search done fast.
    /// So, when getting exactly 1000 messages, the result actually may be truncated;
    /// the UIs may display sth. like "1000+ messages found" in this case.
    /// The chat search (if chat_id is set) is not limited.
    async fn search_messages(
        &self,
        account_id: u32,
        query: String,
        chat_id: Option<u32>,
    ) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let messages = ctx.search_msgs(chat_id.map(ChatId::new), &query).await?;
        Ok(messages
            .iter()
            .map(|msg_id| msg_id.to_u32())
            .collect::<Vec<u32>>())
    }

    async fn message_ids_to_search_results(
        &self,
        account_id: u32,
        message_ids: Vec<u32>,
    ) -> Result<HashMap<u32, MessageSearchResult>> {
        let ctx = self.get_context(account_id).await?;
        let mut results: HashMap<u32, MessageSearchResult> =
            HashMap::with_capacity(message_ids.len());
        for id in message_ids {
            results.insert(
                id,
                MessageSearchResult::from_msg_id(&ctx, MsgId::new(id)).await?,
            );
        }
        Ok(results)
    }

    async fn save_msgs(&self, account_id: u32, message_ids: Vec<u32>) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let message_ids: Vec<MsgId> = message_ids.into_iter().map(MsgId::new).collect();
        chat::save_msgs(&ctx, &message_ids).await
    }

    // ---------------------------------------------
    //  contact
    // ---------------------------------------------

    /// Get a single contact options by ID.
    async fn get_contact(&self, account_id: u32, contact_id: u32) -> Result<ContactObject> {
        let ctx = self.get_context(account_id).await?;
        let contact_id = ContactId::new(contact_id);

        ContactObject::try_from_dc_contact(
            &ctx,
            deltachat::contact::Contact::get_by_id(&ctx, contact_id).await?,
        )
        .await
    }

    /// Add a single contact as a result of an explicit user action.
    ///
    /// This will always create or look up an address-contact,
    /// i.e. a contact identified by an email address,
    /// with all messages sent to and from this contact being unencrypted.
    /// If the user just clicked on an email address,
    /// you should first check [`Self::lookup_contact_id_by_addr`]/`lookupContactIdByAddr.`,
    /// and only if there is no contact yet, call this function here.
    ///
    /// Returns contact id of the created or existing contact.
    async fn create_contact(
        &self,
        account_id: u32,
        email: String,
        name: Option<String>,
    ) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        if !may_be_valid_addr(&email) {
            bail!(anyhow!(
                "provided email address is not a valid email address"
            ))
        }
        let contact_id = Contact::create(&ctx, &name.unwrap_or_default(), &email).await?;
        Ok(contact_id.to_u32())
    }

    /// Returns contact id of the created or existing DM chat with that contact
    async fn create_chat_by_contact_id(&self, account_id: u32, contact_id: u32) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        let contact = Contact::get_by_id(&ctx, ContactId::new(contact_id)).await?;
        ChatId::create_for_contact(&ctx, contact.id)
            .await
            .map(|id| id.to_u32())
    }

    async fn block_contact(&self, account_id: u32, contact_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        Contact::block(&ctx, ContactId::new(contact_id)).await
    }

    async fn unblock_contact(&self, account_id: u32, contact_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        Contact::unblock(&ctx, ContactId::new(contact_id)).await
    }

    async fn get_blocked_contacts(&self, account_id: u32) -> Result<Vec<ContactObject>> {
        let ctx = self.get_context(account_id).await?;
        let blocked_ids = Contact::get_all_blocked(&ctx).await?;
        let mut contacts: Vec<ContactObject> = Vec::with_capacity(blocked_ids.len());
        for id in blocked_ids {
            contacts.push(
                ContactObject::try_from_dc_contact(
                    &ctx,
                    deltachat::contact::Contact::get_by_id(&ctx, id).await?,
                )
                .await?,
            );
        }
        Ok(contacts)
    }

    /// Returns ids of known and unblocked contacts.
    ///
    /// By default, key-contacts are listed.
    ///
    /// * `list_flags` - A combination of flags:
    ///   - `DC_GCL_ADD_SELF` - Add SELF unless filtered by other parameters.
    ///   - `DC_GCL_ADDRESS` - List address-contacts instead of key-contacts.
    /// * `query` - A string to filter the list.
    async fn get_contact_ids(
        &self,
        account_id: u32,
        list_flags: u32,
        query: Option<String>,
    ) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let contacts = Contact::get_all(&ctx, list_flags, query.as_deref()).await?;
        Ok(contacts.into_iter().map(|c| c.to_u32()).collect())
    }

    /// Returns known and unblocked contacts.
    ///
    /// Formerly called `getContacts2` in Desktop.
    /// See [`Self::get_contact_ids`] for parameters and more info.
    async fn get_contacts(
        &self,
        account_id: u32,
        list_flags: u32,
        query: Option<String>,
    ) -> Result<Vec<ContactObject>> {
        let ctx = self.get_context(account_id).await?;
        let contact_ids = Contact::get_all(&ctx, list_flags, query.as_deref()).await?;
        let mut contacts: Vec<ContactObject> = Vec::with_capacity(contact_ids.len());
        for id in contact_ids {
            contacts.push(
                ContactObject::try_from_dc_contact(
                    &ctx,
                    deltachat::contact::Contact::get_by_id(&ctx, id).await?,
                )
                .await?,
            );
        }
        Ok(contacts)
    }

    async fn get_contacts_by_ids(
        &self,
        account_id: u32,
        ids: Vec<u32>,
    ) -> Result<HashMap<u32, ContactObject>> {
        let ctx = self.get_context(account_id).await?;

        let mut contacts = HashMap::with_capacity(ids.len());
        for id in ids {
            contacts.insert(
                id,
                ContactObject::try_from_dc_contact(
                    &ctx,
                    deltachat::contact::Contact::get_by_id(&ctx, ContactId::new(id)).await?,
                )
                .await?,
            );
        }
        Ok(contacts)
    }

    async fn delete_contact(&self, account_id: u32, contact_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let contact_id = ContactId::new(contact_id);

        Contact::delete(&ctx, contact_id).await?;
        Ok(())
    }

    /// Sets display name for existing contact.
    async fn change_contact_name(
        &self,
        account_id: u32,
        contact_id: u32,
        name: String,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let contact_id = ContactId::new(contact_id);
        contact_id.set_name(&ctx, &name).await?;
        Ok(())
    }

    /// Get encryption info for a contact.
    /// Get a multi-line encryption info, containing your fingerprint and the
    /// fingerprint of the contact, used e.g. to compare the fingerprints for a simple out-of-band verification.
    async fn get_contact_encryption_info(
        &self,
        account_id: u32,
        contact_id: u32,
    ) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        Contact::get_encrinfo(&ctx, ContactId::new(contact_id)).await
    }

    /// Looks up a known and unblocked contact with a given e-mail address.
    /// To get a list of all known and unblocked contacts, use contacts_get_contacts().
    ///
    /// **POTENTIAL SECURITY ISSUE**: If there are multiple contacts with this address
    /// (e.g. an address-contact and a key-contact),
    /// this looks up the most recently seen contact,
    /// i.e. which contact is returned depends on which contact last sent a message.
    /// If the user just clicked on a mailto: link, then this is the best thing you can do.
    /// But **DO NOT** internally represent contacts by their email address
    /// and do not use this function to look them up;
    /// otherwise this function will sometimes look up the wrong contact.
    /// Instead, you should internally represent contacts by their ids.
    ///
    /// To validate an e-mail address independently of the contact database
    /// use check_email_validity().
    async fn lookup_contact_id_by_addr(
        &self,
        account_id: u32,
        addr: String,
    ) -> Result<Option<u32>> {
        let ctx = self.get_context(account_id).await?;
        let contact_id = Contact::lookup_id_by_addr(&ctx, &addr, Origin::IncomingReplyTo).await?;
        Ok(contact_id.map(|id| id.to_u32()))
    }

    /// Parses a vCard file located at the given path. Returns contacts in their original order.
    async fn parse_vcard(&self, path: String) -> Result<Vec<VcardContact>> {
        let vcard = fs::read(Path::new(&path)).await?;
        let vcard = str::from_utf8(&vcard)?;
        Ok(deltachat_contact_tools::parse_vcard(vcard)
            .into_iter()
            .map(|c| c.into())
            .collect())
    }

    /// Imports contacts from a vCard file located at the given path.
    ///
    /// Returns the ids of created/modified contacts in the order they appear in the vCard.
    async fn import_vcard(&self, account_id: u32, path: String) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        let vcard = tokio::fs::read(Path::new(&path)).await?;
        let vcard = str::from_utf8(&vcard)?;
        Ok(deltachat::contact::import_vcard(&ctx, vcard)
            .await?
            .into_iter()
            .map(|c| c.to_u32())
            .collect())
    }

    /// Imports contacts from a vCard.
    ///
    /// Returns the ids of created/modified contacts in the order they appear in the vCard.
    async fn import_vcard_contents(&self, account_id: u32, vcard: String) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;
        Ok(deltachat::contact::import_vcard(&ctx, &vcard)
            .await?
            .into_iter()
            .map(|c| c.to_u32())
            .collect())
    }

    /// Returns a vCard containing contacts with the given ids.
    async fn make_vcard(&self, account_id: u32, contacts: Vec<u32>) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        let contacts: Vec<_> = contacts.iter().map(|&c| ContactId::new(c)).collect();
        deltachat::contact::make_vcard(&ctx, &contacts).await
    }

    /// Sets vCard containing the given contacts to the message draft.
    async fn set_draft_vcard(
        &self,
        account_id: u32,
        msg_id: u32,
        contacts: Vec<u32>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let contacts: Vec<_> = contacts.iter().map(|&c| ContactId::new(c)).collect();
        let mut msg = Message::load_from_db(&ctx, MsgId::new(msg_id)).await?;
        msg.make_vcard(&ctx, &contacts).await?;
        msg.get_chat_id().set_draft(&ctx, Some(&mut msg)).await
    }

    // ---------------------------------------------
    //                   chat
    // ---------------------------------------------

    /// Returns the [`ChatId`] for the 1:1 chat with `contact_id` if it exists.
    ///
    /// If it does not exist, `None` is returned.
    async fn get_chat_id_by_contact_id(
        &self,
        account_id: u32,
        contact_id: u32,
    ) -> Result<Option<u32>> {
        let ctx = self.get_context(account_id).await?;
        let chat_id = ChatId::lookup_by_contact(&ctx, ContactId::new(contact_id)).await?;
        Ok(chat_id.map(|id| id.to_u32()))
    }

    /// Returns all message IDs of the given types in a chat.
    /// Typically used to show a gallery.
    ///
    /// The list is already sorted and starts with the oldest message.
    /// Clients should not try to re-sort the list as this would be an expensive action
    /// and would result in inconsistencies between clients.
    ///
    /// Setting `chat_id` to `None` (`null` in typescript) means get messages with media
    /// from any chat of the currently used account.
    async fn get_chat_media(
        &self,
        account_id: u32,
        chat_id: Option<u32>,
        message_type: MessageViewtype,
        or_message_type2: Option<MessageViewtype>,
        or_message_type3: Option<MessageViewtype>,
    ) -> Result<Vec<u32>> {
        let ctx = self.get_context(account_id).await?;

        let chat_id = match chat_id {
            None | Some(0) => None,
            Some(id) => Some(ChatId::new(id)),
        };
        let msg_type = message_type.into();
        let or_msg_type2 = or_message_type2.map_or(Viewtype::Unknown, |v| v.into());
        let or_msg_type3 = or_message_type3.map_or(Viewtype::Unknown, |v| v.into());

        let media = get_chat_media(&ctx, chat_id, msg_type, or_msg_type2, or_msg_type3).await?;
        Ok(media.iter().map(|msg_id| msg_id.to_u32()).collect())
    }

    // ---------------------------------------------
    //                   backup
    // ---------------------------------------------

    async fn export_backup(
        &self,
        account_id: u32,
        destination: String,
        passphrase: Option<String>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        imex::imex(
            &ctx,
            imex::ImexMode::ExportBackup,
            destination.as_ref(),
            passphrase,
        )
        .await
    }

    async fn import_backup(
        &self,
        account_id: u32,
        path: String,
        passphrase: Option<String>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        imex::imex(
            &ctx,
            imex::ImexMode::ImportBackup,
            path.as_ref(),
            passphrase,
        )
        .await
    }

    /// Offers a backup for remote devices to retrieve.
    ///
    /// Can be canceled by stopping the ongoing process.  Success or failure can be tracked
    /// via the `ImexProgress` event which should either reach `1000` for success or `0` for
    /// failure.
    ///
    /// This **stops IO** while it is running.
    ///
    /// Returns once a remote device has retrieved the backup, or is canceled.
    async fn provide_backup(&self, account_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;

        let provider = imex::BackupProvider::prepare(&ctx).await?;
        self.with_state(account_id, |state| {
            state.backup_provider_qr.send_replace(Some(provider.qr()));
        })
        .await;

        let res = provider.await;

        self.with_state(account_id, |state| {
            state.backup_provider_qr.send_replace(None);
        })
        .await;

        res
    }

    /// Returns the text of the QR code for the running [`CommandApi::provide_backup`].
    ///
    /// This QR code text can be used in [`CommandApi::get_backup`] on a second device to
    /// retrieve the backup and setup this second device.
    ///
    /// This call will block until the QR code is ready,
    /// even if there is no concurrent call to [`CommandApi::provide_backup`],
    /// but will fail after 60 seconds to avoid deadlocks.
    async fn get_backup_qr(&self, account_id: u32) -> Result<String> {
        let qr = tokio::time::timeout(
            Duration::from_secs(60),
            self.inner_get_backup_qr(account_id),
        )
        .await
        .context("Backup provider did not start in time")?
        .context("Failed to get backup QR code")?;
        qr::format_backup(&qr)
    }

    /// Returns the rendered QR code for the running [`CommandApi::provide_backup`].
    ///
    /// This QR code can be used in [`CommandApi::get_backup`] on a second device to
    /// retrieve the backup and setup this second device.
    ///
    /// This call will block until the QR code is ready,
    /// even if there is no concurrent call to [`CommandApi::provide_backup`],
    /// but will fail after 60 seconds to avoid deadlocks.
    ///
    /// Returns the QR code rendered as an SVG image.
    async fn get_backup_qr_svg(&self, account_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        let qr = tokio::time::timeout(
            Duration::from_secs(60),
            self.inner_get_backup_qr(account_id),
        )
        .await
        .context("Backup provider did not start in time")?
        .context("Failed to get backup QR code")?;
        generate_backup_qr(&ctx, &qr).await
    }

    /// Gets a backup from a remote provider.
    ///
    /// This retrieves the backup from a remote device over the network and imports it into
    /// the current device.
    ///
    /// Can be canceled by stopping the ongoing process.
    ///
    /// Do not forget to call start_io on the account after a successful import,
    /// otherwise it will not connect to the email server.
    async fn get_backup(&self, account_id: u32, qr_text: String) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let qr = qr::check_qr(&ctx, &qr_text).await?;
        imex::get_backup(&ctx, qr).await?;
        Ok(())
    }

    // ---------------------------------------------
    //                connectivity
    // ---------------------------------------------

    /// Indicate that the network likely has come back.
    /// or just that the network conditions might have changed
    async fn maybe_network(&self) -> Result<()> {
        self.accounts.read().await.maybe_network().await;
        Ok(())
    }

    /// Get the current connectivity, i.e. whether the device is connected to the IMAP server.
    /// One of:
    /// - DC_CONNECTIVITY_NOT_CONNECTED (1000-1999): Show e.g. the string "Not connected" or a red dot
    /// - DC_CONNECTIVITY_CONNECTING (2000-2999): Show e.g. the string "Connecting…" or a yellow dot
    /// - DC_CONNECTIVITY_WORKING (3000-3999): Show e.g. the string "Getting new messages" or a spinning wheel
    /// - DC_CONNECTIVITY_CONNECTED (>=4000): Show e.g. the string "Connected" or a green dot
    ///
    /// We don't use exact values but ranges here so that we can split up
    /// states into multiple states in the future.
    ///
    /// Meant as a rough overview that can be shown
    /// e.g. in the title of the main screen.
    ///
    /// If the connectivity changes, a #DC_EVENT_CONNECTIVITY_CHANGED will be emitted.
    async fn get_connectivity(&self, account_id: u32) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        Ok(ctx.get_connectivity() as u32)
    }

    /// Get an overview of the current connectivity, and possibly more statistics.
    /// Meant to give the user more insight about the current status than
    /// the basic connectivity info returned by get_connectivity(); show this
    /// e.g., if the user taps on said basic connectivity info.
    ///
    /// If this page changes, a #DC_EVENT_CONNECTIVITY_CHANGED will be emitted.
    ///
    /// This comes as an HTML from the core so that we can easily improve it
    /// and the improvement instantly reaches all UIs.
    async fn get_connectivity_html(&self, account_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        ctx.get_connectivity_html().await
    }

    // ---------------------------------------------
    //                  locations
    // ---------------------------------------------

    async fn get_locations(
        &self,
        account_id: u32,
        chat_id: Option<u32>,
        contact_id: Option<u32>,
        timestamp_begin: i64,
        timestamp_end: i64,
    ) -> Result<Vec<JsonrpcLocation>> {
        let ctx = self.get_context(account_id).await?;

        let locations = location::get_range(
            &ctx,
            chat_id.map(ChatId::new),
            contact_id,
            timestamp_begin,
            timestamp_end,
        )
        .await?;

        Ok(locations.into_iter().map(|l| l.into()).collect())
    }

    // ---------------------------------------------
    //                   webxdc
    // ---------------------------------------------

    async fn send_webxdc_status_update(
        &self,
        account_id: u32,
        instance_msg_id: u32,
        update_str: String,
        _descr: Option<String>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.send_webxdc_status_update(MsgId::new(instance_msg_id), &update_str)
            .await
    }

    async fn send_webxdc_realtime_data(
        &self,
        account_id: u32,
        instance_msg_id: u32,
        data: Vec<u8>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        send_webxdc_realtime_data(&ctx, MsgId::new(instance_msg_id), data).await
    }

    async fn send_webxdc_realtime_advertisement(
        &self,
        account_id: u32,
        instance_msg_id: u32,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        if let Some(fut) =
            send_webxdc_realtime_advertisement(&ctx, MsgId::new(instance_msg_id)).await?
        {
            tokio::spawn(fut);
        }
        Ok(())
    }

    /// Leaves the gossip of the webxdc with the given message id.
    ///
    /// NB: When this is called before closing a webxdc app in UIs, it must be guaranteed that
    /// `send_webxdc_realtime_*()` functions aren't called for the given `instance_message_id`
    /// anymore until the app is open again.
    async fn leave_webxdc_realtime(&self, account_id: u32, instance_message_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        leave_webxdc_realtime(&ctx, MsgId::new(instance_message_id)).await
    }

    async fn get_webxdc_status_updates(
        &self,
        account_id: u32,
        instance_msg_id: u32,
        last_known_serial: u32,
    ) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        ctx.get_webxdc_status_updates(
            MsgId::new(instance_msg_id),
            StatusUpdateSerial::new(last_known_serial),
        )
        .await
    }

    /// Get info from a webxdc message
    async fn get_webxdc_info(
        &self,
        account_id: u32,
        instance_msg_id: u32,
    ) -> Result<WebxdcMessageInfo> {
        let ctx = self.get_context(account_id).await?;
        WebxdcMessageInfo::get_for_message(&ctx, MsgId::new(instance_msg_id)).await
    }

    /// Get href from a WebxdcInfoMessage which might include a hash holding
    /// information about a specific position or state in a webxdc app (optional)
    async fn get_webxdc_href(&self, account_id: u32, info_msg_id: u32) -> Result<Option<String>> {
        let ctx = self.get_context(account_id).await?;
        let message = Message::load_from_db(&ctx, MsgId::new(info_msg_id)).await?;
        Ok(message.get_webxdc_href())
    }

    /// Get blob encoded as base64 from a webxdc message
    ///
    /// path is the path of the file within webxdc archive
    async fn get_webxdc_blob(
        &self,
        account_id: u32,
        instance_msg_id: u32,
        path: String,
    ) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        let message = Message::load_from_db(&ctx, MsgId::new(instance_msg_id)).await?;
        let blob = message.get_webxdc_blob(&ctx, &path).await?;

        use base64::{engine::general_purpose, Engine as _};
        Ok(general_purpose::STANDARD_NO_PAD.encode(blob))
    }

    /// Sets Webxdc file as integration.
    /// `file` is the .xdc to use as Webxdc integration.
    async fn set_webxdc_integration(&self, account_id: u32, file_path: String) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.set_webxdc_integration(&file_path).await
    }

    /// Returns Webxdc instance used for optional integrations.
    /// UI can open the Webxdc as usual.
    /// Returns `None` if there is no integration; the caller can add one using `set_webxdc_integration` then.
    /// `integrate_for` is the chat to get the integration for.
    async fn init_webxdc_integration(
        &self,
        account_id: u32,
        chat_id: Option<u32>,
    ) -> Result<Option<u32>> {
        let ctx = self.get_context(account_id).await?;
        Ok(ctx
            .init_webxdc_integration(chat_id.map(ChatId::new))
            .await?
            .map(|msg_id| msg_id.to_u32()))
    }

    /// Starts an outgoing call.
    async fn place_outgoing_call(
        &self,
        account_id: u32,
        chat_id: u32,
        place_call_info: String,
    ) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        let msg_id = ctx
            .place_outgoing_call(ChatId::new(chat_id), place_call_info)
            .await?;
        Ok(msg_id.to_u32())
    }

    /// Accepts an incoming call.
    async fn accept_incoming_call(
        &self,
        account_id: u32,
        msg_id: u32,
        accept_call_info: String,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.accept_incoming_call(MsgId::new(msg_id), accept_call_info)
            .await?;
        Ok(())
    }

    /// Ends incoming or outgoing call.
    async fn end_call(&self, account_id: u32, msg_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ctx.end_call(MsgId::new(msg_id)).await?;
        Ok(())
    }

    /// Returns information about the call.
    async fn call_info(&self, account_id: u32, msg_id: u32) -> Result<JsonrpcCallInfo> {
        let ctx = self.get_context(account_id).await?;
        let call_info = JsonrpcCallInfo::from_msg_id(&ctx, MsgId::new(msg_id)).await?;
        Ok(call_info)
    }

    /// Returns JSON with ICE servers, to be used for WebRTC video calls.
    async fn ice_servers(&self, account_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        ice_servers(&ctx).await
    }

    /// Makes an HTTP GET request and returns a response.
    ///
    /// `url` is the HTTP or HTTPS URL.
    async fn get_http_response(&self, account_id: u32, url: String) -> Result<HttpResponse> {
        let ctx = self.get_context(account_id).await?;
        let response = deltachat::net::read_url_blob(&ctx, &url).await?.into();
        Ok(response)
    }

    /// Forward messages to another chat.
    ///
    /// All types of messages can be forwarded,
    /// however, they will be flagged as such (dc_msg_is_forwarded() is set).
    ///
    /// Original sender, info-state and webxdc updates are not forwarded on purpose.
    async fn forward_messages(
        &self,
        account_id: u32,
        message_ids: Vec<u32>,
        chat_id: u32,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let message_ids: Vec<MsgId> = message_ids.into_iter().map(MsgId::new).collect();
        forward_msgs(&ctx, &message_ids, ChatId::new(chat_id)).await
    }

    /// Forward messages to a chat in another account.
    /// See [`Self::forward_messages`] for more info.
    async fn forward_messages_to_account(
        &self,
        src_account_id: u32,
        src_message_ids: Vec<u32>,
        dst_account_id: u32,
        dst_chat_id: u32,
    ) -> Result<()> {
        let src_ctx = self.get_context(src_account_id).await?;
        let dst_ctx = self.get_context(dst_account_id).await?;
        let src_message_ids: Vec<MsgId> = src_message_ids.into_iter().map(MsgId::new).collect();
        forward_msgs_2ctx(
            &src_ctx,
            &src_message_ids,
            &dst_ctx,
            ChatId::new(dst_chat_id),
        )
        .await
    }

    /// Resend messages and make information available for newly added chat members.
    /// Resending sends out the original message, however, recipients and webxdc-status may differ.
    /// Clients that already have the original message can still ignore the resent message as
    /// they have tracked the state by dedicated updates.
    ///
    /// Some messages cannot be resent, eg. info-messages, drafts, already pending messages or messages that are not sent by SELF.
    ///
    /// message_ids all message IDs that should be resend. All messages must belong to the same chat.
    async fn resend_messages(&self, account_id: u32, message_ids: Vec<u32>) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let message_ids: Vec<MsgId> = message_ids.into_iter().map(MsgId::new).collect();
        chat::resend_msgs(&ctx, &message_ids).await
    }

    async fn send_sticker(
        &self,
        account_id: u32,
        chat_id: u32,
        sticker_path: String,
    ) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;

        let mut msg = Message::new(Viewtype::Sticker);
        msg.set_file_and_deduplicate(&ctx, Path::new(&sticker_path), None, None)?;

        // JSON-rpc does not need heuristics to turn [Viewtype::Sticker] into [Viewtype::Image]
        msg.force_sticker();

        let message_id = deltachat::chat::send_msg(&ctx, ChatId::new(chat_id), &mut msg).await?;
        Ok(message_id.to_u32())
    }

    /// Send a reaction to message.
    ///
    /// Reaction is a string of emojis separated by spaces. Reaction to a
    /// single message can be sent multiple times. The last reaction
    /// received overrides all previously received reactions. It is
    /// possible to remove all reactions by sending an empty string.
    async fn send_reaction(
        &self,
        account_id: u32,
        message_id: u32,
        reaction: Vec<String>,
    ) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        let message_id = send_reaction(&ctx, MsgId::new(message_id), &reaction.join(" ")).await?;
        Ok(message_id.to_u32())
    }

    /// Returns reactions to the message.
    async fn get_message_reactions(
        &self,
        account_id: u32,
        message_id: u32,
    ) -> Result<Option<JsonrpcReactions>> {
        let ctx = self.get_context(account_id).await?;
        let reactions = get_msg_reactions(&ctx, MsgId::new(message_id)).await?;
        if reactions.is_empty() {
            Ok(None)
        } else {
            Ok(Some(reactions.into()))
        }
    }

    async fn send_msg(&self, account_id: u32, chat_id: u32, data: MessageData) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        let mut message = data
            .create_message(&ctx)
            .await
            .context("Failed to create message")?;
        let msg_id = chat::send_msg(&ctx, ChatId::new(chat_id), &mut message)
            .await
            .context("Failed to send created message")?
            .to_u32();
        Ok(msg_id)
    }

    async fn send_edit_request(
        &self,
        account_id: u32,
        msg_id: u32,
        new_text: String,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        chat::send_edit_request(&ctx, MsgId::new(msg_id), new_text).await
    }

    /// Checks if messages can be sent to a given chat.
    async fn can_send(&self, account_id: u32, chat_id: u32) -> Result<bool> {
        let ctx = self.get_context(account_id).await?;
        let chat_id = ChatId::new(chat_id);
        let chat = Chat::load_from_db(&ctx, chat_id).await?;
        let can_send = chat.can_send(&ctx).await?;
        Ok(can_send)
    }

    /// Saves a file copy at the user-provided path.
    ///
    /// Fails if file already exists at the provided path.
    async fn save_msg_file(&self, account_id: u32, msg_id: u32, path: String) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let message = Message::load_from_db(&ctx, MsgId::new(msg_id)).await?;
        message.save_file(&ctx, Path::new(&path)).await
    }

    // ---------------------------------------------
    //           functions for the composer
    //    the composer is the message input field
    // ---------------------------------------------

    async fn remove_draft(&self, account_id: u32, chat_id: u32) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        ChatId::new(chat_id).set_draft(&ctx, None).await
    }

    ///  Get draft for a chat, if any.
    async fn get_draft(&self, account_id: u32, chat_id: u32) -> Result<Option<MessageObject>> {
        let ctx = self.get_context(account_id).await?;
        if let Some(draft) = ChatId::new(chat_id).get_draft(&ctx).await? {
            Ok(MessageObject::from_msg_id(&ctx, draft.get_id()).await?)
        } else {
            Ok(None)
        }
    }

    // ---------------------------------------------
    //           misc prototyping functions
    //       that might get removed later again
    // ---------------------------------------------

    async fn misc_get_sticker_folder(&self, account_id: u32) -> Result<String> {
        let ctx = self.get_context(account_id).await?;
        let account_folder = ctx
            .get_dbfile()
            .parent()
            .context("account folder not found")?;
        let sticker_folder_path = account_folder.join("stickers");
        fs::create_dir_all(&sticker_folder_path).await?;
        sticker_folder_path
            .to_str()
            .map(|s| s.to_owned())
            .context("path conversion to string failed")
    }

    /// Saves a sticker to a collection/folder in the account's sticker folder.
    async fn misc_save_sticker(
        &self,
        account_id: u32,
        msg_id: u32,
        collection: String,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let message = Message::load_from_db(&ctx, MsgId::new(msg_id)).await?;
        ensure!(
            message.get_viewtype() == Viewtype::Sticker,
            "message {msg_id} is not a sticker"
        );
        let account_folder = ctx
            .get_dbfile()
            .parent()
            .context("account folder not found")?;
        ensure!(
            is_sanitized(&collection),
            "illegal characters in collection name"
        );
        let destination_path = account_folder.join("stickers").join(collection);
        fs::create_dir_all(&destination_path).await?;
        let file = message.get_filename().context("no file?")?;
        message
            .save_file(
                &ctx,
                &destination_path.join(format!(
                    "{}.{}",
                    msg_id,
                    Path::new(&file)
                        .extension()
                        .unwrap_or_default()
                        .to_str()
                        .unwrap_or_default()
                )),
            )
            .await?;
        Ok(())
    }

    /// for desktop, get stickers from stickers folder,
    /// grouped by the collection/folder they are in.
    async fn misc_get_stickers(&self, account_id: u32) -> Result<HashMap<String, Vec<String>>> {
        let ctx = self.get_context(account_id).await?;
        let account_folder = ctx
            .get_dbfile()
            .parent()
            .context("account folder not found")?;
        let sticker_folder_path = account_folder.join("stickers");
        fs::create_dir_all(&sticker_folder_path).await?;
        let mut result = HashMap::new();

        let mut packs = tokio::fs::read_dir(sticker_folder_path).await?;
        while let Some(entry) = packs.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            let pack_name = entry.file_name().into_string().unwrap_or_default();
            let mut stickers = tokio::fs::read_dir(entry.path()).await?;
            let mut sticker_paths = Vec::new();
            while let Some(sticker_entry) = stickers.next_entry().await? {
                if !sticker_entry.file_type().await?.is_file() {
                    continue;
                }
                let sticker_name = sticker_entry.file_name().into_string().unwrap_or_default();
                if sticker_name.ends_with(".png") || sticker_name.ends_with(".webp") {
                    sticker_paths.push(
                        sticker_entry
                            .path()
                            .to_str()
                            .map(|s| s.to_owned())
                            .context("path conversion to string failed")?,
                    );
                }
            }
            if !sticker_paths.is_empty() {
                result.insert(pack_name, sticker_paths);
            }
        }

        Ok(result)
    }

    /// Returns the messageid of the sent message
    async fn misc_send_text_message(
        &self,
        account_id: u32,
        chat_id: u32,
        text: String,
    ) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;

        let mut msg = Message::new_text(text);

        let message_id = deltachat::chat::send_msg(&ctx, ChatId::new(chat_id), &mut msg).await?;
        Ok(message_id.to_u32())
    }

    // mimics the old desktop call, will get replaced with something better in the composer rewrite,
    // the better version will just be sending the current draft, though there will be probably something similar with more options to this for the corner cases like setting a marker on the map
    /// Send a message to a chat.
    ///
    /// This function returns after the message has been placed in the sending queue.
    /// This does not imply that the message was really sent out yet.
    /// However, from your view, you're done with the message.
    /// Sooner or later it will find its way.
    ///
    /// **Attaching files:**
    ///
    /// Pass the file path in the `file` parameter.
    /// If `file` is not in the blob directory yet,
    /// it will be copied into the blob directory.
    /// If you want, you can delete the file immediately after this function returns.
    ///
    /// You can also write the attachment directly into the blob directory
    /// and then pass the path as the `file` parameter;
    /// this will prevent an unnecessary copying of the file.
    ///
    /// In `filename`, you can pass the original name of the file,
    /// which will then be shown in the UI.
    /// in this case the current name of `file` on the filesystem will be ignored.
    ///
    /// In order to deduplicate files that contain the same data,
    /// the file will be named `<hash>.<extension>`, e.g. `ce940175885d7b78f7b7e9f1396611f.jpg`.
    ///
    /// NOTE:
    /// - This function will rename the file. To get the new file path, call `get_file()`.
    /// - The file must not be modified after this function was called.
    /// - Images etc. will NOT be recoded.
    ///   In order to recode images,
    ///   use `misc_set_draft` and pass `Image` as the viewtype.
    #[expect(clippy::too_many_arguments)]
    async fn misc_send_msg(
        &self,
        account_id: u32,
        chat_id: u32,
        text: Option<String>,
        file: Option<String>,
        filename: Option<String>,
        location: Option<(f64, f64)>,
        quoted_message_id: Option<u32>,
    ) -> Result<(u32, MessageObject)> {
        let ctx = self.get_context(account_id).await?;
        let mut message = Message::new(if file.is_some() {
            Viewtype::File
        } else {
            Viewtype::Text
        });
        message.set_text(text.unwrap_or_default());
        if let Some(file) = file {
            message.set_file_and_deduplicate(&ctx, Path::new(&file), filename.as_deref(), None)?;
        }
        if let Some((latitude, longitude)) = location {
            message.set_location(latitude, longitude);
        }
        if let Some(id) = quoted_message_id {
            message
                .set_quote(
                    &ctx,
                    Some(
                        &Message::load_from_db(&ctx, MsgId::new(id))
                            .await
                            .context("message to quote could not be loaded")?,
                    ),
                )
                .await?;
        }
        let msg_id = chat::send_msg(&ctx, ChatId::new(chat_id), &mut message).await?;
        let message = MessageObject::from_msg_id(&ctx, msg_id)
            .await?
            .context("Just sent message does not exist")?;
        Ok((msg_id.to_u32(), message))
    }

    // mimics the old desktop call, will get replaced with something better in the composer rewrite,
    // the better version should support:
    // - changing viewtype to enable/disable compression
    // - keeping same message id as long as attachment does not change for webxdc messages
    #[expect(clippy::too_many_arguments)]
    async fn misc_set_draft(
        &self,
        account_id: u32,
        chat_id: u32,
        text: Option<String>,
        file: Option<String>,
        filename: Option<String>,
        quoted_message_id: Option<u32>,
        view_type: Option<MessageViewtype>,
    ) -> Result<()> {
        let ctx = self.get_context(account_id).await?;
        let mut draft = Message::new(view_type.map_or_else(
            || {
                if file.is_some() {
                    Viewtype::File
                } else {
                    Viewtype::Text
                }
            },
            |v| v.into(),
        ));
        draft.set_text(text.unwrap_or_default());
        if let Some(file) = file {
            draft.set_file_and_deduplicate(&ctx, Path::new(&file), filename.as_deref(), None)?;
        }
        if let Some(id) = quoted_message_id {
            draft
                .set_quote(
                    &ctx,
                    Some(
                        &Message::load_from_db(&ctx, MsgId::new(id))
                            .await
                            .context("message to quote could not be loaded")?,
                    ),
                )
                .await?;
        }

        ChatId::new(chat_id).set_draft(&ctx, Some(&mut draft)).await
    }

    // send the chat's current set draft
    async fn misc_send_draft(&self, account_id: u32, chat_id: u32) -> Result<u32> {
        let ctx = self.get_context(account_id).await?;
        if let Some(draft) = ChatId::new(chat_id).get_draft(&ctx).await? {
            let mut draft = draft;
            let msg_id = chat::send_msg(&ctx, ChatId::new(chat_id), &mut draft)
                .await?
                .to_u32();
            Ok(msg_id)
        } else {
            Err(anyhow!("chat with id {chat_id} doesn't have draft message"))
        }
    }
}

// Helper functions (to prevent code duplication)
async fn set_config(
    ctx: &deltachat::context::Context,
    key: &str,
    value: Option<&str>,
) -> Result<(), anyhow::Error> {
    if key.starts_with("ui.") {
        ctx.set_ui_config(key, value).await?;
    } else {
        ctx.set_config(
            Config::from_str(key).with_context(|| format!("unknown key {key:?}"))?,
            value,
        )
        .await?;
    }
    Ok(())
}

async fn get_config(
    ctx: &deltachat::context::Context,
    key: &str,
) -> Result<Option<String>, anyhow::Error> {
    if key.starts_with("ui.") {
        ctx.get_ui_config(key).await
    } else {
        ctx.get_config(Config::from_str(key).with_context(|| format!("unknown key {key:?}"))?)
            .await
    }
}
