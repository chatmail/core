//! # IMAP handling module.
//!
//! uses [async-email/async-imap](https://github.com/async-email/async-imap)
//! to implement connect, fetch, delete functionality with standard IMAP servers.

use std::{
    cmp::max,
    cmp::min,
    collections::{BTreeMap, BTreeSet, HashMap},
    iter::Peekable,
    mem::take,
    sync::atomic::Ordering,
    time::{Duration, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail, ensure, format_err};
use async_channel::{self, Receiver, Sender};
use async_imap::types::{Fetch, Flag, Name, NameAttribute, UnsolicitedResponse};
use futures::{FutureExt as _, TryStreamExt};
use futures_lite::FutureExt;
use num_traits::FromPrimitive;
use ratelimit::Ratelimit;
use url::Url;

use crate::calls::{
    UnresolvedIceServer, create_fallback_ice_servers, create_ice_servers_from_metadata,
};
use crate::chat::{self, ChatId, ChatIdBlocked, add_device_msg};
use crate::chatlist_events;
use crate::config::Config;
use crate::constants::{self, Blocked, DC_VERSION_STR, ShowEmails};
use crate::contact::ContactId;
use crate::context::Context;
use crate::events::EventType;
use crate::headerdef::{HeaderDef, HeaderDefMap};
use crate::log::{LogExt, warn};
use crate::message::{self, Message, MessageState, MessengerMessage, MsgId};
use crate::mimeparser;
use crate::net::proxy::ProxyConfig;
use crate::net::session::SessionStream;
use crate::oauth2::get_oauth2_access_token;
use crate::push::encrypt_device_token;
use crate::receive_imf::{
    ReceivedMsg, from_field_to_contact_id, get_prefetch_parent_message, receive_imf_inner,
};
use crate::scheduler::connectivity::ConnectivityStore;
use crate::stock_str;
use crate::tools::{self, create_id, duration_to_str, time};
use crate::transport::{
    ConfiguredLoginParam, ConfiguredServerLoginParam, prioritize_server_login_params,
};

pub(crate) mod capabilities;
mod client;
mod idle;
pub mod select_folder;
pub(crate) mod session;

use client::{Client, determine_capabilities};
use session::Session;

pub(crate) const GENERATED_PREFIX: &str = "GEN_";

const RFC724MID_UID: &str = "(UID BODY.PEEK[HEADER.FIELDS (\
                             MESSAGE-ID \
                             X-MICROSOFT-ORIGINAL-MESSAGE-ID\
                             )])";
const BODY_FULL: &str = "(FLAGS BODY.PEEK[])";

#[derive(Debug)]
pub(crate) struct Imap {
    /// ID of the transport configuration in the `transports` table.
    ///
    /// This ID is used to namespace records in the `imap` table.
    transport_id: u32,

    pub(crate) idle_interrupt_receiver: Receiver<()>,

    /// Email address.
    pub(crate) addr: String,

    /// Login parameters.
    lp: Vec<ConfiguredServerLoginParam>,

    /// Password.
    password: String,

    /// Proxy configuration.
    proxy_config: Option<ProxyConfig>,

    strict_tls: bool,

    oauth2: bool,

    authentication_failed_once: bool,

    pub(crate) connectivity: ConnectivityStore,

    conn_last_try: tools::Time,
    conn_backoff_ms: u64,

    /// Rate limit for successful IMAP connections.
    ///
    /// This rate limit prevents busy loop in case the server refuses logins
    /// or in case connection gets dropped over and over due to IMAP bug,
    /// e.g. the server returning invalid response to SELECT command
    /// immediately after logging in or returning an error in response to LOGIN command
    /// due to internal server error.
    ratelimit: Ratelimit,

    /// IMAP UID resync request sender.
    pub(crate) resync_request_sender: async_channel::Sender<()>,

    /// IMAP UID resync request receiver.
    pub(crate) resync_request_receiver: async_channel::Receiver<()>,
}

#[derive(Debug)]
struct OAuth2 {
    user: String,
    access_token: String,
}

#[derive(Debug, Default)]
pub(crate) struct ServerMetadata {
    /// IMAP METADATA `/shared/comment` as defined in
    /// <https://www.rfc-editor.org/rfc/rfc5464#section-6.2.1>.
    pub comment: Option<String>,

    /// IMAP METADATA `/shared/admin` as defined in
    /// <https://www.rfc-editor.org/rfc/rfc5464#section-6.2.2>.
    pub admin: Option<String>,

    pub iroh_relay: Option<Url>,

    /// ICE servers for WebRTC calls.
    pub ice_servers: Vec<UnresolvedIceServer>,

    /// Timestamp when ICE servers are considered
    /// expired and should be updated.
    ///
    /// If ICE servers are about to expire, new TURN credentials
    /// should be fetched from the server
    /// to be ready for WebRTC calls.
    pub ice_servers_expiration_timestamp: i64,
}

impl async_imap::Authenticator for OAuth2 {
    type Response = String;

    fn process(&mut self, _data: &[u8]) -> Self::Response {
        format!(
            "user={}\x01auth=Bearer {}\x01\x01",
            self.user, self.access_token
        )
    }
}

#[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
pub enum FolderMeaning {
    Unknown,

    /// Spam folder.
    Spam,
    Inbox,
    Mvbox,
    Trash,

    /// Virtual folders.
    ///
    /// On Gmail there are virtual folders marked as \\All, \\Important and \\Flagged.
    /// Delta Chat ignores these folders because the same messages can be fetched
    /// from the real folder and the result of moving and deleting messages via
    /// virtual folder is unclear.
    Virtual,
}

impl FolderMeaning {
    pub fn to_config(self) -> Option<Config> {
        match self {
            FolderMeaning::Unknown => None,
            FolderMeaning::Spam => None,
            FolderMeaning::Inbox => Some(Config::ConfiguredInboxFolder),
            FolderMeaning::Mvbox => Some(Config::ConfiguredMvboxFolder),
            FolderMeaning::Trash => None,
            FolderMeaning::Virtual => None,
        }
    }
}

struct UidGrouper<T: Iterator<Item = (i64, u32, String)>> {
    inner: Peekable<T>,
}

impl<T, I> From<I> for UidGrouper<T>
where
    T: Iterator<Item = (i64, u32, String)>,
    I: IntoIterator<IntoIter = T>,
{
    fn from(inner: I) -> Self {
        Self {
            inner: inner.into_iter().peekable(),
        }
    }
}

impl<T: Iterator<Item = (i64, u32, String)>> Iterator for UidGrouper<T> {
    // Tuple of folder, row IDs, and UID range as a string.
    type Item = (String, Vec<i64>, String);

    #[expect(clippy::arithmetic_side_effects)]
    fn next(&mut self) -> Option<Self::Item> {
        let (_, _, folder) = self.inner.peek().cloned()?;

        let mut uid_set = String::new();
        let mut rowid_set = Vec::new();

        while uid_set.len() < 1000 {
            // Construct a new range.
            if let Some((start_rowid, start_uid, _)) = self
                .inner
                .next_if(|(_, _, start_folder)| start_folder == &folder)
            {
                rowid_set.push(start_rowid);
                let mut end_uid = start_uid;

                while let Some((next_rowid, next_uid, _)) =
                    self.inner.next_if(|(_, next_uid, next_folder)| {
                        next_folder == &folder && (*next_uid == end_uid + 1 || *next_uid == end_uid)
                    })
                {
                    end_uid = next_uid;
                    rowid_set.push(next_rowid);
                }

                let uid_range = UidRange {
                    start: start_uid,
                    end: end_uid,
                };
                if !uid_set.is_empty() {
                    uid_set.push(',');
                }
                uid_set.push_str(&uid_range.to_string());
            } else {
                break;
            }
        }

        Some((folder, rowid_set, uid_set))
    }
}

impl Imap {
    /// Creates new disconnected IMAP client using the specific login parameters.
    pub async fn new(
        context: &Context,
        transport_id: u32,
        param: ConfiguredLoginParam,
        idle_interrupt_receiver: Receiver<()>,
    ) -> Result<Self> {
        let lp = param.imap.clone();
        let password = param.imap_password.clone();
        let proxy_config = ProxyConfig::load(context).await?;
        let addr = &param.addr;
        let strict_tls = param.strict_tls(proxy_config.is_some());
        let oauth2 = param.oauth2;
        let (resync_request_sender, resync_request_receiver) = async_channel::bounded(1);
        Ok(Imap {
            transport_id,
            idle_interrupt_receiver,
            addr: addr.to_string(),
            lp,
            password,
            proxy_config,
            strict_tls,
            oauth2,
            authentication_failed_once: false,
            connectivity: Default::default(),
            conn_last_try: UNIX_EPOCH,
            conn_backoff_ms: 0,
            // 1 connection per minute + a burst of 2.
            ratelimit: Ratelimit::new(Duration::new(120, 0), 2.0),
            resync_request_sender,
            resync_request_receiver,
        })
    }

    /// Creates new disconnected IMAP client using configured parameters.
    pub async fn new_configured(
        context: &Context,
        idle_interrupt_receiver: Receiver<()>,
    ) -> Result<Self> {
        let (transport_id, param) = ConfiguredLoginParam::load(context)
            .await?
            .context("Not configured")?;
        let imap = Self::new(context, transport_id, param, idle_interrupt_receiver).await?;
        Ok(imap)
    }

    /// Connects to IMAP server and returns a new IMAP session.
    ///
    /// Calling this function is not enough to perform IMAP operations. Use [`Imap::prepare`]
    /// instead if you are going to actually use connection rather than trying connection
    /// parameters.
    pub(crate) async fn connect(
        &mut self,
        context: &Context,
        configuring: bool,
    ) -> Result<Session> {
        let now = tools::Time::now();
        let until_can_send = max(
            min(self.conn_last_try, now)
                .checked_add(Duration::from_millis(self.conn_backoff_ms))
                .unwrap_or(now),
            now,
        )
        .duration_since(now)?;
        let ratelimit_duration = max(until_can_send, self.ratelimit.until_can_send());
        if !ratelimit_duration.is_zero() {
            warn!(
                context,
                "IMAP got rate limited, waiting for {} until can connect.",
                duration_to_str(ratelimit_duration),
            );
            let interrupted = async {
                tokio::time::sleep(ratelimit_duration).await;
                false
            }
            .race(self.idle_interrupt_receiver.recv().map(|_| true))
            .await;
            if interrupted {
                info!(
                    context,
                    "Connecting to IMAP without waiting for ratelimit due to interrupt."
                );
            }
        }

        info!(context, "Connecting to IMAP server.");
        self.connectivity.set_connecting(context);

        self.conn_last_try = tools::Time::now();
        const BACKOFF_MIN_MS: u64 = 2000;
        const BACKOFF_MAX_MS: u64 = 80_000;
        self.conn_backoff_ms = min(self.conn_backoff_ms, BACKOFF_MAX_MS / 2);
        self.conn_backoff_ms = self.conn_backoff_ms.saturating_add(rand::random_range(
            (self.conn_backoff_ms / 2)..=self.conn_backoff_ms,
        ));
        self.conn_backoff_ms = max(BACKOFF_MIN_MS, self.conn_backoff_ms);

        let login_params = prioritize_server_login_params(&context.sql, &self.lp, "imap").await?;
        let mut first_error = None;
        for lp in login_params {
            info!(context, "IMAP trying to connect to {}.", &lp.connection);
            let connection_candidate = lp.connection.clone();
            let client = match Client::connect(
                context,
                self.proxy_config.clone(),
                self.strict_tls,
                &connection_candidate,
            )
            .await
            .with_context(|| format!("IMAP failed to connect to {connection_candidate}"))
            {
                Ok(client) => client,
                Err(err) => {
                    warn!(context, "{err:#}.");
                    first_error.get_or_insert(err);
                    continue;
                }
            };

            self.conn_backoff_ms = BACKOFF_MIN_MS;
            self.ratelimit.send();

            let imap_user: &str = lp.user.as_ref();
            let imap_pw: &str = &self.password;

            let login_res = if self.oauth2 {
                info!(context, "Logging into IMAP server with OAuth 2.");
                let addr: &str = self.addr.as_ref();

                let token = get_oauth2_access_token(context, addr, imap_pw, true)
                    .await?
                    .context("IMAP could not get OAUTH token")?;
                let auth = OAuth2 {
                    user: imap_user.into(),
                    access_token: token,
                };
                client.authenticate("XOAUTH2", auth).await
            } else {
                info!(context, "Logging into IMAP server with LOGIN.");
                client.login(imap_user, imap_pw).await
            };

            match login_res {
                Ok(mut session) => {
                    let capabilities = determine_capabilities(&mut session).await?;
                    let resync_request_sender = self.resync_request_sender.clone();

                    let session = if capabilities.can_compress {
                        info!(context, "Enabling IMAP compression.");
                        let compressed_session = session
                            .compress(|s| {
                                let session_stream: Box<dyn SessionStream> = Box::new(s);
                                session_stream
                            })
                            .await
                            .context("Failed to enable IMAP compression")?;
                        Session::new(
                            compressed_session,
                            capabilities,
                            resync_request_sender,
                            self.transport_id,
                        )
                    } else {
                        Session::new(
                            session,
                            capabilities,
                            resync_request_sender,
                            self.transport_id,
                        )
                    };

                    // Store server ID in the context to display in account info.
                    let mut lock = context.server_id.write().await;
                    lock.clone_from(&session.capabilities.server_id);

                    self.authentication_failed_once = false;
                    context.emit_event(EventType::ImapConnected(format!(
                        "IMAP-LOGIN as {}",
                        lp.user
                    )));
                    self.connectivity.set_preparing(context);
                    info!(context, "Successfully logged into IMAP server.");
                    return Ok(session);
                }

                Err(err) => {
                    let imap_user = lp.user.to_owned();
                    let message = stock_str::cannot_login(context, &imap_user).await;

                    warn!(context, "IMAP failed to login: {err:#}.");
                    first_error.get_or_insert(format_err!("{message} ({err:#})"));

                    // If it looks like the password is wrong, send a notification:
                    let _lock = context.wrong_pw_warning_mutex.lock().await;
                    if err.to_string().to_lowercase().contains("authentication") {
                        if self.authentication_failed_once
                            && !configuring
                            && context.get_config_bool(Config::NotifyAboutWrongPw).await?
                        {
                            let mut msg = Message::new_text(message);
                            if let Err(e) = chat::add_device_msg_with_importance(
                                context,
                                None,
                                Some(&mut msg),
                                true,
                            )
                            .await
                            {
                                warn!(context, "Failed to add device message: {e:#}.");
                            } else {
                                context
                                    .set_config_internal(Config::NotifyAboutWrongPw, None)
                                    .await
                                    .log_err(context)
                                    .ok();
                            }
                        } else {
                            self.authentication_failed_once = true;
                        }
                    } else {
                        self.authentication_failed_once = false;
                    }
                }
            }
        }

        Err(first_error.unwrap_or_else(|| format_err!("No IMAP connection candidates provided")))
    }

    /// Prepare a new IMAP session.
    ///
    /// This creates a new IMAP connection and ensures
    /// that folders are created and IMAP capabilities are determined.
    pub(crate) async fn prepare(&mut self, context: &Context) -> Result<Session> {
        let configuring = false;
        let mut session = match self.connect(context, configuring).await {
            Ok(session) => session,
            Err(err) => {
                self.connectivity.set_err(context, &err);
                return Err(err);
            }
        };

        let folders_configured = context
            .sql
            .get_raw_config_int(constants::DC_FOLDERS_CONFIGURED_KEY)
            .await?;
        if folders_configured.unwrap_or_default() < constants::DC_FOLDERS_CONFIGURED_VERSION {
            self.configure_folders(context, &mut session).await?;
        }

        Ok(session)
    }

    /// FETCH-MOVE-DELETE iteration.
    ///
    /// Prefetches headers and downloads new message from the folder, moves messages away from the
    /// folder and deletes messages in the folder.
    pub async fn fetch_move_delete(
        &mut self,
        context: &Context,
        session: &mut Session,
        watch_folder: &str,
        folder_meaning: FolderMeaning,
    ) -> Result<()> {
        if !context.sql.is_open().await {
            // probably shutdown
            bail!("IMAP operation attempted while it is torn down");
        }

        let msgs_fetched = self
            .fetch_new_messages(context, session, watch_folder, folder_meaning)
            .await
            .context("fetch_new_messages")?;
        if msgs_fetched && context.get_config_delete_device_after().await?.is_some() {
            // New messages were fetched and shall be deleted later, restart ephemeral loop.
            // Note that the `Config::DeleteDeviceAfter` timer starts as soon as the messages are
            // fetched while the per-chat ephemeral timers start as soon as the messages are marked
            // as noticed.
            context.scheduler.interrupt_ephemeral_task().await;
        }

        session
            .move_delete_messages(context, watch_folder)
            .await
            .context("move_delete_messages")?;

        Ok(())
    }

    /// Fetches new messages.
    ///
    /// Returns true if at least one message was fetched.
    #[expect(clippy::arithmetic_side_effects)]
    pub(crate) async fn fetch_new_messages(
        &mut self,
        context: &Context,
        session: &mut Session,
        folder: &str,
        folder_meaning: FolderMeaning,
    ) -> Result<bool> {
        if should_ignore_folder(context, folder, folder_meaning).await? {
            info!(context, "Not fetching from {folder:?}.");
            session.new_mail = false;
            return Ok(false);
        }

        let folder_exists = session
            .select_with_uidvalidity(context, folder)
            .await
            .with_context(|| format!("Failed to select folder {folder:?}"))?;
        if !folder_exists {
            return Ok(false);
        }

        if !session.new_mail {
            info!(context, "No new emails in folder {folder:?}.");
            return Ok(false);
        }
        session.new_mail = false;

        let mut read_cnt = 0;
        loop {
            let (n, fetch_more) = self
                .fetch_new_msg_batch(context, session, folder, folder_meaning)
                .await?;
            read_cnt += n;
            if !fetch_more {
                return Ok(read_cnt > 0);
            }
        }
    }

    /// Returns number of messages processed and whether the function should be called again.
    #[expect(clippy::arithmetic_side_effects)]
    async fn fetch_new_msg_batch(
        &mut self,
        context: &Context,
        session: &mut Session,
        folder: &str,
        folder_meaning: FolderMeaning,
    ) -> Result<(usize, bool)> {
        let transport_id = self.transport_id;
        let uid_validity = get_uidvalidity(context, transport_id, folder).await?;
        let old_uid_next = get_uid_next(context, transport_id, folder).await?;
        info!(
            context,
            "fetch_new_msg_batch({folder}): UIDVALIDITY={uid_validity}, UIDNEXT={old_uid_next}."
        );

        let uids_to_prefetch = 500;
        let msgs = session
            .prefetch(old_uid_next, uids_to_prefetch)
            .await
            .context("prefetch")?;
        let read_cnt = msgs.len();

        let mut uids_fetch: Vec<u32> = Vec::new();
        let mut available_post_msgs: Vec<String> = Vec::new();
        let mut download_later: Vec<String> = Vec::new();
        let mut uid_message_ids = BTreeMap::new();
        let mut largest_uid_skipped = None;

        let download_limit: Option<u32> = context
            .get_config_parsed(Config::DownloadLimit)
            .await?
            .filter(|&l| 0 < l);

        // Store the info about IMAP messages in the database.
        for (uid, ref fetch_response) in msgs {
            let headers = match get_fetch_headers(fetch_response) {
                Ok(headers) => headers,
                Err(err) => {
                    warn!(context, "Failed to parse FETCH headers: {err:#}.");
                    continue;
                }
            };

            let message_id = prefetch_get_message_id(&headers);
            let size = fetch_response
                .size
                .context("imap fetch response does not contain size")?;

            // Determine the target folder where the message should be moved to.
            //
            // We only move the messages from the INBOX and Spam folders.
            // This is required to avoid infinite MOVE loop on IMAP servers
            // that alias `DeltaChat` folder to other names.
            // For example, some Dovecot servers alias `DeltaChat` folder to `INBOX.DeltaChat`.
            // In this case moving from `INBOX.DeltaChat` to `DeltaChat`
            // results in the messages getting a new UID,
            // so the messages will be detected as new
            // in the `INBOX.DeltaChat` folder again.
            let delete = if let Some(message_id) = &message_id {
                message::rfc724_mid_exists_ex(context, message_id, "deleted=1")
                    .await?
                    .is_some_and(|(_msg_id, deleted)| deleted)
            } else {
                false
            };

            // Generate a fake Message-ID to identify the message in the database
            // if the message has no real Message-ID.
            let message_id = message_id.unwrap_or_else(create_message_id);

            if delete {
                info!(context, "Deleting locally deleted message {message_id}.");
            }

            let _target;
            let target = if delete {
                ""
            } else {
                _target = target_folder(context, folder, folder_meaning, &headers).await?;
                &_target
            };

            context
                .sql
                .execute(
                    "INSERT INTO imap (transport_id, rfc724_mid, folder, uid, uidvalidity, target)
                       VALUES         (?,            ?,          ?,      ?,   ?,           ?)
                       ON CONFLICT(transport_id, folder, uid, uidvalidity)
                       DO UPDATE SET rfc724_mid=excluded.rfc724_mid,
                                     target=excluded.target",
                    (
                        self.transport_id,
                        &message_id,
                        &folder,
                        uid,
                        uid_validity,
                        target,
                    ),
                )
                .await?;

            // Download only the messages which have reached their target folder if there are
            // multiple devices. This prevents race conditions in multidevice case, where one
            // device tries to download the message while another device moves the message at the
            // same time. Even in single device case it is possible to fail downloading the first
            // message, move it to the movebox and then download the second message before
            // downloading the first one, if downloading from inbox before moving is allowed.
            if folder == target
                // Never download messages directly from the spam folder.
                // If the sender is known, the message will be moved to the Inbox or Mvbox
                // and then we download the message from there.
                // Also see `spam_target_folder_cfg()`.
                && folder_meaning != FolderMeaning::Spam
                && prefetch_should_download(
                    context,
                    &headers,
                    &message_id,
                    fetch_response.flags(),
                )
                .await.context("prefetch_should_download")?
            {
                if headers
                    .get_header_value(HeaderDef::ChatIsPostMessage)
                    .is_some()
                {
                    info!(context, "{message_id:?} is a post-message.");
                    available_post_msgs.push(message_id.clone());

                    if download_limit.is_none_or(|download_limit| size <= download_limit) {
                        download_later.push(message_id.clone());
                    }
                    largest_uid_skipped = Some(uid);
                } else {
                    info!(context, "{message_id:?} is not a post-message.");
                    if download_limit.is_none_or(|download_limit| size <= download_limit) {
                        uids_fetch.push(uid);
                        uid_message_ids.insert(uid, message_id);
                    } else {
                        download_later.push(message_id.clone());
                        largest_uid_skipped = Some(uid);
                    }
                };
            } else {
                largest_uid_skipped = Some(uid);
            }
        }

        if !uids_fetch.is_empty() {
            self.connectivity.set_working(context);
        }

        let (sender, receiver) = async_channel::unbounded();

        let mut received_msgs = Vec::with_capacity(uids_fetch.len());
        let mailbox_uid_next = session
            .selected_mailbox
            .as_ref()
            .with_context(|| format!("Expected {folder:?} to be selected"))?
            .uid_next
            .unwrap_or_default();

        let update_uids_future = async {
            let mut largest_uid_fetched: u32 = 0;

            while let Ok((uid, received_msg_opt)) = receiver.recv().await {
                largest_uid_fetched = max(largest_uid_fetched, uid);
                if let Some(received_msg) = received_msg_opt {
                    received_msgs.push(received_msg)
                }
            }

            largest_uid_fetched
        };

        let actually_download_messages_future = async {
            session
                .fetch_many_msgs(context, folder, uids_fetch, &uid_message_ids, sender)
                .await
                .context("fetch_many_msgs")
        };

        let (largest_uid_fetched, fetch_res) =
            tokio::join!(update_uids_future, actually_download_messages_future);

        // Advance uid_next to the largest fetched UID plus 1.
        //
        // This may be larger than `mailbox_uid_next`
        // if the message has arrived after selecting mailbox
        // and determining its UIDNEXT and before prefetch.
        let mut new_uid_next = largest_uid_fetched + 1;
        let fetch_more = fetch_res.is_ok() && {
            let prefetch_uid_next = old_uid_next + uids_to_prefetch;
            // If we have successfully fetched all messages we planned during prefetch,
            // then we have covered at least the range between old UIDNEXT
            // and UIDNEXT of the mailbox at the time of selecting it.
            new_uid_next = max(new_uid_next, min(prefetch_uid_next, mailbox_uid_next));

            new_uid_next = max(new_uid_next, largest_uid_skipped.unwrap_or(0) + 1);

            prefetch_uid_next < mailbox_uid_next
        };
        if new_uid_next > old_uid_next {
            set_uid_next(context, self.transport_id, folder, new_uid_next).await?;
        }

        info!(context, "{} mails read from \"{}\".", read_cnt, folder);

        if !received_msgs.is_empty() {
            context.emit_event(EventType::IncomingMsgBunch);
        }

        chat::mark_old_messages_as_noticed(context, received_msgs).await?;

        if fetch_res.is_ok() {
            info!(
                context,
                "available_post_msgs: {}, download_later: {}.",
                available_post_msgs.len(),
                download_later.len(),
            );
            let trans_fn = |t: &mut rusqlite::Transaction| {
                let mut stmt = t.prepare("INSERT OR IGNORE INTO available_post_msgs VALUES (?)")?;
                for rfc724_mid in available_post_msgs {
                    stmt.execute((rfc724_mid,))
                        .context("INSERT OR IGNORE INTO available_post_msgs")?;
                }
                let mut stmt =
                    t.prepare("INSERT OR IGNORE INTO download (rfc724_mid, msg_id) VALUES (?,0)")?;
                for rfc724_mid in download_later {
                    stmt.execute((rfc724_mid,))
                        .context("INSERT OR IGNORE INTO download")?;
                }
                Ok(())
            };
            context.sql.transaction(trans_fn).await?;
        }

        // Now fail if fetching failed, so we will
        // establish a new session if this one is broken.
        fetch_res?;

        Ok((read_cnt, fetch_more))
    }
}

impl Session {
    /// Synchronizes UIDs for all folders.
    pub(crate) async fn resync_folders(&mut self, context: &Context) -> Result<()> {
        let all_folders = self
            .list_folders()
            .await
            .context("listing folders for resync")?;
        for folder in all_folders {
            let folder_meaning = get_folder_meaning(&folder);
            if !matches!(
                folder_meaning,
                FolderMeaning::Virtual | FolderMeaning::Unknown
            ) {
                self.resync_folder_uids(context, folder.name(), folder_meaning)
                    .await?;
            }
        }
        Ok(())
    }

    /// Synchronizes UIDs in the database with UIDs on the server.
    ///
    /// It is assumed that no operations are taking place on the same
    /// folder at the moment. Make sure to run it in the same
    /// thread/task as other network operations on this folder to
    /// avoid race conditions.
    pub(crate) async fn resync_folder_uids(
        &mut self,
        context: &Context,
        folder: &str,
        folder_meaning: FolderMeaning,
    ) -> Result<()> {
        let uid_validity;
        // Collect pairs of UID and Message-ID.
        let mut msgs = BTreeMap::new();

        let folder_exists = self.select_with_uidvalidity(context, folder).await?;
        let transport_id = self.transport_id();
        if folder_exists {
            let mut list = self
                .uid_fetch("1:*", RFC724MID_UID)
                .await
                .with_context(|| format!("Can't resync folder {folder}"))?;
            while let Some(fetch) = list.try_next().await? {
                let headers = match get_fetch_headers(&fetch) {
                    Ok(headers) => headers,
                    Err(err) => {
                        warn!(context, "Failed to parse FETCH headers: {}", err);
                        continue;
                    }
                };
                let message_id = prefetch_get_message_id(&headers);

                if let (Some(uid), Some(rfc724_mid)) = (fetch.uid, message_id) {
                    msgs.insert(
                        uid,
                        (
                            rfc724_mid,
                            target_folder(context, folder, folder_meaning, &headers).await?,
                        ),
                    );
                }
            }

            info!(
                context,
                "resync_folder_uids: Collected {} message IDs in {folder}.",
                msgs.len(),
            );

            uid_validity = get_uidvalidity(context, transport_id, folder).await?;
        } else {
            warn!(context, "resync_folder_uids: No folder {folder}.");
            uid_validity = 0;
        }

        // Write collected UIDs to SQLite database.
        context
            .sql
            .transaction(move |transaction| {
                transaction.execute("DELETE FROM imap WHERE transport_id=? AND folder=?", (transport_id, folder,))?;
                for (uid, (rfc724_mid, target)) in &msgs {
                    // This may detect previously undetected moved
                    // messages, so we update server_folder too.
                    transaction.execute(
                        "INSERT INTO imap (transport_id, rfc724_mid, folder, uid, uidvalidity, target)
                         VALUES           (?,            ?,          ?,      ?,   ?,           ?)
                         ON CONFLICT(transport_id, folder, uid, uidvalidity)
                         DO UPDATE SET rfc724_mid=excluded.rfc724_mid,
                                       target=excluded.target",
                        (transport_id, rfc724_mid, folder, uid, uid_validity, target),
                    )?;
                }
                Ok(())
            })
            .await?;
        Ok(())
    }

    /// Deletes batch of messages identified by their UID from the currently
    /// selected folder.
    async fn delete_message_batch(
        &mut self,
        context: &Context,
        uid_set: &str,
        row_ids: Vec<i64>,
    ) -> Result<()> {
        // mark the message for deletion
        self.add_flag_finalized_with_set(uid_set, "\\Deleted")
            .await?;
        context
            .sql
            .transaction(|transaction| {
                let mut stmt = transaction.prepare("DELETE FROM imap WHERE id = ?")?;
                for row_id in row_ids {
                    stmt.execute((row_id,))?;
                }
                Ok(())
            })
            .await
            .context("Cannot remove deleted messages from imap table")?;

        context.emit_event(EventType::ImapMessageDeleted(format!(
            "IMAP messages {uid_set} marked as deleted"
        )));
        Ok(())
    }

    /// Moves batch of messages identified by their UID from the currently
    /// selected folder to the target folder.
    async fn move_message_batch(
        &mut self,
        context: &Context,
        set: &str,
        row_ids: Vec<i64>,
        target: &str,
    ) -> Result<()> {
        if self.can_move() {
            match self.uid_mv(set, &target).await {
                Ok(()) => {
                    // Messages are moved or don't exist, IMAP returns OK response in both cases.
                    context
                        .sql
                        .transaction(|transaction| {
                            let mut stmt = transaction.prepare("DELETE FROM imap WHERE id = ?")?;
                            for row_id in row_ids {
                                stmt.execute((row_id,))?;
                            }
                            Ok(())
                        })
                        .await
                        .context("Cannot delete moved messages from imap table")?;
                    context.emit_event(EventType::ImapMessageMoved(format!(
                        "IMAP messages {set} moved to {target}"
                    )));
                    return Ok(());
                }
                Err(err) => {
                    warn!(
                        context,
                        "Cannot move messages, fallback to COPY/DELETE {} to {}: {}",
                        set,
                        target,
                        err
                    );
                }
            }
        }

        // Server does not support MOVE or MOVE failed.
        // Copy messages to the destination folder if needed and mark records for deletion.
        info!(
            context,
            "Server does not support MOVE, fallback to COPY/DELETE {} to {}", set, target
        );
        self.uid_copy(&set, &target).await?;
        context
            .sql
            .transaction(|transaction| {
                let mut stmt = transaction.prepare("UPDATE imap SET target='' WHERE id = ?")?;
                for row_id in row_ids {
                    stmt.execute((row_id,))?;
                }
                Ok(())
            })
            .await
            .context("Cannot plan deletion of messages")?;
        context.emit_event(EventType::ImapMessageMoved(format!(
            "IMAP messages {set} copied to {target}"
        )));
        Ok(())
    }

    /// Moves and deletes messages as planned in the `imap` table.
    ///
    /// This is the only place where messages are moved or deleted on the IMAP server.
    async fn move_delete_messages(&mut self, context: &Context, folder: &str) -> Result<()> {
        let transport_id = self.transport_id();
        let rows = context
            .sql
            .query_map_vec(
                "SELECT id, uid, target FROM imap
                 WHERE folder = ?
                 AND transport_id = ?
                 AND target != folder
                 ORDER BY target, uid",
                (folder, transport_id),
                |row| {
                    let rowid: i64 = row.get(0)?;
                    let uid: u32 = row.get(1)?;
                    let target: String = row.get(2)?;
                    Ok((rowid, uid, target))
                },
            )
            .await?;

        for (target, rowid_set, uid_set) in UidGrouper::from(rows) {
            // Select folder inside the loop to avoid selecting it if there are no pending
            // MOVE/DELETE operations. This does not result in multiple SELECT commands
            // being sent because `select_folder()` does nothing if the folder is already
            // selected.
            let folder_exists = self.select_with_uidvalidity(context, folder).await?;
            ensure!(folder_exists, "No folder {folder}");

            // Empty target folder name means messages should be deleted.
            if target.is_empty() {
                self.delete_message_batch(context, &uid_set, rowid_set)
                    .await
                    .with_context(|| format!("cannot delete batch of messages {:?}", &uid_set))?;
            } else {
                self.move_message_batch(context, &uid_set, rowid_set, &target)
                    .await
                    .with_context(|| {
                        format!(
                            "cannot move batch of messages {:?} to folder {:?}",
                            &uid_set, target
                        )
                    })?;
            }
        }

        // Expunge folder if needed, e.g. if some jobs have
        // deleted messages on the server.
        if let Err(err) = self.maybe_close_folder(context).await {
            warn!(context, "Failed to close folder: {err:#}.");
        }

        Ok(())
    }

    /// Stores pending `\Seen` flags for messages in `imap_markseen` table.
    pub(crate) async fn store_seen_flags_on_imap(&mut self, context: &Context) -> Result<()> {
        if context.get_config_bool(Config::TeamProfile).await? {
            return Ok(());
        }

        let transport_id = self.transport_id();
        let rows = context
            .sql
            .query_map_vec(
                "SELECT imap.id, uid, folder FROM imap, imap_markseen
                 WHERE imap.id = imap_markseen.id
                 AND imap.transport_id=?
                 AND target = folder
                 ORDER BY folder, uid",
                (transport_id,),
                |row| {
                    let rowid: i64 = row.get(0)?;
                    let uid: u32 = row.get(1)?;
                    let folder: String = row.get(2)?;
                    Ok((rowid, uid, folder))
                },
            )
            .await?;

        for (folder, rowid_set, uid_set) in UidGrouper::from(rows) {
            let folder_exists = match self.select_with_uidvalidity(context, &folder).await {
                Err(err) => {
                    warn!(
                        context,
                        "store_seen_flags_on_imap: Failed to select {folder}, will retry later: {err:#}."
                    );
                    continue;
                }
                Ok(folder_exists) => folder_exists,
            };
            if !folder_exists {
                warn!(context, "store_seen_flags_on_imap: No folder {folder}.");
            } else if let Err(err) = self.add_flag_finalized_with_set(&uid_set, "\\Seen").await {
                warn!(
                    context,
                    "Cannot mark messages {uid_set} in {folder} as seen, will retry later: {err:#}."
                );
                continue;
            } else {
                info!(
                    context,
                    "Marked messages {} in folder {} as seen.", uid_set, folder
                );
            }
            context
                .sql
                .transaction(|transaction| {
                    let mut stmt = transaction.prepare("DELETE FROM imap_markseen WHERE id = ?")?;
                    for rowid in rowid_set {
                        stmt.execute((rowid,))?;
                    }
                    Ok(())
                })
                .await
                .context("Cannot remove messages marked as seen from imap_markseen table")?;
        }

        Ok(())
    }

    /// Synchronizes `\Seen` flags using `CONDSTORE` extension.
    pub(crate) async fn sync_seen_flags(&mut self, context: &Context, folder: &str) -> Result<()> {
        if !self.can_condstore() {
            info!(
                context,
                "Server does not support CONDSTORE, skipping flag synchronization."
            );
            return Ok(());
        }

        if context.get_config_bool(Config::TeamProfile).await? {
            return Ok(());
        }

        let folder_exists = self
            .select_with_uidvalidity(context, folder)
            .await
            .context("Failed to select folder")?;
        if !folder_exists {
            return Ok(());
        }

        let mailbox = self
            .selected_mailbox
            .as_ref()
            .with_context(|| format!("No mailbox selected, folder: {folder}"))?;

        // Check if the mailbox supports MODSEQ.
        // We are not interested in actual value of HIGHESTMODSEQ.
        if mailbox.highest_modseq.is_none() {
            info!(
                context,
                "Mailbox {} does not support mod-sequences, skipping flag synchronization.", folder
            );
            return Ok(());
        }

        let transport_id = self.transport_id();
        let mut updated_chat_ids = BTreeSet::new();
        let uid_validity = get_uidvalidity(context, transport_id, folder)
            .await
            .with_context(|| format!("failed to get UID validity for folder {folder}"))?;
        let mut highest_modseq = get_modseq(context, transport_id, folder)
            .await
            .with_context(|| format!("failed to get MODSEQ for folder {folder}"))?;
        let mut list = self
            .uid_fetch("1:*", format!("(FLAGS) (CHANGEDSINCE {highest_modseq})"))
            .await
            .context("failed to fetch flags")?;

        let mut got_unsolicited_fetch = false;

        while let Some(fetch) = list
            .try_next()
            .await
            .context("failed to get FETCH result")?
        {
            let uid = if let Some(uid) = fetch.uid {
                uid
            } else {
                info!(context, "FETCH result contains no UID, skipping");
                got_unsolicited_fetch = true;
                continue;
            };
            let is_seen = fetch.flags().any(|flag| flag == Flag::Seen);
            if is_seen
                && let Some(chat_id) = mark_seen_by_uid(context, transport_id, folder, uid_validity, uid)
                    .await
                    .with_context(|| {
                        format!("Transport {transport_id}: Failed to update seen status for msg {folder}/{uid}")
                    })?
            {
                updated_chat_ids.insert(chat_id);
            }

            if let Some(modseq) = fetch.modseq {
                if modseq > highest_modseq {
                    highest_modseq = modseq;
                }
            } else {
                warn!(context, "FETCH result contains no MODSEQ");
            }
        }
        drop(list);

        if got_unsolicited_fetch {
            // We got unsolicited FETCH, which means some flags
            // have been modified while our request was in progress.
            // We may or may not have these new flags as a part of the response,
            // so better skip next IDLE and do another round of flag synchronization.
            self.new_mail = true;
        }

        set_modseq(context, transport_id, folder, highest_modseq)
            .await
            .with_context(|| format!("failed to set MODSEQ for folder {folder}"))?;
        if !updated_chat_ids.is_empty() {
            context.on_archived_chats_maybe_noticed();
        }
        for updated_chat_id in updated_chat_ids {
            context.emit_event(EventType::MsgsNoticed(updated_chat_id));
            chatlist_events::emit_chatlist_item_changed(context, updated_chat_id);
        }

        Ok(())
    }

    /// Fetches a list of messages by server UID.
    ///
    /// Sends pairs of UID and info about each downloaded message to the provided channel.
    /// Received message info is optional because UID may be ignored
    /// if the message has a `\Deleted` flag.
    ///
    /// The channel is used to return the results because the function may fail
    /// due to network errors before it finishes fetching all the messages.
    /// In this case caller still may want to process all the results
    /// received over the channel and persist last seen UID in the database
    /// before bubbling up the failure.
    ///
    /// If the message is incorrect or there is a failure to write a message to the database,
    /// it is skipped and the error is logged.
    #[expect(clippy::arithmetic_side_effects)]
    pub(crate) async fn fetch_many_msgs(
        &mut self,
        context: &Context,
        folder: &str,
        request_uids: Vec<u32>,
        uid_message_ids: &BTreeMap<u32, String>,
        received_msgs_channel: Sender<(u32, Option<ReceivedMsg>)>,
    ) -> Result<()> {
        if request_uids.is_empty() {
            return Ok(());
        }

        for (request_uids, set) in build_sequence_sets(&request_uids)? {
            info!(context, "Starting UID FETCH of message set \"{}\".", set);
            let mut fetch_responses = self.uid_fetch(&set, BODY_FULL).await.with_context(|| {
                format!("fetching messages {} from folder \"{}\"", &set, folder)
            })?;

            // Map from UIDs to unprocessed FETCH results. We put unprocessed FETCH results here
            // when we want to process other messages first.
            let mut uid_msgs = HashMap::with_capacity(request_uids.len());

            let mut count = 0;
            for &request_uid in &request_uids {
                // Check if FETCH response is already in `uid_msgs`.
                let mut fetch_response = uid_msgs.remove(&request_uid);

                // Try to find a requested UID in returned FETCH responses.
                while fetch_response.is_none() {
                    let Some(next_fetch_response) = fetch_responses
                        .try_next()
                        .await
                        .context("Failed to process IMAP FETCH result")?
                    else {
                        // No more FETCH responses received from the server.
                        break;
                    };

                    if let Some(next_uid) = next_fetch_response.uid {
                        if next_uid == request_uid {
                            fetch_response = Some(next_fetch_response);
                        } else if !request_uids.contains(&next_uid) {
                            // (size of `request_uids` is bounded by IMAP command length limit,
                            // search in this vector is always fast)

                            // Unwanted UIDs are possible because of unsolicited responses, e.g. if
                            // another client changes \Seen flag on a message after we do a prefetch but
                            // before fetch. It's not an error if we receive such unsolicited response.
                            info!(
                                context,
                                "Skipping not requested FETCH response for UID {}.", next_uid
                            );
                        } else if uid_msgs.insert(next_uid, next_fetch_response).is_some() {
                            warn!(context, "Got duplicated UID {}.", next_uid);
                        }
                    } else {
                        info!(context, "Skipping FETCH response without UID.");
                    }
                }

                let fetch_response = match fetch_response {
                    Some(fetch) => fetch,
                    None => {
                        warn!(
                            context,
                            "Missed UID {} in the server response.", request_uid
                        );
                        continue;
                    }
                };
                count += 1;

                let is_deleted = fetch_response.flags().any(|flag| flag == Flag::Deleted);
                let body = fetch_response.body();

                if is_deleted {
                    info!(context, "Not processing deleted msg {}.", request_uid);
                    received_msgs_channel.send((request_uid, None)).await?;
                    continue;
                }

                let body = if let Some(body) = body {
                    body
                } else {
                    info!(
                        context,
                        "Not processing message {} without a BODY.", request_uid
                    );
                    received_msgs_channel.send((request_uid, None)).await?;
                    continue;
                };

                let is_seen = fetch_response.flags().any(|flag| flag == Flag::Seen);

                let Some(rfc724_mid) = uid_message_ids.get(&request_uid) else {
                    error!(
                        context,
                        "No Message-ID corresponding to UID {} passed in uid_messsage_ids.",
                        request_uid
                    );
                    continue;
                };

                info!(
                    context,
                    "Passing message UID {} to receive_imf().", request_uid
                );
                let res = receive_imf_inner(context, rfc724_mid, body, is_seen).await;
                let received_msg = match res {
                    Err(err) => {
                        warn!(context, "receive_imf error: {err:#}.");

                        let text = format!(
                            "❌ Failed to receive a message: {err:#}. Core version v{DC_VERSION_STR}. Please report this bug to delta@merlinux.eu or https://support.delta.chat/.",
                        );
                        let mut msg = Message::new_text(text);
                        add_device_msg(context, None, Some(&mut msg)).await?;
                        None
                    }
                    Ok(msg) => msg,
                };
                received_msgs_channel
                    .send((request_uid, received_msg))
                    .await?;
            }

            // If we don't process the whole response, IMAP client is left in a broken state where
            // it will try to process the rest of response as the next response.
            //
            // Make sure to not ignore the errors, because
            // if connection times out, it will return
            // infinite stream of `Some(Err(_))` results.
            while fetch_responses
                .try_next()
                .await
                .context("Failed to drain FETCH responses")?
                .is_some()
            {}

            if count != request_uids.len() {
                warn!(
                    context,
                    "Failed to fetch all UIDs: got {}, requested {}, we requested the UIDs {:?}.",
                    count,
                    request_uids.len(),
                    request_uids,
                );
            } else {
                info!(
                    context,
                    "Successfully received {} UIDs.",
                    request_uids.len()
                );
            }
        }

        Ok(())
    }

    /// Retrieves server metadata if it is supported, otherwise uses fallback one.
    ///
    /// We get [`/shared/comment`](https://www.rfc-editor.org/rfc/rfc5464#section-6.2.1)
    /// and [`/shared/admin`](https://www.rfc-editor.org/rfc/rfc5464#section-6.2.2)
    /// metadata.
    #[expect(clippy::arithmetic_side_effects)]
    pub(crate) async fn update_metadata(&mut self, context: &Context) -> Result<()> {
        let mut lock = context.metadata.write().await;

        if !self.can_metadata() {
            *lock = Some(Default::default());
        }
        if let Some(ref mut old_metadata) = *lock {
            let now = time();

            // Refresh TURN server credentials if they expire in 12 hours.
            if now + 3600 * 12 < old_metadata.ice_servers_expiration_timestamp {
                return Ok(());
            }

            let mut got_turn_server = false;
            if self.can_metadata() {
                info!(context, "ICE servers expired, requesting new credentials.");
                let mailbox = "";
                let options = "";
                let metadata = self
                    .get_metadata(mailbox, options, "(/shared/vendor/deltachat/turn)")
                    .await?;
                for m in metadata {
                    if m.entry == "/shared/vendor/deltachat/turn"
                        && let Some(value) = m.value
                    {
                        match create_ice_servers_from_metadata(&value).await {
                            Ok((parsed_timestamp, parsed_ice_servers)) => {
                                old_metadata.ice_servers_expiration_timestamp = parsed_timestamp;
                                old_metadata.ice_servers = parsed_ice_servers;
                                got_turn_server = true;
                            }
                            Err(err) => {
                                warn!(context, "Failed to parse TURN server metadata: {err:#}.");
                            }
                        }
                    }
                }
            }
            if !got_turn_server {
                info!(context, "Will use fallback ICE servers.");
                // Set expiration timestamp 7 days in the future so we don't request it again.
                old_metadata.ice_servers_expiration_timestamp = time() + 3600 * 24 * 7;
                old_metadata.ice_servers = create_fallback_ice_servers();
            }
            return Ok(());
        }

        info!(
            context,
            "Server supports metadata, retrieving server comment and admin contact."
        );

        let mut comment = None;
        let mut admin = None;
        let mut iroh_relay = None;
        let mut ice_servers = None;
        let mut ice_servers_expiration_timestamp = 0;

        let mailbox = "";
        let options = "";
        let metadata = self
            .get_metadata(
                mailbox,
                options,
                "(/shared/comment /shared/admin /shared/vendor/deltachat/irohrelay /shared/vendor/deltachat/turn)",
            )
            .await?;
        for m in metadata {
            match m.entry.as_ref() {
                "/shared/comment" => {
                    comment = m.value;
                }
                "/shared/admin" => {
                    admin = m.value;
                }
                "/shared/vendor/deltachat/irohrelay" => {
                    if let Some(value) = m.value {
                        if let Ok(url) = Url::parse(&value) {
                            iroh_relay = Some(url);
                        } else {
                            warn!(
                                context,
                                "Got invalid URL from iroh relay metadata: {:?}.", value
                            );
                        }
                    }
                }
                "/shared/vendor/deltachat/turn" => {
                    if let Some(value) = m.value {
                        match create_ice_servers_from_metadata(&value).await {
                            Ok((parsed_timestamp, parsed_ice_servers)) => {
                                ice_servers_expiration_timestamp = parsed_timestamp;
                                ice_servers = Some(parsed_ice_servers);
                            }
                            Err(err) => {
                                warn!(context, "Failed to parse TURN server metadata: {err:#}.");
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        let ice_servers = if let Some(ice_servers) = ice_servers {
            ice_servers
        } else {
            // Set expiration timestamp 7 days in the future so we don't request it again.
            ice_servers_expiration_timestamp = time() + 3600 * 24 * 7;
            create_fallback_ice_servers()
        };

        *lock = Some(ServerMetadata {
            comment,
            admin,
            iroh_relay,
            ice_servers,
            ice_servers_expiration_timestamp,
        });
        Ok(())
    }

    /// Stores device token into /private/devicetoken IMAP METADATA of the Inbox.
    pub(crate) async fn register_token(&mut self, context: &Context) -> Result<()> {
        if context.push_subscribed.load(Ordering::Relaxed) {
            return Ok(());
        }

        let Some(device_token) = context.push_subscriber.device_token().await else {
            return Ok(());
        };

        if self.can_metadata() && self.can_push() {
            let old_encrypted_device_token =
                context.get_config(Config::EncryptedDeviceToken).await?;

            // Whether we need to update encrypted device token.
            let device_token_changed = old_encrypted_device_token.is_none()
                || context.get_config(Config::DeviceToken).await?.as_ref() != Some(&device_token);

            let new_encrypted_device_token;
            if device_token_changed {
                let encrypted_device_token = encrypt_device_token(&device_token)
                    .context("Failed to encrypt device token")?;

                // We expect that the server supporting `XDELTAPUSH` capability
                // has non-synchronizing literals support as well:
                // <https://www.rfc-editor.org/rfc/rfc7888>.
                let encrypted_device_token_len = encrypted_device_token.len();

                // Store device token saved on the server
                // to prevent storing duplicate tokens.
                // The server cannot deduplicate on its own
                // because encryption gives a different
                // result each time.
                context
                    .set_config_internal(Config::DeviceToken, Some(&device_token))
                    .await?;
                context
                    .set_config_internal(
                        Config::EncryptedDeviceToken,
                        Some(&encrypted_device_token),
                    )
                    .await?;

                if encrypted_device_token_len <= 4096 {
                    new_encrypted_device_token = Some(encrypted_device_token);
                } else {
                    // If Apple or Google (FCM) gives us a very large token,
                    // do not even try to give it to IMAP servers.
                    //
                    // Limit of 4096 is arbitrarily selected
                    // to be the same as required by LITERAL- IMAP extension.
                    //
                    // Dovecot supports LITERAL+ and non-synchronizing literals
                    // of any length, but there is no reason for tokens
                    // to be that large even after OpenPGP encryption.
                    warn!(context, "Device token is too long for LITERAL-, ignoring.");
                    new_encrypted_device_token = None;
                }
            } else {
                new_encrypted_device_token = old_encrypted_device_token;
            }

            // Store new encrypted device token on the server
            // even if it is the same as the old one.
            if let Some(encrypted_device_token) = new_encrypted_device_token {
                let folder = context
                    .get_config(Config::ConfiguredInboxFolder)
                    .await?
                    .context("INBOX is not configured")?;

                self.run_command_and_check_ok(&format_setmetadata(
                    &folder,
                    &encrypted_device_token,
                ))
                .await
                .context("SETMETADATA command failed")?;

                context.push_subscribed.store(true, Ordering::Relaxed);
            }
        } else if !context.push_subscriber.heartbeat_subscribed().await {
            let context = context.clone();
            // Subscribe for heartbeat notifications.
            tokio::spawn(async move { context.push_subscriber.subscribe(&context).await });
        }

        Ok(())
    }
}

fn format_setmetadata(folder: &str, device_token: &str) -> String {
    let device_token_len = device_token.len();
    format!(
        "SETMETADATA \"{folder}\" (/private/devicetoken {{{device_token_len}+}}\r\n{device_token})"
    )
}

impl Session {
    /// Returns success if we successfully set the flag or we otherwise
    /// think add_flag should not be retried: Disconnection during setting
    /// the flag, or other imap-errors, returns Ok as well.
    ///
    /// Returning error means that the operation can be retried.
    async fn add_flag_finalized_with_set(&mut self, uid_set: &str, flag: &str) -> Result<()> {
        if flag == "\\Deleted" {
            self.selected_folder_needs_expunge = true;
        }
        let query = format!("+FLAGS ({flag})");
        let mut responses = self
            .uid_store(uid_set, &query)
            .await
            .with_context(|| format!("IMAP failed to store: ({uid_set}, {query})"))?;
        while let Some(_response) = responses.try_next().await? {
            // Read all the responses
        }
        Ok(())
    }

    /// Attempts to configure mvbox.
    ///
    /// Tries to find any folder examining `folders` in the order they go.
    /// This method does not use LIST command to ensure that
    /// configuration works even if mailbox lookup is forbidden via Access Control List (see
    /// <https://datatracker.ietf.org/doc/html/rfc4314>).
    ///
    /// Returns first found folder name.
    async fn configure_mvbox<'a>(
        &mut self,
        context: &Context,
        folders: &[&'a str],
    ) -> Result<Option<&'a str>> {
        // Close currently selected folder if needed.
        // We are going to select folders using low-level EXAMINE operations below.
        self.maybe_close_folder(context).await?;

        for folder in folders {
            info!(context, "Looking for MVBOX-folder \"{}\"...", &folder);
            let res = self.examine(&folder).await;
            if res.is_ok() {
                info!(
                    context,
                    "MVBOX-folder {:?} successfully selected, using it.", &folder
                );
                self.close().await?;
                // Before moving emails to the mvbox we need to remember its UIDVALIDITY, otherwise
                // emails moved before that wouldn't be fetched but considered "old" instead.
                let folder_exists = self.select_with_uidvalidity(context, folder).await?;
                ensure!(folder_exists, "No MVBOX folder {:?}??", &folder);
                return Ok(Some(folder));
            }
        }

        Ok(None)
    }
}

impl Imap {
    pub(crate) async fn configure_folders(
        &mut self,
        context: &Context,
        session: &mut Session,
    ) -> Result<()> {
        let mut folders = session
            .list(Some(""), Some("*"))
            .await
            .context("list_folders failed")?;
        let mut delimiter = ".".to_string();
        let mut delimiter_is_default = true;
        let mut folder_configs = BTreeMap::new();

        while let Some(folder) = folders.try_next().await? {
            info!(context, "Scanning folder: {:?}", folder);

            // Update the delimiter iff there is a different one, but only once.
            if let Some(d) = folder.delimiter()
                && delimiter_is_default
                && !d.is_empty()
                && delimiter != d
            {
                delimiter = d.to_string();
                delimiter_is_default = false;
            }

            let folder_meaning = get_folder_meaning_by_attrs(folder.attributes());
            let folder_name_meaning = get_folder_meaning_by_name(folder.name());
            if let Some(config) = folder_meaning.to_config() {
                // Always takes precedence
                folder_configs.insert(config, folder.name().to_string());
            } else if let Some(config) = folder_name_meaning.to_config() {
                // only set if none has been already set
                folder_configs
                    .entry(config)
                    .or_insert_with(|| folder.name().to_string());
            }
        }
        drop(folders);

        info!(context, "Using \"{}\" as folder-delimiter.", delimiter);

        let fallback_folder = format!("INBOX{delimiter}DeltaChat");
        let mvbox_folder = session
            .configure_mvbox(context, &["DeltaChat", &fallback_folder])
            .await
            .context("failed to configure mvbox")?;

        context
            .set_config_internal(Config::ConfiguredInboxFolder, Some("INBOX"))
            .await?;
        if let Some(mvbox_folder) = mvbox_folder {
            info!(context, "Setting MVBOX FOLDER TO {}", &mvbox_folder);
            context
                .set_config_internal(Config::ConfiguredMvboxFolder, Some(mvbox_folder))
                .await?;
        }
        for (config, name) in folder_configs {
            context.set_config_internal(config, Some(&name)).await?;
        }
        context
            .sql
            .set_raw_config_int(
                constants::DC_FOLDERS_CONFIGURED_KEY,
                constants::DC_FOLDERS_CONFIGURED_VERSION,
            )
            .await?;

        info!(context, "FINISHED configuring IMAP-folders.");
        Ok(())
    }
}

impl Session {
    /// Return whether the server sent an unsolicited EXISTS or FETCH response.
    ///
    /// Drains all responses from `session.unsolicited_responses` in the process.
    ///
    /// If this returns `true`, this means that new emails arrived
    /// or flags have been changed.
    /// In this case we may want to skip next IDLE and do a round
    /// of fetching new messages and synchronizing seen flags.
    fn drain_unsolicited_responses(&self, context: &Context) -> Result<bool> {
        use UnsolicitedResponse::*;
        use async_imap::imap_proto::Response;
        use async_imap::imap_proto::ResponseCode;

        let folder = self.selected_folder.as_deref().unwrap_or_default();
        let mut should_refetch = false;
        while let Ok(response) = self.unsolicited_responses.try_recv() {
            match response {
                Exists(_) => {
                    info!(
                        context,
                        "Need to refetch {folder:?}, got unsolicited EXISTS {response:?}"
                    );
                    should_refetch = true;
                }

                Expunge(_) | Recent(_) => {}
                Other(ref response_data) => {
                    match response_data.parsed() {
                        Response::Fetch { .. } => {
                            info!(
                                context,
                                "Need to refetch {folder:?}, got unsolicited FETCH {response:?}"
                            );
                            should_refetch = true;
                        }

                        // We are not interested in the following responses and they are are
                        // sent quite frequently, so, we ignore them without logging them.
                        Response::Done {
                            code: Some(ResponseCode::CopyUid(_, _, _)),
                            ..
                        } => {}

                        _ => {
                            info!(context, "{folder:?}: got unsolicited response {response:?}")
                        }
                    }
                }
                _ => {
                    info!(context, "{folder:?}: got unsolicited response {response:?}")
                }
            }
        }
        Ok(should_refetch)
    }
}

async fn should_move_out_of_spam(
    context: &Context,
    headers: &[mailparse::MailHeader<'_>],
) -> Result<bool> {
    if headers.get_header_value(HeaderDef::ChatVersion).is_some() {
        // If this is a chat message (i.e. has a ChatVersion header), then this might be
        // a securejoin message. We can't find out at this point as we didn't prefetch
        // the SecureJoin header. So, we always move chat messages out of Spam.
        // Two possibilities to change this would be:
        // 1. Remove the `&& !context.is_spam_folder(folder).await?` check from
        // `fetch_new_messages()`, and then let `receive_imf()` check
        // if it's a spam message and should be hidden.
        // 2. Or add a flag to the ChatVersion header that this is a securejoin
        // request, and return `true` here only if the message has this flag.
        // `receive_imf()` can then check if the securejoin request is valid.
        return Ok(true);
    }

    if let Some(msg) = get_prefetch_parent_message(context, headers).await? {
        if msg.chat_blocked != Blocked::Not {
            // Blocked or contact request message in the spam folder, leave it there.
            return Ok(false);
        }
    } else {
        let from = match mimeparser::get_from(headers) {
            Some(f) => f,
            None => return Ok(false),
        };
        // No chat found.
        let (from_id, blocked_contact, _origin) =
            match from_field_to_contact_id(context, &from, None, true, true)
                .await
                .context("from_field_to_contact_id")?
            {
                Some(res) => res,
                None => {
                    warn!(
                        context,
                        "Contact with From address {:?} cannot exist, not moving out of spam", from
                    );
                    return Ok(false);
                }
            };
        if blocked_contact {
            // Contact is blocked, leave the message in spam.
            return Ok(false);
        }

        if let Some(chat_id_blocked) = ChatIdBlocked::lookup_by_contact(context, from_id).await? {
            if chat_id_blocked.blocked != Blocked::Not {
                return Ok(false);
            }
        } else if from_id != ContactId::SELF {
            // No chat with this contact found.
            return Ok(false);
        }
    }

    Ok(true)
}

/// Returns target folder for a message found in the Spam folder.
/// If this returns None, the message will not be moved out of the
/// Spam folder, and as `fetch_new_messages()` doesn't download
/// messages from the Spam folder, the message will be ignored.
async fn spam_target_folder_cfg(
    context: &Context,
    headers: &[mailparse::MailHeader<'_>],
) -> Result<Option<Config>> {
    if !should_move_out_of_spam(context, headers).await? {
        return Ok(None);
    }

    if needs_move_to_mvbox(context, headers).await?
        // If OnlyFetchMvbox is set, we don't want to move the message to
        // the inbox where we wouldn't fetch it again:
        || context.get_config_bool(Config::OnlyFetchMvbox).await?
    {
        Ok(Some(Config::ConfiguredMvboxFolder))
    } else {
        Ok(Some(Config::ConfiguredInboxFolder))
    }
}

/// Returns `ConfiguredInboxFolder` or `ConfiguredMvboxFolder` if
/// the message needs to be moved from `folder`. Otherwise returns `None`.
pub async fn target_folder_cfg(
    context: &Context,
    folder: &str,
    folder_meaning: FolderMeaning,
    headers: &[mailparse::MailHeader<'_>],
) -> Result<Option<Config>> {
    if context.is_mvbox(folder).await? {
        return Ok(None);
    }

    if folder_meaning == FolderMeaning::Spam {
        spam_target_folder_cfg(context, headers).await
    } else if folder_meaning == FolderMeaning::Inbox
        && needs_move_to_mvbox(context, headers).await?
    {
        Ok(Some(Config::ConfiguredMvboxFolder))
    } else {
        Ok(None)
    }
}

pub async fn target_folder(
    context: &Context,
    folder: &str,
    folder_meaning: FolderMeaning,
    headers: &[mailparse::MailHeader<'_>],
) -> Result<String> {
    match target_folder_cfg(context, folder, folder_meaning, headers).await? {
        Some(config) => match context.get_config(config).await? {
            Some(target) => Ok(target),
            None => Ok(folder.to_string()),
        },
        None => Ok(folder.to_string()),
    }
}

async fn needs_move_to_mvbox(
    context: &Context,
    headers: &[mailparse::MailHeader<'_>],
) -> Result<bool> {
    let has_chat_version = headers.get_header_value(HeaderDef::ChatVersion).is_some();
    if !context.get_config_bool(Config::MvboxMove).await? {
        return Ok(false);
    }

    if headers
        .get_header_value(HeaderDef::AutocryptSetupMessage)
        .is_some()
    {
        // do not move setup messages;
        // there may be a non-delta device that wants to handle it
        return Ok(false);
    }

    if has_chat_version {
        Ok(true)
    } else if let Some(parent) = get_prefetch_parent_message(context, headers).await? {
        match parent.is_dc_message {
            MessengerMessage::No => Ok(false),
            MessengerMessage::Yes | MessengerMessage::Reply => Ok(true),
        }
    } else {
        Ok(false)
    }
}

/// Try to get the folder meaning by the name of the folder only used if the server does not support XLIST.
// TODO: lots languages missing - maybe there is a list somewhere on other MUAs?
// however, if we fail to find out the sent-folder,
// only watching this folder is not working. at least, this is no show stopper.
// CAVE: if possible, take care not to add a name here that is "sent" in one language
// but sth. different in others - a hard job.
fn get_folder_meaning_by_name(folder_name: &str) -> FolderMeaning {
    // source: <https://stackoverflow.com/questions/2185391/localized-gmail-imap-folders>
    const SPAM_NAMES: &[&str] = &[
        "spam",
        "junk",
        "Correio electrónico não solicitado",
        "Correo basura",
        "Lixo",
        "Nettsøppel",
        "Nevyžádaná pošta",
        "No solicitado",
        "Ongewenst",
        "Posta indesiderata",
        "Skräp",
        "Wiadomości-śmieci",
        "Önemsiz",
        "Ανεπιθύμητα",
        "Спам",
        "垃圾邮件",
        "垃圾郵件",
        "迷惑メール",
        "스팸",
    ];
    const TRASH_NAMES: &[&str] = &[
        "Trash",
        "Bin",
        "Caixote do lixo",
        "Cestino",
        "Corbeille",
        "Papelera",
        "Papierkorb",
        "Papirkurv",
        "Papperskorgen",
        "Prullenbak",
        "Rubujo",
        "Κάδος απορριμμάτων",
        "Корзина",
        "Кошик",
        "ゴミ箱",
        "垃圾桶",
        "已删除邮件",
        "휴지통",
    ];
    let lower = folder_name.to_lowercase();

    if lower == "inbox" {
        FolderMeaning::Inbox
    } else if SPAM_NAMES.iter().any(|s| s.to_lowercase() == lower) {
        FolderMeaning::Spam
    } else if TRASH_NAMES.iter().any(|s| s.to_lowercase() == lower) {
        FolderMeaning::Trash
    } else {
        FolderMeaning::Unknown
    }
}

fn get_folder_meaning_by_attrs(folder_attrs: &[NameAttribute]) -> FolderMeaning {
    for attr in folder_attrs {
        match attr {
            NameAttribute::Trash => return FolderMeaning::Trash,
            NameAttribute::Junk => return FolderMeaning::Spam,
            NameAttribute::All | NameAttribute::Flagged => return FolderMeaning::Virtual,
            NameAttribute::Extension(label) => {
                match label.as_ref() {
                    "\\Spam" => return FolderMeaning::Spam,
                    "\\Important" => return FolderMeaning::Virtual,
                    _ => {}
                };
            }
            _ => {}
        }
    }
    FolderMeaning::Unknown
}

pub(crate) fn get_folder_meaning(folder: &Name) -> FolderMeaning {
    match get_folder_meaning_by_attrs(folder.attributes()) {
        FolderMeaning::Unknown => get_folder_meaning_by_name(folder.name()),
        meaning => meaning,
    }
}

/// Parses the headers from the FETCH result.
fn get_fetch_headers(prefetch_msg: &Fetch) -> Result<Vec<mailparse::MailHeader<'_>>> {
    match prefetch_msg.header() {
        Some(header_bytes) => {
            let (headers, _) = mailparse::parse_headers(header_bytes)?;
            Ok(headers)
        }
        None => Ok(Vec::new()),
    }
}

pub(crate) fn prefetch_get_message_id(headers: &[mailparse::MailHeader]) -> Option<String> {
    headers
        .get_header_value(HeaderDef::XMicrosoftOriginalMessageId)
        .or_else(|| headers.get_header_value(HeaderDef::MessageId))
        .and_then(|msgid| mimeparser::parse_message_id(&msgid).ok())
}

pub(crate) fn create_message_id() -> String {
    format!("{}{}", GENERATED_PREFIX, create_id())
}

/// Determines whether the message should be downloaded based on prefetched headers.
pub(crate) async fn prefetch_should_download(
    context: &Context,
    headers: &[mailparse::MailHeader<'_>],
    message_id: &str,
    mut flags: impl Iterator<Item = Flag<'_>>,
) -> Result<bool> {
    if message::rfc724_mid_download_tried(context, message_id).await? {
        if let Some(from) = mimeparser::get_from(headers)
            && context.is_self_addr(&from.addr).await?
        {
            markseen_on_imap_table(context, message_id).await?;
        }
        return Ok(false);
    }

    // We do not know the Message-ID or the Message-ID is missing (in this case, we create one in
    // the further process).

    let maybe_ndn = if let Some(from) = headers.get_header_value(HeaderDef::From_) {
        let from = from.to_ascii_lowercase();
        from.contains("mailer-daemon") || from.contains("mail-daemon")
    } else {
        false
    };

    // Autocrypt Setup Message should be shown even if it is from non-chat client.
    let is_autocrypt_setup_message = headers
        .get_header_value(HeaderDef::AutocryptSetupMessage)
        .is_some();

    let from = match mimeparser::get_from(headers) {
        Some(f) => f,
        None => return Ok(false),
    };
    let (_from_id, blocked_contact, origin) =
        match from_field_to_contact_id(context, &from, None, true, true).await? {
            Some(res) => res,
            None => return Ok(false),
        };
    // prevent_rename=true as this might be a mailing list message and in this case it would be bad if we rename the contact.
    // (prevent_rename is the last argument of from_field_to_contact_id())

    if flags.any(|f| f == Flag::Draft) {
        info!(context, "Ignoring draft message");
        return Ok(false);
    }

    let is_chat_message = headers.get_header_value(HeaderDef::ChatVersion).is_some();
    let accepted_contact = origin.is_known();
    let is_reply_to_chat_message = get_prefetch_parent_message(context, headers)
        .await?
        .is_some_and(|parent| match parent.is_dc_message {
            MessengerMessage::No => false,
            MessengerMessage::Yes | MessengerMessage::Reply => true,
        });

    let show_emails =
        ShowEmails::from_i32(context.get_config_int(Config::ShowEmails).await?).unwrap_or_default();

    let show = is_autocrypt_setup_message
        || match show_emails {
            ShowEmails::Off => is_chat_message || is_reply_to_chat_message,
            ShowEmails::AcceptedContacts => {
                is_chat_message || is_reply_to_chat_message || accepted_contact
            }
            ShowEmails::All => true,
        };

    let should_download = (show && !blocked_contact) || maybe_ndn;
    Ok(should_download)
}

/// Marks messages in `msgs` table as seen, searching for them by UID.
///
/// Returns updated chat ID if any message was marked as seen.
async fn mark_seen_by_uid(
    context: &Context,
    transport_id: u32,
    folder: &str,
    uid_validity: u32,
    uid: u32,
) -> Result<Option<ChatId>> {
    if let Some((msg_id, chat_id)) = context
        .sql
        .query_row_optional(
            "SELECT id, chat_id FROM msgs
                 WHERE id > 9 AND rfc724_mid IN (
                   SELECT rfc724_mid FROM imap
                   WHERE transport_id=?
                   AND folder=?
                   AND uidvalidity=?
                   AND uid=?
                   LIMIT 1
                 )",
            (transport_id, &folder, uid_validity, uid),
            |row| {
                let msg_id: MsgId = row.get(0)?;
                let chat_id: ChatId = row.get(1)?;
                Ok((msg_id, chat_id))
            },
        )
        .await
        .with_context(|| format!("failed to get msg and chat ID for IMAP message {folder}/{uid}"))?
    {
        let updated = context
            .sql
            .execute(
                "UPDATE msgs SET state=?1
                     WHERE (state=?2 OR state=?3)
                     AND id=?4",
                (
                    MessageState::InSeen,
                    MessageState::InFresh,
                    MessageState::InNoticed,
                    msg_id,
                ),
            )
            .await
            .with_context(|| format!("failed to update msg {msg_id} state"))?
            > 0;

        if updated {
            msg_id
                .start_ephemeral_timer(context)
                .await
                .with_context(|| format!("failed to start ephemeral timer for message {msg_id}"))?;
            Ok(Some(chat_id))
        } else {
            // Message state has not changed.
            Ok(None)
        }
    } else {
        // There is no message is `msgs` table matching the given UID.
        Ok(None)
    }
}

/// Schedule marking the message as Seen on IMAP by adding all known IMAP messages corresponding to
/// the given Message-ID to `imap_markseen` table.
pub(crate) async fn markseen_on_imap_table(context: &Context, message_id: &str) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT OR IGNORE INTO imap_markseen (id)
             SELECT id FROM imap WHERE rfc724_mid=?",
            (message_id,),
        )
        .await?;
    context.scheduler.interrupt_inbox().await;

    Ok(())
}

/// uid_next is the next unique identifier value from the last time we fetched a folder
/// See <https://tools.ietf.org/html/rfc3501#section-2.3.1.1>
/// This function is used to update our uid_next after fetching messages.
pub(crate) async fn set_uid_next(
    context: &Context,
    transport_id: u32,
    folder: &str,
    uid_next: u32,
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO imap_sync (transport_id, folder, uid_next) VALUES (?, ?,?)
                ON CONFLICT(transport_id, folder) DO UPDATE SET uid_next=excluded.uid_next",
            (transport_id, folder, uid_next),
        )
        .await?;
    Ok(())
}

/// uid_next is the next unique identifier value from the last time we fetched a folder
/// See <https://tools.ietf.org/html/rfc3501#section-2.3.1.1>
/// This method returns the uid_next from the last time we fetched messages.
/// We can compare this to the current uid_next to find out whether there are new messages
/// and fetch from this value on to get all new messages.
async fn get_uid_next(context: &Context, transport_id: u32, folder: &str) -> Result<u32> {
    Ok(context
        .sql
        .query_get_value(
            "SELECT uid_next FROM imap_sync WHERE transport_id=? AND folder=?",
            (transport_id, folder),
        )
        .await?
        .unwrap_or(0))
}

pub(crate) async fn set_uidvalidity(
    context: &Context,
    transport_id: u32,
    folder: &str,
    uidvalidity: u32,
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO imap_sync (transport_id, folder, uidvalidity) VALUES (?,?,?)
                ON CONFLICT(transport_id, folder) DO UPDATE SET uidvalidity=excluded.uidvalidity",
            (transport_id, folder, uidvalidity),
        )
        .await?;
    Ok(())
}

async fn get_uidvalidity(context: &Context, transport_id: u32, folder: &str) -> Result<u32> {
    Ok(context
        .sql
        .query_get_value(
            "SELECT uidvalidity FROM imap_sync WHERE transport_id=? AND folder=?",
            (transport_id, folder),
        )
        .await?
        .unwrap_or(0))
}

pub(crate) async fn set_modseq(
    context: &Context,
    transport_id: u32,
    folder: &str,
    modseq: u64,
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO imap_sync (transport_id, folder, modseq) VALUES (?,?,?)
                ON CONFLICT(transport_id, folder) DO UPDATE SET modseq=excluded.modseq",
            (transport_id, folder, modseq),
        )
        .await?;
    Ok(())
}

async fn get_modseq(context: &Context, transport_id: u32, folder: &str) -> Result<u64> {
    Ok(context
        .sql
        .query_get_value(
            "SELECT modseq FROM imap_sync WHERE transport_id=? AND folder=?",
            (transport_id, folder),
        )
        .await?
        .unwrap_or(0))
}

/// Whether to ignore fetching messages from a folder.
///
/// This caters for the [`Config::OnlyFetchMvbox`] setting which means mails from folders
/// not explicitly watched should not be fetched.
async fn should_ignore_folder(
    context: &Context,
    folder: &str,
    folder_meaning: FolderMeaning,
) -> Result<bool> {
    if !context.get_config_bool(Config::OnlyFetchMvbox).await? {
        return Ok(false);
    }
    Ok(!(context.is_mvbox(folder).await? || folder_meaning == FolderMeaning::Spam))
}

/// Builds a list of sequence/uid sets. The returned sets have each no more than around 1000
/// characters because according to <https://tools.ietf.org/html/rfc2683#section-3.2.1.5>
/// command lines should not be much more than 1000 chars (servers should allow at least 8000 chars)
#[expect(clippy::arithmetic_side_effects)]
fn build_sequence_sets(uids: &[u32]) -> Result<Vec<(Vec<u32>, String)>> {
    // first, try to find consecutive ranges:
    let mut ranges: Vec<UidRange> = vec![];

    for &current in uids {
        if let Some(last) = ranges.last_mut()
            && last.end + 1 == current
        {
            last.end = current;
            continue;
        }

        ranges.push(UidRange {
            start: current,
            end: current,
        });
    }

    // Second, sort the uids into uid sets that are each below ~1000 characters
    let mut result = vec![];
    let (mut last_uids, mut last_str) = (Vec::new(), String::new());
    for range in ranges {
        last_uids.reserve((range.end - range.start + 1).try_into()?);
        (range.start..=range.end).for_each(|u| last_uids.push(u));
        if !last_str.is_empty() {
            last_str.push(',');
        }
        last_str.push_str(&range.to_string());

        if last_str.len() > 990 {
            result.push((take(&mut last_uids), take(&mut last_str)));
        }
    }
    result.push((last_uids, last_str));

    result.retain(|(_, s)| !s.is_empty());
    Ok(result)
}

struct UidRange {
    start: u32,
    end: u32,
    // If start == end, then this range represents a single number
}

impl std::fmt::Display for UidRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}:{}", self.start, self.end)
        }
    }
}

pub(crate) async fn get_watched_folder_configs(context: &Context) -> Result<Vec<Config>> {
    let mut res = vec![Config::ConfiguredInboxFolder];
    if context.should_watch_mvbox().await? {
        res.push(Config::ConfiguredMvboxFolder);
    }
    Ok(res)
}

pub(crate) async fn get_watched_folders(context: &Context) -> Result<Vec<String>> {
    let mut res = Vec::new();
    for folder_config in get_watched_folder_configs(context).await? {
        if let Some(folder) = context.get_config(folder_config).await? {
            res.push(folder);
        }
    }
    Ok(res)
}

#[cfg(test)]
mod imap_tests;
