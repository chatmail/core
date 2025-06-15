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

use anyhow::{bail, ensure, format_err, Context as _, Result};
use async_channel::Receiver;
use async_imap::types::{Fetch, Flag, Name, NameAttribute, UnsolicitedResponse};
use deltachat_contact_tools::ContactAddress;
use futures::{FutureExt as _, StreamExt, TryStreamExt};
use futures_lite::FutureExt;
use num_traits::FromPrimitive;
use rand::Rng;
use ratelimit::Ratelimit;
use url::Url;

use crate::chat::{self, ChatId, ChatIdBlocked};
use crate::chatlist_events;
use crate::config::Config;
use crate::constants::{self, Blocked, Chattype, ShowEmails};
use crate::contact::{Contact, ContactId, Modifier, Origin};
use crate::context::Context;
use crate::events::EventType;
use crate::headerdef::{HeaderDef, HeaderDefMap};
use crate::log::{error, info, warn, LogExt};
use crate::login_param::{
    prioritize_server_login_params, ConfiguredLoginParam, ConfiguredServerLoginParam,
};
use crate::message::{self, Message, MessageState, MessengerMessage, MsgId};
use crate::mimeparser;
use crate::net::proxy::ProxyConfig;
use crate::net::session::SessionStream;
use crate::oauth2::get_oauth2_access_token;
use crate::push::encrypt_device_token;
use crate::receive_imf::{
    from_field_to_contact_id, get_prefetch_parent_message, receive_imf_inner, ReceivedMsg,
};
use crate::scheduler::connectivity::ConnectivityStore;
use crate::stock_str;
use crate::tools::{self, create_id, duration_to_str};

pub(crate) mod capabilities;
mod client;
mod idle;
pub mod scan_folders;
pub mod select_folder;
pub(crate) mod session;

use client::{determine_capabilities, Client};
use mailparse::SingleInfo;
use session::Session;

pub(crate) const GENERATED_PREFIX: &str = "GEN_";

const RFC724MID_UID: &str = "(UID BODY.PEEK[HEADER.FIELDS (\
                             MESSAGE-ID \
                             X-MICROSOFT-ORIGINAL-MESSAGE-ID\
                             )])";
const BODY_FULL: &str = "(FLAGS BODY.PEEK[])";
const BODY_PARTIAL: &str = "(FLAGS RFC822.SIZE BODY.PEEK[HEADER])";

#[derive(Debug)]
pub(crate) struct Imap {
    pub(crate) idle_interrupt_receiver: Receiver<()>,

    /// Email address.
    addr: String,

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
}

#[derive(Debug)]
struct OAuth2 {
    user: String,
    access_token: String,
}

#[derive(Debug)]
pub(crate) struct ServerMetadata {
    /// IMAP METADATA `/shared/comment` as defined in
    /// <https://www.rfc-editor.org/rfc/rfc5464#section-6.2.1>.
    pub comment: Option<String>,

    /// IMAP METADATA `/shared/admin` as defined in
    /// <https://www.rfc-editor.org/rfc/rfc5464#section-6.2.2>.
    pub admin: Option<String>,

    pub iroh_relay: Option<Url>,
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
    Sent,
    Trash,
    Drafts,

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
            FolderMeaning::Sent => Some(Config::ConfiguredSentboxFolder),
            FolderMeaning::Trash => Some(Config::ConfiguredTrashFolder),
            FolderMeaning::Drafts => None,
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
    ///
    /// `addr` is used to renew token if OAuth2 authentication is used.
    pub fn new(
        lp: Vec<ConfiguredServerLoginParam>,
        password: String,
        proxy_config: Option<ProxyConfig>,
        addr: &str,
        strict_tls: bool,
        oauth2: bool,
        idle_interrupt_receiver: Receiver<()>,
    ) -> Self {
        Imap {
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
        }
    }

    /// Creates new disconnected IMAP client using configured parameters.
    pub async fn new_configured(
        context: &Context,
        idle_interrupt_receiver: Receiver<()>,
    ) -> Result<Self> {
        let param = ConfiguredLoginParam::load(context)
            .await?
            .context("Not configured")?;
        let proxy_config = ProxyConfig::load(context).await?;
        let strict_tls = param.strict_tls(proxy_config.is_some());
        let imap = Self::new(
            param.imap.clone(),
            param.imap_password.clone(),
            proxy_config,
            &param.addr,
            strict_tls,
            param.oauth2,
            idle_interrupt_receiver,
        );
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
        self.connectivity.set_connecting(context).await;

        self.conn_last_try = tools::Time::now();
        const BACKOFF_MIN_MS: u64 = 2000;
        const BACKOFF_MAX_MS: u64 = 80_000;
        self.conn_backoff_ms = min(self.conn_backoff_ms, BACKOFF_MAX_MS / 2);
        self.conn_backoff_ms = self.conn_backoff_ms.saturating_add(
            rand::thread_rng().gen_range((self.conn_backoff_ms / 2)..=self.conn_backoff_ms),
        );
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
                connection_candidate,
            )
            .await
            .context("IMAP failed to connect")
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

                    let session = if capabilities.can_compress {
                        info!(context, "Enabling IMAP compression.");
                        let compressed_session = session
                            .compress(|s| {
                                let session_stream: Box<dyn SessionStream> = Box::new(s);
                                session_stream
                            })
                            .await
                            .context("Failed to enable IMAP compression")?;
                        Session::new(compressed_session, capabilities)
                    } else {
                        Session::new(session, capabilities)
                    };

                    // Store server ID in the context to display in account info.
                    let mut lock = context.server_id.write().await;
                    lock.clone_from(&session.capabilities.server_id);

                    self.authentication_failed_once = false;
                    context.emit_event(EventType::ImapConnected(format!(
                        "IMAP-LOGIN as {}",
                        lp.user
                    )));
                    self.connectivity.set_preparing(context).await;
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
                self.connectivity.set_err(context, &err).await;
                return Err(err);
            }
        };

        let folders_configured = context
            .sql
            .get_raw_config_int(constants::DC_FOLDERS_CONFIGURED_KEY)
            .await?;
        if folders_configured.unwrap_or_default() < constants::DC_FOLDERS_CONFIGURED_VERSION {
            let is_chatmail = match context.get_config_bool(Config::FixIsChatmail).await? {
                false => session.is_chatmail(),
                true => context.get_config_bool(Config::IsChatmail).await?,
            };
            let create_mvbox = !is_chatmail || context.get_config_bool(Config::MvboxMove).await?;
            self.configure_folders(context, &mut session, create_mvbox)
                .await?;
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

        let create = false;
        let folder_exists = session
            .select_with_uidvalidity(context, folder, create)
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

        let uid_validity = get_uidvalidity(context, folder).await?;
        let old_uid_next = get_uid_next(context, folder).await?;

        let msgs = session.prefetch(old_uid_next).await.context("prefetch")?;
        let read_cnt = msgs.len();

        let download_limit = context.download_limit().await?;
        let mut uids_fetch = Vec::<(_, bool /* partially? */)>::with_capacity(msgs.len() + 1);
        let mut uid_message_ids = BTreeMap::new();
        let mut largest_uid_skipped = None;
        let delete_target = context.get_delete_msgs_target().await?;

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

            // Determine the target folder where the message should be moved to.
            //
            // If we have seen the message on the IMAP server before, do not move it.
            // This is required to avoid infinite MOVE loop on IMAP servers
            // that alias `DeltaChat` folder to other names.
            // For example, some Dovecot servers alias `DeltaChat` folder to `INBOX.DeltaChat`.
            // In this case Delta Chat configured with `DeltaChat` as the destination folder
            // would detect messages in the `INBOX.DeltaChat` folder
            // and try to move them to the `DeltaChat` folder.
            // Such move to the same folder results in the messages
            // getting a new UID, so the messages will be detected as new
            // in the `INBOX.DeltaChat` folder again.
            let _target;
            let target = if let Some(message_id) = &message_id {
                let msg_info =
                    message::rfc724_mid_exists_ex(context, message_id, "deleted=1").await?;
                let delete = if let Some((_, _, true)) = msg_info {
                    info!(context, "Deleting locally deleted message {message_id}.");
                    true
                } else if let Some((_, ts_sent_old, _)) = msg_info {
                    let is_chat_msg = headers.get_header_value(HeaderDef::ChatVersion).is_some();
                    let ts_sent = headers
                        .get_header_value(HeaderDef::Date)
                        .and_then(|v| mailparse::dateparse(&v).ok())
                        .unwrap_or_default();
                    let is_dup = is_dup_msg(is_chat_msg, ts_sent, ts_sent_old);
                    if is_dup {
                        info!(context, "Deleting duplicate message {message_id}.");
                    }
                    is_dup
                } else {
                    false
                };
                if delete {
                    &delete_target
                } else if context
                    .sql
                    .exists(
                        "SELECT COUNT (*) FROM imap WHERE rfc724_mid=?",
                        (message_id,),
                    )
                    .await?
                {
                    info!(
                        context,
                        "Not moving the message {} that we have seen before.", &message_id
                    );
                    folder
                } else {
                    _target = target_folder(context, folder, folder_meaning, &headers).await?;
                    &_target
                }
            } else {
                // Do not move the messages without Message-ID.
                // We cannot reliably determine if we have seen them before,
                // so it is safer not to move them.
                warn!(
                    context,
                    "Not moving the message that does not have a Message-ID."
                );
                folder
            };

            // Generate a fake Message-ID to identify the message in the database
            // if the message has no real Message-ID.
            let message_id = message_id.unwrap_or_else(create_message_id);

            context
                .sql
                .execute(
                    "INSERT INTO imap (rfc724_mid, folder, uid, uidvalidity, target)
                       VALUES         (?1,         ?2,     ?3,  ?4,          ?5)
                       ON CONFLICT(folder, uid, uidvalidity)
                       DO UPDATE SET rfc724_mid=excluded.rfc724_mid,
                                     target=excluded.target",
                    (&message_id, &folder, uid, uid_validity, target),
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
                match download_limit {
                    Some(download_limit) => uids_fetch.push((
                        uid,
                        fetch_response.size.unwrap_or_default() > download_limit,
                    )),
                    None => uids_fetch.push((uid, false)),
                }
                uid_message_ids.insert(uid, message_id);
            } else {
                largest_uid_skipped = Some(uid);
            }
        }

        if !uids_fetch.is_empty() {
            self.connectivity.set_working(context).await;
        }

        // Actually download messages.
        let mut largest_uid_fetched: u32 = 0;
        let mut received_msgs = Vec::with_capacity(uids_fetch.len());
        let mut uids_fetch_in_batch = Vec::with_capacity(max(uids_fetch.len(), 1));
        let mut fetch_partially = false;
        uids_fetch.push((0, !uids_fetch.last().unwrap_or(&(0, false)).1));
        for (uid, fp) in uids_fetch {
            if fp != fetch_partially {
                let (largest_uid_fetched_in_batch, received_msgs_in_batch) = session
                    .fetch_many_msgs(
                        context,
                        folder,
                        uid_validity,
                        uids_fetch_in_batch.split_off(0),
                        &uid_message_ids,
                        fetch_partially,
                    )
                    .await
                    .context("fetch_many_msgs")?;
                received_msgs.extend(received_msgs_in_batch);
                largest_uid_fetched = max(
                    largest_uid_fetched,
                    largest_uid_fetched_in_batch.unwrap_or(0),
                );
                fetch_partially = fp;
            }
            uids_fetch_in_batch.push(uid);
        }

        // Advance uid_next to the maximum of the largest known UID plus 1
        // and mailbox UIDNEXT.
        // Largest known UID is normally less than UIDNEXT,
        // but a message may have arrived between determining UIDNEXT
        // and executing the FETCH command.
        let mailbox_uid_next = session
            .selected_mailbox
            .as_ref()
            .with_context(|| format!("Expected {folder:?} to be selected"))?
            .uid_next
            .unwrap_or_default();
        let new_uid_next = max(
            max(largest_uid_fetched, largest_uid_skipped.unwrap_or(0)) + 1,
            mailbox_uid_next,
        );

        if new_uid_next > old_uid_next {
            set_uid_next(context, folder, new_uid_next).await?;
        }

        info!(context, "{} mails read from \"{}\".", read_cnt, folder);

        if !received_msgs.is_empty() {
            context.emit_event(EventType::IncomingMsgBunch);
        }

        chat::mark_old_messages_as_noticed(context, received_msgs).await?;

        Ok(read_cnt > 0)
    }

    /// Read the recipients from old emails sent by the user and add them as contacts.
    /// This way, we can already offer them some email addresses they can write to.
    ///
    /// Then, Fetch the last messages DC_FETCH_EXISTING_MSGS_COUNT emails from the server
    /// and show them in the chat list.
    pub(crate) async fn fetch_existing_msgs(
        &mut self,
        context: &Context,
        session: &mut Session,
    ) -> Result<()> {
        add_all_recipients_as_contacts(context, session, Config::ConfiguredSentboxFolder)
            .await
            .context("failed to get recipients from the sentbox")?;
        add_all_recipients_as_contacts(context, session, Config::ConfiguredMvboxFolder)
            .await
            .context("failed to get recipients from the movebox")?;
        add_all_recipients_as_contacts(context, session, Config::ConfiguredInboxFolder)
            .await
            .context("failed to get recipients from the inbox")?;

        info!(context, "Done fetching existing messages.");
        Ok(())
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
            if folder_meaning != FolderMeaning::Virtual {
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

        let create = false;
        let folder_exists = self
            .select_with_uidvalidity(context, folder, create)
            .await?;
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

            uid_validity = get_uidvalidity(context, folder).await?;
        } else {
            warn!(context, "resync_folder_uids: No folder {folder}.");
            uid_validity = 0;
        }

        // Write collected UIDs to SQLite database.
        context
            .sql
            .transaction(move |transaction| {
                transaction.execute("DELETE FROM imap WHERE folder=?", (folder,))?;
                for (uid, (rfc724_mid, target)) in &msgs {
                    // This may detect previously undetected moved
                    // messages, so we update server_folder too.
                    transaction.execute(
                        "INSERT INTO imap (rfc724_mid, folder, uid, uidvalidity, target)
                         VALUES           (?1,         ?2,     ?3,  ?4,          ?5)
                         ON CONFLICT(folder, uid, uidvalidity)
                         DO UPDATE SET rfc724_mid=excluded.rfc724_mid,
                                       target=excluded.target",
                        (rfc724_mid, folder, uid, uid_validity, target),
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
                    if context.should_delete_to_trash().await? {
                        error!(
                            context,
                            "Cannot move messages {} to {}, no fallback to COPY/DELETE because \
                            delete_to_trash is set. Error: {:#}",
                            set,
                            target,
                            err,
                        );
                        return Err(err.into());
                    }
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
        let copy = !context.is_trash(target).await?;
        if copy {
            info!(
                context,
                "Server does not support MOVE, fallback to COPY/DELETE {} to {}", set, target
            );
            self.uid_copy(&set, &target).await?;
        } else {
            error!(
                context,
                "Server does not support MOVE, fallback to DELETE {} to {}", set, target,
            );
        }
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
        if copy {
            context.emit_event(EventType::ImapMessageMoved(format!(
                "IMAP messages {set} copied to {target}"
            )));
        }
        Ok(())
    }

    /// Moves and deletes messages as planned in the `imap` table.
    ///
    /// This is the only place where messages are moved or deleted on the IMAP server.
    async fn move_delete_messages(&mut self, context: &Context, folder: &str) -> Result<()> {
        let rows = context
            .sql
            .query_map(
                "SELECT id, uid, target FROM imap
        WHERE folder = ?
        AND target != folder
        ORDER BY target, uid",
                (folder,),
                |row| {
                    let rowid: i64 = row.get(0)?;
                    let uid: u32 = row.get(1)?;
                    let target: String = row.get(2)?;
                    Ok((rowid, uid, target))
                },
                |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
            )
            .await?;

        for (target, rowid_set, uid_set) in UidGrouper::from(rows) {
            // Select folder inside the loop to avoid selecting it if there are no pending
            // MOVE/DELETE operations. This does not result in multiple SELECT commands
            // being sent because `select_folder()` does nothing if the folder is already
            // selected.
            let create = false;
            let folder_exists = self
                .select_with_uidvalidity(context, folder, create)
                .await?;
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

    /// Uploads sync messages from the `imap_send` table with `\Seen` flag set.
    pub(crate) async fn send_sync_msgs(&mut self, context: &Context, folder: &str) -> Result<()> {
        context.send_sync_msg().await?;
        while let Some((id, mime, msg_id, attempts)) = context
            .sql
            .query_row_optional(
                "SELECT id, mime, msg_id, attempts FROM imap_send ORDER BY id LIMIT 1",
                (),
                |row| {
                    let id: i64 = row.get(0)?;
                    let mime: String = row.get(1)?;
                    let msg_id: MsgId = row.get(2)?;
                    let attempts: i64 = row.get(3)?;
                    Ok((id, mime, msg_id, attempts))
                },
            )
            .await
            .context("Failed to SELECT from imap_send")?
        {
            let res = self
                .append(folder, Some("(\\Seen)"), None, mime)
                .await
                .with_context(|| format!("IMAP APPEND to {folder} failed for {msg_id}"))
                .log_err(context);
            if res.is_ok() {
                msg_id.set_delivered(context).await?;
            }
            const MAX_ATTEMPTS: i64 = 2;
            if res.is_ok() || attempts >= MAX_ATTEMPTS - 1 {
                context
                    .sql
                    .execute("DELETE FROM imap_send WHERE id=?", (id,))
                    .await
                    .context("Failed to delete from imap_send")?;
            } else {
                context
                    .sql
                    .execute("UPDATE imap_send SET attempts=attempts+1 WHERE id=?", (id,))
                    .await
                    .context("Failed to update imap_send.attempts")?;
                res?;
            }
        }
        Ok(())
    }

    /// Stores pending `\Seen` flags for messages in `imap_markseen` table.
    pub(crate) async fn store_seen_flags_on_imap(&mut self, context: &Context) -> Result<()> {
        let rows = context
            .sql
            .query_map(
                "SELECT imap.id, uid, folder FROM imap, imap_markseen
                 WHERE imap.id = imap_markseen.id AND target = folder
                 ORDER BY folder, uid",
                [],
                |row| {
                    let rowid: i64 = row.get(0)?;
                    let uid: u32 = row.get(1)?;
                    let folder: String = row.get(2)?;
                    Ok((rowid, uid, folder))
                },
                |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
            )
            .await?;

        for (folder, rowid_set, uid_set) in UidGrouper::from(rows) {
            let create = false;
            let folder_exists = match self.select_with_uidvalidity(context, &folder, create).await {
                Err(err) => {
                    warn!(
                        context,
                        "store_seen_flags_on_imap: Failed to select {folder}, will retry later: {err:#}.");
                    continue;
                }
                Ok(folder_exists) => folder_exists,
            };
            if !folder_exists {
                warn!(context, "store_seen_flags_on_imap: No folder {folder}.");
            } else if let Err(err) = self.add_flag_finalized_with_set(&uid_set, "\\Seen").await {
                warn!(
                    context,
                    "Cannot mark messages {uid_set} in {folder} as seen, will retry later: {err:#}.");
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

        let create = false;
        let folder_exists = self
            .select_with_uidvalidity(context, folder, create)
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

        let mut updated_chat_ids = BTreeSet::new();
        let uid_validity = get_uidvalidity(context, folder)
            .await
            .with_context(|| format!("failed to get UID validity for folder {folder}"))?;
        let mut highest_modseq = get_modseq(context, folder)
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
            if is_seen {
                if let Some(chat_id) = mark_seen_by_uid(context, folder, uid_validity, uid)
                    .await
                    .with_context(|| {
                        format!("failed to update seen status for msg {folder}/{uid}")
                    })?
                {
                    updated_chat_ids.insert(chat_id);
                }
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

        set_modseq(context, folder, highest_modseq)
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

    /// Gets the from, to and bcc addresses from all existing outgoing emails.
    pub async fn get_all_recipients(&mut self, context: &Context) -> Result<Vec<SingleInfo>> {
        let mut uids: Vec<_> = self
            .uid_search(get_imap_self_sent_search_command(context).await?)
            .await?
            .into_iter()
            .collect();
        uids.sort_unstable();

        let mut result = Vec::new();
        for (_, uid_set) in build_sequence_sets(&uids)? {
            let mut list = self
                .uid_fetch(uid_set, "(UID BODY.PEEK[HEADER.FIELDS (FROM TO CC BCC)])")
                .await
                .context("IMAP Could not fetch")?;

            while let Some(msg) = list.try_next().await? {
                match get_fetch_headers(&msg) {
                    Ok(headers) => {
                        if let Some(from) = mimeparser::get_from(&headers) {
                            if context.is_self_addr(&from.addr).await? {
                                result.extend(mimeparser::get_recipients(&headers));
                            }
                        }
                    }
                    Err(err) => {
                        warn!(context, "{}", err);
                        continue;
                    }
                };
            }
        }
        Ok(result)
    }

    /// Fetches a list of messages by server UID.
    ///
    /// Returns the last UID fetched successfully and the info about each downloaded message.
    /// If the message is incorrect or there is a failure to write a message to the database,
    /// it is skipped and the error is logged.
    pub(crate) async fn fetch_many_msgs(
        &mut self,
        context: &Context,
        folder: &str,
        uidvalidity: u32,
        request_uids: Vec<u32>,
        uid_message_ids: &BTreeMap<u32, String>,
        fetch_partially: bool,
    ) -> Result<(Option<u32>, Vec<ReceivedMsg>)> {
        let mut last_uid = None;
        let mut received_msgs = Vec::new();

        if request_uids.is_empty() {
            return Ok((last_uid, received_msgs));
        }

        for (request_uids, set) in build_sequence_sets(&request_uids)? {
            info!(
                context,
                "Starting a {} FETCH of message set \"{}\".",
                if fetch_partially { "partial" } else { "full" },
                set
            );
            let mut fetch_responses = self
                .uid_fetch(
                    &set,
                    if fetch_partially {
                        BODY_PARTIAL
                    } else {
                        BODY_FULL
                    },
                )
                .await
                .with_context(|| {
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
                    let next_fetch_response =
                        if let Some(next_fetch_response) = fetch_responses.next().await {
                            next_fetch_response
                        } else {
                            // No more FETCH responses received from the server.
                            break;
                        };

                    let next_fetch_response =
                        next_fetch_response.context("Failed to process IMAP FETCH result")?;

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
                let (body, partial) = if fetch_partially {
                    (fetch_response.header(), fetch_response.size) // `BODY.PEEK[HEADER]` goes to header() ...
                } else {
                    (fetch_response.body(), None) // ... while `BODY.PEEK[]` goes to body() - and includes header()
                };

                if is_deleted {
                    info!(context, "Not processing deleted msg {}.", request_uid);
                    last_uid = Some(request_uid);
                    continue;
                }

                let body = if let Some(body) = body {
                    body
                } else {
                    info!(
                        context,
                        "Not processing message {} without a BODY.", request_uid
                    );
                    last_uid = Some(request_uid);
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
                match receive_imf_inner(
                    context,
                    folder,
                    uidvalidity,
                    request_uid,
                    rfc724_mid,
                    body,
                    is_seen,
                    partial,
                )
                .await
                {
                    Ok(received_msg) => {
                        if let Some(m) = received_msg {
                            received_msgs.push(m);
                        }
                    }
                    Err(err) => {
                        warn!(context, "receive_imf error: {:#}.", err);
                    }
                };
                last_uid = Some(request_uid)
            }

            // If we don't process the whole response, IMAP client is left in a broken state where
            // it will try to process the rest of response as the next response.
            while fetch_responses.next().await.is_some() {}

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

        Ok((last_uid, received_msgs))
    }

    /// Retrieves server metadata if it is supported.
    ///
    /// We get [`/shared/comment`](https://www.rfc-editor.org/rfc/rfc5464#section-6.2.1)
    /// and [`/shared/admin`](https://www.rfc-editor.org/rfc/rfc5464#section-6.2.2)
    /// metadata.
    pub(crate) async fn fetch_metadata(&mut self, context: &Context) -> Result<()> {
        if !self.can_metadata() {
            return Ok(());
        }

        let mut lock = context.metadata.write().await;
        if (*lock).is_some() {
            return Ok(());
        }

        info!(
            context,
            "Server supports metadata, retrieving server comment and admin contact."
        );

        let mut comment = None;
        let mut admin = None;
        let mut iroh_relay = None;

        let mailbox = "";
        let options = "";
        let metadata = self
            .get_metadata(
                mailbox,
                options,
                "(/shared/comment /shared/admin /shared/vendor/deltachat/irohrelay)",
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
                _ => {}
            }
        }
        *lock = Some(ServerMetadata {
            comment,
            admin,
            iroh_relay,
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
        while let Some(_response) = responses.next().await {
            // Read all the responses
        }
        Ok(())
    }

    /// Attempts to configure mvbox.
    ///
    /// Tries to find any folder examining `folders` in the order they go. If none is found, tries
    /// to create any folder in the same order. This method does not use LIST command to ensure that
    /// configuration works even if mailbox lookup is forbidden via Access Control List (see
    /// <https://datatracker.ietf.org/doc/html/rfc4314>).
    ///
    /// Returns first found or created folder name.
    async fn configure_mvbox<'a>(
        &mut self,
        context: &Context,
        folders: &[&'a str],
        create_mvbox: bool,
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
                let create = false;
                let folder_exists = self
                    .select_with_uidvalidity(context, folder, create)
                    .await?;
                ensure!(folder_exists, "No MVBOX folder {:?}??", &folder);
                return Ok(Some(folder));
            }
        }

        if !create_mvbox {
            return Ok(None);
        }
        // Some servers require namespace-style folder names like "INBOX.DeltaChat", so we try all
        // the variants here.
        for folder in folders {
            match self
                .select_with_uidvalidity(context, folder, create_mvbox)
                .await
            {
                Ok(_) => {
                    info!(context, "MVBOX-folder {} created.", folder);
                    return Ok(Some(folder));
                }
                Err(err) => {
                    warn!(context, "Cannot create MVBOX-folder {:?}: {}", folder, err);
                }
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
        create_mvbox: bool,
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
            if let Some(d) = folder.delimiter() {
                if delimiter_is_default && !d.is_empty() && delimiter != d {
                    delimiter = d.to_string();
                    delimiter_is_default = false;
                }
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
            .configure_mvbox(context, &["DeltaChat", &fallback_folder], create_mvbox)
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
        use async_imap::imap_proto::Response;
        use async_imap::imap_proto::ResponseCode;
        use UnsolicitedResponse::*;

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
            match from_field_to_contact_id(context, &from, true)
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
        // the inbox or sentbox where we wouldn't fetch it again:
        || context.get_config_bool(Config::OnlyFetchMvbox).await?
    {
        Ok(Some(Config::ConfiguredMvboxFolder))
    } else {
        Ok(Some(Config::ConfiguredInboxFolder))
    }
}

/// Returns `ConfiguredInboxFolder`, `ConfiguredMvboxFolder` or `ConfiguredSentboxFolder` if
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
    } else if needs_move_to_mvbox(context, headers).await? {
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
    if !context.get_config_bool(Config::IsChatmail).await?
        && has_chat_version
        && headers
            .get_header_value(HeaderDef::AutoSubmitted)
            .filter(|val| val.eq_ignore_ascii_case("auto-generated"))
            .is_some()
    {
        if let Some(from) = mimeparser::get_from(headers) {
            if context.is_self_addr(&from.addr).await? {
                return Ok(true);
            }
        }
    }
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
    const SENT_NAMES: &[&str] = &[
        "sent",
        "sentmail",
        "sent objects",
        "gesendet",
        "Sent Mail",
        "Sendte e-mails",
        "Enviados",
        "Messages envoyés",
        "Messages envoyes",
        "Posta inviata",
        "Verzonden berichten",
        "Wyslane",
        "E-mails enviados",
        "Correio enviado",
        "Enviada",
        "Enviado",
        "Gönderildi",
        "Inviati",
        "Odeslaná pošta",
        "Sendt",
        "Skickat",
        "Verzonden",
        "Wysłane",
        "Éléments envoyés",
        "Απεσταλμένα",
        "Отправленные",
        "寄件備份",
        "已发送邮件",
        "送信済み",
        "보낸편지함",
    ];
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
    const DRAFT_NAMES: &[&str] = &[
        "Drafts",
        "Kladder",
        "Entw?rfe",
        "Borradores",
        "Brouillons",
        "Bozze",
        "Concepten",
        "Wersje robocze",
        "Rascunhos",
        "Entwürfe",
        "Koncepty",
        "Kopie robocze",
        "Taslaklar",
        "Utkast",
        "Πρόχειρα",
        "Черновики",
        "下書き",
        "草稿",
        "임시보관함",
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

    if SENT_NAMES.iter().any(|s| s.to_lowercase() == lower) {
        FolderMeaning::Sent
    } else if SPAM_NAMES.iter().any(|s| s.to_lowercase() == lower) {
        FolderMeaning::Spam
    } else if DRAFT_NAMES.iter().any(|s| s.to_lowercase() == lower) {
        FolderMeaning::Drafts
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
            NameAttribute::Sent => return FolderMeaning::Sent,
            NameAttribute::Junk => return FolderMeaning::Spam,
            NameAttribute::Drafts => return FolderMeaning::Drafts,
            NameAttribute::All | NameAttribute::Flagged => return FolderMeaning::Virtual,
            NameAttribute::Extension(ref label) => {
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

/// Returns chat by prefetched headers.
async fn prefetch_get_chat(
    context: &Context,
    headers: &[mailparse::MailHeader<'_>],
) -> Result<Option<chat::Chat>> {
    let parent = get_prefetch_parent_message(context, headers).await?;
    if let Some(parent) = &parent {
        return Ok(Some(
            chat::Chat::load_from_db(context, parent.get_chat_id()).await?,
        ));
    }

    Ok(None)
}

/// Determines whether the message should be downloaded based on prefetched headers.
pub(crate) async fn prefetch_should_download(
    context: &Context,
    headers: &[mailparse::MailHeader<'_>],
    message_id: &str,
    mut flags: impl Iterator<Item = Flag<'_>>,
) -> Result<bool> {
    if message::rfc724_mid_exists(context, message_id)
        .await?
        .is_some()
    {
        markseen_on_imap_table(context, message_id).await?;
        return Ok(false);
    }

    // We do not know the Message-ID or the Message-ID is missing (in this case, we create one in
    // the further process).

    if let Some(chat) = prefetch_get_chat(context, headers).await? {
        if chat.typ == Chattype::Group && !chat.id.is_special() {
            // This might be a group command, like removing a group member.
            // We really need to fetch this to avoid inconsistent group state.
            return Ok(true);
        }
    }

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
        match from_field_to_contact_id(context, &from, true).await? {
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
        .map(|parent| match parent.is_dc_message {
            MessengerMessage::No => false,
            MessengerMessage::Yes | MessengerMessage::Reply => true,
        })
        .unwrap_or_default();

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

/// Returns whether a message is a duplicate (resent message).
pub(crate) fn is_dup_msg(is_chat_msg: bool, ts_sent: i64, ts_sent_old: i64) -> bool {
    // If the existing message has timestamp_sent == 0, that means we don't know its actual sent
    // timestamp, so don't delete the new message. E.g. outgoing messages have zero timestamp_sent
    // because they are stored to the db before sending. Also consider as duplicates only messages
    // with greater timestamp to avoid deleting both messages in a multi-device setting.
    is_chat_msg && ts_sent_old != 0 && ts_sent > ts_sent_old
}

/// Marks messages in `msgs` table as seen, searching for them by UID.
///
/// Returns updated chat ID if any message was marked as seen.
async fn mark_seen_by_uid(
    context: &Context,
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
                   WHERE folder=?1
                   AND uidvalidity=?2
                   AND uid=?3
                   LIMIT 1
                 )",
            (&folder, uid_validity, uid),
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
pub(crate) async fn set_uid_next(context: &Context, folder: &str, uid_next: u32) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO imap_sync (folder, uid_next) VALUES (?,?)
                ON CONFLICT(folder) DO UPDATE SET uid_next=excluded.uid_next",
            (folder, uid_next),
        )
        .await?;
    Ok(())
}

/// uid_next is the next unique identifier value from the last time we fetched a folder
/// See <https://tools.ietf.org/html/rfc3501#section-2.3.1.1>
/// This method returns the uid_next from the last time we fetched messages.
/// We can compare this to the current uid_next to find out whether there are new messages
/// and fetch from this value on to get all new messages.
async fn get_uid_next(context: &Context, folder: &str) -> Result<u32> {
    Ok(context
        .sql
        .query_get_value("SELECT uid_next FROM imap_sync WHERE folder=?;", (folder,))
        .await?
        .unwrap_or(0))
}

pub(crate) async fn set_uidvalidity(
    context: &Context,
    folder: &str,
    uidvalidity: u32,
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO imap_sync (folder, uidvalidity) VALUES (?,?)
                ON CONFLICT(folder) DO UPDATE SET uidvalidity=excluded.uidvalidity",
            (folder, uidvalidity),
        )
        .await?;
    Ok(())
}

async fn get_uidvalidity(context: &Context, folder: &str) -> Result<u32> {
    Ok(context
        .sql
        .query_get_value(
            "SELECT uidvalidity FROM imap_sync WHERE folder=?;",
            (folder,),
        )
        .await?
        .unwrap_or(0))
}

pub(crate) async fn set_modseq(context: &Context, folder: &str, modseq: u64) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO imap_sync (folder, modseq) VALUES (?,?)
                ON CONFLICT(folder) DO UPDATE SET modseq=excluded.modseq",
            (folder, modseq),
        )
        .await?;
    Ok(())
}

async fn get_modseq(context: &Context, folder: &str) -> Result<u64> {
    Ok(context
        .sql
        .query_get_value("SELECT modseq FROM imap_sync WHERE folder=?;", (folder,))
        .await?
        .unwrap_or(0))
}

/// Compute the imap search expression for all self-sent mails (for all self addresses)
pub(crate) async fn get_imap_self_sent_search_command(context: &Context) -> Result<String> {
    // See https://www.rfc-editor.org/rfc/rfc3501#section-6.4.4 for syntax of SEARCH and OR
    let mut search_command = format!("FROM \"{}\"", context.get_primary_self_addr().await?);

    for item in context.get_secondary_self_addrs().await? {
        search_command = format!("OR ({search_command}) (FROM \"{item}\")");
    }

    Ok(search_command)
}

/// Deprecated, use get_uid_next() and get_uidvalidity()
pub async fn get_config_last_seen_uid(context: &Context, folder: &str) -> Result<(u32, u32)> {
    let key = format!("imap.mailbox.{folder}");
    if let Some(entry) = context.sql.get_raw_config(&key).await? {
        // the entry has the format `imap.mailbox.<folder>=<uidvalidity>:<lastseenuid>`
        let mut parts = entry.split(':');
        Ok((
            parts.next().unwrap_or_default().parse().unwrap_or(0),
            parts.next().unwrap_or_default().parse().unwrap_or(0),
        ))
    } else {
        Ok((0, 0))
    }
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
    if context.is_sentbox(folder).await? {
        // Still respect the SentboxWatch setting.
        return Ok(!context.get_config_bool(Config::SentboxWatch).await?);
    }
    Ok(!(context.is_mvbox(folder).await? || folder_meaning == FolderMeaning::Spam))
}

/// Builds a list of sequence/uid sets. The returned sets have each no more than around 1000
/// characters because according to <https://tools.ietf.org/html/rfc2683#section-3.2.1.5>
/// command lines should not be much more than 1000 chars (servers should allow at least 8000 chars)
fn build_sequence_sets(uids: &[u32]) -> Result<Vec<(Vec<u32>, String)>> {
    // first, try to find consecutive ranges:
    let mut ranges: Vec<UidRange> = vec![];

    for &current in uids {
        if let Some(last) = ranges.last_mut() {
            if last.end + 1 == current {
                last.end = current;
                continue;
            }
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
async fn add_all_recipients_as_contacts(
    context: &Context,
    session: &mut Session,
    folder: Config,
) -> Result<()> {
    let mailbox = if let Some(m) = context.get_config(folder).await? {
        m
    } else {
        info!(
            context,
            "Folder {} is not configured, skipping fetching contacts from it.", folder
        );
        return Ok(());
    };
    let create = false;
    let folder_exists = session
        .select_with_uidvalidity(context, &mailbox, create)
        .await
        .with_context(|| format!("could not select {mailbox}"))?;
    if !folder_exists {
        return Ok(());
    }

    let recipients = session
        .get_all_recipients(context)
        .await
        .context("could not get recipients")?;

    let mut any_modified = false;
    for recipient in recipients {
        let recipient_addr = match ContactAddress::new(&recipient.addr) {
            Err(err) => {
                warn!(
                    context,
                    "Could not add contact for recipient with address {:?}: {:#}",
                    recipient.addr,
                    err
                );
                continue;
            }
            Ok(recipient_addr) => recipient_addr,
        };

        let (_, modified) = Contact::add_or_lookup(
            context,
            &recipient.display_name.unwrap_or_default(),
            &recipient_addr,
            Origin::OutgoingTo,
        )
        .await?;
        if modified != Modifier::None {
            any_modified = true;
        }
    }
    if any_modified {
        context.emit_event(EventType::ContactsChanged(None));
    }

    Ok(())
}

#[cfg(test)]
mod imap_tests;
