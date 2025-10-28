//! Utilities to help writing tests.
//!
//! This private module is only compiled for test runs.
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::env::current_dir;
use std::fmt::Write;
use std::ops::{Deref, DerefMut};
use std::panic;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use async_channel::{self as channel, Receiver, Sender};
use chat::ChatItem;
use deltachat_contact_tools::{ContactAddress, EmailAddress};
use nu_ansi_term::Color;
use pretty_assertions::assert_eq;
use tempfile::{TempDir, tempdir};
use tokio::runtime::Handle;
use tokio::{fs, task};

use crate::chat::{
    self, Chat, ChatId, ChatIdBlocked, MessageListOptions, add_to_chat_contacts_table, create_group,
};
use crate::chatlist::Chatlist;
use crate::config::Config;
use crate::constants::{Blocked, Chattype};
use crate::constants::{DC_CHAT_ID_TRASH, DC_GCL_NO_SPECIALS};
use crate::contact::{
    Contact, ContactId, Modifier, Origin, import_vcard, make_vcard, mark_contact_id_as_verified,
};
use crate::context::Context;
use crate::events::{Event, EventEmitter, EventType, Events};
use crate::key::{self, DcKey, DcSecretKey, self_fingerprint};
use crate::log::warn;
use crate::message::{Message, MessageState, MsgId, update_msg_state};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::pgp::KeyPair;
use crate::receive_imf::receive_imf;
use crate::securejoin::{get_securejoin_qr, join_securejoin};
use crate::stock_str::StockStrings;
use crate::tools::time;

/// The number of info messages added to new e2ee chats.
/// Currently this is "End-to-end encryption available", string `E2eAvailable`.
pub const E2EE_INFO_MSGS: usize = 1;

#[allow(non_upper_case_globals)]
pub const AVATAR_900x900_BYTES: &[u8] = include_bytes!("../test-data/image/avatar900x900.png");

#[allow(non_upper_case_globals)]
pub const AVATAR_64x64_BYTES: &[u8] = include_bytes!("../test-data/image/avatar64x64.png");

/// The filename of [`AVATAR_64x64_BYTES`],
/// after it has been saved
/// by [`crate::blob::BlobObject::create_and_deduplicate`].
#[allow(non_upper_case_globals)]
pub const AVATAR_64x64_DEDUPLICATED: &str = "e9b6c7a78aa2e4f415644f55a553e73.png";

/// Map of context IDs to names for [`TestContext`]s.
static CONTEXT_NAMES: LazyLock<std::sync::RwLock<BTreeMap<u32, String>>> =
    LazyLock::new(|| std::sync::RwLock::new(BTreeMap::new()));

/// Manage multiple [`TestContext`]s in one place.
///
/// The main advantage is that the log records of the contexts will appear in the order they
/// occurred rather than grouped by context like would happen when you use separate
/// [`TestContext`]s without managing your own [`LogSink`].
pub struct TestContextManager {
    log_sink: LogSink,
    used_names: BTreeSet<String>,
}

impl TestContextManager {
    pub fn new() -> Self {
        Self {
            log_sink: LogSink::new(),
            used_names: BTreeSet::new(),
        }
    }

    pub async fn alice(&mut self) -> TestContext {
        TestContext::builder()
            .configure_alice()
            .with_id_offset(1000)
            .with_log_sink(self.log_sink.clone())
            .build(Some(&mut self.used_names))
            .await
    }

    pub async fn bob(&mut self) -> TestContext {
        TestContext::builder()
            .configure_bob()
            .with_id_offset(2000)
            .with_log_sink(self.log_sink.clone())
            .build(Some(&mut self.used_names))
            .await
    }

    pub async fn charlie(&mut self) -> TestContext {
        TestContext::builder()
            .configure_charlie()
            .with_id_offset(3000)
            .with_log_sink(self.log_sink.clone())
            .build(Some(&mut self.used_names))
            .await
    }

    pub async fn dom(&mut self) -> TestContext {
        TestContext::builder()
            .configure_dom()
            .with_id_offset(4000)
            .with_log_sink(self.log_sink.clone())
            .build(Some(&mut self.used_names))
            .await
    }

    pub async fn elena(&mut self) -> TestContext {
        TestContext::builder()
            .configure_elena()
            .with_id_offset(5000)
            .with_log_sink(self.log_sink.clone())
            .build(Some(&mut self.used_names))
            .await
    }

    pub async fn fiona(&mut self) -> TestContext {
        TestContext::builder()
            .configure_fiona()
            .with_id_offset(6000)
            .with_log_sink(self.log_sink.clone())
            .build(Some(&mut self.used_names))
            .await
    }

    /// Creates a new unconfigured test account.
    pub async fn unconfigured(&mut self) -> TestContext {
        TestContext::builder()
            .with_log_sink(self.log_sink.clone())
            .build(Some(&mut self.used_names))
            .await
    }

    /// Writes info events to the log that mark a section, e.g.:
    ///
    /// ========== `msg` goes here ==========
    pub fn section(&self, msg: &str) {
        self.log_sink
            .sender
            .try_send(LogEvent::Section(msg.to_string()))
            .expect(
            "The events channel should be unbounded and not closed, so try_send() shouldn't fail",
        );
    }

    /// - Let one TestContext send a message
    /// - Let the other TestContext receive it and accept the chat
    /// - Assert that the message arrived
    pub async fn send_recv_accept(
        &self,
        from: &TestContext,
        to: &TestContext,
        msg: &str,
    ) -> Message {
        let received_msg = self.send_recv(from, to, msg).await;
        assert_eq!(
            received_msg.chat_blocked,
            Blocked::Request,
            "`send_recv_accept()` is meant to be used for chat requests. Use `send_recv()` if the chat is already accepted."
        );
        received_msg.chat_id.accept(to).await.unwrap();
        received_msg
    }

    /// - Let one TestContext send a message
    /// - Let the other TestContext receive it
    /// - Assert that the message arrived
    pub async fn send_recv(&self, from: &TestContext, to: &TestContext, msg: &str) -> Message {
        let received_msg = self.try_send_recv(from, to, msg).await;
        assert_eq!(received_msg.text, msg);
        received_msg
    }

    /// - Let one TestContext send a message
    /// - Let the other TestContext receive it
    pub async fn try_send_recv(&self, from: &TestContext, to: &TestContext, msg: &str) -> Message {
        self.section(&format!(
            "{} sends a message '{}' to {}",
            from.name(),
            msg,
            to.name()
        ));
        let chat_id = from.create_chat_id(to).await;
        let sent = from.send_text(chat_id, msg).await;
        to.recv_msg(&sent).await
    }

    pub async fn change_addr(&self, test_context: &TestContext, new_addr: &str) {
        self.section(&format!(
            "{} changes her self address and reconfigures",
            test_context.name()
        ));
        test_context.set_primary_self_addr(new_addr).await.unwrap();
        // ensure_secret_key_exists() is called during configure
        crate::e2ee::ensure_secret_key_exists(test_context)
            .await
            .unwrap();

        assert_eq!(
            test_context.get_primary_self_addr().await.unwrap(),
            new_addr
        );
    }

    /// Executes SecureJoin protocol between `scanner` and `scanned`.
    ///
    /// Returns chat ID of the 1:1 chat for `scanner`.
    pub async fn execute_securejoin(&self, scanner: &TestContext, scanned: &TestContext) -> ChatId {
        self.section(&format!(
            "{} scans {}'s QR code",
            scanner.name(),
            scanned.name()
        ));

        let qr = get_securejoin_qr(&scanned.ctx, None).await.unwrap();
        self.exec_securejoin_qr(scanner, scanned, &qr).await
    }

    /// Executes SecureJoin initiated by `joiner` scanning `qr` generated by `inviter`.
    ///
    /// The [`ChatId`] of the created chat is returned, for a SetupContact QR this is the 1:1
    /// chat with `inviter`, for a SecureJoin QR this is the group chat.
    pub async fn exec_securejoin_qr(
        &self,
        joiner: &TestContext,
        inviter: &TestContext,
        qr: &str,
    ) -> ChatId {
        self.exec_securejoin_qr_multi_device(joiner, &[inviter], qr)
            .await
    }

    /// Executes SecureJoin initiated by `joiner`
    /// scanning `qr` generated by one of the `inviters` devices.
    /// All of the `inviters` devices will get the messages and send replies.
    ///
    /// The [`ChatId`] of the created chat is returned, for a SetupContact QR this is the 1:1
    /// chat with the inviter, for a SecureJoin QR this is the group chat.
    pub async fn exec_securejoin_qr_multi_device(
        &self,
        joiner: &TestContext,
        inviters: &[&TestContext],
        qr: &str,
    ) -> ChatId {
        assert!(joiner.pop_sent_msg_opt(Duration::ZERO).await.is_none());
        for inviter in inviters {
            assert!(inviter.pop_sent_msg_opt(Duration::ZERO).await.is_none());
        }

        let chat_id = join_securejoin(&joiner.ctx, qr).await.unwrap();

        loop {
            let mut something_sent = false;
            if let Some(sent) = joiner.pop_sent_msg_opt(Duration::ZERO).await {
                for inviter in inviters {
                    inviter.recv_msg_opt(&sent).await;
                }
                something_sent = true;
            }
            for inviter in inviters {
                if let Some(sent) = inviter.pop_sent_msg_opt(Duration::ZERO).await {
                    joiner.recv_msg_opt(&sent).await;
                    something_sent = true;
                }
            }

            if !something_sent {
                break;
            }
        }
        chat_id
    }
}

/// Builder for the [TestContext].
#[derive(Debug, Clone, Default)]
pub struct TestContextBuilder {
    key_pair: Option<KeyPair>,

    /// Log sink if set.
    ///
    /// If log sink is not set,
    /// a new one will be created and stored
    /// inside the test context when it is built.
    /// If log sink is provided by the caller,
    /// it will be subscribed to the test context,
    /// but not stored inside of it,
    /// so the caller should store the LogSink elsewhere to
    /// prevent it from being dropped immediately.
    log_sink: Option<LogSink>,

    /// Offset for chat-,message-,contact ids.
    ///
    /// This makes tests fail where ids from different accounts were mixed up.
    id_offset: Option<u32>,
}

impl TestContextBuilder {
    /// Configures as alice@example.org with fixed secret key.
    ///
    /// This is a shortcut for `.with_key_pair(alice_keypair())`.
    pub fn configure_alice(self) -> Self {
        self.with_key_pair(alice_keypair())
    }

    /// Configures as bob@example.net with fixed secret key.
    ///
    /// This is a shortcut for `.with_key_pair(bob_keypair())`.
    pub fn configure_bob(self) -> Self {
        self.with_key_pair(bob_keypair())
    }

    /// Configures as charlie@example.net with fixed secret key.
    ///
    /// This is a shortcut for `.with_key_pair(charlie_keypair())`.
    pub fn configure_charlie(self) -> Self {
        self.with_key_pair(charlie_keypair())
    }

    /// Configures as dom@example.net with fixed secret key.
    ///
    /// This is a shortcut for `.with_key_pair(dom_keypair())`.
    pub fn configure_dom(self) -> Self {
        self.with_key_pair(dom_keypair())
    }

    /// Configures as elena@example.net with fixed secret key.
    ///
    /// This is a shortcut for `.with_key_pair(elena_keypair())`.
    pub fn configure_elena(self) -> Self {
        self.with_key_pair(elena_keypair())
    }

    /// Configures as fiona@example.net with fixed secret key.
    ///
    /// This is a shortcut for `.with_key_pair(fiona_keypair())`.
    pub fn configure_fiona(self) -> Self {
        self.with_key_pair(fiona_keypair())
    }

    /// Configures the new [`TestContext`] with the provided [`KeyPair`].
    ///
    /// This will extract the email address from the key and configure the context with the
    /// given identity.
    pub fn with_key_pair(mut self, key_pair: KeyPair) -> Self {
        self.key_pair = Some(key_pair);
        self
    }

    /// Attaches a [`LogSink`] to this [`TestContext`].
    ///
    /// This is useful when using multiple [`TestContext`] instances in one test: it allows
    /// using a single [`LogSink`] for both contexts.  This shows the log messages in
    /// sequence as they occurred rather than all messages from each context in a single
    /// block.
    pub fn with_log_sink(mut self, sink: LogSink) -> Self {
        self.log_sink = Some(sink);
        self
    }

    /// Adds an offset for chat-, message-, contact IDs.
    ///
    /// This makes it harder to accidentally mix up IDs from different accounts.
    pub fn with_id_offset(mut self, offset: u32) -> Self {
        self.id_offset = Some(offset);
        self
    }

    /// Builds the [`TestContext`].
    pub async fn build(self, used_names: Option<&mut BTreeSet<String>>) -> TestContext {
        if let Some(key_pair) = self.key_pair {
            let userid = {
                let public_key = &key_pair.public;
                let id_bstr = public_key.details.users.first().unwrap().id.id();
                String::from_utf8(id_bstr.to_vec()).unwrap()
            };
            let addr = mailparse::addrparse(&userid)
                .unwrap()
                .extract_single_info()
                .unwrap()
                .addr;
            let name = EmailAddress::new(&addr).unwrap().local;

            let mut unused_name = name.clone();
            if let Some(used_names) = used_names {
                assert!(used_names.len() < 100);
                // If there are multiple Alices, call them 'alice', 'alice2', 'alice3', ...
                let mut i = 1;
                while used_names.contains(&unused_name) {
                    i += 1;
                    unused_name = format!("{name}{i}");
                }
                used_names.insert(unused_name.clone());
            }

            let test_context = TestContext::new_internal(Some(unused_name), self.log_sink).await;
            test_context.configure_addr(&addr).await;
            key::store_self_keypair(&test_context, &key_pair)
                .await
                .expect("Failed to save key");

            if let Some(offset) = self.id_offset {
                test_context
                    .ctx
                    .sql
                    .execute(
                        "UPDATE sqlite_sequence SET seq = ?
                        WHERE name = 'contacts'
                        OR name = 'chats'
                        OR name = 'msgs'",
                        (offset,),
                    )
                    .await
                    .expect("Failed set id offset");
            }

            test_context
        } else {
            TestContext::new_internal(None, self.log_sink).await
        }
    }
}

/// A Context and temporary directory.
#[derive(Debug)]
pub struct TestContext {
    pub ctx: Context,

    /// Temporary directory used to store SQLite database.
    pub dir: TempDir,

    pub evtracker: EventTracker,

    /// Reference to implicit [`LogSink`] so it is dropped together with the context.
    ///
    /// Only used if no explicit `log_sender` is passed into [`TestContext::new_internal`]
    /// (which is assumed to be the sending end of a [`LogSink`]).
    ///
    /// This is a convenience in case only a single [`TestContext`] is used to avoid dealing
    /// with [`LogSink`].  Never read, since the only purpose is to
    /// control when Drop is invoked.
    _log_sink: Option<LogSink>,
}

impl TestContext {
    /// Returns the builder to have more control over creating the context.
    pub fn builder() -> TestContextBuilder {
        TestContextBuilder::default()
    }

    /// Creates a new [`TestContext`].
    ///
    /// The [Context] will be created and have an SQLite database named "db.sqlite" in the
    /// [TestContext.dir] directory.  This directory is cleaned up when the [TestContext] is
    /// dropped.
    ///
    /// [Context]: crate::context::Context
    pub async fn new() -> Self {
        Self::new_internal(None, None).await
    }

    /// Creates a new configured [`TestContext`].
    ///
    /// This is a shortcut which configures alice@example.org with a fixed key.
    pub async fn new_alice() -> Self {
        Self::builder()
            .configure_alice()
            .with_id_offset(11000)
            .build(None)
            .await
    }

    /// Creates a new configured [`TestContext`].
    ///
    /// This is a shortcut which configures bob@example.net with a fixed key.
    pub async fn new_bob() -> Self {
        Self::builder()
            .configure_bob()
            .with_id_offset(12000)
            .build(None)
            .await
    }

    /// Creates a new configured [`TestContext`].
    ///
    /// This is a shortcut which configures fiona@example.net with a fixed key.
    pub async fn new_fiona() -> Self {
        Self::builder()
            .configure_fiona()
            .with_id_offset(13000)
            .build(None)
            .await
    }

    /// Print current chat state.
    pub async fn print_chats(&self) {
        println!("\n========== Chats of {}: ==========", self.name());
        if let Ok(chats) = Chatlist::try_load(self, 0, None, None).await {
            for (chat, _) in chats.iter() {
                print!("{}", self.display_chat(*chat).await);
            }
        }
        println!();
    }

    /// Internal constructor.
    ///
    /// `name` is used to identify this context in e.g. log output.  This is useful mostly
    /// when you have multiple [`TestContext`]s in a test.
    ///
    /// `log_sender` is assumed to be the sender for a [`LogSink`].  If not supplied a new
    /// [`LogSink`] will be created so that events are logged to this test when the
    /// [`TestContext`] is dropped.
    async fn new_internal(name: Option<String>, log_sink: Option<LogSink>) -> Self {
        let dir = tempdir().unwrap();
        let dbfile = dir.path().join("db.sqlite");
        let id = rand::random();
        if let Some(name) = name {
            let mut context_names = CONTEXT_NAMES.write().unwrap();
            context_names.insert(id, name);
        }
        let events = Events::new();
        let evtracker_receiver = events.get_emitter();
        let ctx = Context::new(&dbfile, id, events, StockStrings::new())
            .await
            .expect("failed to create context");

        let _log_sink = if let Some(log_sink) = log_sink {
            // Subscribe existing LogSink and don't store reference to it.
            log_sink.subscribe(ctx.get_event_emitter());
            None
        } else {
            // Create new LogSink and store it inside the `TestContext`.
            let log_sink = LogSink::new();
            log_sink.subscribe(ctx.get_event_emitter());
            Some(log_sink)
        };

        ctx.set_config(Config::SkipStartMessages, Some("1"))
            .await
            .unwrap();
        ctx.set_config(Config::SyncMsgs, Some("0")).await.unwrap();

        Self {
            ctx,
            dir,
            evtracker: EventTracker::new(evtracker_receiver),
            _log_sink,
        }
    }

    /// Sets a name for this [`TestContext`] if one isn't yet set.
    ///
    /// This will show up in events logged in the test output.
    pub fn set_name(&self, name: &str) {
        let mut context_names = CONTEXT_NAMES.write().unwrap();
        context_names
            .entry(self.ctx.get_id())
            .or_insert_with(|| name.to_string());
    }

    /// Returns the name of this [`TestContext`].
    ///
    /// This is the same name that is shown in events logged in the test output.
    pub fn name(&self) -> String {
        let context_names = CONTEXT_NAMES.read().unwrap();
        let id = &self.ctx.id;
        context_names.get(id).unwrap_or(&id.to_string()).to_string()
    }

    /// Configure as a given email address.
    ///
    /// The context will be configured but the key will not be pre-generated so if a key is
    /// used the fingerprint will be different every time.
    pub async fn configure_addr(&self, addr: &str) {
        self.ctx
            .set_config(Config::ConfiguredAddr, Some(addr))
            .await
            .unwrap();

        if let Some(name) = addr.split('@').next() {
            self.set_name(name);
        }
    }

    /// Retrieves a sent message from the jobs table.
    ///
    /// This retrieves and removes a message which has been scheduled to send from the jobs
    /// table. Messages are returned in the reverse order of sending.
    ///
    /// Panics if there is no message or on any error.
    pub async fn pop_sent_msg(&self) -> SentMessage<'_> {
        self.pop_sent_msg_opt(Duration::from_secs(3))
            .await
            .expect("no sent message found in jobs table")
    }

    pub async fn pop_sent_msg_opt(&self, timeout: Duration) -> Option<SentMessage<'_>> {
        let start = Instant::now();
        let (rowid, msg_id, payload, recipients) = loop {
            let row = self
                .ctx
                .sql
                .query_row_optional(
                    r#"
                    SELECT id, msg_id, mime, recipients
                    FROM smtp
                    ORDER BY id DESC"#,
                    (),
                    |row| {
                        let rowid: i64 = row.get(0)?;
                        let msg_id: MsgId = row.get(1)?;
                        let mime: String = row.get(2)?;
                        let recipients: String = row.get(3)?;
                        Ok((rowid, msg_id, mime, recipients))
                    },
                )
                .await
                .expect("query_row_optional failed");
            if let Some(row) = row {
                break row;
            }
            if start.elapsed() < timeout {
                tokio::time::sleep(Duration::from_millis(100)).await;
            } else {
                return None;
            }
        };
        self.ctx
            .sql
            .execute("DELETE FROM smtp WHERE id=?;", (rowid,))
            .await
            .expect("failed to remove job");
        if !self
            .ctx
            .sql
            .exists("SELECT COUNT(*) FROM smtp WHERE msg_id=?", (msg_id,))
            .await
            .expect("Failed to check for more jobs")
        {
            update_msg_state(&self.ctx, msg_id, MessageState::OutDelivered)
                .await
                .expect("failed to update message state");
            self.sql
                .execute(
                    "UPDATE msgs SET timestamp_sent=? WHERE id=?",
                    (time(), msg_id),
                )
                .await
                .expect("Failed to update timestamp_sent");
        }

        let payload_headers = payload.split("\r\n\r\n").next().unwrap().lines();
        let payload_header_names: Vec<_> = payload_headers
            .map(|h| h.split(':').next().unwrap())
            .collect();

        // Check that we are sending exactly one From, Subject, Date, To, Message-ID, and MIME-Version header:
        for header in &[
            "From",
            "Subject",
            "Date",
            "To",
            "Message-ID",
            "MIME-Version",
        ] {
            assert_eq!(
                payload_header_names.iter().filter(|h| *h == header).count(),
                1,
                "This sent email should contain the header {header} exactly 1 time:\n{payload}"
            );
        }
        // Check that we aren't sending any header twice:
        let mut hash_set = HashSet::new();
        for header_name in payload_header_names {
            assert!(
                hash_set.insert(header_name),
                "This sent email shouldn't contain the header {header_name} multiple times:\n{payload}"
            );
        }

        Some(SentMessage {
            payload,
            sender_msg_id: msg_id,
            sender_context: &self.ctx,
            recipients,
        })
    }

    /// Retrieves a sent sync message from the db.
    ///
    /// This retrieves and removes a sync message which has been scheduled to send from the jobs
    /// table. Messages are returned in the order they have been sent.
    ///
    /// Panics if there is no message or on any error.
    pub async fn pop_sent_sync_msg(&self) -> SentMessage<'_> {
        let (id, msg_id, payload) = self
            .ctx
            .sql
            .query_row(
                "SELECT id, msg_id, mime \
                FROM imap_send \
                ORDER BY id",
                (),
                |row| {
                    let rowid: i64 = row.get(0)?;
                    let msg_id: MsgId = row.get(1)?;
                    let mime: String = row.get(2)?;
                    Ok((rowid, msg_id, mime))
                },
            )
            .await
            .expect("query_row failed");
        self.ctx
            .sql
            .execute("DELETE FROM imap_send WHERE id=?", (id,))
            .await
            .expect("failed to remove job");
        update_msg_state(&self.ctx, msg_id, MessageState::OutDelivered)
            .await
            .expect("failed to update message state");
        SentMessage {
            payload,
            sender_msg_id: msg_id,
            sender_context: &self.ctx,
            recipients: self.get_primary_self_addr().await.unwrap(),
        }
    }

    /// Parses a message.
    ///
    /// Parsing a message does not run the entire receive pipeline, but is not without
    /// side-effects either.  E.g. if the message includes autocrypt headers,
    /// gossiped public keys will be saved.  Later receiving the message using [Self.recv_msg()] is
    /// unlikely to be affected as the message would be processed again in exactly the
    /// same way.
    pub(crate) async fn parse_msg(&self, msg: &SentMessage<'_>) -> MimeMessage {
        MimeMessage::from_bytes(&self.ctx, msg.payload().as_bytes(), None)
            .await
            .unwrap()
    }

    /// Receive a message using the `receive_imf()` pipeline. Panics if it's not shown
    /// in the chat as exactly one message.
    pub async fn recv_msg(&self, msg: &SentMessage<'_>) -> Message {
        let received = self
            .recv_msg_opt(msg)
            .await
            .expect("receive_imf() seems not to have added a new message to the db");

        let msg = Message::load_from_db(self, *received.msg_ids.last().unwrap())
            .await
            .unwrap();

        let chat_msgs = chat::get_chat_msgs(self, received.chat_id).await.unwrap();
        assert!(
            chat_msgs.contains(&ChatItem::Message { msg_id: msg.id }),
            "received message is not shown in chat, maybe it's hidden (you may have \
                to call set_config(Config::ShowEmails, Some(\"2\")).await)"
        );

        msg
    }

    /// Receive a message using the `receive_imf()` pipeline. Panics if it's not hidden.
    pub async fn recv_msg_hidden(&self, msg: &SentMessage<'_>) -> Message {
        let received = self
            .recv_msg_opt(msg)
            .await
            .expect("receive_imf() seems not to have added a new message to the db");
        let msg = Message::load_from_db(self, *received.msg_ids.last().unwrap())
            .await
            .unwrap();
        assert!(msg.hidden);
        msg
    }

    /// Receive a message using the `receive_imf()` pipeline. This is similar
    /// to `recv_msg()`, but doesn't assume that the message is shown in the chat.
    pub async fn recv_msg_opt(
        &self,
        msg: &SentMessage<'_>,
    ) -> Option<crate::receive_imf::ReceivedMsg> {
        receive_imf(self, msg.payload().as_bytes(), false)
            .await
            .unwrap()
            .filter(|msg| msg.chat_id != DC_CHAT_ID_TRASH)
    }

    /// Receives a message and asserts that it goes to trash chat.
    pub async fn recv_msg_trash(&self, msg: &SentMessage<'_>) {
        let received = receive_imf(self, msg.payload().as_bytes(), false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.chat_id, DC_CHAT_ID_TRASH);
    }

    /// Gets the most recent message of a chat.
    ///
    /// Panics on errors or if the most recent message is a marker.
    pub async fn get_last_msg_in(&self, chat_id: ChatId) -> Message {
        let msgs = chat::get_chat_msgs(&self.ctx, chat_id).await.unwrap();
        let msg_id = if let ChatItem::Message { msg_id } = msgs.last().unwrap() {
            msg_id
        } else {
            panic!("Wrong item type");
        };
        Message::load_from_db(&self.ctx, *msg_id).await.unwrap()
    }

    /// Gets the most recent message over all chats.
    pub async fn get_last_msg(&self) -> Message {
        let chats = Chatlist::try_load(&self.ctx, DC_GCL_NO_SPECIALS, None, None)
            .await
            .expect("failed to load chatlist");
        // 0 is correct in the next line (as opposed to `chats.len() - 1`, which would be the last element):
        // The chatlist describes what you see when you open DC, a list of chats and in each of them
        // the first words of the last message. To get the last message overall, we look at the chat at the top of the
        // list, which has the index 0.
        let msg_id = chats.get_msg_id(0).unwrap().unwrap();
        Message::load_from_db(&self.ctx, msg_id)
            .await
            .expect("failed to load msg")
    }

    /// Returns the [`ContactId`] for the other [`TestContext`], creating a contact if necessary.
    pub async fn add_or_lookup_address_contact_id(&self, other: &TestContext) -> ContactId {
        let primary_self_addr = other.ctx.get_primary_self_addr().await.unwrap();
        let addr = ContactAddress::new(&primary_self_addr).unwrap();
        // MailinglistAddress is the lowest allowed origin, we'd prefer to not modify the
        // origin when creating this contact.
        let (contact_id, modified) =
            Contact::add_or_lookup(self, "", &addr, Origin::MailinglistAddress)
                .await
                .expect("add_or_lookup");
        match modified {
            Modifier::None => (),
            Modifier::Modified => warn!(&self.ctx, "Contact {} modified by TestContext", &addr),
            Modifier::Created => warn!(&self.ctx, "Contact {} created by TestContext", &addr),
        }
        contact_id
    }

    /// Returns the [`Contact`] for the other [`TestContext`], creating it if necessary.
    pub async fn add_or_lookup_address_contact(&self, other: &TestContext) -> Contact {
        let contact_id = self.add_or_lookup_address_contact_id(other).await;
        let contact = Contact::get_by_id(&self.ctx, contact_id).await.unwrap();
        assert_eq!(contact.is_key_contact(), false);
        contact
    }

    /// Returns the [`ContactId`] for the other [`TestContext`], creating it if necessary.
    pub async fn add_or_lookup_contact_id(&self, other: &TestContext) -> ContactId {
        let vcard = make_vcard(other, &[ContactId::SELF]).await.unwrap();
        let contact_ids = import_vcard(self, &vcard).await.unwrap();
        assert_eq!(contact_ids.len(), 1);
        *contact_ids.first().unwrap()
    }

    /// Returns the [`Contact`] for the other [`TestContext`], creating it if necessary.
    ///
    /// This function imports a vCard, so will transfer the public key
    /// as a side effect.
    pub async fn add_or_lookup_contact(&self, other: &TestContext) -> Contact {
        let contact_id = self.add_or_lookup_contact_id(other).await;
        Contact::get_by_id(&self.ctx, contact_id).await.unwrap()
    }

    /// Returns the [`Contact`] for the other [`TestContext`], creating it if necessary.
    ///
    /// If the contact does not exist yet, a new contact will be created
    /// with the correct fingerprint, but without the public key.
    pub async fn add_or_lookup_contact_no_key(&self, other: &TestContext) -> Contact {
        let primary_self_addr = other.ctx.get_primary_self_addr().await.unwrap();
        let addr = ContactAddress::new(&primary_self_addr).unwrap();
        let fingerprint = self_fingerprint(other).await.unwrap();

        let (contact_id, _modified) =
            Contact::add_or_lookup_ex(self, "", &addr, fingerprint, Origin::MailinglistAddress)
                .await
                .expect("add_or_lookup");
        Contact::get_by_id(&self.ctx, contact_id).await.unwrap()
    }

    /// Returns 1:1 [`Chat`] with another account address-contact.
    /// Panics if it doesn't exist.
    /// May return a blocked chat.
    ///
    /// This first creates a contact using the configured details on the other account, then
    /// gets the 1:1 chat with this contact.
    pub async fn get_email_chat(&self, other: &TestContext) -> Chat {
        let contact = self.add_or_lookup_address_contact(other).await;

        let chat_id = ChatIdBlocked::lookup_by_contact(&self.ctx, contact.id)
            .await
            .unwrap()
            .map(|chat_id_blocked| chat_id_blocked.id)
            .expect(
                "There is no chat with this contact. \
                Hint: Use create_email_chat() instead of get_email_chat() if this is expected.",
            );

        Chat::load_from_db(&self.ctx, chat_id).await.unwrap()
    }

    /// Returns 1:1 [`Chat`] with another account key-contact.
    /// Panics if the chat does not exist.
    ///
    /// This first creates a contact, but does not import the key,
    /// so may create a key-contact with a fingerprint
    /// but without the key.
    pub async fn get_chat(&self, other: &TestContext) -> Chat {
        let contact = self.add_or_lookup_contact_id(other).await;

        let chat_id = ChatIdBlocked::lookup_by_contact(&self.ctx, contact)
            .await
            .unwrap()
            .map(|chat_id_blocked| chat_id_blocked.id)
            .expect(
                "There is no chat with this contact. \
                 Hint: Use create_chat() instead of get_chat() if this is expected.",
            );

        Chat::load_from_db(&self.ctx, chat_id).await.unwrap()
    }

    /// Creates or returns an existing 1:1 [`ChatId`] with another account.
    ///
    /// This first creates a contact by exporting a vCard from the `other`
    /// and importing it into `self`,
    /// then creates a 1:1 chat with this contact.
    pub async fn create_chat_id(&self, other: &TestContext) -> ChatId {
        let contact_id = self.add_or_lookup_contact_id(other).await;
        ChatId::create_for_contact(self, contact_id).await.unwrap()
    }

    /// Creates or returns an existing 1:1 [`Chat`] with another account.
    ///
    /// This first creates a contact by exporting a vCard from the `other`
    /// and importing it into `self`,
    /// then creates a 1:1 chat with this contact.
    pub async fn create_chat(&self, other: &TestContext) -> Chat {
        let chat_id = self.create_chat_id(other).await;
        Chat::load_from_db(self, chat_id).await.unwrap()
    }

    /// Creates or returns an existing 1:1 [`Chat`] with another account
    /// by email address.
    ///
    /// This function can be used to create unencrypted chats.
    pub async fn create_email_chat(&self, other: &TestContext) -> Chat {
        let contact = self.add_or_lookup_address_contact(other).await;
        let chat_id = ChatId::create_for_contact(self, contact.id).await.unwrap();

        Chat::load_from_db(self, chat_id).await.unwrap()
    }

    /// Creates or returns an existing [`Contact`] and 1:1 [`Chat`] with another email.
    ///
    /// This first creates a contact from the `name` and `addr` and then creates a 1:1 chat
    /// with this contact.
    pub async fn create_chat_with_contact(&self, name: &str, addr: &str) -> Chat {
        let contact = Contact::create(self, name, addr)
            .await
            .expect("failed to create contact");
        let chat_id = ChatId::create_for_contact(self, contact).await.unwrap();
        Chat::load_from_db(self, chat_id).await.unwrap()
    }

    /// Retrieves the "self" chat.
    pub async fn get_self_chat(&self) -> Chat {
        let chat_id = ChatId::create_for_contact(self, ContactId::SELF)
            .await
            .unwrap();
        Chat::load_from_db(self, chat_id).await.unwrap()
    }

    pub async fn assert_no_chat(&self, id: ChatId) {
        assert!(Chat::load_from_db(self, id).await.is_err());
        assert!(
            !self
                .sql
                .exists("SELECT COUNT(*) FROM chats WHERE id=?", (id,))
                .await
                .unwrap()
        );
    }

    /// Sends out the text message.
    ///
    /// This is not hooked up to any SMTP-IMAP pipeline, so the other account must call
    /// [`TestContext::recv_msg`] with the returned [`SentMessage`] if it wants to receive
    /// the message.
    pub async fn send_text(&self, chat_id: ChatId, txt: &str) -> SentMessage<'_> {
        let mut msg = Message::new_text(txt.to_string());
        self.send_msg(chat_id, &mut msg).await
    }

    /// Sends out the message to the specified chat.
    ///
    /// This is not hooked up to any SMTP-IMAP pipeline, so the other account must call
    /// [`TestContext::recv_msg`] with the returned [`SentMessage`] if it wants to receive
    /// the message.
    pub async fn send_msg(&self, chat_id: ChatId, msg: &mut Message) -> SentMessage<'_> {
        let msg_id = chat::send_msg(self, chat_id, msg).await.unwrap();
        let res = self.pop_sent_msg().await;
        assert_eq!(
            res.sender_msg_id, msg_id,
            "Apparently the message was not actually sent out"
        );
        res
    }

    pub async fn golden_test_chat(&self, chat_id: ChatId, filename: &str) {
        let filename = Path::new("test-data/golden/").join(filename);

        let actual = self.display_chat(chat_id).await;

        // We're using `unwrap_or_default()` here so that if the file doesn't exist,
        // it can be created using `write` below.
        let expected = fs::read(&filename).await.unwrap_or_default();
        let expected = String::from_utf8(expected).unwrap().replace("\r\n", "\n");
        if (std::env::var("UPDATE_GOLDEN_TESTS") == Ok("1".to_string())) && actual != expected {
            fs::write(&filename, &actual)
                .await
                .unwrap_or_else(|e| panic!("Error writing {filename:?}: {e}"));
        } else {
            let green = Color::Green.normal();
            let red = Color::Red.normal();
            assert_eq!(
                actual,
                expected,
                "{} != {} on {}'s device.\nTo update the expected value, run with `UPDATE_GOLDEN_TESTS=1` environment variable",
                red.paint("actual chat content (shown in red)"),
                green.paint("expected chat content (shown in green)"),
                self.name(),
            );
        }
    }

    /// Prints out the entire chat to stdout.
    ///
    /// You can use this to debug your test by printing the entire chat conversation.
    // This code is mainly the same as `log_msglist` in `cmdline.rs`, so one day, we could
    // merge them to a public function in the `deltachat` crate.
    async fn display_chat(&self, chat_id: ChatId) -> String {
        let mut res = String::new();

        let msglist = chat::get_chat_msgs_ex(
            self,
            chat_id,
            MessageListOptions {
                info_only: false,
                add_daymarker: false,
            },
        )
        .await
        .unwrap();
        let msglist: Vec<MsgId> = msglist
            .into_iter()
            .filter_map(|x| match x {
                ChatItem::Message { msg_id } => Some(msg_id),
                ChatItem::DayMarker { .. } => None,
            })
            .collect();

        let Ok(sel_chat) = Chat::load_from_db(self, chat_id).await else {
            return String::from("Can't load chat\n");
        };
        let members = chat::get_chat_contacts(self, sel_chat.id).await.unwrap();
        let subtitle = if sel_chat.is_device_talk() {
            "device-talk".to_string()
        } else if sel_chat.get_type() == Chattype::Single && !members.is_empty() {
            let contact = Contact::get_by_id(self, members[0]).await.unwrap();
            if contact.is_key_contact() {
                format!("KEY {}", contact.get_addr())
            } else {
                contact.get_addr().to_string()
            }
        } else if sel_chat.get_type() == Chattype::Mailinglist && !members.is_empty() {
            "mailinglist".to_string()
        } else {
            format!("{} member(s)", members.len())
        };
        writeln!(
            res,
            "{}#{}: {} [{}]{}{}{}",
            sel_chat.typ,
            sel_chat.get_id(),
            sel_chat.get_name(),
            subtitle,
            if sel_chat.is_muted() { "🔇" } else { "" },
            if sel_chat.is_sending_locations() {
                "📍"
            } else {
                ""
            },
            match sel_chat.get_profile_image(self).await.unwrap() {
                Some(icon) => match icon.strip_prefix(self.get_blobdir()).unwrap().to_str() {
                    Some(icon) => format!(" Icon: {icon}"),
                    _ => " Icon: Err".to_string(),
                },
                _ => "".to_string(),
            },
        )
        .unwrap();

        let mut lines_out = 0;
        for msg_id in msglist {
            if msg_id.is_special() {
                continue;
            }
            if lines_out == 0 {
                writeln!(res,
                    "--------------------------------------------------------------------------------",
                ).unwrap();
                lines_out += 1
            }
            let msg = Message::load_from_db(self, msg_id).await.unwrap();
            write_msg(self, "", &msg, &mut res).await;
        }
        if lines_out > 0 {
            writeln!(
                res,
                "--------------------------------------------------------------------------------"
            )
            .unwrap();
        }

        res
    }

    pub async fn create_group_with_members(
        &self,
        chat_name: &str,
        members: &[&TestContext],
    ) -> ChatId {
        let chat_id = create_group(self, chat_name).await.unwrap();
        let mut to_add = vec![];
        for member in members {
            let contact_id = self.add_or_lookup_contact_id(member).await;
            to_add.push(contact_id);
        }
        add_to_chat_contacts_table(self, time(), chat_id, &to_add)
            .await
            .unwrap();

        chat_id
    }

    /// Set the legacy `protected` column in the chats table to 1,
    /// because for now, only these chats that were once protected can be used
    /// to gossip verifications.
    // TODO remove the next statement
    // when we send the _verified header for all verified contacts
    pub(crate) async fn set_chat_protected(self: &TestContext, chat_id: chat::ChatId) {
        self.sql
            .execute("UPDATE chats SET protected=1 WHERE id=?", (chat_id,))
            .await
            .unwrap();
    }
}

impl Deref for TestContext {
    type Target = Context;

    fn deref(&self) -> &Context {
        &self.ctx
    }
}

impl Drop for TestContext {
    fn drop(&mut self) {
        task::block_in_place(move || {
            if let Ok(handle) = Handle::try_current() {
                // Print the chats if runtime still exists.
                handle.block_on(async move {
                    self.print_chats().await;

                    // If you set this to true, and a test fails,
                    // the sql databases will be saved into the current working directory
                    // so that you can examine them.
                    if std::env::var("DELTACHAT_SAVE_TMP_DB").is_ok() {
                        let _: u32 = self
                            .sql
                            .query_get_value("PRAGMA wal_checkpoint;", ())
                            .await
                            .unwrap()
                            .unwrap();

                        let from = self.get_dbfile();
                        let target = current_dir()
                            .unwrap()
                            .join(format!("test-account-{}.db", self.name()));
                        tokio::fs::copy(from, &target).await.unwrap();
                        eprintln!("Copied database from {from:?} to {target:?}\n");
                    }
                });
            }
        });
    }
}

pub enum LogEvent {
    /// Logged event.
    Event(Event),

    /// Test output section.
    Section(String),
}

/// A receiver of [`Event`]s which will log the events to the captured test stdout.
///
/// Tests redirect the stdout of the test thread and capture this, showing the captured
/// stdout if the test fails.  This means printing log messages must be done on the thread
/// of the test itself and not from a spawned task.
///
/// This sink achieves this by printing the events, in the order received, at the time it is
/// dropped.  Thus to use you must only make sure this sink is dropped in the test itself.
///
/// To use this create an instance using [`LogSink::new`] and then use the
/// [`TestContextBuilder::with_log_sink`] or use [`TestContextManager`].
#[derive(Debug, Clone, Default)]
pub struct LogSink(Arc<InnerLogSink>);

impl LogSink {
    /// Creates a new [`LogSink`] and returns the attached event sink.
    pub fn new() -> Self {
        Default::default()
    }
}

impl Deref for LogSink {
    type Target = InnerLogSink;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct InnerLogSink {
    events: Receiver<LogEvent>,

    /// Sender side of the log receiver.
    ///
    /// It is cloned when log sink is subscribed
    /// to new event emitter
    /// and can be used directly from the test to
    /// add "sections" to the log.
    sender: Sender<LogEvent>,
}

impl Default for InnerLogSink {
    fn default() -> Self {
        let (tx, rx) = channel::unbounded();
        Self {
            events: rx,
            sender: tx,
        }
    }
}

impl InnerLogSink {
    /// Subscribes this log sink to event emitter.
    pub fn subscribe(&self, event_emitter: EventEmitter) {
        let sender = self.sender.clone();
        task::spawn(async move {
            while let Some(event) = event_emitter.recv().await {
                sender.try_send(LogEvent::Event(event.clone())).ok();
            }
        });
    }
}

impl Drop for InnerLogSink {
    fn drop(&mut self) {
        while let Ok(event) = self.events.try_recv() {
            print_logevent(&event);
        }
        if std::env::var("DELTACHAT_SAVE_TMP_DB").is_err() {
            eprintln!(
                "note: If you want to examine the database files, set environment variable DELTACHAT_SAVE_TMP_DB=1"
            )
        }
    }
}

/// A raw message as it was scheduled to be sent.
///
/// This is a raw message, probably in the shape DC was planning to send it but not having
/// passed through a SMTP-IMAP pipeline.
#[derive(Debug, Clone)]
pub struct SentMessage<'a> {
    pub payload: String,
    pub recipients: String,
    pub sender_msg_id: MsgId,
    sender_context: &'a Context,
}

impl SentMessage<'_> {
    /// A recipient the message was destined for.
    ///
    /// If there are multiple recipients this is just a random one, so is not very useful.
    pub fn recipient(&self) -> EmailAddress {
        let rcpt = self
            .recipients
            .split(' ')
            .next()
            .expect("no recipient found");
        EmailAddress::new(rcpt).expect("failed to parse email address")
    }

    /// The raw message payload.
    pub fn payload(&self) -> &str {
        &self.payload
    }

    pub async fn load_from_db(&self) -> Message {
        Message::load_from_db(self.sender_context, self.sender_msg_id)
            .await
            .unwrap()
    }
}

/// Load a pre-generated keypair for alice@example.org from disk.
///
/// This saves CPU cycles by avoiding having to generate a key.
///
/// The keypair was created using the crate::key::tests::gen_key test.
pub fn alice_keypair() -> KeyPair {
    let secret =
        key::SignedSecretKey::from_asc(include_str!("../test-data/key/alice-secret.asc")).unwrap();
    let public = secret.split_public_key().unwrap();
    KeyPair { public, secret }
}

/// Load a pre-generated keypair for bob@example.net from disk.
///
/// Like [alice_keypair] but a different key and identity.
pub fn bob_keypair() -> KeyPair {
    let secret =
        key::SignedSecretKey::from_asc(include_str!("../test-data/key/bob-secret.asc")).unwrap();
    let public = secret.split_public_key().unwrap();
    KeyPair { public, secret }
}

/// Load a pre-generated keypair for charlie@example.net from disk.
///
/// Like [alice_keypair] but a different key and identity.
pub fn charlie_keypair() -> KeyPair {
    let secret =
        key::SignedSecretKey::from_asc(include_str!("../test-data/key/charlie-secret.asc"))
            .unwrap();
    let public = secret.split_public_key().unwrap();
    KeyPair { public, secret }
}

/// Load a pre-generated keypair for dom@example.net from disk.
///
/// Like [alice_keypair] but a different key and identity.
pub fn dom_keypair() -> KeyPair {
    let secret =
        key::SignedSecretKey::from_asc(include_str!("../test-data/key/dom-secret.asc")).unwrap();
    let public = secret.split_public_key().unwrap();
    KeyPair { public, secret }
}

/// Load a pre-generated keypair for elena@example.net from disk.
///
/// Like [alice_keypair] but a different key and identity.
pub fn elena_keypair() -> KeyPair {
    let secret =
        key::SignedSecretKey::from_asc(include_str!("../test-data/key/elena-secret.asc")).unwrap();
    let public = secret.split_public_key().unwrap();
    KeyPair { public, secret }
}

/// Load a pre-generated keypair for fiona@example.net from disk.
///
/// Like [alice_keypair] but a different key and identity.
pub fn fiona_keypair() -> KeyPair {
    let secret =
        key::SignedSecretKey::from_asc(include_str!("../test-data/key/fiona-secret.asc")).unwrap();
    let public = secret.split_public_key().unwrap();
    KeyPair { public, secret }
}

/// Utility to help wait for and retrieve events.
///
/// This buffers the events in order they are emitted.  This allows consuming events in
/// order while looking for the right events using the provided methods.
///
/// The methods only return [`EventType`] rather than the full [`Event`] since it can only
/// be attached to a single [`TestContext`] and therefore the context is already known as
/// you will be accessing it as [`TestContext::evtracker`].
#[derive(Debug)]
pub struct EventTracker(EventEmitter);

impl Deref for EventTracker {
    type Target = EventEmitter;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for EventTracker {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl EventTracker {
    pub fn new(emitter: EventEmitter) -> Self {
        Self(emitter)
    }

    /// Consumes emitted events returning the first matching one.
    ///
    /// If no matching events are ready this will wait for new events to arrive and time out
    /// after 10 seconds.
    pub async fn get_matching<F: Fn(&EventType) -> bool>(&self, event_matcher: F) -> EventType {
        tokio::time::timeout(Duration::from_secs(10), async move {
            loop {
                let event = self.recv().await.unwrap();
                if event_matcher(&event.typ) {
                    return event.typ;
                }
            }
        })
        .await
        .expect("timeout waiting for event match")
    }

    /// Consumes emitted events returning the first matching one if any.
    pub async fn get_matching_opt<F: Fn(&EventType) -> bool>(
        &self,
        ctx: &Context,
        event_matcher: F,
    ) -> Option<EventType> {
        ctx.emit_event(EventType::Test);
        loop {
            let event = self.recv().await.unwrap();
            if event_matcher(&event.typ) {
                return Some(event.typ);
            }
            if let EventType::Test = event.typ {
                return None;
            }
        }
    }

    /// Consumes events looking for an [`EventType::Info`] with substring matching.
    pub async fn get_info_contains(&self, s: &str) -> EventType {
        self.get_matching(|evt| match evt {
            EventType::Info(msg) => msg.contains(s),
            _ => false,
        })
        .await
    }

    /// Wait for the next IncomingMsg event.
    pub async fn wait_next_incoming_message(&self) {
        self.get_matching(|evt| matches!(evt, EventType::IncomingMsg { .. }))
            .await;
    }

    /// Clears event queue.
    pub fn clear_events(&self) {
        while let Ok(_ev) = self.try_recv() {}
    }
}

/// Gets a specific message from a chat and asserts that the chat has a specific length.
///
/// Panics if the length of the chat is not `asserted_msgs_count` or if the chat item at `index` is not a Message.
pub(crate) async fn get_chat_msg(
    t: &TestContext,
    chat_id: ChatId,
    index: usize,
    asserted_msgs_count: usize,
) -> Message {
    let msgs = chat::get_chat_msgs(&t.ctx, chat_id).await.unwrap();
    assert_eq!(
        msgs.len(),
        asserted_msgs_count,
        "expected {} messages in a chat but {} found",
        asserted_msgs_count,
        msgs.len()
    );
    let msg_id = if let ChatItem::Message { msg_id } = msgs[index] {
        msg_id
    } else {
        panic!("Wrong item type");
    };
    Message::load_from_db(&t.ctx, msg_id).await.unwrap()
}

fn print_logevent(logevent: &LogEvent) {
    match logevent {
        LogEvent::Event(event) => print_event(event),
        LogEvent::Section(msg) => println!("\n========== {msg} =========="),
    }
}

/// Saves the other account's public key as verified
pub(crate) async fn mark_as_verified(this: &TestContext, other: &TestContext) {
    let contact_id = this.add_or_lookup_contact_id(other).await;
    mark_contact_id_as_verified(this, contact_id, Some(ContactId::SELF))
        .await
        .unwrap();
}

/// Pops a sync message from alice0 and receives it on alice1. Should be used after an action on
/// alice0's side that implies sending a sync message.
pub(crate) async fn sync(alice0: &TestContext, alice1: &TestContext) {
    alice0.send_sync_msg().await.unwrap();
    let sync_msg = alice0.pop_sent_sync_msg().await;
    alice1.recv_msg_trash(&sync_msg).await;
}

/// Pretty-print an event to stdout
///
/// Done during tests this is captured by `cargo test` and associated with the test itself.
fn print_event(event: &Event) {
    let green = Color::Green.normal();
    let yellow = Color::Yellow.normal();
    let red = Color::Red.normal();

    let msg = match &event.typ {
        EventType::Info(msg) => format!("INFO: {msg}"),
        EventType::SmtpConnected(msg) => format!("[SMTP_CONNECTED] {msg}"),
        EventType::ImapConnected(msg) => format!("[IMAP_CONNECTED] {msg}"),
        EventType::SmtpMessageSent(msg) => format!("[SMTP_MESSAGE_SENT] {msg}"),
        EventType::Warning(msg) => format!("WARN: {}", yellow.paint(msg)),
        EventType::Error(msg) => format!("ERROR: {}", red.paint(msg)),
        EventType::ErrorSelfNotInGroup(msg) => {
            format!("{}", red.paint(format!("[SELF_NOT_IN_GROUP] {msg}")))
        }
        EventType::MsgsChanged { chat_id, msg_id } => format!(
            "{}",
            green.paint(format!(
                "Received MSGS_CHANGED(chat_id={chat_id}, msg_id={msg_id})",
            ))
        ),
        EventType::ContactsChanged(contact) => format!(
            "{}",
            green.paint(format!("Received CONTACTS_CHANGED(contact={contact:?})"))
        ),
        EventType::LocationChanged(contact) => format!(
            "{}",
            green.paint(format!("Received LOCATION_CHANGED(contact={contact:?})"))
        ),
        EventType::ConfigureProgress { progress, comment } => {
            if let Some(comment) = comment {
                format!(
                    "{}",
                    green.paint(format!(
                        "Received CONFIGURE_PROGRESS({progress} ‰, {comment})"
                    ))
                )
            } else {
                format!(
                    "{}",
                    green.paint(format!("Received CONFIGURE_PROGRESS({progress} ‰)"))
                )
            }
        }
        EventType::ImexProgress(progress) => format!(
            "{}",
            green.paint(format!("Received IMEX_PROGRESS({progress} ‰)"))
        ),
        EventType::ImexFileWritten(file) => format!(
            "{}",
            green.paint(format!("Received IMEX_FILE_WRITTEN({})", file.display()))
        ),
        EventType::ChatModified(chat) => {
            format!("{}", green.paint(format!("Received CHAT_MODIFIED({chat})")))
        }
        _ => format!("Received {event:?}"),
    };
    let context_names = CONTEXT_NAMES.read().unwrap();
    match context_names.get(&event.id) {
        Some(name) => println!("{name} {msg}"),
        None => println!("{} {}", event.id, msg),
    }
}

/// Logs an individual message to stdout.
///
/// This includes a bunch of the message meta-data as well.
async fn write_msg(context: &Context, prefix: &str, msg: &Message, buf: &mut String) {
    let contact = match Contact::get_by_id(context, msg.get_from_id()).await {
        Ok(contact) => contact,
        Err(e) => {
            println!("Can't log message: invalid contact: {e}");
            return;
        }
    };

    let contact_name = contact.get_name();
    let contact_id = contact.get_id();

    let statestr = match msg.get_state() {
        MessageState::OutPending => " o",
        MessageState::OutDelivered => " √",
        MessageState::OutMdnRcvd => " √√",
        MessageState::OutFailed => " !!",
        _ => "",
    };
    let msgtext = msg.get_text();
    writeln!(
        buf,
        "{}{}{}{}: {} (Contact#{}): {} {}{}{}{}",
        prefix,
        msg.get_id(),
        if msg.get_showpadlock() { "🔒" } else { "" },
        if msg.has_location() { "📍" } else { "" },
        &contact_name,
        contact_id,
        msgtext,
        if msg.get_from_id() == ContactId::SELF {
            ""
        } else if msg.get_state() == MessageState::InSeen {
            "[SEEN]"
        } else if msg.get_state() == MessageState::InNoticed {
            "[NOTICED]"
        } else {
            "[FRESH]"
        },
        if msg.is_info() {
            if msg.get_info_type() == SystemMessage::ChatProtectionEnabled {
                "[INFO 🛡️]"
            } else if msg.get_info_type() == SystemMessage::ChatProtectionDisabled {
                "[INFO 🛡️❌]"
            } else {
                "[INFO]"
            }
        } else {
            ""
        },
        if msg.is_forwarded() {
            "[FORWARDED]"
        } else {
            ""
        },
        statestr,
    )
    .unwrap();
}

/// When dropped after a test failure,
/// prints a note about a possible false-possible caused by SystemTime::shift().
pub(crate) struct TimeShiftFalsePositiveNote;
impl Drop for TimeShiftFalsePositiveNote {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let green = nu_ansi_term::Color::Green.normal();
            println!("{}", green.paint(
            "\nNOTE: This test failure may be a false-positive, caused by tests running in parallel.
The issue is that `SystemTime::shift()` (a utility function for tests) changes the time for all threads doing tests, and not only for the running test.
Until the false-positive is fixed:
- Use `cargo test -- --test-threads 1` instead of `cargo test`
- Or use `cargo nextest run` (install with `cargo install cargo-nextest --locked`)\n")
            );
        }
    }
}

mod tests {
    use super::*;

    // The following three tests demonstrate, when made to fail, the log output being
    // directed to the correct test output.

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_with_alice() {
        let alice = TestContext::builder().configure_alice().build(None).await;
        alice.ctx.emit_event(EventType::Info("hello".into()));
        // panic!("Alice fails");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_with_bob() {
        let bob = TestContext::builder().configure_bob().build(None).await;
        bob.ctx.emit_event(EventType::Info("there".into()));
        // panic!("Bob fails");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_with_both() {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;

        alice.ctx.emit_event(EventType::Info("hello".into()));
        bob.ctx.emit_event(EventType::Info("there".into()));
        // panic!("Both fail");
    }

    /// Checks that dropping the `TestContext` after the runtime does not panic,
    /// e.g. that `TestContext::drop` does not assume the runtime still exists.
    #[test]
    fn test_new_test_context() {
        let runtime = tokio::runtime::Runtime::new().expect("unable to create tokio runtime");
        runtime.block_on(TestContext::new());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_id_offset() {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        let fiona = tcm.fiona().await;

        // chat ids
        let alice_bob_chat = alice.create_chat(&bob).await;
        let bob_alice_chat = bob.create_chat(&alice).await;
        assert_ne!(alice_bob_chat.id, bob_alice_chat.id);

        // contact ids
        let alice_fiona_contact_id = alice.add_or_lookup_contact_id(&fiona).await;
        let fiona_fiona_contact_id = bob.add_or_lookup_contact_id(&fiona).await;
        assert_ne!(alice_fiona_contact_id, fiona_fiona_contact_id);

        // message ids
        let alice_group_id = alice
            .create_group_with_members("test group", &[&bob, &fiona])
            .await;
        let alice_sent_msg = alice.send_text(alice_group_id, "testing").await;
        let bob_received_id = bob.recv_msg(&alice_sent_msg).await;
        assert_ne!(alice_sent_msg.sender_msg_id, bob_received_id.id);
        let fiona_received_id = fiona.recv_msg(&alice_sent_msg).await;
        assert_ne!(bob_received_id.id, fiona_received_id.id);
    }
}
