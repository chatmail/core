//! # SMTP transport module.

mod connect;
pub mod send;

use anyhow::{Context as _, Error, Result, bail, format_err};
use async_smtp::response::{Category, Code, Detail};
use async_smtp::{EmailAddress, SmtpTransport};
use tokio::task;

use crate::chat::{ChatId, add_info_msg_with_cmd};
use crate::config::Config;
use crate::contact::{Contact, ContactId};
use crate::context::Context;
use crate::events::EventType;
use crate::log::warn;
use crate::message::Message;
use crate::message::{self, MsgId};
use crate::mimefactory::MimeFactory;
use crate::net::proxy::ProxyConfig;
use crate::net::session::SessionBufStream;
use crate::scheduler::connectivity::ConnectivityStore;
use crate::stock_str::unencrypted_email;
use crate::tools::{self, time_elapsed};
use crate::transport::{
    ConfiguredLoginParam, ConfiguredServerLoginParam, prioritize_server_login_params,
};

#[derive(Default)]
pub(crate) struct Smtp {
    /// SMTP connection.
    transport: Option<SmtpTransport<Box<dyn SessionBufStream>>>,

    /// Email address we are sending from.
    from: Option<EmailAddress>,

    /// Timestamp of last successful send/receive network interaction
    /// (eg connect or send succeeded). On initialization and disconnect
    /// it is set to None.
    last_success: Option<tools::Time>,

    pub(crate) connectivity: ConnectivityStore,

    /// If sending the last message failed, contains the error message.
    pub(crate) last_send_error: Option<String>,
}

impl Smtp {
    /// Create a new Smtp instances.
    pub fn new() -> Self {
        Default::default()
    }

    /// Disconnect the SMTP transport and drop it entirely.
    pub fn disconnect(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            // Closing connection with a QUIT command may take some time, especially if it's a
            // stale connection and an attempt to send the command times out. Send a command in a
            // separate task to avoid waiting for reply or timeout.
            task::spawn(async move { transport.quit().await });
        }
        self.last_success = None;
    }

    /// Return true if smtp was connected but is not known to
    /// have been successfully used the last 60 seconds
    pub fn has_maybe_stale_connection(&self) -> bool {
        if let Some(last_success) = self.last_success {
            time_elapsed(&last_success).as_secs() > 60
        } else {
            false
        }
    }

    /// Check whether we are connected.
    pub fn is_connected(&self) -> bool {
        self.transport.is_some()
    }

    /// Connect using configured parameters.
    pub async fn connect_configured(&mut self, context: &Context) -> Result<()> {
        if self.has_maybe_stale_connection() {
            info!(context, "Closing stale connection.");
            self.disconnect();
        }

        if self.is_connected() {
            return Ok(());
        }

        self.connectivity.set_connecting(context);
        let (_transport_id, lp) = ConfiguredLoginParam::load(context)
            .await?
            .context("Not configured")?;
        let proxy_config = ProxyConfig::load(context).await?;
        self.connect(
            context,
            &lp.smtp,
            &lp.smtp_password,
            &proxy_config,
            &lp.addr,
            lp.strict_tls(proxy_config.is_some()),
            lp.oauth2,
        )
        .await
    }

    /// Connect using the provided login params.
    #[expect(clippy::too_many_arguments)]
    pub async fn connect(
        &mut self,
        context: &Context,
        login_params: &[ConfiguredServerLoginParam],
        password: &str,
        proxy_config: &Option<ProxyConfig>,
        addr: &str,
        strict_tls: bool,
        oauth2: bool,
    ) -> Result<()> {
        if self.is_connected() {
            warn!(context, "SMTP already connected.");
            return Ok(());
        }

        let from = EmailAddress::new(addr.to_string())
            .with_context(|| format!("Invalid address {addr:?}"))?;
        self.from = Some(from);

        let login_params =
            prioritize_server_login_params(&context.sql, login_params, "smtp").await?;
        let mut first_error = None;
        for lp in login_params {
            info!(context, "SMTP trying to connect to {}.", &lp.connection);
            let transport = match connect::connect_and_auth(
                context,
                proxy_config,
                strict_tls,
                lp.connection.clone(),
                oauth2,
                addr,
                &lp.user,
                password,
            )
            .await
            {
                Ok(transport) => transport,
                Err(err) => {
                    warn!(context, "SMTP failed to connect and authenticate: {err:#}.");
                    first_error.get_or_insert(err);
                    continue;
                }
            };

            self.transport = Some(transport);
            self.last_success = Some(tools::Time::now());

            context.emit_event(EventType::SmtpConnected(format!(
                "SMTP-LOGIN as {} ok",
                lp.user,
            )));
            return Ok(());
        }

        Err(first_error.unwrap_or_else(|| format_err!("No SMTP connection candidates provided")))
    }
}

pub(crate) enum SendResult {
    /// Message was sent successfully.
    Success,

    /// Permanent error, message sending has failed.
    Failure(Error),

    /// Temporary error, the message should be retried later.
    Retry,
}

/// Tries to send a message.
pub(crate) async fn smtp_send(
    context: &Context,
    recipients: &[async_smtp::EmailAddress],
    message: &str,
    smtp: &mut Smtp,
    msg_id: Option<MsgId>,
) -> SendResult {
    if std::env::var(crate::DCC_MIME_DEBUG).is_ok() {
        info!(context, "SMTP-sending out mime message:\n{message}");
    }

    smtp.connectivity.set_working(context);

    if let Err(err) = smtp
        .connect_configured(context)
        .await
        .context("Failed to open SMTP connection")
    {
        smtp.last_send_error = Some(format!("{err:#}"));
        return SendResult::Retry;
    }

    let send_result = smtp.send(context, recipients, message.as_bytes()).await;
    smtp.last_send_error = send_result.as_ref().err().map(|e| e.to_string());

    let status = match send_result {
        Err(crate::smtp::send::Error::SmtpSend(err)) => {
            // Remote error, retry later.
            info!(context, "SMTP failed to send: {:?}.", &err);

            let res = match err {
                async_smtp::error::Error::Permanent(ref response) => {
                    // Workaround for incorrectly configured servers returning permanent errors
                    // instead of temporary ones.
                    let maybe_transient = match response.code {
                        // Sometimes servers send a permanent error when actually it is a temporary error
                        // For documentation see <https://tools.ietf.org/html/rfc3463>
                        Code {
                            category: Category::MailSystem,
                            detail: Detail::Zero,
                            ..
                        } => {
                            // Ignore status code 5.5.0, see <https://support.delta.chat/t/every-other-message-gets-stuck/877/2>
                            // Maybe incorrectly configured Postfix milter with "reject" instead of "tempfail", which returns
                            // "550 5.5.0 Service unavailable" instead of "451 4.7.1 Service unavailable - try again later".
                            //
                            // Other enhanced status codes, such as Postfix
                            // "550 5.1.1 <foobar@example.org>: Recipient address rejected: User unknown in local recipient table"
                            // are not ignored.
                            response.first_word() == Some("5.5.0")
                        }
                        _ => false,
                    };

                    if maybe_transient {
                        info!(
                            context,
                            "Permanent error that is likely to actually be transient, postponing retry for later."
                        );
                        SendResult::Retry
                    } else {
                        info!(context, "Permanent error, message sending failed.");
                        // If we do not retry, add an info message to the chat.
                        // Yandex error "554 5.7.1 [2] Message rejected under suspicion of SPAM; https://ya.cc/..."
                        // should definitely go here, because user has to open the link to
                        // resume message sending.
                        SendResult::Failure(format_err!("Permanent SMTP error: {err}"))
                    }
                }
                async_smtp::error::Error::Transient(ref response) => {
                    // We got a transient 4xx response from SMTP server.
                    // Give some time until the server-side error maybe goes away.
                    //
                    // One particular case is
                    // `450 4.1.2 <alice@example.org>: Recipient address rejected: Domain not found`.
                    // known to be returned by Postfix.
                    //
                    // [RFC 3463](https://tools.ietf.org/html/rfc3463#section-3.2)
                    // says "This code is only useful for permanent failures."
                    // in X.1.1, X.1.2 and X.1.3 descriptions.
                    //
                    // Previous Delta Chat core versions
                    // from 1.51.0 to 1.151.1
                    // were treating such errors as permanent.
                    //
                    // This was later reverted because such errors were observed
                    // for existing domains and turned out to be actually transient,
                    // likely caused by nameserver downtime.
                    info!(
                        context,
                        "Transient error {response:?}, postponing retry for later."
                    );
                    SendResult::Retry
                }
                _ => {
                    info!(
                        context,
                        "Message sending failed without error returned by the server, retry later."
                    );
                    SendResult::Retry
                }
            };

            // this clears last_success info
            info!(context, "Failed to send message over SMTP, disconnecting.");
            smtp.disconnect();

            res
        }
        Err(crate::smtp::send::Error::Envelope(err)) => {
            // Local error, job is invalid, do not retry.
            smtp.disconnect();
            warn!(context, "SMTP job is invalid: {err:#}.");
            SendResult::Failure(err)
        }
        Err(crate::smtp::send::Error::NoTransport) => {
            // Should never happen.
            // It does not even make sense to disconnect here.
            error!(context, "SMTP job failed because SMTP has no transport.");
            SendResult::Failure(format_err!("SMTP has not transport"))
        }
        Err(crate::smtp::send::Error::Other(err)) => {
            // Local error, job is invalid, do not retry.
            smtp.disconnect();
            warn!(context, "Unable to load SMTP job: {err:#}.");
            SendResult::Failure(err)
        }
        Ok(()) => SendResult::Success,
    };

    if let SendResult::Failure(err) = &status
        && let Some(msg_id) = msg_id
    {
        // We couldn't send the message, so mark it as failed
        match Message::load_from_db(context, msg_id).await {
            Ok(mut msg) => {
                if let Err(err) = message::set_msg_failed(context, &mut msg, &err.to_string()).await
                {
                    error!(context, "Failed to mark {msg_id} as failed: {err:#}.");
                }
            }
            Err(err) => {
                error!(
                    context,
                    "Failed to load {msg_id} to mark it as failed: {err:#}."
                );
            }
        }
    }
    status
}

/// Sends message identified by `smtp` table rowid over SMTP connection.
///
/// Removes row if the message should not be retried, otherwise increments retry count.
pub(crate) async fn send_msg_to_smtp(
    context: &Context,
    smtp: &mut Smtp,
    rowid: i64,
) -> anyhow::Result<()> {
    if let Err(err) = smtp
        .connect_configured(context)
        .await
        .context("SMTP connection failure")
    {
        smtp.last_send_error = Some(format!("{err:#}"));
        return Err(err);
    }

    // Increase retry count as soon as we have an SMTP connection. This ensures that the message is
    // eventually removed from the queue by exceeding retry limit even in case of an error that
    // keeps happening early in the message sending code, e.g. failure to read the message from the
    // database.
    context
        .sql
        .execute("UPDATE smtp SET retries=retries+1 WHERE id=?", (rowid,))
        .await
        .context("failed to update retries count")?;

    let Some((body, recipients, msg_id, retries)) = context
        .sql
        .query_row_optional(
            "SELECT mime, recipients, msg_id, retries FROM smtp WHERE id=?",
            (rowid,),
            |row| {
                let mime: String = row.get(0)?;
                let recipients: String = row.get(1)?;
                let msg_id: MsgId = row.get(2)?;
                let retries: i64 = row.get(3)?;
                Ok((mime, recipients, msg_id, retries))
            },
        )
        .await?
    else {
        return Ok(());
    };
    if retries > 6 {
        if let Some(mut msg) = Message::load_from_db_optional(context, msg_id).await? {
            message::set_msg_failed(context, &mut msg, "Number of retries exceeded the limit.")
                .await?;
        }
        context
            .sql
            .execute("DELETE FROM smtp WHERE id=?", (rowid,))
            .await
            .context("Failed to remove message with exceeded retry limit from smtp table")?;
        return Ok(());
    }
    info!(
        context,
        "Try number {retries} to send message {msg_id} (entry {rowid}) over SMTP."
    );

    let recipients_list = recipients
        .split(' ')
        .filter_map(
            |addr| match async_smtp::EmailAddress::new(addr.to_string()) {
                Ok(addr) => Some(addr),
                Err(err) => {
                    warn!(context, "Invalid recipient: {} {:?}.", addr, err);
                    None
                }
            },
        )
        .collect::<Vec<_>>();

    let status = smtp_send(context, &recipients_list, body.as_str(), smtp, Some(msg_id)).await;

    match status {
        SendResult::Retry => {}
        SendResult::Success => {
            context
                .sql
                .execute("DELETE FROM smtp WHERE id=?", (rowid,))
                .await?;
        }
        SendResult::Failure(ref err) => {
            if err
                .to_string()
                .to_lowercase()
                .contains("invalid unencrypted mail")
            {
                let res = context
                    .sql
                    .query_row_optional(
                        "SELECT chat_id, timestamp FROM msgs WHERE id=?;",
                        (msg_id,),
                        |row| Ok((row.get::<_, ChatId>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .await?;

                if let Some((chat_id, timestamp_sort)) = res {
                    let addr = context.get_config(Config::ConfiguredAddr).await?;
                    let text = unencrypted_email(
                        context,
                        addr.unwrap_or_default()
                            .split('@')
                            .nth(1)
                            .unwrap_or_default(),
                    )
                    .await;
                    add_info_msg_with_cmd(
                        context,
                        chat_id,
                        &text,
                        crate::mimeparser::SystemMessage::InvalidUnencryptedMail,
                        Some(timestamp_sort),
                        timestamp_sort,
                        None,
                        None,
                        None,
                    )
                    .await?;
                };
            }
            context
                .sql
                .execute("DELETE FROM smtp WHERE id=?", (rowid,))
                .await?;
        }
    };

    match status {
        SendResult::Retry => Err(format_err!("Retry")),
        SendResult::Success => {
            if !context
                .sql
                .exists("SELECT COUNT(*) FROM smtp WHERE msg_id=?", (msg_id,))
                .await?
            {
                msg_id.set_delivered(context).await?;
            }
            Ok(())
        }
        SendResult::Failure(err) => Err(format_err!("{err}")),
    }
}

/// Attempts to send queued MDNs.
async fn send_mdns(context: &Context, connection: &mut Smtp) -> Result<()> {
    loop {
        if !context.ratelimit.read().await.can_send() {
            info!(context, "Ratelimiter does not allow sending MDNs now.");
            return Ok(());
        }

        let more_mdns = send_mdn(context, connection).await?;
        if !more_mdns {
            // No more MDNs to send or one of them failed.
            return Ok(());
        }
    }
}

/// Tries to send all messages currently in `smtp`, `smtp_status_updates` and `smtp_mdns` tables.
pub(crate) async fn send_smtp_messages(context: &Context, connection: &mut Smtp) -> Result<()> {
    let ratelimited = if context.ratelimit.read().await.can_send() {
        // add status updates and sync messages to end of sending queue
        context.flush_status_updates().await?;
        false
    } else {
        true
    };

    let rowids = context
        .sql
        .query_map_vec("SELECT id FROM smtp ORDER BY id ASC", (), |row| {
            let rowid: i64 = row.get(0)?;
            Ok(rowid)
        })
        .await?;

    info!(context, "Selected rows from SMTP queue: {rowids:?}.");
    for rowid in rowids {
        send_msg_to_smtp(context, connection, rowid)
            .await
            .context("Failed to send message")?;
    }

    // although by slow sending, ratelimit may have been expired meanwhile,
    // do not attempt to send MDNs if ratelimited happened before on status-updates/sync:
    // instead, let the caller recall this function so that more important status-updates/sync are sent out.
    if !ratelimited {
        send_mdns(context, connection)
            .await
            .context("Failed to send MDNs")?;
    }
    Ok(())
}

/// Tries to send MDN for message identified by `rfc724_mdn` to `contact_id`.
///
/// Attempts to aggregate additional MDNs for `contact_id` into sent MDN.
///
/// On failure returns an error without removing any `smtp_mdns` entries, the caller is responsible
/// for removing the corresponding entry to prevent endless loop in case the entry is invalid, e.g.
/// points to non-existent message or contact.
///
/// Returns true on success, false on temporary error.
async fn send_mdn_rfc724_mid(
    context: &Context,
    rfc724_mid: &str,
    contact_id: ContactId,
    smtp: &mut Smtp,
) -> Result<bool> {
    let contact = Contact::get_by_id(context, contact_id).await?;
    if contact.is_blocked() {
        return Err(format_err!("Contact is blocked"));
    }

    // Try to aggregate additional MDNs into this MDN.
    let additional_rfc724_mids = context
        .sql
        .query_map_vec(
            "SELECT rfc724_mid
             FROM smtp_mdns
             WHERE from_id=? AND rfc724_mid!=?",
            (contact_id, &rfc724_mid),
            |row| {
                let rfc724_mid: String = row.get(0)?;
                Ok(rfc724_mid)
            },
        )
        .await?;

    let mimefactory = MimeFactory::from_mdn(
        context,
        contact_id,
        rfc724_mid.to_string(),
        additional_rfc724_mids.clone(),
    )
    .await?;
    let rendered_msg = mimefactory.render(context).await?;
    let body = rendered_msg.message;

    let addr = contact.get_addr();
    let recipient = async_smtp::EmailAddress::new(addr.to_string())
        .map_err(|err| format_err!("invalid recipient: {addr} {err:?}"))?;
    let recipients = vec![recipient];

    match smtp_send(context, &recipients, &body, smtp, None).await {
        SendResult::Success => {
            info!(context, "Successfully sent MDN for {rfc724_mid}.");
            context
                .sql
                .transaction(|transaction| {
                    let mut stmt =
                        transaction.prepare("DELETE FROM smtp_mdns WHERE rfc724_mid = ?")?;
                    stmt.execute((rfc724_mid,))?;
                    for additional_rfc724_mid in additional_rfc724_mids {
                        stmt.execute((additional_rfc724_mid,))?;
                    }
                    Ok(())
                })
                .await?;
            Ok(true)
        }
        SendResult::Retry => {
            info!(
                context,
                "Temporary SMTP failure while sending an MDN for {rfc724_mid}."
            );
            Ok(false)
        }
        SendResult::Failure(err) => Err(err),
    }
}

/// Tries to send a single MDN. Returns true if more MDNs should be sent.
async fn send_mdn(context: &Context, smtp: &mut Smtp) -> Result<bool> {
    if !context.should_send_mdns().await? {
        context.sql.execute("DELETE FROM smtp_mdns", []).await?;
        return Ok(false);
    }
    info!(context, "Sending MDNs.");

    context
        .sql
        .execute("DELETE FROM smtp_mdns WHERE retries > 6", [])
        .await?;
    let Some(msg_row) = context
        .sql
        .query_row_optional(
            "SELECT rfc724_mid, from_id FROM smtp_mdns ORDER BY retries LIMIT 1",
            [],
            |row| {
                let rfc724_mid: String = row.get(0)?;
                let from_id: ContactId = row.get(1)?;
                Ok((rfc724_mid, from_id))
            },
        )
        .await?
    else {
        return Ok(false);
    };
    let (rfc724_mid, contact_id) = msg_row;

    context
        .sql
        .execute(
            "UPDATE smtp_mdns SET retries=retries+1 WHERE rfc724_mid=?",
            (rfc724_mid.clone(),),
        )
        .await
        .context("Failed to update MDN retries count")?;

    match send_mdn_rfc724_mid(context, &rfc724_mid, contact_id, smtp).await {
        Err(err) => {
            // If there is an error, for example there is no message corresponding to the msg_id in the
            // database, do not try to send this MDN again.
            warn!(
                context,
                "Error sending MDN for {rfc724_mid}, removing it: {err:#}."
            );
            context
                .sql
                .execute("DELETE FROM smtp_mdns WHERE rfc724_mid = ?", (rfc724_mid,))
                .await?;
            Err(err)
        }
        Ok(false) => {
            bail!("Temporary error while sending an MDN");
        }
        Ok(true) => {
            // Successfully sent MDN.
            Ok(true)
        }
    }
}
