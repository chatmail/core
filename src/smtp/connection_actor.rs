//! # Module for actor maintaining a single SMTP connection.
//!
//! [ConnectionActor] is the actor that processes messages
//! of [ConnectionActorMessage] type.
//! [ConnectionActor::run()] is supposed to be run in a separate task.
//! [ConnectionActorHandle] is the sender of the actor messages,
//! dropping it also closes the channel and terminates the actor.

use anyhow::{Error, Result, format_err};
use async_smtp::response::{Category, Code, Detail};
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use crate::context::Context;
use crate::log::warn;
use crate::net::proxy::ProxyConfig;
use crate::smtp::Connection;
use crate::smtp::send;
use crate::tools::time_elapsed;
use crate::transport::ConfiguredLoginParam;

/// Possible outcomes of sending a mail.
#[derive(Debug)]
pub(super) enum SendResult {
    /// Message was sent successfully.
    Success,

    /// Permanent SMTP error, message sending has failed.
    ///
    /// Error message may be displayed to the user as the reason
    /// for why the message was not sent.
    PermanentFailure(Error),

    /// Temporary SMTP error.
    TemporaryFailure(Error),

    /// Other temporary error, e.g. timeout.
    Retry,
}

#[derive(Debug)]
pub(super) enum ConnectionActorMessage {
    /// Request for the actor to connect to SMTP server
    /// and report back when it has connected,
    /// but don't send anything yet.
    ///
    /// This message is useful if you have multiple actors
    /// and want to send message over the one that is ready first.
    /// It is not required to explicitly connect before sending a message.
    Connect {
        callback: oneshot::Sender<Result<()>>,
    },

    /// Sends a single queued mail.
    ///
    /// Actor connects as needed,
    /// it is not required to ask it to connect in advance.
    SendMail {
        callback: oneshot::Sender<SendResult>,

        /// Recipients for the `RCPT TO:` commands.
        recipients: Vec<async_smtp::EmailAddress>,

        /// SMTP DATA command payload.
        data: Bytes,
    },
}

/// SMTP actor that maintains connection to a single transport.
#[derive(Debug)]
pub(super) struct ConnectionActor {
    context: Context,

    proxy_config: Option<ProxyConfig>,

    login_param: ConfiguredLoginParam,

    /// Email address to use in `MAIL FROM` SMTP command.
    ///
    /// `login_param` contains the address as well,
    /// but this one is converted from a string.
    from: async_smtp::EmailAddress,

    /// SMTP connection.
    connection: Option<Connection>,
}

impl ConnectionActor {
    pub(super) fn new(
        context: Context,
        proxy_config: Option<ProxyConfig>,
        login_param: ConfiguredLoginParam,
    ) -> Result<Self> {
        let from = async_smtp::EmailAddress::new(login_param.addr.clone())?;
        Ok(Self {
            context,
            from,
            proxy_config,
            login_param,
            connection: None,
        })
    }

    async fn handle_message(&mut self, msg: ConnectionActorMessage) {
        match msg {
            ConnectionActorMessage::Connect { callback } => {
                let res = self.connect().await;
                let _ = callback.send(res);
            }
            ConnectionActorMessage::SendMail {
                callback,
                recipients,
                data,
            } => {
                let res = self.sendmail(recipients, data).await;
                let _ = callback.send(res);
            }
        }
    }

    pub(super) async fn run(mut self, mut rx: mpsc::Receiver<ConnectionActorMessage>) {
        while let Some(msg) = rx.recv().await {
            self.handle_message(msg).await;
        }
    }

    /// Handles [ConnectionActorMessage::Connect] requests.
    async fn connect(&mut self) -> Result<()> {
        if self.has_maybe_stale_connection() {
            info!(self.context, "Closing stale connection.");
            self.disconnect();
        }

        if self.connection.is_some() {
            return Ok(());
        }

        let connection = Connection::new(
            &self.context,
            &self.login_param.smtp,
            &self.login_param.smtp_password,
            &self.proxy_config,
            self.login_param.strict_tls(self.proxy_config.is_some())?,
        )
        .await?;
        self.connection = Some(connection);
        Ok(())
    }

    /// Handles [ConnectionActorMessage::SendMail] requests.
    async fn sendmail(
        &mut self,
        recipients: Vec<async_smtp::EmailAddress>,
        data: Bytes,
    ) -> SendResult {
        if recipients.is_empty() {
            return SendResult::Success;
        }
        if std::env::var(crate::DCC_MIME_DEBUG).is_ok() {
            info!(&self.context, "SMTP-sending out mime message:\n{data:?}");
        }
        if let Err(_err) = self.connect().await {
            return SendResult::Retry;
        }
        let Some(ref mut connection) = self.connection else {
            return SendResult::Retry;
        };

        let send_result = connection
            .send(&self.context, self.from.clone(), &recipients, &data)
            .await;

        match send_result {
            Err(send::Error::SmtpSend(err)) => {
                info!(&self.context, "SMTP failed to send: {err:?}.");

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
                                &self.context,
                                "Permanent error that is likely to actually be transient, postponing retry for later."
                            );
                            SendResult::TemporaryFailure(format_err!(
                                "Likely temporary SMTP error: {err}"
                            ))
                        } else {
                            info!(&self.context, "Permanent error, message sending failed.");
                            // If we do not retry, add an info message to the chat.
                            // Yandex error "554 5.7.1 [2] Message rejected under suspicion of SPAM; https://ya.cc/..."
                            // should definitely go here, because user has to open the link to
                            // resume message sending.
                            SendResult::PermanentFailure(format_err!("Permanent SMTP error: {err}"))
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
                            &self.context,
                            "Transient error {response:?}, postponing retry for later."
                        );
                        SendResult::TemporaryFailure(format_err!("Temporary SMTP error: {err}"))
                    }
                    _ => {
                        info!(
                            &self.context,
                            "Message sending failed without error returned by the server, retry later."
                        );
                        SendResult::Retry
                    }
                };

                info!(
                    &self.context,
                    "Failed to send message over SMTP, disconnecting."
                );
                self.disconnect();

                res
            }
            Err(send::Error::Other(err)) => {
                // Local error, job is invalid, do not retry.
                self.disconnect();
                warn!(&self.context, "Unable to load SMTP job: {err:#}.");
                SendResult::Retry
            }
            Ok(()) => SendResult::Success,
        }
    }

    /// Return true if smtp was connected but is not known to
    /// have been successfully used the last 60 seconds
    fn has_maybe_stale_connection(&self) -> bool {
        self.connection
            .as_ref()
            .is_some_and(|connection| time_elapsed(&connection.last_success).as_secs() > 60)
    }

    /// Disconnects the SMTP transport and drops it.
    fn disconnect(&mut self) {
        if let Some(mut connection) = self.connection.take() {
            // Closing connection with a QUIT command may take some time, especially if it's a
            // stale connection and an attempt to send the command times out. Send a command in a
            // separate task to avoid waiting for reply or timeout.
            tokio::task::spawn(async move { connection.transport.quit().await });
        }
    }
}

pub(super) struct ConnectionActorHandle {
    sender: mpsc::Sender<ConnectionActorMessage>,

    /// Email address stored in the handle for convenience.
    ///
    /// It is the address that should be used
    /// when rendering messages about to be sent over this connector.
    from: async_smtp::EmailAddress,
}

impl ConnectionActorHandle {
    pub(super) fn new(
        sender: mpsc::Sender<ConnectionActorMessage>,
        from: async_smtp::EmailAddress,
    ) -> Self {
        Self { sender, from }
    }

    pub(super) fn from(&self) -> &async_smtp::EmailAddress {
        &self.from
    }

    pub(super) async fn connect(&self) -> Result<()> {
        let (callback, callback_receiver) = oneshot::channel();
        let msg = ConnectionActorMessage::Connect { callback };
        self.sender.send(msg).await?;
        callback_receiver.await?
    }

    pub(super) async fn sendmail(
        &self,
        recipients: Vec<async_smtp::EmailAddress>,
        data: Bytes,
    ) -> Result<SendResult> {
        let (callback, callback_receiver) = oneshot::channel();
        let msg = ConnectionActorMessage::SendMail {
            callback,
            recipients,
            data,
        };
        self.sender.send(msg).await?;
        Ok(callback_receiver.await?)
    }
}
