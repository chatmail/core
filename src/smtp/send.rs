//! # SMTP message sending

use async_smtp::{EmailAddress, Envelope, SendableEmail};

use super::Smtp;
use crate::config::Config;
use crate::context::Context;
use crate::events::EventType;
use crate::log::warn;
use crate::tools;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Envelope error: {}", _0)]
    Envelope(anyhow::Error),
    #[error("Send error: {}", _0)]
    SmtpSend(async_smtp::error::Error),
    #[error("SMTP has no transport")]
    NoTransport,
    #[error("{}", _0)]
    Other(#[from] anyhow::Error),
}

impl Smtp {
    /// Send a prepared mail to recipients.
    /// On successful send out Ok() is returned.
    pub async fn send(
        &mut self,
        context: &Context,
        recipients: &[EmailAddress],
        message: &[u8],
    ) -> Result<()> {
        if !context.get_config_bool(Config::Bot).await? {
            // Notify ratelimiter about sent message regardless of whether quota is exceeded or not.
            // Checking whether sending is allowed for low-priority messages should be done by the
            // caller.
            context.ratelimit.write().await.send();
        }

        let message_len_bytes = message.len();
        let recipients_display = recipients
            .iter()
            .map(|x| x.as_ref())
            .collect::<Vec<&str>>()
            .join(",");

        let envelope =
            Envelope::new(self.from.clone(), recipients.to_vec()).map_err(Error::Envelope)?;
        let mail = SendableEmail::new(envelope, message);

        if let Some(ref mut transport) = self.transport {
            transport.send(mail).await.map_err(Error::SmtpSend)?;

            let info_msg =
                format!("Message len={message_len_bytes} was SMTP-sent to {recipients_display}");
            info!(context, "{info_msg}.");
            context.emit_event(EventType::SmtpMessageSent(info_msg));
            self.last_success = Some(tools::Time::now());
        } else {
            warn!(
                context,
                "uh? SMTP has no transport, failed to send to {}", recipients_display
            );
            return Err(Error::NoTransport);
        }
        Ok(())
    }
}
