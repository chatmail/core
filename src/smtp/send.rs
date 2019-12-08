//! # SMTP message sending

use super::Smtp;
use async_smtp::*;

use async_std::task;

use crate::context::Context;
use crate::events::Event;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Envelope error: {}", _0)]
    EnvelopeError(#[cause] async_smtp::error::Error),
    #[fail(display = "Send error: {}", _0)]
    SendError(#[cause] async_smtp::smtp::error::Error),
    #[fail(display = "SMTP has no transport")]
    NoTransport,
}

impl Smtp {
    /// Send a prepared mail to recipients.
    /// On successful send out Ok() is returned.
    pub fn send(
        &mut self,
        context: &Context,
        recipients: Vec<EmailAddress>,
        message: Vec<u8>,
        job_id: u32,
    ) -> Result<()> {
        let message_len = message.len();

        let recipients_display = recipients
            .iter()
            .map(|x| format!("{}", x))
            .collect::<Vec<String>>()
            .join(",");

        if let Some(ref mut transport) = self.transport {
            let envelope =
                Envelope::new(self.from.clone(), recipients).map_err(Error::EnvelopeError)?;
            let mail = SendableEmail::new(
                envelope,
                format!("{}", job_id), // only used for internal logging
                message,
            );

            task::block_on(transport.send(mail)).map_err(Error::SendError)?;

            context.call_cb(Event::SmtpMessageSent(format!(
                "Message len={} was smtp-sent to {}",
                message_len, recipients_display
            )));
            self.transport_connected = true;
            Ok(())
        } else {
            warn!(
                context,
                "uh? SMTP has no transport, failed to send to {}", recipients_display
            );
            Err(Error::NoTransport)
        }
    }
}
