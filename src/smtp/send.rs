//! # SMTP message sending

use anyhow::Context as _;
use async_smtp::{EmailAddress, Envelope, SendableEmail};

use super::Connection;
use crate::config::Config;
use crate::context::Context;
use crate::tools;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Send error: {}", _0)]
    SmtpSend(async_smtp::error::Error),
    #[error("{}", _0)]
    Other(#[from] anyhow::Error),
}

impl Connection {
    /// Send a prepared mail to recipients.
    /// On successful send out Ok() is returned.
    pub(super) async fn send(
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

        let envelope = Envelope::new(Some(self.from.clone()), recipients.to_vec())
            .context("Envelope error")?;
        let mail = SendableEmail::new(envelope, message);

        self.transport.send(mail).await.map_err(Error::SmtpSend)?;

        self.last_success = tools::Time::now();
        Ok(())
    }
}
