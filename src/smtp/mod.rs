//! # SMTP transport module

pub mod send;

use std::time::{Duration, Instant};

use async_smtp::smtp::client::net::*;
use async_smtp::*;

use crate::context::Context;
use crate::events::Event;
use crate::login_param::{dc_build_tls, LoginParam, ServerSecurity, IDX_SMTP};
use crate::oauth2::*;
use crate::stock::StockMessage;

/// SMTP write and read timeout in seconds.
const SMTP_TIMEOUT: u64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Bad parameters")]
    BadParameters,

    #[error("Invalid login address {address}: {error}")]
    InvalidLoginAddress {
        address: String,
        #[source]
        error: error::Error,
    },

    #[error("SMTP: failed to connect: {0:?}")]
    ConnectionFailure(#[source] smtp::error::Error),

    #[error("SMTP: failed to setup connection {0:?}")]
    ConnectionSetupFailure(#[source] smtp::error::Error),

    #[error("SMTP: oauth2 error {address}")]
    Oauth2Error { address: String },

    #[error("TLS error")]
    Tls(#[from] async_native_tls::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, DebugStub)]
pub struct Smtp {
    #[debug_stub(some = "SmtpTransport")]
    transport: Option<smtp::SmtpTransport>,

    /// Email address we are sending from.
    from: Option<EmailAddress>,

    /// Timestamp of last successful send/receive network interaction
    /// (eg connect or send succeeded). On initialization and disconnect
    /// it is set to None.
    last_success: Option<Instant>,
}

impl Smtp {
    /// Create a new Smtp instances.
    pub fn new() -> Self {
        Default::default()
    }

    /// Disconnect the SMTP transport and drop it entirely.
    pub async fn disconnect(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            transport.close().await.ok();
        }
        self.last_success = None;
    }

    /// Return true if smtp was connected but is not known to
    /// have been successfully used the last 60 seconds
    pub async fn has_maybe_stale_connection(&self) -> bool {
        if let Some(last_success) = self.last_success {
            Instant::now().duration_since(last_success).as_secs() > 60
        } else {
            false
        }
    }

    /// Check whether we are connected.
    pub async fn is_connected(&self) -> bool {
        self.transport
            .as_ref()
            .map(|t| t.is_connected())
            .unwrap_or_default()
    }

    /// Connect using the provided login params.
    pub async fn connect(&mut self, context: &Context, lp: &LoginParam) -> Result<()> {
        if self.is_connected().await {
            warn!(context, "SMTP already connected.");
            return Ok(());
        }

        if lp.srv_params[IDX_SMTP].hostname.is_empty() || lp.srv_params[IDX_SMTP].port == 0 {
            context.emit_event(Event::ErrorNetwork("SMTP bad parameters.".into()));
            return Err(Error::BadParameters);
        }

        let from =
            EmailAddress::new(lp.addr.clone()).map_err(|err| Error::InvalidLoginAddress {
                address: lp.addr.clone(),
                error: err,
            })?;

        self.from = Some(from);

        let domain = &lp.srv_params[IDX_SMTP].hostname;
        let port = lp.srv_params[IDX_SMTP].port as u16;

        let tls_config = dc_build_tls(lp.srv_params[IDX_SMTP].certificate_checks);
        let tls_parameters = ClientTlsParameters::new(domain.to_string(), tls_config);

        let (creds, mechanism) = if lp.auth_scheme.is_oauth2() {
            // oauth2
            let addr = &lp.addr;
            let send_pw = &lp.srv_params[IDX_SMTP].pw;
            let access_token = dc_get_oauth2_access_token(context, addr, send_pw, false).await;
            if access_token.is_none() {
                return Err(Error::Oauth2Error {
                    address: addr.to_string(),
                });
            }
            let user = &lp.srv_params[IDX_SMTP].user;
            (
                smtp::authentication::Credentials::new(
                    user.to_string(),
                    access_token.unwrap_or_default(),
                ),
                vec![smtp::authentication::Mechanism::Xoauth2],
            )
        } else {
            // plain
            let user = lp.srv_params[IDX_SMTP].user.clone();
            let pw = lp.srv_params[IDX_SMTP].pw.clone();
            (
                smtp::authentication::Credentials::new(user, pw),
                vec![
                    smtp::authentication::Mechanism::Plain,
                    smtp::authentication::Mechanism::Login,
                ],
            )
        };

        let security = match lp.srv_params[IDX_SMTP].security.unwrap() {
            ServerSecurity::Ssl => smtp::ClientSecurity::Wrapper(tls_parameters),
            _ => smtp::ClientSecurity::Opportunistic(tls_parameters),
        };

        let client = smtp::SmtpClient::with_security((domain.as_str(), port), security)
            .await
            .map_err(Error::ConnectionSetupFailure)?;

        let client = client
            .smtp_utf8(true)
            .credentials(creds)
            .authentication_mechanism(mechanism)
            .connection_reuse(smtp::ConnectionReuseParameters::ReuseUnlimited)
            .timeout(Some(Duration::from_secs(SMTP_TIMEOUT)));

        let mut trans = client.into_transport();
        if let Err(err) = trans.connect().await {
            let message = context
                .stock_string_repl_str2(
                    StockMessage::ServerResponse,
                    format!("SMTP {}:{}", domain, port),
                    err.to_string(),
                )
                .await;

            emit_event!(context, Event::ErrorNetwork(message));
            return Err(Error::ConnectionFailure(err));
        }

        self.transport = Some(trans);
        self.last_success = Some(Instant::now());

        context.emit_event(Event::SmtpConnected(format!(
            "SMTP-LOGIN as {} ok",
            lp.srv_params[IDX_SMTP].user,
        )));

        Ok(())
    }

    pub(crate) async fn try_connect(&mut self, context: &Context, lp: &LoginParam) -> bool {
        match self.connect(context, lp).await {
            Ok(()) => true,
            Err(err) => {
                warn!(context, "SMTP connection error: {}", err);
                false
            }
        }
    }
}
