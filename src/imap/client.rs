use std::net::SocketAddr;
use std::ops::{Deref, DerefMut};

use anyhow::{Context as _, Result};
use async_imap::Client as ImapClient;
use async_imap::Session as ImapSession;
use tokio::io::BufWriter;

use super::capabilities::Capabilities;
use crate::context::Context;
use crate::log::{LoggingStream, warn};
use crate::net::dns::{lookup_host_with_cache, update_connect_timestamp};
use crate::net::proxy::ProxyConfig;
use crate::net::session::SessionStream;
use crate::net::tls::wrap_tls;
use crate::net::{connect_tcp_inner, run_connection_attempts, update_connection_history};
use crate::tools::time;
use crate::transport::ConnectionCandidate;
use crate::transport::ConnectionSecurity;

#[derive(Debug)]
pub(crate) struct Client {
    inner: ImapClient<Box<dyn SessionStream>>,
}

impl Deref for Client {
    type Target = ImapClient<Box<dyn SessionStream>>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Converts port number to ALPN list.
fn alpn(port: u16) -> &'static str {
    if port == 993 {
        // Do not request ALPN on standard port.
        ""
    } else {
        "imap"
    }
}

/// Determine server capabilities.
///
/// If server supports ID capability, send our client ID.
pub(crate) async fn determine_capabilities(
    session: &mut ImapSession<Box<dyn SessionStream>>,
) -> Result<Capabilities> {
    let caps = session
        .capabilities()
        .await
        .context("CAPABILITY command error")?;
    let server_id = if caps.has_str("ID") {
        session.id([("name", Some("Delta Chat"))]).await?
    } else {
        None
    };
    let capabilities = Capabilities {
        can_idle: caps.has_str("IDLE"),
        can_move: caps.has_str("MOVE"),
        can_check_quota: caps.has_str("QUOTA"),
        can_condstore: caps.has_str("CONDSTORE"),
        can_metadata: caps.has_str("METADATA"),
        can_compress: caps.has_str("COMPRESS=DEFLATE"),
        can_push: caps.has_str("XDELTAPUSH"),
        is_chatmail: caps.has_str("XCHATMAIL"),
        server_id,
    };
    Ok(capabilities)
}

impl Client {
    fn new(stream: Box<dyn SessionStream>) -> Self {
        Self {
            inner: ImapClient::new(stream),
        }
    }

    pub(crate) async fn login(
        self,
        username: &str,
        password: &str,
    ) -> Result<ImapSession<Box<dyn SessionStream>>> {
        let Client { inner, .. } = self;

        let session = inner
            .login(username, password)
            .await
            .map_err(|(err, _client)| err)?;
        Ok(session)
    }

    pub(crate) async fn authenticate(
        self,
        auth_type: &str,
        authenticator: impl async_imap::Authenticator,
    ) -> Result<ImapSession<Box<dyn SessionStream>>> {
        let Client { inner, .. } = self;
        let session = inner
            .authenticate(auth_type, authenticator)
            .await
            .map_err(|(err, _client)| err)?;
        Ok(session)
    }

    async fn connection_attempt(
        context: Context,
        host: String,
        security: ConnectionSecurity,
        resolved_addr: SocketAddr,
        strict_tls: bool,
    ) -> Result<Self> {
        let context = &context;
        let host = &host;
        info!(
            context,
            "Attempting IMAP connection to {host} ({resolved_addr})."
        );
        let res = match security {
            ConnectionSecurity::Tls => {
                Client::connect_secure(context, resolved_addr, host, strict_tls).await
            }
            ConnectionSecurity::Starttls => {
                Client::connect_starttls(context, resolved_addr, host, strict_tls).await
            }
            ConnectionSecurity::Plain => Client::connect_insecure(context, resolved_addr).await,
        };
        match res {
            Ok(client) => {
                let ip_addr = resolved_addr.ip().to_string();
                let port = resolved_addr.port();

                let save_cache = match security {
                    ConnectionSecurity::Tls | ConnectionSecurity::Starttls => strict_tls,
                    ConnectionSecurity::Plain => false,
                };
                if save_cache {
                    update_connect_timestamp(context, host, &ip_addr).await?;
                }
                update_connection_history(context, "imap", host, port, &ip_addr, time()).await?;
                Ok(client)
            }
            Err(err) => {
                warn!(
                    context,
                    "IMAP failed to connect to {host} ({resolved_addr}): {err:#}."
                );
                Err(err)
            }
        }
    }

    pub async fn connect(
        context: &Context,
        proxy_config: Option<ProxyConfig>,
        strict_tls: bool,
        candidate: &ConnectionCandidate,
    ) -> Result<Self> {
        let host = &candidate.host;
        let port = candidate.port;
        let security = candidate.security;
        if let Some(proxy_config) = proxy_config {
            let client = match security {
                ConnectionSecurity::Tls => {
                    Client::connect_secure_proxy(context, host, port, strict_tls, proxy_config)
                        .await?
                }
                ConnectionSecurity::Starttls => {
                    Client::connect_starttls_proxy(context, host, port, proxy_config, strict_tls)
                        .await?
                }
                ConnectionSecurity::Plain => {
                    Client::connect_insecure_proxy(context, host, port, proxy_config).await?
                }
            };
            update_connection_history(context, "imap", host, port, host, time()).await?;
            Ok(client)
        } else {
            let load_cache = match security {
                ConnectionSecurity::Tls | ConnectionSecurity::Starttls => strict_tls,
                ConnectionSecurity::Plain => false,
            };

            let connection_futures =
                lookup_host_with_cache(context, host, port, "imap", load_cache)
                    .await?
                    .into_iter()
                    .map(|resolved_addr| {
                        let context = context.clone();
                        let host = host.to_string();
                        Self::connection_attempt(context, host, security, resolved_addr, strict_tls)
                    });
            run_connection_attempts(connection_futures).await
        }
    }

    async fn connect_secure(
        context: &Context,
        addr: SocketAddr,
        hostname: &str,
        strict_tls: bool,
    ) -> Result<Self> {
        let use_sni = true;
        let tcp_stream = connect_tcp_inner(addr).await?;
        let account_id = context.get_id();
        let events = context.events.clone();
        let logging_stream = LoggingStream::new(tcp_stream, account_id, events)?;
        let tls_stream = wrap_tls(
            strict_tls,
            hostname,
            addr.port(),
            use_sni,
            alpn(addr.port()),
            logging_stream,
            &context.tls_session_store,
        )
        .await?;
        let buffered_stream = BufWriter::new(tls_stream);
        let session_stream: Box<dyn SessionStream> = Box::new(buffered_stream);
        let mut client = Client::new(session_stream);
        let _greeting = client
            .read_response()
            .await?
            .context("Failed to read greeting")?;
        Ok(client)
    }

    async fn connect_insecure(context: &Context, addr: SocketAddr) -> Result<Self> {
        let tcp_stream = connect_tcp_inner(addr).await?;
        let account_id = context.get_id();
        let events = context.events.clone();
        let logging_stream = LoggingStream::new(tcp_stream, account_id, events)?;
        let buffered_stream = BufWriter::new(logging_stream);
        let session_stream: Box<dyn SessionStream> = Box::new(buffered_stream);
        let mut client = Client::new(session_stream);
        let _greeting = client
            .read_response()
            .await?
            .context("Failed to read greeting")?;
        Ok(client)
    }

    async fn connect_starttls(
        context: &Context,
        addr: SocketAddr,
        host: &str,
        strict_tls: bool,
    ) -> Result<Self> {
        let use_sni = false;
        let tcp_stream = connect_tcp_inner(addr).await?;

        let account_id = context.get_id();
        let events = context.events.clone();
        let tcp_stream = LoggingStream::new(tcp_stream, account_id, events)?;

        // Run STARTTLS command and convert the client back into a stream.
        let buffered_tcp_stream = BufWriter::new(tcp_stream);
        let mut client = async_imap::Client::new(buffered_tcp_stream);
        let _greeting = client
            .read_response()
            .await?
            .context("Failed to read greeting")?;
        client
            .run_command_and_check_ok("STARTTLS", None)
            .await
            .context("STARTTLS command failed")?;
        let buffered_tcp_stream = client.into_inner();
        let tcp_stream = buffered_tcp_stream.into_inner();

        let tls_stream = wrap_tls(
            strict_tls,
            host,
            addr.port(),
            use_sni,
            "",
            tcp_stream,
            &context.tls_session_store,
        )
        .await
        .context("STARTTLS upgrade failed")?;
        let buffered_stream = BufWriter::new(tls_stream);
        let session_stream: Box<dyn SessionStream> = Box::new(buffered_stream);
        let client = Client::new(session_stream);
        Ok(client)
    }

    async fn connect_secure_proxy(
        context: &Context,
        domain: &str,
        port: u16,
        strict_tls: bool,
        proxy_config: ProxyConfig,
    ) -> Result<Self> {
        let use_sni = true;
        let proxy_stream = proxy_config
            .connect(context, domain, port, strict_tls)
            .await?;
        let tls_stream = wrap_tls(
            strict_tls,
            domain,
            port,
            use_sni,
            alpn(port),
            proxy_stream,
            &context.tls_session_store,
        )
        .await?;
        let buffered_stream = BufWriter::new(tls_stream);
        let session_stream: Box<dyn SessionStream> = Box::new(buffered_stream);
        let mut client = Client::new(session_stream);
        let _greeting = client
            .read_response()
            .await?
            .context("Failed to read greeting")?;
        Ok(client)
    }

    async fn connect_insecure_proxy(
        context: &Context,
        domain: &str,
        port: u16,
        proxy_config: ProxyConfig,
    ) -> Result<Self> {
        let proxy_stream = proxy_config.connect(context, domain, port, false).await?;
        let buffered_stream = BufWriter::new(proxy_stream);
        let session_stream: Box<dyn SessionStream> = Box::new(buffered_stream);
        let mut client = Client::new(session_stream);
        let _greeting = client
            .read_response()
            .await?
            .context("Failed to read greeting")?;
        Ok(client)
    }

    async fn connect_starttls_proxy(
        context: &Context,
        hostname: &str,
        port: u16,
        proxy_config: ProxyConfig,
        strict_tls: bool,
    ) -> Result<Self> {
        let use_sni = false;
        let proxy_stream = proxy_config
            .connect(context, hostname, port, strict_tls)
            .await?;

        // Run STARTTLS command and convert the client back into a stream.
        let buffered_proxy_stream = BufWriter::new(proxy_stream);
        let mut client = ImapClient::new(buffered_proxy_stream);
        let _greeting = client
            .read_response()
            .await?
            .context("Failed to read greeting")?;
        client
            .run_command_and_check_ok("STARTTLS", None)
            .await
            .context("STARTTLS command failed")?;
        let buffered_proxy_stream = client.into_inner();
        let proxy_stream = buffered_proxy_stream.into_inner();

        let tls_stream = wrap_tls(
            strict_tls,
            hostname,
            port,
            use_sni,
            "",
            proxy_stream,
            &context.tls_session_store,
        )
        .await
        .context("STARTTLS upgrade failed")?;
        let buffered_stream = BufWriter::new(tls_stream);
        let session_stream: Box<dyn SessionStream> = Box::new(buffered_stream);
        let client = Client::new(session_stream);
        Ok(client)
    }
}
