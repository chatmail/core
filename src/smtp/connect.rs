//! SMTP connection establishment.

use std::net::SocketAddr;

use anyhow::{Context as _, Result, bail};
use async_smtp::{SmtpClient, SmtpTransport};
use tokio::io::{AsyncBufRead, AsyncWrite, BufStream};

use crate::context::Context;
use crate::log::warn;
use crate::net::dns::{lookup_host_with_cache, update_connect_timestamp};
use crate::net::proxy::ProxyConfig;
use crate::net::session::SessionBufStream;
use crate::net::tls::{TlsSessionStore, wrap_tls};
use crate::net::{
    connect_tcp_inner, connect_tls_inner, run_connection_attempts, update_connection_history,
};
use crate::oauth2::get_oauth2_access_token;
use crate::tools::time;
use crate::transport::ConnectionCandidate;
use crate::transport::ConnectionSecurity;

/// Converts port number to ALPN.
fn alpn(port: u16) -> &'static str {
    if port == 465 {
        // Do not request ALPN on standard port.
        ""
    } else {
        "smtp"
    }
}

// Constructs a new SMTP transport
// over a stream with already skipped SMTP greeting.
async fn new_smtp_transport<S: AsyncBufRead + AsyncWrite + Unpin>(
    stream: S,
) -> Result<SmtpTransport<S>> {
    // We always read the greeting manually to unify
    // the cases of STARTTLS where the greeting is
    // sent outside the encrypted channel and implicit TLS
    // where the greeting is sent after establishing TLS channel.
    let client = SmtpClient::new().smtp_utf8(true).without_greeting();

    let transport = SmtpTransport::new(client, stream)
        .await
        .context("Failed to send EHLO command")?;
    Ok(transport)
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn connect_and_auth(
    context: &Context,
    proxy_config: &Option<ProxyConfig>,
    strict_tls: bool,
    candidate: ConnectionCandidate,
    oauth2: bool,
    addr: &str,
    user: &str,
    password: &str,
) -> Result<SmtpTransport<Box<dyn SessionBufStream>>> {
    let session_stream = connect_stream(context, proxy_config.clone(), strict_tls, candidate)
        .await
        .context("SMTP failed to connect")?;
    let mut transport = new_smtp_transport(session_stream).await?;

    // Authenticate.
    let (creds, mechanism) = if oauth2 {
        // oauth2
        let access_token = get_oauth2_access_token(context, addr, password, false)
            .await
            .context("SMTP failed to get OAUTH2 access token")?;
        if access_token.is_none() {
            bail!("SMTP OAuth 2 error {addr}");
        }
        (
            async_smtp::authentication::Credentials::new(
                user.to_string(),
                access_token.unwrap_or_default(),
            ),
            vec![async_smtp::authentication::Mechanism::Xoauth2],
        )
    } else {
        // plain
        (
            async_smtp::authentication::Credentials::new(user.to_string(), password.to_string()),
            vec![
                async_smtp::authentication::Mechanism::Plain,
                async_smtp::authentication::Mechanism::Login,
            ],
        )
    };
    transport
        .try_login(&creds, &mechanism)
        .await
        .context("SMTP failed to login")?;
    Ok(transport)
}

async fn connection_attempt(
    context: Context,
    host: String,
    security: ConnectionSecurity,
    resolved_addr: SocketAddr,
    strict_tls: bool,
) -> Result<Box<dyn SessionBufStream>> {
    let context = &context;
    let host = &host;
    info!(
        context,
        "Attempting SMTP connection to {host} ({resolved_addr})."
    );
    let res = match security {
        ConnectionSecurity::Tls => {
            connect_secure(resolved_addr, host, strict_tls, &context.tls_session_store).await
        }
        ConnectionSecurity::Starttls => {
            connect_starttls(resolved_addr, host, strict_tls, &context.tls_session_store).await
        }
        ConnectionSecurity::Plain => connect_insecure(resolved_addr).await,
    };
    match res {
        Ok(stream) => {
            let ip_addr = resolved_addr.ip().to_string();
            let port = resolved_addr.port();

            let save_cache = match security {
                ConnectionSecurity::Tls | ConnectionSecurity::Starttls => strict_tls,
                ConnectionSecurity::Plain => false,
            };
            if save_cache {
                update_connect_timestamp(context, host, &ip_addr).await?;
            }
            update_connection_history(context, "smtp", host, port, &ip_addr, time()).await?;
            Ok(stream)
        }
        Err(err) => {
            warn!(
                context,
                "SMTP failed to connect to {host} ({resolved_addr}): {err:#}."
            );
            Err(err)
        }
    }
}

/// Returns TLS, STARTTLS or plaintext connection
/// using SOCKS5 or direct connection depending on the given configuration.
///
/// Connection is returned after skipping the welcome message
/// and is ready for sending commands. Because SMTP STARTTLS
/// does not send welcome message over TLS connection
/// after establishing it, welcome message is always ignored
/// to unify the result regardless of whether TLS or STARTTLS is used.
async fn connect_stream(
    context: &Context,
    proxy_config: Option<ProxyConfig>,
    strict_tls: bool,
    candidate: ConnectionCandidate,
) -> Result<Box<dyn SessionBufStream>> {
    let host = &candidate.host;
    let port = candidate.port;
    let security = candidate.security;

    if let Some(proxy_config) = proxy_config {
        let stream = match security {
            ConnectionSecurity::Tls => {
                connect_secure_proxy(context, host, port, strict_tls, proxy_config.clone()).await?
            }
            ConnectionSecurity::Starttls => {
                connect_starttls_proxy(context, host, port, strict_tls, proxy_config.clone())
                    .await?
            }
            ConnectionSecurity::Plain => {
                connect_insecure_proxy(context, host, port, proxy_config.clone()).await?
            }
        };
        update_connection_history(context, "smtp", host, port, host, time()).await?;
        Ok(stream)
    } else {
        let load_cache = match security {
            ConnectionSecurity::Tls | ConnectionSecurity::Starttls => strict_tls,
            ConnectionSecurity::Plain => false,
        };

        let connection_futures = lookup_host_with_cache(context, host, port, "smtp", load_cache)
            .await?
            .into_iter()
            .map(|resolved_addr| {
                let context = context.clone();
                let host = host.to_string();
                connection_attempt(context, host, security, resolved_addr, strict_tls)
            });
        run_connection_attempts(connection_futures).await
    }
}

/// Reads and ignores SMTP greeting.
///
/// This function is used to unify
/// TLS, STARTTLS and plaintext connection setup
/// by skipping the greeting in case of TLS
/// and STARTTLS connection setup.
async fn skip_smtp_greeting<R: tokio::io::AsyncBufReadExt + Unpin>(stream: &mut R) -> Result<()> {
    let mut line = String::with_capacity(512);
    loop {
        line.clear();
        let read = stream
            .read_line(&mut line)
            .await
            .context("Failed to read from stream while waiting for SMTP greeting")?;
        if read == 0 {
            bail!("Unexpected EOF while reading SMTP greeting");
        }
        if line.starts_with("220-") {
            continue;
        } else if line.starts_with("220 ") {
            return Ok(());
        } else {
            bail!("Unexpected greeting: {line:?}");
        }
    }
}

async fn connect_secure_proxy(
    context: &Context,
    hostname: &str,
    port: u16,
    strict_tls: bool,
    proxy_config: ProxyConfig,
) -> Result<Box<dyn SessionBufStream>> {
    let use_sni = true;
    let proxy_stream = proxy_config
        .connect(context, hostname, port, strict_tls)
        .await?;
    let tls_stream = wrap_tls(
        strict_tls,
        hostname,
        port,
        use_sni,
        alpn(port),
        proxy_stream,
        &context.tls_session_store,
    )
    .await?;
    let mut buffered_stream = BufStream::new(tls_stream);
    skip_smtp_greeting(&mut buffered_stream).await?;
    let session_stream: Box<dyn SessionBufStream> = Box::new(buffered_stream);
    Ok(session_stream)
}

async fn connect_starttls_proxy(
    context: &Context,
    hostname: &str,
    port: u16,
    strict_tls: bool,
    proxy_config: ProxyConfig,
) -> Result<Box<dyn SessionBufStream>> {
    let use_sni = false;
    let proxy_stream = proxy_config
        .connect(context, hostname, port, strict_tls)
        .await?;

    // Run STARTTLS command and convert the client back into a stream.
    let mut buffered_stream = BufStream::new(proxy_stream);
    skip_smtp_greeting(&mut buffered_stream).await?;
    let transport = new_smtp_transport(buffered_stream).await?;
    let tcp_stream = transport.starttls().await?.into_inner();
    let tls_stream = wrap_tls(
        strict_tls,
        hostname,
        port,
        use_sni,
        "",
        tcp_stream,
        &context.tls_session_store,
    )
    .await
    .context("STARTTLS upgrade failed")?;
    let buffered_stream = BufStream::new(tls_stream);
    let session_stream: Box<dyn SessionBufStream> = Box::new(buffered_stream);
    Ok(session_stream)
}

async fn connect_insecure_proxy(
    context: &Context,
    hostname: &str,
    port: u16,
    proxy_config: ProxyConfig,
) -> Result<Box<dyn SessionBufStream>> {
    let proxy_stream = proxy_config.connect(context, hostname, port, false).await?;
    let mut buffered_stream = BufStream::new(proxy_stream);
    skip_smtp_greeting(&mut buffered_stream).await?;
    let session_stream: Box<dyn SessionBufStream> = Box::new(buffered_stream);
    Ok(session_stream)
}

async fn connect_secure(
    addr: SocketAddr,
    hostname: &str,
    strict_tls: bool,
    tls_session_store: &TlsSessionStore,
) -> Result<Box<dyn SessionBufStream>> {
    let tls_stream = connect_tls_inner(
        addr,
        hostname,
        strict_tls,
        alpn(addr.port()),
        tls_session_store,
    )
    .await?;
    let mut buffered_stream = BufStream::new(tls_stream);
    skip_smtp_greeting(&mut buffered_stream).await?;
    let session_stream: Box<dyn SessionBufStream> = Box::new(buffered_stream);
    Ok(session_stream)
}

async fn connect_starttls(
    addr: SocketAddr,
    host: &str,
    strict_tls: bool,
    tls_session_store: &TlsSessionStore,
) -> Result<Box<dyn SessionBufStream>> {
    let use_sni = false;
    let tcp_stream = connect_tcp_inner(addr).await?;

    // Run STARTTLS command and convert the client back into a stream.
    let mut buffered_stream = BufStream::new(tcp_stream);
    skip_smtp_greeting(&mut buffered_stream).await?;
    let transport = new_smtp_transport(buffered_stream).await?;
    let tcp_stream = transport.starttls().await?.into_inner();
    let tls_stream = wrap_tls(
        strict_tls,
        host,
        addr.port(),
        use_sni,
        "",
        tcp_stream,
        tls_session_store,
    )
    .await
    .context("STARTTLS upgrade failed")?;

    let buffered_stream = BufStream::new(tls_stream);
    let session_stream: Box<dyn SessionBufStream> = Box::new(buffered_stream);
    Ok(session_stream)
}

async fn connect_insecure(addr: SocketAddr) -> Result<Box<dyn SessionBufStream>> {
    let tcp_stream = connect_tcp_inner(addr).await?;
    let mut buffered_stream = BufStream::new(tcp_stream);
    skip_smtp_greeting(&mut buffered_stream).await?;
    let session_stream: Box<dyn SessionBufStream> = Box::new(buffered_stream);
    Ok(session_stream)
}

#[cfg(test)]
mod tests {
    use tokio::io::BufReader;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_skip_smtp_greeting() -> Result<()> {
        let greeting = b"220-server261.web-hosting.com ESMTP Exim 4.96.2 #2 Sat, 24 Aug 2024 12:25:53 -0400 \r\n\
                         220-We do not authorize the use of this system to transport unsolicited,\r\n\
                         220 and/or bulk e-mail.\r\n";
        let mut buffered_stream = BufReader::new(&greeting[..]);
        skip_smtp_greeting(&mut buffered_stream).await
    }
}
