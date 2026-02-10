//! # Common network utilities.
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::time::Duration;

use anyhow::{Context as _, Result, format_err};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_io_timeout::TimeoutStream;

use crate::context::Context;
use crate::net::session::SessionStream;
use crate::net::tls::TlsSessionStore;
use crate::sql::Sql;
use crate::tools::time;

pub(crate) mod dns;
pub(crate) mod http;
pub(crate) mod proxy;
pub(crate) mod session;
pub(crate) mod tls;

use dns::lookup_host_with_cache;
pub use http::{Response as HttpResponse, read_url, read_url_blob};
use tls::wrap_tls;

/// Connection, write and read timeout.
///
/// This constant should be more than the largest expected RTT.
pub(crate) const TIMEOUT: Duration = Duration::from_secs(60);

/// TTL for caches in seconds.
pub(crate) const CACHE_TTL: u64 = 30 * 24 * 60 * 60;

/// Removes connection history entries after `CACHE_TTL`.
pub(crate) async fn prune_connection_history(context: &Context) -> Result<()> {
    let now = time();
    context
        .sql
        .execute(
            "DELETE FROM connection_history
             WHERE ? > timestamp + ?",
            (now, CACHE_TTL),
        )
        .await?;
    Ok(())
}

/// Update the timestamp of the last successful connection
/// to the given `host` and `port`
/// with the given application protocol `alpn`.
///
/// `addr` is the string representation of IP address.
/// If connection is made over a proxy which does
/// its own DNS resolution,
/// `addr` should be the same as `host`.
pub(crate) async fn update_connection_history(
    context: &Context,
    alpn: &str,
    host: &str,
    port: u16,
    addr: &str,
    now: i64,
) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO connection_history (host, port, alpn, addr, timestamp)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT (host, port, alpn, addr)
             DO UPDATE SET timestamp=excluded.timestamp",
            (host, port, alpn, addr, now),
        )
        .await?;
    Ok(())
}

/// Returns timestamp of the most recent successful connection
/// to the host and port for given protocol.
pub(crate) async fn load_connection_timestamp(
    sql: &Sql,
    alpn: &str,
    host: &str,
    port: u16,
    addr: Option<&str>,
) -> Result<Option<i64>> {
    let timestamp = sql
        .query_get_value(
            "SELECT timestamp FROM connection_history
             WHERE host = ?
               AND port = ?
               AND alpn = ?
               AND addr = IFNULL(?, addr)",
            (host, port, alpn, addr),
        )
        .await?;
    Ok(timestamp)
}

/// Returns a TCP connection stream with read/write timeouts set
/// and Nagle's algorithm disabled with `TCP_NODELAY`.
///
/// `TCP_NODELAY` ensures writing to the stream always results in immediate sending of the packet
/// to the network, which is important to reduce the latency of interactive protocols such as IMAP.
pub(crate) async fn connect_tcp_inner(
    addr: SocketAddr,
) -> Result<Pin<Box<TimeoutStream<TcpStream>>>> {
    let tcp_stream = timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .context("Connection timeout")?
        .context("Connection failure")?;

    // Disable Nagle's algorithm.
    tcp_stream.set_nodelay(true)?;

    let mut timeout_stream = TimeoutStream::new(tcp_stream);
    timeout_stream.set_write_timeout(Some(TIMEOUT));
    timeout_stream.set_read_timeout(Some(TIMEOUT));

    Ok(Box::pin(timeout_stream))
}

/// Attempts to establish TLS connection
/// given the result of the hostname to address resolution.
pub(crate) async fn connect_tls_inner(
    addr: SocketAddr,
    host: &str,
    strict_tls: bool,
    alpn: &str,
    tls_session_store: &TlsSessionStore,
) -> Result<impl SessionStream + 'static> {
    let use_sni = true;
    let tcp_stream = connect_tcp_inner(addr).await?;
    let tls_stream = wrap_tls(
        strict_tls,
        host,
        addr.port(),
        use_sni,
        alpn,
        tcp_stream,
        tls_session_store,
    )
    .await?;
    Ok(tls_stream)
}

/// Runs connection attempt futures.
///
/// Accepts iterator of connection attempt futures
/// and runs them until one of them succeeds
/// or all of them fail.
///
/// If all connection attempts fail, returns the first error.
///
/// This functions starts with one connection attempt and maintains
/// up to five parallel connection attempts if connecting takes time.
pub(crate) async fn run_connection_attempts<O, I, F>(mut futures: I) -> Result<O>
where
    I: Iterator<Item = F>,
    F: Future<Output = Result<O>> + Send + 'static,
    O: Send + 'static,
{
    let mut connection_attempt_set = JoinSet::new();

    // Start additional connection attempts after 300 ms, 1 s, 5 s and 10 s.
    // This way we can have up to 5 parallel connection attempts at the same time.
    let mut delay_set = JoinSet::new();
    for delay in [
        Duration::from_millis(300),
        Duration::from_secs(1),
        Duration::from_secs(5),
        Duration::from_secs(10),
    ] {
        delay_set.spawn(tokio::time::sleep(delay));
    }

    let mut first_error = None;

    let res = loop {
        if let Some(fut) = futures.next() {
            connection_attempt_set.spawn(fut);
        }

        tokio::select! {
            biased;

            res = connection_attempt_set.join_next() => {
                match res {
                    Some(res) => {
                        match res.context("Failed to join task") {
                            Ok(Ok(conn)) => {
                                // Successfully connected.
                                break Ok(conn);
                            }
                            Ok(Err(err)) => {
                                // Some connection attempt failed.
                                first_error.get_or_insert(err);
                            }
                            Err(err) => {
                                break Err(err);
                            }
                        }
                    }
                    None => {
                        // Out of connection attempts.
                        //
                        // Break out of the loop and return error.
                        break Err(
                            first_error.unwrap_or_else(|| format_err!("No connection attempts were made"))
                        );
                    }
                }
            },

            _ = delay_set.join_next(), if !delay_set.is_empty() => {
                // Delay expired.
                //
                // Don't do anything other than pushing
                // another connection attempt into `connection_attempt_set`.
            }
        }
    };

    // Abort remaining connection attempts and free resources
    // such as OS sockets and `Context` references
    // held by connection attempt tasks.
    //
    // `delay_set` contains just `sleep` tasks
    // so no need to await futures there,
    // it is enough that futures are aborted
    // when the set is dropped.
    connection_attempt_set.shutdown().await;

    res
}

/// If `load_cache` is true, may use cached DNS results.
/// Because the cache may be poisoned with incorrect results by networks hijacking DNS requests,
/// this option should only be used when connection is authenticated,
/// for example using TLS.
/// If TLS is not used or invalid TLS certificates are allowed,
/// this option should be disabled.
pub(crate) async fn connect_tcp(
    context: &Context,
    host: &str,
    port: u16,
    load_cache: bool,
) -> Result<Pin<Box<TimeoutStream<TcpStream>>>> {
    let connection_futures = lookup_host_with_cache(context, host, port, "", load_cache)
        .await?
        .into_iter()
        .map(connect_tcp_inner);
    run_connection_attempts(connection_futures).await
}
