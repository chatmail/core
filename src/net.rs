//! # Common network utilities.
use std::net::{IpAddr, SocketAddr};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{format_err, Context as _, Result};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;
use tokio_io_timeout::TimeoutStream;

use crate::context::Context;
use crate::tools::time;

pub(crate) mod http;
pub(crate) mod session;
pub(crate) mod tls;

pub use http::{read_url, read_url_blob, Response as HttpResponse};

async fn connect_tcp_inner(addr: SocketAddr, timeout_val: Duration) -> Result<TcpStream> {
    let tcp_stream = timeout(timeout_val, TcpStream::connect(addr))
        .await
        .context("connection timeout")?
        .context("connection failure")?;
    Ok(tcp_stream)
}

async fn lookup_host_with_timeout(
    hostname: &str,
    port: u16,
    timeout_val: Duration,
) -> Result<Vec<SocketAddr>> {
    let res = timeout(timeout_val, lookup_host((hostname, port)))
        .await
        .context("DNS lookup timeout")?
        .context("DNS lookup failure")?;
    Ok(res.collect())
}

/// Looks up hostname and port using DNS and updates the address resolution cache.
///
/// If `load_cache` is true, appends cached results not older than 30 days to the end
/// or entries from fallback cache if there are no cached addresses.
async fn lookup_host_with_cache(
    context: &Context,
    hostname: &str,
    port: u16,
    timeout_val: Duration,
    load_cache: bool,
) -> Result<Vec<SocketAddr>> {
    let now = time();
    let mut resolved_addrs = match lookup_host_with_timeout(hostname, port, timeout_val).await {
        Ok(res) => res,
        Err(err) => {
            warn!(
                context,
                "DNS resolution for {}:{} failed: {:#}.", hostname, port, err
            );
            Vec::new()
        }
    };

    for addr in &resolved_addrs {
        let ip_string = addr.ip().to_string();
        if ip_string == hostname {
            // IP address resolved into itself, not interesting to cache.
            continue;
        }

        info!(context, "Resolved {}:{} into {}.", hostname, port, &addr);

        // Update the cache.
        context
            .sql
            .execute(
                "INSERT INTO dns_cache
                 (hostname, address, timestamp)
                 VALUES (?, ?, ?)
                 ON CONFLICT (hostname, address)
                 DO UPDATE SET timestamp=excluded.timestamp",
                (hostname, ip_string, now),
            )
            .await?;
    }

    if load_cache {
        for cached_address in context
            .sql
            .query_map(
                "SELECT address
                 FROM dns_cache
                 WHERE hostname = ?
                 AND ? < timestamp + 30 * 24 * 3600
                 ORDER BY timestamp DESC",
                (hostname, now),
                |row| {
                    let address: String = row.get(0)?;
                    Ok(address)
                },
                |rows| {
                    rows.collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(Into::into)
                },
            )
            .await?
        {
            match IpAddr::from_str(&cached_address) {
                Ok(ip_addr) => {
                    let addr = SocketAddr::new(ip_addr, port);
                    if !resolved_addrs.contains(&addr) {
                        resolved_addrs.push(addr);
                    }
                }
                Err(err) => {
                    warn!(
                        context,
                        "Failed to parse cached address {:?}: {:#}.", cached_address, err
                    );
                }
            }
        }

        if resolved_addrs.is_empty() {
            // Load hardcoded cache if everything else fails.
            //
            // See <https://support.delta.chat/t/no-dns-resolution-result/2778> and
            // <https://github.com/deltachat/deltachat-core-rust/issues/4920> for reasons.
            //
            // In the future we may pre-resolve all provider database addresses
            // and build them in.
            match hostname {
                "mail.sangham.net" => {
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0xc17, 0x798c, 0, 0, 0, 1)),
                        port,
                    ));
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(159, 69, 186, 85)),
                        port,
                    ));
                }
                "nine.testrun.org" => {
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0x241, 0x4ce8, 0, 0, 0, 2)),
                        port,
                    ));
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(116, 202, 233, 236)),
                        port,
                    ));
                }
                "disroot.org" => {
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(178, 21, 23, 139)),
                        port,
                    ));
                }
                "mail.riseup.net" => {
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(198, 252, 153, 70)),
                        port,
                    ));
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(198, 252, 153, 71)),
                        port,
                    ));
                }
                "imap.gmail.com" => {
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x400c, 0xc1f, 0, 0, 0, 0x6c)),
                        port,
                    ));
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x400c, 0xc1f, 0, 0, 0, 0x6d)),
                        port,
                    ));
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(142, 250, 110, 109)),
                        port,
                    ));
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(142, 250, 110, 108)),
                        port,
                    ));
                }
                "smtp.gmail.com" => {
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x4013, 0xc04, 0, 0, 0, 0x6c)),
                        port,
                    ));
                    resolved_addrs.push(SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(142, 250, 110, 109)),
                        port,
                    ));
                }
                _ => {}
            }
        }
    }

    Ok(resolved_addrs)
}

/// Returns a TCP connection stream with read/write timeouts set
/// and Nagle's algorithm disabled with `TCP_NODELAY`.
///
/// `TCP_NODELAY` ensures writing to the stream always results in immediate sending of the packet
/// to the network, which is important to reduce the latency of interactive protocols such as IMAP.
///
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
    timeout_val: Duration,
    load_cache: bool,
) -> Result<Pin<Box<TimeoutStream<TcpStream>>>> {
    let mut tcp_stream = None;
    let mut last_error = None;

    for resolved_addr in
        lookup_host_with_cache(context, host, port, timeout_val, load_cache).await?
    {
        match connect_tcp_inner(resolved_addr, timeout_val).await {
            Ok(stream) => {
                tcp_stream = Some(stream);

                // Maximize priority of this cached entry.
                context
                    .sql
                    .execute(
                        "UPDATE dns_cache
                         SET timestamp = ?
                         WHERE address = ?",
                        (time(), resolved_addr.ip().to_string()),
                    )
                    .await?;
                break;
            }
            Err(err) => {
                warn!(
                    context,
                    "Failed to connect to {}: {:#}.", resolved_addr, err
                );
                last_error = Some(err);
            }
        }
    }

    let tcp_stream = match tcp_stream {
        Some(tcp_stream) => tcp_stream,
        None => {
            return Err(
                last_error.unwrap_or_else(|| format_err!("no DNS resolution results for {host}"))
            );
        }
    };

    // Disable Nagle's algorithm.
    tcp_stream.set_nodelay(true)?;

    let mut timeout_stream = TimeoutStream::new(tcp_stream);
    timeout_stream.set_write_timeout(Some(timeout_val));
    timeout_stream.set_read_timeout(Some(timeout_val));
    let pinned_stream = Box::pin(timeout_stream);

    Ok(pinned_stream)
}
