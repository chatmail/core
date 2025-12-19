//! DNS resolution and cache.
//!
//! DNS cache in Delta Chat has two layers:
//! in-memory cache and persistent `dns_cache` SQL table.
//!
//! In-memory cache is using a "stale-while-revalidate" strategy.
//! If there is a cached value, it is returned immediately
//! and revalidation task is started in the background
//! to replace old cached IP addresses with new ones.
//! If there is no cached value yet,
//! lookup only finishes when `lookup_host` returns first results.
//! In-memory cache is shared between all accounts
//! and is never stored on the disk.
//! It can be thought of as an extension
//! of the system resolver.
//!
//! Persistent `dns_cache` SQL table is used to collect
//! all IP addresses ever seen for the hostname
//! together with the timestamp
//! of the last time IP address has been seen.
//! Note that this timestamp reflects the time
//! IP address was returned by the in-memory cache
//! rather than the underlying system resolver.
//! Unused entries are removed after 30 days
//! (`CACHE_TTL` constant) to avoid having
//! old non-working IP addresses in the cache indefinitely.
//!
//! When Delta Chat needs an IP address for the host,
//! it queries in-memory cache for the next result
//! and merges the list of IP addresses
//! with the list of IP addresses from persistent cache.
//! Resulting list is constructed
//! by taking the first two results from the resolver
//! followed up by persistent cache results
//! and terminated by the rest of resolver results.
//!
//! Persistent cache results are sorted
//! by the time of the most recent successful connection
//! using the result. For results that have never been
//! used for successful connection timestamp of
//! retrieving them from in-memory cache is used.

use anyhow::{Context as _, Result, ensure};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::LazyLock;
use tokio::net::lookup_host;
use tokio::time::timeout;

use super::load_connection_timestamp;
use crate::context::Context;
use crate::log::warn;
use crate::tools::time;

/// Inserts entry into DNS cache
/// or updates existing one with a new timestamp.
async fn update_cache(context: &Context, host: &str, addr: &str, now: i64) -> Result<()> {
    context
        .sql
        .execute(
            "INSERT INTO dns_cache
             (hostname, address, timestamp)
             VALUES (?, ?, ?)
             ON CONFLICT (hostname, address)
             DO UPDATE SET timestamp=excluded.timestamp",
            (host, addr, now),
        )
        .await?;
    Ok(())
}

pub(crate) async fn prune_dns_cache(context: &Context) -> Result<()> {
    let now = time();
    context
        .sql
        .execute(
            "DELETE FROM dns_cache
             WHERE ? > timestamp + ?",
            (now, super::CACHE_TTL),
        )
        .await?;
    Ok(())
}

/// Map from hostname to IP addresses.
///
/// NOTE: sync RwLock is used, so it must not be held across `.await`
/// to avoid deadlocks.
/// See
/// <https://docs.rs/tokio/1.40.0/tokio/sync/struct.Mutex.html#which-kind-of-mutex-should-you-use>
/// and
/// <https://stackoverflow.com/questions/63712823/why-do-i-get-a-deadlock-when-using-tokio-with-a-stdsyncmutex>.
static LOOKUP_HOST_CACHE: LazyLock<parking_lot::RwLock<HashMap<String, Vec<IpAddr>>>> =
    LazyLock::new(Default::default);

/// Wrapper for `lookup_host` that returns IP addresses.
async fn lookup_ips(host: impl tokio::net::ToSocketAddrs) -> Result<impl Iterator<Item = IpAddr>> {
    Ok(lookup_host(host)
        .await
        .context("DNS lookup failure")?
        .map(|addr| addr.ip()))
}

async fn lookup_host_with_memory_cache(
    context: &Context,
    hostname: &str,
    port: u16,
) -> Result<Vec<IpAddr>> {
    let stale_result = {
        let rwlock_read_guard = LOOKUP_HOST_CACHE.read();
        rwlock_read_guard.get(hostname).cloned()
    };
    if let Some(stale_result) = stale_result {
        // Revalidate the cache in the background.
        {
            let context = context.clone();
            let hostname = hostname.to_string();
            tokio::spawn(async move {
                match lookup_ips((hostname.clone(), port)).await {
                    Ok(res) => {
                        LOOKUP_HOST_CACHE.write().insert(hostname, res.collect());
                    }
                    Err(err) => {
                        warn!(
                            context,
                            "Failed to revalidate results for {hostname:?}: {err:#}."
                        );
                    }
                }
            });
        }

        info!(
            context,
            "Using memory-cached DNS resolution for {hostname}."
        );
        Ok(stale_result)
    } else {
        info!(
            context,
            "No memory-cached DNS resolution for {hostname} available, waiting for the resolver."
        );
        let res: Vec<IpAddr> = lookup_ips((hostname, port)).await?.collect();

        // Insert initial result into the cache.
        //
        // There may already be a result from a parallel
        // task stored, overwriting it is not a problem.
        LOOKUP_HOST_CACHE
            .write()
            .insert(hostname.to_string(), res.clone());
        Ok(res)
    }
}

/// Looks up the hostname and updates
/// persistent DNS cache on success.
async fn lookup_host_and_update_cache(
    context: &Context,
    hostname: &str,
    port: u16,
    now: i64,
) -> Result<Vec<SocketAddr>> {
    let res: Vec<IpAddr> = timeout(
        super::TIMEOUT,
        lookup_host_with_memory_cache(context, hostname, port),
    )
    .await
    .context("DNS lookup timeout")?
    .context("DNS lookup with memory cache failure")?;

    for ip in &res {
        let ip_string = ip.to_string();
        if ip_string == hostname {
            // IP address resolved into itself, not interesting to cache.
            continue;
        }

        info!(context, "Resolved {hostname} into {ip}.");

        // Update the cache.
        update_cache(context, hostname, &ip_string, now).await?;
    }

    let res = res
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect();
    Ok(res)
}

// Updates timestamp of the cached entry
// or inserts a new one if cached entry does not exist.
//
// This function should be called when a successful TLS
// connection is established with strict TLS checks.
//
// This increases priority of existing cached entries
// and copies fallback addresses from built-in cache
// into database cache on successful use.
//
// Unlike built-in cache,
// database cache is used even if DNS
// resolver returns a non-empty
// (but potentially incorrect and unusable) result.
pub(crate) async fn update_connect_timestamp(
    context: &Context,
    host: &str,
    address: &str,
) -> Result<()> {
    if host == address {
        return Ok(());
    }

    context
        .sql
        .execute(
            "INSERT INTO dns_cache (hostname, address, timestamp)
                 VALUES (?, ?, ?)
                 ON CONFLICT (hostname, address)
                 DO UPDATE SET timestamp=excluded.timestamp",
            (host, address, time()),
        )
        .await?;
    Ok(())
}

/// Preloaded DNS results that can be used in case of DNS server failures.
static DNS_PRELOAD: LazyLock<HashMap<&'static str, Vec<IpAddr>>> = LazyLock::new(|| {
    HashMap::from([
        (
            "imap.163.com",
            vec![IpAddr::V4(Ipv4Addr::new(111, 124, 203, 45))],
        ),
        (
            "smtp.163.com",
            vec![IpAddr::V4(Ipv4Addr::new(103, 129, 252, 45))],
        ),
        (
            "newyear.aktivix.org",
            vec![IpAddr::V4(Ipv4Addr::new(209, 51, 180, 245))],
        ),
        (
            "smtp.aliyun.com",
            vec![IpAddr::V4(Ipv4Addr::new(47, 246, 136, 232))],
        ),
        (
            "imap.aliyun.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(59, 82, 43, 123)),
                IpAddr::V4(Ipv4Addr::new(59, 82, 9, 176)),
            ],
        ),
        (
            "imap.aol.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(212, 82, 101, 33)),
                IpAddr::V4(Ipv4Addr::new(87, 248, 98, 69)),
            ],
        ),
        (
            "imap.arcor.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(178, 15, 69, 210)),
                IpAddr::V4(Ipv4Addr::new(151, 189, 176, 206)),
            ],
        ),
        (
            "smtp.aol.com",
            vec![IpAddr::V4(Ipv4Addr::new(87, 248, 97, 31))],
        ),
        (
            "mail.arcor.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(151, 189, 176, 206)),
                IpAddr::V4(Ipv4Addr::new(178, 15, 69, 206)),
            ],
        ),
        (
            "mail.autistici.org",
            vec![
                IpAddr::V4(Ipv4Addr::new(93, 190, 126, 19)),
                IpAddr::V4(Ipv4Addr::new(185, 218, 207, 228)),
                IpAddr::V4(Ipv4Addr::new(198, 167, 222, 108)),
            ],
        ),
        (
            "smtp.autistici.org",
            vec![
                IpAddr::V4(Ipv4Addr::new(82, 94, 249, 234)),
                IpAddr::V4(Ipv4Addr::new(93, 190, 126, 19)),
                IpAddr::V4(Ipv4Addr::new(198, 167, 222, 108)),
            ],
        ),
        (
            "imaps.bluewin.ch",
            vec![
                IpAddr::V4(Ipv4Addr::new(16, 62, 253, 42)),
                IpAddr::V4(Ipv4Addr::new(16, 63, 141, 244)),
                IpAddr::V4(Ipv4Addr::new(16, 63, 146, 183)),
            ],
        ),
        (
            "smtpauths.bluewin.ch",
            vec![
                IpAddr::V4(Ipv4Addr::new(16, 62, 176, 232)),
                IpAddr::V4(Ipv4Addr::new(16, 62, 15, 25)),
                IpAddr::V4(Ipv4Addr::new(16, 63, 183, 216)),
            ],
        ),
        (
            "mail.buzon.uy",
            vec![IpAddr::V4(Ipv4Addr::new(200, 40, 115, 74))],
        ),
        (
            "daleth.cafe",
            vec![IpAddr::V4(Ipv4Addr::new(37, 27, 6, 204))],
        ),
        (
            "disroot.org",
            vec![IpAddr::V4(Ipv4Addr::new(178, 21, 23, 139))],
        ),
        (
            "imap.fastmail.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(103, 168, 172, 43)),
                IpAddr::V4(Ipv4Addr::new(103, 168, 172, 58)),
            ],
        ),
        (
            "smtp.fastmail.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(103, 168, 172, 45)),
                IpAddr::V4(Ipv4Addr::new(103, 168, 172, 60)),
            ],
        ),
        (
            "imap.gmail.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(142, 250, 110, 108)),
                IpAddr::V4(Ipv4Addr::new(142, 250, 110, 109)),
                IpAddr::V4(Ipv4Addr::new(66, 102, 1, 108)),
                IpAddr::V4(Ipv4Addr::new(66, 102, 1, 109)),
                IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x400c, 0xc1f, 0, 0, 0, 0x6c)),
                IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x400c, 0xc1f, 0, 0, 0, 0x6d)),
            ],
        ),
        (
            "mail.ecloud.global",
            vec![IpAddr::V4(Ipv4Addr::new(95, 217, 246, 96))],
        ),
        (
            "mail.ende.in.net",
            vec![IpAddr::V4(Ipv4Addr::new(95, 217, 5, 72))],
        ),
        (
            "smtp.gmail.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(142, 250, 110, 109)),
                IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x4013, 0xc04, 0, 0, 0, 0x6c)),
            ],
        ),
        (
            "mail.gmx.net",
            vec![
                IpAddr::V4(Ipv4Addr::new(212, 227, 17, 190)),
                IpAddr::V4(Ipv4Addr::new(212, 227, 17, 168)),
            ],
        ),
        (
            "imap.gmx.net",
            vec![
                IpAddr::V4(Ipv4Addr::new(212, 227, 17, 170)),
                IpAddr::V4(Ipv4Addr::new(212, 227, 17, 186)),
            ],
        ),
        (
            "mail.sangham.net",
            vec![
                IpAddr::V4(Ipv4Addr::new(159, 69, 186, 85)),
                IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0xc17, 0x798c, 0, 0, 0, 1)),
            ],
        ),
        (
            "imap.mail.de",
            vec![IpAddr::V4(Ipv4Addr::new(62, 201, 172, 16))],
        ),
        (
            "smtp.mailbox.org",
            vec![IpAddr::V4(Ipv4Addr::new(185, 97, 174, 196))],
        ),
        (
            "imap.mailbox.org",
            vec![IpAddr::V4(Ipv4Addr::new(185, 97, 174, 199))],
        ),
        (
            "imap.naver.com",
            vec![IpAddr::V4(Ipv4Addr::new(125, 209, 233, 34))],
        ),
        (
            "imap.ouvaton.coop",
            vec![IpAddr::V4(Ipv4Addr::new(194, 36, 166, 20))],
        ),
        (
            "imap.purelymail.com",
            vec![IpAddr::V4(Ipv4Addr::new(18, 204, 123, 63))],
        ),
        (
            "mail.systemausfall.org",
            vec![
                IpAddr::V4(Ipv4Addr::new(51, 75, 71, 249)),
                IpAddr::V4(Ipv4Addr::new(80, 153, 252, 42)),
            ],
        ),
        (
            "mail.systemli.org",
            vec![IpAddr::V4(Ipv4Addr::new(93, 190, 126, 36))],
        ),
        ("testrun.org", vec![IpAddr::V4(Ipv4Addr::new(5, 1, 76, 52))]),
        (
            "nine.testrun.org",
            vec![
                IpAddr::V4(Ipv4Addr::new(128, 140, 126, 197)),
                IpAddr::V4(Ipv4Addr::new(116, 202, 233, 236)),
                IpAddr::V4(Ipv4Addr::new(216, 144, 228, 100)),
                IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0x241, 0x4ce8, 0, 0, 0, 2)),
                IpAddr::V6(Ipv6Addr::new(
                    0x2001, 0x41d0, 0x701, 0x1100, 0, 0, 0, 0x8ab1,
                )),
            ],
        ),
        (
            "secureimap.t-online.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(194, 25, 134, 114)),
                IpAddr::V4(Ipv4Addr::new(194, 25, 134, 115)),
                IpAddr::V4(Ipv4Addr::new(194, 25, 134, 50)),
                IpAddr::V4(Ipv4Addr::new(194, 25, 134, 51)),
            ],
        ),
        (
            "securesmtp.t-online.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(194, 25, 134, 46)),
                IpAddr::V4(Ipv4Addr::new(194, 25, 134, 110)),
            ],
        ),
        (
            "mail.riseup.net",
            vec![
                IpAddr::V4(Ipv4Addr::new(198, 252, 153, 171)),
                IpAddr::V4(Ipv4Addr::new(198, 252, 153, 170)),
            ],
        ),
        (
            "pimap.schulon.org",
            vec![IpAddr::V4(Ipv4Addr::new(194, 77, 246, 20))],
        ),
        (
            "imap.tiscali.it",
            vec![IpAddr::V4(Ipv4Addr::new(213, 205, 33, 10))],
        ),
        (
            "smtp.tiscali.it",
            vec![IpAddr::V4(Ipv4Addr::new(213, 205, 33, 13))],
        ),
        (
            "imap.ukr.net",
            vec![IpAddr::V4(Ipv4Addr::new(212, 42, 75, 240))],
        ),
        (
            "smtp.ukr.net",
            vec![IpAddr::V4(Ipv4Addr::new(212, 42, 75, 250))],
        ),
        (
            "imap.web.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(212, 227, 17, 162)),
                IpAddr::V4(Ipv4Addr::new(212, 227, 17, 178)),
            ],
        ),
        (
            "imap.ziggo.nl",
            vec![IpAddr::V4(Ipv4Addr::new(84, 116, 6, 3))],
        ),
        (
            "imap.zoho.eu",
            vec![
                IpAddr::V4(Ipv4Addr::new(185, 230, 214, 25)),
                IpAddr::V4(Ipv4Addr::new(185, 230, 214, 206)),
            ],
        ),
        (
            "mail.infomaniak.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(83, 166, 143, 44)),
                IpAddr::V4(Ipv4Addr::new(83, 166, 143, 45)),
            ],
        ),
        (
            "mail.mymagenta.at",
            vec![IpAddr::V4(Ipv4Addr::new(80, 109, 253, 241))],
        ),
        (
            "mail.nubo.coop",
            vec![IpAddr::V4(Ipv4Addr::new(79, 99, 201, 10))],
        ),
        (
            "mx.freenet.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(194, 97, 208, 36)),
                IpAddr::V4(Ipv4Addr::new(194, 97, 208, 34)),
                IpAddr::V4(Ipv4Addr::new(194, 97, 208, 35)),
                IpAddr::V4(Ipv4Addr::new(194, 97, 208, 39)),
                IpAddr::V4(Ipv4Addr::new(194, 97, 208, 37)),
                IpAddr::V4(Ipv4Addr::new(194, 97, 208, 38)),
            ],
        ),
        (
            "posteo.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(185, 67, 36, 168)),
                IpAddr::V4(Ipv4Addr::new(185, 67, 36, 169)),
            ],
        ),
        (
            "psmtp.schulon.org",
            vec![IpAddr::V4(Ipv4Addr::new(194, 77, 246, 20))],
        ),
        (
            "smtp.mail.de",
            vec![IpAddr::V4(Ipv4Addr::new(62, 201, 172, 21))],
        ),
        (
            "smtp.mail.ru",
            vec![
                IpAddr::V4(Ipv4Addr::new(94, 100, 180, 160)),
                IpAddr::V4(Ipv4Addr::new(217, 69, 139, 160)),
            ],
        ),
        (
            "imap.mail.yahoo.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(87, 248, 103, 8)),
                IpAddr::V4(Ipv4Addr::new(212, 82, 101, 24)),
            ],
        ),
        (
            "smtp.mail.yahoo.com",
            vec![IpAddr::V4(Ipv4Addr::new(87, 248, 97, 36))],
        ),
        (
            "imap.mailo.com",
            vec![IpAddr::V4(Ipv4Addr::new(213, 182, 54, 20))],
        ),
        (
            "imap.migadu.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(51, 210, 3, 23)),
                IpAddr::V4(Ipv4Addr::new(51, 210, 3, 20)),
            ],
        ),
        (
            "smtp.migadu.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(37, 59, 57, 117)),
                IpAddr::V4(Ipv4Addr::new(51, 255, 82, 75)),
            ],
        ),
        (
            "smtp.mailo.com",
            vec![IpAddr::V4(Ipv4Addr::new(213, 182, 54, 20))],
        ),
        (
            "smtp.naver.com",
            vec![IpAddr::V4(Ipv4Addr::new(125, 209, 238, 155))],
        ),
        (
            "smtp.ouvaton.coop",
            vec![IpAddr::V4(Ipv4Addr::new(194, 36, 166, 20))],
        ),
        (
            "smtp.purelymail.com",
            vec![IpAddr::V4(Ipv4Addr::new(18, 204, 123, 63))],
        ),
        (
            "imap.qq.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(43, 163, 178, 76)),
                IpAddr::V4(Ipv4Addr::new(43, 129, 255, 54)),
            ],
        ),
        (
            "smtp.qq.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(43, 129, 255, 54)),
                IpAddr::V4(Ipv4Addr::new(43, 163, 178, 76)),
            ],
        ),
        (
            "imap.rambler.ru",
            vec![
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 168)),
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 169)),
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 170)),
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 171)),
            ],
        ),
        (
            "smtp.rambler.ru",
            vec![
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 164)),
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 165)),
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 166)),
                IpAddr::V4(Ipv4Addr::new(81, 19, 77, 167)),
            ],
        ),
        (
            "stinpriza.net",
            vec![IpAddr::V4(Ipv4Addr::new(5, 9, 122, 184))],
        ),
        (
            "webbox222.server-home.org",
            vec![IpAddr::V4(Ipv4Addr::new(91, 203, 111, 88))],
        ),
        (
            "undernet.uy",
            vec![IpAddr::V4(Ipv4Addr::new(200, 40, 115, 74))],
        ),
        (
            "imap.vivaldi.net",
            vec![IpAddr::V4(Ipv4Addr::new(31, 209, 137, 15))],
        ),
        (
            "smtp.vivaldi.net",
            vec![IpAddr::V4(Ipv4Addr::new(31, 209, 137, 12))],
        ),
        (
            "imap.vodafonemail.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(178, 15, 69, 210)),
                IpAddr::V4(Ipv4Addr::new(151, 189, 176, 206)),
            ],
        ),
        (
            "smtp.vodafonemail.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(151, 189, 176, 206)),
                IpAddr::V4(Ipv4Addr::new(178, 15, 69, 206)),
            ],
        ),
        (
            "smtp.web.de",
            vec![
                IpAddr::V4(Ipv4Addr::new(213, 165, 67, 124)),
                IpAddr::V4(Ipv4Addr::new(213, 165, 67, 108)),
            ],
        ),
        (
            "imap.yandex.com",
            vec![IpAddr::V4(Ipv4Addr::new(77, 88, 21, 125))],
        ),
        (
            "smtp.yandex.com",
            vec![IpAddr::V4(Ipv4Addr::new(77, 88, 21, 158))],
        ),
        (
            "smtp.ziggo.nl",
            vec![IpAddr::V4(Ipv4Addr::new(84, 116, 6, 3))],
        ),
        (
            "smtp.zoho.eu",
            vec![
                IpAddr::V4(Ipv4Addr::new(185, 230, 212, 164)),
                IpAddr::V4(Ipv4Addr::new(185, 230, 214, 164)),
            ],
        ),
        // Known public chatmail relays from https://chatmail.at/relays
        (
            "mehl.cloud",
            vec![IpAddr::V4(Ipv4Addr::new(95, 217, 223, 172))],
        ),
        (
            "mailchat.pl",
            vec![IpAddr::V4(Ipv4Addr::new(46, 62, 144, 137))],
        ),
        (
            "chatmail.woodpeckersnest.space",
            vec![IpAddr::V4(Ipv4Addr::new(85, 215, 162, 146))],
        ),
        (
            "chatmail.culturanerd.it",
            vec![IpAddr::V4(Ipv4Addr::new(82, 165, 94, 165))],
        ),
        (
            "chatmail.hackea.org",
            vec![IpAddr::V4(Ipv4Addr::new(82, 165, 11, 85))],
        ),
        (
            "chika.aangat.lahat.computer",
            vec![IpAddr::V4(Ipv4Addr::new(71, 19, 150, 113))],
        ),
        (
            "tarpit.fun",
            vec![IpAddr::V4(Ipv4Addr::new(152, 53, 86, 246))],
        ),
        (
            "d.gaufr.es",
            vec![IpAddr::V4(Ipv4Addr::new(51, 77, 140, 91))],
        ),
        (
            "chtml.ca",
            vec![IpAddr::V4(Ipv4Addr::new(51, 222, 156, 177))],
        ),
        (
            "chatmail.au",
            vec![IpAddr::V4(Ipv4Addr::new(45, 124, 54, 79))],
        ),
        (
            "sombras.chat",
            vec![IpAddr::V4(Ipv4Addr::new(82, 25, 70, 154))],
        ),
        (
            "e2ee.wang",
            vec![IpAddr::V4(Ipv4Addr::new(139, 84, 233, 161))],
        ),
        (
            "chat.privittytech.com",
            vec![IpAddr::V4(Ipv4Addr::new(35, 154, 144, 0))],
        ),
        ("e2ee.im", vec![IpAddr::V4(Ipv4Addr::new(45, 137, 99, 57))]),
        (
            "chatmail.email",
            vec![IpAddr::V4(Ipv4Addr::new(57, 128, 220, 120))],
        ),
        (
            "danneskjold.de",
            vec![IpAddr::V4(Ipv4Addr::new(46, 62, 216, 132))],
        ),
        (
            "darkrun.dev",
            vec![IpAddr::V4(Ipv4Addr::new(72, 11, 149, 146))],
        ),
    ])
});

async fn lookup_cache(
    context: &Context,
    host: &str,
    port: u16,
    alpn: &str,
    now: i64,
) -> Result<Vec<SocketAddr>> {
    let mut res = Vec::new();
    for cached_address in context
        .sql
        .query_map_vec(
            "SELECT dns_cache.address
             FROM dns_cache
             LEFT JOIN connection_history
               ON dns_cache.hostname = connection_history.host
               AND dns_cache.address = connection_history.addr
               AND connection_history.port = ?
               AND connection_history.alpn = ?
             WHERE dns_cache.hostname = ?
             AND ? < dns_cache.timestamp + ?
             ORDER BY IFNULL(connection_history.timestamp, dns_cache.timestamp) DESC
             LIMIT 50",
            (port, alpn, host, now, super::CACHE_TTL),
            |row| {
                let address: String = row.get(0)?;
                Ok(address)
            },
        )
        .await?
    {
        match IpAddr::from_str(&cached_address) {
            Ok(ip_addr) => {
                let addr = SocketAddr::new(ip_addr, port);
                res.push(addr);
            }
            Err(err) => {
                warn!(
                    context,
                    "Failed to parse cached address {:?}: {:#}.", cached_address, err
                );
            }
        }
    }
    Ok(res)
}

/// Sorts DNS resolution results by connection timestamp in descending order
/// so IP addresses that we recently connected to successfully are tried first.
async fn sort_by_connection_timestamp(
    context: &Context,
    input: Vec<SocketAddr>,
    alpn: &str,
    host: &str,
) -> Result<Vec<SocketAddr>> {
    let mut res: Vec<(Option<i64>, SocketAddr)> = Vec::with_capacity(input.len());
    for addr in input {
        let timestamp = load_connection_timestamp(
            &context.sql,
            alpn,
            host,
            addr.port(),
            Some(&addr.ip().to_string()),
        )
        .await?;
        res.push((timestamp, addr));
    }
    res.sort_by_key(|(ts, _addr)| std::cmp::Reverse(*ts));
    Ok(res.into_iter().map(|(_ts, addr)| addr).collect())
}

/// Looks up hostname and port using DNS and updates the address resolution cache.
///
/// `alpn` is used to sort DNS results by the time we have successfully
/// connected to the IP address using given `alpn`.
/// If result sorting is not needed or `alpn` is unknown,
/// pass empty string here, e.g. for HTTP requests
/// or when resolving the IP address of SOCKS proxy.
///
/// If `load_cache` is true, appends cached results not older than 30 days to the end
/// or entries from fallback cache if there are no cached addresses.
pub(crate) async fn lookup_host_with_cache(
    context: &Context,
    hostname: &str,
    port: u16,
    alpn: &str,
    load_cache: bool,
) -> Result<Vec<SocketAddr>> {
    let now = time();
    let resolved_addrs = match lookup_host_and_update_cache(context, hostname, port, now).await {
        Ok(res) => {
            if alpn.is_empty() {
                res
            } else {
                sort_by_connection_timestamp(context, res, alpn, hostname).await?
            }
        }
        Err(err) => {
            warn!(
                context,
                "DNS resolution for {hostname}:{port} failed: {err:#}."
            );
            Vec::new()
        }
    };

    let addrs = if load_cache {
        let mut cache = lookup_cache(context, hostname, port, alpn, now).await?;
        if let Some(ips) = DNS_PRELOAD.get(hostname) {
            for ip in ips {
                let addr = SocketAddr::new(*ip, port);
                if !cache.contains(&addr) {
                    cache.push(addr);
                }
            }
        }

        merge_with_cache(resolved_addrs, cache)
    } else {
        resolved_addrs
    };
    ensure!(
        !addrs.is_empty(),
        "Could not find DNS resolutions for {hostname}:{port}. Check server hostname and your network"
    );
    Ok(addrs)
}

/// Merges results received from DNS with cached results.
///
/// At most 10 results are returned.
fn merge_with_cache(
    mut resolved_addrs: Vec<SocketAddr>,
    cache: Vec<SocketAddr>,
) -> Vec<SocketAddr> {
    let rest = resolved_addrs.split_off(std::cmp::min(resolved_addrs.len(), 2));

    for addr in cache.into_iter().chain(rest.into_iter()) {
        if !resolved_addrs.contains(&addr) {
            resolved_addrs.push(addr);
            if resolved_addrs.len() >= 10 {
                break;
            }
        }
    }

    resolved_addrs
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::net::update_connection_history;
    use crate::test_utils::TestContext;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sort_by_connection_timestamp() {
        let alice = &TestContext::new_alice().await;
        let now = time();

        let ipv6_addr = IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0x241, 0x4ce8, 0, 0, 0, 2));
        let ipv4_addr = IpAddr::V4(Ipv4Addr::new(116, 202, 233, 236));

        assert_eq!(
            sort_by_connection_timestamp(
                alice,
                vec![
                    SocketAddr::new(ipv6_addr, 993),
                    SocketAddr::new(ipv4_addr, 993)
                ],
                "imap",
                "nine.testrun.org"
            )
            .await
            .unwrap(),
            vec![
                SocketAddr::new(ipv6_addr, 993),
                SocketAddr::new(ipv4_addr, 993)
            ]
        );
        update_connection_history(
            alice,
            "imap",
            "nine.testrun.org",
            993,
            "116.202.233.236",
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            sort_by_connection_timestamp(
                alice,
                vec![
                    SocketAddr::new(ipv6_addr, 993),
                    SocketAddr::new(ipv4_addr, 993)
                ],
                "imap",
                "nine.testrun.org"
            )
            .await
            .unwrap(),
            vec![
                SocketAddr::new(ipv4_addr, 993),
                SocketAddr::new(ipv6_addr, 993),
            ]
        );

        assert_eq!(
            sort_by_connection_timestamp(
                alice,
                vec![
                    SocketAddr::new(ipv6_addr, 465),
                    SocketAddr::new(ipv4_addr, 465)
                ],
                "smtp",
                "nine.testrun.org"
            )
            .await
            .unwrap(),
            vec![
                SocketAddr::new(ipv6_addr, 465),
                SocketAddr::new(ipv4_addr, 465),
            ]
        );
        update_connection_history(
            alice,
            "smtp",
            "nine.testrun.org",
            465,
            "116.202.233.236",
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            sort_by_connection_timestamp(
                alice,
                vec![
                    SocketAddr::new(ipv6_addr, 465),
                    SocketAddr::new(ipv4_addr, 465)
                ],
                "smtp",
                "nine.testrun.org"
            )
            .await
            .unwrap(),
            vec![
                SocketAddr::new(ipv4_addr, 465),
                SocketAddr::new(ipv6_addr, 465),
            ]
        );

        update_connection_history(
            alice,
            "imap",
            "nine.testrun.org",
            993,
            "2a01:4f8:241:4ce8::2",
            now,
        )
        .await
        .unwrap();
        assert_eq!(
            sort_by_connection_timestamp(
                alice,
                vec![
                    SocketAddr::new(ipv6_addr, 993),
                    SocketAddr::new(ipv4_addr, 993)
                ],
                "imap",
                "nine.testrun.org"
            )
            .await
            .unwrap(),
            vec![
                SocketAddr::new(ipv6_addr, 993),
                SocketAddr::new(ipv4_addr, 993)
            ]
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_lookup_cache() {
        let alice = &TestContext::new_alice().await;

        let ipv4_addr = IpAddr::V4(Ipv4Addr::new(116, 202, 233, 236));
        let ipv6_addr = IpAddr::V6(Ipv6Addr::new(0x2a01, 0x4f8, 0x241, 0x4ce8, 0, 0, 0, 2));

        let now = time();
        assert!(
            lookup_cache(alice, "nine.testrun.org", 587, "smtp", now)
                .await
                .unwrap()
                .is_empty()
        );

        update_cache(alice, "nine.testrun.org", "116.202.233.236", now)
            .await
            .unwrap();

        assert_eq!(
            lookup_cache(alice, "nine.testrun.org", 587, "smtp", now)
                .await
                .unwrap(),
            vec![SocketAddr::new(ipv4_addr, 587)]
        );

        // Cache should be returned for other ports and no ALPN as well,
        // port and ALPN should only affect the order
        assert_eq!(
            lookup_cache(alice, "nine.testrun.org", 443, "", now)
                .await
                .unwrap(),
            vec![SocketAddr::new(ipv4_addr, 443)]
        );

        update_cache(alice, "nine.testrun.org", "2a01:4f8:241:4ce8::2", now + 30)
            .await
            .unwrap();

        // New DNS cache entry should go first.
        assert_eq!(
            lookup_cache(alice, "nine.testrun.org", 443, "", now + 60)
                .await
                .unwrap(),
            vec![
                SocketAddr::new(ipv6_addr, 443),
                SocketAddr::new(ipv4_addr, 443)
            ],
        );

        // After successful connection to SMTP over port 465 using IPv4 address,
        // IPv4 address has higher priority.
        update_connection_history(
            alice,
            "smtp",
            "nine.testrun.org",
            465,
            "116.202.233.236",
            now + 100,
        )
        .await
        .unwrap();
        assert_eq!(
            lookup_cache(alice, "nine.testrun.org", 465, "smtp", now + 120)
                .await
                .unwrap(),
            vec![
                SocketAddr::new(ipv4_addr, 465),
                SocketAddr::new(ipv6_addr, 465)
            ]
        );

        // For other ports and ALPNs order remains the same.
        assert_eq!(
            lookup_cache(alice, "nine.testrun.org", 993, "imap", now + 120)
                .await
                .unwrap(),
            vec![
                SocketAddr::new(ipv6_addr, 993),
                SocketAddr::new(ipv4_addr, 993)
            ],
        );
        assert_eq!(
            lookup_cache(alice, "nine.testrun.org", 465, "imap", now + 120)
                .await
                .unwrap(),
            vec![
                SocketAddr::new(ipv6_addr, 465),
                SocketAddr::new(ipv4_addr, 465)
            ],
        );
        assert_eq!(
            lookup_cache(alice, "nine.testrun.org", 993, "smtp", now + 120)
                .await
                .unwrap(),
            vec![
                SocketAddr::new(ipv6_addr, 993),
                SocketAddr::new(ipv4_addr, 993)
            ],
        );
    }

    #[test]
    fn test_merge_with_cache() {
        let first_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let second_addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // If there is no cache, just return resolved addresses.
        {
            let resolved_addrs = vec![
                SocketAddr::new(first_addr, 993),
                SocketAddr::new(second_addr, 993),
            ];
            let cache = vec![];
            assert_eq!(
                merge_with_cache(resolved_addrs.clone(), cache),
                resolved_addrs
            );
        }

        // If cache contains address that is not in resolution results,
        // it is inserted in the merged result.
        {
            let resolved_addrs = vec![SocketAddr::new(first_addr, 993)];
            let cache = vec![SocketAddr::new(second_addr, 993)];
            assert_eq!(
                merge_with_cache(resolved_addrs, cache),
                vec![
                    SocketAddr::new(first_addr, 993),
                    SocketAddr::new(second_addr, 993),
                ]
            );
        }

        // If cache contains address that is already in resolution results,
        // it is not duplicated.
        {
            let resolved_addrs = vec![
                SocketAddr::new(first_addr, 993),
                SocketAddr::new(second_addr, 993),
            ];
            let cache = vec![SocketAddr::new(second_addr, 993)];
            assert_eq!(
                merge_with_cache(resolved_addrs, cache),
                vec![
                    SocketAddr::new(first_addr, 993),
                    SocketAddr::new(second_addr, 993),
                ]
            );
        }

        // If DNS resolvers returns a lot of results,
        // we should try cached results before going through all
        // the resolver results.
        {
            let resolved_addrs = vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 993),
            ];
            let cache = vec![SocketAddr::new(second_addr, 993)];
            assert_eq!(
                merge_with_cache(resolved_addrs, cache),
                vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 993),
                    SocketAddr::new(second_addr, 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 993),
                ]
            );
        }

        // Even if cache already contains all the incorrect results
        // that resolver returns, this should not result in them being sorted to the top.
        // Cache has known to work result returned first,
        // so we should try it after the second result.
        {
            let resolved_addrs = vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 993),
            ];
            let cache = vec![
                SocketAddr::new(second_addr, 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 993),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 993),
            ];
            assert_eq!(
                merge_with_cache(resolved_addrs, cache),
                vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 993),
                    SocketAddr::new(second_addr, 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 8)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 7)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 6)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 5)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), 993),
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)), 993),
                ]
            );
        }
    }
}
