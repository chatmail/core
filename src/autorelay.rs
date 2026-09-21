//! # Automatic multi-relay onboarding
//!
//! Support for automatically onboarding a profile on transport
//! candidates without the user choosing a relay.

use std::collections::BTreeMap;
use std::pin::Pin;

use anyhow::{Result, format_err};
use deltachat_contact_tools::addr_normalize;
use rand::distr::{Alphanumeric, SampleString};
use rand::seq::{IndexedRandom, SliceRandom};
use rusqlite::Transaction;
use tokio::task::JoinSet;

use crate::config::{self, Config};
use crate::configure::{EnteredLoginParam, SILENT_PROGRESS, configure};
use crate::log::{LogExt, warn};
use crate::login_param::{EnteredCertificateChecks, EnteredImapLoginParam};
use crate::net::{connect_tcp, proxy::ProxyConfig};
use crate::{context::Context, tools::time};

/// The target number of transports.
const NUM_TRANSPORTS_TARGET: usize = 3;
/// How often we want to try adding new relays.
const AUTOMATIC_ADDITION_DEBOUNCE_SECONDS: i64 = 60 * 60; // one hour
/// How long we ignore a relay candidate after failing to connect to it:
const BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY: i64 = 60 * 60 * 24 * 7; // one week

/// Sorted relay list a profile can attempt to onboard on without the user choosing one.
const DEFAULT_RELAY_CANDIDATES: &[&str] = &[
    "chat.adminforge.de", // iroh relay 404s
    "chat.me.ke",
    "chat.nuvon.app",
    "chat.tinydispatch.org",
    "chat.vim.wtf",
    "chatmail.uk",
    "chtml.ca",
    "deltachat.me",
    "e2e.sus.fr",
    "e2ee.wang",
    "mailchat.pl",
    "nchrcht.la10cy.net",
    "nine.testrun.org",
    "sweetfern.net",
    "tarpit.fun",
];

/// Records the hosts of `addrs` as relay candidates.
pub(crate) async fn add_relay_candidates(context: &Context, addrs: &[String]) -> Result<()> {
    context
        .sql
        .transaction(|tx| hosts_of(addrs).try_for_each(|host| save_relay_candidate(tx, host, 0)))
        .await
}

/// Adds a first transport on the relay candidate that answers fastest.
///
/// All candidates are probed at once with a TCP connection to their HTTPS port
/// and configured in the order in which the connections complete,
/// stopping at the first success. Candidates that fail the probe are skipped.
/// Answering TCP fastest is used as a network proximity measure,
/// which keeps latency low for initial onboarding,
/// and it avoids relays that are down or black-holing traffic.
pub(crate) async fn add_transport_from_candidates(
    context: &Context,
    skip_network: bool,
) -> Result<()> {
    let mut candidates = triable_relay_candidates(context, time()).await?;
    candidates.shuffle(&mut rand::rng());
    let mut probes = JoinSet::new();
    let proxy_config = ProxyConfig::load(context).await?;
    let load_cache = false;
    for host in candidates {
        let ctx = context.clone();
        let proxy_config = proxy_config.clone();
        probes.spawn(async move {
            let res = match proxy_config {
                _ if skip_network => Ok(()),
                Some(proxy) => proxy.connect(&ctx, &host, 443, load_cache).await.map(drop),
                None => connect_tcp(&ctx, &host, 443, load_cache).await.map(drop),
            };
            (host, res)
        });
    }

    let mut last_err = format_err!("No relay candidates");
    let mark_as_autorelay = true;
    while let Some(res) = probes.join_next().await {
        let (host, res) = res?;
        if let Err(err) = res {
            warn!(context, "Failed to connect to relay {host}: {err:#}.");
            last_err = err;
            continue;
        }
        let param = login_param_from_host(&host, mark_as_autorelay);
        match configure(context, &param, skip_network).await {
            Ok(()) => {
                info!(context, "Added a transport on relay {host}.");
                return Ok(());
            }
            Err(err) => {
                warn!(context, "Failed to add relay {host}: {err:#}.");
                last_err = err;
            }
        }
    }
    Err(last_err)
}

pub(crate) fn maybe_add_additional_relays(
    context: Context,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    // We need to Box::pin the future because it wouldn't compile otherwise
    // because Rust async doesn't support recursion:
    // `maybe_add_additional_relays_inner()` calls `restart_io_if_running()`,
    // which (via several other functions) calls `imap_loop()`,
    // which (via several other functions) calls `maybe_add_additional_relays()`
    Box::pin(async move {
        let skip_network = false;
        let relay_added = maybe_add_additional_relays_inner(&context, skip_network)
            .await
            .log_err(&context)
            .unwrap_or(false);

        if relay_added {
            info!(context, "Restarting IO after relay addition");
            context.restart_io_if_running().await;
        }
    })
}

async fn maybe_add_additional_relays_inner(context: &Context, skip_network: bool) -> Result<bool> {
    let now = time();

    let Ok(_lock) = context.background_task_mutex.try_lock() else {
        // Housekeeping or automatic relay management is already running in another thread, do nothing.
        return Ok(false);
    };
    let last_timestamp = context.get_config_i64(Config::LastAutorelay).await?;
    if last_timestamp > now {
        warn!(
            context,
            "Clock ran backwards, unclear if automatic relay management should run. Will run it anyways."
        );
    } else if last_timestamp > now.saturating_sub(AUTOMATIC_ADDITION_DEBOUNCE_SECONDS) {
        return Ok(false);
    }
    if !context.get_config_bool(Config::Autorelay).await? {
        return Ok(false);
    }
    if context.get_config_bool(Config::AutorelayFinished).await? {
        return Ok(false);
    }
    // Set the config at the beginning to avoid endless loops.
    // Race conditions are not a concern because we locked the mutex.
    context
        .set_config_internal(Config::LastAutorelay, Some(&now.to_string()))
        .await?;

    let mut relay_added = false;
    // Using `for` instead of `while` to prevent infinite loop
    for _ in 0..NUM_TRANSPORTS_TARGET {
        if context.count_transports().await? >= NUM_TRANSPORTS_TARGET {
            context
                .set_config_internal(Config::AutorelayFinished, config::from_bool(true))
                .await?;

            return Ok(relay_added);
        }

        let candidates = triable_relay_candidates(context, now).await?;
        let Some(host) = candidates.choose(&mut rand::rng()) else {
            info!(
                context,
                "maybe_add_additional_relays: No suitable candidates"
            );
            return Ok(relay_added);
        };

        info!(
            context,
            "Trying to automatically add relay {host} (there were {} candidates).",
            candidates.len(),
        );

        context
            .sql
            .transaction(|tx| save_relay_candidate(tx, host, now))
            .await?;
        let mark_as_autorelay = true;
        let param = login_param_from_host(host, mark_as_autorelay);
        let res = SILENT_PROGRESS
            .scope((), configure(context, &param, skip_network))
            .await;
        if let Err(e) = res {
            warn!(
                context,
                "Failed to automatically add a relay {host}: {e:#}."
            );
        } else {
            info!(context, "Successfully automatically added relay {host}.");
            relay_added = true;
        }
    }

    Ok(relay_added)
}

async fn triable_relay_candidates(context: &Context, now: i64) -> Result<Vec<String>> {
    let cutoff_timestamp = now.saturating_sub(BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY);
    let mut last_tried: BTreeMap<String, i64> = context
        .sql
        .query_map_collect("SELECT host, last_tried FROM relay_candidates", (), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .await?;
    for host in DEFAULT_RELAY_CANDIDATES {
        last_tried.entry(host.to_string()).or_insert(0);
    }
    let self_addrs = context.get_self_addrs().await?;
    let used_hosts: Vec<&str> = hosts_of(&self_addrs).collect();

    // We also try candidates which have `last_tried` in the future,
    // which on next failure get `last_tried` reset to the current time.
    let candidates = last_tried
        .into_iter()
        .filter(|(host, last_tried)| {
            (*last_tried < cutoff_timestamp || *last_tried > now)
                && !used_hosts.contains(&host.as_str())
        })
        .map(|(host, _)| host)
        .collect();

    Ok(candidates)
}

/// Returns the host of each address in `addrs`.
fn hosts_of(addrs: &[String]) -> impl Iterator<Item = &str> {
    addrs.iter().filter_map(|a| Some(a.rsplit_once('@')?.1))
}

/// Records `host` as a relay candidate, overwriting a stored `last_tried`.
fn save_relay_candidate(tx: &Transaction, host: &str, last_tried: i64) -> Result<()> {
    tx.execute(
        "INSERT INTO relay_candidates (host, last_tried) VALUES (?, ?)
        ON CONFLICT(host) DO UPDATE SET last_tried=excluded.last_tried",
        (host, last_tried),
    )?;
    Ok(())
}

pub(crate) fn login_param_from_host(host: &str, mark_as_autorelay: bool) -> EnteredLoginParam {
    let rng = &mut rand::rng();
    let username = Alphanumeric.sample_string(rng, 9);
    let addr = username + "@" + host;
    let addr = addr_normalize(&addr);

    // `mark_as_autorelay` is a temporary precaution hack
    // while introducing onboarding on multiple community relays from a list:
    // though relay operators were asked to get on that list, unexpected things can happen,
    // and they want to return to allow only manual onboarding.
    // this is possible by failing on `password_len == 23`.

    // 22 * log2(26 * 2 + 10) = 130 bits of entropy
    let password = Alphanumeric.sample_string(rng, if mark_as_autorelay { 23 } else { 22 });

    EnteredLoginParam {
        addr,
        imap: EnteredImapLoginParam {
            password,
            ..Default::default()
        },
        smtp: Default::default(),
        certificate_checks: EnteredCertificateChecks::Strict,
        oauth2: false,
    }
}

#[cfg(test)]
mod autorelay_tests;
