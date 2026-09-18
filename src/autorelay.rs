//! # Automatic relay handling (experimental, still in development)
//!
//! Chatmail relays create an account on first login,
//! so a profile can add further transports on its own without user interaction.
//! Candidate hosts come from the `relay_candidates` table
//! as well as the [`DEFAULT_RELAY_CANDIDATES`] list.
//!
//! Status of implementation:
//! Additions are attempted right before going into IMAP IDLE,
//! i.e. only while connected and with nothing more important to do,
//! and only if a UI opted in via [`Config::Autorelay`].
//! Once a profile has reached `NUM_TRANSPORTS_TARGET` transports,
//! [`Config::AutorelayFinished`] is set and nothing is ever added again,
//! so deleting a transport later does not pull in a replacement.

use std::collections::BTreeSet;
use std::pin::Pin;

use anyhow::Result;
use deltachat_contact_tools::addr_normalize;
use rand::distr::{Alphanumeric, SampleString};
use rand::seq::IndexedRandom;

use crate::config::{self, Config};
use crate::log::{LogExt, warn};
use crate::login_param::{EnteredCertificateChecks, EnteredImapLoginParam};
use crate::sql::TransactionExt as _;
use crate::{configure::EnteredLoginParam, context::Context, tools::time};

/// The target number of transports.
const NUM_TRANSPORTS_TARGET: usize = 3;
/// How often we want to try adding new relays.
const AUTOMATIC_ADDITION_DEBOUNCE_SECONDS: i64 = 60 * 60; // one hour
/// How long we ignore a relay candidate after failing to connect to it:
const BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY: i64 = 60 * 60 * 24 * 7; // one week

/// The list of relays to which we onboard
/// if no other relays are provided via QR codes.
/// Please keep this list alphabetically sorted.
const DEFAULT_RELAY_CANDIDATES: &[&str] = &[
    "chat.adminforge.de",
    "chat.feld.me",
    "chat.nuvon.app",
    "chat.tinydispatch.org",
    "chat.vim.wtf",
    "chatmail.uk",
    "chtml.ca",
    "mailchat.pl",
    "nchrcht.la10cy.net",
    "nine.testrun.org",
    "sweetfern.net",
    "tarpit.fun",
];

pub(crate) async fn init_transports_inner(
    context: &Context,
    addrs_from_qr: Vec<String>,
    skip_network: bool,
) -> Result<()> {
    context
        .sql
        .transaction(|transaction| {
            let mut stmt = transaction.prepare("INSERT INTO relay_candidates(host) VALUES(?)")?;
            for addr in addrs_from_qr {
                stmt.execute((addr,))?;
            }
            Ok(())
        })
        .await?;

    let host = "nine.testrun.org";
    let param = login_param_from_host(host);
    let res = crate::configure::configure(context, &param, skip_network).await;
    if let Err(err) = &res {
        warn!(context, "Failed to init transports: {err:#}.");
    } else {
        info!(context, "Initialized with transport {host}");
    }
    res?;

    context.set_config_bool(Config::Autorelay, true).await?;

    Ok(())
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
        let num_transports = context.count_transports().await?;
        if num_transports >= NUM_TRANSPORTS_TARGET {
            info!(context, "Transports target reached at {num_transports}");
            context
                .set_config_internal(Config::AutorelayFinished, config::from_bool(true))
                .await?;

            return Ok(relay_added);
        } else {
            info!(context, "There are {num_transports} relays, will add more");
        }

        // First, query all candidates that were not tried since `BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY` seconds.
        // Hosts that are already used are excluded.
        let candidates = load_relay_candidates(context, now).await?;

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

        set_relay_candidate_last_tried(context, host, now).await?;
        let param = login_param_from_host(host);
        let res = crate::configure::configure(context, &param, skip_network).await;
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

async fn set_relay_candidate_last_tried(
    context: &Context,
    host: &str,
    now: i64,
) -> Result<(), anyhow::Error> {
    context
        .sql
        .execute(
            "INSERT OR REPLACE INTO relay_candidates_last_tried(host, last_tried) VALUES(?, ?)",
            (host, now),
        )
        .await?;
    Ok(())
}

async fn load_relay_candidates(context: &Context, now: i64) -> Result<Vec<String>> {
    let res = context
        .sql
        .transaction(|transaction| {
            let mut candidates: BTreeSet<String> =
                transaction.query_map_collect("SELECT host FROM relay_candidates", (), |row| {
                    Ok(row.get(0)?)
                })?;

            candidates.extend(DEFAULT_RELAY_CANDIDATES.iter().map(|s| s.to_string()));

            let cutoff_timestamp = now.saturating_sub(BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY);
            // This does not select candidates which have last_tried in the future,
            // essentially treating them as never tried,
            // so if some timestamp far in the future is accidentally stored,
            // we are not stuck never trying the candidate.
            // After trying the candidate, last_tried will be corrected to the current time.
            let exclude: BTreeSet<String> = transaction.query_map_collect(
                "SELECT host FROM relay_candidates_last_tried WHERE (last_tried>=? AND last_tried<=?)
                UNION
                SELECT substr(addr, instr(addr, '@') + 1) FROM transports",
                (cutoff_timestamp, now),
                |row| Ok(row.get(0)?),
            )?;

            Ok(candidates
                .difference(&exclude)
                .map(|s| s.to_string())
                .collect::<Vec<String>>())
        })
        .await?;

    Ok(res)
}

pub(crate) fn login_param_from_host(host: &str) -> EnteredLoginParam {
    let rng = &mut rand::rng();
    let username = Alphanumeric.sample_string(rng, 9);
    let addr = username + "@" + host;
    let addr = addr_normalize(&addr);
    // 22 * log2(26 * 2 + 10) = 130 bits of entropy
    let password = Alphanumeric.sample_string(rng, 22);

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
