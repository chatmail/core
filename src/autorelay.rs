//! # Automatic relay handling (experimental, still in development)
//!
//! Chatmail relays create an account on first login,
//! so a profile can add further transports on its own without user interaction.
//! Candidate hosts come from the `relay_candidates` table,
//! which migrations seed with a list of known chatmail relays.
//!
//! Status of implementation:
//!
//! - When the UI uses `init_transports()`, the user gets 3 randomly selected relays.
//!
//! - Later additions are attempted right before going into IMAP IDLE,
//!   i.e. only while connected and with nothing more important to do,
//!   and only if a UI opted in via [`Config::Autorelay`].
//!   Once a profile has reached `NUM_TRANSPORTS_TARGET` transports,
//!   [`Config::AutorelayFinished`] is set and nothing is ever added again,
//!   so deleting a transport later does not pull in a replacement.

use std::collections::BTreeSet;
use std::pin::Pin;

use anyhow::Result;
use deltachat_contact_tools::{EmailAddress, addr_normalize};
use rand::distr::{Alphanumeric, SampleString};
use rand::rng;
use rand::seq::{IndexedRandom, SliceRandom as _};
use tokio::task::JoinSet;

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

const DEFAULT_RELAY_CANDIDATES: &[&str] = &[
    "chat.adminforge.de",
    "tarpit.fun",
    "sweetfern.net",
    "chat.nuvon.app",
    "nchrcht.la10cy.net",
    "chat.sus.fr",
    "chat.tinydispatch.org",
    "chtml.ca",
    "chatmail.uk",
];

pub(crate) async fn init_transports_inner(
    context: &Context,
    addrs_from_qr: Vec<String>,
    skip_network: bool,
) -> Result<(), anyhow::Error> {
    let mut default_relays: Vec<&str> = DEFAULT_RELAY_CANDIDATES.into();
    default_relays.shuffle(&mut rng());

    let (relays_sender, relays_receiver) = async_channel::unbounded::<String>();
    let relays_from_qr: BTreeSet<_> = addrs_from_qr
        .into_iter()
        .filter_map(|addr| EmailAddress::new(&addr).ok())
        .map(|email| email.domain)
        .collect();
    for relay in &relays_from_qr {
        relays_sender.try_send(relay.to_string())?;
    }
    for relay in default_relays {
        if !relays_from_qr.contains(relay) {
            relays_sender.try_send(relay.to_string())?;
        }
    }

    let mut join_set = JoinSet::new();
    for _ in 0..NUM_TRANSPORTS_TARGET {
        let context = context.clone();
        let relays_receiver = relays_receiver.clone();
        join_set.spawn(async move {
            loop {
                // Take a lock in order to prevent other relay management code
                // from running simultaneously
                let _lock = context.background_task_lock.read();

                let Ok(host) = relays_receiver.try_recv() else {
                    return false; // No more relays to try
                };
                let param = login_param_from_host(&host);
                let res = crate::configure::configure(&context, &param, skip_network).await;
                if let Err(err) = res {
                    warn!(context, "Failed to init transport {host}: {err:#}.");
                    // Try another relay in the next iteration of the loop
                } else {
                    if context.count_transports().await.unwrap_or(0) >= NUM_TRANSPORTS_TARGET {
                        context
                            .set_config_bool(Config::AutorelayFinished, true)
                            .await
                            .log_err(&context)
                            .ok();
                    }
                    return true; // Success
                }
            }
        });
    }

    while let Some(success) = join_set.join_next().await {
        if success? {
            break;
        }
        // If this task was not successful, continue waiting for the other tasks
        // because maybe one of the ongoing configuration attempts will be successful
    }

    join_set.detach_all();

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

    let Ok(_lock) = context.background_task_lock.try_write() else {
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

        context
            .sql
            .execute(
                "UPDATE relay_candidates SET last_tried=? WHERE host=?",
                (now, host),
            )
            .await?;
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

pub(crate) async fn load_relay_candidates(context: &Context, now: i64) -> Result<Vec<String>> {
    let cutoff_timestamp = now.saturating_sub(BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY);

    let candidates: Vec<String> = context
        .sql
        .transaction(|transaction| {
            // Add any relay candidates that are not in the database yet
            let mut statement =
                transaction.prepare("INSERT OR IGNORE INTO relay_candidates(host) VALUES (?)")?;
            for host in DEFAULT_RELAY_CANDIDATES {
                statement.execute((host,))?;
            }

            transaction.query_map_vec(
                // This also selects candidates which have last_tried in the future,
                // essentially treating them as never tried,
                // so if some timestamp far in the future is accidentally stored,
                // we are not stuck never trying the candidate.
                // After trying the candidate, last_tried will be corrected to the current time.
                "SELECT host FROM relay_candidates WHERE (last_tried<? OR last_tried>?)
                AND NOT EXISTS (
                    SELECT 1
                    FROM transports
                    WHERE substr(addr, instr(addr, '@') + 1) = host
                )",
                (cutoff_timestamp, now),
                |row| Ok(row.get::<_, String>(0)?),
            )
        })
        .await?;

    Ok(candidates)
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
