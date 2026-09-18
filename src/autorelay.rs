//! # Automatic relay handling (experimental, still in development)
//!
//! Chatmail relays create an account on first login,
//! so a profile can add further transports on its own without user interaction.
//! Candidate hosts come from the `relay_candidates` table,
//! which migrations seed with a list of known chatmail relays.
//!
//! Status of implementation:
//!
//! - When the UI uses `init_transports()`, we attempt to add 3 relays.
//!
//! - Later additions are attempted right before going into IMAP IDLE,
//!   i.e. only while connected and with nothing more important to do,
//!   and only if a UI opted in via [`Config::Autorelay`].
//!   Once a profile has reached `NUM_TRANSPORTS_TARGET` transports,
//!   [`Config::AutorelayFinished`] is set and nothing is ever added again,
//!   so deleting a transport later does not pull in a replacement.

use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Result, bail};
use deltachat_contact_tools::{EmailAddress, addr_normalize};
use rand::distr::{Alphanumeric, SampleString};
use rand::rng;
use rand::seq::{IndexedRandom, SliceRandom as _};
use tokio::sync::Mutex;
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
    // If relays were provided via the addresses in the QR code,
    // then these relays are tried first.
    let (relays_sender, relays_receiver) = async_channel::unbounded::<String>();
    let relays_from_qr: BTreeSet<String> = addrs_from_qr
        .into_iter()
        .filter_map(|addr| EmailAddress::new(&addr).ok())
        .map(|email| email.domain)
        .collect();
    for relay in &relays_from_qr {
        relays_sender.try_send(relay.to_string())?;
    }

    // After the relays from the QR code,
    // the default relays are tried in a random order.
    let mut default_relays: Vec<&str> = DEFAULT_RELAY_CANDIDATES.into();
    default_relays.shuffle(&mut rng());
    for relay in default_relays {
        if !relays_from_qr.contains(relay) {
            relays_sender.try_send(relay.to_string())?;
        }
    }

    let last_error: Arc<Mutex<String>> = Default::default();

    // Spawn NUM_TRANSPORTS_TARGET tasks that each add a relay concurrently.
    let mut join_set = JoinSet::new();
    for _ in 0..NUM_TRANSPORTS_TARGET {
        let context = context.clone();
        let relays_receiver = relays_receiver.clone();
        let last_error = last_error.clone();
        join_set.spawn(async move {
            // Take a lock in order to prevent other relay management code
            // from running simultaneously
            let _lock = context.background_task_lock.read().await;
            // TODO add a back-channel here,
            // and then the surrounding function has to wait until all tasks took the lock

            loop {
                let Ok(host) = relays_receiver.try_recv() else {
                    return false; // No more relays to try
                };
                let param = login_param_from_host(&host);
                let res = crate::configure::configure(&context, &param, skip_network).await;
                if let Err(err) = res {
                    warn!(context, "Failed to init transport {host}: {err:#}.");
                    *last_error.lock().await = format!("{err:#}");
                    // Try another relay in the next iteration of the loop
                } else {
                    info!(context, "Initialized with transport {host}");
                    if context.count_transports().await.unwrap_or(0) >= NUM_TRANSPORTS_TARGET {
                        context
                            .set_config_bool(Config::AutorelayFinished, true)
                            .await
                            .log_err(&context)
                            .ok();
                        info!(context, "Target number of transports reached.");
                        context.restart_io_if_running().await;
                    }
                    return true; // Success
                }
            }
        });
    }

    loop {
        match join_set.join_next().await {
            Some(Ok(true)) => break, // Success
            Some(Ok(false)) => {}    // Wait until one of the other tasks is successful
            Some(Err(e)) => warn!(context, "One of the init_transports tasks failed: {e:#}"),
            None => bail!(
                "Could not configure any relay, are you offline? ({})",
                last_error.try_lock()?
            ),
        }
    }

    // Let the other tasks continue running in the background
    // while the user can already use Delta Chat:
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

async fn load_relay_candidates(context: &Context, now: i64) -> Result<Vec<String>> {
    let cutoff_timestamp = now.saturating_sub(BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY);
    let candidates: Vec<String> = context
        .sql
        .transaction(|transaction| {
            // Add the default relays if they are not in the database yet
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
