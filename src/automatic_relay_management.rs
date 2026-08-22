use std::pin::Pin;

use anyhow::Result;
use deltachat_contact_tools::addr_normalize;
use rand::distr::{Alphanumeric, SampleString};
use rand::seq::IndexedRandom;

use crate::config::{self, Config};
use crate::log::{LogExt, warn};
use crate::login_param::{EnteredCertificateChecks, EnteredImapLoginParam};
use crate::{configure::EnteredLoginParam, context::Context, tools::time};

/// The target number of transports.
const NUM_TRANSPORTS_TARGET: usize = 3;
/// How often we want to try adding new relays.
const AUTOMATIC_ADDITION_DEBOUNCE_SECONDS: i64 = 60 * 60; // one hour
/// How long we ignore a relay candidate after failing to connect to it:
const BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY: i64 = 60 * 60 * 24 * 7; // one week

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
    let last_timestamp = context
        .get_config_i64(Config::LastAutomaticRelayManagement)
        .await?;
    if last_timestamp > now {
        warn!(
            context,
            "Clock ran backwards, unclear if automatic relay management should run. Will run it anyways."
        );
    } else if last_timestamp > now.saturating_sub(AUTOMATIC_ADDITION_DEBOUNCE_SECONDS) {
        return Ok(false);
    }
    if !context
        .get_config_bool(Config::AutomaticRelayManagement)
        .await?
    {
        return Ok(false);
    }
    if context
        .get_config_bool(Config::AutomaticRelayManagementFinished)
        .await?
    {
        return Ok(false);
    }
    // Set the config at the beginning to avoid endless loops.
    // Race conditions are not a concern because we locked the mutex.
    context
        .set_config_internal(Config::LastAutomaticRelayManagement, Some(&now.to_string()))
        .await?;

    let mut relay_added = false;
    // Using `for` instead of `while` to prevent infinite loop
    for _ in 0..NUM_TRANSPORTS_TARGET {
        if context.count_transports().await? >= NUM_TRANSPORTS_TARGET {
            context
                .set_config_internal(
                    Config::AutomaticRelayManagementFinished,
                    config::from_bool(true),
                )
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

async fn load_relay_candidates(context: &Context, now: i64) -> Result<Vec<String>, anyhow::Error> {
    let cutoff_timestamp = now.saturating_sub(BACKOFF_PERIOD_FOR_NOT_WORKING_RELAY);
    let candidates: Vec<String> = context
        .sql
        .query_map_vec(
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

pub(crate) async fn send_key_update_messages(context: &Context) -> Result<()> {
    let contacts_to_update: Vec<ContactId> = contacts_to_update(context).await?;

    let chunks = contacts_to_update.chunks(20);

    for chunk in chunks {
        send_key_update_message(context, chunk).await?;
    }

    Ok(())
}

#[cfg(test)]
mod automatic_relay_management_tests;
