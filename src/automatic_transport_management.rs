use std::pin::Pin;

use anyhow::Result;
use deltachat_contact_tools::addr_normalize;
use rand::distr::{Alphanumeric, SampleString};
use rand::seq::IndexedRandom;

use crate::config::Config;
use crate::log::{LogExt, warn};
use crate::login_param::{EnteredCertificateChecks, EnteredImapLoginParam};
use crate::{configure::EnteredLoginParam, context::Context, tools::time};

/// The target number of transports we try to reach.
const NUM_TRANSPORTS_TARGET: usize = 3;
/// How often we want to try adding new transports.
const AUTOMATIC_ADDITION_DEBOUNCE_SECONDS: i64 = 60 * 60; // one hour
/// How long we ignore a transport candidate after failing to create an account there:
const BACKOFF_PERIOD_FOR_NOT_WORKING_TRANSPORT: i64 = 60 * 60 * 24 * 7; // one week

pub(crate) fn maybe_add_additional_transports(
    context: Context,
) -> Pin<Box<dyn Future<Output = ()> + Send>> {
    // We need to Box::pin the future because it wouldn't compile otherwise
    // because Rust async doesn't support recursion:
    // `maybe_add_additional_transports_inner()` calls `restart_io_if_running()`,
    // which (via several other functions) calls `imap_loop()`,
    // which (via several other functions) calls `maybe_add_additional_transports()`
    Box::pin(async move {
        let skip_network = false;
        maybe_add_additional_transports_inner(&context, skip_network)
            .await
            .log_err(&context)
            .ok();
    })
}

async fn maybe_add_additional_transports_inner(
    context: &Context,
    skip_network: bool,
) -> Result<()> {
    let now = time();
    let mut transport_added = false;
    info!(context, "dbg maybe_add_additional_transports");

    let Ok(_housekeeping_lock) = context.housekeeping_mutex.try_lock() else {
        // Housekeeping or automatic relay management is already running in another thread, do nothing.
        info!(context, "dbg skipping because of taken mutex");
        return Ok(());
    };
    let last_timestamp = context
        .get_config_i64(Config::LastAutomaticTransportManagement)
        .await?;
    if last_timestamp > now.saturating_sub(AUTOMATIC_ADDITION_DEBOUNCE_SECONDS) {
        info!(context, "dbg already ran recently");
        if last_timestamp > now {
            // The timestamp is in the future. Cap it to the current time.
            context
                .set_config_internal(
                    Config::LastAutomaticTransportManagement,
                    Some(&now.to_string()),
                )
                .await?;
        }
        return Ok(());
    }
    // TODO uncomment this after I'm done with testing:
    if context
        .get_config_bool(Config::AutomaticTransportManagement)
        .await?
    {
        info!(context, "dbg automatic transport management disabled");
        return Ok(());
    }
    // Set the config at the beginning to avoid endless loops.
    // Race conditions are not a concern because we locked the mutex.
    context
        .set_config_internal(
            Config::LastAutomaticTransportManagement,
            Some(&now.to_string()),
        )
        .await?;

    // Using `for` instead of `while` to prevent infinite loop
    for _ in 0..NUM_TRANSPORTS_TARGET {
        if context.count_transports().await? >= NUM_TRANSPORTS_TARGET {
            info!(context, "dbg target reached");
            return Ok(());
        }

        // First, query all candidates that were not tried since `BACKOFF_PERIOD_FOR_NOT_WORKING_TRANSPORT` seconds.
        // Hosts that are already used are excluded.
        let candidates = load_transport_candidates(context, now).await?;

        let Some(host) = candidates.choose(&mut rand::rng()) else {
            info!(
                context,
                "maybe_add_additional_relays: No suitable candidates"
            );
            return Ok(());
        };
        info!(context, "dbg from {candidates:?}, chose {host}");

        let param = login_param_from_host(host);
        let res = crate::configure::configure(context, &param, skip_network).await;
        if let Err(e) = res {
            warn!(context, "Failed to automatically add a transport: {e:?}.");
            context
                .sql
                .execute("UPDATE relay_candidates SET last_tried=?", (now,))
                .await?;
        }

        transport_added = true;
        info!(context, "dbg success");
    }
    if transport_added {
        info!(context, "dbg restarting");
        context.restart_io_if_running().await;
    }

    Ok(())
}

async fn load_transport_candidates(
    context: &Context,
    now: i64,
) -> Result<Vec<String>, anyhow::Error> {
    let cutoff_timestamp = now.saturating_sub(BACKOFF_PERIOD_FOR_NOT_WORKING_TRANSPORT);
    let candidates: Vec<String> = context
        .sql
        .query_map_vec(
            "SELECT host FROM relay_candidates WHERE last_tried<?
                AND NOT EXISTS (
                    SELECT 1
                    FROM transports
                    WHERE substr(addr, instr(addr, '@') + 1) = host
                )",
            (cutoff_timestamp,),
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

    let param = EnteredLoginParam {
        addr,
        imap: EnteredImapLoginParam {
            password,
            ..Default::default()
        },
        smtp: Default::default(),
        certificate_checks: EnteredCertificateChecks::Strict,
    };
    param
}

#[cfg(test)]
mod automatic_transport_management_tests;
