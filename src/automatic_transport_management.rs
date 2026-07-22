use std::pin::Pin;

use anyhow::Result;
use deltachat_contact_tools::addr_normalize;
use rand::distr::{Alphanumeric, SampleString};
use rand::seq::IndexedRandom;

use crate::config::Config;
use crate::log::LogExt as _;
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
    Box::pin(async move {
        maybe_add_additional_transports_inner(&context)
            .await
            .log_err(&context)
            .ok();
    })
}

async fn maybe_add_additional_transports_inner(context: &Context) -> Result<()> {
    let now = time();
    let mut transport_added = false;
    info!(context, "dbg maybe_add_additional_transports");

    let Ok(_housekeeping_lock) = context.housekeeping_mutex.try_lock() else {
        // Housekeeping or automatic relay management is already running in another thread, do nothing.
        info!(context, "dbg skipping because of taken mutex");
        return Ok(());
    };
    if context
        .get_config_i64(Config::LastAutomaticTransportManagement)
        .await?
        > now.saturating_sub(AUTOMATIC_ADDITION_DEBOUNCE_SECONDS)
    {
        info!(context, "dbg already ran recently");
        return Ok(());
    }
    // TODO uncomment this after I'm done with testing:
    // if context
    //     .get_config_bool(Config::AutomaticTransportManagement)
    //     .await?
    // {
    //     info!(context, "dbg automatic transport management disabled");
    //     return Ok(());
    // }
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
        // Domains that are already used are excluded.
        let cutoff_timestamp = now.saturating_sub(BACKOFF_PERIOD_FOR_NOT_WORKING_TRANSPORT);
        let candidates: Vec<String> = context
            .sql
            .query_map_vec(
                "SELECT domain FROM relay_candidates WHERE last_tried<?
                AND NOT EXISTS (
                    SELECT 1
                    FROM transports
                    WHERE substr(addr, instr(addr, '@') + 1) = domain
                )",
                (cutoff_timestamp,),
                |row| Ok(row.get::<_, String>(0)?),
            )
            .await?;

        let Some(domain) = candidates.choose(&mut rand::rng()) else {
            info!(
                context,
                "maybe_add_additional_relays: No suitable candidates"
            );
            return Ok(());
        };
        info!(context, "dbg from {candidates:?}, chose {domain}");

        let param = login_param_from_domain(domain);
        let res = crate::configure::configure(context, &param).await;
        if res.is_err() {
            info!(context, "dbg error {res:?}");
            context
                .sql
                .execute("UPDATE relay_candidates SET last_tried=?", (now,))
                .await?;
        }

        // TODO: Decide whether we want to immediately try again with another relay,
        // if this one failed. If yes, remove the next line.
        res?;

        transport_added = true;
        info!(context, "dbg success");
    }
    if transport_added {
        info!(context, "dbg restarting");
        context.restart_io_if_running().await;
    }

    Ok(())
}

pub(crate) fn login_param_from_domain(domain: &str) -> EnteredLoginParam {
    let rng = &mut rand::rng();
    let username = Alphanumeric.sample_string(rng, 9);
    let addr = username + "@" + domain;
    let addr = addr_normalize(&addr);
    let password = Alphanumeric.sample_string(rng, 50);

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
