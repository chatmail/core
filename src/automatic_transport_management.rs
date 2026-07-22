use anyhow::Result;
use rand::TryRngCore as _;
use rand::distr::{Alphanumeric, SampleString};
use rand::seq::IndexedRandom;

use crate::config::Config;
use crate::login_param::{EnteredCertificateChecks, EnteredImapLoginParam};
use crate::{configure::EnteredLoginParam, context::Context, tools::time};

/// The target number of transports we try to reach.
const NUM_TRANSPORTS_TARGET: usize = 3;
/// How often we want to try adding new transports.
const AUTOMATIC_ADDITION_DEBOUNCE_SECONDS: i64 = 60 * 60; // one hour
/// How long we ignore a transport candidate after failing to create an account there:
const BACKOFF_PERIOD_FOR_NOT_WORKING_TRANSPORT: i64 = 60 * 60 * 24 * 7; // one week

// TODO think about how this interacts with stop_io()/start_io()

// TODO decide if this should be done asynchronously in a task;
// generally we should be able to try adding relays while io is running.
pub(crate) async fn maybe_add_additional_transports(context: &Context) -> Result<()> {
    let now = time();

    // TODO potentially rename housekeeping_mutex
    let Ok(_housekeeping_lock) = context.housekeeping_mutex.try_lock() else {
        // Housekeeping or automatic relay management is already running in another thread, do nothing.
        return Ok(());
    };
    if context
        .get_config_i64(Config::LastAutomaticTransportManagement)
        .await?
        > now.saturating_sub(AUTOMATIC_ADDITION_DEBOUNCE_SECONDS)
    {
        return Ok(());
    }
    context
        .set_config_internal(
            Config::LastAutomaticTransportManagement,
            Some(&now.to_string()),
        )
        .await?;

    // Using `for` instead of `while` to prevent infinite loop
    for _ in 0..NUM_TRANSPORTS_TARGET {
        if context.count_transports().await? >= NUM_TRANSPORTS_TARGET {
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

        let param = login_param_from_domain(domain);
        let res = crate::configure::configure(context, &param).await;
        if res.is_err() {
            context
                .sql
                .execute("UPDATE relay_candidates SET last_tried=?", (now,))
                .await?;
        }

        // TODO: Decide whether we want to immediately try again with another relay,
        // if this one failed. If yes, remove the next line.
        res?;
    }

    Ok(())
}

pub(crate) fn login_param_from_domain(domain: &str) -> EnteredLoginParam {
    let rng = &mut rand::rng();
    let username = Alphanumeric.sample_string(rng, 9);
    let addr = username + "@" + domain;
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
