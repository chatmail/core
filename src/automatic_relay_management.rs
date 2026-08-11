use std::pin::Pin;

use anyhow::Result;
use deltachat_contact_tools::addr_normalize;
use rand::distr::{Alphanumeric, SampleString};
use rand::seq::IndexedRandom;

use crate::chat::add_device_msg;
use crate::config::{self, Config};
use crate::contact::ContactId;
use crate::log::{LogExt, warn};
use crate::login_param::{EnteredCertificateChecks, EnteredImapLoginParam};
use crate::message::{Message, MsgId};
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

pub(crate) async fn record_message_sent_via_transport_by_msg_id(
    context: &Context,
    msg_id: MsgId,
    transport_id: u32,
) -> Result<()> {
    let Some(contact_id): Option<ContactId> = context
        .sql
        .query_get_value("SELECT from_id FROM msgs WHERE id=?", (msg_id,))
        .await?
    else {
        warn!(context, "Invalid msg_id");
        return Ok(());
    };
    record_message_sent_via_transport(context, contact_id, transport_id).await?;

    Ok(())
}

/// Records that the specified contact sent a message via the specified transport,
/// i.e. that we can be sure that the contact knows about this transport.
/// This info is saved into the `transport_awareness_by_contacts` table.
pub(crate) async fn record_message_sent_via_transport(
    context: &Context,
    contact_id: ContactId,
    transport_id: u32,
) -> Result<()> {
    if contact_id.is_special() {
        return Ok(());
    }

    context
        .sql
        .execute(
            "INSERT OR REPLACE INTO transport_awareness_by_contacts(contact_id, transport_id, last_seen)
            VALUES (?,?,?)",
            (contact_id, transport_id, time()),
        )
        .await?;

    Ok(())
}

pub(crate) async fn output_debug_transport_awareness(context: &Context) -> Result<()> {
    let msg = get_debug_transport_awareness(context).await?;
    let mut msg = Message::new_text(msg);
    add_device_msg(context, None, Some(&mut msg)).await?;

    Ok(())
}

async fn get_debug_transport_awareness(context: &Context) -> Result<String, anyhow::Error> {
    fn get_contact_name(row: &rusqlite::Row<'_>) -> Result<String> {
        let name: String = row.get(0)?;
        let authname: String = row.get(1)?;
        if name.is_empty() {
            Ok(authname)
        } else {
            Ok(name)
        }
    }
    fn filter_out_empty<F>(rows: rusqlite::AndThenRows<'_, F>) -> Result<Vec<String>>
    where
        F: FnMut(&rusqlite::Row<'_>) -> Result<String>,
    {
        rows.filter(|name| name.as_ref().is_ok_and(|n| !n.is_empty()))
            .collect()
    }

    let mut msg = "=== Usage of transports by contacts ===".to_string();
    let transports = context
        .sql
        .query_map_vec("SELECT id, addr FROM transports", (), |row| {
            let id: u32 = row.get(0)?;
            let addr: String = row.get(1)?;
            Ok((id, addr))
        })
        .await?;
    for (transport_id, addr) in transports {
        let lost_contacts: Vec<String> = context
            .sql
            .query_map(
                // Select all contacts that can reach us via this transport,
                // but can't reach us via the other transports.
                // These are the contacts we may lose by removing this transport.
                "SELECT name, authname FROM contacts
                WHERE id IN (SELECT contact_id FROM transport_awareness_by_contacts WHERE transport_id = ?1)
                AND id NOT IN (
                    SELECT contact_id FROM transport_awareness_by_contacts WHERE transport_id IN (
                        SELECT id FROM transports WHERE id != ?1
                    )
                )
                AND id>9
                ORDER BY last_seen DESC",
                (transport_id,),
                get_contact_name,
                filter_out_empty,
            )
            .await?;

        msg += &format!("\nThese contacts fail to reach you if you remove transport {addr}:\n");
        msg += &lost_contacts.join("\n");
    }
    let lost_contacts: Vec<String> = context
        .sql
        .query_map(
            // Select all contacts that cannot reach us via one of the current transports,
            // but could reach us via some transport that's not in use anymore:
            "SELECT name, authname FROM contacts
                WHERE id NOT IN (
                    SELECT contact_id FROM transport_awareness_by_contacts WHERE transport_id IN (
                        SELECT id FROM transports
                    )
                )
                AND id IN (SELECT contact_id FROM transport_awareness_by_contacts)
                AND id>9
                ORDER BY last_seen DESC",
            (),
            get_contact_name,
            filter_out_empty,
        )
        .await?;
    msg += "\nThese contacts likely can't reach you anymore:\n";
    msg += &lost_contacts.join("\n");

    let unknown_contacts: Vec<String> = context
        .sql
        .query_map(
            // Select all contacts that never sent a message
            // since we started recording transport usage
            "SELECT name, authname FROM contacts
                WHERE id NOT IN (SELECT contact_id FROM transport_awareness_by_contacts)
                AND id>9
                ORDER BY last_seen DESC",
            (),
            get_contact_name,
            filter_out_empty,
        )
        .await?;
    msg += "\nFor these contacts, it's unclear how they can reach you:\n";
    msg += &unknown_contacts.join("\n");

    Ok(msg)
}

#[cfg(test)]
mod automatic_relay_management_tests;
