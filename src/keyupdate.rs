//! # Keyupdate messages.
//!
//! Contacts learn our relay list from the key our messages carry,
//! so after a relay change a "mutually silent" contact may keep writing
//! to relays we no longer read. A keyupdate tells them proactively,
//! carrying the re-signed key to [`KEYUPDATE_CHUNK_CONTACTS`] contacts at a time.
//!
//! Keyupdates are *unsigned*, because a signature
//! carries one intended recipient fingerprint per recipient,
//! which would tell everyone in the chunk who the others are.
//! Receivers still learn the key, as the Autocrypt header is merged
//! before any signature is checked, and trash the message itself.
//!
//! Nothing authenticates the sender and nothing needs to:
//! certificate merging verifies the relay list in the direct key signature
//! and keeps the newest one, which also defeats replaying an old keyupdate.
//!
//! Recipients ([`keyupdate_recipients`]) are the key-contacts who can
//! plausibly hold our key, aged out after [`KEYUPDATE_MAX_SILENCE`] and capped
//! at [`KEYUPDATE_MAX_RECIPIENTS`] so one relay change cannot cause unbounded traffic.
//!
//! A transport change only schedules a check,
//! debouncing several changes into one message,
//! which the SMTP loop sends once its queue is drained.
//! Whether anything is due is a diff against [`Config::KeyupdateBaseline`]:
//! a migration seeds it so upgrading sends nothing, and a device ingesting a sync
//! records the new list instead of sending ([`set_current_relays_as_keyupdate_baseline`]).

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;

use anyhow::Result;
use deltachat_contact_tools::addr_normalize;
use rand::seq::SliceRandom;

use crate::chat;
use crate::chat::ChatId;
use crate::config::Config;
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::context::Context;
use crate::key::{DcKey, SignedPublicKey};
use crate::log::warn;
use crate::message;
use crate::mimefactory::render_keyupdate_message;
use crate::pgp::{pubkey_can_encrypt, relay_addrs};
use crate::tools::{create_outgoing_rfc724_mid, time};

/// Maximum number of contacts one (chunk of a) keyupdate message is encrypted to.
const KEYUPDATE_CHUNK_CONTACTS: usize = 200;

/// How long a contact may show no sign of life before keyupdates skip them.
const KEYUPDATE_MAX_SILENCE: i64 = 3 * 365 * 24 * 3600;

/// Upper bound on the contacts informed after a relay list change, keeping the freshest.
const KEYUPDATE_MAX_RECIPIENTS: usize = 5000;

/// A contact to inform: the relays to reach them at, and the key to encrypt to.
struct KeyupdateRecipient {
    relays: Vec<String>,
    public_key: SignedPublicKey,
}

/// Returns at most `max_recipients` key-contacts to inform.
async fn keyupdate_recipients(
    context: &Context,
    max_recipients: usize,
) -> Result<Vec<KeyupdateRecipient>> {
    // Single chat contacts only become keyupdate recipient candidates
    // if we have a record of a sent message or `last_seen` is not 0.
    // Ephemeral expiry and `delete_device_after` trash messages and drop their `from_id`.
    // The ephemeral timer change message is exempt and usually carries such a chat,
    // but `delete_device_after` has no equivalent:
    // if we only ever sent messages, now removed, and never received one,
    // the contact does not qualify as a keyupdate recipient.
    let alive_since = time().saturating_sub(KEYUPDATE_MAX_SILENCE);
    let rows = context
        .sql
        .query_map_vec(
            // The outer single-argument MAX aggregates over the contact's chats,
            // the inner multi-argument one picks the newest signal per chat.
            "SELECT c.addr, k.public_key,
                    MAX(MAX(c.last_seen,
                            CASE WHEN ch.type=? THEN 0 ELSE ch.created_timestamp END,
                            cc.add_timestamp,
                            CASE WHEN ch.type=? THEN IFNULL(
                                (SELECT MAX(m.timestamp) FROM msgs m
                                 WHERE m.chat_id=ch.id AND m.from_id=?), 0)
                            ELSE 0 END)) AS freshness
             FROM contacts c
             INNER JOIN public_keys k ON k.fingerprint=c.fingerprint
             INNER JOIN chats_contacts cc ON cc.contact_id=c.id
             INNER JOIN chats ch ON ch.id=cc.chat_id
             WHERE c.id>? AND c.fingerprint<>'' AND c.blocked=0
               AND cc.add_timestamp >= cc.remove_timestamp
               AND ch.id>? AND ch.type IN (?, ?, ?) AND ch.blocked=0
             GROUP BY c.id
             HAVING freshness>?
             ORDER BY freshness DESC
             LIMIT ?",
            (
                Chattype::Single,
                Chattype::Single,
                ContactId::SELF,
                ContactId::LAST_SPECIAL,
                ChatId::LAST_SPECIAL,
                Chattype::Single,
                Chattype::Group,
                Chattype::InBroadcast,
                alive_since,
                max_recipients,
            ),
            |row| {
                let addr: String = row.get(0)?;
                let public_key_bytes: Vec<u8> = row.get(1)?;
                Ok((addr, public_key_bytes))
            },
        )
        .await?;

    let mut recipients = Vec::with_capacity(rows.len());
    for (addr, public_key_bytes) in rows {
        let public_key = match SignedPublicKey::from_slice(&public_key_bytes) {
            Ok(public_key) => public_key,
            Err(err) => {
                warn!(context, "Cannot parse stored key for {addr:?}: {err:#}.");
                continue;
            }
        };
        if !pubkey_can_encrypt(&public_key) {
            warn!(context, "Stored key for {addr:?} cannot be encrypted to.");
            continue;
        }
        let relays = relay_addrs(&public_key, &addr);
        debug_assert!(relays.iter().all(|relay| !relay.is_empty()));
        if !relays.is_empty() {
            recipients.push(KeyupdateRecipient { relays, public_key });
        }
    }

    // Freshness decides who is informed at all, but it must not decide who shares a chunk:
    // an envelope would otherwise group contacts by how active they are.
    recipients.shuffle(&mut rand::rng());
    Ok(recipients)
}

/// Returns the deduplicated relay addresses to put into the SMTP envelope
/// for the keyupdate encrypted to a `chunk` of recipients.
fn envelope_recipients(chunk: &[KeyupdateRecipient]) -> Vec<String> {
    let mut addrs = BTreeSet::new();
    for recipient in chunk {
        for relay in &recipient.relays {
            addrs.insert(addr_normalize(relay));
        }
    }
    Vec::from_iter(addrs)
}

/// Returns the relay list in the format stored in [`Config::KeyupdateBaseline`].
async fn relays_joined(context: &Context) -> Result<String> {
    let mut relays = context.get_self_addrs().await?;
    relays.sort();
    Ok(relays.join(" "))
}

/// Schedules a check for whether a keyupdate needs sending, after the debounce period.
pub(crate) async fn schedule_keyupdate_check(context: &Context) -> Result<()> {
    let debounce = context.get_config_i64(Config::KeyupdateDebounce).await?;
    context
        .next_keyupdate_check
        .store(time().saturating_add(debounce), Ordering::Relaxed);
    Ok(())
}

/// Records the current relay list as not needing a keyupdate, see the module docs.
pub(crate) async fn set_current_relays_as_keyupdate_baseline(context: &Context) -> Result<()> {
    let current = relays_joined(context).await?;
    context
        .set_config_internal(Config::KeyupdateBaseline, Some(&current))
        .await
}

/// Sends a keyupdate message if the relay list differs from the recorded baseline.
pub(crate) async fn maybe_send_keyupdate_message(context: &Context) -> Result<()> {
    let current = relays_joined(context).await?;
    let last = context.get_config(Config::KeyupdateBaseline).await?;
    if last.unwrap_or_default() == current {
        return Ok(());
    }

    let recipients = keyupdate_recipients(context, KEYUPDATE_MAX_RECIPIENTS).await?;
    for chunk in recipients.chunks(KEYUPDATE_CHUNK_CONTACTS) {
        let envelope = envelope_recipients(chunk);
        let rfc724_mid = create_outgoing_rfc724_mid();
        let msg_id = message::insert_tombstone(context, &rfc724_mid).await?;
        let keys = chunk.iter().map(|r| r.public_key.clone()).collect();
        let queued_msg = render_keyupdate_message(context, &rfc724_mid, keys).await?;
        let now = time();
        chat::enqueue_mail(
            context,
            now,
            msg_id,
            ChatId::TRASH,
            &queued_msg,
            &Default::default(),
            &envelope,
        )
        .await?;
    }

    // Record only after queueing, so failed queueing is retried by a later check.
    context
        .set_config_internal(Config::KeyupdateBaseline, Some(&current))
        .await
}

#[cfg(test)]
mod keyupdate_tests;
