//! # Keyupdate messages.
//!
//! Keyupdates keep chats connected when relays are added or removed,
//! by hand today, by automatic relay management later.
//! Contacts learn our relay list only from messages carrying our key,
//! so without keyupdates, the next message of a "mutually silent" contact
//! might go to relays that we no longer read.
//! Reliable keyupdates could also speed up recovery from wider-scale network degradation.
//!
//! When the published relay list changes,
//! key-contacts are informed with a keyupdate message:
//! one broadcast for all contacts, symmetrically encrypted with a secret
//! derived from the own key (`pgp::keyupdate_secret`),
//! carrying the re-signed key with its current relay list
//! and the protected header `Chat-Content: key-update` ([`render_keyupdate_message`]).
//! Receivers trial-decrypt it (`decrypt::try_decrypt_with_keyupdate_secret`),
//! apply the key on the normal Autocrypt path
//! and only then trash the message without updating the sender's `last_seen`.
//! Replaying an old keyupdate cannot revert a relay list,
//! because certificate merging keeps the newest direct key signature.
//!
//! Recipients are the unblocked key-contacts that are members of an accepted chat
//! ([`keyupdate_recipients`]), leaving out (potentially many)
//! subscribers of our own broadcast channels unless they are in a chat too.
//!
//! Incoming keyupdates are accepted from any unblocked key-contact
//! without checking any further chat state (contact request etc.):
//! a stale relay list is worth updating in any case,
//! with certificate merging being the final cryptographic guardian.
//!
//! Sending policy:
//!
//! - A transport change only schedules a check ([`schedule_keyupdate_check`]),
//!   setting a deadline that each further change pushes,
//!   debouncing several changes into a single keyupdate message.
//!
//! - The SMTP loop sends once the deadline passed and its queue is drained,
//!   so real messages are never delayed and a keyupdate is only attempted
//!   when the loop is ready to send: never during send-failure backoff.
//!
//! - Sending is driven by a diff: a keyupdate is due only while the published
//!   relay list differs from the recorded [`Config::KeyupdateBaseline`].
//!   A migration seeds it, so upgrading alone pushes no keyupdate messages.
//!
//! - Only the device where the change originated sends keyupdates:
//!   devices applying a multi-device sync changing the relay list
//!   record the new list as baseline without sending
//!   ([`set_current_relays_as_keyupdate_baseline`]),
//!   which also prevents devices catching up on old sync messages
//!   from sending historical states.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;

use anyhow::Result;
use deltachat_contact_tools::addr_normalize;

use crate::config::Config;
use crate::constants::{Chattype, DC_CHAT_ID_LAST_SPECIAL};
use crate::contact::ContactId;
use crate::context::Context;
use crate::key::{DcKey, SignedPublicKey};
use crate::message::insert_tombstone;
use crate::mimefactory::render_keyupdate_message;
use crate::pgp::relay_addrs;
use crate::smtp::insert_into_smtp;
use crate::tools::{create_outgoing_rfc724_mid, time};

/// Delay after a transport change, so that one automatic relay addition run yields one message.
const KEYUPDATE_DEBOUNCE_SECONDS: i64 = 30;

/// Returns deduplicated relay addresses of the key-contacts to inform,
/// see the module docs for the criteria.
async fn keyupdate_recipients(context: &Context) -> Result<Vec<String>> {
    // Deliberately not narrowed further: selecting by 1:1 chats or by activity
    // may disclose to the relays which contacts are close ones,
    // and we want to ensure chat connectivity also between "mutually silent" contacts.
    let rows = context
        .sql
        .query_map_vec(
            "SELECT c.addr, k.public_key
             FROM contacts c
             LEFT JOIN public_keys k ON k.fingerprint=c.fingerprint
             WHERE c.id>? AND c.fingerprint<>'' AND c.blocked=0
               AND EXISTS (
                   SELECT 1 FROM chats_contacts cc
                   INNER JOIN chats ch ON ch.id=cc.chat_id
                   WHERE cc.contact_id=c.id AND cc.add_timestamp >= cc.remove_timestamp
                     AND ch.id>? AND ch.type IN (?, ?, ?) AND ch.blocked=0
               )",
            (
                ContactId::LAST_SPECIAL,
                DC_CHAT_ID_LAST_SPECIAL,
                Chattype::Single,
                Chattype::Group,
                Chattype::InBroadcast,
            ),
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .await?;

    let mut recipients = BTreeMap::new();
    for (addr, public_key) in rows {
        let public_key = public_key.and_then(|bytes| SignedPublicKey::from_slice(&bytes).ok());
        for relay in relay_addrs(public_key.as_ref(), &addr) {
            if !relay.is_empty() {
                recipients.entry(addr_normalize(&relay)).or_insert(relay);
            }
        }
    }
    Ok(recipients.into_values().collect())
}

/// Returns the published relay list in the format stored in [`Config::KeyupdateBaseline`].
async fn published_relays_joined(context: &Context) -> Result<String> {
    let mut relays = context.get_published_self_addrs().await?;
    relays.sort();
    Ok(relays.join(","))
}

/// Schedules a check for whether a keyupdate needs sending, after the debounce period.
pub(crate) fn schedule_keyupdate_check(context: &Context) {
    context.keyupdate_check_deadline.store(
        time().saturating_add(KEYUPDATE_DEBOUNCE_SECONDS),
        Ordering::Relaxed,
    );
}

/// Records the currently published relay list as not needing a keyupdate, see the module docs.
pub(crate) async fn set_current_relays_as_keyupdate_baseline(context: &Context) -> Result<()> {
    let current = published_relays_joined(context).await?;
    context
        .set_config_internal(Config::KeyupdateBaseline, Some(&current))
        .await
}

/// Sends a keyupdate message if the published relay list differs from the recorded baseline.
pub(crate) async fn maybe_send_keyupdate_message(context: &Context) -> Result<()> {
    let current = published_relays_joined(context).await?;
    let last = context.get_config(Config::KeyupdateBaseline).await?;
    if last.unwrap_or_default() == current {
        return Ok(());
    }

    let recipients = keyupdate_recipients(context).await?.join(" ");
    if !recipients.is_empty() {
        let rfc724_mid = create_outgoing_rfc724_mid();
        let rendered_message = render_keyupdate_message(context, &rfc724_mid).await?;
        let msg_id = insert_tombstone(context, &rfc724_mid).await?;
        insert_into_smtp(context, &rfc724_mid, &recipients, rendered_message, msg_id).await?;
        context.scheduler.interrupt_smtp().await;
    }

    // Record only after queueing, so failed queueing is retried by a later check.
    context
        .set_config_internal(Config::KeyupdateBaseline, Some(&current))
        .await
}

#[cfg(test)]
mod keyupdate_tests;
