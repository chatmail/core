//! TODO doc comment

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Context as _, Result};
use pgp::types::PublicKeyTrait;
use serde::Serialize;

use crate::chat::{self, ChatId, ChatVisibility, MuteDuration, ProtectionStatus};
use crate::config::Config;
use crate::constants::{Chattype, DC_CHAT_ID_TRASH};
use crate::contact::{import_vcard, mark_contact_id_as_verified, ContactId, Origin};
use crate::context::{get_version_str, Context};
use crate::download::DownloadState;
use crate::key::load_self_public_key;
use crate::log::LogExt;
use crate::message::{Message, Viewtype};
use crate::param::{Param, Params};
use crate::tools::{create_id, time};

pub(crate) const SELF_REPORTING_BOT_EMAIL: &str = "self_reporting@testrun.org";
const SELF_REPORTING_BOT_VCARD: &str = include_str!("../assets/self-reporting-bot.vcf");

#[derive(Serialize)]
struct Statistics {
    core_version: String,
    num_msgs: u32,
    num_chats: u32,
    db_size: u64,
    key_created: i64,
    chat_numbers: ChatNumbers,
    self_reporting_id: String,
    contact_stats: Vec<ContactStat>,
    message_stats: MessageStats,
}
#[derive(Default, Serialize)]
struct ChatNumbers {
    protected: u32,
    protection_broken: u32,
    opportunistic_dc: u32,
    opportunistic_mua: u32,
    unencrypted_dc: u32,
    unencrypted_mua: u32,
}

#[derive(Serialize, PartialEq)]
enum VerifiedStatus {
    Direct,
    Transitive,
    TransitiveViaBot,
    Opportunistic,
    Unencrypted,
}

#[derive(Serialize)]
struct ContactStat {
    #[serde(skip_serializing)]
    id: ContactId,

    verified: VerifiedStatus,
    bot: bool,
    direct_chat: bool,
    last_seen: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    transitive_chain: Option<u32>,
    //new: bool, // TODO
}

async fn get_contact_stats(context: &Context) -> Result<Vec<ContactStat>> {
    let mut verified_by_map: BTreeMap<ContactId, ContactId> = BTreeMap::new();
    let mut bot_ids: BTreeSet<ContactId> = BTreeSet::new();

    let mut contacts: Vec<ContactStat> = context
        .sql
        .query_map(
            "SELECT id, fingerprint<>'', verifier, last_seen, is_bot FROM contacts c
            WHERE id>9 AND origin>? AND addr<>?",
            (Origin::Hidden, SELF_REPORTING_BOT_EMAIL),
            |row| {
                let id = row.get(0)?;
                let is_encrypted: bool = row.get(1)?;
                let verifier: ContactId = row.get(2)?;
                let last_seen: u64 = row.get(3)?;
                let bot: bool = row.get(4)?;

                let verified = match (is_encrypted, verifier) {
                    (true, ContactId::SELF) => VerifiedStatus::Direct,
                    (true, ContactId::UNDEFINED) => VerifiedStatus::Opportunistic,
                    (true, _) => VerifiedStatus::Transitive, // TransitiveViaBot will be filled later
                    (false, _) => VerifiedStatus::Unencrypted,
                };

                if verifier != ContactId::UNDEFINED {
                    verified_by_map.insert(id, verifier);
                }

                if bot {
                    bot_ids.insert(id);
                }

                Ok(ContactStat {
                    id,
                    verified,
                    bot,
                    direct_chat: false, // will be filled later
                    last_seen,
                    transitive_chain: None, // will be filled later
                })
            },
            |rows| {
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            },
        )
        .await?;

    // Fill TransitiveViaBot and transitive_chain
    for contact in contacts.iter_mut() {
        if contact.verified == VerifiedStatus::Transitive {
            let mut transitive_chain: u32 = 0;
            let mut has_bot = false;
            let mut current_verifier_id = contact.id;

            while current_verifier_id != ContactId::SELF {
                current_verifier_id = match verified_by_map.get(&current_verifier_id) {
                    Some(id) => *id,
                    None => {
                        // The chain ends here, probably because some verification was done
                        // before we started recording verifiers.
                        // It's unclear how long the chain really is.
                        transitive_chain = 0;
                        break;
                    }
                };
                if bot_ids.contains(&current_verifier_id) {
                    has_bot = true;
                }
                transitive_chain = transitive_chain.saturating_add(1);
            }

            if transitive_chain > 0 {
                contact.transitive_chain = Some(transitive_chain);
            }

            if has_bot {
                contact.verified = VerifiedStatus::TransitiveViaBot;
            }
        }
    }

    // Fill direct_chat
    for contact in contacts.iter_mut() {
        let direct_chat = context
            .sql
            .exists(
                "SELECT COUNT(*)
            FROM chats_contacts cc INNER JOIN chats
            WHERE cc.contact_id=? AND chats.type=?",
                (contact.id, Chattype::Single),
            )
            .await?;
        contact.direct_chat = direct_chat;
    }

    Ok(contacts)
}

#[derive(Serialize)]
struct MessageStats {
    to_verified: u32,
    unverified_encrypted: u32,
    unencrypted: u32,
}

async fn get_message_stats(context: &Context) -> Result<MessageStats> {
    let enabled_ts: i64 = context
        .get_config_i64(Config::SelfReportingEnabledTimestamp)
        .await?;
    ensure!(enabled_ts > 0, "Enabled Timestamp missing");

    let selfreporting_bot_chat_id = get_selfreporting_bot(context).await?;

    let trans_fn = |t: &mut rusqlite::Transaction| {
        t.pragma_update(None, "query_only", "0")?;
        t.execute(
            "CREATE TEMP TABLE temp.verified_chats (
                id INTEGER PRIMARY KEY
            ) STRICT",
            (),
        )?;

        t.execute(
            "INSERT INTO temp.verified_chats
            SELECT id FROM chats
            WHERE protected=1 AND id>9",
            (),
        )?;

        let to_verified = t.query_row(
            "SELECT COUNT(*) FROM msgs
            WHERE chat_id IN temp.verified_chats
            AND chat_id<>? AND id>9 AND timestamp_sent>?",
            (selfreporting_bot_chat_id, enabled_ts),
            |row| row.get(0),
        )?;

        let unverified_encrypted = t.query_row(
            "SELECT COUNT(*) FROM msgs
            WHERE chat_id not IN temp.verified_chats
            AND (param GLOB '*\nc=1*' OR param GLOB 'c=1*')
            AND chat_id<>? AND id>9 AND timestamp_sent>?",
            (selfreporting_bot_chat_id, enabled_ts),
            |row| row.get(0),
        )?;

        let unencrypted = t.query_row(
            "SELECT COUNT(*) FROM msgs
            WHERE chat_id not IN temp.verified_chats
            AND NOT (param GLOB '*\nc=1*' OR param GLOB 'c=1*')
            AND chat_id<>? AND id>9 AND timestamp_sent>=?",
            (selfreporting_bot_chat_id, enabled_ts),
            |row| row.get(0),
        )?;

        t.execute("DROP TABLE temp.verified_chats", ())?;

        Ok(MessageStats {
            to_verified,
            unverified_encrypted,
            unencrypted,
        })
    };

    let query_only = true;
    let message_stats: MessageStats = context.sql.transaction_ex(query_only, trans_fn).await?;

    Ok(message_stats)
}

/// Sends a message with statistics about the usage of Delta Chat,
/// if the last time such a message was sent
/// was more than a week ago.
///
/// On the other end, a bot will receive the message and make it available
/// to Delta Chat's developers.
pub async fn maybe_send_self_report(context: &Context) -> Result<Option<ChatId>> {
    //#[cfg(target_os = "android")] TODO
    if context.get_config_bool(Config::SelfReporting).await? {
        let last_selfreport_time = context.get_config_i64(Config::LastSelfReportSent).await?;
        let next_selfreport_time = last_selfreport_time.saturating_add(30); // TODO increase to 1 day or 1 week
        if next_selfreport_time <= time() {
            return Ok(Some(send_self_report(context).await?));
        }
    }
    Ok(None)
}

async fn send_self_report(context: &Context) -> Result<ChatId> {
    info!(context, "Sending self report.");
    // Setting this config at the beginning avoids endless loops when things do not
    // work out for whatever reason.
    context
        .set_config_internal(Config::LastSelfReportSent, Some(&time().to_string()))
        .await
        .log_err(context)
        .ok();

    let chat_id = get_selfreporting_bot(context).await?;

    let mut msg = Message::new(Viewtype::File);
    msg.set_text(
        "The attachment contains anonymous usage statistics, \
because you enabled this in the settings. \
This helps us improve the security of Delta Chat. \
See TODO[blog post] for more information."
            .to_string(),
    );
    msg.set_file_from_bytes(
        context,
        "statistics.txt",
        get_self_report(context).await?.as_bytes(),
        Some("text/plain"),
    )?;

    crate::chat::send_msg(context, chat_id, &mut msg)
        .await
        .context("Failed to send self_reporting message")
        .log_err(context)
        .ok();

    Ok(chat_id)
}

async fn get_selfreporting_bot(context: &Context) -> Result<ChatId, anyhow::Error> {
    let contact_id: ContactId = *import_vcard(context, SELF_REPORTING_BOT_VCARD)
        .await?
        .first()
        .context("Self reporting bot vCard does not contain a contact")?;
    mark_contact_id_as_verified(context, contact_id, ContactId::SELF).await?;

    let chat_id = if let Some(res) = ChatId::lookup_by_contact(context, contact_id).await? {
        // Already exists, no need to create.
        res
    } else {
        let chat_id = ChatId::get_for_contact(context, contact_id).await?;
        chat_id
            .set_visibility(context, ChatVisibility::Archived)
            .await?;
        chat::set_muted(context, chat_id, MuteDuration::Forever).await?;
        chat_id
    };

    chat_id
        .set_protection(
            context,
            ProtectionStatus::Protected,
            time(),
            Some(contact_id),
        )
        .await?;

    Ok(chat_id)
}

async fn get_self_report(context: &Context) -> Result<String> {
    let num_msgs: u32 = context
        .sql
        .query_get_value(
            "SELECT COUNT(*) FROM msgs WHERE hidden=0 AND chat_id!=?",
            (DC_CHAT_ID_TRASH,),
        )
        .await?
        .unwrap_or_default();

    let num_chats: u32 = context
        .sql
        .query_get_value("SELECT COUNT(*) FROM chats WHERE id>9 AND blocked!=1", ())
        .await?
        .unwrap_or_default();

    let db_size = tokio::fs::metadata(&context.sql.dbfile).await?.len();

    let key_created = load_self_public_key(context)
        .await?
        .primary_key
        .created_at()
        .timestamp();

    // how many of the chats active in the last months are:
    // - protected
    // - protection-broken
    // - opportunistic-encrypted and the contact uses Delta Chat
    // - opportunistic-encrypted and the contact uses a classical MUA
    // - unencrypted and the contact uses Delta Chat
    // - unencrypted and the contact uses a classical MUA
    let three_months_ago = time().saturating_sub(3600 * 24 * 30 * 3);
    let chat_numbers = context
        .sql
        .query_map(
            "SELECT c.protected, m.param, m.msgrmsg
                    FROM chats c
                    JOIN msgs m
                        ON c.id=m.chat_id
                        AND m.id=(
                                SELECT id
                                FROM msgs
                                WHERE chat_id=c.id
                                AND hidden=0
                                AND download_state=?
                                AND to_id!=?
                                ORDER BY timestamp DESC, id DESC LIMIT 1)
                    WHERE c.id>9
                    AND (c.blocked=0 OR c.blocked=2)
                    AND IFNULL(m.timestamp,c.created_timestamp) > ?
                    GROUP BY c.id",
            (DownloadState::Done, ContactId::INFO, three_months_ago),
            |row| {
                let protected: ProtectionStatus = row.get(0)?;
                let message_param: Params = row.get::<_, String>(1)?.parse().unwrap_or_default();
                let is_dc_message: bool = row.get(2)?;
                Ok((protected, message_param, is_dc_message))
            },
            |rows| {
                let mut chats = ChatNumbers::default();
                for row in rows {
                    let (protected, message_param, is_dc_message) = row?;
                    let encrypted = message_param
                        .get_bool(Param::GuaranteeE2ee)
                        .unwrap_or(false);

                    if protected == ProtectionStatus::Protected {
                        chats.protected += 1;
                    } else if protected == ProtectionStatus::ProtectionBroken {
                        chats.protection_broken += 1;
                    } else if encrypted {
                        if is_dc_message {
                            chats.opportunistic_dc += 1;
                        } else {
                            chats.opportunistic_mua += 1;
                        }
                    } else if is_dc_message {
                        chats.unencrypted_dc += 1;
                    } else {
                        chats.unencrypted_mua += 1;
                    }
                }
                Ok(chats)
            },
        )
        .await?;

    let self_reporting_id = match context.get_config(Config::SelfReportingId).await? {
        Some(id) => id,
        None => {
            let id = create_id();
            context
                .set_config_internal(Config::SelfReportingId, Some(&id))
                .await?;
            id
        }
    };
    let statistics = Statistics {
        core_version: get_version_str().to_string(),
        num_msgs,
        num_chats,
        db_size,
        key_created,
        chat_numbers,
        self_reporting_id,
        contact_stats: get_contact_stats(context).await?,
        message_stats: get_message_stats(context).await?,
    };

    Ok(serde_json::to_string_pretty(&statistics)?)
}

#[cfg(test)]
mod self_reporting_tests;
