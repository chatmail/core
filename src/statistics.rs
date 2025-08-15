//! Delta Chat has an advanced option
//! "Send statistics to the developers of Delta Chat".
//! If this is enabled, a JSON file with some anonymous statistics
//! will be sent to a bot once a week.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result, ensure};
use deltachat_derive::FromSql;
use pgp::types::PublicKeyTrait;
use serde::Serialize;

use crate::chat::{self, ChatId, ChatVisibility, MuteDuration, ProtectionStatus};
use crate::config::Config;
use crate::constants::Chattype;
use crate::contact::{Contact, ContactId, Origin, import_vcard, mark_contact_id_as_verified};
use crate::context::{Context, get_version_str};
use crate::key::load_self_public_keyring;
use crate::log::LogExt;
use crate::message::{Message, Viewtype};
use crate::securejoin::QrInvite;
use crate::tools::{create_id, time};

pub(crate) const STATISTICS_BOT_EMAIL: &str = "self_reporting@testrun.org";
const STATISTICS_BOT_VCARD: &str = include_str!("../assets/statistics-bot.vcf");

#[derive(Serialize)]
struct Statistics {
    core_version: String,
    key_created: Vec<i64>,
    statistics_id: String,
    is_chatmail: bool,
    contact_stats: Vec<ContactStat>,
    message_stats_one_one: MessageStats,
    message_stats_multi_user: MessageStats,
    securejoin_sources: SecurejoinSources,
    securejoin_uipaths: SecurejoinUIPaths,
    securejoin_invites: Vec<JoinedInvite>,
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

    // If one of the boolean properties is false,
    // we leave them away.
    // This way, the Json file becomes a lot smaller.
    #[serde(skip_serializing_if = "is_false")]
    bot: bool,

    #[serde(skip_serializing_if = "is_false")]
    direct_chat: bool,

    last_seen: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    transitive_chain: Option<u32>,

    /// Whether the contact was established after stats-sending was enabled
    #[serde(skip_serializing_if = "is_false")]
    new: bool,
}

fn is_false(b: &bool) -> bool {
    !b
}

#[derive(Serialize)]
struct MessageStats {
    to_verified: u32,
    unverified_encrypted: u32,
    unencrypted: u32,
    only_to_self: u32,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, FromPrimitive, FromSql, PartialEq, Eq, PartialOrd, Ord)]
enum SecurejoinSource {
    Unknown = 0,
    ExternalLink = 1,
    InternalLink = 2,
    Clipboard = 3,
    ImageLoaded = 4,
    Scan = 5,
}

#[derive(Serialize)]
struct SecurejoinSources {
    unknown: u32,
    external_link: u32,
    internal_link: u32,
    clipboard: u32,
    image_loaded: u32,
    scan: u32,
}

#[derive(Debug, Clone, Copy, FromPrimitive, FromSql, PartialEq, Eq, PartialOrd, Ord)]
enum SecurejoinUIPath {
    Unknown = 0,
    QrIcon = 1,
    NewContact = 2,
}

#[derive(Serialize)]
struct SecurejoinUIPaths {
    other: u32,
    qr_icon: u32,
    new_contact: u32,
}

/// Sends a message with statistics about the usage of Delta Chat,
/// if the last time such a message was sent
/// was more than a week ago.
///
/// On the other end, a bot will receive the message and make it available
/// to Delta Chat's developers.
pub async fn maybe_send_statistics(context: &Context) -> Result<Option<ChatId>> {
    if context.get_config_bool(Config::SendStatistics).await? {
        let last_sending_time = context.get_config_i64(Config::LastStatisticsSent).await?;
        let next_sending_time = last_sending_time.saturating_add(30); // TODO increase to 1 day or 1 week
        if next_sending_time <= time() {
            return Ok(Some(send_statistics(context).await?));
        }
    }
    Ok(None)
}

async fn send_statistics(context: &Context) -> Result<ChatId> {
    info!(context, "Sending statistics.");

    // Setting this config at the beginning avoids endless loops when things do not
    // work out for whatever reason.
    context
        .set_config_internal(Config::LastStatisticsSent, Some(&time().to_string()))
        .await
        .log_err(context)
        .ok();

    let chat_id = get_statistics_bot(context).await?;

    let mut msg = Message::new(Viewtype::File);
    msg.set_text(
        "The attachment contains anonymous usage statistics, \
because you enabled this in the settings. \
This helps us improve the security of Delta Chat. \
See TODO[blog post] for more information."
            .to_string(),
    );

    let statistics = get_statistics(context).await?;

    msg.set_file_from_bytes(
        context,
        "statistics.txt",
        statistics.as_bytes(),
        Some("text/plain"),
    )?;

    chat::send_msg(context, chat_id, &mut msg)
        .await
        .context("Failed to send statistics message")
        .log_err(context)
        .ok();

    set_last_excluded_msg_id(context).await?;

    Ok(chat_id)
}

pub(crate) async fn set_last_excluded_msg_id(context: &Context) -> Result<()> {
    let last_msgid: u64 = context
        .sql
        .query_get_value("SELECT MAX(id) FROM msgs", ())
        .await?
        .unwrap_or(0);

    context
        .sql
        .set_raw_config(
            Config::StatsLastExcludedMsgId.as_ref(),
            Some(&last_msgid.to_string()),
        )
        .await?;

    Ok(())
}

pub(crate) async fn set_last_old_contact_id(context: &Context) -> Result<()> {
    let config_exists = context
        .sql
        .get_raw_config(Config::StatsLastOldContactId.as_ref())
        .await?
        .is_some();
    if config_exists {
        // The user had statistics-sending enabled already in the past,
        // keep the 'last old contact id' as-is
        return Ok(());
    }

    let last_contact_id: u64 = context
        .sql
        .query_get_value("SELECT MAX(id) FROM contacts", ())
        .await?
        .unwrap_or(0);

    context
        .sql
        .set_raw_config(
            Config::StatsLastOldContactId.as_ref(),
            Some(&last_contact_id.to_string()),
        )
        .await?;

    Ok(())
}

async fn get_statistics(context: &Context) -> Result<String> {
    // The ID of the last msg that was already counted in the previously sent statistics.
    // Only newer messages will be counted in the current statistics.
    let last_excluded_msg = context
        .get_config_u32(Config::StatsLastExcludedMsgId)
        .await?;

    // The Id of the last contact that already existed when the user enabled the setting.
    // Newer contacts will get the `new` flag set.
    let last_old_contact = context
        .get_config_u32(Config::StatsLastOldContactId)
        .await?;

    let key_created: Vec<i64> = load_self_public_keyring(context)
        .await?
        .iter()
        .map(|k| k.created_at().timestamp())
        .collect();

    let statistics_id = match context.get_config(Config::StatisticsId).await? {
        Some(id) => id,
        None => {
            let id = create_id();
            context
                .set_config_internal(Config::StatisticsId, Some(&id))
                .await?;
            id
        }
    };

    let statistics = Statistics {
        core_version: get_version_str().to_string(),
        key_created,
        statistics_id,
        is_chatmail: context.is_chatmail().await?,
        contact_stats: get_contact_stats(context, last_old_contact).await?,
        message_stats_one_one: get_message_stats(context, last_excluded_msg, true).await?,
        message_stats_multi_user: get_message_stats(context, last_excluded_msg, false).await?,
        securejoin_sources: get_securejoin_source_stats(context).await?,
        securejoin_uipaths: get_securejoin_uipath_stats(context).await?,
        securejoin_invites: get_securejoin_invite_stats(context).await?,
    };

    Ok(serde_json::to_string_pretty(&statistics)?)
}

async fn get_statistics_bot(context: &Context) -> Result<ChatId, anyhow::Error> {
    let contact_id: ContactId = *import_vcard(context, STATISTICS_BOT_VCARD)
        .await?
        .first()
        .context("Statistics bot vCard does not contain a contact")?;
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

async fn get_contact_stats(context: &Context, last_old_contact: u32) -> Result<Vec<ContactStat>> {
    let mut verified_by_map: BTreeMap<ContactId, ContactId> = BTreeMap::new();
    let mut bot_ids: BTreeSet<ContactId> = BTreeSet::new();

    let mut contacts: Vec<ContactStat> = context
        .sql
        .query_map(
            "SELECT id, fingerprint<>'', verifier, last_seen, is_bot FROM contacts c
            WHERE id>9 AND origin>? AND addr<>?",
            (Origin::Hidden, STATISTICS_BOT_EMAIL),
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
                    new: id.to_u32() > last_old_contact,
                })
            },
            |rows| {
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            },
        )
        .await?;

    // Fill TransitiveViaBot and transitive_chain
    for contact in &mut contacts {
        if contact.verified == VerifiedStatus::Transitive {
            let mut transitive_chain: u32 = 0;
            let mut has_bot = false;
            let mut current_verifier_id = contact.id;

            while current_verifier_id != ContactId::SELF && transitive_chain < 100 {
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
    for contact in &mut contacts {
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

/// - `last_msg_id`: The last msg_id that was already counted in the previous stats.
///   Only messages newer than that will be counted.
/// - `one_one_chats`: If true, only messages in 1:1 chats are counted.
///    If false, only messages in other chats (groups and broadcast channels) are counted.
async fn get_message_stats(
    context: &Context,
    last_excluded_msg: u32,
    one_one_chats: bool,
) -> Result<MessageStats> {
    ensure!(
        last_excluded_msg >= 9,
        "Last_msgid < 9 would mean including 'special' messages in the statistics"
    );

    let statistics_bot_chat_id = get_statistics_bot(context).await?;

    let trans_fn = |t: &mut rusqlite::Transaction| {
        t.pragma_update(None, "query_only", "0")?;

        // This table will hold all empty chats,
        // i.e. all chats that do not contain any members except for self.
        // Messages in these chats are not actually sent out.
        t.execute(
            "CREATE TEMP TABLE temp.empty_chats (
                id INTEGER PRIMARY KEY
            ) STRICT",
            (),
        )?;

        // id>9 because chat ids 0..9 are "special" chats like the trash chat,
        // and contact ids 0..9 are "special" contact ids like the 'device'.
        t.execute(
            "INSERT INTO temp.empty_chats
            SELECT id FROM chats
            WHERE id>9 AND NOT EXISTS(
                SELECT *
                FROM contacts, chats_contacts
                WHERE chats_contacts.contact_id=contacts.id AND chats_contacts.chat_id=chats.id
				AND contacts.id>9
            )",
            (),
        )?;

        // This table will hold all verified chats,
        // i.e. all chats that only contain verified contacts.
        t.execute(
            "CREATE TEMP TABLE temp.verified_chats (
                id INTEGER PRIMARY KEY
            ) STRICT",
            (),
        )?;

        // Verified chats are chats that are not empty,
        // and do not contain any unverified contacts
        t.execute(
            "INSERT INTO temp.verified_chats
            SELECT id FROM chats
            WHERE id>9
            AND id NOT IN (SELECT id FROM temp.empty_chats)
            AND NOT EXISTS(
                SELECT *
                FROM contacts, chats_contacts
                WHERE chats_contacts.contact_id=contacts.id AND chats_contacts.chat_id=chats.id
				AND contacts.id>9
				AND contacts.verifier=0
            )",
            (),
        )?;

        // This table will hold all 1:1 chats.
        t.execute(
            "CREATE TEMP TABLE temp.one_one_chats (
                id INTEGER PRIMARY KEY
            ) STRICT",
            (),
        )?;

        t.execute(
            "INSERT INTO temp.one_one_chats
            SELECT id FROM chats
            WHERE type=?;",
            (Chattype::Single,),
        )?;

        // - `from_id=?` is to count only outgoing messages.
        // - `chat_id<>?` excludes the chat with the statistics bot itself,
        // - `id>?` excludes messages that were already counted in the previously sent statistics, or messages sent before the config was enabled
        // - `hidden=0` excludes hidden system messages, which are not actually shown to the user
        // - `chat_id>9` excludes messages in the 'Trash' chat, which is an internal chat assigned to messages that are not shown to the user
        let mut general_requirements =
            "from_id=? AND chat_id<>? AND id>? AND hidden=0 AND chat_id>9".to_string();
        if one_one_chats {
            general_requirements += " AND chat_id IN temp.one_one_chats";
        } else {
            general_requirements += " AND chat_id NOT IN temp.one_one_chats";
        }
        let params = (ContactId::SELF, statistics_bot_chat_id, last_excluded_msg);

        let to_verified = t.query_row(
            &format!(
                "SELECT COUNT(*) FROM msgs
                WHERE chat_id IN temp.verified_chats
                AND {general_requirements}"
            ),
            params,
            |row| row.get(0),
        )?;

        let unverified_encrypted = t.query_row(
            &format!(
                // (param GLOB '*\nc=1*' OR param GLOB 'c=1*')`
                // matches all messages that are end-to-end encrypted
                "SELECT COUNT(*) FROM msgs
                WHERE chat_id NOT IN temp.verified_chats AND chat_id NOT IN temp.empty_chats
                AND (param GLOB '*\nc=1*' OR param GLOB 'c=1*')
                AND {general_requirements}"
            ),
            params,
            |row| row.get(0),
        )?;

        let unencrypted = t.query_row(
            &format!(
                "SELECT COUNT(*) FROM msgs
                WHERE chat_id NOT IN temp.verified_chats AND chat_id NOT IN temp.empty_chats
                AND NOT (param GLOB '*\nc=1*' OR param GLOB 'c=1*')
                AND {general_requirements}"
            ),
            params,
            |row| row.get(0),
        )?;

        let only_to_self = t.query_row(
            &format!(
                "SELECT COUNT(*) FROM msgs
                WHERE chat_id IN temp.empty_chats
                AND {general_requirements}"
            ),
            params,
            |row| row.get(0),
        )?;

        t.execute("DROP TABLE temp.verified_chats", ())?;
        t.execute("DROP TABLE temp.empty_chats", ())?;
        t.execute("DROP TABLE temp.one_one_chats", ())?;

        Ok(MessageStats {
            to_verified,
            unverified_encrypted,
            unencrypted,
            only_to_self,
        })
    };

    let query_only = true;
    let message_stats: MessageStats = context.sql.transaction_ex(query_only, trans_fn).await?;

    Ok(message_stats)
}

pub(crate) async fn count_securejoin_source(
    context: &Context,
    source: Option<u32>,
    uipath: Option<u32>,
) -> Result<()> {
    if !context.get_config_bool(Config::SendStatistics).await? {
        return Ok(());
    }

    let source = source
        .context("Missing securejoin source")
        .log_err(context)
        .unwrap_or(0);

    context
        .sql
        .execute(
            "INSERT INTO statistics_securejoin_sources VALUES (?, 1)
                ON CONFLICT (source) DO UPDATE SET count=count+1;",
            (source,),
        )
        .await?;

    // We only get a UI path if the source is a QR code scan,
    // a loaded image, or a link pasted from the QR code,
    // so, no need to log an error if `uipath` is None:
    let uipath = uipath.unwrap_or(0);
    context
        .sql
        .execute(
            "INSERT INTO statistics_securejoin_uipaths VALUES (?, 1)
                ON CONFLICT (uipath) DO UPDATE SET count=count+1;",
            (uipath,),
        )
        .await?;
    Ok(())
}

async fn get_securejoin_source_stats(context: &Context) -> Result<SecurejoinSources> {
    let map = context
        .sql
        .query_map(
            "SELECT source, count FROM statistics_securejoin_sources",
            (),
            |row| {
                let source: SecurejoinSource = row.get(0)?;
                let count: u32 = row.get(1)?;
                Ok((source, count))
            },
            |rows| Ok(rows.collect::<rusqlite::Result<BTreeMap<_, _>>>()?),
        )
        .await?;

    let stats = SecurejoinSources {
        unknown: *map.get(&SecurejoinSource::Unknown).unwrap_or(&0),
        external_link: *map.get(&SecurejoinSource::ExternalLink).unwrap_or(&0),
        internal_link: *map.get(&SecurejoinSource::InternalLink).unwrap_or(&0),
        clipboard: *map.get(&SecurejoinSource::Clipboard).unwrap_or(&0),
        image_loaded: *map.get(&SecurejoinSource::ImageLoaded).unwrap_or(&0),
        scan: *map.get(&SecurejoinSource::Scan).unwrap_or(&0),
    };

    Ok(stats)
}

async fn get_securejoin_uipath_stats(context: &Context) -> Result<SecurejoinUIPaths> {
    let map = context
        .sql
        .query_map(
            "SELECT uipath, count FROM statistics_securejoin_uipaths",
            (),
            |row| {
                let uipath: SecurejoinUIPath = row.get(0)?;
                let count: u32 = row.get(1)?;
                Ok((uipath, count))
            },
            |rows| Ok(rows.collect::<rusqlite::Result<BTreeMap<_, _>>>()?),
        )
        .await?;

    let stats = SecurejoinUIPaths {
        other: *map.get(&SecurejoinUIPath::Unknown).unwrap_or(&0),
        qr_icon: *map.get(&SecurejoinUIPath::QrIcon).unwrap_or(&0),
        new_contact: *map.get(&SecurejoinUIPath::NewContact).unwrap_or(&0),
    };

    Ok(stats)
}

pub(crate) async fn count_securejoin_invite(context: &Context, invite: &QrInvite) -> Result<()> {
    if !context.get_config_bool(Config::SendStatistics).await? {
        return Ok(());
    }

    let contact = Contact::get_by_id(context, invite.contact_id()).await?;

    // If the contact was created just now by the QR code scan,
    // (or if a contact existed in the database
    // but it was not visible in the contacts list in the UI
    // e.g. because it's a past contact of a group we're in),
    // then its origin is UnhandledSecurejoinQrScan.
    let contact_created = contact.origin == Origin::UnhandledSecurejoinQrScan;

    // Check whether the contact was verified already before the QR scan.
    let already_verified = contact.is_verified(context).await?;

    let typ = match invite {
        QrInvite::Contact { .. } => "contact",
        QrInvite::Group { .. } => "group",
    };

    context
        .sql
        .execute(
            "INSERT INTO statistics_securejoin_invites (contact_created, already_verified, type)
            VALUES (?, ?, ?)",
            (contact_created, already_verified, typ),
        )
        .await?;

    Ok(())
}

/// Some information on an invite-joining event
/// (i.e. a qr scan or a clicked link).
#[derive(Serialize)]
struct JoinedInvite {
    /// Whether the contact was newly created right now.
    /// If this is false, then a contact existed already before.
    contact_created: bool,
    /// If a contact already existed,
    /// this tells us whether the contact was verified already.
    already_verified: bool,
    /// The type of the invite:
    /// "contact" for 1:1 invites that setup a verified contact,
    /// "group" for invites that invite to a group
    /// and also perform the contact verification 'along the way'.
    typ: String,
}

async fn get_securejoin_invite_stats(context: &Context) -> Result<Vec<JoinedInvite>> {
    let qr_scans: Vec<JoinedInvite> = context
        .sql
        .query_map(
            "SELECT contact_created, already_verified, type FROM statistics_securejoin_invites",
            (),
            |row| {
                let contact_created: bool = row.get(0)?;
                let already_verified: bool = row.get(1)?;
                let typ: String = row.get(2)?;

                Ok(JoinedInvite {
                    contact_created,
                    already_verified,
                    typ,
                })
            },
            |rows| {
                rows.collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(Into::into)
            },
        )
        .await?;

    Ok(qr_scans)
}

#[cfg(test)]
mod statistics_tests;
