//! Delta Chat has an advanced option
//! "Send statistics to the developers of Delta Chat".
//! If this is enabled, a JSON file with some anonymous statistics
//! will be sent to a bot once a week.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context as _, Result};
use deltachat_derive::FromSql;
use num_traits::ToPrimitive;
use pgp::types::PublicKeyTrait;
use rusqlite::OptionalExtension;
use serde::Serialize;

use crate::chat::{self, ChatId, MuteDuration};
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
const SENDING_INTERVAL_SECONDS: i64 = 3600 * 24 * 7; // 1 week
// const SENDING_INTERVAL_SECONDS: i64 = 60; // 1 minute (for testing)
const MESSAGE_STATS_UPDATE_INTERVAL_SECONDS: i64 = 4 * 60; // 4 minutes (less than the lowest ephemeral messages timeout)

#[derive(Serialize)]
struct Statistics {
    core_version: String,
    key_create_timestamps: Vec<i64>,
    stats_id: String,
    is_chatmail: bool,
    contact_stats: Vec<ContactStat>,
    message_stats: BTreeMap<Chattype, MessageStats>,
    securejoin_sources: SecurejoinSources,
    securejoin_uipaths: SecurejoinUiPaths,
    securejoin_invites: Vec<JoinedInvite>,
    sending_enabled_timestamps: Vec<i64>,
    sending_disabled_timestamps: Vec<i64>,
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

#[derive(Serialize, Default)]
struct MessageStats {
    verified: u32,
    unverified_encrypted: u32,
    unencrypted: u32,
    only_to_self: u32,
}

/// Where a securejoin invite link or QR code came from.
/// This is only used if the user enabled StatsSending.
#[repr(u32)]
#[derive(
    Debug, Clone, Copy, ToPrimitive, FromPrimitive, FromSql, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum SecurejoinSource {
    /// Because of some problem, it is unknown where the QR code came from.
    Unknown = 0,
    /// The user opened a link somewhere outside Delta Chat
    ExternalLink = 1,
    /// The user clicked on a link in a message inside Delta Chat
    InternalLink = 2,
    /// The user clicked "Paste from Clipboard" in the QR scan activity
    Clipboard = 3,
    /// The user clicked "Load QR code as image" in the QR scan activity
    ImageLoaded = 4,
    /// The user scanned a QR code
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

/// How the user opened the QR activity in order scan a QR code on Android.
/// This is only used if the user enabled StatsSending.
#[derive(
    Debug, Clone, Copy, ToPrimitive, FromPrimitive, FromSql, PartialEq, Eq, PartialOrd, Ord,
)]
pub enum SecurejoinUiPath {
    /// The UI path is unknown, or the user didn't open the QR code screen at all.
    Unknown = 0,
    /// The user directly clicked on the QR icon in the main screen
    QrIcon = 1,
    /// The user first clicked on the `+` button in the main screen,
    /// and then on "New Contact"
    NewContact = 2,
}

#[derive(Serialize)]
struct SecurejoinUiPaths {
    other: u32,
    qr_icon: u32,
    new_contact: u32,
}

/// Some information on an invite-joining event
/// (i.e. a qr scan or a clicked link).
#[derive(Serialize)]
struct JoinedInvite {
    /// Whether the contact already existed before.
    /// If this is false, then a contact was newly created.
    already_existed: bool,
    /// If a contact already existed,
    /// this tells us whether the contact was verified already.
    already_verified: bool,
    /// The type of the invite:
    /// "contact" for 1:1 invites that setup a verified contact,
    /// "group" for invites that invite to a group,
    /// "broadcast" for invites that invite to a broadcast channel.
    /// The invite also performs the contact verification 'along the way'.
    typ: String,
}

pub(crate) async fn pre_sending_config_change(
    context: &Context,
    old_value: bool,
    new_value: bool,
) -> Result<()> {
    // These functions are no-ops if they were called in the past already;
    // just call them opportunistically:
    ensure_last_old_contact_id(context).await?;
    // Make sure that StatsId is available for the UI,
    // in order to open the survey with the StatsId as a parameter:
    stats_id(context).await?;

    if old_value != new_value {
        if new_value {
            // Only count messages sent from now on:
            set_last_counted_msg_id(context).await?;
        } else {
            // Update message stats one last time in case it's enabled again in the future:
            update_message_stats(context).await?;
        }

        let sql_table = if new_value {
            "stats_sending_enabled_events"
        } else {
            "stats_sending_disabled_events"
        };

        context
            .sql
            .execute(&format!("INSERT INTO {sql_table} VALUES(?)"), (time(),))
            .await?;
    }

    Ok(())
}

/// Sends a message with statistics about the usage of Delta Chat,
/// if the last time such a message was sent
/// was more than a week ago.
///
/// On the other end, a bot will receive the message and make it available
/// to Delta Chat's developers.
pub async fn maybe_send_stats(context: &Context) -> Result<Option<ChatId>> {
    if should_send_stats(context).await?
        && time_has_passed(context, Config::StatsLastSent, SENDING_INTERVAL_SECONDS).await?
    {
        let chat_id = send_stats(context).await?;

        return Ok(Some(chat_id));
    }
    Ok(None)
}

pub(crate) async fn maybe_update_message_stats(context: &Context) -> Result<()> {
    if should_send_stats(context).await?
        && time_has_passed(
            context,
            Config::StatsLastUpdate,
            MESSAGE_STATS_UPDATE_INTERVAL_SECONDS,
        )
        .await?
    {
        update_message_stats(context).await?;
    }

    Ok(())
}

async fn time_has_passed(context: &Context, config: Config, seconds: i64) -> Result<bool> {
    let last_time = context.get_config_i64(config).await?;
    let next_time = last_time.saturating_add(seconds);

    let res = if next_time <= time() {
        // Already set the config to the current time.
        // This prevents infinite loops in the (unlikely) case of an error:
        context
            .set_config_internal(config, Some(&time().to_string()))
            .await?;
        true
    } else {
        if time() < last_time {
            // The clock was rewound.
            // Reset the config, so that the statistics will be sent normally in a week,
            // or be normally updated in a few minutes.
            context
                .set_config_internal(config, Some(&time().to_string()))
                .await?;
        }
        false
    };

    Ok(res)
}

#[allow(clippy::unused_async, unused)]
pub(crate) async fn should_send_stats(context: &Context) -> Result<bool> {
    #[cfg(any(target_os = "android", test))]
    {
        context.get_config_bool(Config::StatsSending).await
    }

    // If the user enables statistics-sending on Android,
    // and then transfers the account to e.g. Desktop,
    // we should not send any statistics:
    #[cfg(not(any(target_os = "android", test)))]
    {
        Ok(false)
    }
}

async fn send_stats(context: &Context) -> Result<ChatId> {
    info!(context, "Sending statistics.");

    update_message_stats(context).await?;

    let chat_id = get_stats_chat_id(context).await?;

    let mut msg = Message::new(Viewtype::File);
    msg.set_text(crate::stock_str::stats_msg_body(context).await);

    let stats = get_stats(context).await?;

    msg.set_file_from_bytes(
        context,
        "statistics.txt",
        stats.as_bytes(),
        Some("text/plain"),
    )?;

    chat::send_msg(context, chat_id, &mut msg)
        .await
        .context("Failed to send statistics message")
        .log_err(context)
        .ok();

    Ok(chat_id)
}

async fn set_last_counted_msg_id(context: &Context) -> Result<()> {
    context
        .sql
        .execute(
            "UPDATE stats_msgs
            SET last_counted_msg_id=(SELECT MAX(id) FROM msgs)",
            (),
        )
        .await?;

    Ok(())
}

async fn ensure_last_old_contact_id(context: &Context) -> Result<()> {
    if context.config_exists(Config::StatsLastOldContactId).await? {
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

async fn get_stats(context: &Context) -> Result<String> {
    // The Id of the last contact that already existed when the user enabled the setting.
    // Newer contacts will get the `new` flag set.
    let last_old_contact = context
        .get_config_u32(Config::StatsLastOldContactId)
        .await?;

    let key_create_timestamps: Vec<i64> = load_self_public_keyring(context)
        .await?
        .iter()
        .map(|k| k.created_at().timestamp())
        .collect();

    let sending_enabled_timestamps =
        get_timestamps(context, "stats_sending_enabled_events").await?;
    let sending_disabled_timestamps =
        get_timestamps(context, "stats_sending_disabled_events").await?;

    let stats = Statistics {
        core_version: get_version_str().to_string(),
        key_create_timestamps,
        stats_id: stats_id(context).await?,
        is_chatmail: context.is_chatmail().await?,
        contact_stats: get_contact_stats(context, last_old_contact).await?,
        message_stats: get_message_stats(context).await?,
        securejoin_sources: get_securejoin_source_stats(context).await?,
        securejoin_uipaths: get_securejoin_uipath_stats(context).await?,
        securejoin_invites: get_securejoin_invite_stats(context).await?,
        sending_enabled_timestamps,
        sending_disabled_timestamps,
    };

    Ok(serde_json::to_string_pretty(&stats)?)
}

async fn get_timestamps(context: &Context, sql_table: &str) -> Result<Vec<i64>> {
    context
        .sql
        .query_map_vec(
            &format!("SELECT timestamp FROM {sql_table} LIMIT 1000"),
            (),
            |row| row.get(0),
        )
        .await
}

pub(crate) async fn stats_id(context: &Context) -> Result<String> {
    Ok(match context.get_config(Config::StatsId).await? {
        Some(id) => id,
        None => {
            let id = create_id();
            context
                .set_config_internal(Config::StatsId, Some(&id))
                .await?;
            id
        }
    })
}

async fn get_stats_chat_id(context: &Context) -> Result<ChatId, anyhow::Error> {
    let contact_id: ContactId = *import_vcard(context, STATISTICS_BOT_VCARD)
        .await?
        .first()
        .context("Statistics bot vCard does not contain a contact")?;
    mark_contact_id_as_verified(context, contact_id, Some(ContactId::SELF)).await?;

    let chat_id = if let Some(res) = ChatId::lookup_by_contact(context, contact_id).await? {
        // Already exists, no need to create.
        res
    } else {
        let chat_id = ChatId::get_for_contact(context, contact_id).await?;
        chat::set_muted(context, chat_id, MuteDuration::Forever).await?;
        chat_id
    };

    Ok(chat_id)
}

async fn get_contact_stats(context: &Context, last_old_contact: u32) -> Result<Vec<ContactStat>> {
    let mut verified_by_map: BTreeMap<ContactId, ContactId> = BTreeMap::new();
    let mut bot_ids: BTreeSet<ContactId> = BTreeSet::new();

    let mut contacts = context
        .sql
        .query_map_vec(
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
///   If false, only messages in other chats (groups and broadcast channels) are counted.
async fn get_message_stats(context: &Context) -> Result<BTreeMap<Chattype, MessageStats>> {
    let mut map: BTreeMap<Chattype, MessageStats> = context
        .sql
        .query_map_collect(
            "SELECT chattype, verified, unverified_encrypted, unencrypted, only_to_self
            FROM stats_msgs",
            (),
            |row| {
                let chattype: Chattype = row.get(0)?;
                let verified: u32 = row.get(1)?;
                let unverified_encrypted: u32 = row.get(2)?;
                let unencrypted: u32 = row.get(3)?;
                let only_to_self: u32 = row.get(4)?;
                let message_stats = MessageStats {
                    verified,
                    unverified_encrypted,
                    unencrypted,
                    only_to_self,
                };
                Ok((chattype, message_stats))
            },
        )
        .await?;

    // Fill zeroes if a chattype wasn't present:
    for chattype in [Chattype::Group, Chattype::Single, Chattype::OutBroadcast] {
        map.entry(chattype).or_default();
    }

    Ok(map)
}

pub(crate) async fn update_message_stats(context: &Context) -> Result<()> {
    for chattype in [Chattype::Single, Chattype::Group, Chattype::OutBroadcast] {
        update_message_stats_inner(context, chattype).await?;
    }
    context
        .set_config_internal(Config::StatsLastUpdate, Some(&time().to_string()))
        .await?;
    Ok(())
}

async fn update_message_stats_inner(context: &Context, chattype: Chattype) -> Result<()> {
    let stats_bot_chat_id = get_stats_chat_id(context).await?;

    let trans_fn = |t: &mut rusqlite::Transaction| {
        // The ID of the last msg that was already counted in the previously sent stats.
        // Only newer messages will be counted in the current statistics.
        let last_counted_msg_id: u32 = t
            .query_row(
                "SELECT last_counted_msg_id FROM stats_msgs WHERE chattype=?",
                (chattype,),
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        t.execute(
            "UPDATE stats_msgs
            SET last_counted_msg_id=(SELECT MAX(id) FROM msgs)
            WHERE chattype=?",
            (chattype,),
        )?;

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
            "CREATE TEMP TABLE temp.chat_with_correct_type (
                id INTEGER PRIMARY KEY
            ) STRICT",
            (),
        )?;

        t.execute(
            "INSERT INTO temp.chat_with_correct_type
            SELECT id FROM chats
            WHERE type=?;",
            (chattype,),
        )?;

        // - `from_id=?` is to count only outgoing messages.
        // - `chat_id<>?` excludes the chat with the statistics bot itself,
        // - `id>?` excludes messages that were already counted in the previously sent statistics, or messages sent before the config was enabled
        // - `hidden=0` excludes hidden system messages, which are not actually shown to the user.
        //   Note that reactions are also not counted as a message.
        // - `chat_id>9` excludes messages in the 'Trash' chat, which is an internal chat assigned to messages that are not shown to the user
        let general_requirements = "id>? AND from_id=? AND chat_id<>?
            AND hidden=0 AND chat_id>9 AND chat_id IN temp.chat_with_correct_type"
            .to_string();
        let params = (last_counted_msg_id, ContactId::SELF, stats_bot_chat_id);

        let verified: u32 = t.query_row(
            &format!(
                "SELECT COUNT(*) FROM msgs
                WHERE chat_id IN temp.verified_chats
                AND {general_requirements}"
            ),
            params,
            |row| row.get(0),
        )?;

        let unverified_encrypted: u32 = t.query_row(
            &format!(
                // (param GLOB '*\nc=1*' OR param GLOB 'c=1*') matches all messages that are end-to-end encrypted
                "SELECT COUNT(*) FROM msgs
                WHERE chat_id NOT IN temp.verified_chats AND chat_id NOT IN temp.empty_chats
                AND (param GLOB '*\nc=1*' OR param GLOB 'c=1*')
                AND {general_requirements}"
            ),
            params,
            |row| row.get(0),
        )?;

        let unencrypted: u32 = t.query_row(
            &format!(
                "SELECT COUNT(*) FROM msgs
                WHERE chat_id NOT IN temp.verified_chats AND chat_id NOT IN temp.empty_chats
                AND NOT (param GLOB '*\nc=1*' OR param GLOB 'c=1*')
                AND {general_requirements}"
            ),
            params,
            |row| row.get(0),
        )?;

        let only_to_self: u32 = t.query_row(
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
        t.execute("DROP TABLE temp.chat_with_correct_type", ())?;

        t.execute(
            "INSERT INTO stats_msgs(chattype) VALUES (?)
            ON CONFLICT(chattype) DO NOTHING",
            (chattype,),
        )?;
        t.execute(
            "UPDATE stats_msgs SET
            verified=verified+?,
            unverified_encrypted=unverified_encrypted+?,
            unencrypted=unencrypted+?,
            only_to_self=only_to_self+?
            WHERE chattype=?",
            (
                verified,
                unverified_encrypted,
                unencrypted,
                only_to_self,
                chattype,
            ),
        )?;

        Ok(())
    };

    context.sql.transaction(trans_fn).await?;

    Ok(())
}

pub(crate) async fn count_securejoin_ux_info(
    context: &Context,
    source: Option<SecurejoinSource>,
    uipath: Option<SecurejoinUiPath>,
) -> Result<()> {
    if !should_send_stats(context).await? {
        return Ok(());
    }

    let source = source
        .context("Missing securejoin source")
        .log_err(context)
        .unwrap_or(SecurejoinSource::Unknown);

    // We only get a UI path if the source is a QR code scan,
    // a loaded image, or a link pasted from the QR code,
    // so, no need to log an error if `uipath` is None:
    let uipath = uipath.unwrap_or(SecurejoinUiPath::Unknown);

    context
        .sql
        .transaction(|conn| {
            conn.execute(
                "INSERT INTO stats_securejoin_sources VALUES (?, 1)
                ON CONFLICT (source) DO UPDATE SET count=count+1;",
                (source.to_u32(),),
            )?;

            conn.execute(
                "INSERT INTO stats_securejoin_uipaths VALUES (?, 1)
                ON CONFLICT (uipath) DO UPDATE SET count=count+1;",
                (uipath.to_u32(),),
            )?;
            Ok(())
        })
        .await?;

    Ok(())
}

async fn get_securejoin_source_stats(context: &Context) -> Result<SecurejoinSources> {
    let map: BTreeMap<SecurejoinSource, u32> = context
        .sql
        .query_map_collect(
            "SELECT source, count FROM stats_securejoin_sources",
            (),
            |row| {
                let source: SecurejoinSource = row.get(0)?;
                let count: u32 = row.get(1)?;
                Ok((source, count))
            },
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

async fn get_securejoin_uipath_stats(context: &Context) -> Result<SecurejoinUiPaths> {
    let map: BTreeMap<SecurejoinUiPath, u32> = context
        .sql
        .query_map_collect(
            "SELECT uipath, count FROM stats_securejoin_uipaths",
            (),
            |row| {
                let uipath: SecurejoinUiPath = row.get(0)?;
                let count: u32 = row.get(1)?;
                Ok((uipath, count))
            },
        )
        .await?;

    let stats = SecurejoinUiPaths {
        other: *map.get(&SecurejoinUiPath::Unknown).unwrap_or(&0),
        qr_icon: *map.get(&SecurejoinUiPath::QrIcon).unwrap_or(&0),
        new_contact: *map.get(&SecurejoinUiPath::NewContact).unwrap_or(&0),
    };

    Ok(stats)
}

pub(crate) async fn count_securejoin_invite(context: &Context, invite: &QrInvite) -> Result<()> {
    if !should_send_stats(context).await? {
        return Ok(());
    }

    let contact = Contact::get_by_id(context, invite.contact_id()).await?;

    // If the contact was created just now by the QR code scan,
    // (or if a contact existed in the database
    // but it was not visible in the contacts list in the UI
    // e.g. because it's a past contact of a group we're in),
    // then its origin is UnhandledSecurejoinQrScan.
    let already_existed = contact.origin > Origin::UnhandledSecurejoinQrScan;

    // Check whether the contact was verified already before the QR scan.
    let already_verified = contact.is_verified(context).await?;

    let typ = match invite {
        QrInvite::Contact { .. } => "contact",
        QrInvite::Group { .. } => "group",
        QrInvite::Broadcast { .. } => "broadcast",
    };

    context
        .sql
        .execute(
            "INSERT INTO stats_securejoin_invites (already_existed, already_verified, type)
            VALUES (?, ?, ?)",
            (already_existed, already_verified, typ),
        )
        .await?;

    Ok(())
}

async fn get_securejoin_invite_stats(context: &Context) -> Result<Vec<JoinedInvite>> {
    context
        .sql
        .query_map_vec(
            "SELECT already_existed, already_verified, type FROM stats_securejoin_invites",
            (),
            |row| {
                let already_existed: bool = row.get(0)?;
                let already_verified: bool = row.get(1)?;
                let typ: String = row.get(2)?;

                Ok(JoinedInvite {
                    already_existed,
                    already_verified,
                    typ,
                })
            },
        )
        .await
}

#[cfg(test)]
mod stats_tests;
