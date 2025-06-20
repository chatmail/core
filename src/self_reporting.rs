//! TODO doc comment

use anyhow::{Context as _, Result};
use pgp::types::PublicKeyTrait;
use serde::Serialize;

use crate::chat::{self, ChatId, ChatVisibility, MuteDuration, ProtectionStatus};
use crate::config::Config;
use crate::constants::DC_CHAT_ID_TRASH;
use crate::contact::{import_vcard, mark_contact_id_as_verified, ContactId};
use crate::context::{get_version_str, Context};
use crate::download::DownloadState;
use crate::key::load_self_public_key;
use crate::log::LogExt;
use crate::message::{Message, Viewtype};
use crate::param::{Param, Params};
use crate::tools::{create_id, time};

#[derive(Serialize)]
struct Statistics {
    core_version: String,
    num_msgs: u32,
    num_chats: u32,
    db_size: u64,
    key_created: i64,
    chat_numbers: ChatNumbers,
    self_reporting_id: String,
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

pub async fn maybe_send_self_report(context: &Context) -> Result<()> {
    //#[cfg(target_os = "android")] TODO
    if context.get_config_bool(Config::SelfReporting).await? {
        match context.get_config_i64(Config::LastSelfReportSent).await {
            Ok(last_selfreport_time) => {
                let next_selfreport_time = last_selfreport_time.saturating_add(30); // TODO increase to 1 day or 1 week
                if next_selfreport_time <= time() {
                    send_self_report(context).await?;
                }
            }
            Err(err) => {
                warn!(context, "Failed to get last self_reporting time: {}", err);
            }
        }
    }
    Ok(())
}

/// Drafts a message with statistics about the usage of Delta Chat.
/// The user can inspect the message if they want, and then hit "Send".
///
/// On the other end, a bot will receive the message and make it available
/// to Delta Chat's developers.
async fn send_self_report(context: &Context) -> Result<ChatId> {
    info!(context, "Sending self report.");
    // Setting `Config::LastHousekeeping` at the beginning avoids endless loops when things do not
    // work out for whatever reason or are interrupted by the OS.
    context
        .set_config_internal(Config::LastSelfReportSent, Some(&time().to_string()))
        .await
        .log_err(context)
        .ok();

    const SELF_REPORTING_BOT_VCARD: &str = include_str!("../assets/self-reporting-bot.vcf");
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
    };

    Ok(serde_json::to_string_pretty(&statistics)?)
}

#[cfg(test)]
mod self_reporting_tests {
    use anyhow::Context as _;
    use strum::IntoEnumIterator;
    use tempfile::tempdir;

    use super::*;
    use crate::chat::{get_chat_contacts, get_chat_msgs, send_msg, set_muted, Chat, MuteDuration};
    use crate::chatlist::Chatlist;
    use crate::constants::Chattype;
    use crate::mimeparser::SystemMessage;
    use crate::receive_imf::receive_imf;
    use crate::test_utils::{get_chat_msg, TestContext};
    use crate::tools::{create_outgoing_rfc724_mid, SystemTime};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_draft_self_report() -> Result<()> {
        let alice = TestContext::new_alice().await;

        let chat_id = send_self_report(&alice).await?;
        let msg = get_chat_msg(&alice, chat_id, 0, 2).await;
        assert_eq!(msg.get_info_type(), SystemMessage::ChatProtectionEnabled);

        let chat = Chat::load_from_db(&alice, chat_id).await?;
        assert!(chat.is_protected());

        let statistics_msg = get_chat_msg(&alice, chat_id, 1, 2).await;
        assert_eq!(statistics_msg.get_filename().unwrap(), "statistics.txt");

        Ok(())
    }
}
