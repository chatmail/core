//! # Broadcasting Reactions.
//!
//! For broadcast channels, reactions are sent from the subscriber to the broadcast channel owner as usual.
//! The owner then remembers these changes by adding a record to `reactions_need_broadcast`,
//! and every some minutes sends an update to all subscribers.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::chat::{ChatId, send_msg};
use crate::config::Config;
use crate::context::Context;
use crate::log::warn;
use crate::message::{Message, MsgId};
use crate::reaction::get_msg_reactions;
use crate::tools::time;

// Wire format for accumulated reactions
#[derive(Debug, Serialize, Deserialize)]
struct BroadcastReactionsPayload {
    messages: Vec<BroadcastReactionsMessage>,
}
#[derive(Debug, Serialize, Deserialize)]
struct BroadcastReactionsMessage {
    id: String,
    reactions: Vec<BroadcastReactionsEntry>,
}
#[derive(Debug, Serialize, Deserialize)]
struct BroadcastReactionsEntry {
    emoji: String,
    count: usize,
}

// Seconds between sending out accumulated reaction updates for broadcast channels from `reactions_need_broadcast` table
const REACTION_BROADCAST_PERIOD: i64 = 10 * 60;

/// Starts broadcasting if last broadcasting so more than `REACTION_BROADCAST_PERIOD` seconds in the past.
pub(crate) async fn maybe_broadcast_reactions(context: &Context) -> Result<()> {
    let last_broadcast_time = context
        .get_config_i64(Config::LastReactionsBroadcast)
        .await?;
    let next_broadcast_time = last_broadcast_time.saturating_add(REACTION_BROADCAST_PERIOD);
    if next_broadcast_time <= time() {
        context
            .set_config_internal(Config::LastReactionsBroadcast, Some(&time().to_string()))
            .await?;
        broadcast_reactions_for_all_chats(context).await?;
    }
    Ok(())
}

/// Sends out accumulated reactions
/// for all broadcast channels with reactions in `reactions_need_broadcast`.
///
/// For every affected `chat_id`,
/// a single hidden message is sent to all subscribers containing the full, current reaction state (not a diff)
/// for every message that received a reaction change since the last broadcast.
async fn broadcast_reactions_for_all_chats(context: &Context) -> Result<()> {
    let chat_ids: Vec<ChatId> = context
        .sql
        .query_map_collect(
            "SELECT DISTINCT chat_id FROM reactions_need_broadcast",
            (),
            |row| {
                let chat_id: ChatId = row.get(0)?;
                Ok(chat_id)
            },
        )
        .await?;

    for chat_id in chat_ids {
        if let Err(err) = broadcast_reactions_for_one_chat(context, chat_id).await {
            warn!(
                context,
                "Failed to broadcast reactions for chat {chat_id}: {err:#}."
            );
        }
    }
    Ok(())
}

/// Sends out accumulated reactions for a single broadcast channel
async fn broadcast_reactions_for_one_chat(context: &Context, chat_id: ChatId) -> Result<()> {
    let msg_ids: Vec<MsgId> = context
        .sql
        .query_map_collect(
            "SELECT DISTINCT msg_id FROM reactions_need_broadcast WHERE chat_id=?",
            (chat_id,),
            |row| {
                let msg_id: MsgId = row.get(0)?;
                Ok(msg_id)
            },
        )
        .await?;

    context
        .sql
        .execute(
            "DELETE FROM reactions_need_broadcast WHERE chat_id=?",
            (chat_id,),
        )
        .await?;

    let mut messages: Vec<BroadcastReactionsMessage> = Vec::new();
    for msg_id in &msg_ids {
        let Some(msg) = Message::load_from_db_optional(context, *msg_id).await? else {
            continue;
        };
        let reactions = get_msg_reactions(context, *msg_id).await?;
        let entries: Vec<BroadcastReactionsEntry> = reactions
            .emoji_sorted_by_frequency()
            .into_iter()
            .map(|(emoji, count)| BroadcastReactionsEntry { emoji, count })
            .collect();
        messages.push(BroadcastReactionsMessage {
            id: msg.rfc724_mid,
            reactions: entries, // can be empty if all reactions were removed
        });
    }
    if messages.is_empty() {
        return Ok(());
    }

    let payload = BroadcastReactionsPayload { messages };
    let json = serde_json::to_string(&payload)?;
    let mut reaction_msg = Message::new_text(json); // TOOD: maybe json is better put to the header
    reaction_msg.set_reaction();
    reaction_msg.hidden = true;
    send_msg(context, chat_id, &mut reaction_msg).await?;

    Ok(())
}
