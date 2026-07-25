//! # Broadcasting Reactions.
//!
//! For broadcast channels, reactions are sent from the subscriber to the broadcast channel owner as usual.
//! The owner then remembers these changes by adding a record to `reactions_need_broadcast`,
//! and every some minutes sends an update to all subscribers.

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::EventType;
use crate::chat::{Chat, ChatId, send_msg};
use crate::config::Config;
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::context::Context;
use crate::log::warn;
use crate::message::{Message, MsgId, rfc724_mid_exists};
use crate::param::Param;
use crate::reaction::get_msg_reactions;
use crate::tools::time;

/// Wire format for accumulated reactions
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

/// Seconds between sending out accumulated reaction updates for broadcast channels from `reactions_need_broadcast` table
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
            .frequencies
            .into_iter()
            .map(|entry| BroadcastReactionsEntry {
                emoji: entry.reaction.as_str().to_string(),
                count: entry.count,
            })
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
    let mut reaction_msg = Message::new_text("".to_string());
    reaction_msg.set_reaction();
    reaction_msg.param.set(Param::BroadcastReactions, json);
    reaction_msg.hidden = true;
    send_msg(context, chat_id, &mut reaction_msg).await?;

    Ok(())
}

/// Applies incoming, accumulated reactions received via the `Broadcast-Reactions:` header
/// to the `reactions_accumulated` table.
pub(crate) async fn receive_broadcast_reactions(context: &Context, json: &str) -> Result<()> {
    let payload: BroadcastReactionsPayload = serde_json::from_str(json)?;

    for message in payload.messages {
        let Some(msg_id) = rfc724_mid_exists(context, &message.id).await? else {
            continue; // no need for a pending reaction, the next periodic update has the state again
        };
        let Some(msg) = Message::load_from_db_optional(context, msg_id).await? else {
            continue; // there may have been a deletion race, ignore error
        };
        let Ok(chat) = Chat::load_from_db(context, msg.chat_id).await else {
            continue; // there may have been a deletion race, ignore error
        };
        if chat.typ != Chattype::InBroadcast {
            continue;
        }

        context
            .sql
            .transaction(move |transaction| {
                transaction.execute(
                    "DELETE FROM reactions_accumulated WHERE msg_id=?",
                    (msg_id,),
                )?;
                for entry in &message.reactions {
                    transaction.execute(
                        "INSERT INTO reactions_accumulated (msg_id, reaction, count)
                         VALUES (?1, ?2, ?3)",
                        (msg_id, &entry.emoji, entry.count),
                    )?;
                }
                Ok(())
            })
            .await?;

        context.emit_event(EventType::ReactionsChanged {
            // the event is for the subscriber, ReactionsIncoming is not needed
            chat_id: msg.chat_id,
            msg_id: msg_id,
            contact_id: ContactId::UNDEFINED,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::create_broadcast;
    use crate::reaction::send_reaction;
    use crate::securejoin::get_securejoin_qr;
    use crate::test_utils::TestContextManager;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_broadcast_channel_reaction() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let claire = &tcm.charlie().await;

        // Alice creates a channel
        let alice_chat_id = create_broadcast(alice, "Channel".to_string()).await?;
        let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await?;

        // Bob and claire join the channel via QR code
        let bob_chat_id = tcm.exec_securejoin_qr(bob, alice, &qr).await;
        bob_chat_id.accept(bob).await?;
        let claire_chat_id = tcm.exec_securejoin_qr(claire, alice, &qr).await;
        claire_chat_id.accept(claire).await?;

        // Alice sends a message to the channel
        let sent_msg = alice.send_text(alice_chat_id, "hi channel!").await;
        let alice_msg_id = sent_msg.load_from_db().await.id;

        // Bob and Claire receive the message
        let bob_msg = bob.recv_msg(&sent_msg).await;
        let claire_msg = claire.recv_msg(&sent_msg).await;
        assert_eq!(bob_msg.get_text(), "hi channel!");
        assert_eq!(claire_msg.get_text(), "hi channel!");

        // Bob reacts to the message
        send_reaction(bob, bob_msg.id, "🏳️‍🌈").await?;
        let sent_msg = bob.pop_sent_msg().await;
        let reactions = get_msg_reactions(bob, bob_msg.id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈1");

        // Alice receives Bob's reaction
        alice.recv_msg_hidden(&sent_msg).await;
        let reactions = get_msg_reactions(alice, alice_msg_id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈1");
        assert_eq!(
            alice
                .sql
                .count("SELECT COUNT(*) FROM reactions_need_broadcast", ())
                .await?,
            1
        );

        // Alice broadcasts reaction to Claire
        // On the wire, the hidden message has a header like
        // `Broadcast-Reactions: {"messages":[{"id":"123@adc","reactions":[{"emoji":"🏳️‍🌈","count":1}]}]}`
        maybe_broadcast_reactions(alice).await?;
        assert_eq!(
            alice
                .sql
                .count("SELECT COUNT(*) FROM reactions_need_broadcast", ())
                .await?,
            0
        );
        let sent_msg = alice.pop_sent_msg().await;
        claire.recv_msg_hidden(&sent_msg).await;
        assert_eq!(
            claire
                .sql
                .count("SELECT COUNT(*) FROM reactions_accumulated", ())
                .await?,
            1
        );

        Ok(())
    }
}
