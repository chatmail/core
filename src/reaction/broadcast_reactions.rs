//! # Broadcasting Reactions.
//!
//! For broadcast channels, reactions are sent from the subscriber to the broadcast channel owner as usual.
//! The owner then remembers these changes by adding a record to `reactions_need_broadcast`,
//! and every some minutes sends an update to all subscribers.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::chat::{Chat, ChatId, send_msg};
use crate::config::Config;
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::context::Context;
use crate::log::warn;
use crate::message::{Message, MsgId, rfc724_mid_exists};
use crate::param::Param;
use crate::reaction::{Reaction, ReactionFrequency, get_msg_reactions, sort_frequencies};
use crate::tools::time;
use crate::{EventType, chatlist_events};

/// Wire format for accumulated broadcast reactions
/// (sent as JSON from broadcast channel owner to subscriber in `Chat-Broadcast-Reactions:` header)
#[derive(Debug, Serialize, Deserialize)]
struct WirePayload {
    messages: Vec<WireMessage>,
}
#[derive(Debug, Serialize, Deserialize)]
struct WireMessage {
    /// RFC 724 Message-ID.
    id: String,

    /// Array of reaction entries.
    reactions: Vec<WireEntry>,
}
#[derive(Debug, Serialize, Deserialize)]
struct WireEntry {
    emoji: String,
    count: usize,
}

/// Renders one or more message's reactions as a JSON string, ready to be sent in `Broadcast-Reactions:` header.
///
/// The returned reaction array for a message may be empty,
/// allowing to broadcast reaction removal.
pub(crate) async fn render_json(context: &Context, msg_ids: &[MsgId]) -> Result<Option<String>> {
    let mut messages: Vec<WireMessage> = Vec::new();
    for msg_id in msg_ids {
        let Some(msg) = Message::load_from_db_optional(context, *msg_id).await? else {
            continue;
        };
        let reactions = get_msg_reactions(context, *msg_id).await?;
        let entries: Vec<WireEntry> = reactions
            .frequencies
            .into_iter()
            .map(|entry| WireEntry {
                emoji: entry.reaction.as_str().to_string(),
                count: entry.count,
            })
            .collect();
        messages.push(WireMessage {
            id: msg.rfc724_mid,
            reactions: entries, // can be empty if all reactions were removed
        });
    }
    if messages.is_empty() {
        return Ok(None);
    }

    let payload = WirePayload { messages };
    let json = serde_json::to_string(&payload)?;
    Ok(Some(json))
}

/// Seconds between sending out accumulated reaction updates for broadcast channels from `reactions_need_broadcast` table
const REACTION_BROADCAST_PERIOD: i64 = 10 * 60;

/// Starts broadcasting if last broadcasting is more than `REACTION_BROADCAST_PERIOD` seconds in the past.
///
/// Moreover, also broadcast if `lst_broadcast_time` is in the future:
/// That way we're not stuck e.g. if the clock was accidentally set to one year in the future and then rewinded back.
pub(crate) async fn maybe_broadcast_reactions(context: &Context) -> Result<()> {
    let now = time();
    let last_broadcast_time = context
        .get_config_i64(Config::LastReactionsBroadcast)
        .await?;
    let next_broadcast_time = last_broadcast_time.saturating_add(REACTION_BROADCAST_PERIOD);
    if next_broadcast_time <= now || last_broadcast_time > now {
        context
            .set_config_internal(Config::LastReactionsBroadcast, Some(&now.to_string()))
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

    if let Some(json) = render_json(context, &msg_ids).await? {
        let mut reaction_msg = Message::new_text("".to_string());
        reaction_msg.set_reaction();
        reaction_msg.param.set(Param::BroadcastReactions, json);
        reaction_msg.hidden = true;
        send_msg(context, chat_id, &mut reaction_msg).await?;
    }

    context
        .sql
        .execute(
            "DELETE FROM reactions_need_broadcast WHERE chat_id=?",
            (chat_id,),
        )
        .await?;

    Ok(())
}

/// Applies incoming, accumulated reactions received via the `Chat-Broadcast-Reactions:` header
/// to the `broadcasted_reactions` table.
pub(crate) async fn receive_broadcast_reactions(context: &Context, json: &str) -> Result<()> {
    let payload: WirePayload = serde_json::from_str(json)?;

    for message in payload.messages {
        let Some(msg_id) = rfc724_mid_exists(context, &message.id).await? else {
            continue; // no need for a pending reaction, the next periodic update has the state again
        };
        let Some(msg) = Message::load_from_db_optional(context, msg_id).await? else {
            continue; // there may have been a deletion race, ignore error
        };
        let chat = match Chat::load_from_db(context, msg.chat_id).await {
            Ok(chat) => chat,
            Err(err) => {
                warn!(context, "Cannot load chat for broadcast reaction: {err}");
                continue;
            }
        };
        if chat.typ != Chattype::InBroadcast {
            continue;
        }

        let frequencies: Vec<ReactionFrequency> = message
            .reactions
            .into_iter()
            .map(|entry| ReactionFrequency {
                reaction: Reaction::new(&entry.emoji),
                count: entry.count,
                is_from_self: false, // set in refine_frequencies()
            })
            .collect();
        save_broadcast_reactions(context, msg_id, &frequencies).await?;

        context.emit_event(EventType::ReactionsChanged {
            // the event is for the subscriber, ReactionsIncoming is not needed
            chat_id: msg.chat_id,
            msg_id,
            contact_id: ContactId::UNDEFINED,
        });
        chatlist_events::emit_chatlist_item_changed(context, msg.chat_id);
    }

    Ok(())
}

/// Load broadcasted reactions from `broadcasted_reactions`.
/// This table is filled only for the broadcast channel subscribers (`Chattype::InBroadcast`),
/// by received reactions from the owner or by or temporarily add SELF-reactions.
/// In there are no broadcasted reactions, an empty array is returned.
pub(crate) async fn load_broadcast_reactions(
    context: &Context,
    msg_id: MsgId,
) -> Result<Vec<ReactionFrequency>> {
    let mut frequencies: Vec<ReactionFrequency> = context
        .sql
        .query_map_collect(
            "SELECT reaction, count FROM broadcasted_reactions WHERE msg_id=?",
            (msg_id,),
            |row| {
                let reaction: String = row.get(0)?;
                let count: i64 = row.get(1)?;
                Ok(ReactionFrequency {
                    reaction: Reaction::new(&reaction),
                    count: count as usize,
                    is_from_self: false,
                })
            },
        )
        .await?;

    sort_frequencies(&mut frequencies);
    Ok(frequencies)
}

/// Save an array of frequencies to the `broadcasted_reactions` table.
pub(crate) async fn save_broadcast_reactions(
    context: &Context,
    msg_id: MsgId,
    frequencies: &Vec<ReactionFrequency>,
) -> Result<()> {
    context
        .sql
        .transaction(move |transaction| {
            transaction.execute(
                "DELETE FROM broadcasted_reactions WHERE msg_id=?",
                (msg_id,),
            )?;
            for entry in frequencies {
                transaction.execute(
                    "INSERT INTO broadcasted_reactions (msg_id, reaction, count)
                         VALUES (?1, ?2, ?3)",
                    (msg_id, &entry.reaction.as_str(), entry.count),
                )?;
            }
            Ok(())
        })
        .await?;
    Ok(())
}

/// Modifies frequencies in-place to reflect a change in the SELF user's reaction.
///
/// This is used for immediate local feedback in `Chattype::InBroadcast` before the
/// next periodic broadcast overwrites this "dirty state".
pub(crate) fn modify_frequencies(
    frequencies: &mut Vec<ReactionFrequency>,
    old_self_reaction: Option<&Reaction>,
    new_self_reaction: &Reaction,
) {
    if let Some(old_reaction) = old_self_reaction {
        let mut remove_idx = None;
        for (idx, entry) in frequencies.iter_mut().enumerate() {
            if entry.reaction == *old_reaction {
                entry.count = entry.count.saturating_sub(1);
                if entry.count == 0 {
                    remove_idx = Some(idx);
                }
                break;
            }
        }
        if let Some(idx) = remove_idx {
            frequencies.remove(idx);
        }
    }

    if new_self_reaction.is_empty() {
        return;
    }

    if let Some(entry) = frequencies
        .iter_mut()
        .find(|e| e.reaction == *new_self_reaction)
    {
        entry.count = entry.count.saturating_add(1);
    } else {
        frequencies.push(ReactionFrequency {
            reaction: new_self_reaction.clone(),
            count: 1,
            is_from_self: false, // Will be correctly set to `true` by `refine_frequencies`
        });
    }
}

/// Merge `by_contact` status to broadcasted reaction frequencies.
pub(crate) fn refine_frequencies(
    mut broadcasted_reactions: Vec<ReactionFrequency>,
    by_contact: &BTreeMap<ContactId, Reaction>,
) -> Vec<ReactionFrequency> {
    // Add missing reactions.
    // This can happen e.g. for SELF-reactions done during offline when state of owner does not have ones yet.
    // It will repair on the next reaction broadcast, until then, the following is good enough.
    for reaction in by_contact.values() {
        if !broadcasted_reactions
            .iter()
            .any(|entry| entry.reaction == *reaction)
        {
            broadcasted_reactions.push(ReactionFrequency {
                reaction: reaction.clone(),
                count: 1,
                is_from_self: false,
            });
        }
    }

    // Mark SELF-reaction as such
    if let Some(self_reaction) = by_contact.get(&ContactId::SELF) {
        for entry in &mut broadcasted_reactions {
            entry.is_from_self = entry.reaction == *self_reaction;
        }
    }

    sort_frequencies(&mut broadcasted_reactions);
    broadcasted_reactions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::create_broadcast;
    use crate::reaction::send_reaction;
    use crate::securejoin::get_securejoin_qr;
    use crate::test_utils::TestContextManager;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_broadcast_reaction_wire_format() {
        let payload = WirePayload {
            messages: vec![
                WireMessage {
                    id: "12345678@foo".to_string(),
                    reactions: vec![
                        WireEntry {
                            emoji: "😎".to_string(),
                            count: 4,
                        },
                        WireEntry {
                            emoji: "🕺".to_string(),
                            count: 2,
                        },
                    ],
                },
                WireMessage {
                    id: "23456789@bar".to_string(),
                    reactions: vec![],
                },
            ],
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(
            json,
            r#"{"messages":[{"id":"12345678@foo","reactions":[{"emoji":"😎","count":4},{"emoji":"🕺","count":2}]},{"id":"23456789@bar","reactions":[]}]}"#
        );

        let payload: WirePayload = serde_json::from_str(&json).unwrap();
        assert_eq!(payload.messages.len(), 2);
        assert_eq!(payload.messages[0].id, "12345678@foo");
        assert_eq!(payload.messages[0].reactions.len(), 2);
        assert_eq!(payload.messages[0].reactions[0].emoji, "😎");
        assert_eq!(payload.messages[0].reactions[0].count, 4);
        assert_eq!(payload.messages[0].reactions[1].emoji, "🕺");
        assert_eq!(payload.messages[0].reactions[1].count, 2);
        assert_eq!(payload.messages[1].id, "23456789@bar");
        assert!(payload.messages[1].reactions.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_modify_frequencies() {
        // Helper to create a ReactionFrequency entry
        let freq = |emoji: &str, count: usize, is_from_self: bool| -> ReactionFrequency {
            ReactionFrequency {
                reaction: Reaction::new(emoji),
                count,
                is_from_self,
            }
        };

        // Add entry
        let mut frequencies = vec![freq("👍", 2, false)];
        let old: Option<&Reaction> = None;
        let new = Reaction::new("❤️");
        modify_frequencies(&mut frequencies, old, &new);
        assert_eq!(frequencies.len(), 2);
        assert_eq!(frequencies[0].reaction.as_str(), "👍");
        assert_eq!(frequencies[0].count, 2);
        assert_eq!(frequencies[1].reaction.as_str(), "❤️");
        assert_eq!(frequencies[1].count, 1);

        // Increase existing entry
        let mut frequencies = vec![freq("👍", 2, false)];
        let old: Option<&Reaction> = None;
        let new = Reaction::new("👍");
        modify_frequencies(&mut frequencies, old, &new);
        assert_eq!(frequencies.len(), 1);
        assert_eq!(frequencies[0].reaction.as_str(), "👍");
        assert_eq!(frequencies[0].count, 3);

        // Decreased existing entry
        let mut frequencies = vec![freq("👍", 2, false)];
        let old = Some(Reaction::new("👍"));
        let new = Reaction::new("");
        modify_frequencies(&mut frequencies, old.as_ref(), &new);
        assert_eq!(frequencies.len(), 1);
        assert_eq!(frequencies[0].reaction.as_str(), "👍");
        assert_eq!(frequencies[0].count, 1);

        // Remove existing entry
        let mut frequencies = vec![freq("👍", 1, false)];
        let old = Some(Reaction::new("👍"));
        let new = Reaction::new("");
        modify_frequencies(&mut frequencies, old.as_ref(), &new);
        assert_eq!(frequencies.len(), 0);

        // Reaction changed: old reaction removed (count was 1), new reaction added
        let mut frequencies = vec![freq("👍", 1, false), freq("❤️", 3, false)];
        let old = Some(Reaction::new("👍"));
        let new = Reaction::new("🎉");
        modify_frequencies(&mut frequencies, old.as_ref(), &new);
        assert_eq!(frequencies.len(), 2);
        assert_eq!(frequencies[0].reaction.as_str(), "❤️");
        assert_eq!(frequencies[0].count, 3);
        assert_eq!(frequencies[1].reaction.as_str(), "🎉");
        assert_eq!(frequencies[1].count, 1);

        // Reaction changed: old reaction decreased (count was 2), new reaction added
        let mut frequencies = vec![freq("👍", 2, false)];
        let old = Some(Reaction::new("👍"));
        let new = Reaction::new("🎉");
        modify_frequencies(&mut frequencies, old.as_ref(), &new);
        assert_eq!(frequencies.len(), 2);
        assert_eq!(frequencies[0].reaction.as_str(), "👍");
        assert_eq!(frequencies[0].count, 1);
        assert_eq!(frequencies[1].reaction.as_str(), "🎉");
        assert_eq!(frequencies[1].count, 1);

        // Old and new reaction are the same
        let mut frequencies = vec![freq("👍", 2, false)];
        let old = Some(Reaction::new("👍"));
        let new = Reaction::new("👍");
        modify_frequencies(&mut frequencies, old.as_ref(), &new);
        assert_eq!(frequencies.len(), 1);
        assert_eq!(frequencies[0].reaction.as_str(), "👍");
        assert_eq!(frequencies[0].count, 2);

        // Empty frequencies array, adding a new reaction
        let mut frequencies = vec![];
        let old: Option<&Reaction> = None;
        let new = Reaction::new("👍");
        modify_frequencies(&mut frequencies, old, &new);
        assert_eq!(frequencies.len(), 1);
        assert_eq!(frequencies[0].reaction.as_str(), "👍");
        assert_eq!(frequencies[0].count, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_refine_frequencies() {
        // Test for empty inputs
        let broadcasted = vec![];
        let by_contact: BTreeMap<ContactId, Reaction> = BTreeMap::new();
        let result = refine_frequencies(broadcasted, &by_contact);
        assert!(result.is_empty());

        // Test broadcasted reactions only, no by_contact reactions
        let broadcasted = vec![ReactionFrequency {
            reaction: Reaction::new("👍"),
            count: 2,
            is_from_self: false,
        }];
        let by_contact: BTreeMap<ContactId, Reaction> = BTreeMap::new();
        let result = refine_frequencies(broadcasted, &by_contact);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].reaction.as_str(), "👍");
        assert_eq!(result[0].count, 2);
        assert_eq!(result[0].is_from_self, false);

        // Test `by_contact` adding a completely new reaction not yet in `broadcasted`
        let broadcasted = vec![ReactionFrequency {
            reaction: Reaction::new("👍"),
            count: 2,
            is_from_self: false,
        }];
        let mut by_contact: BTreeMap<ContactId, Reaction> = BTreeMap::new();
        by_contact.insert(ContactId::new(10), Reaction::new("❤️"));
        let result = refine_frequencies(broadcasted, &by_contact);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].reaction.as_str(), "👍");
        assert_eq!(result[0].count, 2);
        assert_eq!(result[1].reaction.as_str(), "❤️");
        assert_eq!(result[1].count, 1);
        assert_eq!(result[1].is_from_self, false);

        // Test `by_contact` contains SELF reaction, ensuring it is marked correctly
        let broadcasted = vec![
            ReactionFrequency {
                reaction: Reaction::new("❤️"),
                count: 1,
                is_from_self: false,
            },
            ReactionFrequency {
                reaction: Reaction::new("👍"),
                count: 2,
                is_from_self: false,
            },
        ];
        let mut by_contact: BTreeMap<ContactId, Reaction> = BTreeMap::new();
        by_contact.insert(ContactId::SELF, Reaction::new("❤️"));
        let result = refine_frequencies(broadcasted, &by_contact);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].reaction.as_str(), "👍");
        assert_eq!(result[0].is_from_self, false);
        assert_eq!(result[1].reaction.as_str(), "❤️");
        assert_eq!(result[1].is_from_self, true);

        // Test `by_contact` contains a reaction already in broadcasted; count must NOT increase
        let broadcasted = vec![ReactionFrequency {
            reaction: Reaction::new("👍"),
            count: 2,
            is_from_self: false,
        }];
        let mut by_contact: BTreeMap<ContactId, Reaction> = BTreeMap::new();
        by_contact.insert(ContactId::new(10), Reaction::new("👍"));
        let result = refine_frequencies(broadcasted, &by_contact);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].reaction.as_str(), "👍");
        assert_eq!(result[0].count, 2);

        // Test scenario with multiple contacts, overlapping reactions, and SELF
        let broadcasted = vec![ReactionFrequency {
            reaction: Reaction::new("👍"),
            count: 3,
            is_from_self: false,
        }];
        let mut by_contact: BTreeMap<ContactId, Reaction> = BTreeMap::new();
        by_contact.insert(ContactId::new(11), Reaction::new("👍"));
        by_contact.insert(ContactId::SELF, Reaction::new("❤️"));
        let result = refine_frequencies(broadcasted, &by_contact);

        assert_eq!(result.len(), 2);
        assert_eq!(result[0].reaction.as_str(), "👍");
        assert_eq!(result[0].count, 3);
        assert_eq!(result[0].is_from_self, false);

        assert_eq!(result[1].reaction.as_str(), "❤️");
        assert_eq!(result[1].count, 1);
        assert_eq!(result[1].is_from_self, true);
    }

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

        // Alice broadcasts recent reaction changes to Bob and Claire.
        // On the wire, the hidden message has a header like
        // `Chat-Broadcast-Reactions: {"messages":[{"id":"123@adc","reactions":[{"emoji":"🏳️‍🌈","count":1}]}]}`
        maybe_broadcast_reactions(alice).await?;
        let sent_msg = alice.pop_sent_msg().await;
        bob.recv_msg_hidden(&sent_msg).await;
        claire.recv_msg_hidden(&sent_msg).await;

        // Check that there is nothing left for Alice to broadcast
        maybe_broadcast_reactions(alice).await?;
        broadcast_reactions_for_all_chats(alice).await?;
        assert!(alice.pop_sent_msg_opt().await.is_none());

        // Claire got the broadcasted reaction, and then reacts herself.
        // This means, her local view on reactions are a mix `broadcasted_reactions`and `reactions`.
        let reactions = get_msg_reactions(claire, claire_msg.id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈1");
        assert_eq!(reactions.frequencies.len(), 1);
        assert_eq!(reactions.by_contact.len(), 0);

        send_reaction(claire, claire_msg.id, "💪").await?;
        let reactions = get_msg_reactions(claire, claire_msg.id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈1 💪1");
        assert_eq!(reactions.frequencies.len(), 2);
        assert_eq!(reactions.frequencies[0].is_from_self, false);
        assert_eq!(reactions.frequencies[1].is_from_self, true);

        // Claire's reaction is sent to Alice who in turn broadcast it again to Bob and Claire.
        // This must not modify Claire's get_reactions() even tho the reaction is present now in `broadcasted_reactions` and `reactions`.
        let sent_msg = claire.pop_sent_msg().await;
        alice.recv_msg_hidden(&sent_msg).await;
        let reactions = get_msg_reactions(alice, alice_msg_id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈1 💪1");

        broadcast_reactions_for_all_chats(alice).await?; // bypass timer in maybe_broadcast_reactions()
        let sent_msg = alice.pop_sent_msg().await;
        bob.recv_msg_hidden(&sent_msg).await;

        claire.recv_msg_hidden(&sent_msg).await;
        let reactions = get_msg_reactions(claire, claire_msg.id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈1 💪1");
        assert_eq!(reactions.frequencies.len(), 2);
        assert_eq!(reactions.frequencies[0].is_from_self, false);
        assert_eq!(reactions.frequencies[1].is_from_self, true);

        // Claire removes her 💪 reaction, and also reactios with 🏳️‍🌈;
        // SELF-changes are immediate even tho not broadcasted yet, the bring broadcasted reactions table to a "dirty state" ...
        send_reaction(claire, claire_msg.id, "").await?;
        let sent_msg = claire.pop_sent_msg().await;
        let reactions = get_msg_reactions(claire, claire_msg.id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈1");

        send_reaction(claire, claire_msg.id, "🏳️‍🌈").await?;
        let sent_msg2 = claire.pop_sent_msg().await;
        let reactions = get_msg_reactions(claire, claire_msg.id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈2");

        // ... "dirty state" is fixed after next broadcast then, counters should stay the same
        alice.recv_msg_hidden(&sent_msg).await;
        alice.recv_msg_hidden(&sent_msg2).await;
        broadcast_reactions_for_all_chats(alice).await?; // bypass timer in maybe_broadcast_reactions()
        let sent_msg = alice.pop_sent_msg().await;
        claire.recv_msg_hidden(&sent_msg).await;
        let reactions = get_msg_reactions(claire, claire_msg.id).await?;
        assert_eq!(reactions.to_string(), "🏳️‍🌈2");

        Ok(())
    }
}
