use std::collections::BTreeMap;

use deltachat::contact::ContactId;
use deltachat::reaction::Reactions;
use serde::Serialize;
use typescript_type_def::TypeDef;

/// A single reaction emoji.
#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "Reaction", rename_all = "camelCase")]
pub struct JsonrpcReaction {
    /// Emoji.
    emoji: String,

    /// Emoji frequency.
    count: usize,

    /// True if we reacted with this emoji.
    is_from_self: bool,
}

/// Structure representing all reactions to a particular message.
#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "Reactions", rename_all = "camelCase")]
pub struct JsonrpcReactions {
    /// Map from a contact to it's reaction to message.
    reactions_by_contact: BTreeMap<u32, Vec<String>>,
    /// Unique reactions and their count, sorted in descending order.
    reactions: Vec<JsonrpcReaction>,
}

impl From<Reactions> for JsonrpcReactions {
    fn from(reactions: Reactions) -> Self {
        let mut reactions_by_contact: BTreeMap<u32, Vec<String>> = BTreeMap::new();

        for contact_id in reactions.contacts() {
            let reaction = reactions.get(contact_id);
            if reaction.is_empty() {
                continue;
            }
            let emojis: Vec<String> = reaction
                .emojis()
                .into_iter()
                .map(|emoji| emoji.to_owned())
                .collect();
            reactions_by_contact.insert(contact_id.to_u32(), emojis.clone());
        }

        let self_reactions = reactions_by_contact.get(&ContactId::SELF.to_u32());

        let mut reactions_v = Vec::new();
        for (emoji, count) in reactions.emoji_sorted_by_frequency() {
            let is_from_self = if let Some(self_reactions) = self_reactions {
                self_reactions.contains(&emoji)
            } else {
                false
            };

            let reaction = JsonrpcReaction {
                emoji,
                count,
                is_from_self,
            };
            reactions_v.push(reaction)
        }

        JsonrpcReactions {
            reactions_by_contact,
            reactions: reactions_v,
        }
    }
}
