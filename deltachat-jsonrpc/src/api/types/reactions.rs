use std::collections::BTreeMap;

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
    /// There is only a single reaction per contact,
    /// but this contains a list of reactions for historical reasons.
    reactions_by_contact: BTreeMap<u32, Vec<String>>,
    /// Unique reactions and their count, sorted in descending order.
    reactions: Vec<JsonrpcReaction>,
}

impl From<Reactions> for JsonrpcReactions {
    fn from(reactions: Reactions) -> Self {
        let reactions_by_contact: BTreeMap<u32, Vec<String>> = reactions
            .by_contact
            .iter()
            .map(|(key, value)| (key.to_u32(), vec![value.as_str().to_string()]))
            .collect();

        let reactions = reactions
            .frequencies
            .into_iter()
            .map(|entry| JsonrpcReaction {
                emoji: entry.reaction.as_str().to_string(),
                count: entry.count,
                is_from_self: entry.is_from_self,
            })
            .collect();

        JsonrpcReactions {
            reactions_by_contact,
            reactions,
        }
    }
}
