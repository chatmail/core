use std::time::{Duration, SystemTime};

use anyhow::{bail, Context as _, Result};
use deltachat::chat::{self, get_chat_contacts, get_past_chat_contacts, ChatVisibility};
use deltachat::chat::{Chat, ChatId};
use deltachat::constants::Chattype;
use deltachat::contact::{Contact, ContactId};
use deltachat::context::Context;
use serde::{Deserialize, Serialize};
use typescript_type_def::TypeDef;

use super::color_int_to_hex_string;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FullChat {
    id: u32,
    name: String,

    /// True if the chat is encrypted.
    /// This means that all messages in the chat are encrypted,
    /// and all contacts in the chat are "key-contacts",
    /// i.e. identified by the PGP key fingerprint.
    ///
    /// False if the chat is unencrypted.
    /// This means that all messages in the chat are unencrypted,
    /// and all contacts in the chat are "address-contacts",
    /// i.e. identified by the email address.
    /// The UI should mark this chat e.g. with a mail-letter icon.
    ///
    /// Unencrypted groups are called "ad-hoc groups"
    /// and the user can't add/remove members,
    /// create a QR invite code,
    /// or set an avatar.
    /// These options should therefore be disabled in the UI.
    ///
    /// Note that it can happen that an encrypted chat
    /// contains unencrypted messages that were received in core <= v1.159.*
    /// and vice versa.
    ///
    /// See also `is_key_contact` on `Contact`.
    is_encrypted: bool,
    profile_image: Option<String>, //BLOBS ?
    archived: bool,
    pinned: bool,
    // subtitle  - will be moved to frontend because it uses translation functions
    chat_type: JsonrpcChatType,
    is_unpromoted: bool,
    is_self_talk: bool,
    contact_ids: Vec<u32>,

    /// Contact IDs of the past chat members.
    past_contact_ids: Vec<u32>,

    color: String,
    fresh_message_counter: usize,
    // is_group - please check over chat.type in frontend instead
    is_contact_request: bool,

    is_device_chat: bool,
    /// Note that this is different from
    /// [`ChatListItem::is_self_in_group`](`crate::api::types::chat_list::ChatListItemFetchResult::ChatListItem::is_self_in_group`).
    /// This property should only be accessed
    /// when [`FullChat::chat_type`] is [`Chattype::Group`].
    //
    // We could utilize [`Chat::is_self_in_chat`],
    // but that would be an extra DB query.
    self_in_group: bool,
    is_muted: bool,
    ephemeral_timer: u32,
    can_send: bool,
    was_seen_recently: bool,
    mailing_list_address: Option<String>,
}

impl FullChat {
    pub async fn try_from_dc_chat_id(context: &Context, chat_id: u32) -> Result<Self> {
        let rust_chat_id = ChatId::new(chat_id);
        let chat = Chat::load_from_db(context, rust_chat_id).await?;

        let contact_ids = get_chat_contacts(context, rust_chat_id).await?;
        let past_contact_ids = get_past_chat_contacts(context, rust_chat_id).await?;

        let profile_image = match chat.get_profile_image(context).await? {
            Some(path_buf) => path_buf.to_str().map(|s| s.to_owned()),
            None => None,
        };

        let color = color_int_to_hex_string(chat.get_color(context).await?);
        let fresh_message_counter = rust_chat_id.get_fresh_msg_cnt(context).await?;
        let ephemeral_timer = rust_chat_id.get_ephemeral_timer(context).await?.to_u32();

        let can_send = chat.can_send(context).await?;

        let was_seen_recently = if chat.get_type() == Chattype::Single {
            match contact_ids.first() {
                Some(contact) => Contact::get_by_id(context, *contact)
                    .await
                    .context("failed to load contact for was_seen_recently")?
                    .was_seen_recently(),
                None => false,
            }
        } else {
            false
        };

        let mailing_list_address = chat.get_mailinglist_addr().map(|s| s.to_string());

        Ok(FullChat {
            id: chat_id,
            name: chat.name.clone(),
            is_encrypted: chat.is_encrypted(context).await?,
            profile_image, //BLOBS ?
            archived: chat.get_visibility() == chat::ChatVisibility::Archived,
            pinned: chat.get_visibility() == chat::ChatVisibility::Pinned,
            chat_type: chat.get_type().into(),
            is_unpromoted: chat.is_unpromoted(),
            is_self_talk: chat.is_self_talk(),
            contact_ids: contact_ids.iter().map(|id| id.to_u32()).collect(),
            past_contact_ids: past_contact_ids.iter().map(|id| id.to_u32()).collect(),
            color,
            fresh_message_counter,
            is_contact_request: chat.is_contact_request(),
            is_device_chat: chat.is_device_talk(),
            self_in_group: contact_ids.contains(&ContactId::SELF),
            is_muted: chat.is_muted(),
            ephemeral_timer,
            can_send,
            was_seen_recently,
            mailing_list_address,
        })
    }
}

/// cheaper version of fullchat, omits:
/// - contact_ids
/// - fresh_message_counter
/// - ephemeral_timer
/// - self_in_group
/// - was_seen_recently
/// - can_send
///
/// used when you only need the basic metadata of a chat like type, name, profile picture
#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BasicChat {
    id: u32,
    name: String,

    /// True if the chat is encrypted.
    /// This means that all messages in the chat are encrypted,
    /// and all contacts in the chat are "key-contacts",
    /// i.e. identified by the PGP key fingerprint.
    ///
    /// False if the chat is unencrypted.
    /// This means that all messages in the chat are unencrypted,
    /// and all contacts in the chat are "address-contacts",
    /// i.e. identified by the email address.
    /// The UI should mark this chat e.g. with a mail-letter icon.
    ///
    /// Unencrypted groups are called "ad-hoc groups"
    /// and the user can't add/remove members,
    /// create a QR invite code,
    /// or set an avatar.
    /// These options should therefore be disabled in the UI.
    ///
    /// Note that it can happen that an encrypted chat
    /// contains unencrypted messages that were received in core <= v1.159.*
    /// and vice versa.
    ///
    /// See also `is_key_contact` on `Contact`.
    is_encrypted: bool,
    profile_image: Option<String>, //BLOBS ?
    archived: bool,
    pinned: bool,
    chat_type: JsonrpcChatType,
    is_unpromoted: bool,
    is_self_talk: bool,
    color: String,
    is_contact_request: bool,

    is_device_chat: bool,
    is_muted: bool,
}

impl BasicChat {
    pub async fn try_from_dc_chat_id(context: &Context, chat_id: u32) -> Result<Self> {
        let rust_chat_id = ChatId::new(chat_id);
        let chat = Chat::load_from_db(context, rust_chat_id).await?;

        let profile_image = match chat.get_profile_image(context).await? {
            Some(path_buf) => path_buf.to_str().map(|s| s.to_owned()),
            None => None,
        };
        let color = color_int_to_hex_string(chat.get_color(context).await?);

        Ok(BasicChat {
            id: chat_id,
            name: chat.name.clone(),
            is_encrypted: chat.is_encrypted(context).await?,
            profile_image, //BLOBS ?
            archived: chat.get_visibility() == chat::ChatVisibility::Archived,
            pinned: chat.get_visibility() == chat::ChatVisibility::Pinned,
            chat_type: chat.get_type().into(),
            is_unpromoted: chat.is_unpromoted(),
            is_self_talk: chat.is_self_talk(),
            color,
            is_contact_request: chat.is_contact_request(),
            is_device_chat: chat.is_device_talk(),
            is_muted: chat.is_muted(),
        })
    }
}

#[derive(Clone, Serialize, Deserialize, TypeDef, schemars::JsonSchema)]
#[serde(tag = "kind")]
pub enum MuteDuration {
    NotMuted,
    Forever,
    Until { duration: i64 },
}

impl MuteDuration {
    pub fn try_into_core_type(self) -> Result<chat::MuteDuration> {
        match self {
            MuteDuration::NotMuted => Ok(chat::MuteDuration::NotMuted),
            MuteDuration::Forever => Ok(chat::MuteDuration::Forever),
            MuteDuration::Until { duration } => {
                if duration <= 0 {
                    bail!("failed to read mute duration")
                }

                Ok(SystemTime::now()
                    .checked_add(Duration::from_secs(duration as u64))
                    .map_or(chat::MuteDuration::Forever, chat::MuteDuration::Until))
            }
        }
    }
}

#[derive(Clone, Serialize, Deserialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "ChatVisibility")]
pub enum JsonrpcChatVisibility {
    Normal,
    Archived,
    Pinned,
}

impl JsonrpcChatVisibility {
    pub fn into_core_type(self) -> ChatVisibility {
        match self {
            JsonrpcChatVisibility::Normal => ChatVisibility::Normal,
            JsonrpcChatVisibility::Archived => ChatVisibility::Archived,
            JsonrpcChatVisibility::Pinned => ChatVisibility::Pinned,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, TypeDef, schemars::JsonSchema)]
#[serde(rename = "ChatType")]
pub enum JsonrpcChatType {
    Single,
    Group,
    Mailinglist,
    OutBroadcast,
    InBroadcast,
}

impl From<Chattype> for JsonrpcChatType {
    fn from(chattype: Chattype) -> Self {
        match chattype {
            Chattype::Single => JsonrpcChatType::Single,
            Chattype::Group => JsonrpcChatType::Group,
            Chattype::Mailinglist => JsonrpcChatType::Mailinglist,
            Chattype::OutBroadcast => JsonrpcChatType::OutBroadcast,
            Chattype::InBroadcast => JsonrpcChatType::InBroadcast,
        }
    }
}

impl From<JsonrpcChatType> for Chattype {
    fn from(chattype: JsonrpcChatType) -> Self {
        match chattype {
            JsonrpcChatType::Single => Chattype::Single,
            JsonrpcChatType::Group => Chattype::Group,
            JsonrpcChatType::Mailinglist => Chattype::Mailinglist,
            JsonrpcChatType::OutBroadcast => Chattype::OutBroadcast,
            JsonrpcChatType::InBroadcast => Chattype::InBroadcast,
        }
    }
}
