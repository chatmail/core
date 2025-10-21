use anyhow::{Context, Result};
use deltachat::chat::{Chat, ChatId};
use deltachat::chatlist::get_last_message_for_chat;
use deltachat::constants::*;
use deltachat::contact::Contact;
use deltachat::{
    chat::{get_chat_contacts, ChatVisibility},
    chatlist::Chatlist,
};
use num_traits::cast::ToPrimitive;
use serde::Serialize;
use typescript_type_def::TypeDef;

use super::color_int_to_hex_string;
use super::message::MessageViewtype;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(tag = "kind")]
pub enum ChatListItemFetchResult {
    #[serde(rename_all = "camelCase")]
    ChatListItem {
        id: u32,
        name: String,
        avatar_path: Option<String>,
        color: String,
        chat_type: u32,
        last_updated: Option<i64>,
        summary_text1: String,
        summary_text2: String,
        summary_status: u32,
        /// showing preview if last chat message is image
        summary_preview_image: Option<String>,

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
        /// deprecated 2025-07, use chat_type instead
        is_group: bool,
        fresh_message_counter: usize,
        is_self_talk: bool,
        is_device_talk: bool,
        is_sending_location: bool,
        is_self_in_group: bool,
        is_archived: bool,
        is_pinned: bool,
        is_muted: bool,
        is_contact_request: bool,
        /// contact id if this is a dm chat (for view profile entry in context menu)
        dm_chat_contact: Option<u32>,
        was_seen_recently: bool,
        last_message_type: Option<MessageViewtype>,
        last_message_id: Option<u32>,
    },
    #[serde(rename_all = "camelCase")]
    ArchiveLink { fresh_message_counter: usize },
    #[serde(rename_all = "camelCase")]
    Error { id: u32, error: String },
}

pub(crate) async fn get_chat_list_item_by_id(
    ctx: &deltachat::context::Context,
    entry: u32,
) -> Result<ChatListItemFetchResult> {
    let chat_id = ChatId::new(entry);
    let fresh_message_counter = chat_id.get_fresh_msg_cnt(ctx).await?;

    if chat_id.is_archived_link() {
        return Ok(ChatListItemFetchResult::ArchiveLink {
            fresh_message_counter,
        });
    }

    let last_msgid = get_last_message_for_chat(ctx, chat_id).await?;

    let chat = Chat::load_from_db(ctx, chat_id).await.context("chat")?;
    let summary = Chatlist::get_summary2(ctx, chat_id, last_msgid, Some(&chat))
        .await
        .context("summary")?;

    let summary_text1 = summary.prefix.map_or_else(String::new, |s| s.to_string());
    let summary_text2 = summary.text.to_owned();

    let summary_preview_image = summary.thumbnail_path;

    let visibility = chat.get_visibility();

    let avatar_path = chat
        .get_profile_image(ctx)
        .await?
        .map(|path| path.to_str().unwrap_or("invalid/path").to_owned());

    let (last_updated, message_type) = match last_msgid {
        Some(id) => {
            if let Some(last_message) =
                deltachat::message::Message::load_from_db_optional(ctx, id).await?
            {
                (
                    Some(last_message.get_timestamp() * 1000),
                    Some(last_message.get_viewtype().into()),
                )
            } else {
                // Message may be deleted by the time we try to load it.
                (None, None)
            }
        }
        None => (None, None),
    };

    let (dm_chat_contact, was_seen_recently) = if chat.get_type() == Chattype::Single {
        let chat_contacts = get_chat_contacts(ctx, chat_id).await?;
        let contact = chat_contacts.first();
        let was_seen_recently = match contact {
            Some(contact) => Contact::get_by_id(ctx, *contact)
                .await
                .context("contact")?
                .was_seen_recently(),
            None => false,
        };
        (
            contact.map(|contact_id| contact_id.to_u32()),
            was_seen_recently,
        )
    } else {
        (None, false)
    };

    let color = color_int_to_hex_string(chat.get_color(ctx).await?);

    Ok(ChatListItemFetchResult::ChatListItem {
        id: chat_id.to_u32(),
        name: chat.get_name().to_owned(),
        avatar_path,
        color,
        chat_type: chat.get_type().to_u32().context("unknown chat type id")?,
        last_updated,
        summary_text1,
        summary_text2,
        summary_status: summary.state.to_u32().expect("impossible"), // idea and a function to transform the constant to strings? or return string enum
        summary_preview_image,
        is_encrypted: chat.is_encrypted(ctx).await?,
        is_group: chat.get_type() == Chattype::Group,
        fresh_message_counter,
        is_self_talk: chat.is_self_talk(),
        is_device_talk: chat.is_device_talk(),
        is_self_in_group: chat.is_self_in_chat(ctx).await?,
        is_sending_location: chat.is_sending_locations(),
        is_archived: visibility == ChatVisibility::Archived,
        is_pinned: visibility == ChatVisibility::Pinned,
        is_muted: chat.is_muted(),
        is_contact_request: chat.is_contact_request(),
        dm_chat_contact,
        was_seen_recently,
        last_message_type: message_type,
        last_message_id: last_msgid.map(|id| id.to_u32()),
    })
}
