//! # Handle pinned messages.
//!
//! Pinned messages can be used in all types of chats
//! and for all but info-messages.
//!
//! Pinned messages are synchronized for all chat members by sending an info-message
//! that refers the pinned message in the `In-Reply-To:` header.
//! The info-message is only shown for pinning (not for unpinning).
//! Unpinning is an action that does not require so much attention; internally it is a hidden info-message.

use anyhow::{Result, ensure};

use crate::chat::{ChatId, send_msg};
use crate::contact::ContactId;
use crate::context::Context;
use crate::events::EventType;
use crate::log::warn;
use crate::message::{Message, MessageState, MsgId, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::stock_str;

/// Check if the given message is pinnable in general.
/// This does not mean the local user is allowed to pin/unpin it themselves,
/// e.g. messages in broadcast channels may be pinnable - but cannot be pinned by the local user.
fn is_pinnable(msg: &Message) -> bool {
    !msg.id.is_special()
    && !msg.is_info()
    && !msg.hidden
    && msg.state != MessageState::OutDraft
    && msg.state != MessageState::OutFailed // Some user did not get the message, pinning it raises wrong expectations
    && !msg.chat_id.is_special()
}

/// Pin or unpin a message.
///
/// If the message is not pinnable, an error is returned.
/// If pinning changes, `EventType::MsgsChanged` event is fired to show/hide the pinning needle.
pub async fn set_pinned_state(
    context: &Context,
    msg_id: MsgId,
    new_pinned_state: bool,
) -> Result<()> {
    let msg = Message::load_from_db(context, msg_id).await?;
    ensure!(is_pinnable(&msg), "Message is not pinnable.");
    if msg.is_pinned() == new_pinned_state {
        return Ok(());
    }

    let mut info_msg = Message::new(Viewtype::Text);
    info_msg.text = if new_pinned_state {
        stock_str::msg_pinned(context, ContactId::SELF).await
    } else {
        "Message unpinned.".to_string() // no need to localize, "unpinned" messages are not visible
    };
    info_msg.hidden = !new_pinned_state;
    info_msg.in_reply_to = Some(msg.rfc724_mid.clone());
    info_msg.param.set_cmd(if new_pinned_state {
        SystemMessage::MessagePinned
    } else {
        SystemMessage::MessageUnpinned
    });
    send_msg(context, msg.chat_id, &mut info_msg).await?;

    // alter database only after we successfully sent the message
    update_pinned_state_in_db(context, &msg, new_pinned_state).await?;

    Ok(())
}

async fn update_pinned_state_in_db(
    context: &Context,
    msg: &Message,
    new_pinned_state: bool,
) -> Result<()> {
    context
        .sql
        .execute(
            "UPDATE msgs SET pinned=? WHERE id=?",
            (new_pinned_state, msg.id),
        )
        .await?;

    context.emit_msgs_changed(msg.chat_id, msg.id);
    context.emit_event(EventType::PinnedMessagesChanged {
        chat_id: msg.chat_id,
    });

    Ok(())
}

/// Returns all pinned messages of a chat.
///
/// The list is ordered by message date, not by pinning date,
/// and starts with the oldest message - same as the normal message view.
///
/// When a chat is opened, UI should show the newest message in the "pinned banner".
/// The scrollbar of the "pinned banner" will be scrolled down all the way, same as the whole chat.
/// The pinned message is shown using `Message::get_summary()`, enriched by thumbnails and a "Start" button for webxdc.
///
/// Once the banner is tapped, UI should scroll to that message and replace the banner by pinned message one position less.
/// When the position is 0, UI should wrap and show the newest message again.
///
/// By that, usually scrolling the message view and the pinned view have the same direction.
pub async fn get_pinned_messages(context: &Context, chat_id: ChatId) -> Result<Vec<MsgId>> {
    ensure!(!chat_id.is_special(), "Invalid chat ID.");

    let pinned_msg_ids = context
        .sql
        .query_map_vec(
            "SELECT id
               FROM msgs
              WHERE pinned=1 AND chat_id=?
              ORDER BY timestamp, id;",
            (chat_id,),
            |row| {
                let msg_id: MsgId = row.get(0)?;
                Ok(msg_id)
            },
        )
        .await?;
    Ok(pinned_msg_ids)
}

/// Handle pinned state received from the wire, e.g. by an info message.
///
/// This function checks and updates the state and sends events,
/// but does not add a info message or sync otherwise.
///
/// If the message is not pinnable, a warning is logged and the message is ignored.
pub(crate) async fn handle_pinned_state_from_wire(
    context: &Context,
    msg: &Message,
    new_pinned_state: bool,
) -> Result<()> {
    if !is_pinnable(msg) {
        warn!(context, "Message is not pinnable.");
        return Ok(());
    }

    if msg.is_pinned() == new_pinned_state {
        return Ok(());
    }
    update_pinned_state_in_db(context, msg, new_pinned_state).await?;
    Ok(())
}

#[cfg(test)]
mod pinned_messages_tests;
