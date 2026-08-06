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
mod tests {
    use super::*;
    use crate::chat::{ChatItem, add_info_msg, create_broadcast, get_chat_msgs};
    use crate::config::Config;
    use crate::securejoin::get_securejoin_qr;
    use crate::test_utils::{TestContextManager, sync};
    use std::time::Duration;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pinned_messages() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let alice2 = &tcm.alice().await; // Alice's second device
        let bob = &tcm.bob().await;

        alice.set_config_bool(Config::SyncMsgs, true).await?;
        alice2.set_config_bool(Config::SyncMsgs, true).await?;

        // Alice creates all chat types upfront, with Bob as member if possible
        let single_chat_id = alice.create_chat(bob).await.id;
        let group_chat_id = alice.create_group_with_members("Group", &[bob]).await;
        let broadcast_chat_id = create_broadcast(alice, "Channel".to_string()).await?;
        let qr = get_securejoin_qr(alice, Some(broadcast_chat_id)).await?;
        tcm.exec_securejoin_qr(bob, alice, &qr).await;
        let self_chat_id = alice.get_self_chat().await.id;
        sync(alice, alice2).await;

        for alice_chat_id in [
            single_chat_id,
            group_chat_id,
            broadcast_chat_id,
            self_chat_id,
        ] {
            let pinned = get_pinned_messages(alice, alice_chat_id).await?;
            assert!(pinned.is_empty());

            // Alice sends message "Foo" and pins it
            let sent1 = alice.send_text(alice_chat_id, "Foo").await;
            let msg1 = sent1.load_from_db().await;
            assert!(!msg1.is_pinned());

            set_pinned_state(alice, msg1.id, true).await?;
            let sent2 = alice.pop_sent_msg().await;
            assert!(sent1.load_from_db().await.is_pinned());

            let info_msg = sent2.load_from_db().await;
            assert!(info_msg.is_info());
            assert!(!info_msg.hidden);
            assert_eq!(info_msg.get_info_type(), SystemMessage::MessagePinned);
            assert!(info_msg.get_info_contact_id(alice).await?.is_none()); // contact not needed, tapping shall jump to message

            let pinned = get_pinned_messages(alice, alice_chat_id).await?;
            assert_eq!(pinned.len(), 1);
            assert_eq!(pinned[0], msg1.id);

            // Pinning an info message does not work
            assert!(set_pinned_state(alice, info_msg.id, true).await.is_err());

            // Unpin the initially pinned message.
            // Before, send another message "Bar". To test, no visible info message is added this time,
            let sent3 = alice.send_text(alice_chat_id, "Bar").await;

            set_pinned_state(alice, msg1.id, false).await?;
            let sent4 = alice.pop_sent_msg().await;
            assert!(!sent1.load_from_db().await.is_pinned());

            let pinned = get_pinned_messages(alice, alice_chat_id).await?;
            assert!(pinned.is_empty());

            let msg3 = sent3.load_from_db().await;
            assert!(!msg3.is_info());
            assert!(!msg3.is_pinned());
            assert_eq!(alice.get_last_msg_id_in(msg3.chat_id).await, msg3.id); // last message is still "Bar", not an info message

            if alice_chat_id != self_chat_id {
                // Bob receives message "Foo"
                let msg1 = bob.recv_msg(&sent1).await;
                assert!(!msg1.is_pinned());
                let pinned = get_pinned_messages(bob, msg1.chat_id).await?;
                assert!(pinned.is_empty());

                // Bob receives info message to pin "Foo"
                bob.recv_msg(&sent2).await;
                assert!(Message::load_from_db(bob, msg1.id).await?.is_pinned());

                let pinned = get_pinned_messages(bob, msg1.chat_id).await?;
                assert_eq!(pinned.len(), 1);
                assert_eq!(pinned[0], msg1.id);

                let info_msg =
                    Message::load_from_db(bob, bob.get_last_msg_id_in(msg1.chat_id).await).await?;
                assert!(info_msg.is_info());
                assert!(!info_msg.hidden);
                assert_eq!(info_msg.get_info_type(), SystemMessage::MessagePinned);
                assert!(info_msg.get_info_contact_id(bob).await?.is_none());

                // Bob receives message "Bar" and hidden message to unpin message "Foo"
                bob.recv_msg(&sent3).await;
                bob.recv_msg_trash(&sent4).await;
                assert!(!Message::load_from_db(bob, msg1.id).await?.is_pinned());

                let pinned = get_pinned_messages(bob, msg1.chat_id).await?;
                assert!(pinned.is_empty());

                let no_info_msg =
                    Message::load_from_db(bob, bob.get_last_msg_id_in(msg1.chat_id).await).await?;
                assert!(!no_info_msg.is_info());
                assert_eq!(no_info_msg.text, "Bar");
            }

            // Alice's second device receives all four messages and ends up in the same state
            let msg1 = alice2.recv_msg(&sent1).await;
            alice2.recv_msg(&sent2).await;
            assert!(Message::load_from_db(alice2, msg1.id).await?.is_pinned());

            alice2.recv_msg(&sent3).await;
            alice2.recv_msg_trash(&sent4).await;
            assert!(!Message::load_from_db(alice2, msg1.id).await?.is_pinned());

            let no_info_msg =
                Message::load_from_db(alice2, alice2.get_last_msg_id_in(msg1.chat_id).await)
                    .await?;
            assert!(!no_info_msg.is_info());
            assert_eq!(no_info_msg.text, "Bar");
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_get_pinned_messages_order() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let chat_id = alice.get_self_chat().await.id;
        let boilerplate_msg_count = get_chat_msgs(alice, chat_id).await?.len();

        // create three messages, sent1 and sent2 have different timestamp, sent2 and sent3 may differ by ID only
        let sent1 = alice.send_text(chat_id, "1").await;
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let sent2 = alice.send_text(chat_id, "2").await;
        let sent3 = alice.send_text(chat_id, "3").await;

        // get_chat_msgs() start with the oldest message
        let chat_msgs = get_chat_msgs(alice, chat_id).await?;
        let msg_ids: Vec<_> = chat_msgs
            .into_iter()
            .filter_map(|item| match item {
                ChatItem::Message { msg_id } => Some(msg_id),
                ChatItem::DayMarker { .. } => None,
            })
            .collect();
        assert_eq!(
            &msg_ids[boilerplate_msg_count..],
            &[
                sent1.sender_msg_id,
                sent2.sender_msg_id,
                sent3.sender_msg_id
            ]
        );

        // get_pinned_messages() has the same order, also starting with the oldest message
        set_pinned_state(alice, sent1.sender_msg_id, true).await?;
        set_pinned_state(alice, sent2.sender_msg_id, true).await?;
        set_pinned_state(alice, sent3.sender_msg_id, true).await?;
        let pinned = get_pinned_messages(alice, chat_id).await?;
        assert_eq!(pinned.len(), 3);
        assert_eq!(pinned[0], sent1.sender_msg_id);
        assert_eq!(pinned[1], sent2.sender_msg_id);
        assert_eq!(pinned[2], sent3.sender_msg_id);

        // order of pinning does not affect the order of pinned messages.
        // this is to keep scrolling direction of chat bubbles and pinned banner scrollbar in sync,
        // and not jumping wildly around.
        // this is also what most other messengers are doing.
        set_pinned_state(alice, sent1.sender_msg_id, false).await?;
        set_pinned_state(alice, sent2.sender_msg_id, false).await?;
        set_pinned_state(alice, sent3.sender_msg_id, false).await?;
        let pinned = get_pinned_messages(alice, chat_id).await?;
        assert_eq!(pinned.len(), 0);

        set_pinned_state(alice, sent3.sender_msg_id, true).await?;
        set_pinned_state(alice, sent2.sender_msg_id, true).await?;
        set_pinned_state(alice, sent1.sender_msg_id, true).await?;
        let pinned = get_pinned_messages(alice, chat_id).await?;
        assert_eq!(pinned.len(), 3);
        assert_eq!(pinned[0], sent1.sender_msg_id);
        assert_eq!(pinned[1], sent2.sender_msg_id);
        assert_eq!(pinned[2], sent3.sender_msg_id);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_handle_pinned_state_from_wire() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let chat_id = alice.get_self_chat().await.id;

        let sent1 = alice.send_text(chat_id, "pinnable").await;
        let msg1 = sent1.load_from_db().await;
        assert!(is_pinnable(&msg1));
        assert!(
            handle_pinned_state_from_wire(alice, &msg1, true)
                .await
                .is_ok()
        );

        // For not-pinnable messages, handle_pinned_state_from_wire() logs a warning and returns "ok".
        // otherwise if there is an incompatibility in which messages are treated as "pinnable",
        // this error will bubble up and user will get a device message saying "please report a bug".
        let msg2_id = add_info_msg(alice, chat_id, "not pinnable").await?;
        let msg2 = Message::load_from_db(alice, msg2_id).await?;
        assert!(!is_pinnable(&msg2));
        assert!(
            handle_pinned_state_from_wire(alice, &msg2, true)
                .await
                .is_ok()
        );

        Ok(())
    }
}
