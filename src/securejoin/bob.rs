//! Bob's side of SecureJoin handling, the joiner-side.

use anyhow::{Context as _, Result};

use super::HandshakeMessage;
use super::qrinvite::QrInvite;
use crate::chat::{self, ChatId, is_contact_in_chat};
use crate::chatlist_events;
use crate::constants::{Blocked, Chattype};
use crate::contact::Origin;
use crate::context::Context;
use crate::events::EventType;
use crate::key::self_fingerprint;
use crate::log::LogExt;
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::{Param, Params};
use crate::securejoin::{ContactId, encrypted_and_signed, verify_sender_by_fingerprint};
use crate::stock_str;
use crate::sync::Sync::*;
use crate::tools::{smeared_time, time};

/// Starts the securejoin protocol with the QR `invite`.
///
/// This will try to start the securejoin protocol for the given QR `invite`.
///
/// If Bob already has Alice's key, he sends `AUTH` token
/// and forgets about the invite.
/// If Bob does not yet have Alice's key, he sends `vc-request`
/// or `vg-request` message and stores a row in the `bobstate` table
/// so he can check Alice's key against the fingerprint
/// and send `AUTH` token later.
///
/// This function takes care of handling multiple concurrent joins and handling errors while
/// starting the protocol.
///
/// # Bob - the joiner's side
/// ## Step 2 in the "Setup Contact protocol", section 2.1 of countermitm 0.10.0
///
/// # Returns
///
/// The [`ChatId`] of the created chat is returned, for a SetupContact QR this is the 1:1
/// chat with Alice, for a SecureJoin QR this is the group chat.
pub(super) async fn start_protocol(context: &Context, invite: QrInvite) -> Result<ChatId> {
    // A 1:1 chat is needed to send messages to Alice.  When joining a group this chat is
    // hidden, if a user starts sending messages in it it will be unhidden in
    // receive_imf.
    let private_chat_id = private_chat_id(context, &invite).await?;

    ContactId::scaleup_origin(context, &[invite.contact_id()], Origin::SecurejoinJoined).await?;
    context.emit_event(EventType::ContactsChanged(None));

    let has_key = context
        .sql
        .exists(
            "SELECT COUNT(*) FROM public_keys WHERE fingerprint=?",
            (invite.fingerprint().hex(),),
        )
        .await?;

    // Now start the protocol and initialise the state.
    {
        // `joining_chat_id` is `Some` if group chat
        // already exists and we are in the chat.
        let joining_chat_id = match invite {
            QrInvite::Group { ref grpid, .. } | QrInvite::Broadcast { ref grpid, .. } => {
                if let Some((joining_chat_id, _blocked)) =
                    chat::get_chat_id_by_grpid(context, grpid).await?
                {
                    if is_contact_in_chat(context, joining_chat_id, ContactId::SELF).await? {
                        Some(joining_chat_id)
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
            QrInvite::Contact { .. } => None,
        };

        if let Some(joining_chat_id) = joining_chat_id {
            // If QR code is a group invite
            // and we are already in the chat,
            // nothing needs to be done.
            // Even if Alice is not verified, we don't send anything.
            context.emit_event(EventType::SecurejoinJoinerProgress {
                contact_id: invite.contact_id(),
                progress: JoinerProgress::Succeeded.into_u16(),
            });
            return Ok(joining_chat_id);
        } else if has_key
            && verify_sender_by_fingerprint(context, invite.fingerprint(), invite.contact_id())
                .await?
        {
            // The scanned fingerprint matches Alice's key, we can proceed to step 4b.
            info!(context, "Taking securejoin protocol shortcut");
            send_handshake_message(
                context,
                &invite,
                private_chat_id,
                BobHandshakeMsg::RequestWithAuth,
            )
            .await?;

            context.emit_event(EventType::SecurejoinJoinerProgress {
                contact_id: invite.contact_id(),
                progress: JoinerProgress::RequestWithAuthSent.into_u16(),
            });
        } else {
            send_handshake_message(context, &invite, private_chat_id, BobHandshakeMsg::Request)
                .await?;

            insert_new_db_entry(context, invite.clone(), private_chat_id).await?;
        }
    }

    match invite {
        QrInvite::Group { .. } => {
            let joining_chat_id = joining_chat_id(context, &invite, private_chat_id).await?;
            let msg = stock_str::secure_join_started(context, invite.contact_id()).await;
            chat::add_info_msg(context, joining_chat_id, &msg).await?;
            Ok(joining_chat_id)
        }
        QrInvite::Broadcast { .. } => {
            let joining_chat_id = joining_chat_id(context, &invite, private_chat_id).await?;
            // We created the broadcast channel already, now we need to add Alice to it.
            if !is_contact_in_chat(context, joining_chat_id, invite.contact_id()).await? {
                chat::add_to_chat_contacts_table(
                    context,
                    time(),
                    joining_chat_id,
                    &[invite.contact_id()],
                )
                .await?;
            }

            // If we were not in the broadcast channel before, show a 'please wait' info message.
            if !is_contact_in_chat(context, joining_chat_id, ContactId::SELF).await? {
                let msg =
                    stock_str::secure_join_broadcast_started(context, invite.contact_id()).await;
                chat::add_info_msg(context, joining_chat_id, &msg).await?;
            }
            Ok(joining_chat_id)
        }
        QrInvite::Contact { .. } => {
            // For setup-contact the BobState already ensured the 1:1 chat exists because it is
            // used to send the handshake messages.
            if !has_key {
                chat::add_info_msg_with_cmd(
                    context,
                    private_chat_id,
                    &stock_str::securejoin_wait(context).await,
                    SystemMessage::SecurejoinWait,
                    None,
                    time(),
                    None,
                    None,
                    None,
                )
                .await?;
            }
            Ok(private_chat_id)
        }
    }
}

/// Inserts a new entry in the bobstate table.
///
/// Returns the ID of the newly inserted entry.
async fn insert_new_db_entry(context: &Context, invite: QrInvite, chat_id: ChatId) -> Result<i64> {
    // The `chat_id` isn't actually needed anymore,
    // but we still save it;
    // can be removed as a future improvement.
    context
        .sql
        .insert(
            "INSERT INTO bobstate (invite, next_step, chat_id) VALUES (?, ?, ?);",
            (invite, 0, chat_id),
        )
        .await
}

async fn delete_securejoin_wait_msg(context: &Context, chat_id: ChatId) -> Result<()> {
    if let Some((msg_id, param)) = context
        .sql
        .query_row_optional(
            "
SELECT id, param FROM msgs
WHERE timestamp=(SELECT MAX(timestamp) FROM msgs WHERE chat_id=? AND hidden=0)
    AND chat_id=? AND hidden=0
LIMIT 1
            ",
            (chat_id, chat_id),
            |row| {
                let id: MsgId = row.get(0)?;
                let param: String = row.get(1)?;
                let param: Params = param.parse().unwrap_or_default();
                Ok((id, param))
            },
        )
        .await?
        && param.get_cmd() == SystemMessage::SecurejoinWait
    {
        let on_server = false;
        msg_id.trash(context, on_server).await?;
        context.emit_event(EventType::MsgDeleted { chat_id, msg_id });
        context.emit_msgs_changed_without_msg_id(chat_id);
        chatlist_events::emit_chatlist_item_changed(context, chat_id);
        context.emit_msgs_changed_without_ids();
        chatlist_events::emit_chatlist_changed(context);
    }
    Ok(())
}

/// Handles `vc-auth-required` and `vg-auth-required` handshake messages.
///
/// # Bob - the joiner's side
/// ## Step 4 in the "Setup Contact protocol"
pub(super) async fn handle_auth_required(
    context: &Context,
    message: &MimeMessage,
) -> Result<HandshakeMessage> {
    // Load all Bob states that expect `vc-auth-required` or `vg-auth-required`.
    let bob_states = context
        .sql
        .query_map_vec("SELECT id, invite FROM bobstate", (), |row| {
            let row_id: i64 = row.get(0)?;
            let invite: QrInvite = row.get(1)?;
            Ok((row_id, invite))
        })
        .await?;

    info!(
        context,
        "Bob Step 4 - handling {{vc,vg}}-auth-required message."
    );

    let mut auth_sent = false;
    for (bobstate_row_id, invite) in bob_states {
        if !encrypted_and_signed(context, message, invite.fingerprint()) {
            continue;
        }

        if !verify_sender_by_fingerprint(context, invite.fingerprint(), invite.contact_id()).await?
        {
            continue;
        }

        info!(context, "Fingerprint verified.",);
        let chat_id = private_chat_id(context, &invite).await?;
        delete_securejoin_wait_msg(context, chat_id)
            .await
            .context("delete_securejoin_wait_msg")
            .log_err(context)
            .ok();
        send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::RequestWithAuth).await?;
        context
            .sql
            .execute("DELETE FROM bobstate WHERE id=?", (bobstate_row_id,))
            .await?;

        match invite {
            QrInvite::Contact { .. } | QrInvite::Broadcast { .. } => {}
            QrInvite::Group { .. } => {
                // The message reads "Alice replied, waiting to be added to the group…",
                // so only show it when joining a group and not for a 1:1 chat or broadcast channel.
                let contact_id = invite.contact_id();
                let msg = stock_str::secure_join_replies(context, contact_id).await;
                let chat_id = joining_chat_id(context, &invite, chat_id).await?;
                chat::add_info_msg(context, chat_id, &msg).await?;
            }
        }

        context.emit_event(EventType::SecurejoinJoinerProgress {
            contact_id: invite.contact_id(),
            progress: JoinerProgress::RequestWithAuthSent.into_u16(),
        });

        auth_sent = true;
    }

    if auth_sent {
        // Delete the message from IMAP server.
        Ok(HandshakeMessage::Done)
    } else {
        // We have not found any corresponding AUTH codes,
        // maybe another Bob device has scanned the QR code.
        // Leave the message on IMAP server and let the other device
        // process it.
        Ok(HandshakeMessage::Ignore)
    }
}

/// Sends the requested handshake message to Alice.
pub(crate) async fn send_handshake_message(
    context: &Context,
    invite: &QrInvite,
    chat_id: ChatId,
    step: BobHandshakeMsg,
) -> Result<()> {
    let mut msg = Message {
        viewtype: Viewtype::Text,
        text: step.body_text(invite),
        hidden: true,
        ..Default::default()
    };
    msg.param.set_cmd(SystemMessage::SecurejoinMessage);

    // Sends the step in Secure-Join header.
    msg.param.set(Param::Arg, step.securejoin_header(invite));

    match step {
        BobHandshakeMsg::Request => {
            // Sends the Secure-Join-Invitenumber header in mimefactory.rs.
            msg.param.set(Param::Arg2, invite.invitenumber());
            msg.force_plaintext();
        }
        BobHandshakeMsg::RequestWithAuth => {
            // Sends the Secure-Join-Auth header in mimefactory.rs.
            msg.param.set(Param::Arg2, invite.authcode());
            msg.param.set_int(Param::GuaranteeE2ee, 1);

            // Sends our own fingerprint in the Secure-Join-Fingerprint header.
            let bob_fp = self_fingerprint(context).await?;
            msg.param.set(Param::Arg3, bob_fp);

            // Sends the grpid in the Secure-Join-Group header.
            //
            // `Secure-Join-Group` header is deprecated,
            // but old Delta Chat core requires that Alice receives it.
            //
            // Previous Delta Chat core also sent `Secure-Join-Group` header
            // in `vg-request` messages,
            // but it was not used on the receiver.
            if let QrInvite::Group { grpid, .. } = invite {
                msg.param.set(Param::Arg4, grpid);
            }
        }
    };

    chat::send_msg(context, chat_id, &mut msg).await?;
    Ok(())
}

/// Identifies the SecureJoin handshake messages Bob can send.
pub(crate) enum BobHandshakeMsg {
    /// vc-request or vg-request
    Request,
    /// vc-request-with-auth or vg-request-with-auth
    RequestWithAuth,
}

impl BobHandshakeMsg {
    /// Returns the text to send in the body of the handshake message.
    ///
    /// This text has no significance to the protocol, but would be visible if users see
    /// this email message directly, e.g. when accessing their email without using
    /// DeltaChat.
    fn body_text(&self, invite: &QrInvite) -> String {
        format!("Secure-Join: {}", self.securejoin_header(invite))
    }

    /// Returns the `Secure-Join` header value.
    ///
    /// This identifies the step this message is sending information about.  Most protocol
    /// steps include additional information into other headers, see
    /// [`send_handshake_message`] for these.
    fn securejoin_header(&self, invite: &QrInvite) -> &'static str {
        match self {
            Self::Request => match invite {
                QrInvite::Contact { .. } => "vc-request",
                QrInvite::Group { .. } => "vg-request",
                QrInvite::Broadcast { .. } => "vg-request",
            },
            Self::RequestWithAuth => match invite {
                QrInvite::Contact { .. } => "vc-request-with-auth",
                QrInvite::Group { .. } => "vg-request-with-auth",
                QrInvite::Broadcast { .. } => "vg-request-with-auth",
            },
        }
    }
}

/// Returns the 1:1 chat with the inviter.
///
/// This is the chat in which securejoin messages are sent.
/// The 1:1 chat will be created if it does not yet exist.
async fn private_chat_id(context: &Context, invite: &QrInvite) -> Result<ChatId> {
    let hidden = match invite {
        QrInvite::Contact { .. } => Blocked::Not,
        QrInvite::Group { .. } => Blocked::Yes,
        QrInvite::Broadcast { .. } => Blocked::Yes,
    };

    ChatId::create_for_contact_with_blocked(context, invite.contact_id(), hidden)
        .await
        .with_context(|| format!("can't create chat for contact {}", invite.contact_id()))
}

/// Returns the [`ChatId`] of the chat being joined.
///
/// This is the chat in which you want to notify the user as well.
///
/// When joining a group this is the [`ChatId`] of the group chat, when verifying a
/// contact this is the [`ChatId`] of the 1:1 chat.
/// The group chat will be created if it does not yet exist.
async fn joining_chat_id(
    context: &Context,
    invite: &QrInvite,
    alice_chat_id: ChatId,
) -> Result<ChatId> {
    match invite {
        QrInvite::Contact { .. } => Ok(alice_chat_id),
        QrInvite::Group { grpid, name, .. } | QrInvite::Broadcast { name, grpid, .. } => {
            let chattype = if matches!(invite, QrInvite::Group { .. }) {
                Chattype::Group
            } else {
                Chattype::InBroadcast
            };

            let chat_id = match chat::get_chat_id_by_grpid(context, grpid).await? {
                Some((chat_id, _blocked)) => {
                    chat_id.unblock_ex(context, Nosync).await?;
                    chat_id
                }
                None => {
                    ChatId::create_multiuser_record(
                        context,
                        chattype,
                        grpid,
                        name,
                        Blocked::Not,
                        None,
                        smeared_time(context),
                    )
                    .await?
                }
            };
            Ok(chat_id)
        }
    }
}

/// Progress updates for [`EventType::SecurejoinJoinerProgress`].
///
/// This has an `From<JoinerProgress> for usize` impl yielding numbers between 0 and a 1000
/// which can be shown as a progress bar.
pub(crate) enum JoinerProgress {
    /// vg-vc-request-with-auth sent.
    ///
    /// Typically shows as "alice@addr verified, introducing myself."
    RequestWithAuthSent,
    /// Completed securejoin.
    Succeeded,
}

impl JoinerProgress {
    pub(crate) fn into_u16(self) -> u16 {
        match self {
            JoinerProgress::RequestWithAuthSent => 400,
            JoinerProgress::Succeeded => 1000,
        }
    }
}
