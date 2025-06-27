//! Bob's side of SecureJoin handling, the joiner-side.

use anyhow::{Context as _, Result};

use super::HandshakeMessage;
use super::qrinvite::QrInvite;
use crate::chat::{self, ChatId, ProtectionStatus, is_contact_in_chat};
use crate::constants::{Blocked, Chattype};
use crate::contact::Origin;
use crate::context::Context;
use crate::events::EventType;
use crate::key::self_fingerprint;
use crate::log::info;
use crate::message::{Message, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::Param;
use crate::securejoin::{ContactId, encrypted_and_signed, verify_sender_by_fingerprint};
use crate::stock_str;
use crate::sync::Sync::*;
use crate::tools::{create_smeared_timestamp, time};

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
    let hidden = match invite {
        QrInvite::Contact { .. } => Blocked::Not,
        QrInvite::Group { .. } => Blocked::Yes,
    };
    let chat_id = ChatId::create_for_contact_with_blocked(context, invite.contact_id(), hidden)
        .await
        .with_context(|| format!("can't create chat for contact {}", invite.contact_id()))?;

    ContactId::scaleup_origin(context, &[invite.contact_id()], Origin::SecurejoinJoined).await?;
    context.emit_event(EventType::ContactsChanged(None));

    // Now start the protocol and initialise the state.
    {
        let has_key = context
            .sql
            .exists(
                "SELECT COUNT(*) FROM public_keys WHERE fingerprint=?",
                (invite.fingerprint().hex(),),
            )
            .await?;

        if has_key
            && verify_sender_by_fingerprint(context, invite.fingerprint(), invite.contact_id())
                .await?
        {
            // The scanned fingerprint matches Alice's key, we can proceed to step 4b.
            info!(context, "Taking securejoin protocol shortcut");
            send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::RequestWithAuth)
                .await?;

            // Mark 1:1 chat as verified already.
            chat_id
                .set_protection(
                    context,
                    ProtectionStatus::Protected,
                    time(),
                    Some(invite.contact_id()),
                )
                .await?;

            context.emit_event(EventType::SecurejoinJoinerProgress {
                contact_id: invite.contact_id(),
                progress: JoinerProgress::RequestWithAuthSent.to_usize(),
            });
        } else {
            send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::Request).await?;

            insert_new_db_entry(context, invite.clone(), chat_id).await?;
        }
    }

    match invite {
        QrInvite::Group { .. } => {
            // For a secure-join we need to create the group and add the contact.  The group will
            // only become usable once the protocol is finished.
            let group_chat_id = joining_chat_id(context, &invite, chat_id).await?;
            if !is_contact_in_chat(context, group_chat_id, invite.contact_id()).await? {
                chat::add_to_chat_contacts_table(
                    context,
                    time(),
                    group_chat_id,
                    &[invite.contact_id()],
                )
                .await?;
            }
            let msg = stock_str::secure_join_started(context, invite.contact_id()).await;
            chat::add_info_msg(context, group_chat_id, &msg, time()).await?;
            Ok(group_chat_id)
        }
        QrInvite::Contact { .. } => {
            // For setup-contact the BobState already ensured the 1:1 chat exists because it
            // uses it to send the handshake messages.
            // Calculate the sort timestamp before checking the chat protection status so that if we
            // race with its change, we don't add our message below the protection message.
            let sort_to_bottom = true;
            let (received, incoming) = (false, false);
            let ts_sort = chat_id
                .calc_sort_timestamp(context, 0, sort_to_bottom, received, incoming)
                .await?;
            if chat_id.is_protected(context).await? == ProtectionStatus::Unprotected {
                let ts_start = time();
                chat::add_info_msg_with_cmd(
                    context,
                    chat_id,
                    &stock_str::securejoin_wait(context).await,
                    SystemMessage::SecurejoinWait,
                    ts_sort,
                    Some(ts_start),
                    None,
                    None,
                    None,
                )
                .await?;
            }
            Ok(chat_id)
        }
    }
}

/// Inserts a new entry in the bobstate table.
///
/// Returns the ID of the newly inserted entry.
async fn insert_new_db_entry(context: &Context, invite: QrInvite, chat_id: ChatId) -> Result<i64> {
    context
        .sql
        .insert(
            "INSERT INTO bobstate (invite, next_step, chat_id) VALUES (?, ?, ?);",
            (invite, 0, chat_id),
        )
        .await
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
    let bob_states: Vec<(i64, QrInvite, ChatId)> = context
        .sql
        .query_map(
            "SELECT id, invite, chat_id FROM bobstate",
            (),
            |row| {
                let row_id: i64 = row.get(0)?;
                let invite: QrInvite = row.get(1)?;
                let chat_id: ChatId = row.get(2)?;
                Ok((row_id, invite, chat_id))
            },
            |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await?;

    info!(
        context,
        "Bob Step 4 - handling {{vc,vg}}-auth-required message."
    );

    let mut auth_sent = false;
    for (bobstate_row_id, invite, chat_id) in bob_states {
        if !encrypted_and_signed(context, message, invite.fingerprint()) {
            continue;
        }

        if !verify_sender_by_fingerprint(context, invite.fingerprint(), invite.contact_id()).await?
        {
            continue;
        }

        info!(context, "Fingerprint verified.",);
        send_handshake_message(context, &invite, chat_id, BobHandshakeMsg::RequestWithAuth).await?;
        context
            .sql
            .execute("DELETE FROM bobstate WHERE id=?", (bobstate_row_id,))
            .await?;

        match invite {
            QrInvite::Contact { .. } => {}
            QrInvite::Group { .. } => {
                // The message reads "Alice replied, waiting to be added to the group…",
                // so only show it on secure-join and not on setup-contact.
                let contact_id = invite.contact_id();
                let msg = stock_str::secure_join_replies(context, contact_id).await;
                let chat_id = joining_chat_id(context, &invite, chat_id).await?;
                chat::add_info_msg(context, chat_id, &msg, time()).await?;
            }
        }

        chat_id
            .set_protection(
                context,
                ProtectionStatus::Protected,
                message.timestamp_sent,
                Some(invite.contact_id()),
            )
            .await?;

        context.emit_event(EventType::SecurejoinJoinerProgress {
            contact_id: invite.contact_id(),
            progress: JoinerProgress::RequestWithAuthSent.to_usize(),
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
            },
            Self::RequestWithAuth => match invite {
                QrInvite::Contact { .. } => "vc-request-with-auth",
                QrInvite::Group { .. } => "vg-request-with-auth",
            },
        }
    }
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
        QrInvite::Group { grpid, name, .. } => {
            let group_chat_id = match chat::get_chat_id_by_grpid(context, grpid).await? {
                Some((chat_id, _protected, _blocked)) => {
                    chat_id.unblock_ex(context, Nosync).await?;
                    chat_id
                }
                None => {
                    ChatId::create_multiuser_record(
                        context,
                        Chattype::Group,
                        grpid,
                        name,
                        Blocked::Not,
                        ProtectionStatus::Unprotected, // protection is added later as needed
                        None,
                        create_smeared_timestamp(context),
                    )
                    .await?
                }
            };
            Ok(group_chat_id)
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
    #[expect(clippy::wrong_self_convention)]
    pub(crate) fn to_usize(self) -> usize {
        match self {
            JoinerProgress::RequestWithAuthSent => 400,
            JoinerProgress::Succeeded => 1000,
        }
    }
}
