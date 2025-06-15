//! Implementation of [SecureJoin protocols](https://securejoin.delta.chat/).

use anyhow::{ensure, Context as _, Error, Result};
use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};

use crate::aheader::EncryptPreference;
use crate::chat::{self, get_chat_id_by_grpid, Chat, ChatId, ChatIdBlocked, ProtectionStatus};
use crate::chatlist_events;
use crate::config::Config;
use crate::constants::{Blocked, Chattype, NON_ALPHANUMERIC_WITHOUT_DOT};
use crate::contact::{Contact, ContactId, Origin};
use crate::context::Context;
use crate::e2ee::ensure_secret_key_exists;
use crate::events::EventType;
use crate::headerdef::HeaderDef;
use crate::key::{load_self_public_key, DcKey, Fingerprint};
use crate::log::{error, info, warn};
use crate::message::{Message, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::Param;
use crate::peerstate::Peerstate;
use crate::qr::check_qr;
use crate::securejoin::bob::JoinerProgress;
use crate::stock_str;
use crate::sync::Sync::*;
use crate::token;
use crate::tools::time;

mod bob;
mod qrinvite;

use qrinvite::QrInvite;

use crate::token::Namespace;

fn inviter_progress(context: &Context, contact_id: ContactId, progress: usize) {
    debug_assert!(
        progress <= 1000,
        "value in range 0..1000 expected with: 0=error, 1..999=progress, 1000=success"
    );
    context.emit_event(EventType::SecurejoinInviterProgress {
        contact_id,
        progress,
    });
}

/// Generates a Secure Join QR code.
///
/// With `group` set to `None` this generates a setup-contact QR code, with `group` set to a
/// [`ChatId`] generates a join-group QR code for the given chat.
pub async fn get_securejoin_qr(context: &Context, group: Option<ChatId>) -> Result<String> {
    /*=======================================================
    ====             Alice - the inviter side            ====
    ====   Step 1 in "Setup verified contact" protocol   ====
    =======================================================*/

    ensure_secret_key_exists(context).await.ok();

    let chat = match group {
        Some(id) => {
            let chat = Chat::load_from_db(context, id).await?;
            ensure!(
                chat.typ == Chattype::Group,
                "Can't generate SecureJoin QR code for 1:1 chat {id}"
            );
            ensure!(
                !chat.grpid.is_empty(),
                "Can't generate SecureJoin QR code for ad-hoc group {id}"
            );
            Some(chat)
        }
        None => None,
    };
    let grpid = chat.as_ref().map(|c| c.grpid.as_str());
    let sync_token = token::lookup(context, Namespace::InviteNumber, grpid)
        .await?
        .is_none();
    // invitenumber will be used to allow starting the handshake,
    // auth will be used to verify the fingerprint
    let invitenumber = token::lookup_or_new(context, Namespace::InviteNumber, grpid).await?;
    let auth = token::lookup_or_new(context, Namespace::Auth, grpid).await?;
    let self_addr = context.get_primary_self_addr().await?;
    let self_name = context
        .get_config(Config::Displayname)
        .await?
        .unwrap_or_default();

    let fingerprint = get_self_fingerprint(context).await?;

    let self_addr_urlencoded =
        utf8_percent_encode(&self_addr, NON_ALPHANUMERIC_WITHOUT_DOT).to_string();
    let self_name_urlencoded =
        utf8_percent_encode(&self_name, NON_ALPHANUMERIC_WITHOUT_DOT).to_string();

    let qr = if let Some(chat) = chat {
        // parameters used: a=g=x=i=s=
        let group_name = chat.get_name();
        let group_name_urlencoded = utf8_percent_encode(group_name, NON_ALPHANUMERIC).to_string();
        if sync_token {
            context
                .sync_qr_code_tokens(Some(chat.grpid.as_str()))
                .await?;
            context.scheduler.interrupt_inbox().await;
        }
        format!(
            "https://i.delta.chat/#{}&a={}&g={}&x={}&i={}&s={}",
            fingerprint.hex(),
            self_addr_urlencoded,
            &group_name_urlencoded,
            &chat.grpid,
            &invitenumber,
            &auth,
        )
    } else {
        // parameters used: a=n=i=s=
        if sync_token {
            context.sync_qr_code_tokens(None).await?;
            context.scheduler.interrupt_inbox().await;
        }
        format!(
            "https://i.delta.chat/#{}&a={}&n={}&i={}&s={}",
            fingerprint.hex(),
            self_addr_urlencoded,
            self_name_urlencoded,
            &invitenumber,
            &auth,
        )
    };

    info!(context, "Generated QR code.");
    Ok(qr)
}

async fn get_self_fingerprint(context: &Context) -> Result<Fingerprint> {
    let key = load_self_public_key(context)
        .await
        .context("Failed to load key")?;
    Ok(key.dc_fingerprint())
}

/// Take a scanned QR-code and do the setup-contact/join-group/invite handshake.
///
/// This is the start of the process for the joiner.  See the module and ffi documentation
/// for more details.
///
/// The function returns immediately and the handshake will run in background.
pub async fn join_securejoin(context: &Context, qr: &str) -> Result<ChatId> {
    securejoin(context, qr).await.map_err(|err| {
        warn!(context, "Fatal joiner error: {:#}", err);
        // The user just scanned this QR code so has context on what failed.
        error!(context, "QR process failed");
        err
    })
}

async fn securejoin(context: &Context, qr: &str) -> Result<ChatId> {
    /*========================================================
    ====             Bob - the joiner's side             =====
    ====   Step 2 in "Setup verified contact" protocol   =====
    ========================================================*/

    info!(context, "Requesting secure-join ...",);
    let qr_scan = check_qr(context, qr).await?;

    let invite = QrInvite::try_from(qr_scan)?;

    bob::start_protocol(context, invite).await
}

/// Send handshake message from Alice's device.
async fn send_alice_handshake_msg(
    context: &Context,
    contact_id: ContactId,
    step: &str,
) -> Result<()> {
    let mut msg = Message {
        viewtype: Viewtype::Text,
        text: format!("Secure-Join: {step}"),
        hidden: true,
        ..Default::default()
    };
    msg.param.set_cmd(SystemMessage::SecurejoinMessage);
    msg.param.set(Param::Arg, step);
    msg.param.set_int(Param::GuaranteeE2ee, 1);
    chat::send_msg(
        context,
        ChatIdBlocked::get_for_contact(context, contact_id, Blocked::Yes)
            .await?
            .id,
        &mut msg,
    )
    .await?;
    Ok(())
}

/// Get an unblocked chat that can be used for info messages.
async fn info_chat_id(context: &Context, contact_id: ContactId) -> Result<ChatId> {
    let chat_id_blocked = ChatIdBlocked::get_for_contact(context, contact_id, Blocked::Not).await?;
    Ok(chat_id_blocked.id)
}

/// Checks fingerprint and marks the contact as forward verified
/// if fingerprint matches.
async fn verify_sender_by_fingerprint(
    context: &Context,
    fingerprint: &Fingerprint,
    contact_id: ContactId,
) -> Result<bool> {
    let contact = Contact::get_by_id(context, contact_id).await?;
    let peerstate = match Peerstate::from_addr(context, contact.get_addr()).await {
        Ok(peerstate) => peerstate,
        Err(err) => {
            warn!(
                context,
                "Failed to sender peerstate for {}: {}",
                contact.get_addr(),
                err
            );
            return Ok(false);
        }
    };

    if let Some(mut peerstate) = peerstate {
        if peerstate
            .public_key_fingerprint
            .as_ref()
            .filter(|&fp| fp == fingerprint)
            .is_some()
        {
            if let Some(public_key) = &peerstate.public_key {
                let verifier = contact.get_addr().to_owned();
                peerstate.set_verified(public_key.clone(), fingerprint.clone(), verifier)?;
                peerstate.prefer_encrypt = EncryptPreference::Mutual;
                peerstate.save_to_db(&context.sql).await?;
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// What to do with a Secure-Join handshake message after it was handled.
///
/// This status is returned to [`receive_imf_inner`] which will use it to decide what to do
/// next with this incoming setup-contact/secure-join handshake message.
///
/// [`receive_imf_inner`]: crate::receive_imf::receive_imf_inner
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HandshakeMessage {
    /// The message has been fully handled and should be removed/delete.
    ///
    /// This removes the message both locally and on the IMAP server.
    Done,
    /// The message should be ignored/hidden, but not removed/deleted.
    ///
    /// This leaves it on the IMAP server.  It means other devices on this account can
    /// receive and potentially process this message as well.  This is useful for example
    /// when the other device is running the protocol and has the relevant QR-code
    /// information while this device does not have the joiner state.
    Ignore,
    /// The message should be further processed by incoming message handling.
    ///
    /// This may for example result in a group being created if it is a message which added
    /// us to a group (a `vg-member-added` message).
    Propagate,
}

/// Handle incoming secure-join handshake.
///
/// This function will update the securejoin state in the database as the protocol
/// progresses.
///
/// A message which results in [`Err`] will be hidden from the user but not deleted, it may
/// be a valid message for something else we are not aware off.  E.g. it could be part of a
/// handshake performed by another DC app on the same account.
///
/// When `handle_securejoin_handshake()` is called, the message is not yet filed in the
/// database; this is done by `receive_imf()` later on as needed.
pub(crate) async fn handle_securejoin_handshake(
    context: &Context,
    mime_message: &mut MimeMessage,
    contact_id: ContactId,
) -> Result<HandshakeMessage> {
    if contact_id.is_special() {
        return Err(Error::msg("Can not be called with special contact ID"));
    }
    let step = mime_message
        .get_header(HeaderDef::SecureJoin)
        .context("Not a Secure-Join message")?;

    info!(context, "Received secure-join message {step:?}.");

    let join_vg = step.starts_with("vg-");

    if !matches!(step, "vg-request" | "vc-request") {
        let mut self_found = false;
        let self_fingerprint = load_self_public_key(context).await?.dc_fingerprint();
        for (addr, key) in &mime_message.gossiped_keys {
            if key.dc_fingerprint() == self_fingerprint && context.is_self_addr(addr).await? {
                self_found = true;
                break;
            }
        }
        if !self_found {
            // This message isn't intended for us. Possibly the peer doesn't own the key which the
            // message is signed with but forwarded someone's message to us.
            warn!(context, "Step {step}: No self addr+pubkey gossip found.");
            return Ok(HandshakeMessage::Ignore);
        }
    }

    match step {
        "vg-request" | "vc-request" => {
            /*=======================================================
            ====             Alice - the inviter side            ====
            ====   Step 3 in "Setup verified contact" protocol   ====
            =======================================================*/

            // this message may be unencrypted (Bob, the joiner and the sender, might not have Alice's key yet)
            // it just ensures, we have Bobs key now. If we do _not_ have the key because eg. MitM has removed it,
            // send_message() will fail with the error "End-to-end-encryption unavailable unexpectedly.", so, there is no additional check needed here.
            // verify that the `Secure-Join-Invitenumber:`-header matches invitenumber written to the QR code
            let invitenumber = match mime_message.get_header(HeaderDef::SecureJoinInvitenumber) {
                Some(n) => n,
                None => {
                    warn!(context, "Secure-join denied (invitenumber missing)");
                    return Ok(HandshakeMessage::Ignore);
                }
            };
            if !token::exists(context, token::Namespace::InviteNumber, invitenumber).await? {
                warn!(context, "Secure-join denied (bad invitenumber).");
                return Ok(HandshakeMessage::Ignore);
            }

            inviter_progress(context, contact_id, 300);

            // Alice -> Bob
            send_alice_handshake_msg(
                context,
                contact_id,
                &format!("{}-auth-required", &step.get(..2).unwrap_or_default()),
            )
            .await
            .context("failed sending auth-required handshake message")?;
            Ok(HandshakeMessage::Done)
        }
        "vg-auth-required" | "vc-auth-required" => {
            /*========================================================
            ====             Bob - the joiner's side             =====
            ====   Step 4 in "Setup verified contact" protocol   =====
            ========================================================*/
            bob::handle_auth_required(context, mime_message).await
        }
        "vg-request-with-auth" | "vc-request-with-auth" => {
            /*==========================================================
            ====              Alice - the inviter side              ====
            ====   Steps 5+6 in "Setup verified contact" protocol   ====
            ====  Step 6 in "Out-of-band verified groups" protocol  ====
            ==========================================================*/

            // verify that Secure-Join-Fingerprint:-header matches the fingerprint of Bob
            let Some(fp) = mime_message.get_header(HeaderDef::SecureJoinFingerprint) else {
                warn!(
                    context,
                    "Ignoring {step} message because fingerprint is not provided."
                );
                return Ok(HandshakeMessage::Ignore);
            };
            let fingerprint: Fingerprint = fp.parse()?;
            if !encrypted_and_signed(context, mime_message, &fingerprint) {
                warn!(
                    context,
                    "Ignoring {step} message because the message is not encrypted."
                );
                return Ok(HandshakeMessage::Ignore);
            }
            // verify that the `Secure-Join-Auth:`-header matches the secret written to the QR code
            let Some(auth) = mime_message.get_header(HeaderDef::SecureJoinAuth) else {
                warn!(
                    context,
                    "Ignoring {step} message because of missing auth code."
                );
                return Ok(HandshakeMessage::Ignore);
            };
            let Some(grpid) = token::auth_foreign_key(context, auth).await? else {
                warn!(
                    context,
                    "Ignoring {step} message because of invalid auth code."
                );
                return Ok(HandshakeMessage::Ignore);
            };
            let group_chat_id = match grpid.as_str() {
                "" => None,
                id => {
                    let Some((chat_id, ..)) = get_chat_id_by_grpid(context, id).await? else {
                        warn!(context, "Ignoring {step} message: unknown grpid {id}.",);
                        return Ok(HandshakeMessage::Ignore);
                    };
                    Some(chat_id)
                }
            };

            if !verify_sender_by_fingerprint(context, &fingerprint, contact_id).await? {
                warn!(
                    context,
                    "Ignoring {step} message because of fingerprint mismatch."
                );
                return Ok(HandshakeMessage::Ignore);
            }

            let contact_addr = Contact::get_by_id(context, contact_id)
                .await?
                .get_addr()
                .to_owned();
            let backward_verified = true;
            let fingerprint_found = mark_peer_as_verified(
                context,
                fingerprint.clone(),
                contact_addr,
                backward_verified,
            )
            .await?;
            if !fingerprint_found {
                warn!(
                    context,
                    "Ignoring {step} message because of the failure to find matching peerstate."
                );
                return Ok(HandshakeMessage::Ignore);
            }
            info!(context, "Fingerprint verified via Auth code.",);
            contact_id.regossip_keys(context).await?;
            ContactId::scaleup_origin(context, &[contact_id], Origin::SecurejoinInvited).await?;
            // for setup-contact, make Alice's one-to-one chat with Bob visible
            // (secure-join-information are shown in the group chat)
            if !join_vg {
                ChatId::create_for_contact(context, contact_id).await?;
            }
            context.emit_event(EventType::ContactsChanged(Some(contact_id)));
            inviter_progress(context, contact_id, 600);
            if let Some(group_chat_id) = group_chat_id {
                // Join group.
                secure_connection_established(
                    context,
                    contact_id,
                    group_chat_id,
                    mime_message.timestamp_sent,
                )
                .await?;
                chat::add_contact_to_chat_ex(context, Nosync, group_chat_id, contact_id, true)
                    .await?;
                inviter_progress(context, contact_id, 800);
                inviter_progress(context, contact_id, 1000);
                // IMAP-delete the message to avoid handling it by another device and adding the
                // member twice. Another device will know the member's key from Autocrypt-Gossip.
                Ok(HandshakeMessage::Done)
            } else {
                // Setup verified contact.
                secure_connection_established(
                    context,
                    contact_id,
                    info_chat_id(context, contact_id).await?,
                    mime_message.timestamp_sent,
                )
                .await?;
                send_alice_handshake_msg(context, contact_id, "vc-contact-confirm")
                    .await
                    .context("failed sending vc-contact-confirm message")?;

                inviter_progress(context, contact_id, 1000);
                Ok(HandshakeMessage::Ignore) // "Done" would delete the message and break multi-device (the key from Autocrypt-header is needed)
            }
        }
        /*=======================================================
        ====             Bob - the joiner's side             ====
        ====   Step 7 in "Setup verified contact" protocol   ====
        =======================================================*/
        "vc-contact-confirm" => {
            context.emit_event(EventType::SecurejoinJoinerProgress {
                contact_id,
                progress: JoinerProgress::Succeeded.to_usize(),
            });
            Ok(HandshakeMessage::Ignore)
        }
        "vg-member-added" => {
            let Some(member_added) = mime_message.get_header(HeaderDef::ChatGroupMemberAdded)
            else {
                warn!(
                    context,
                    "vg-member-added without Chat-Group-Member-Added header."
                );
                return Ok(HandshakeMessage::Propagate);
            };
            if !context.is_self_addr(member_added).await? {
                info!(
                    context,
                    "Member {member_added} added by unrelated SecureJoin process."
                );
                return Ok(HandshakeMessage::Propagate);
            }

            // Mark peer as backward verified.
            //
            // This is needed for the case when we join a non-protected group
            // because in this case `Chat-Verified` header that otherwise
            // sets backward verification is not sent.
            if let Some(peerstate) = &mut mime_message.peerstate {
                peerstate.backward_verified_key_id =
                    Some(context.get_config_i64(Config::KeyId).await?).filter(|&id| id > 0);
                peerstate.save_to_db(&context.sql).await?;
            }

            context.emit_event(EventType::SecurejoinJoinerProgress {
                contact_id,
                progress: JoinerProgress::Succeeded.to_usize(),
            });
            Ok(HandshakeMessage::Propagate)
        }

        "vg-member-added-received" | "vc-contact-confirm-received" => {
            // Deprecated steps, delete them immediately.
            Ok(HandshakeMessage::Done)
        }
        _ => {
            warn!(context, "invalid step: {}", step);
            Ok(HandshakeMessage::Ignore)
        }
    }
}

/// Observe self-sent Securejoin message.
///
/// In a multi-device-setup, there may be other devices that "see" the handshake messages.
/// If we see self-sent messages encrypted+signed correctly with our key,
/// we can make some conclusions of it.
///
/// If we see self-sent {vc,vg}-request-with-auth,
/// we know that we are Bob (joiner-observer)
/// that just marked peer (Alice) as forward-verified
/// either after receiving {vc,vg}-auth-required
/// or immediately after scanning the QR-code
/// if the key was already known.
///
/// If we see self-sent vc-contact-confirm or vg-member-added message,
/// we know that we are Alice (inviter-observer)
/// that just marked peer (Bob) as forward (and backward)-verified
/// in response to correct vc-request-with-auth message.
///
/// In both cases we can mark the peer as forward-verified.
pub(crate) async fn observe_securejoin_on_other_device(
    context: &Context,
    mime_message: &MimeMessage,
    contact_id: ContactId,
) -> Result<HandshakeMessage> {
    if contact_id.is_special() {
        return Err(Error::msg("Can not be called with special contact ID"));
    }
    let step = mime_message
        .get_header(HeaderDef::SecureJoin)
        .context("Not a Secure-Join message")?;
    info!(context, "Observing secure-join message {step:?}.");

    if !matches!(
        step,
        "vg-request-with-auth" | "vc-request-with-auth" | "vg-member-added" | "vc-contact-confirm"
    ) {
        return Ok(HandshakeMessage::Ignore);
    };

    if !encrypted_and_signed(context, mime_message, &get_self_fingerprint(context).await?) {
        could_not_establish_secure_connection(
            context,
            contact_id,
            info_chat_id(context, contact_id).await?,
            "Message not encrypted correctly.",
        )
        .await?;
        return Ok(HandshakeMessage::Ignore);
    }

    let addr = Contact::get_by_id(context, contact_id)
        .await?
        .get_addr()
        .to_lowercase();

    let Some(key) = mime_message.gossiped_keys.get(&addr) else {
        could_not_establish_secure_connection(
            context,
            contact_id,
            info_chat_id(context, contact_id).await?,
            &format!(
                "No gossip header for '{}' at step {}, please update Delta Chat on all \
                        your devices.",
                &addr, step,
            ),
        )
        .await?;
        return Ok(HandshakeMessage::Ignore);
    };

    let Some(mut peerstate) = Peerstate::from_addr(context, &addr).await? else {
        could_not_establish_secure_connection(
            context,
            contact_id,
            info_chat_id(context, contact_id).await?,
            &format!("No peerstate in db for '{}' at step {}", &addr, step),
        )
        .await?;
        return Ok(HandshakeMessage::Ignore);
    };

    let Some(fingerprint) = peerstate.gossip_key_fingerprint.clone() else {
        could_not_establish_secure_connection(
            context,
            contact_id,
            info_chat_id(context, contact_id).await?,
            &format!(
                "No gossip key fingerprint in db for '{}' at step {}",
                &addr, step,
            ),
        )
        .await?;
        return Ok(HandshakeMessage::Ignore);
    };
    peerstate.set_verified(key.clone(), fingerprint, addr)?;
    if matches!(step, "vg-member-added" | "vc-contact-confirm") {
        peerstate.backward_verified_key_id =
            Some(context.get_config_i64(Config::KeyId).await?).filter(|&id| id > 0);
    }
    peerstate.prefer_encrypt = EncryptPreference::Mutual;
    peerstate.save_to_db(&context.sql).await?;

    ChatId::set_protection_for_contact(context, contact_id, mime_message.timestamp_sent).await?;

    if step == "vg-member-added" {
        inviter_progress(context, contact_id, 800);
    }
    if step == "vg-member-added" || step == "vc-contact-confirm" {
        inviter_progress(context, contact_id, 1000);
    }

    if step == "vg-request-with-auth" || step == "vc-request-with-auth" {
        // This actually reflects what happens on the first device (which does the secure
        // join) and causes a subsequent "vg-member-added" message to create an unblocked
        // verified group.
        ChatId::create_for_contact_with_blocked(context, contact_id, Blocked::Not).await?;
    }

    if step == "vg-member-added" {
        Ok(HandshakeMessage::Propagate)
    } else {
        Ok(HandshakeMessage::Ignore)
    }
}

async fn secure_connection_established(
    context: &Context,
    contact_id: ContactId,
    chat_id: ChatId,
    timestamp: i64,
) -> Result<()> {
    let private_chat_id = ChatIdBlocked::get_for_contact(context, contact_id, Blocked::Yes)
        .await?
        .id;
    private_chat_id
        .set_protection(
            context,
            ProtectionStatus::Protected,
            timestamp,
            Some(contact_id),
        )
        .await?;
    context.emit_event(EventType::ChatModified(chat_id));
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    Ok(())
}

async fn could_not_establish_secure_connection(
    context: &Context,
    contact_id: ContactId,
    chat_id: ChatId,
    details: &str,
) -> Result<()> {
    let contact = Contact::get_by_id(context, contact_id).await?;
    let mut msg = stock_str::contact_not_verified(context, &contact).await;
    msg += " (";
    msg += details;
    msg += ")";
    chat::add_info_msg(context, chat_id, &msg, time()).await?;
    warn!(
        context,
        "StockMessage::ContactNotVerified posted to 1:1 chat ({})", details
    );
    Ok(())
}

/// Tries to mark peer with provided key fingerprint as verified.
///
/// Returns true if such key was found, false otherwise.
async fn mark_peer_as_verified(
    context: &Context,
    fingerprint: Fingerprint,
    verifier: String,
    backward_verified: bool,
) -> Result<bool> {
    let Some(ref mut peerstate) = Peerstate::from_fingerprint(context, &fingerprint).await? else {
        return Ok(false);
    };
    let Some(ref public_key) = peerstate.public_key else {
        return Ok(false);
    };
    peerstate.set_verified(public_key.clone(), fingerprint, verifier)?;
    peerstate.prefer_encrypt = EncryptPreference::Mutual;
    if backward_verified {
        peerstate.backward_verified_key_id =
            Some(context.get_config_i64(Config::KeyId).await?).filter(|&id| id > 0);
    }
    peerstate.save_to_db(&context.sql).await?;
    Ok(true)
}

/* ******************************************************************************
 * Tools: Misc.
 ******************************************************************************/

fn encrypted_and_signed(
    context: &Context,
    mimeparser: &MimeMessage,
    expected_fingerprint: &Fingerprint,
) -> bool {
    if !mimeparser.was_encrypted() {
        warn!(context, "Message not encrypted.",);
        false
    } else if !mimeparser.signatures.contains(expected_fingerprint) {
        warn!(
            context,
            "Message does not match expected fingerprint {}.", expected_fingerprint,
        );
        false
    } else {
        true
    }
}

#[cfg(test)]
mod securejoin_tests;
