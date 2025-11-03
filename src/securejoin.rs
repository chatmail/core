//! Implementation of [SecureJoin protocols](https://securejoin.delta.chat/).

use anyhow::{Context as _, Error, Result, bail, ensure};
use deltachat_contact_tools::ContactAddress;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};

use crate::chat::{self, Chat, ChatId, ChatIdBlocked, get_chat_id_by_grpid};
use crate::config::Config;
use crate::constants::{Blocked, Chattype, NON_ALPHANUMERIC_WITHOUT_DOT};
use crate::contact::mark_contact_id_as_verified;
use crate::contact::{Contact, ContactId, Origin};
use crate::context::Context;
use crate::e2ee::ensure_secret_key_exists;
use crate::events::EventType;
use crate::headerdef::HeaderDef;
use crate::key::{DcKey, Fingerprint, load_self_public_key};
use crate::log::LogExt as _;
use crate::log::{error, info, warn};
use crate::message::{Message, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::Param;
use crate::qr::check_qr;
use crate::securejoin::bob::JoinerProgress;
use crate::sync::Sync::*;
use crate::tools::{create_id, time};
use crate::{SecurejoinSource, stats};
use crate::{SecurejoinUiPath, token};

mod bob;
mod qrinvite;

pub(crate) use qrinvite::QrInvite;

use crate::token::Namespace;

/// Only new QR codes cause a verification on Alice's side.
/// When a QR code is too old, it is assumed that there was no direct QR scan,
/// and that the QR code was potentially published on a website,
/// so, Alice doesn't mark Bob as verified.
// TODO For backwards compatibility reasons, this is still using a rather large value.
// Set this to a lower value (e.g. 10 minutes)
// when Delta Chat v2.22.0 is sufficiently rolled out
const VERIFICATION_TIMEOUT_SECONDS: i64 = 7 * 24 * 3600;

fn inviter_progress(
    context: &Context,
    contact_id: ContactId,
    chat_id: ChatId,
    chat_type: Chattype,
) -> Result<()> {
    // No other values are used.
    let progress = 1000;
    context.emit_event(EventType::SecurejoinInviterProgress {
        contact_id,
        chat_id,
        chat_type,
        progress,
    });

    Ok(())
}

/// Generates a Secure Join QR code.
///
/// With `chat` set to `None` this generates a setup-contact QR code, with `chat` set to a
/// [`ChatId`] generates a join-group/join-broadcast-channel QR code for the given chat.
pub async fn get_securejoin_qr(context: &Context, chat: Option<ChatId>) -> Result<String> {
    /*=======================================================
    ====             Alice - the inviter side            ====
    ====   Step 1 in "Setup verified contact" protocol   ====
    =======================================================*/

    ensure_secret_key_exists(context).await.ok();

    let chat = match chat {
        Some(id) => {
            let chat = Chat::load_from_db(context, id).await?;
            ensure!(
                chat.typ == Chattype::Group || chat.typ == Chattype::OutBroadcast,
                "Can't generate SecureJoin QR code for chat {id} of type {}",
                chat.typ
            );
            if chat.grpid.is_empty() {
                let err = format!("Can't generate QR code, chat {id} is a email thread");
                error!(context, "get_securejoin_qr: {}.", err);
                bail!(err);
            }
            Some(chat)
        }
        None => None,
    };
    let grpid = chat.as_ref().map(|c| c.grpid.as_str());
    let sync_token = token::lookup(context, Namespace::InviteNumber, grpid)
        .await?
        .is_none();
    // Invite number is used to request the inviter key.
    let invitenumber = token::lookup_or_new(context, Namespace::InviteNumber, grpid).await?;

    // Auth token is used to verify the key-contact
    // if the token is not old
    // and add the contact to the group
    // if there is an associated group ID.
    //
    // We always generate a new auth token
    // because auth tokens "expire"
    // and can only be used to join groups
    // without verification afterwards.
    let auth = create_id();
    token::save(context, Namespace::Auth, grpid, &auth, time()).await?;

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
        if sync_token {
            context
                .sync_qr_code_tokens(Some(chat.grpid.as_str()))
                .await?;
            context.scheduler.interrupt_inbox().await;
        }

        let chat_name = chat.get_name();
        let chat_name_urlencoded = utf8_percent_encode(chat_name, NON_ALPHANUMERIC).to_string();
        if chat.typ == Chattype::OutBroadcast {
            // For historic reansons, broadcasts currently use j instead of i for the invitenumber.
            format!(
                "https://i.delta.chat/#{}&a={}&b={}&x={}&j={}&s={}",
                fingerprint.hex(),
                self_addr_urlencoded,
                &chat_name_urlencoded,
                &chat.grpid,
                &invitenumber,
                &auth,
            )
        } else {
            format!(
                "https://i.delta.chat/#{}&a={}&g={}&x={}&i={}&s={}",
                fingerprint.hex(),
                self_addr_urlencoded,
                &chat_name_urlencoded,
                &chat.grpid,
                &invitenumber,
                &auth,
            )
        }
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
    join_securejoin_with_ux_info(context, qr, None, None).await
}

/// Take a scanned QR-code and do the setup-contact/join-group/invite handshake.
///
/// This is the start of the process for the joiner.  See the module and ffi documentation
/// for more details.
///
/// The function returns immediately and the handshake will run in background.
///
/// **source** and **uipath** are for statistics-sending,
/// if the user enabled it in the settings;
/// if you don't have statistics-sending implemented, just pass `None` here.
pub async fn join_securejoin_with_ux_info(
    context: &Context,
    qr: &str,
    source: Option<SecurejoinSource>,
    uipath: Option<SecurejoinUiPath>,
) -> Result<ChatId> {
    let res = securejoin(context, qr).await.map_err(|err| {
        warn!(context, "Fatal joiner error: {:#}", err);
        // The user just scanned this QR code so has context on what failed.
        error!(context, "QR process failed");
        err
    })?;

    stats::count_securejoin_ux_info(context, source, uipath)
        .await
        .log_err(context)
        .ok();

    Ok(res)
}

async fn securejoin(context: &Context, qr: &str) -> Result<ChatId> {
    /*========================================================
    ====             Bob - the joiner's side             =====
    ====   Step 2 in "Setup verified contact" protocol   =====
    ========================================================*/

    info!(context, "Requesting secure-join ...",);
    let qr_scan = check_qr(context, qr).await?;

    let invite = QrInvite::try_from(qr_scan)?;

    stats::count_securejoin_invite(context, &invite)
        .await
        .log_err(context)
        .ok();

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

/// Checks fingerprint and marks the contact as verified
/// if fingerprint matches.
async fn verify_sender_by_fingerprint(
    context: &Context,
    fingerprint: &Fingerprint,
    contact_id: ContactId,
) -> Result<bool> {
    let contact = Contact::get_by_id(context, contact_id).await?;
    let is_verified = contact.fingerprint().is_some_and(|fp| &fp == fingerprint);
    if is_verified {
        mark_contact_id_as_verified(context, contact_id, Some(ContactId::SELF)).await?;
    }
    Ok(is_verified)
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

    // Opportunistically protect against a theoretical 'surreptitious forwarding' attack:
    // If Eve obtains a QR code from Alice and starts a securejoin with her,
    // and also lets Bob scan a manipulated QR code,
    // she could reencrypt the v*-request-with-auth message to Bob while maintaining the signature,
    // and Bob would regard the message as valid.
    //
    // This attack is not actually relevant in any threat model,
    // because if Eve can see Alice's QR code and have Bob scan a manipulated QR code,
    // she can just do a classical MitM attack.
    //
    // Protecting all messages sent by Delta Chat against 'surreptitious forwarding'
    // by checking the 'intended recipient fingerprint'
    // will improve security (completely unrelated to the securejoin protocol)
    // and is something we want to do in the future:
    // https://www.rfc-editor.org/rfc/rfc9580.html#name-surreptitious-forwarding
    if !matches!(step, "vg-request" | "vc-request") {
        let mut self_found = false;
        let self_fingerprint = load_self_public_key(context).await?.dc_fingerprint();
        for (addr, key) in &mime_message.gossiped_keys {
            if key.public_key.dc_fingerprint() == self_fingerprint
                && context.is_self_addr(addr).await?
            {
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

            let from_addr = ContactAddress::new(&mime_message.from.addr)?;
            let autocrypt_fingerprint = mime_message.autocrypt_fingerprint.as_deref().unwrap_or("");
            let (autocrypt_contact_id, _) = Contact::add_or_lookup_ex(
                context,
                "",
                &from_addr,
                autocrypt_fingerprint,
                Origin::IncomingUnknownFrom,
            )
            .await?;

            // Alice -> Bob
            send_alice_handshake_msg(
                context,
                autocrypt_contact_id,
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
            let Some((grpid, timestamp)) = context
                .sql
                .query_row_optional(
                    "SELECT foreign_key, timestamp FROM tokens WHERE namespc=? AND token=?",
                    (Namespace::Auth, auth),
                    |row| {
                        let foreign_key: String = row.get(0)?;
                        let timestamp: i64 = row.get(1)?;
                        Ok((foreign_key, timestamp))
                    },
                )
                .await?
            else {
                warn!(
                    context,
                    "Ignoring {step} message because of invalid auth code."
                );
                return Ok(HandshakeMessage::Ignore);
            };
            let joining_chat_id = match grpid.as_str() {
                "" => None,
                id => {
                    let Some((chat_id, ..)) = get_chat_id_by_grpid(context, id).await? else {
                        warn!(context, "Ignoring {step} message: unknown grpid {id}.",);
                        return Ok(HandshakeMessage::Ignore);
                    };
                    Some(chat_id)
                }
            };

            let sender_contact = Contact::get_by_id(context, contact_id).await?;
            if sender_contact
                .fingerprint()
                .is_none_or(|fp| fp != fingerprint)
            {
                warn!(
                    context,
                    "Ignoring {step} message because of fingerprint mismatch."
                );
                return Ok(HandshakeMessage::Ignore);
            }
            info!(context, "Fingerprint verified via Auth code.",);

            // Mark the contact as verified if auth code is less than VERIFICATION_TIMEOUT_SECONDS seconds old.
            if time() < timestamp + VERIFICATION_TIMEOUT_SECONDS {
                mark_contact_id_as_verified(context, contact_id, Some(ContactId::SELF)).await?;
            }
            contact_id.regossip_keys(context).await?;
            ContactId::scaleup_origin(context, &[contact_id], Origin::SecurejoinInvited).await?;
            // for setup-contact, make Alice's one-to-one chat with Bob visible
            // (secure-join-information are shown in the group chat)
            if grpid.is_empty() {
                ChatId::create_for_contact(context, contact_id).await?;
            }
            context.emit_event(EventType::ContactsChanged(Some(contact_id)));
            if let Some(joining_chat_id) = joining_chat_id {
                // Join group.
                chat::add_contact_to_chat_ex(context, Nosync, joining_chat_id, contact_id, true)
                    .await?;
                let chat = Chat::load_from_db(context, joining_chat_id).await?;

                inviter_progress(context, contact_id, joining_chat_id, chat.typ)?;
                // IMAP-delete the message to avoid handling it by another device and adding the
                // member twice. Another device will know the member's key from Autocrypt-Gossip.
                Ok(HandshakeMessage::Done)
            } else {
                let chat_id = info_chat_id(context, contact_id).await?;
                // Setup verified contact.
                send_alice_handshake_msg(context, contact_id, "vc-contact-confirm")
                    .await
                    .context("failed sending vc-contact-confirm message")?;

                inviter_progress(context, contact_id, chat_id, Chattype::Single)?;
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
/// that just marked peer (Alice) as verified
/// either after receiving {vc,vg}-auth-required
/// or immediately after scanning the QR-code
/// if the key was already known.
///
/// If we see self-sent vc-contact-confirm or vg-member-added message,
/// we know that we are Alice (inviter-observer)
/// that just marked peer (Bob) as verified
/// in response to correct vc-request-with-auth message.
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
        warn!(
            context,
            "Observed SecureJoin message is not encrypted correctly."
        );
        return Ok(HandshakeMessage::Ignore);
    }

    let contact = Contact::get_by_id(context, contact_id).await?;
    let addr = contact.get_addr().to_lowercase();

    let Some(key) = mime_message.gossiped_keys.get(&addr) else {
        warn!(context, "No gossip header for {addr} at step {step}.");
        return Ok(HandshakeMessage::Ignore);
    };

    let Some(contact_fingerprint) = contact.fingerprint() else {
        // Not a key-contact, should not happen.
        warn!(context, "Contact does not have a fingerprint.");
        return Ok(HandshakeMessage::Ignore);
    };

    if key.public_key.dc_fingerprint() != contact_fingerprint {
        // Fingerprint does not match, ignore.
        warn!(context, "Fingerprint does not match.");
        return Ok(HandshakeMessage::Ignore);
    }

    mark_contact_id_as_verified(context, contact_id, Some(ContactId::SELF)).await?;

    if step == "vg-member-added" || step == "vc-contact-confirm" {
        let chat_type = if mime_message
            .get_header(HeaderDef::ChatGroupMemberAdded)
            .is_none()
        {
            Chattype::Single
        } else if mime_message.get_header(HeaderDef::ListId).is_some() {
            Chattype::OutBroadcast
        } else {
            Chattype::Group
        };

        // We don't know the chat ID
        // as we may not know about the group yet.
        //
        // Event is mostly used for bots
        // which only have a single device
        // and tests which don't care about the chat ID,
        // so we pass invalid chat ID here.
        let chat_id = ChatId::new(0);
        inviter_progress(context, contact_id, chat_id, chat_type)?;
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

/* ******************************************************************************
 * Tools: Misc.
 ******************************************************************************/

fn encrypted_and_signed(
    context: &Context,
    mimeparser: &MimeMessage,
    expected_fingerprint: &Fingerprint,
) -> bool {
    if let Some(signature) = mimeparser.signature.as_ref() {
        if signature == expected_fingerprint {
            true
        } else {
            warn!(
                context,
                "Message does not match expected fingerprint {expected_fingerprint}.",
            );
            false
        }
    } else {
        warn!(context, "Message not encrypted.",);
        false
    }
}

#[cfg(test)]
mod securejoin_tests;
