//! Internet Message Format reception pipeline.

use std::collections::{HashMap, HashSet};
use std::iter;
use std::sync::LazyLock;

use anyhow::{Context as _, Result, ensure};
use data_encoding::BASE32_NOPAD;
use deltachat_contact_tools::{
    ContactAddress, addr_cmp, addr_normalize, may_be_valid_addr, sanitize_single_line,
};
use iroh_gossip::proto::TopicId;
use mailparse::SingleInfo;
use num_traits::FromPrimitive;
use regex::Regex;

use crate::chat::{
    self, Chat, ChatId, ChatIdBlocked, ProtectionStatus, remove_from_chat_contacts_table,
};
use crate::config::Config;
use crate::constants::{self, Blocked, Chattype, DC_CHAT_ID_TRASH, EDITED_PREFIX, ShowEmails};
use crate::contact::{Contact, ContactId, Origin, mark_contact_id_as_verified};
use crate::context::Context;
use crate::debug_logging::maybe_set_logging_xdc_inner;
use crate::download::DownloadState;
use crate::ephemeral::{Timer as EphemeralTimer, stock_ephemeral_timer_changed};
use crate::events::EventType;
use crate::headerdef::{HeaderDef, HeaderDefMap};
use crate::imap::{GENERATED_PREFIX, markseen_on_imap_table};
use crate::key::self_fingerprint_opt;
use crate::key::{DcKey, Fingerprint, SignedPublicKey};
use crate::log::LogExt;
use crate::log::{info, warn};
use crate::logged_debug_assert;
use crate::message::{
    self, Message, MessageState, MessengerMessage, MsgId, Viewtype, rfc724_mid_exists,
};
use crate::mimeparser::{AvatarAction, MimeMessage, SystemMessage, parse_message_ids};
use crate::param::{Param, Params};
use crate::peer_channels::{add_gossip_peer_from_header, insert_topic_stub};
use crate::reaction::{Reaction, set_msg_reaction};
use crate::rusqlite::OptionalExtension;
use crate::securejoin::{self, handle_securejoin_handshake, observe_securejoin_on_other_device};
use crate::simplify;
use crate::stock_str;
use crate::sync::Sync::*;
use crate::tools::{self, buf_compress, remove_subject_prefix};
use crate::{chatlist_events, ensure_and_debug_assert, ensure_and_debug_assert_eq, location};
use crate::{contact, imap};

/// This is the struct that is returned after receiving one email (aka MIME message).
///
/// One email with multiple attachments can end up as multiple chat messages, but they
/// all have the same chat_id, state and sort_timestamp.
#[derive(Debug)]
pub struct ReceivedMsg {
    /// Chat the message is assigned to.
    pub chat_id: ChatId,

    /// Received message state.
    pub state: MessageState,

    /// Whether the message is hidden.
    pub hidden: bool,

    /// Message timestamp for sorting.
    pub sort_timestamp: i64,

    /// IDs of inserted rows in messages table.
    pub msg_ids: Vec<MsgId>,

    /// Whether IMAP messages should be immediately deleted.
    pub needs_delete_job: bool,
}

/// Decision on which kind of chat the message
/// should be assigned in.
///
/// This is done before looking up contact IDs
/// so we know in advance whether to lookup
/// key-contacts or email address contacts.
///
/// Once this decision is made,
/// it should not be changed so we
/// don't assign the message to an encrypted
/// group after looking up key-contacts
/// or vice versa.
#[derive(Debug)]
enum ChatAssignment {
    /// Trash the message.
    Trash,

    /// Group chat with a Group ID.
    ///
    /// Lookup key-contacts and
    /// assign to encrypted group.
    GroupChat { grpid: String },

    /// Mailing list or broadcast channel.
    ///
    /// Mailing lists don't have members.
    /// Broadcast channels have members
    /// on the sender side,
    /// but their addresses don't go into
    /// the `To` field.
    ///
    /// In any case, the `To`
    /// field should be ignored
    /// and no contact IDs should be looked
    /// up except the `from_id`
    /// which may be an email address contact
    /// or a key-contact.
    MailingListOrBroadcast,

    /// Group chat without a Group ID.
    ///
    /// This is not encrypted.
    AdHocGroup,

    /// Assign the message to existing chat
    /// with a known `chat_id`.
    ExistingChat {
        /// ID of existing chat
        /// which the message should be assigned to.
        chat_id: ChatId,

        /// Whether existing chat is blocked.
        /// This is loaded together with a chat ID
        /// reduce the number of database calls.
        ///
        /// We may want to unblock the chat
        /// after adding the message there
        /// if the chat is currently blocked.
        chat_id_blocked: Blocked,
    },

    /// 1:1 chat with a single contact.
    ///
    /// The chat may be encrypted or not,
    /// it does not matter.
    /// It is not possible to mix
    /// email address contacts
    /// with key-contacts in a single 1:1 chat anyway.
    OneOneChat,
}

/// Emulates reception of a message from the network.
///
/// This method returns errors on a failure to parse the mail or extract Message-ID. It's only used
/// for tests and REPL tool, not actual message reception pipeline.
#[cfg(any(test, feature = "internals"))]
pub async fn receive_imf(
    context: &Context,
    imf_raw: &[u8],
    seen: bool,
) -> Result<Option<ReceivedMsg>> {
    let mail = mailparse::parse_mail(imf_raw).context("can't parse mail")?;
    let rfc724_mid =
        imap::prefetch_get_message_id(&mail.headers).unwrap_or_else(imap::create_message_id);
    if let Some(download_limit) = context.download_limit().await? {
        let download_limit: usize = download_limit.try_into()?;
        if imf_raw.len() > download_limit {
            let head = std::str::from_utf8(imf_raw)?
                .split("\r\n\r\n")
                .next()
                .context("No empty line in the message")?;
            return receive_imf_from_inbox(
                context,
                &rfc724_mid,
                head.as_bytes(),
                seen,
                Some(imf_raw.len().try_into()?),
            )
            .await;
        }
    }
    receive_imf_from_inbox(context, &rfc724_mid, imf_raw, seen, None).await
}

/// Emulates reception of a message from "INBOX".
///
/// Only used for tests and REPL tool, not actual message reception pipeline.
#[cfg(any(test, feature = "internals"))]
pub(crate) async fn receive_imf_from_inbox(
    context: &Context,
    rfc724_mid: &str,
    imf_raw: &[u8],
    seen: bool,
    is_partial_download: Option<u32>,
) -> Result<Option<ReceivedMsg>> {
    receive_imf_inner(
        context,
        "INBOX",
        0,
        0,
        rfc724_mid,
        imf_raw,
        seen,
        is_partial_download,
    )
    .await
}

/// Inserts a tombstone into `msgs` table
/// to prevent downloading the same message in the future.
///
/// Returns tombstone database row ID.
async fn insert_tombstone(context: &Context, rfc724_mid: &str) -> Result<MsgId> {
    let row_id = context
        .sql
        .insert(
            "INSERT INTO msgs(rfc724_mid, chat_id) VALUES (?,?)",
            (rfc724_mid, DC_CHAT_ID_TRASH),
        )
        .await?;
    let msg_id = MsgId::new(u32::try_from(row_id)?);
    Ok(msg_id)
}

async fn get_to_and_past_contact_ids(
    context: &Context,
    mime_parser: &MimeMessage,
    chat_assignment: &ChatAssignment,
    is_partial_download: Option<u32>,
    parent_message: &Option<Message>,
    incoming_origin: Origin,
) -> Result<(Vec<Option<ContactId>>, Vec<Option<ContactId>>)> {
    // `None` means that the chat is encrypted,
    // but we were not able to convert the address
    // to key-contact, e.g.
    // because there was no corresponding
    // Autocrypt-Gossip header.
    //
    // This way we still preserve remaining
    // number of contacts and their positions
    // so we can match the contacts to
    // e.g. Chat-Group-Member-Timestamps
    // header.
    let to_ids: Vec<Option<ContactId>>;
    let past_ids: Vec<Option<ContactId>>;

    // ID of the chat to look up the addresses in.
    //
    // Note that this is not necessarily the chat we want to assign the message to.
    // In case of an outgoing private reply to a group message we may
    // lookup the address of receipient in the list of addresses used in the group,
    // but want to assign the message to 1:1 chat.
    let chat_id = match chat_assignment {
        ChatAssignment::Trash => None,
        ChatAssignment::GroupChat { grpid } => {
            if let Some((chat_id, _protected, _blocked)) =
                chat::get_chat_id_by_grpid(context, grpid).await?
            {
                Some(chat_id)
            } else {
                None
            }
        }
        ChatAssignment::AdHocGroup => {
            // If we are going to assign a message to ad hoc group,
            // we can just convert the email addresses
            // to e-mail address contacts and don't need a `ChatId`
            // to lookup key-contacts.
            None
        }
        ChatAssignment::ExistingChat { chat_id, .. } => Some(*chat_id),
        ChatAssignment::MailingListOrBroadcast => None,
        ChatAssignment::OneOneChat => {
            if is_partial_download.is_none() && !mime_parser.incoming {
                parent_message.as_ref().map(|m| m.chat_id)
            } else {
                None
            }
        }
    };

    let member_fingerprints = mime_parser.chat_group_member_fingerprints();
    let to_member_fingerprints;
    let past_member_fingerprints;

    if !member_fingerprints.is_empty() {
        if member_fingerprints.len() >= mime_parser.recipients.len() {
            (to_member_fingerprints, past_member_fingerprints) =
                member_fingerprints.split_at(mime_parser.recipients.len());
        } else {
            warn!(
                context,
                "Unexpected length of the fingerprint header, expected at least {}, got {}.",
                mime_parser.recipients.len(),
                member_fingerprints.len()
            );
            to_member_fingerprints = &[];
            past_member_fingerprints = &[];
        }
    } else {
        to_member_fingerprints = &[];
        past_member_fingerprints = &[];
    }

    match chat_assignment {
        ChatAssignment::GroupChat { .. } => {
            to_ids = add_or_lookup_key_contacts(
                context,
                &mime_parser.recipients,
                &mime_parser.gossiped_keys,
                to_member_fingerprints,
                Origin::Hidden,
            )
            .await?;

            if let Some(chat_id) = chat_id {
                past_ids = lookup_key_contacts_by_address_list(
                    context,
                    &mime_parser.past_members,
                    past_member_fingerprints,
                    Some(chat_id),
                )
                .await?;
            } else {
                past_ids = add_or_lookup_key_contacts(
                    context,
                    &mime_parser.past_members,
                    &mime_parser.gossiped_keys,
                    past_member_fingerprints,
                    Origin::Hidden,
                )
                .await?;
            }
        }
        ChatAssignment::Trash | ChatAssignment::MailingListOrBroadcast => {
            to_ids = Vec::new();
            past_ids = Vec::new();
        }
        ChatAssignment::ExistingChat { chat_id, .. } => {
            let chat = Chat::load_from_db(context, *chat_id).await?;
            if chat.is_encrypted(context).await? {
                to_ids = add_or_lookup_key_contacts(
                    context,
                    &mime_parser.recipients,
                    &mime_parser.gossiped_keys,
                    to_member_fingerprints,
                    Origin::Hidden,
                )
                .await?;
                past_ids = lookup_key_contacts_by_address_list(
                    context,
                    &mime_parser.past_members,
                    past_member_fingerprints,
                    Some(*chat_id),
                )
                .await?;
            } else {
                to_ids = add_or_lookup_contacts_by_address_list(
                    context,
                    &mime_parser.recipients,
                    if !mime_parser.incoming {
                        Origin::OutgoingTo
                    } else if incoming_origin.is_known() {
                        Origin::IncomingTo
                    } else {
                        Origin::IncomingUnknownTo
                    },
                )
                .await?;

                past_ids = add_or_lookup_contacts_by_address_list(
                    context,
                    &mime_parser.past_members,
                    Origin::Hidden,
                )
                .await?;
            }
        }
        ChatAssignment::AdHocGroup => {
            to_ids = add_or_lookup_contacts_by_address_list(
                context,
                &mime_parser.recipients,
                if !mime_parser.incoming {
                    Origin::OutgoingTo
                } else if incoming_origin.is_known() {
                    Origin::IncomingTo
                } else {
                    Origin::IncomingUnknownTo
                },
            )
            .await?;

            past_ids = add_or_lookup_contacts_by_address_list(
                context,
                &mime_parser.past_members,
                Origin::Hidden,
            )
            .await?;
        }
        ChatAssignment::OneOneChat => {
            let pgp_to_ids = add_or_lookup_key_contacts(
                context,
                &mime_parser.recipients,
                &mime_parser.gossiped_keys,
                to_member_fingerprints,
                Origin::Hidden,
            )
            .await?;
            if pgp_to_ids
                .first()
                .is_some_and(|contact_id| contact_id.is_some())
            {
                // There is a single recipient and we have
                // mapped it to a key contact.
                // This is an encrypted 1:1 chat.
                to_ids = pgp_to_ids
            } else if let Some(chat_id) = chat_id {
                to_ids = match mime_parser.was_encrypted() {
                    true => {
                        lookup_key_contacts_by_address_list(
                            context,
                            &mime_parser.recipients,
                            to_member_fingerprints,
                            Some(chat_id),
                        )
                        .await?
                    }
                    false => {
                        add_or_lookup_contacts_by_address_list(
                            context,
                            &mime_parser.recipients,
                            if !mime_parser.incoming {
                                Origin::OutgoingTo
                            } else if incoming_origin.is_known() {
                                Origin::IncomingTo
                            } else {
                                Origin::IncomingUnknownTo
                            },
                        )
                        .await?
                    }
                }
            } else {
                let ids = match mime_parser.was_encrypted() {
                    true => {
                        lookup_key_contacts_by_address_list(
                            context,
                            &mime_parser.recipients,
                            to_member_fingerprints,
                            None,
                        )
                        .await?
                    }
                    false => vec![],
                };
                if mime_parser.was_encrypted() && !ids.contains(&None)
                // Prefer creating PGP chats if there are any key-contacts. At least this prevents
                // from replying unencrypted.
                || ids
                    .iter()
                    .any(|&c| c.is_some() && c != Some(ContactId::SELF))
                {
                    to_ids = ids;
                } else {
                    to_ids = add_or_lookup_contacts_by_address_list(
                        context,
                        &mime_parser.recipients,
                        if !mime_parser.incoming {
                            Origin::OutgoingTo
                        } else if incoming_origin.is_known() {
                            Origin::IncomingTo
                        } else {
                            Origin::IncomingUnknownTo
                        },
                    )
                    .await?;
                }
            }

            past_ids = add_or_lookup_contacts_by_address_list(
                context,
                &mime_parser.past_members,
                Origin::Hidden,
            )
            .await?;
        }
    };

    Ok((to_ids, past_ids))
}

/// Receive a message and add it to the database.
///
/// Returns an error on database failure or if the message is broken,
/// e.g. has nonstandard MIME structure.
///
/// If possible, creates a database entry to prevent the message from being
/// downloaded again, sets `chat_id=DC_CHAT_ID_TRASH` and returns `Ok(Some(…))`.
/// If the message is so wrong that we didn't even create a database entry,
/// returns `Ok(None)`.
///
/// If `is_partial_download` is set, it contains the full message size in bytes.
/// Do not confuse that with `replace_msg_id` that will be set when the full message is loaded
/// later.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn receive_imf_inner(
    context: &Context,
    folder: &str,
    uidvalidity: u32,
    uid: u32,
    rfc724_mid: &str,
    imf_raw: &[u8],
    seen: bool,
    is_partial_download: Option<u32>,
) -> Result<Option<ReceivedMsg>> {
    if std::env::var(crate::DCC_MIME_DEBUG).is_ok() {
        info!(
            context,
            "receive_imf: incoming message mime-body:\n{}",
            String::from_utf8_lossy(imf_raw),
        );
    }

    let mut mime_parser = match MimeMessage::from_bytes(context, imf_raw, is_partial_download).await
    {
        Err(err) => {
            warn!(context, "receive_imf: can't parse MIME: {err:#}.");
            if rfc724_mid.starts_with(GENERATED_PREFIX) {
                // We don't have an rfc724_mid, there's no point in adding a trash entry
                return Ok(None);
            }

            let msg_ids = vec![insert_tombstone(context, rfc724_mid).await?];

            return Ok(Some(ReceivedMsg {
                chat_id: DC_CHAT_ID_TRASH,
                state: MessageState::Undefined,
                hidden: false,
                sort_timestamp: 0,
                msg_ids,
                needs_delete_job: false,
            }));
        }
        Ok(mime_parser) => mime_parser,
    };

    let rfc724_mid_orig = &mime_parser
        .get_rfc724_mid()
        .unwrap_or(rfc724_mid.to_string());
    info!(
        context,
        "Receiving message {rfc724_mid_orig:?}, seen={seen}...",
    );

    // check, if the mail is already in our database.
    // make sure, this check is done eg. before securejoin-processing.
    let (replace_msg_id, replace_chat_id);
    if let Some((old_msg_id, _)) = message::rfc724_mid_exists(context, rfc724_mid).await? {
        if is_partial_download.is_some() {
            // Should never happen, see imap::prefetch_should_download(), but still.
            info!(
                context,
                "Got a partial download and message is already in DB."
            );
            return Ok(None);
        }
        let msg = Message::load_from_db(context, old_msg_id).await?;
        replace_msg_id = Some(old_msg_id);
        replace_chat_id = if msg.download_state() != DownloadState::Done {
            // the message was partially downloaded before and is fully downloaded now.
            info!(
                context,
                "Message already partly in DB, replacing by full message."
            );
            Some(msg.chat_id)
        } else {
            None
        };
    } else {
        replace_msg_id = if rfc724_mid_orig == rfc724_mid {
            None
        } else if let Some((old_msg_id, old_ts_sent)) =
            message::rfc724_mid_exists(context, rfc724_mid_orig).await?
        {
            if imap::is_dup_msg(
                mime_parser.has_chat_version(),
                mime_parser.timestamp_sent,
                old_ts_sent,
            ) {
                info!(context, "Deleting duplicate message {rfc724_mid_orig}.");
                let target = context.get_delete_msgs_target().await?;
                context
                    .sql
                    .execute(
                        "UPDATE imap SET target=? WHERE folder=? AND uidvalidity=? AND uid=?",
                        (target, folder, uidvalidity, uid),
                    )
                    .await?;
            }
            Some(old_msg_id)
        } else {
            None
        };
        replace_chat_id = None;
    }

    if replace_chat_id.is_some() {
        // Need to update chat id in the db.
    } else if let Some(msg_id) = replace_msg_id {
        info!(context, "Message is already downloaded.");
        if mime_parser.incoming {
            return Ok(None);
        }
        // For the case if we missed a successful SMTP response. Be optimistic that the message is
        // delivered also.
        let self_addr = context.get_primary_self_addr().await?;
        context
            .sql
            .execute(
                "DELETE FROM smtp \
                WHERE rfc724_mid=?1 AND (recipients LIKE ?2 OR recipients LIKE ('% ' || ?2))",
                (rfc724_mid_orig, &self_addr),
            )
            .await?;
        if !context
            .sql
            .exists(
                "SELECT COUNT(*) FROM smtp WHERE rfc724_mid=?",
                (rfc724_mid_orig,),
            )
            .await?
        {
            msg_id.set_delivered(context).await?;
        }
        return Ok(None);
    };

    let prevent_rename = should_prevent_rename(&mime_parser);

    // get From: (it can be an address list!) and check if it is known (for known From:'s we add
    // the other To:/Cc: in the 3rd pass)
    // or if From: is equal to SELF (in this case, it is any outgoing messages,
    // we do not check Return-Path any more as this is unreliable, see
    // <https://github.com/deltachat/deltachat-core/issues/150>)
    //
    // If this is a mailing list email (i.e. list_id_header is some), don't change the displayname because in
    // a mailing list the sender displayname sometimes does not belong to the sender email address.
    // For example, GitHub sends messages from `notifications@github.com`,
    // but uses display name of the user whose action generated the notification
    // as the display name.
    let fingerprint = mime_parser.signatures.iter().next();
    let (from_id, _from_id_blocked, incoming_origin) = match from_field_to_contact_id(
        context,
        &mime_parser.from,
        fingerprint,
        prevent_rename,
        is_partial_download.is_some()
            && mime_parser
                .get_header(HeaderDef::ContentType)
                .unwrap_or_default()
                .starts_with("multipart/encrypted"),
    )
    .await?
    {
        Some(contact_id_res) => contact_id_res,
        None => {
            warn!(
                context,
                "receive_imf: From field does not contain an acceptable address."
            );
            return Ok(None);
        }
    };

    // Lookup parent message.
    //
    // This may be useful to assign the message to
    // group chats without Chat-Group-ID
    // when a message is sent by Thunderbird.
    //
    // This can be also used to lookup
    // key-contact by email address
    // when receiving a private 1:1 reply
    // to a group chat message.
    let parent_message = get_parent_message(
        context,
        mime_parser.get_header(HeaderDef::References),
        mime_parser.get_header(HeaderDef::InReplyTo),
    )
    .await?
    .filter(|p| Some(p.id) != replace_msg_id);

    let chat_assignment = decide_chat_assignment(
        context,
        &mime_parser,
        &parent_message,
        rfc724_mid,
        from_id,
        &is_partial_download,
    )
    .await?;
    info!(context, "Chat assignment is {chat_assignment:?}.");

    let (to_ids, past_ids) = get_to_and_past_contact_ids(
        context,
        &mime_parser,
        &chat_assignment,
        is_partial_download,
        &parent_message,
        incoming_origin,
    )
    .await?;

    let received_msg;
    if mime_parser.get_header(HeaderDef::SecureJoin).is_some() {
        let res = if mime_parser.incoming {
            handle_securejoin_handshake(context, &mut mime_parser, from_id)
                .await
                .context("error in Secure-Join message handling")?
        } else {
            let to_id = to_ids.first().copied().flatten().unwrap_or(ContactId::SELF);
            // handshake may mark contacts as verified and must be processed before chats are created
            observe_securejoin_on_other_device(context, &mime_parser, to_id)
                .await
                .context("error in Secure-Join watching")?
        };

        match res {
            securejoin::HandshakeMessage::Done | securejoin::HandshakeMessage::Ignore => {
                let msg_id = insert_tombstone(context, rfc724_mid).await?;
                received_msg = Some(ReceivedMsg {
                    chat_id: DC_CHAT_ID_TRASH,
                    state: MessageState::InSeen,
                    hidden: false,
                    sort_timestamp: mime_parser.timestamp_sent,
                    msg_ids: vec![msg_id],
                    needs_delete_job: res == securejoin::HandshakeMessage::Done,
                });
            }
            securejoin::HandshakeMessage::Propagate => {
                received_msg = None;
            }
        }
    } else {
        received_msg = None;
    }

    let verified_encryption = has_verified_encryption(context, &mime_parser, from_id).await?;

    if verified_encryption == VerifiedEncryption::Verified {
        mark_recipients_as_verified(context, from_id, &to_ids, &mime_parser).await?;
    }

    let received_msg = if let Some(received_msg) = received_msg {
        received_msg
    } else {
        let is_dc_message = if mime_parser.has_chat_version() {
            MessengerMessage::Yes
        } else if let Some(parent_message) = &parent_message {
            match parent_message.is_dc_message {
                MessengerMessage::No => MessengerMessage::No,
                MessengerMessage::Yes | MessengerMessage::Reply => MessengerMessage::Reply,
            }
        } else {
            MessengerMessage::No
        };

        let show_emails = ShowEmails::from_i32(context.get_config_int(Config::ShowEmails).await?)
            .unwrap_or_default();

        let is_reaction = mime_parser.parts.iter().any(|part| part.is_reaction);
        let allow_creation = if mime_parser.decrypting_failed {
            false
        } else if mime_parser.is_system_message != SystemMessage::AutocryptSetupMessage
            && is_dc_message == MessengerMessage::No
            && !context.get_config_bool(Config::IsChatmail).await?
        {
            // the message is a classic email in a classic profile
            // (in chatmail profiles, we always show all messages, because shared dc-mua usage is not supported)
            match show_emails {
                ShowEmails::Off | ShowEmails::AcceptedContacts => false,
                ShowEmails::All => true,
            }
        } else {
            !is_reaction
        };

        let to_id = if mime_parser.incoming {
            ContactId::SELF
        } else {
            to_ids.first().copied().flatten().unwrap_or(ContactId::SELF)
        };

        let (chat_id, chat_id_blocked) = do_chat_assignment(
            context,
            chat_assignment,
            from_id,
            &to_ids,
            &past_ids,
            to_id,
            allow_creation,
            &mut mime_parser,
            is_partial_download,
            &verified_encryption,
            parent_message,
        )
        .await?;

        // Add parts
        add_parts(
            context,
            &mut mime_parser,
            imf_raw,
            &to_ids,
            &past_ids,
            rfc724_mid_orig,
            from_id,
            seen,
            is_partial_download,
            replace_msg_id,
            prevent_rename,
            verified_encryption,
            chat_id,
            chat_id_blocked,
            is_dc_message,
        )
        .await
        .context("add_parts error")?
    };

    if !from_id.is_special() {
        contact::update_last_seen(context, from_id, mime_parser.timestamp_sent).await?;
    }

    // Update gossiped timestamp for the chat if someone else or our other device sent
    // Autocrypt-Gossip header to avoid sending Autocrypt-Gossip ourselves
    // and waste traffic.
    let chat_id = received_msg.chat_id;
    if !chat_id.is_special() {
        for gossiped_key in mime_parser.gossiped_keys.values() {
            context
                .sql
                .transaction(move |transaction| {
                    let fingerprint = gossiped_key.dc_fingerprint().hex();
                    transaction.execute(
                        "INSERT INTO gossip_timestamp (chat_id, fingerprint, timestamp)
                         VALUES                       (?, ?, ?)
                         ON CONFLICT                  (chat_id, fingerprint)
                         DO UPDATE SET timestamp=MAX(timestamp, excluded.timestamp)",
                        (chat_id, &fingerprint, mime_parser.timestamp_sent),
                    )?;

                    Ok(())
                })
                .await?;
        }
    }

    let insert_msg_id = if let Some(msg_id) = received_msg.msg_ids.last() {
        *msg_id
    } else {
        MsgId::new_unset()
    };

    save_locations(context, &mime_parser, chat_id, from_id, insert_msg_id).await?;

    if let Some(ref sync_items) = mime_parser.sync_items {
        if from_id == ContactId::SELF {
            if mime_parser.was_encrypted() {
                context.execute_sync_items(sync_items).await;
            } else {
                warn!(context, "Sync items are not encrypted.");
            }
        } else {
            warn!(context, "Sync items not sent by self.");
        }
    }

    if let Some(ref status_update) = mime_parser.webxdc_status_update {
        let can_info_msg;
        let instance = if mime_parser
            .parts
            .first()
            .filter(|part| part.typ == Viewtype::Webxdc)
            .is_some()
        {
            can_info_msg = false;
            Some(Message::load_from_db(context, insert_msg_id).await?)
        } else if let Some(field) = mime_parser.get_header(HeaderDef::InReplyTo) {
            if let Some(instance) =
                message::get_by_rfc724_mids(context, &parse_message_ids(field)).await?
            {
                can_info_msg = instance.download_state() == DownloadState::Done;
                Some(instance)
            } else {
                can_info_msg = false;
                None
            }
        } else {
            can_info_msg = false;
            None
        };

        if let Some(instance) = instance {
            if let Err(err) = context
                .receive_status_update(
                    from_id,
                    &instance,
                    received_msg.sort_timestamp,
                    can_info_msg,
                    status_update,
                )
                .await
            {
                warn!(context, "receive_imf cannot update status: {err:#}.");
            }
        } else {
            warn!(
                context,
                "Received webxdc update, but cannot assign it to message."
            );
        }
    }

    if let Some(avatar_action) = &mime_parser.user_avatar {
        if from_id != ContactId::UNDEFINED
            && context
                .update_contacts_timestamp(
                    from_id,
                    Param::AvatarTimestamp,
                    mime_parser.timestamp_sent,
                )
                .await?
        {
            if let Err(err) = contact::set_profile_image(
                context,
                from_id,
                avatar_action,
                mime_parser.was_encrypted(),
            )
            .await
            {
                warn!(context, "receive_imf cannot update profile image: {err:#}.");
            };
        }
    }

    // Ignore footers from mailinglists as they are often created or modified by the mailinglist software.
    if let Some(footer) = &mime_parser.footer {
        if !mime_parser.is_mailinglist_message()
            && from_id != ContactId::UNDEFINED
            && context
                .update_contacts_timestamp(
                    from_id,
                    Param::StatusTimestamp,
                    mime_parser.timestamp_sent,
                )
                .await?
        {
            if let Err(err) = contact::set_status(
                context,
                from_id,
                footer.to_string(),
                mime_parser.was_encrypted(),
                mime_parser.has_chat_version(),
            )
            .await
            {
                warn!(context, "Cannot update contact status: {err:#}.");
            }
        }
    }

    // Get user-configured server deletion
    let delete_server_after = context.get_config_delete_server_after().await?;

    if !received_msg.msg_ids.is_empty() {
        let target = if received_msg.needs_delete_job
            || (delete_server_after == Some(0) && is_partial_download.is_none())
        {
            Some(context.get_delete_msgs_target().await?)
        } else {
            None
        };
        if target.is_some() || rfc724_mid_orig != rfc724_mid {
            let target_subst = match &target {
                Some(_) => "target=?1,",
                None => "",
            };
            context
                .sql
                .execute(
                    &format!("UPDATE imap SET {target_subst} rfc724_mid=?2 WHERE rfc724_mid=?3"),
                    (
                        target.as_deref().unwrap_or_default(),
                        rfc724_mid_orig,
                        rfc724_mid,
                    ),
                )
                .await?;
        }
        if target.is_none() && !mime_parser.mdn_reports.is_empty() && mime_parser.has_chat_version()
        {
            // This is a Delta Chat MDN. Mark as read.
            markseen_on_imap_table(context, rfc724_mid_orig).await?;
        }
    }

    if received_msg.hidden {
        // No need to emit an event about the changed message
    } else if let Some(replace_chat_id) = replace_chat_id {
        context.emit_msgs_changed_without_msg_id(replace_chat_id);
    } else if !chat_id.is_trash() {
        let fresh = received_msg.state == MessageState::InFresh;
        for msg_id in &received_msg.msg_ids {
            chat_id.emit_msg_event(context, *msg_id, mime_parser.incoming && fresh);
        }
    }
    context.new_msgs_notify.notify_one();

    mime_parser
        .handle_reports(context, from_id, &mime_parser.parts)
        .await;

    if let Some(is_bot) = mime_parser.is_bot {
        // If the message is auto-generated and was generated by Delta Chat,
        // mark the contact as a bot.
        if mime_parser.get_header(HeaderDef::ChatVersion).is_some() {
            from_id.mark_bot(context, is_bot).await?;
        }
    }

    Ok(Some(received_msg))
}

/// Converts "From" field to contact id.
///
/// Also returns whether it is blocked or not and its origin.
///
/// * `prevent_rename`: if true, the display_name of this contact will not be changed. Useful for
///   mailing lists: In some mailing lists, many users write from the same address but with different
///   display names. We don't want the display name to change every time the user gets a new email from
///   a mailing list.
///
/// * `find_key_contact_by_addr`: if true, we only know the e-mail address
///   of the contact, but not the fingerprint,
///   yet want to assign the message to some key-contact.
///   This can happen during prefetch or when the message is partially downloaded.
///   If we get it wrong, the message will be placed into the correct
///   chat after downloading.
///
/// Returns `None` if From field does not contain a valid contact address.
pub async fn from_field_to_contact_id(
    context: &Context,
    from: &SingleInfo,
    fingerprint: Option<&Fingerprint>,
    prevent_rename: bool,
    find_key_contact_by_addr: bool,
) -> Result<Option<(ContactId, bool, Origin)>> {
    let fingerprint = fingerprint.as_ref().map(|fp| fp.hex()).unwrap_or_default();
    let display_name = if prevent_rename {
        Some("")
    } else {
        from.display_name.as_deref()
    };
    let from_addr = match ContactAddress::new(&from.addr) {
        Ok(from_addr) => from_addr,
        Err(err) => {
            warn!(
                context,
                "Cannot create a contact for the given From field: {err:#}."
            );
            return Ok(None);
        }
    };

    if fingerprint.is_empty() && find_key_contact_by_addr {
        let addr_normalized = addr_normalize(&from_addr);

        // Try to assign to some key-contact.
        if let Some((from_id, origin)) = context
            .sql
            .query_row_optional(
                "SELECT id, origin FROM contacts
                 WHERE addr=?1 COLLATE NOCASE
                 AND fingerprint<>'' -- Only key-contacts
                 AND id>?2 AND origin>=?3 AND blocked=?4
                 ORDER BY last_seen DESC
                 LIMIT 1",
                (
                    &addr_normalized,
                    ContactId::LAST_SPECIAL,
                    Origin::IncomingUnknownFrom,
                    Blocked::Not,
                ),
                |row| {
                    let id: ContactId = row.get(0)?;
                    let origin: Origin = row.get(1)?;
                    Ok((id, origin))
                },
            )
            .await?
        {
            return Ok(Some((from_id, false, origin)));
        }
    }

    let (from_id, _) = Contact::add_or_lookup_ex(
        context,
        display_name.unwrap_or_default(),
        &from_addr,
        &fingerprint,
        Origin::IncomingUnknownFrom,
    )
    .await?;

    if from_id == ContactId::SELF {
        Ok(Some((ContactId::SELF, false, Origin::OutgoingBcc)))
    } else {
        let contact = Contact::get_by_id(context, from_id).await?;
        let from_id_blocked = contact.blocked;
        let incoming_origin = contact.origin;

        context
            .sql
            .execute(
                "UPDATE contacts SET addr=? WHERE id=?",
                (from_addr, from_id),
            )
            .await?;

        Ok(Some((from_id, from_id_blocked, incoming_origin)))
    }
}

async fn decide_chat_assignment(
    context: &Context,
    mime_parser: &MimeMessage,
    parent_message: &Option<Message>,
    rfc724_mid: &str,
    from_id: ContactId,
    is_partial_download: &Option<u32>,
) -> Result<ChatAssignment> {
    let should_trash = if !mime_parser.mdn_reports.is_empty() {
        info!(context, "Message is an MDN (TRASH).");
        true
    } else if mime_parser.delivery_report.is_some() {
        info!(context, "Message is a DSN (TRASH).");
        markseen_on_imap_table(context, rfc724_mid).await.ok();
        true
    } else if mime_parser.get_header(HeaderDef::ChatEdit).is_some()
        || mime_parser.get_header(HeaderDef::ChatDelete).is_some()
        || mime_parser.get_header(HeaderDef::IrohNodeAddr).is_some()
        || mime_parser.sync_items.is_some()
    {
        info!(context, "Chat edit/delete/iroh/sync message (TRASH).");
        true
    } else if mime_parser.decrypting_failed && !mime_parser.incoming {
        // Outgoing undecryptable message.
        let last_time = context
            .get_config_i64(Config::LastCantDecryptOutgoingMsgs)
            .await?;
        let now = tools::time();
        let update_config = if last_time.saturating_add(24 * 60 * 60) <= now {
            let mut msg = Message::new_text(stock_str::cant_decrypt_outgoing_msgs(context).await);
            chat::add_device_msg(context, None, Some(&mut msg))
                .await
                .log_err(context)
                .ok();
            true
        } else {
            last_time > now
        };
        if update_config {
            context
                .set_config_internal(Config::LastCantDecryptOutgoingMsgs, Some(&now.to_string()))
                .await?;
        }
        info!(context, "Outgoing undecryptable message (TRASH).");
        true
    } else if mime_parser.is_system_message != SystemMessage::AutocryptSetupMessage
        && !mime_parser.has_chat_version()
        && parent_message
            .as_ref()
            .is_none_or(|p| p.is_dc_message == MessengerMessage::No)
        && !context.get_config_bool(Config::IsChatmail).await?
        && ShowEmails::from_i32(context.get_config_int(Config::ShowEmails).await?)
            .unwrap_or_default()
            == ShowEmails::Off
    {
        info!(context, "Classical email not shown (TRASH).");
        // the message is a classic email in a classic profile
        // (in chatmail profiles, we always show all messages, because shared dc-mua usage is not supported)
        true
    } else if mime_parser
        .get_header(HeaderDef::XMozillaDraftInfo)
        .is_some()
    {
        // Mozilla Thunderbird does not set \Draft flag on "Templates", but sets
        // X-Mozilla-Draft-Info header, which can be used to detect both drafts and templates
        // created by Thunderbird.

        // Most mailboxes have a "Drafts" folder where constantly new emails appear but we don't actually want to show them
        info!(context, "Email is probably just a draft (TRASH).");
        true
    } else if mime_parser.webxdc_status_update.is_some() && mime_parser.parts.len() == 1 {
        if let Some(part) = mime_parser.parts.first() {
            if part.typ == Viewtype::Text && part.msg.is_empty() {
                info!(context, "Message is a status update only (TRASH).");
                markseen_on_imap_table(context, rfc724_mid).await.ok();
                true
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };

    // Decide on the type of chat we assign the message to.
    //
    // The chat may not exist yet, i.e. there may be
    // no database row and ChatId yet.
    let mut num_recipients = mime_parser.recipients.len();
    if from_id != ContactId::SELF {
        let mut has_self_addr = false;
        for recipient in &mime_parser.recipients {
            if context.is_self_addr(&recipient.addr).await? {
                has_self_addr = true;
            }
        }
        if !has_self_addr {
            num_recipients += 1;
        }
    }

    let chat_assignment = if should_trash {
        ChatAssignment::Trash
    } else if mime_parser.get_mailinglist_header().is_some() {
        ChatAssignment::MailingListOrBroadcast
    } else if let Some(grpid) = mime_parser.get_chat_group_id() {
        if mime_parser.was_encrypted() {
            ChatAssignment::GroupChat {
                grpid: grpid.to_string(),
            }
        } else if let Some(parent) = &parent_message {
            if let Some((chat_id, chat_id_blocked)) =
                lookup_chat_by_reply(context, mime_parser, parent, is_partial_download).await?
            {
                // Try to assign to a chat based on In-Reply-To/References.
                ChatAssignment::ExistingChat {
                    chat_id,
                    chat_id_blocked,
                }
            } else {
                ChatAssignment::AdHocGroup
            }
        } else {
            // Could be a message from old version
            // with opportunistic encryption.
            //
            // We still want to assign this to a group
            // even if it had only two members.
            //
            // Group ID is ignored, however.
            ChatAssignment::AdHocGroup
        }
    } else if let Some(parent) = &parent_message {
        if let Some((chat_id, chat_id_blocked)) =
            lookup_chat_by_reply(context, mime_parser, parent, is_partial_download).await?
        {
            // Try to assign to a chat based on In-Reply-To/References.
            ChatAssignment::ExistingChat {
                chat_id,
                chat_id_blocked,
            }
        } else if mime_parser.get_header(HeaderDef::ChatGroupName).is_some() {
            ChatAssignment::AdHocGroup
        } else if num_recipients <= 1 {
            ChatAssignment::OneOneChat
        } else {
            ChatAssignment::AdHocGroup
        }
    } else if mime_parser.get_header(HeaderDef::ChatGroupName).is_some() {
        ChatAssignment::AdHocGroup
    } else if num_recipients <= 1 {
        ChatAssignment::OneOneChat
    } else {
        ChatAssignment::AdHocGroup
    };
    Ok(chat_assignment)
}

/// Assigns the message to a chat.
///
/// Creates a new chat if necessary.
#[expect(clippy::too_many_arguments)]
async fn do_chat_assignment(
    context: &Context,
    chat_assignment: ChatAssignment,
    from_id: ContactId,
    to_ids: &[Option<ContactId>],
    past_ids: &[Option<ContactId>],
    to_id: ContactId,
    allow_creation: bool,
    mime_parser: &mut MimeMessage,
    is_partial_download: Option<u32>,
    verified_encryption: &VerifiedEncryption,
    parent_message: Option<Message>,
) -> Result<(ChatId, Blocked)> {
    let is_bot = context.get_config_bool(Config::Bot).await?;

    let mut chat_id = None;
    let mut chat_id_blocked = Blocked::Not;

    if mime_parser.incoming {
        let test_normal_chat = ChatIdBlocked::lookup_by_contact(context, from_id).await?;

        let create_blocked_default = if is_bot {
            Blocked::Not
        } else {
            Blocked::Request
        };
        let create_blocked = if let Some(ChatIdBlocked { id: _, blocked }) = test_normal_chat {
            match blocked {
                Blocked::Request => create_blocked_default,
                Blocked::Not => Blocked::Not,
                Blocked::Yes => {
                    if Contact::is_blocked_load(context, from_id).await? {
                        // User has blocked the contact.
                        // Block the group contact created as well.
                        Blocked::Yes
                    } else {
                        // 1:1 chat is blocked, but the contact is not.
                        // This happens when 1:1 chat is hidden
                        // during scanning of a group invitation code.
                        create_blocked_default
                    }
                }
            }
        } else {
            create_blocked_default
        };

        match &chat_assignment {
            ChatAssignment::Trash => {
                chat_id = Some(DC_CHAT_ID_TRASH);
            }
            ChatAssignment::GroupChat { grpid } => {
                // Try to assign to a chat based on Chat-Group-ID.
                if let Some((id, _protected, blocked)) =
                    chat::get_chat_id_by_grpid(context, grpid).await?
                {
                    chat_id = Some(id);
                    chat_id_blocked = blocked;
                } else if allow_creation || test_normal_chat.is_some() {
                    if let Some((new_chat_id, new_chat_id_blocked)) = create_group(
                        context,
                        mime_parser,
                        is_partial_download.is_some(),
                        create_blocked,
                        from_id,
                        to_ids,
                        past_ids,
                        verified_encryption,
                        grpid,
                    )
                    .await?
                    {
                        chat_id = Some(new_chat_id);
                        chat_id_blocked = new_chat_id_blocked;
                    }
                }
            }
            ChatAssignment::MailingListOrBroadcast => {
                if let Some(mailinglist_header) = mime_parser.get_mailinglist_header() {
                    if let Some((new_chat_id, new_chat_id_blocked)) =
                        create_or_lookup_mailinglist_or_broadcast(
                            context,
                            allow_creation,
                            mailinglist_header,
                            from_id,
                            mime_parser,
                        )
                        .await?
                    {
                        chat_id = Some(new_chat_id);
                        chat_id_blocked = new_chat_id_blocked;

                        apply_mailinglist_changes(context, mime_parser, new_chat_id).await?;
                    }
                }
            }
            ChatAssignment::ExistingChat {
                chat_id: new_chat_id,
                chat_id_blocked: new_chat_id_blocked,
            } => {
                chat_id = Some(*new_chat_id);
                chat_id_blocked = *new_chat_id_blocked;
            }
            ChatAssignment::AdHocGroup => {
                if let Some((new_chat_id, new_chat_id_blocked)) = lookup_or_create_adhoc_group(
                    context,
                    mime_parser,
                    to_ids,
                    allow_creation || test_normal_chat.is_some(),
                    create_blocked,
                    is_partial_download.is_some(),
                )
                .await?
                {
                    chat_id = Some(new_chat_id);
                    chat_id_blocked = new_chat_id_blocked;
                }
            }
            ChatAssignment::OneOneChat => {}
        }

        // if the chat is somehow blocked but we want to create a non-blocked chat,
        // unblock the chat
        if chat_id_blocked != Blocked::Not
            && create_blocked != Blocked::Yes
            && !matches!(chat_assignment, ChatAssignment::MailingListOrBroadcast)
        {
            if let Some(chat_id) = chat_id {
                chat_id.set_blocked(context, create_blocked).await?;
                chat_id_blocked = create_blocked;
            }
        }

        if chat_id.is_none() {
            // Try to create a 1:1 chat.
            let contact = Contact::get_by_id(context, from_id).await?;
            let create_blocked = match contact.is_blocked() {
                true => Blocked::Yes,
                false if is_bot => Blocked::Not,
                false => Blocked::Request,
            };

            if let Some(chat) = test_normal_chat {
                chat_id = Some(chat.id);
                chat_id_blocked = chat.blocked;
            } else if allow_creation {
                let chat = ChatIdBlocked::get_for_contact(context, from_id, create_blocked)
                    .await
                    .context("Failed to get (new) chat for contact")?;
                chat_id = Some(chat.id);
                chat_id_blocked = chat.blocked;
            }

            if let Some(chat_id) = chat_id {
                if chat_id_blocked != Blocked::Not {
                    if chat_id_blocked != create_blocked {
                        chat_id.set_blocked(context, create_blocked).await?;
                    }
                    if create_blocked == Blocked::Request && parent_message.is_some() {
                        // we do not want any chat to be created implicitly.  Because of the origin-scale-up,
                        // the contact requests will pop up and this should be just fine.
                        ContactId::scaleup_origin(context, &[from_id], Origin::IncomingReplyTo)
                            .await?;
                        info!(
                            context,
                            "Message is a reply to a known message, mark sender as known.",
                        );
                    }
                }

                // Check if the message was sent with verified encryption and set the protection of
                // the 1:1 chat accordingly.
                let chat = match is_partial_download.is_none()
                    && mime_parser.get_header(HeaderDef::SecureJoin).is_none()
                {
                    true => Some(Chat::load_from_db(context, chat_id).await?)
                        .filter(|chat| chat.typ == Chattype::Single),
                    false => None,
                };
                if let Some(chat) = chat {
                    ensure_and_debug_assert!(
                        chat.typ == Chattype::Single,
                        "Chat {chat_id} is not Single",
                    );
                    let new_protection = match verified_encryption {
                        VerifiedEncryption::Verified => ProtectionStatus::Protected,
                        VerifiedEncryption::NotVerified(_) => ProtectionStatus::Unprotected,
                    };

                    ensure_and_debug_assert!(
                        chat.protected == ProtectionStatus::Unprotected
                            || new_protection == ProtectionStatus::Protected,
                        "Chat {chat_id} can't downgrade to Unprotected",
                    );
                    if chat.protected != new_protection {
                        // The message itself will be sorted under the device message since the device
                        // message is `MessageState::InNoticed`, which means that all following
                        // messages are sorted under it.
                        chat_id
                            .set_protection(
                                context,
                                new_protection,
                                mime_parser.timestamp_sent,
                                Some(from_id),
                            )
                            .await?;
                    }
                }
            }
        }
    } else {
        // Outgoing

        // Older Delta Chat versions with core <=1.152.2 only accepted
        // self-sent messages in Saved Messages with own address in the `To` field.
        // New Delta Chat versions may use empty `To` field
        // with only a single `hidden-recipients` group in this case.
        let self_sent = to_ids.len() <= 1 && to_id == ContactId::SELF;

        match &chat_assignment {
            ChatAssignment::Trash => {
                chat_id = Some(DC_CHAT_ID_TRASH);
            }
            ChatAssignment::GroupChat { grpid } => {
                if let Some((id, _protected, blocked)) =
                    chat::get_chat_id_by_grpid(context, grpid).await?
                {
                    chat_id = Some(id);
                    chat_id_blocked = blocked;
                } else if allow_creation {
                    if let Some((new_chat_id, new_chat_id_blocked)) = create_group(
                        context,
                        mime_parser,
                        is_partial_download.is_some(),
                        Blocked::Not,
                        from_id,
                        to_ids,
                        past_ids,
                        verified_encryption,
                        grpid,
                    )
                    .await?
                    {
                        chat_id = Some(new_chat_id);
                        chat_id_blocked = new_chat_id_blocked;
                    }
                }
            }
            ChatAssignment::ExistingChat {
                chat_id: new_chat_id,
                chat_id_blocked: new_chat_id_blocked,
            } => {
                chat_id = Some(*new_chat_id);
                chat_id_blocked = *new_chat_id_blocked;
            }
            ChatAssignment::MailingListOrBroadcast => {
                // Check if the message belongs to a broadcast channel
                // (it can't be a mailing list, since it's outgoing)
                if let Some(mailinglist_header) = mime_parser.get_mailinglist_header() {
                    let listid = mailinglist_header_listid(mailinglist_header)?;
                    chat_id = Some(
                        if let Some((id, ..)) = chat::get_chat_id_by_grpid(context, &listid).await?
                        {
                            id
                        } else {
                            let name =
                                compute_mailinglist_name(mailinglist_header, &listid, mime_parser);
                            chat::create_broadcast_ex(context, Nosync, listid, name).await?
                        },
                    );
                }
            }
            ChatAssignment::AdHocGroup => {
                if let Some((new_chat_id, new_chat_id_blocked)) = lookup_or_create_adhoc_group(
                    context,
                    mime_parser,
                    to_ids,
                    allow_creation,
                    Blocked::Not,
                    is_partial_download.is_some(),
                )
                .await?
                {
                    chat_id = Some(new_chat_id);
                    chat_id_blocked = new_chat_id_blocked;
                }
            }
            ChatAssignment::OneOneChat => {}
        }

        if !to_ids.is_empty() {
            if chat_id.is_none() && allow_creation {
                let to_contact = Contact::get_by_id(context, to_id).await?;
                if let Some(list_id) = to_contact.param.get(Param::ListId) {
                    if let Some((id, _, blocked)) =
                        chat::get_chat_id_by_grpid(context, list_id).await?
                    {
                        chat_id = Some(id);
                        chat_id_blocked = blocked;
                    }
                } else {
                    let chat = ChatIdBlocked::get_for_contact(context, to_id, Blocked::Not).await?;
                    chat_id = Some(chat.id);
                    chat_id_blocked = chat.blocked;
                }
            }
            if chat_id.is_none() && mime_parser.has_chat_version() {
                if let Some(chat) = ChatIdBlocked::lookup_by_contact(context, to_id).await? {
                    chat_id = Some(chat.id);
                    chat_id_blocked = chat.blocked;
                }
            }
        }

        if chat_id.is_none() && self_sent {
            // from_id==to_id==ContactId::SELF - this is a self-sent messages,
            // maybe an Autocrypt Setup Message
            let chat = ChatIdBlocked::get_for_contact(context, ContactId::SELF, Blocked::Not)
                .await
                .context("Failed to get (new) chat for contact")?;

            chat_id = Some(chat.id);
            chat_id_blocked = chat.blocked;

            if Blocked::Not != chat.blocked {
                chat.id.unblock_ex(context, Nosync).await?;
            }
        }

        // automatically unblock chat when the user sends a message
        if chat_id_blocked != Blocked::Not {
            if let Some(chat_id) = chat_id {
                chat_id.unblock_ex(context, Nosync).await?;
                chat_id_blocked = Blocked::Not;
            }
        }
    }
    let chat_id = chat_id.unwrap_or_else(|| {
        info!(context, "No chat id for message (TRASH).");
        DC_CHAT_ID_TRASH
    });
    Ok((chat_id, chat_id_blocked))
}

/// Creates a `ReceivedMsg` from given parts which might consist of
/// multiple messages (if there are multiple attachments).
/// Every entry in `mime_parser.parts` produces a new row in the `msgs` table.
#[expect(clippy::too_many_arguments)]
async fn add_parts(
    context: &Context,
    mime_parser: &mut MimeMessage,
    imf_raw: &[u8],
    to_ids: &[Option<ContactId>],
    past_ids: &[Option<ContactId>],
    rfc724_mid: &str,
    from_id: ContactId,
    seen: bool,
    is_partial_download: Option<u32>,
    mut replace_msg_id: Option<MsgId>,
    prevent_rename: bool,
    verified_encryption: VerifiedEncryption,
    chat_id: ChatId,
    chat_id_blocked: Blocked,
    is_dc_message: MessengerMessage,
) -> Result<ReceivedMsg> {
    let to_id = if mime_parser.incoming {
        ContactId::SELF
    } else {
        to_ids.first().copied().flatten().unwrap_or(ContactId::SELF)
    };

    // if contact renaming is prevented (for mailinglists and bots),
    // we use name from From:-header as override name
    if prevent_rename {
        if let Some(name) = &mime_parser.from.display_name {
            for part in &mut mime_parser.parts {
                part.param.set(Param::OverrideSenderDisplayname, name);
            }
        }
    }

    let mut chat = Chat::load_from_db(context, chat_id).await?;

    if mime_parser.incoming && !chat_id.is_trash() {
        // It can happen that the message is put into a chat
        // but the From-address is not a member of this chat.
        if !chat::is_contact_in_chat(context, chat_id, from_id).await? {
            // Mark the sender as overridden.
            // The UI will prepend `~` to the sender's name,
            // indicating that the sender is not part of the group.
            let from = &mime_parser.from;
            let name: &str = from.display_name.as_ref().unwrap_or(&from.addr);
            for part in &mut mime_parser.parts {
                part.param.set(Param::OverrideSenderDisplayname, name);

                if chat.is_protected() {
                    // In protected chat, also mark the message with an error.
                    let s = stock_str::unknown_sender_for_chat(context).await;
                    part.error = Some(s);
                }
            }
        }
    }

    let is_location_kml = mime_parser.location_kml.is_some();
    let is_mdn = !mime_parser.mdn_reports.is_empty();

    let mut group_changes = match chat.typ {
        _ if chat.id.is_special() => GroupChangesInfo::default(),
        Chattype::Single => GroupChangesInfo::default(),
        Chattype::Mailinglist => GroupChangesInfo::default(),
        Chattype::OutBroadcast => {
            apply_out_broadcast_changes(context, mime_parser, &mut chat, from_id).await?
        }
        Chattype::Group => {
            apply_group_changes(
                context,
                mime_parser,
                &mut chat,
                from_id,
                to_ids,
                past_ids,
                &verified_encryption,
            )
            .await?
        }
        Chattype::InBroadcast => {
            apply_in_broadcast_changes(context, mime_parser, &mut chat, from_id).await?
        }
    };

    let rfc724_mid_orig = &mime_parser
        .get_rfc724_mid()
        .unwrap_or(rfc724_mid.to_string());

    // Extract ephemeral timer from the message or use the existing timer if the message is not fully downloaded.
    let mut ephemeral_timer = if is_partial_download.is_some() {
        chat_id.get_ephemeral_timer(context).await?
    } else if let Some(value) = mime_parser.get_header(HeaderDef::EphemeralTimer) {
        match value.parse::<EphemeralTimer>() {
            Ok(timer) => timer,
            Err(err) => {
                warn!(context, "Can't parse ephemeral timer \"{value}\": {err:#}.");
                EphemeralTimer::Disabled
            }
        }
    } else {
        EphemeralTimer::Disabled
    };

    let state = if !mime_parser.incoming {
        MessageState::OutDelivered
    } else if seen || is_mdn || chat_id_blocked == Blocked::Yes || group_changes.silent
    // No check for `hidden` because only reactions are such and they should be `InFresh`.
    {
        MessageState::InSeen
    } else {
        MessageState::InFresh
    };
    let in_fresh = state == MessageState::InFresh;

    let sort_to_bottom = false;
    let received = true;
    let sort_timestamp = chat_id
        .calc_sort_timestamp(
            context,
            mime_parser.timestamp_sent,
            sort_to_bottom,
            received,
            mime_parser.incoming,
        )
        .await?;

    // Apply ephemeral timer changes to the chat.
    //
    // Only apply the timer when there are visible parts (e.g., the message does not consist only
    // of `location.kml` attachment).  Timer changes without visible received messages may be
    // confusing to the user.
    if !chat_id.is_special()
        && !mime_parser.parts.is_empty()
        && chat_id.get_ephemeral_timer(context).await? != ephemeral_timer
    {
        let chat_contacts =
            HashSet::<ContactId>::from_iter(chat::get_chat_contacts(context, chat_id).await?);
        let is_from_in_chat =
            !chat_contacts.contains(&ContactId::SELF) || chat_contacts.contains(&from_id);

        info!(
            context,
            "Received new ephemeral timer value {ephemeral_timer:?} for chat {chat_id}, checking if it should be applied."
        );
        if !is_from_in_chat {
            warn!(
                context,
                "Ignoring ephemeral timer change to {ephemeral_timer:?} for chat {chat_id} because sender {from_id} is not a member.",
            );
        } else if is_dc_message == MessengerMessage::Yes
            && get_previous_message(context, mime_parser)
                .await?
                .map(|p| p.ephemeral_timer)
                == Some(ephemeral_timer)
            && mime_parser.is_system_message != SystemMessage::EphemeralTimerChanged
        {
            // The message is a Delta Chat message, so we know that previous message according to
            // References header is the last message in the chat as seen by the sender. The timer
            // is the same in both the received message and the last message, so we know that the
            // sender has not seen any change of the timer between these messages. As our timer
            // value is different, it means the sender has not received some timer update that we
            // have seen or sent ourselves, so we ignore incoming timer to prevent a rollback.
            warn!(
                context,
                "Ignoring ephemeral timer change to {ephemeral_timer:?} for chat {chat_id} to avoid rollback.",
            );
        } else if chat_id
            .update_timestamp(
                context,
                Param::EphemeralSettingsTimestamp,
                mime_parser.timestamp_sent,
            )
            .await?
        {
            if let Err(err) = chat_id
                .inner_set_ephemeral_timer(context, ephemeral_timer)
                .await
            {
                warn!(
                    context,
                    "Failed to modify timer for chat {chat_id}: {err:#}."
                );
            } else {
                info!(
                    context,
                    "Updated ephemeral timer to {ephemeral_timer:?} for chat {chat_id}."
                );
                if mime_parser.is_system_message != SystemMessage::EphemeralTimerChanged {
                    chat::add_info_msg(
                        context,
                        chat_id,
                        &stock_ephemeral_timer_changed(context, ephemeral_timer, from_id).await,
                        sort_timestamp,
                    )
                    .await?;
                }
            }
        } else {
            warn!(
                context,
                "Ignoring ephemeral timer change to {ephemeral_timer:?} because it is outdated."
            );
        }
    }

    let mut better_msg = if mime_parser.is_system_message == SystemMessage::LocationStreamingEnabled
    {
        Some(stock_str::msg_location_enabled_by(context, from_id).await)
    } else if mime_parser.is_system_message == SystemMessage::EphemeralTimerChanged {
        let better_msg = stock_ephemeral_timer_changed(context, ephemeral_timer, from_id).await;

        // Do not delete the system message itself.
        //
        // This prevents confusion when timer is changed
        // to 1 week, and then changed to 1 hour: after 1
        // hour, only the message about the change to 1
        // week is left.
        ephemeral_timer = EphemeralTimer::Disabled;

        Some(better_msg)
    } else {
        None
    };

    let mut verification_failed = false;
    if !chat_id.is_special() && is_partial_download.is_none() {
        // For outgoing emails in the 1:1 chat we have an exception that
        // they are allowed to be unencrypted:
        // 1. They can't be an attack (they are outgoing, not incoming)
        // 2. Probably the unencryptedness is just a temporary state, after all
        //    the user obviously still uses DC
        //    -> Showing info messages every time would be a lot of noise
        // 3. The info messages that are shown to the user ("Your chat partner
        //    likely reinstalled DC" or similar) would be wrong.
        if chat.is_protected() && (mime_parser.incoming || chat.typ != Chattype::Single) {
            if let VerifiedEncryption::NotVerified(err) = verified_encryption {
                verification_failed = true;
                warn!(context, "Verification problem: {err:#}.");
                let s = format!("{err}. Re-download the message or see 'Info' for more details");
                mime_parser.replace_msg_by_error(&s);
            }
        }
    }
    drop(chat); // Avoid using stale `chat` object.

    let sort_timestamp = tweak_sort_timestamp(
        context,
        mime_parser,
        group_changes.silent,
        chat_id,
        sort_timestamp,
    )
    .await?;

    let mime_in_reply_to = mime_parser
        .get_header(HeaderDef::InReplyTo)
        .unwrap_or_default();
    let mime_references = mime_parser
        .get_header(HeaderDef::References)
        .unwrap_or_default();

    // fine, so far.  now, split the message into simple parts usable as "short messages"
    // and add them to the database (mails sent by other messenger clients should result
    // into only one message; mails sent by other clients may result in several messages
    // (eg. one per attachment))
    let icnt = mime_parser.parts.len();

    let subject = mime_parser.get_subject().unwrap_or_default();

    let is_system_message = mime_parser.is_system_message;

    // if indicated by the parser,
    // we save the full mime-message and add a flag
    // that the ui should show button to display the full message.

    // We add "Show Full Message" button to the last message bubble (part) if this flag evaluates to
    // `true` finally.
    let mut save_mime_modified = false;

    let mime_headers = if mime_parser.is_mime_modified {
        let headers = if !mime_parser.decoded_data.is_empty() {
            mime_parser.decoded_data.clone()
        } else {
            imf_raw.to_vec()
        };
        tokio::task::block_in_place(move || buf_compress(&headers))?
    } else {
        Vec::new()
    };

    let mut created_db_entries = Vec::with_capacity(mime_parser.parts.len());

    if let Some(m) = group_changes.better_msg {
        match &better_msg {
            None => better_msg = Some(m),
            Some(_) => {
                if !m.is_empty() {
                    group_changes.extra_msgs.push((m, is_system_message, None))
                }
            }
        }
    }

    let chat_id = if better_msg
        .as_ref()
        .is_some_and(|better_msg| better_msg.is_empty())
        && is_partial_download.is_none()
    {
        DC_CHAT_ID_TRASH
    } else {
        chat_id
    };

    for (group_changes_msg, cmd, added_removed_id) in group_changes.extra_msgs {
        chat::add_info_msg_with_cmd(
            context,
            chat_id,
            &group_changes_msg,
            cmd,
            sort_timestamp,
            None,
            None,
            None,
            added_removed_id,
        )
        .await?;
    }

    if let Some(node_addr) = mime_parser.get_header(HeaderDef::IrohNodeAddr) {
        match mime_parser.get_header(HeaderDef::InReplyTo) {
            Some(in_reply_to) => match rfc724_mid_exists(context, in_reply_to).await? {
                Some((instance_id, _ts_sent)) => {
                    if let Err(err) =
                        add_gossip_peer_from_header(context, instance_id, node_addr).await
                    {
                        warn!(context, "Failed to add iroh peer from header: {err:#}.");
                    }
                }
                None => {
                    warn!(
                        context,
                        "Cannot add iroh peer because WebXDC instance does not exist."
                    );
                }
            },
            None => {
                warn!(
                    context,
                    "Cannot add iroh peer because the message has no In-Reply-To."
                );
            }
        }
    }

    handle_edit_delete(context, mime_parser, from_id).await?;

    let is_reaction = mime_parser.parts.iter().any(|part| part.is_reaction);
    let hidden = is_reaction;
    let mut parts = mime_parser.parts.iter().peekable();
    while let Some(part) = parts.next() {
        if part.is_reaction {
            let reaction_str = simplify::remove_footers(part.msg.as_str());
            let is_incoming_fresh = mime_parser.incoming && !seen;
            set_msg_reaction(
                context,
                mime_in_reply_to,
                chat_id,
                from_id,
                sort_timestamp,
                Reaction::from(reaction_str.as_str()),
                is_incoming_fresh,
            )
            .await?;
        }

        let mut param = part.param.clone();
        if is_system_message != SystemMessage::Unknown {
            param.set_int(Param::Cmd, is_system_message as i32);
        }

        if let Some(replace_msg_id) = replace_msg_id {
            let placeholder = Message::load_from_db(context, replace_msg_id).await?;
            for key in [
                Param::WebxdcSummary,
                Param::WebxdcSummaryTimestamp,
                Param::WebxdcDocument,
                Param::WebxdcDocumentTimestamp,
            ] {
                if let Some(value) = placeholder.param.get(key) {
                    param.set(key, value);
                }
            }
        }

        let (msg, typ): (&str, Viewtype) = if let Some(better_msg) = &better_msg {
            (better_msg, Viewtype::Text)
        } else {
            (&part.msg, part.typ)
        };
        let part_is_empty =
            typ == Viewtype::Text && msg.is_empty() && part.param.get(Param::Quote).is_none();

        if let Some(contact_id) = group_changes.added_removed_id {
            param.set(Param::ContactAddedRemoved, contact_id.to_u32().to_string());
        }

        save_mime_modified |= mime_parser.is_mime_modified && !part_is_empty && !hidden;
        let save_mime_modified = save_mime_modified && parts.peek().is_none();

        let ephemeral_timestamp = if in_fresh {
            0
        } else {
            match ephemeral_timer {
                EphemeralTimer::Disabled => 0,
                EphemeralTimer::Enabled { duration } => {
                    mime_parser.timestamp_rcvd.saturating_add(duration.into())
                }
            }
        };

        // If you change which information is skipped if the message is trashed,
        // also change `MsgId::trash()` and `delete_expired_messages()`
        let trash = chat_id.is_trash() || (is_location_kml && part_is_empty && !save_mime_modified);

        let row_id = context
            .sql
            .call_write(|conn| {
                let mut stmt = conn.prepare_cached(
            r#"
INSERT INTO msgs
  (
    id,
    rfc724_mid, chat_id,
    from_id, to_id, timestamp, timestamp_sent, 
    timestamp_rcvd, type, state, msgrmsg, 
    txt, txt_normalized, subject, param, hidden,
    bytes, mime_headers, mime_compressed, mime_in_reply_to,
    mime_references, mime_modified, error, ephemeral_timer,
    ephemeral_timestamp, download_state, hop_info
  )
  VALUES (
    ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?,
    ?, ?, ?, ?, ?, 1,
    ?, ?, ?, ?,
    ?, ?, ?, ?
  )
ON CONFLICT (id) DO UPDATE
SET rfc724_mid=excluded.rfc724_mid, chat_id=excluded.chat_id,
    from_id=excluded.from_id, to_id=excluded.to_id, timestamp_sent=excluded.timestamp_sent,
    type=excluded.type, state=max(state,excluded.state), msgrmsg=excluded.msgrmsg,
    txt=excluded.txt, txt_normalized=excluded.txt_normalized, subject=excluded.subject,
    param=excluded.param,
    hidden=excluded.hidden,bytes=excluded.bytes, mime_headers=excluded.mime_headers,
    mime_compressed=excluded.mime_compressed, mime_in_reply_to=excluded.mime_in_reply_to,
    mime_references=excluded.mime_references, mime_modified=excluded.mime_modified, error=excluded.error, ephemeral_timer=excluded.ephemeral_timer,
    ephemeral_timestamp=excluded.ephemeral_timestamp, download_state=excluded.download_state, hop_info=excluded.hop_info
RETURNING id
"#)?;
                let row_id: MsgId = stmt.query_row(params![
                    replace_msg_id,
                    rfc724_mid_orig,
                    if trash { DC_CHAT_ID_TRASH } else { chat_id },
                    if trash { ContactId::UNDEFINED } else { from_id },
                    if trash { ContactId::UNDEFINED } else { to_id },
                    sort_timestamp,
                    if trash { 0 } else { mime_parser.timestamp_sent },
                    if trash { 0 } else { mime_parser.timestamp_rcvd },
                    if trash { Viewtype::Unknown } else { typ },
                    if trash { MessageState::Undefined } else { state },
                    if trash { MessengerMessage::No } else { is_dc_message },
                    if trash || hidden { "" } else { msg },
                    if trash || hidden { None } else { message::normalize_text(msg) },
                    if trash || hidden { "" } else { &subject },
                    if trash {
                        "".to_string()
                    } else {
                        param.to_string()
                    },
                    !trash && hidden,
                    if trash { 0 } else { part.bytes as isize },
                    if save_mime_modified && !(trash || hidden) {
                        mime_headers.clone()
                    } else {
                        Vec::new()
                    },
                    if trash { "" } else { mime_in_reply_to },
                    if trash { "" } else { mime_references },
                    !trash && save_mime_modified,
                    if trash { "" } else { part.error.as_deref().unwrap_or_default() },
                    if trash { 0 } else { ephemeral_timer.to_u32() },
                    if trash { 0 } else { ephemeral_timestamp },
                    if trash {
                        DownloadState::Done
                    } else if is_partial_download.is_some() {
                        DownloadState::Available
                    } else if mime_parser.decrypting_failed {
                        DownloadState::Undecipherable
                    } else if verification_failed {
                        // Verification can fail because of message reordering. Re-downloading the
                        // message should help if so.
                        DownloadState::Available
                    } else {
                        DownloadState::Done
                    },
                    if trash { "" } else { &mime_parser.hop_info },
                ],
                |row| {
                    let msg_id: MsgId = row.get(0)?;
                    Ok(msg_id)
                }
                )?;
                Ok(row_id)
            })
            .await?;

        // We only replace placeholder with a first part,
        // afterwards insert additional parts.
        replace_msg_id = None;

        ensure_and_debug_assert!(!row_id.is_special(), "Rowid {row_id} is special");
        created_db_entries.push(row_id);
    }

    // Maybe set logging xdc and add gossip topics for webxdcs.
    for (part, msg_id) in mime_parser.parts.iter().zip(&created_db_entries) {
        // check if any part contains a webxdc topic id
        if part.typ == Viewtype::Webxdc {
            if let Some(topic) = mime_parser.get_header(HeaderDef::IrohGossipTopic) {
                // default encoding of topic ids is `hex`.
                let mut topic_raw = [0u8; 32];
                BASE32_NOPAD
                    .decode_mut(topic.to_ascii_uppercase().as_bytes(), &mut topic_raw)
                    .map_err(|e| e.error)
                    .context("Wrong gossip topic header")?;

                let topic = TopicId::from_bytes(topic_raw);
                insert_topic_stub(context, *msg_id, topic).await?;
            } else {
                warn!(context, "webxdc doesn't have a gossip topic")
            }
        }

        maybe_set_logging_xdc_inner(
            context,
            part.typ,
            chat_id,
            part.param.get(Param::Filename),
            *msg_id,
        )
        .await?;
    }

    if let Some(replace_msg_id) = replace_msg_id {
        // Trash the "replace" placeholder with a message that has no parts. If it has the original
        // "Message-ID", mark the placeholder for server-side deletion so as if the user deletes the
        // fully downloaded message later, the server-side deletion is issued.
        let on_server = rfc724_mid == rfc724_mid_orig;
        replace_msg_id.trash(context, on_server).await?;
    }

    let unarchive = match mime_parser.get_header(HeaderDef::ChatGroupMemberRemoved) {
        Some(addr) => context.is_self_addr(addr).await?,
        None => true,
    };
    if unarchive {
        chat_id.unarchive_if_not_muted(context, state).await?;
    }

    info!(
        context,
        "Message has {icnt} parts and is assigned to chat #{chat_id}."
    );

    if !chat_id.is_trash() && !hidden {
        let mut chat = Chat::load_from_db(context, chat_id).await?;

        // In contrast to most other update-timestamps,
        // use `sort_timestamp` instead of `sent_timestamp` for the subject-timestamp comparison.
        // This way, `LastSubject` actually refers to the most recent message _shown_ in the chat.
        if chat
            .param
            .update_timestamp(Param::SubjectTimestamp, sort_timestamp)?
        {
            // write the last subject even if empty -
            // otherwise a reply may get an outdated subject.
            let subject = mime_parser.get_subject().unwrap_or_default();

            chat.param.set(Param::LastSubject, subject);
            chat.update_param(context).await?;
        }
    }

    // Normally outgoing MDNs sent by us never appear in mailboxes, but Gmail saves all
    // outgoing messages, including MDNs, to the Sent folder. If we detect such saved MDN,
    // delete it.
    let needs_delete_job =
        !mime_parser.incoming && is_mdn && is_dc_message == MessengerMessage::Yes;

    Ok(ReceivedMsg {
        chat_id,
        state,
        hidden,
        sort_timestamp,
        msg_ids: created_db_entries,
        needs_delete_job,
    })
}

/// Checks for "Chat-Edit" and "Chat-Delete" headers,
/// and edits/deletes existing messages accordingly.
///
/// Returns `true` if this message is an edit/deletion request.
async fn handle_edit_delete(
    context: &Context,
    mime_parser: &MimeMessage,
    from_id: ContactId,
) -> Result<()> {
    if let Some(rfc724_mid) = mime_parser.get_header(HeaderDef::ChatEdit) {
        if let Some((original_msg_id, _)) = rfc724_mid_exists(context, rfc724_mid).await? {
            if let Some(mut original_msg) =
                Message::load_from_db_optional(context, original_msg_id).await?
            {
                if original_msg.from_id == from_id {
                    if let Some(part) = mime_parser.parts.first() {
                        let edit_msg_showpadlock = part
                            .param
                            .get_bool(Param::GuaranteeE2ee)
                            .unwrap_or_default();
                        if edit_msg_showpadlock || !original_msg.get_showpadlock() {
                            let new_text =
                                part.msg.strip_prefix(EDITED_PREFIX).unwrap_or(&part.msg);
                            chat::save_text_edit_to_db(context, &mut original_msg, new_text)
                                .await?;
                        } else {
                            warn!(context, "Edit message: Not encrypted.");
                        }
                    }
                } else {
                    warn!(context, "Edit message: Bad sender.");
                }
            } else {
                warn!(context, "Edit message: Database entry does not exist.");
            }
        } else {
            warn!(
                context,
                "Edit message: rfc724_mid {rfc724_mid:?} not found."
            );
        }
    } else if let Some(rfc724_mid_list) = mime_parser.get_header(HeaderDef::ChatDelete) {
        if let Some(part) = mime_parser.parts.first() {
            // See `message::delete_msgs_ex()`, unlike edit requests, DC doesn't send unencrypted
            // deletion requests, so there's no need to support them.
            if part.param.get_bool(Param::GuaranteeE2ee).unwrap_or(false) {
                let mut modified_chat_ids = HashSet::new();
                let mut msg_ids = Vec::new();

                let rfc724_mid_vec: Vec<&str> = rfc724_mid_list.split_whitespace().collect();
                for rfc724_mid in rfc724_mid_vec {
                    if let Some((msg_id, _)) =
                        message::rfc724_mid_exists(context, rfc724_mid).await?
                    {
                        if let Some(msg) = Message::load_from_db_optional(context, msg_id).await? {
                            if msg.from_id == from_id {
                                message::delete_msg_locally(context, &msg).await?;
                                msg_ids.push(msg.id);
                                modified_chat_ids.insert(msg.chat_id);
                            } else {
                                warn!(context, "Delete message: Bad sender.");
                            }
                        } else {
                            warn!(context, "Delete message: Database entry does not exist.");
                        }
                    } else {
                        warn!(context, "Delete message: {rfc724_mid:?} not found.");
                    }
                }
                message::delete_msgs_locally_done(context, &msg_ids, modified_chat_ids).await?;
            } else {
                warn!(context, "Delete message: Not encrypted.");
            }
        }
    }
    Ok(())
}

async fn tweak_sort_timestamp(
    context: &Context,
    mime_parser: &mut MimeMessage,
    silent: bool,
    chat_id: ChatId,
    sort_timestamp: i64,
) -> Result<i64> {
    // Ensure replies to messages are sorted after the parent message.
    //
    // This is useful in a case where sender clocks are not
    // synchronized and parent message has a Date: header with a
    // timestamp higher than reply timestamp.
    //
    // This does not help if parent message arrives later than the
    // reply.
    let parent_timestamp = mime_parser.get_parent_timestamp(context).await?;
    let mut sort_timestamp = parent_timestamp.map_or(sort_timestamp, |parent_timestamp| {
        std::cmp::max(sort_timestamp, parent_timestamp)
    });

    // If the message should be silent,
    // set the timestamp to be no more than the same as last message
    // so that the chat is not sorted to the top of the chatlist.
    if silent {
        let last_msg_timestamp = if let Some(t) = chat_id.get_timestamp(context).await? {
            t
        } else {
            chat_id.created_timestamp(context).await?
        };
        sort_timestamp = std::cmp::min(sort_timestamp, last_msg_timestamp);
    }
    Ok(sort_timestamp)
}

/// Saves attached locations to the database.
///
/// Emits an event if at least one new location was added.
async fn save_locations(
    context: &Context,
    mime_parser: &MimeMessage,
    chat_id: ChatId,
    from_id: ContactId,
    msg_id: MsgId,
) -> Result<()> {
    if chat_id.is_special() {
        // Do not save locations for trashed messages.
        return Ok(());
    }

    let mut send_event = false;

    if let Some(message_kml) = &mime_parser.message_kml {
        if let Some(newest_location_id) =
            location::save(context, chat_id, from_id, &message_kml.locations, true).await?
        {
            location::set_msg_location_id(context, msg_id, newest_location_id).await?;
            send_event = true;
        }
    }

    if let Some(location_kml) = &mime_parser.location_kml {
        if let Some(addr) = &location_kml.addr {
            let contact = Contact::get_by_id(context, from_id).await?;
            if contact.get_addr().to_lowercase() == addr.to_lowercase() {
                if location::save(context, chat_id, from_id, &location_kml.locations, false)
                    .await?
                    .is_some()
                {
                    send_event = true;
                }
            } else {
                warn!(
                    context,
                    "Address in location.kml {:?} is not the same as the sender address {:?}.",
                    addr,
                    contact.get_addr()
                );
            }
        }
    }
    if send_event {
        context.emit_location_changed(Some(from_id)).await?;
    }
    Ok(())
}

async fn lookup_chat_by_reply(
    context: &Context,
    mime_parser: &MimeMessage,
    parent: &Message,
    is_partial_download: &Option<u32>,
) -> Result<Option<(ChatId, Blocked)>> {
    // If the message is encrypted and has group ID,
    // lookup by reply should never be needed
    // as we can directly assign the message to the chat
    // by its group ID.
    ensure_and_debug_assert!(
        mime_parser.get_chat_group_id().is_none() || !mime_parser.was_encrypted(),
        "Encrypted message has group ID {}",
        mime_parser.get_chat_group_id().unwrap_or_default(),
    );

    // Try to assign message to the same chat as the parent message.
    let Some(parent_chat_id) = ChatId::lookup_by_message(parent) else {
        return Ok(None);
    };

    // If this was a private message just to self, it was probably a private reply.
    // It should not go into the group then, but into the private chat.
    if is_probably_private_reply(context, mime_parser, parent_chat_id).await? {
        return Ok(None);
    }

    // If the parent chat is a 1:1 chat, and the sender added
    // a new person to TO/CC, then the message should not go to the 1:1 chat, but to a
    // newly created ad-hoc group.
    let parent_chat = Chat::load_from_db(context, parent_chat_id).await?;
    if parent_chat.typ == Chattype::Single && mime_parser.recipients.len() > 1 {
        return Ok(None);
    }

    // Do not assign unencrypted messages to encrypted chats.
    if is_partial_download.is_none()
        && parent_chat.is_encrypted(context).await?
        && !mime_parser.was_encrypted()
    {
        return Ok(None);
    }

    info!(
        context,
        "Assigning message to {parent_chat_id} as it's a reply to {}.", parent.rfc724_mid
    );
    Ok(Some((parent_chat.id, parent_chat.blocked)))
}

async fn lookup_or_create_adhoc_group(
    context: &Context,
    mime_parser: &MimeMessage,
    to_ids: &[Option<ContactId>],
    allow_creation: bool,
    create_blocked: Blocked,
    is_partial_download: bool,
) -> Result<Option<(ChatId, Blocked)>> {
    // Partial download may be an encrypted message with protected Subject header. We do not want to
    // create a group with "..." or "Encrypted message" as a subject. The same is for undecipherable
    // messages. Instead, assign the message to 1:1 chat with the sender.
    if is_partial_download {
        info!(
            context,
            "Ad-hoc group cannot be created from partial download."
        );
        return Ok(None);
    }
    if mime_parser.decrypting_failed {
        warn!(
            context,
            "Not creating ad-hoc group for message that cannot be decrypted."
        );
        return Ok(None);
    }

    // Lookup address-contact by the From address.
    let fingerprint = None;
    let find_key_contact_by_addr = false;
    let prevent_rename = should_prevent_rename(mime_parser);
    let (from_id, _from_id_blocked, _incoming_origin) = from_field_to_contact_id(
        context,
        &mime_parser.from,
        fingerprint,
        prevent_rename,
        find_key_contact_by_addr,
    )
    .await?
    .context("Cannot lookup address-contact by the From field")?;

    let grpname = mime_parser
        .get_header(HeaderDef::ChatGroupName)
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            mime_parser
                .get_subject()
                .map(|s| remove_subject_prefix(&s))
                .unwrap_or_else(|| "👥📧".to_string())
        });
    let to_ids: Vec<ContactId> = to_ids.iter().filter_map(|x| *x).collect();
    let mut contact_ids = Vec::with_capacity(to_ids.len() + 1);
    contact_ids.extend(&to_ids);
    if !contact_ids.contains(&from_id) {
        contact_ids.push(from_id);
    }
    let trans_fn = |t: &mut rusqlite::Transaction| {
        t.pragma_update(None, "query_only", "0")?;
        t.execute(
            "CREATE TEMP TABLE temp.contacts (
                id INTEGER PRIMARY KEY
            ) STRICT",
            (),
        )?;
        let mut stmt = t.prepare("INSERT INTO temp.contacts(id) VALUES (?)")?;
        for &id in &contact_ids {
            stmt.execute((id,))?;
        }
        let val = t
            .query_row(
                "SELECT c.id, c.blocked
                FROM chats c INNER JOIN msgs m ON c.id=m.chat_id
                WHERE m.hidden=0 AND c.grpid='' AND c.name=?
                AND (SELECT COUNT(*) FROM chats_contacts
                     WHERE chat_id=c.id
                     AND add_timestamp >= remove_timestamp)=?
                AND (SELECT COUNT(*) FROM chats_contacts
                     WHERE chat_id=c.id
                     AND contact_id NOT IN (SELECT id FROM temp.contacts)
                     AND add_timestamp >= remove_timestamp)=0
                ORDER BY m.timestamp DESC",
                (&grpname, contact_ids.len()),
                |row| {
                    let id: ChatId = row.get(0)?;
                    let blocked: Blocked = row.get(1)?;
                    Ok((id, blocked))
                },
            )
            .optional()?;
        t.execute("DROP TABLE temp.contacts", ())?;
        Ok(val)
    };
    let query_only = true;
    if let Some((chat_id, blocked)) = context.sql.transaction_ex(query_only, trans_fn).await? {
        info!(
            context,
            "Assigning message to ad-hoc group {chat_id} with matching name and members."
        );
        return Ok(Some((chat_id, blocked)));
    }
    if !allow_creation {
        return Ok(None);
    }
    create_adhoc_group(
        context,
        mime_parser,
        create_blocked,
        from_id,
        &to_ids,
        &grpname,
    )
    .await
    .context("Could not create ad hoc group")
}

/// If this method returns true, the message shall be assigned to the 1:1 chat with the sender.
/// If it returns false, it shall be assigned to the parent chat.
async fn is_probably_private_reply(
    context: &Context,
    mime_parser: &MimeMessage,
    parent_chat_id: ChatId,
) -> Result<bool> {
    // Message cannot be a private reply if it has an explicit Chat-Group-ID header.
    if mime_parser.get_chat_group_id().is_some() {
        return Ok(false);
    }

    // Usually we don't want to show private replies in the parent chat, but in the
    // 1:1 chat with the sender.
    //
    // There is one exception: Classical MUA replies to two-member groups
    // should be assigned to the group chat. We restrict this exception to classical emails, as chat-group-messages
    // contain a Chat-Group-Id header and can be sorted into the correct chat this way.

    if mime_parser.recipients.len() != 1 {
        return Ok(false);
    }

    if !mime_parser.has_chat_version() {
        let chat_contacts = chat::get_chat_contacts(context, parent_chat_id).await?;
        if chat_contacts.len() == 2 && chat_contacts.contains(&ContactId::SELF) {
            return Ok(false);
        }
    }

    Ok(true)
}

/// This function tries to extract the group-id from the message and create a new group
/// chat with this ID. If there is no group-id and there are more
/// than two members, a new ad hoc group is created.
///
/// On success the function returns the created (chat_id, chat_blocked) tuple.
#[expect(clippy::too_many_arguments)]
async fn create_group(
    context: &Context,
    mime_parser: &mut MimeMessage,
    is_partial_download: bool,
    create_blocked: Blocked,
    from_id: ContactId,
    to_ids: &[Option<ContactId>],
    past_ids: &[Option<ContactId>],
    verified_encryption: &VerifiedEncryption,
    grpid: &str,
) -> Result<Option<(ChatId, Blocked)>> {
    let to_ids_flat: Vec<ContactId> = to_ids.iter().filter_map(|x| *x).collect();
    let mut chat_id = None;
    let mut chat_id_blocked = Default::default();

    let create_protected = if mime_parser.get_header(HeaderDef::ChatVerified).is_some() {
        if let VerifiedEncryption::NotVerified(err) = verified_encryption {
            warn!(
                context,
                "Creating unprotected group because of the verification problem: {err:#}."
            );
            ProtectionStatus::Unprotected
        } else {
            ProtectionStatus::Protected
        }
    } else {
        ProtectionStatus::Unprotected
    };

    async fn self_explicitly_added(
        context: &Context,
        mime_parser: &&mut MimeMessage,
    ) -> Result<bool> {
        let ret = match mime_parser.get_header(HeaderDef::ChatGroupMemberAdded) {
            Some(member_addr) => context.is_self_addr(member_addr).await?,
            None => false,
        };
        Ok(ret)
    }

    if chat_id.is_none()
            && !mime_parser.is_mailinglist_message()
            && !grpid.is_empty()
            && mime_parser.get_header(HeaderDef::ChatGroupName).is_some()
            // otherwise, a pending "quit" message may pop up
            && mime_parser.get_header(HeaderDef::ChatGroupMemberRemoved).is_none()
            // re-create explicitly left groups only if ourself is re-added
            && (!chat::is_group_explicitly_left(context, grpid).await?
                || self_explicitly_added(context, &mime_parser).await?)
    {
        // Group does not exist but should be created.
        let grpname = mime_parser
            .get_header(HeaderDef::ChatGroupName)
            .context("Chat-Group-Name vanished")?
            // Workaround for the "Space added before long group names after MIME
            // serialization/deserialization #3650" issue. DC itself never creates group names with
            // leading/trailing whitespace.
            .trim();
        let new_chat_id = ChatId::create_multiuser_record(
            context,
            Chattype::Group,
            grpid,
            grpname,
            create_blocked,
            create_protected,
            None,
            mime_parser.timestamp_sent,
        )
        .await
        .with_context(|| format!("Failed to create group '{grpname}' for grpid={grpid}"))?;

        chat_id = Some(new_chat_id);
        chat_id_blocked = create_blocked;

        // Create initial member list.
        if let Some(mut chat_group_member_timestamps) = mime_parser.chat_group_member_timestamps() {
            let mut new_to_ids = to_ids.to_vec();
            if !new_to_ids.contains(&Some(from_id)) {
                new_to_ids.insert(0, Some(from_id));
                chat_group_member_timestamps.insert(0, mime_parser.timestamp_sent);
            }

            update_chats_contacts_timestamps(
                context,
                new_chat_id,
                None,
                &new_to_ids,
                past_ids,
                &chat_group_member_timestamps,
            )
            .await?;
        } else {
            let mut members = vec![ContactId::SELF];
            if !from_id.is_special() {
                members.push(from_id);
            }
            members.extend(to_ids_flat);

            // Add all members with 0 timestamp
            // because we don't know the real timestamp of their addition.
            // This will allow other senders who support
            // `Chat-Group-Member-Timestamps` to overwrite
            // timestamps later.
            let timestamp = 0;

            chat::add_to_chat_contacts_table(context, timestamp, new_chat_id, &members).await?;
        }

        context.emit_event(EventType::ChatModified(new_chat_id));
        chatlist_events::emit_chatlist_changed(context);
        chatlist_events::emit_chatlist_item_changed(context, new_chat_id);
    }

    if let Some(chat_id) = chat_id {
        Ok(Some((chat_id, chat_id_blocked)))
    } else if is_partial_download || mime_parser.decrypting_failed {
        // It is possible that the message was sent to a valid,
        // yet unknown group, which was rejected because
        // Chat-Group-Name, which is in the encrypted part, was
        // not found. We can't create a properly named group in
        // this case, so assign error message to 1:1 chat with the
        // sender instead.
        Ok(None)
    } else {
        // The message was decrypted successfully, but contains a late "quit" or otherwise
        // unwanted message.
        info!(context, "Message belongs to unwanted group (TRASH).");
        Ok(Some((DC_CHAT_ID_TRASH, Blocked::Not)))
    }
}

async fn update_chats_contacts_timestamps(
    context: &Context,
    chat_id: ChatId,
    ignored_id: Option<ContactId>,
    to_ids: &[Option<ContactId>],
    past_ids: &[Option<ContactId>],
    chat_group_member_timestamps: &[i64],
) -> Result<bool> {
    let expected_timestamps_count = to_ids.len() + past_ids.len();

    if chat_group_member_timestamps.len() != expected_timestamps_count {
        warn!(
            context,
            "Chat-Group-Member-Timestamps has wrong number of timestamps, got {}, expected {}.",
            chat_group_member_timestamps.len(),
            expected_timestamps_count
        );
        return Ok(false);
    }

    let mut modified = false;

    context
        .sql
        .transaction(|transaction| {
            let mut add_statement = transaction.prepare(
                "INSERT INTO chats_contacts (chat_id, contact_id, add_timestamp)
                 VALUES                     (?1,      ?2,         ?3)
                 ON CONFLICT (chat_id, contact_id)
                 DO
                   UPDATE SET add_timestamp=?3
                   WHERE ?3>add_timestamp AND ?3>=remove_timestamp",
            )?;

            for (contact_id, ts) in iter::zip(
                to_ids.iter(),
                chat_group_member_timestamps.iter().take(to_ids.len()),
            ) {
                if let Some(contact_id) = contact_id {
                    if Some(*contact_id) != ignored_id {
                        // It could be that member was already added,
                        // but updated addition timestamp
                        // is also a modification worth notifying about.
                        modified |= add_statement.execute((chat_id, contact_id, ts))? > 0;
                    }
                }
            }

            let mut remove_statement = transaction.prepare(
                "INSERT INTO chats_contacts (chat_id, contact_id, remove_timestamp)
                 VALUES                     (?1,      ?2,         ?3)
                 ON CONFLICT (chat_id, contact_id)
                 DO
                   UPDATE SET remove_timestamp=?3
                   WHERE ?3>remove_timestamp AND ?3>add_timestamp",
            )?;

            for (contact_id, ts) in iter::zip(
                past_ids.iter(),
                chat_group_member_timestamps.iter().skip(to_ids.len()),
            ) {
                if let Some(contact_id) = contact_id {
                    // It could be that member was already removed,
                    // but updated removal timestamp
                    // is also a modification worth notifying about.
                    modified |= remove_statement.execute((chat_id, contact_id, ts))? > 0;
                }
            }

            Ok(())
        })
        .await?;

    Ok(modified)
}

/// The return type of [apply_group_changes].
/// Contains information on which system messages
/// should be shown in the chat.
#[derive(Default)]
struct GroupChangesInfo {
    /// Optional: A better message that should replace the original system message.
    /// If this is an empty string, the original system message should be trashed.
    better_msg: Option<String>,
    /// Added/removed contact `better_msg` refers to.
    added_removed_id: Option<ContactId>,
    /// If true, the user should not be notified about the group change.
    silent: bool,
    /// A list of additional group changes messages that should be shown in the chat.
    extra_msgs: Vec<(String, SystemMessage, Option<ContactId>)>,
}

/// Apply group member list, name, avatar and protection status changes from the MIME message.
///
/// Returns [GroupChangesInfo].
///
/// * `to_ids` - contents of the `To` and `Cc` headers.
/// * `past_ids` - contents of the `Chat-Group-Past-Members` header.
async fn apply_group_changes(
    context: &Context,
    mime_parser: &mut MimeMessage,
    chat: &mut Chat,
    from_id: ContactId,
    to_ids: &[Option<ContactId>],
    past_ids: &[Option<ContactId>],
    verified_encryption: &VerifiedEncryption,
) -> Result<GroupChangesInfo> {
    let to_ids_flat: Vec<ContactId> = to_ids.iter().filter_map(|x| *x).collect();
    ensure!(chat.typ == Chattype::Group);
    ensure!(!chat.id.is_special());

    let mut send_event_chat_modified = false;
    let (mut removed_id, mut added_id) = (None, None);
    let mut better_msg = None;
    let mut silent = false;

    // True if a Delta Chat client has explicitly added our current primary address.
    let self_added =
        if let Some(added_addr) = mime_parser.get_header(HeaderDef::ChatGroupMemberAdded) {
            addr_cmp(&context.get_primary_self_addr().await?, added_addr)
        } else {
            false
        };

    let chat_contacts =
        HashSet::<ContactId>::from_iter(chat::get_chat_contacts(context, chat.id).await?);
    let is_from_in_chat =
        !chat_contacts.contains(&ContactId::SELF) || chat_contacts.contains(&from_id);

    if mime_parser.get_header(HeaderDef::ChatVerified).is_some() && !chat.is_protected() {
        if let VerifiedEncryption::NotVerified(err) = verified_encryption {
            warn!(
                context,
                "Not marking chat {} as protected due to verification problem: {err:#}.", chat.id,
            );
        } else {
            chat.id
                .set_protection(
                    context,
                    ProtectionStatus::Protected,
                    mime_parser.timestamp_sent,
                    Some(from_id),
                )
                .await?;
        }
    }

    if let Some(removed_addr) = mime_parser.get_header(HeaderDef::ChatGroupMemberRemoved) {
        // TODO: if address "alice@example.org" is a member of the group twice,
        // with old and new key,
        // and someone (maybe Alice's new contact) just removed Alice's old contact,
        // we may lookup the wrong contact because we only look up by the address.
        // The result is that info message may contain the new Alice's display name
        // rather than old display name.
        // This could be fixed by looking up the contact with the highest
        // `remove_timestamp` after applying Chat-Group-Member-Timestamps.
        removed_id = lookup_key_contact_by_address(context, removed_addr, Some(chat.id)).await?;
        if let Some(id) = removed_id {
            better_msg = if id == from_id {
                silent = true;
                Some(stock_str::msg_group_left_local(context, from_id).await)
            } else {
                Some(stock_str::msg_del_member_local(context, id, from_id).await)
            };
        } else {
            warn!(context, "Removed {removed_addr:?} has no contact id.")
        }
    } else if let Some(added_addr) = mime_parser.get_header(HeaderDef::ChatGroupMemberAdded) {
        if let Some(key) = mime_parser.gossiped_keys.get(added_addr) {
            // TODO: if gossiped keys contain the same address multiple times,
            // we may lookup the wrong contact.
            // This could be fixed by looking up the contact with
            // highest `add_timestamp` to disambiguate.
            // The result of the error is that info message
            // may contain display name of the wrong contact.
            let fingerprint = key.dc_fingerprint().hex();
            if let Some(contact_id) =
                lookup_key_contact_by_fingerprint(context, &fingerprint).await?
            {
                added_id = Some(contact_id);
                better_msg =
                    Some(stock_str::msg_add_member_local(context, contact_id, from_id).await);
            } else {
                warn!(context, "Added {added_addr:?} has no contact id.");
            }
        } else {
            warn!(context, "Added {added_addr:?} has no gossiped key.");
        }
    }

    if is_from_in_chat {
        apply_chat_name_and_avatar_changes(
            context,
            mime_parser,
            from_id,
            chat,
            &mut send_event_chat_modified,
            &mut better_msg,
        )
        .await?;

        if chat.member_list_is_stale(context).await? {
            info!(context, "Member list is stale.");
            let mut new_members: HashSet<ContactId> =
                HashSet::from_iter(to_ids_flat.iter().copied());
            new_members.insert(ContactId::SELF);
            if !from_id.is_special() {
                new_members.insert(from_id);
            }

            context
                .sql
                .transaction(|transaction| {
                    // Remove all contacts and tombstones.
                    transaction.execute(
                        "DELETE FROM chats_contacts
                         WHERE chat_id=?",
                        (chat.id,),
                    )?;

                    // Insert contacts with default timestamps of 0.
                    let mut statement = transaction.prepare(
                        "INSERT INTO chats_contacts (chat_id, contact_id)
                         VALUES                     (?,       ?)",
                    )?;
                    for contact_id in &new_members {
                        statement.execute((chat.id, contact_id))?;
                    }

                    Ok(())
                })
                .await?;
            send_event_chat_modified = true;
        } else if let Some(ref chat_group_member_timestamps) =
            mime_parser.chat_group_member_timestamps()
        {
            send_event_chat_modified |= update_chats_contacts_timestamps(
                context,
                chat.id,
                Some(from_id),
                to_ids,
                past_ids,
                chat_group_member_timestamps,
            )
            .await?;
        } else {
            let mut new_members: HashSet<ContactId>;
            if self_added {
                new_members = HashSet::from_iter(to_ids_flat.iter().copied());
                new_members.insert(ContactId::SELF);
                if !from_id.is_special() {
                    new_members.insert(from_id);
                }
            } else {
                new_members = chat_contacts.clone();
            }

            // Allow non-Delta Chat MUAs to add members.
            if mime_parser.get_header(HeaderDef::ChatVersion).is_none() {
                // Don't delete any members locally, but instead add absent ones to provide group
                // membership consistency for all members:
                new_members.extend(to_ids_flat.iter());
            }

            // Apply explicit addition if any.
            if let Some(added_id) = added_id {
                new_members.insert(added_id);
            }

            // Apply explicit removal if any.
            if let Some(removed_id) = removed_id {
                new_members.remove(&removed_id);
            }

            if new_members != chat_contacts {
                chat::update_chat_contacts_table(
                    context,
                    mime_parser.timestamp_sent,
                    chat.id,
                    &new_members,
                )
                .await?;
                send_event_chat_modified = true;
            }
        }

        chat.id
            .update_timestamp(
                context,
                Param::MemberListTimestamp,
                mime_parser.timestamp_sent,
            )
            .await?;
    }

    let new_chat_contacts = HashSet::<ContactId>::from_iter(
        chat::get_chat_contacts(context, chat.id)
            .await?
            .iter()
            .copied(),
    );

    // These are for adding info messages about implicit membership changes.
    let mut added_ids: HashSet<ContactId> = new_chat_contacts
        .difference(&chat_contacts)
        .copied()
        .collect();
    let mut removed_ids: HashSet<ContactId> = chat_contacts
        .difference(&new_chat_contacts)
        .copied()
        .collect();

    if let Some(added_id) = added_id {
        if !added_ids.remove(&added_id) && !self_added {
            // No-op "Member added" message.
            //
            // Trash it.
            better_msg = Some(String::new());
        }
    }
    if let Some(removed_id) = removed_id {
        removed_ids.remove(&removed_id);
    }
    let group_changes_msgs = if self_added {
        Vec::new()
    } else {
        group_changes_msgs(context, &added_ids, &removed_ids, chat.id).await?
    };

    if send_event_chat_modified {
        context.emit_event(EventType::ChatModified(chat.id));
        chatlist_events::emit_chatlist_item_changed(context, chat.id);
    }
    Ok(GroupChangesInfo {
        better_msg,
        added_removed_id: if added_id.is_some() {
            added_id
        } else {
            removed_id
        },
        silent,
        extra_msgs: group_changes_msgs,
    })
}

/// Applies incoming changes to the group's or broadcast channel's name and avatar.
///
/// - `send_event_chat_modified` is set to `true` if ChatModified event should be sent
/// - `better_msg` is filled with an info message about name change, if necessary
async fn apply_chat_name_and_avatar_changes(
    context: &Context,
    mime_parser: &MimeMessage,
    from_id: ContactId,
    chat: &mut Chat,
    send_event_chat_modified: &mut bool,
    better_msg: &mut Option<String>,
) -> Result<()> {
    // ========== Apply chat name changes ==========

    let group_name_timestamp = mime_parser
        .get_header(HeaderDef::ChatGroupNameTimestamp)
        .and_then(|s| s.parse::<i64>().ok());

    if let Some(old_name) = mime_parser
        .get_header(HeaderDef::ChatGroupNameChanged)
        .map(|s| s.trim())
        .or(match group_name_timestamp {
            Some(0) => None,
            Some(_) => Some(chat.name.as_str()),
            None => None,
        })
    {
        if let Some(grpname) = mime_parser
            .get_header(HeaderDef::ChatGroupName)
            .map(|grpname| grpname.trim())
            .filter(|grpname| grpname.len() < 200)
        {
            let grpname = &sanitize_single_line(grpname);

            let chat_group_name_timestamp =
                chat.param.get_i64(Param::GroupNameTimestamp).unwrap_or(0);
            let group_name_timestamp = group_name_timestamp.unwrap_or(mime_parser.timestamp_sent);
            // To provide group name consistency, compare names if timestamps are equal.
            if (chat_group_name_timestamp, grpname) < (group_name_timestamp, &chat.name)
                && chat
                    .id
                    .update_timestamp(context, Param::GroupNameTimestamp, group_name_timestamp)
                    .await?
                && grpname != &chat.name
            {
                info!(context, "Updating grpname for chat {}.", chat.id);
                context
                    .sql
                    .execute("UPDATE chats SET name=? WHERE id=?;", (grpname, chat.id))
                    .await?;
                *send_event_chat_modified = true;
            }
            if mime_parser
                .get_header(HeaderDef::ChatGroupNameChanged)
                .is_some()
            {
                let old_name = &sanitize_single_line(old_name);
                better_msg.get_or_insert(
                    stock_str::msg_grp_name(context, old_name, grpname, from_id).await,
                );
            }
        }
    }

    // ========== Apply chat avatar changes ==========

    if let (Some(value), None) = (mime_parser.get_header(HeaderDef::ChatContent), &better_msg) {
        if value == "group-avatar-changed" {
            if let Some(avatar_action) = &mime_parser.group_avatar {
                // this is just an explicit message containing the group-avatar,
                // apart from that, the group-avatar is send along with various other messages
                better_msg.get_or_insert(match avatar_action {
                    AvatarAction::Delete => stock_str::msg_grp_img_deleted(context, from_id).await,
                    AvatarAction::Change(_) => {
                        stock_str::msg_grp_img_changed(context, from_id).await
                    }
                });
            }
        }
    }

    if let Some(avatar_action) = &mime_parser.group_avatar {
        info!(context, "Group-avatar change for {}.", chat.id);
        if chat
            .param
            .update_timestamp(Param::AvatarTimestamp, mime_parser.timestamp_sent)?
        {
            match avatar_action {
                AvatarAction::Change(profile_image) => {
                    chat.param.set(Param::ProfileImage, profile_image);
                }
                AvatarAction::Delete => {
                    chat.param.remove(Param::ProfileImage);
                }
            };
            chat.update_param(context).await?;
            *send_event_chat_modified = true;
        }
    }

    Ok(())
}

/// Returns a list of strings that should be shown as info messages, informing about group membership changes.
async fn group_changes_msgs(
    context: &Context,
    added_ids: &HashSet<ContactId>,
    removed_ids: &HashSet<ContactId>,
    chat_id: ChatId,
) -> Result<Vec<(String, SystemMessage, Option<ContactId>)>> {
    let mut group_changes_msgs: Vec<(String, SystemMessage, Option<ContactId>)> = Vec::new();
    if !added_ids.is_empty() {
        warn!(
            context,
            "Implicit addition of {added_ids:?} to chat {chat_id}."
        );
    }
    if !removed_ids.is_empty() {
        warn!(
            context,
            "Implicit removal of {removed_ids:?} from chat {chat_id}."
        );
    }
    group_changes_msgs.reserve(added_ids.len() + removed_ids.len());
    for contact_id in added_ids {
        group_changes_msgs.push((
            stock_str::msg_add_member_local(context, *contact_id, ContactId::UNDEFINED).await,
            SystemMessage::MemberAddedToGroup,
            Some(*contact_id),
        ));
    }
    for contact_id in removed_ids {
        group_changes_msgs.push((
            stock_str::msg_del_member_local(context, *contact_id, ContactId::UNDEFINED).await,
            SystemMessage::MemberRemovedFromGroup,
            Some(*contact_id),
        ));
    }

    Ok(group_changes_msgs)
}

static LIST_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+)<(.+)>$").unwrap());

fn mailinglist_header_listid(list_id_header: &str) -> Result<String> {
    Ok(match LIST_ID_REGEX.captures(list_id_header) {
        Some(cap) => cap.get(2).context("no match??")?.as_str().trim(),
        None => list_id_header
            .trim()
            .trim_start_matches('<')
            .trim_end_matches('>'),
    }
    .to_string())
}

/// Create or lookup a mailing list or incoming broadcast channel chat.
///
/// `list_id_header` contains the Id that must be used for the mailing list
/// and has the form `Name <Id>`, `<Id>` or just `Id`.
/// Depending on the mailing list type, `list_id_header`
/// was picked from `ListId:`-header or the `Sender:`-header.
///
/// `mime_parser` is the corresponding message
/// and is used to figure out the mailing list name from different header fields.
async fn create_or_lookup_mailinglist_or_broadcast(
    context: &Context,
    allow_creation: bool,
    list_id_header: &str,
    from_id: ContactId,
    mime_parser: &MimeMessage,
) -> Result<Option<(ChatId, Blocked)>> {
    let listid = mailinglist_header_listid(list_id_header)?;

    if let Some((chat_id, _, blocked)) = chat::get_chat_id_by_grpid(context, &listid).await? {
        return Ok(Some((chat_id, blocked)));
    }

    let chattype = if mime_parser.was_encrypted() {
        Chattype::InBroadcast
    } else {
        Chattype::Mailinglist
    };

    let name = if chattype == Chattype::InBroadcast {
        mime_parser
            .get_header(HeaderDef::ChatGroupName)
            .unwrap_or("Broadcast Channel")
    } else {
        &compute_mailinglist_name(list_id_header, &listid, mime_parser)
    };

    if allow_creation {
        // list does not exist but should be created
        let param = mime_parser.list_post.as_ref().map(|list_post| {
            let mut p = Params::new();
            p.set(Param::ListPost, list_post);
            p.to_string()
        });

        let is_bot = context.get_config_bool(Config::Bot).await?;
        let blocked = if is_bot {
            Blocked::Not
        } else {
            Blocked::Request
        };
        let chat_id = ChatId::create_multiuser_record(
            context,
            chattype,
            &listid,
            name,
            blocked,
            ProtectionStatus::Unprotected,
            param,
            mime_parser.timestamp_sent,
        )
        .await
        .with_context(|| {
            format!(
                "failed to create mailinglist '{}' for grpid={}",
                &name, &listid
            )
        })?;

        chat::add_to_chat_contacts_table(
            context,
            mime_parser.timestamp_sent,
            chat_id,
            &[ContactId::SELF],
        )
        .await?;
        if chattype == Chattype::InBroadcast {
            chat::add_to_chat_contacts_table(
                context,
                mime_parser.timestamp_sent,
                chat_id,
                &[from_id],
            )
            .await?;
        }
        Ok(Some((chat_id, blocked)))
    } else {
        info!(context, "Creating list forbidden by caller.");
        Ok(None)
    }
}

fn compute_mailinglist_name(
    list_id_header: &str,
    listid: &str,
    mime_parser: &MimeMessage,
) -> String {
    let mut name = match LIST_ID_REGEX
        .captures(list_id_header)
        .and_then(|caps| caps.get(1))
    {
        Some(cap) => cap.as_str().trim().to_string(),
        None => "".to_string(),
    };

    // for mailchimp lists, the name in `ListId` is just a long number.
    // a usable name for these lists is in the `From` header
    // and we can detect these lists by a unique `ListId`-suffix.
    if listid.ends_with(".list-id.mcsv.net") {
        if let Some(display_name) = &mime_parser.from.display_name {
            name.clone_from(display_name);
        }
    }

    // additional names in square brackets in the subject are preferred
    // (as that part is much more visible, we assume, that names is shorter and comes more to the point,
    // than the sometimes longer part from ListId)
    let subject = mime_parser.get_subject().unwrap_or_default();
    static SUBJECT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^.{0,5}\[(.+?)\](\s*\[.+\])?").unwrap()); // remove square brackets around first name
    if let Some(cap) = SUBJECT.captures(&subject) {
        name = cap[1].to_string() + cap.get(2).map_or("", |m| m.as_str());
    }

    // if we do not have a name yet and `From` indicates, that this is a notification list,
    // a usable name is often in the `From` header (seen for several parcel service notifications).
    // same, if we do not have a name yet and `List-Id` has a known suffix (`.xt.local`)
    //
    // this pattern is similar to mailchimp above, however,
    // with weaker conditions and does not overwrite existing names.
    if name.is_empty()
        && (mime_parser.from.addr.contains("noreply")
            || mime_parser.from.addr.contains("no-reply")
            || mime_parser.from.addr.starts_with("notifications@")
            || mime_parser.from.addr.starts_with("newsletter@")
            || listid.ends_with(".xt.local"))
    {
        if let Some(display_name) = &mime_parser.from.display_name {
            name.clone_from(display_name);
        }
    }

    // as a last resort, use the ListId as the name
    // but strip some known, long hash prefixes
    if name.is_empty() {
        // 51231231231231231231231232869f58.xing.com -> xing.com
        static PREFIX_32_CHARS_HEX: LazyLock<Regex> =
            LazyLock::new(|| Regex::new(r"([0-9a-fA-F]{32})\.(.{6,})").unwrap());
        if let Some(cap) = PREFIX_32_CHARS_HEX
            .captures(listid)
            .and_then(|caps| caps.get(2))
        {
            name = cap.as_str().to_string();
        } else {
            name = listid.to_string();
        }
    }

    sanitize_single_line(&name)
}

/// Set ListId param on the contact and ListPost param the chat.
/// Only called for incoming messages since outgoing messages never have a
/// List-Post header, anyway.
async fn apply_mailinglist_changes(
    context: &Context,
    mime_parser: &MimeMessage,
    chat_id: ChatId,
) -> Result<()> {
    let Some(mailinglist_header) = mime_parser.get_mailinglist_header() else {
        return Ok(());
    };

    let mut chat = Chat::load_from_db(context, chat_id).await?;
    if chat.typ != Chattype::Mailinglist {
        return Ok(());
    }
    let listid = &chat.grpid;

    let new_name = compute_mailinglist_name(mailinglist_header, listid, mime_parser);
    if chat.name != new_name
        && chat_id
            .update_timestamp(
                context,
                Param::GroupNameTimestamp,
                mime_parser.timestamp_sent,
            )
            .await?
    {
        info!(context, "Updating listname for chat {chat_id}.");
        context
            .sql
            .execute("UPDATE chats SET name=? WHERE id=?;", (new_name, chat_id))
            .await?;
        context.emit_event(EventType::ChatModified(chat_id));
    }

    let Some(list_post) = &mime_parser.list_post else {
        return Ok(());
    };

    let list_post = match ContactAddress::new(list_post) {
        Ok(list_post) => list_post,
        Err(err) => {
            warn!(context, "Invalid List-Post: {:#}.", err);
            return Ok(());
        }
    };
    let (contact_id, _) = Contact::add_or_lookup(context, "", &list_post, Origin::Hidden).await?;
    let mut contact = Contact::get_by_id(context, contact_id).await?;
    if contact.param.get(Param::ListId) != Some(listid) {
        contact.param.set(Param::ListId, listid);
        contact.update_param(context).await?;
    }

    if let Some(old_list_post) = chat.param.get(Param::ListPost) {
        if list_post.as_ref() != old_list_post {
            // Apparently the mailing list is using a different List-Post header in each message.
            // Make the mailing list read-only because we wouldn't know which message the user wants to reply to.
            chat.param.remove(Param::ListPost);
            chat.update_param(context).await?;
        }
    } else {
        chat.param.set(Param::ListPost, list_post);
        chat.update_param(context).await?;
    }

    Ok(())
}

async fn apply_out_broadcast_changes(
    context: &Context,
    mime_parser: &MimeMessage,
    chat: &mut Chat,
    from_id: ContactId,
) -> Result<GroupChangesInfo> {
    ensure!(chat.typ == Chattype::OutBroadcast);

    if let Some(_removed_addr) = mime_parser.get_header(HeaderDef::ChatGroupMemberRemoved) {
        // The sender of the message left the broadcast channel
        remove_from_chat_contacts_table(context, chat.id, from_id).await?;

        return Ok(GroupChangesInfo {
            better_msg: Some("".to_string()),
            added_removed_id: None,
            silent: true,
            extra_msgs: vec![],
        });
    }

    Ok(GroupChangesInfo::default())
}

async fn apply_in_broadcast_changes(
    context: &Context,
    mime_parser: &MimeMessage,
    chat: &mut Chat,
    from_id: ContactId,
) -> Result<GroupChangesInfo> {
    ensure!(chat.typ == Chattype::InBroadcast);

    let mut send_event_chat_modified = false;
    let mut better_msg = None;

    apply_chat_name_and_avatar_changes(
        context,
        mime_parser,
        from_id,
        chat,
        &mut send_event_chat_modified,
        &mut better_msg,
    )
    .await?;

    if let Some(_removed_addr) = mime_parser.get_header(HeaderDef::ChatGroupMemberRemoved) {
        // The only member added/removed message that is ever sent is "I left.",
        // so, this is the only case we need to handle here
        if from_id == ContactId::SELF {
            better_msg
                .get_or_insert(stock_str::msg_group_left_local(context, ContactId::SELF).await);
        }
    }

    if send_event_chat_modified {
        context.emit_event(EventType::ChatModified(chat.id));
        chatlist_events::emit_chatlist_item_changed(context, chat.id);
    }
    Ok(GroupChangesInfo {
        better_msg,
        added_removed_id: None,
        silent: false,
        extra_msgs: vec![],
    })
}

/// Creates ad-hoc group and returns chat ID on success.
async fn create_adhoc_group(
    context: &Context,
    mime_parser: &MimeMessage,
    create_blocked: Blocked,
    from_id: ContactId,
    to_ids: &[ContactId],
    grpname: &str,
) -> Result<Option<(ChatId, Blocked)>> {
    let mut member_ids: Vec<ContactId> = to_ids.to_vec();
    if !member_ids.contains(&(from_id)) {
        member_ids.push(from_id);
    }
    if !member_ids.contains(&(ContactId::SELF)) {
        member_ids.push(ContactId::SELF);
    }

    if mime_parser.is_mailinglist_message() {
        return Ok(None);
    }
    if mime_parser
        .get_header(HeaderDef::ChatGroupMemberRemoved)
        .is_some()
    {
        info!(
            context,
            "Message removes member from unknown ad-hoc group (TRASH)."
        );
        return Ok(Some((DC_CHAT_ID_TRASH, Blocked::Not)));
    }
    if member_ids.len() < 2 {
        info!(
            context,
            "Not creating ad hoc group with less than 2 members."
        );
        return Ok(None);
    }

    let new_chat_id: ChatId = ChatId::create_multiuser_record(
        context,
        Chattype::Group,
        "", // Ad hoc groups have no ID.
        grpname,
        create_blocked,
        ProtectionStatus::Unprotected,
        None,
        mime_parser.timestamp_sent,
    )
    .await?;

    info!(
        context,
        "Created ad-hoc group id={new_chat_id}, name={grpname:?}."
    );
    chat::add_to_chat_contacts_table(
        context,
        mime_parser.timestamp_sent,
        new_chat_id,
        &member_ids,
    )
    .await?;

    context.emit_event(EventType::ChatModified(new_chat_id));
    chatlist_events::emit_chatlist_changed(context);
    chatlist_events::emit_chatlist_item_changed(context, new_chat_id);

    Ok(Some((new_chat_id, create_blocked)))
}

#[derive(Debug, PartialEq, Eq)]
enum VerifiedEncryption {
    Verified,
    NotVerified(String), // The string contains the reason why it's not verified
}

/// Checks whether the message is allowed to appear in a protected chat.
///
/// This means that it is encrypted and signed with a verified key.
async fn has_verified_encryption(
    context: &Context,
    mimeparser: &MimeMessage,
    from_id: ContactId,
) -> Result<VerifiedEncryption> {
    use VerifiedEncryption::*;

    if !mimeparser.was_encrypted() {
        return Ok(NotVerified("This message is not encrypted".to_string()));
    };

    if from_id == ContactId::SELF {
        return Ok(Verified);
    }

    let from_contact = Contact::get_by_id(context, from_id).await?;

    let Some(fingerprint) = from_contact.fingerprint() else {
        return Ok(NotVerified(
            "The message was sent without encryption".to_string(),
        ));
    };

    if from_contact.get_verifier_id(context).await?.is_none() {
        return Ok(NotVerified(
            "The message was sent by non-verified contact".to_string(),
        ));
    }

    let signed_with_verified_key = mimeparser.signatures.contains(&fingerprint);
    if signed_with_verified_key {
        Ok(Verified)
    } else {
        Ok(NotVerified(
            "The message was sent with non-verified encryption".to_string(),
        ))
    }
}

async fn mark_recipients_as_verified(
    context: &Context,
    from_id: ContactId,
    to_ids: &[Option<ContactId>],
    mimeparser: &MimeMessage,
) -> Result<()> {
    if mimeparser.get_header(HeaderDef::ChatVerified).is_none() {
        return Ok(());
    }
    for to_id in to_ids.iter().filter_map(|&x| x) {
        if to_id == ContactId::SELF || to_id == from_id {
            continue;
        }

        mark_contact_id_as_verified(context, to_id, from_id).await?;
        ChatId::set_protection_for_contact(context, to_id, mimeparser.timestamp_sent).await?;
    }

    Ok(())
}

/// Returns the last message referenced from `References` header if it is in the database.
///
/// For Delta Chat messages it is the last message in the chat of the sender.
async fn get_previous_message(
    context: &Context,
    mime_parser: &MimeMessage,
) -> Result<Option<Message>> {
    if let Some(field) = mime_parser.get_header(HeaderDef::References) {
        if let Some(rfc724mid) = parse_message_ids(field).last() {
            if let Some((msg_id, _)) = rfc724_mid_exists(context, rfc724mid).await? {
                return Message::load_from_db_optional(context, msg_id).await;
            }
        }
    }
    Ok(None)
}

/// Returns the last message referenced from References: header found in the database.
///
/// If none found, tries In-Reply-To: as a fallback for classic MUAs that don't set the
/// References: header.
async fn get_parent_message(
    context: &Context,
    references: Option<&str>,
    in_reply_to: Option<&str>,
) -> Result<Option<Message>> {
    let mut mids = Vec::new();
    if let Some(field) = in_reply_to {
        mids = parse_message_ids(field);
    }
    if let Some(field) = references {
        mids.append(&mut parse_message_ids(field));
    }
    message::get_by_rfc724_mids(context, &mids).await
}

pub(crate) async fn get_prefetch_parent_message(
    context: &Context,
    headers: &[mailparse::MailHeader<'_>],
) -> Result<Option<Message>> {
    get_parent_message(
        context,
        headers.get_header_value(HeaderDef::References).as_deref(),
        headers.get_header_value(HeaderDef::InReplyTo).as_deref(),
    )
    .await
}

/// Looks up contact IDs from the database given the list of recipients.
async fn add_or_lookup_contacts_by_address_list(
    context: &Context,
    address_list: &[SingleInfo],
    origin: Origin,
) -> Result<Vec<Option<ContactId>>> {
    let mut contact_ids = Vec::new();
    for info in address_list {
        let addr = &info.addr;
        if !may_be_valid_addr(addr) {
            contact_ids.push(None);
            continue;
        }
        let display_name = info.display_name.as_deref();
        if let Ok(addr) = ContactAddress::new(addr) {
            let (contact_id, _) =
                Contact::add_or_lookup(context, display_name.unwrap_or_default(), &addr, origin)
                    .await?;
            contact_ids.push(Some(contact_id));
        } else {
            warn!(context, "Contact with address {:?} cannot exist.", addr);
            contact_ids.push(None);
        }
    }

    Ok(contact_ids)
}

/// Looks up contact IDs from the database given the list of recipients.
async fn add_or_lookup_key_contacts(
    context: &Context,
    address_list: &[SingleInfo],
    gossiped_keys: &HashMap<String, SignedPublicKey>,
    fingerprints: &[Fingerprint],
    origin: Origin,
) -> Result<Vec<Option<ContactId>>> {
    let mut contact_ids = Vec::new();
    let mut fingerprint_iter = fingerprints.iter();
    for info in address_list {
        let addr = &info.addr;
        if !may_be_valid_addr(addr) {
            contact_ids.push(None);
            continue;
        }
        let fingerprint: String = if let Some(fp) = fingerprint_iter.next() {
            // Iterator has not ran out of fingerprints yet.
            fp.hex()
        } else if let Some(key) = gossiped_keys.get(addr) {
            key.dc_fingerprint().hex()
        } else if context.is_self_addr(addr).await? {
            contact_ids.push(Some(ContactId::SELF));
            continue;
        } else {
            contact_ids.push(None);
            continue;
        };
        let display_name = info.display_name.as_deref();
        if let Ok(addr) = ContactAddress::new(addr) {
            let (contact_id, _) = Contact::add_or_lookup_ex(
                context,
                display_name.unwrap_or_default(),
                &addr,
                &fingerprint,
                origin,
            )
            .await?;
            contact_ids.push(Some(contact_id));
        } else {
            warn!(context, "Contact with address {:?} cannot exist.", addr);
            contact_ids.push(None);
        }
    }

    ensure_and_debug_assert_eq!(contact_ids.len(), address_list.len(),);
    Ok(contact_ids)
}

/// Looks up a key-contact by email address.
///
/// If provided, `chat_id` must be an encrypted chat ID that has key-contacts inside.
/// Otherwise the function searches in all contacts, preferring accepted and most recently seen ones.
async fn lookup_key_contact_by_address(
    context: &Context,
    addr: &str,
    chat_id: Option<ChatId>,
) -> Result<Option<ContactId>> {
    if context.is_self_addr(addr).await? {
        if chat_id.is_none() {
            return Ok(Some(ContactId::SELF));
        }
        let is_self_in_chat = context
            .sql
            .exists(
                "SELECT COUNT(*) FROM chats_contacts WHERE chat_id=? AND contact_id=1",
                (chat_id,),
            )
            .await?;
        if is_self_in_chat {
            return Ok(Some(ContactId::SELF));
        }
    }
    let contact_id: Option<ContactId> = match chat_id {
        Some(chat_id) => {
            context
                .sql
                .query_row_optional(
                    "SELECT id FROM contacts
                     WHERE contacts.addr=?
                     AND EXISTS (SELECT 1 FROM chats_contacts
                                 WHERE contact_id=contacts.id
                                 AND chat_id=?)
                     AND fingerprint<>'' -- Should always be true
                     ",
                    (addr, chat_id),
                    |row| {
                        let contact_id: ContactId = row.get(0)?;
                        Ok(contact_id)
                    },
                )
                .await?
        }
        None => {
            context
                .sql
                .query_row_optional(
                    "SELECT id FROM contacts
                     WHERE addr=?
                     AND fingerprint<>''
                     ORDER BY
                         (
                             SELECT COUNT(*) FROM chats c
                             INNER JOIN chats_contacts cc
                             ON c.id=cc.chat_id
                             WHERE c.type=?
                                 AND c.id>?
                                 AND c.blocked=?
                                 AND cc.contact_id=contacts.id
                         ) DESC,
                         last_seen DESC, id DESC
                     ",
                    (
                        addr,
                        Chattype::Single,
                        constants::DC_CHAT_ID_LAST_SPECIAL,
                        Blocked::Not,
                    ),
                    |row| {
                        let contact_id: ContactId = row.get(0)?;
                        Ok(contact_id)
                    },
                )
                .await?
        }
    };
    Ok(contact_id)
}

async fn lookup_key_contact_by_fingerprint(
    context: &Context,
    fingerprint: &str,
) -> Result<Option<ContactId>> {
    logged_debug_assert!(
        context,
        !fingerprint.is_empty(),
        "lookup_key_contact_by_fingerprint: fingerprint is empty."
    );
    if fingerprint.is_empty() {
        // Avoid accidentally looking up a non-key-contact.
        return Ok(None);
    }
    if let Some(contact_id) = context
        .sql
        .query_row_optional(
            "SELECT id FROM contacts
             WHERE fingerprint=? AND fingerprint!=''",
            (fingerprint,),
            |row| {
                let contact_id: ContactId = row.get(0)?;
                Ok(contact_id)
            },
        )
        .await?
    {
        Ok(Some(contact_id))
    } else if let Some(self_fp) = self_fingerprint_opt(context).await? {
        if self_fp == fingerprint {
            Ok(Some(ContactId::SELF))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}

/// Looks up key-contacts by email addresses.
///
/// `fingerprints` may be empty.
/// This is used as a fallback when email addresses are available,
/// but not the fingerprints, e.g. when core 1.157.3
/// client sends the `To` and `Chat-Group-Past-Members` header
/// but not the corresponding fingerprint list.
///
/// Lookup is restricted to the chat ID.
///
/// If contact cannot be found, `None` is returned.
/// This ensures that the length of the result vector
/// is the same as the number of addresses in the header
/// and it is possible to find corresponding
/// `Chat-Group-Member-Timestamps` items.
async fn lookup_key_contacts_by_address_list(
    context: &Context,
    address_list: &[SingleInfo],
    fingerprints: &[Fingerprint],
    chat_id: Option<ChatId>,
) -> Result<Vec<Option<ContactId>>> {
    let mut contact_ids = Vec::new();
    let mut fingerprint_iter = fingerprints.iter();
    for info in address_list {
        let addr = &info.addr;
        if !may_be_valid_addr(addr) {
            contact_ids.push(None);
            continue;
        }

        if let Some(fp) = fingerprint_iter.next() {
            // Iterator has not ran out of fingerprints yet.
            let display_name = info.display_name.as_deref();
            let fingerprint: String = fp.hex();

            if let Ok(addr) = ContactAddress::new(addr) {
                let (contact_id, _) = Contact::add_or_lookup_ex(
                    context,
                    display_name.unwrap_or_default(),
                    &addr,
                    &fingerprint,
                    Origin::Hidden,
                )
                .await?;
                contact_ids.push(Some(contact_id));
            } else {
                warn!(context, "Contact with address {:?} cannot exist.", addr);
                contact_ids.push(None);
            }
        } else {
            let contact_id = lookup_key_contact_by_address(context, addr, chat_id).await?;
            contact_ids.push(contact_id);
        }
    }
    ensure_and_debug_assert_eq!(address_list.len(), contact_ids.len(),);
    Ok(contact_ids)
}

/// Returns true if the message should not result in renaming
/// of the sender contact.
fn should_prevent_rename(mime_parser: &MimeMessage) -> bool {
    (mime_parser.is_mailinglist_message() && !mime_parser.was_encrypted())
        || mime_parser.get_header(HeaderDef::Sender).is_some()
}

#[cfg(test)]
mod receive_imf_tests;
