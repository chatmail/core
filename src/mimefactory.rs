//! # MIME message production.

use std::collections::{BTreeSet, HashSet};
use std::io::Cursor;

use anyhow::{Context as _, Result, bail, format_err};
use base64::Engine as _;
use data_encoding::BASE32_NOPAD;
use deltachat_contact_tools::sanitize_bidi_characters;
use iroh_gossip::proto::TopicId;
use mail_builder::headers::HeaderType;
use mail_builder::headers::address::Address;
use mail_builder::mime::MimePart;
use tokio::fs;

use crate::aheader::{Aheader, EncryptPreference};
use crate::blob::BlobObject;
use crate::chat::{self, Chat, PARAM_BROADCAST_SECRET, load_broadcast_secret};
use crate::config::Config;
use crate::constants::{ASM_SUBJECT, BROADCAST_INCOMPATIBILITY_MSG};
use crate::constants::{Chattype, DC_FROM_HANDSHAKE};
use crate::contact::{Contact, ContactId, Origin};
use crate::context::Context;
use crate::download::PostMsgMetadata;
use crate::e2ee::EncryptHelper;
use crate::ensure_and_debug_assert;
use crate::ephemeral::Timer as EphemeralTimer;
use crate::headerdef::HeaderDef;
use crate::key::{DcKey, SignedPublicKey, self_fingerprint};
use crate::location;
use crate::log::warn;
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::{SystemMessage, is_hidden};
use crate::param::Param;
use crate::peer_channels::{create_iroh_header, get_iroh_topic_for_msg};
use crate::pgp::SeipdVersion;
use crate::simplify::escape_message_footer_marks;
use crate::stock_str;
use crate::tools::{
    IsNoneOrEmpty, create_outgoing_rfc724_mid, create_smeared_timestamp, remove_subject_prefix,
    time,
};
use crate::webxdc::StatusUpdateSerial;

// attachments of 25 mb brutto should work on the majority of providers
// (brutto examples: web.de=50, 1&1=40, t-online.de=32, gmail=25, posteo=50, yahoo=25, all-inkl=100).
// to get the netto sizes, we subtract 1 mb header-overhead and the base64-overhead.
pub const RECOMMENDED_FILE_SIZE: u64 = 24 * 1024 * 1024 / 4 * 3;

#[derive(Debug, Clone)]
#[expect(clippy::large_enum_variant)]
pub enum Loaded {
    Message {
        chat: Chat,
        msg: Message,
    },
    Mdn {
        rfc724_mid: String,
        additional_msg_ids: Vec<String>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PreMessageMode {
    /// adds the Chat-Is-Post-Message header in unprotected part
    Post,
    /// adds the Chat-Post-Message-ID header to protected part
    /// also adds metadata and explicitly excludes attachment
    Pre { post_msg_rfc724_mid: String },
    /// Atomic ("normal") message.
    None,
}

/// Helper to construct mime messages.
#[derive(Debug, Clone)]
pub struct MimeFactory {
    from_addr: String,
    from_displayname: String,

    /// Goes to the `Sender:`-header, if set.
    /// For overridden names, `sender_displayname` is set to the
    /// config-name while `from_displayname` is set to the overridden name.
    /// From the perspective of the receiver,
    /// a set `Sender:`-header is used as an indicator that the name is overridden;
    /// names are alsways read from the `From:`-header.
    sender_displayname: Option<String>,

    selfstatus: String,

    /// Vector of actual recipient addresses.
    ///
    /// This is the list of addresses the message should be sent to.
    /// It is not the same as the `To` header,
    /// because in case of "member removed" message
    /// removed member is in the recipient list,
    /// but not in the `To` header.
    /// In case of broadcast channels there are multiple recipients,
    /// but the `To` header has no members.
    ///
    /// If `bcc_self` configuration is enabled,
    /// this list will be extended with own address later,
    /// but `MimeFactory` is not responsible for this.
    recipients: Vec<String>,

    /// Vector of pairs of recipient
    /// addresses and OpenPGP keys
    /// to use for encryption.
    ///
    /// If `Some`, encrypt to self also.
    /// `None` if the message is not encrypted.
    encryption_pubkeys: Option<Vec<(String, SignedPublicKey)>>,

    /// Vector of pairs of recipient name and address that goes into the `To` field.
    ///
    /// The list of actual message recipient addresses may be different,
    /// e.g. if members are hidden for broadcast channels
    /// or if the keys for some recipients are missing
    /// and encrypted message cannot be sent to them.
    to: Vec<(String, String)>,

    /// Vector of pairs of past group member names and addresses.
    past_members: Vec<(String, String)>,

    /// Fingerprints of the members in the same order as in the `to`
    /// followed by `past_members`.
    ///
    /// If this is not empty, its length
    /// should be the sum of `to` and `past_members` length.
    member_fingerprints: Vec<String>,

    /// Timestamps of the members in the same order as in the `to`
    /// followed by `past_members`.
    ///
    /// If this is not empty, its length
    /// should be the sum of `to` and `past_members` length.
    member_timestamps: Vec<i64>,

    timestamp: i64,
    loaded: Loaded,
    in_reply_to: String,

    /// List of Message-IDs for `References` header.
    references: Vec<String>,

    /// True if the message requests Message Disposition Notification
    /// using `Chat-Disposition-Notification-To` header.
    req_mdn: bool,

    last_added_location_id: Option<u32>,

    /// If the created mime-structure contains sync-items,
    /// the IDs of these items are listed here.
    /// The IDs are returned via `RenderedEmail`
    /// and must be deleted if the message is actually queued for sending.
    sync_ids_to_delete: Option<String>,

    /// True if the avatar should be attached.
    pub attach_selfavatar: bool,

    /// This field is used to sustain the topic id of webxdcs needed for peer channels.
    webxdc_topic: Option<TopicId>,

    /// Pre-message / post-message / atomic message.
    pre_message_mode: PreMessageMode,
}

/// Result of rendering a message, ready to be submitted to a send job.
#[derive(Debug, Clone)]
pub struct RenderedEmail {
    pub message: String,
    // pub envelope: Envelope,
    pub is_encrypted: bool,
    pub last_added_location_id: Option<u32>,

    /// A comma-separated string of sync-IDs that are used by the rendered email and must be deleted
    /// from `multi_device_sync` once the message is actually queued for sending.
    pub sync_ids_to_delete: Option<String>,

    /// Message ID (Message in the sense of Email)
    pub rfc724_mid: String,

    /// Message subject.
    pub subject: String,
}

fn new_address_with_name(name: &str, address: String) -> Address<'static> {
    Address::new_address(
        if name == address || name.is_empty() {
            None
        } else {
            Some(name.to_string())
        },
        address,
    )
}

impl MimeFactory {
    #[expect(clippy::arithmetic_side_effects)]
    pub async fn from_msg(context: &Context, msg: Message) -> Result<MimeFactory> {
        let now = time();
        let chat = Chat::load_from_db(context, msg.chat_id).await?;
        let attach_profile_data = Self::should_attach_profile_data(&msg);
        let undisclosed_recipients = should_hide_recipients(&msg, &chat);

        let from_addr = context.get_primary_self_addr().await?;
        let config_displayname = context
            .get_config(Config::Displayname)
            .await?
            .unwrap_or_default();
        let (from_displayname, sender_displayname) =
            if let Some(override_name) = msg.param.get(Param::OverrideSenderDisplayname) {
                (override_name.to_string(), Some(config_displayname))
            } else {
                let name = match attach_profile_data {
                    true => config_displayname,
                    false => "".to_string(),
                };
                (name, None)
            };

        let mut recipients = Vec::new();
        let mut to = Vec::new();
        let mut past_members = Vec::new();
        let mut member_fingerprints = Vec::new();
        let mut member_timestamps = Vec::new();
        let mut recipient_ids = HashSet::new();
        let mut req_mdn = false;

        let encryption_pubkeys;

        let self_fingerprint = self_fingerprint(context).await?;

        if chat.is_self_talk() {
            to.push((from_displayname.to_string(), from_addr.to_string()));

            encryption_pubkeys = if msg.param.get_bool(Param::ForcePlaintext).unwrap_or(false) {
                None
            } else {
                Some(Vec::new())
            };
        } else if chat.is_mailing_list() {
            let list_post = chat
                .param
                .get(Param::ListPost)
                .context("Can't write to mailinglist without ListPost param")?;
            to.push(("".to_string(), list_post.to_string()));
            recipients.push(list_post.to_string());

            // Do not encrypt messages to mailing lists.
            encryption_pubkeys = None;
        } else if let Some(fp) = must_have_only_one_recipient(&msg, &chat) {
            let fp = fp?;
            // In a broadcast channel, only send member-added/removed messages
            // to the affected member
            let (authname, addr) = context
                .sql
                .query_row(
                    "SELECT authname, addr FROM contacts WHERE fingerprint=?",
                    (fp,),
                    |row| {
                        let authname: String = row.get(0)?;
                        let addr: String = row.get(1)?;
                        Ok((authname, addr))
                    },
                )
                .await?;

            let public_key_bytes: Vec<_> = context
                .sql
                .query_get_value(
                    "SELECT public_key FROM public_keys WHERE fingerprint=?",
                    (fp,),
                )
                .await?
                .context("Can't send member addition/removal: missing key")?;

            recipients.push(addr.clone());
            to.push((authname, addr.clone()));

            let public_key = SignedPublicKey::from_slice(&public_key_bytes)?;
            encryption_pubkeys = Some(vec![(addr, public_key)]);
        } else {
            let email_to_remove = if msg.param.get_cmd() == SystemMessage::MemberRemovedFromGroup {
                msg.param.get(Param::Arg)
            } else {
                None
            };

            let is_encrypted = if msg
                .param
                .get_bool(Param::ForcePlaintext)
                .unwrap_or_default()
            {
                false
            } else {
                msg.param.get_bool(Param::GuaranteeE2ee).unwrap_or_default()
                    || chat.is_encrypted(context).await?
            };

            let mut keys = Vec::new();
            let mut missing_key_addresses = BTreeSet::new();
            context
                .sql
                // Sort recipients by `add_timestamp DESC` so that if the group is large and there
                // are multiple SMTP messages, a newly added member receives the member addition
                // message earlier and has gossiped keys of other members (otherwise the new member
                // may receive messages from other members earlier and fail to verify them).
                .query_map(
                    "SELECT
                     c.authname,
                     c.addr,
                     c.fingerprint,
                     c.id,
                     cc.add_timestamp,
                     cc.remove_timestamp,
                     k.public_key
                     FROM chats_contacts cc
                     LEFT JOIN contacts c ON cc.contact_id=c.id
                     LEFT JOIN public_keys k ON k.fingerprint=c.fingerprint
                     WHERE cc.chat_id=?
                     AND (cc.contact_id>9 OR (cc.contact_id=1 AND ?))
                     ORDER BY cc.add_timestamp DESC",
                    (msg.chat_id, chat.typ == Chattype::Group),
                    |row| {
                        let authname: String = row.get(0)?;
                        let addr: String = row.get(1)?;
                        let fingerprint: String = row.get(2)?;
                        let id: ContactId = row.get(3)?;
                        let add_timestamp: i64 = row.get(4)?;
                        let remove_timestamp: i64 = row.get(5)?;
                        let public_key_bytes_opt: Option<Vec<u8>> = row.get(6)?;
                        Ok((authname, addr, fingerprint, id, add_timestamp, remove_timestamp, public_key_bytes_opt))
                    },
                    |rows| {
                        let mut past_member_timestamps = Vec::new();
                        let mut past_member_fingerprints = Vec::new();

                        for row in rows {
                            let (authname, addr, fingerprint, id, add_timestamp, remove_timestamp, public_key_bytes_opt) = row?;

                            let public_key_opt = if let Some(public_key_bytes) = &public_key_bytes_opt {
                                Some(SignedPublicKey::from_slice(public_key_bytes)?)
                            } else {
                                None
                            };

                            let addr = if id == ContactId::SELF {
                                from_addr.to_string()
                            } else {
                                addr
                            };
                            let name = match attach_profile_data {
                                true => authname,
                                false => "".to_string(),
                            };
                            if add_timestamp >= remove_timestamp {
                                if !recipients_contain_addr(&to, &addr) {
                                    if id != ContactId::SELF {
                                        recipients.push(addr.clone());
                                    }
                                    if !undisclosed_recipients {
                                        to.push((name, addr.clone()));

                                        if is_encrypted {
                                            if !fingerprint.is_empty() {
                                                member_fingerprints.push(fingerprint);
                                            } else if id == ContactId::SELF {
                                                member_fingerprints.push(self_fingerprint.to_string());
                                            } else {
                                                ensure_and_debug_assert!(member_fingerprints.is_empty(), "If some past member is a key-contact, all other past members should be key-contacts too");
                                            }
                                        }
                                        member_timestamps.push(add_timestamp);
                                    }
                                }
                                recipient_ids.insert(id);

                                if let Some(public_key) = public_key_opt {
                                    keys.push((addr.clone(), public_key))
                                } else if id != ContactId::SELF && !should_encrypt_symmetrically(&msg, &chat) {
                                    missing_key_addresses.insert(addr.clone());
                                    if is_encrypted {
                                        warn!(context, "Missing key for {addr}");
                                    }
                                }
                            } else if remove_timestamp.saturating_add(60 * 24 * 3600) > now {
                                // Row is a tombstone,
                                // member is not actually part of the group.
                                if !recipients_contain_addr(&past_members, &addr) {
                                    if let Some(email_to_remove) = email_to_remove
                                        && email_to_remove == addr {
                                            // This is a "member removed" message,
                                            // we need to notify removed member
                                            // that it was removed.
                                            if id != ContactId::SELF {
                                                recipients.push(addr.clone());
                                            }

                                            if let Some(public_key) = public_key_opt {
                                                keys.push((addr.clone(), public_key))
                                            } else if id != ContactId::SELF && !should_encrypt_symmetrically(&msg, &chat)  {
                                                missing_key_addresses.insert(addr.clone());
                                                if is_encrypted {
                                                    warn!(context, "Missing key for {addr}");
                                                }
                                            }
                                        }
                                    if !undisclosed_recipients {
                                        past_members.push((name, addr.clone()));
                                        past_member_timestamps.push(remove_timestamp);

                                        if is_encrypted {
                                            if !fingerprint.is_empty() {
                                                past_member_fingerprints.push(fingerprint);
                                            } else if id == ContactId::SELF {
                                                // It's fine to have self in past members
                                                // if we are leaving the group.
                                                past_member_fingerprints.push(self_fingerprint.to_string());
                                            } else {
                                                ensure_and_debug_assert!(past_member_fingerprints.is_empty(), "If some past member is a key-contact, all other past members should be key-contacts too");
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        ensure_and_debug_assert!(
                            member_timestamps.len() >= to.len(),
                            "member_timestamps.len() ({}) < to.len() ({})",
                            member_timestamps.len(), to.len());
                        ensure_and_debug_assert!(
                            member_fingerprints.is_empty() || member_fingerprints.len() >= to.len(),
                            "member_fingerprints.len() ({}) < to.len() ({})",
                            member_fingerprints.len(), to.len());

                        if to.len() > 1
                            && let Some(position) = to.iter().position(|(_, x)| x == &from_addr) {
                                to.remove(position);
                                member_timestamps.remove(position);
                                if is_encrypted {
                                    member_fingerprints.remove(position);
                                }
                            }

                        member_timestamps.extend(past_member_timestamps);
                        if is_encrypted {
                            member_fingerprints.extend(past_member_fingerprints);
                        }
                        Ok(())
                    },
                )
                .await?;
            let recipient_ids: Vec<_> = recipient_ids
                .into_iter()
                .filter(|id| *id != ContactId::SELF)
                .collect();
            if recipient_ids.len() == 1
                && msg.param.get_cmd() != SystemMessage::MemberRemovedFromGroup
                && chat.typ != Chattype::OutBroadcast
            {
                ContactId::scaleup_origin(context, &recipient_ids, Origin::OutgoingTo).await?;
            }

            if !msg.is_system_message()
                && msg.param.get_int(Param::Reaction).unwrap_or_default() == 0
                && context.should_request_mdns().await?
            {
                req_mdn = true;
            }

            encryption_pubkeys = if !is_encrypted {
                None
            } else if should_encrypt_symmetrically(&msg, &chat) {
                Some(Vec::new())
            } else {
                if keys.is_empty() && !recipients.is_empty() {
                    bail!("No recipient keys are available, cannot encrypt to {recipients:?}.");
                }

                // Remove recipients for which the key is missing.
                if !missing_key_addresses.is_empty() {
                    recipients.retain(|addr| !missing_key_addresses.contains(addr));
                }

                Some(keys)
            };
        }

        let (in_reply_to, references) = context
            .sql
            .query_row(
                "SELECT mime_in_reply_to, IFNULL(mime_references, '')
                 FROM msgs WHERE id=?",
                (msg.id,),
                |row| {
                    let in_reply_to: String = row.get(0)?;
                    let references: String = row.get(1)?;

                    Ok((in_reply_to, references))
                },
            )
            .await?;
        let references: Vec<String> = references
            .trim()
            .split_ascii_whitespace()
            .map(|s| s.trim_start_matches('<').trim_end_matches('>').to_string())
            .collect();
        let selfstatus = match attach_profile_data {
            true => context
                .get_config(Config::Selfstatus)
                .await?
                .unwrap_or_default(),
            false => "".to_string(),
        };
        // We don't display avatars for address-contacts, so sending avatars w/o encryption is not
        // useful and causes e.g. Outlook to reject a message with a big header, see
        // https://support.delta.chat/t/invalid-mime-content-single-text-value-size-32822-exceeded-allowed-maximum-32768-for-the-chat-user-avatar-header/4067.
        let attach_selfavatar =
            Self::should_attach_selfavatar(context, &msg).await && encryption_pubkeys.is_some();

        ensure_and_debug_assert!(
            member_timestamps.is_empty()
                || to.len() + past_members.len() == member_timestamps.len(),
            "to.len() ({}) + past_members.len() ({}) != member_timestamps.len() ({})",
            to.len(),
            past_members.len(),
            member_timestamps.len(),
        );
        let webxdc_topic = get_iroh_topic_for_msg(context, msg.id).await?;
        let factory = MimeFactory {
            from_addr,
            from_displayname,
            sender_displayname,
            selfstatus,
            recipients,
            encryption_pubkeys,
            to,
            past_members,
            member_fingerprints,
            member_timestamps,
            timestamp: msg.timestamp_sort,
            loaded: Loaded::Message { msg, chat },
            in_reply_to,
            references,
            req_mdn,
            last_added_location_id: None,
            sync_ids_to_delete: None,
            attach_selfavatar,
            webxdc_topic,
            pre_message_mode: PreMessageMode::None,
        };
        Ok(factory)
    }

    pub async fn from_mdn(
        context: &Context,
        from_id: ContactId,
        rfc724_mid: String,
        additional_msg_ids: Vec<String>,
    ) -> Result<MimeFactory> {
        let contact = Contact::get_by_id(context, from_id).await?;
        let from_addr = context.get_primary_self_addr().await?;
        let timestamp = create_smeared_timestamp(context);

        let addr = contact.get_addr().to_string();
        let encryption_pubkeys = if from_id == ContactId::SELF {
            Some(Vec::new())
        } else if contact.is_key_contact() {
            if let Some(key) = contact.public_key(context).await? {
                Some(vec![(addr.clone(), key)])
            } else {
                Some(Vec::new())
            }
        } else {
            None
        };

        let res = MimeFactory {
            from_addr,
            from_displayname: "".to_string(),
            sender_displayname: None,
            selfstatus: "".to_string(),
            recipients: vec![addr],
            encryption_pubkeys,
            to: vec![("".to_string(), contact.get_addr().to_string())],
            past_members: vec![],
            member_fingerprints: vec![],
            member_timestamps: vec![],
            timestamp,
            loaded: Loaded::Mdn {
                rfc724_mid,
                additional_msg_ids,
            },
            in_reply_to: String::default(),
            references: Vec::new(),
            req_mdn: false,
            last_added_location_id: None,
            sync_ids_to_delete: None,
            attach_selfavatar: false,
            webxdc_topic: None,
            pre_message_mode: PreMessageMode::None,
        };

        Ok(res)
    }

    fn should_skip_autocrypt(&self) -> bool {
        match &self.loaded {
            Loaded::Message { msg, .. } => {
                msg.param.get_bool(Param::SkipAutocrypt).unwrap_or_default()
            }
            Loaded::Mdn { .. } => true,
        }
    }

    fn should_attach_profile_data(msg: &Message) -> bool {
        msg.param.get_cmd() != SystemMessage::SecurejoinMessage || {
            let step = msg.param.get(Param::Arg).unwrap_or_default();
            // Don't attach profile data at the earlier SecureJoin steps:
            // - The corresponding messages, i.e. "v{c,g}-request" and "v{c,g}-auth-required" are
            //   deleted right after processing, so other devices won't see the avatar etc.
            // - It's also good for privacy because the contact isn't yet verified and these
            //   messages are auto-sent unlike usual unencrypted messages.
            step == "vg-request-with-auth"
                || step == "vc-request-with-auth"
                // Note that for "vg-member-added"
                // get_cmd() returns `MemberAddedToGroup` rather than `SecurejoinMessage`,
                // so, it wouldn't actually be necessary to have them in the list here.
                // Still, they are here for completeness.
                || step == "vg-member-added"
                || step == "vc-contact-confirm"
        }
    }

    async fn should_attach_selfavatar(context: &Context, msg: &Message) -> bool {
        Self::should_attach_profile_data(msg)
            && match chat::shall_attach_selfavatar(context, msg.chat_id).await {
                Ok(should) => should,
                Err(err) => {
                    warn!(
                        context,
                        "should_attach_selfavatar: cannot get selfavatar state: {err:#}."
                    );
                    false
                }
            }
    }

    fn grpimage(&self) -> Option<String> {
        match &self.loaded {
            Loaded::Message { chat, msg } => {
                let cmd = msg.param.get_cmd();

                match cmd {
                    SystemMessage::MemberAddedToGroup => {
                        return chat.param.get(Param::ProfileImage).map(Into::into);
                    }
                    SystemMessage::GroupImageChanged => {
                        return msg.param.get(Param::Arg).map(Into::into);
                    }
                    _ => {}
                }

                if msg
                    .param
                    .get_bool(Param::AttachChatAvatarAndDescription)
                    .unwrap_or_default()
                {
                    return chat.param.get(Param::ProfileImage).map(Into::into);
                }

                None
            }
            Loaded::Mdn { .. } => None,
        }
    }

    async fn subject_str(&self, context: &Context) -> Result<String> {
        let subject = match &self.loaded {
            Loaded::Message { chat, msg } => {
                let quoted_msg_subject = msg.quoted_message(context).await?.map(|m| m.subject);

                if !msg.subject.is_empty() {
                    return Ok(msg.subject.clone());
                }

                if (chat.typ == Chattype::Group || chat.typ == Chattype::OutBroadcast)
                    && quoted_msg_subject.is_none_or_empty()
                {
                    let re = if self.in_reply_to.is_empty() {
                        ""
                    } else {
                        "Re: "
                    };
                    return Ok(format!("{}{}", re, chat.name));
                }

                let parent_subject = if quoted_msg_subject.is_none_or_empty() {
                    chat.param.get(Param::LastSubject)
                } else {
                    quoted_msg_subject.as_deref()
                };
                if let Some(last_subject) = parent_subject {
                    return Ok(format!("Re: {}", remove_subject_prefix(last_subject)));
                }

                let self_name = match Self::should_attach_profile_data(msg) {
                    true => context.get_config(Config::Displayname).await?,
                    false => None,
                };
                let self_name = &match self_name {
                    Some(name) => name,
                    None => context.get_config(Config::Addr).await?.unwrap_or_default(),
                };
                stock_str::subject_for_new_contact(context, self_name).await
            }
            Loaded::Mdn { .. } => "Receipt Notification".to_string(), // untranslated to no reveal sender's language
        };

        Ok(subject)
    }

    pub fn recipients(&self) -> Vec<String> {
        self.recipients.clone()
    }

    /// Consumes a `MimeFactory` and renders it into a message which is then stored in
    /// `smtp`-table to be used by the SMTP loop
    #[expect(clippy::arithmetic_side_effects)]
    pub async fn render(mut self, context: &Context) -> Result<RenderedEmail> {
        let mut headers = Vec::<(&'static str, HeaderType<'static>)>::new();

        let from = new_address_with_name(&self.from_displayname, self.from_addr.clone());

        let mut to: Vec<Address<'static>> = Vec::new();
        for (name, addr) in &self.to {
            to.push(Address::new_address(
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                },
                addr.clone(),
            ));
        }

        let mut past_members: Vec<Address<'static>> = Vec::new(); // Contents of `Chat-Group-Past-Members` header.
        for (name, addr) in &self.past_members {
            past_members.push(Address::new_address(
                if name.is_empty() {
                    None
                } else {
                    Some(name.to_string())
                },
                addr.clone(),
            ));
        }

        ensure_and_debug_assert!(
            self.member_timestamps.is_empty()
                || to.len() + past_members.len() == self.member_timestamps.len(),
            "to.len() ({}) + past_members.len() ({}) != self.member_timestamps.len() ({})",
            to.len(),
            past_members.len(),
            self.member_timestamps.len(),
        );
        if to.is_empty() {
            to.push(hidden_recipients());
        }

        // Start with Internet Message Format headers in the order of the standard example
        // <https://datatracker.ietf.org/doc/html/rfc5322#appendix-A.1.1>.
        headers.push(("From", from.into()));

        if let Some(sender_displayname) = &self.sender_displayname {
            let sender = new_address_with_name(sender_displayname, self.from_addr.clone());
            headers.push(("Sender", sender.into()));
        }
        headers.push((
            "To",
            mail_builder::headers::address::Address::new_list(to.clone()).into(),
        ));
        if !past_members.is_empty() {
            headers.push((
                "Chat-Group-Past-Members",
                mail_builder::headers::address::Address::new_list(past_members.clone()).into(),
            ));
        }

        if let Loaded::Message { chat, .. } = &self.loaded
            && chat.typ == Chattype::Group
        {
            if !self.member_timestamps.is_empty() && !chat.member_list_is_stale(context).await? {
                headers.push((
                    "Chat-Group-Member-Timestamps",
                    mail_builder::headers::raw::Raw::new(
                        self.member_timestamps
                            .iter()
                            .map(|ts| ts.to_string())
                            .collect::<Vec<String>>()
                            .join(" "),
                    )
                    .into(),
                ));
            }

            if !self.member_fingerprints.is_empty() {
                headers.push((
                    "Chat-Group-Member-Fpr",
                    mail_builder::headers::raw::Raw::new(
                        self.member_fingerprints
                            .iter()
                            .map(|fp| fp.to_string())
                            .collect::<Vec<String>>()
                            .join(" "),
                    )
                    .into(),
                ));
            }
        }

        let subject_str = self.subject_str(context).await?;
        headers.push((
            "Subject",
            mail_builder::headers::text::Text::new(subject_str.to_string()).into(),
        ));

        let date = chrono::DateTime::<chrono::Utc>::from_timestamp(self.timestamp, 0)
            .unwrap()
            .to_rfc2822();
        headers.push(("Date", mail_builder::headers::raw::Raw::new(date).into()));

        let rfc724_mid = match &self.loaded {
            Loaded::Message { msg, .. } => match &self.pre_message_mode {
                PreMessageMode::Pre { .. } => create_outgoing_rfc724_mid(),
                _ => msg.rfc724_mid.clone(),
            },
            Loaded::Mdn { .. } => create_outgoing_rfc724_mid(),
        };
        headers.push((
            "Message-ID",
            mail_builder::headers::message_id::MessageId::new(rfc724_mid.clone()).into(),
        ));

        // Reply headers as in <https://datatracker.ietf.org/doc/html/rfc5322#appendix-A.2>.
        if !self.in_reply_to.is_empty() {
            headers.push((
                "In-Reply-To",
                mail_builder::headers::message_id::MessageId::new(self.in_reply_to.clone()).into(),
            ));
        }
        if !self.references.is_empty() {
            headers.push((
                "References",
                mail_builder::headers::message_id::MessageId::<'static>::new_list(
                    self.references.iter().map(|s| s.to_string()),
                )
                .into(),
            ));
        }

        // Automatic Response headers <https://www.rfc-editor.org/rfc/rfc3834>
        if let Loaded::Mdn { .. } = self.loaded {
            headers.push((
                "Auto-Submitted",
                mail_builder::headers::raw::Raw::new("auto-replied".to_string()).into(),
            ));
        } else if context.get_config_bool(Config::Bot).await? {
            headers.push((
                "Auto-Submitted",
                mail_builder::headers::raw::Raw::new("auto-generated".to_string()).into(),
            ));
        } else if let Loaded::Message { msg, .. } = &self.loaded
            && msg.param.get_cmd() == SystemMessage::SecurejoinMessage
        {
            let step = msg.param.get(Param::Arg).unwrap_or_default();
            if step != "vg-request" && step != "vc-request" {
                headers.push((
                    "Auto-Submitted",
                    mail_builder::headers::raw::Raw::new("auto-replied".to_string()).into(),
                ));
            }
        }

        if let Loaded::Message { msg, chat } = &self.loaded
            && (chat.typ == Chattype::OutBroadcast || chat.typ == Chattype::InBroadcast)
        {
            headers.push((
                "Chat-List-ID",
                mail_builder::headers::text::Text::new(format!("{} <{}>", chat.name, chat.grpid))
                    .into(),
            ));

            if msg.param.get_cmd() == SystemMessage::MemberAddedToGroup
                && let Some(secret) = msg.param.get(PARAM_BROADCAST_SECRET)
            {
                headers.push((
                    "Chat-Broadcast-Secret",
                    mail_builder::headers::text::Text::new(secret.to_string()).into(),
                ));
            }
        }

        if let Loaded::Message { msg, .. } = &self.loaded {
            if let Some(original_rfc724_mid) = msg.param.get(Param::TextEditFor) {
                headers.push((
                    "Chat-Edit",
                    mail_builder::headers::message_id::MessageId::new(
                        original_rfc724_mid.to_string(),
                    )
                    .into(),
                ));
            } else if let Some(rfc724_mid_list) = msg.param.get(Param::DeleteRequestFor) {
                headers.push((
                    "Chat-Delete",
                    mail_builder::headers::message_id::MessageId::new(rfc724_mid_list.to_string())
                        .into(),
                ));
            }
        }

        // Non-standard headers.
        headers.push((
            "Chat-Version",
            mail_builder::headers::raw::Raw::new("1.0").into(),
        ));

        if self.req_mdn {
            // we use "Chat-Disposition-Notification-To"
            // because replies to "Disposition-Notification-To" are weird in many cases
            // eg. are just freetext and/or do not follow any standard.
            headers.push((
                "Chat-Disposition-Notification-To",
                mail_builder::headers::raw::Raw::new(self.from_addr.clone()).into(),
            ));
        }

        let grpimage = self.grpimage();
        let skip_autocrypt = self.should_skip_autocrypt();
        let encrypt_helper = EncryptHelper::new(context).await?;

        if !skip_autocrypt {
            // unless determined otherwise we add the Autocrypt header
            let aheader = encrypt_helper.get_aheader().to_string();
            headers.push((
                "Autocrypt",
                mail_builder::headers::raw::Raw::new(aheader).into(),
            ));
        }

        let is_encrypted = self.will_be_encrypted();

        // Add ephemeral timer for non-MDN messages.
        // For MDNs it does not matter because they are not visible
        // and ignored by the receiver.
        if let Loaded::Message { msg, .. } = &self.loaded {
            let ephemeral_timer = msg.chat_id.get_ephemeral_timer(context).await?;
            if let EphemeralTimer::Enabled { duration } = ephemeral_timer {
                headers.push((
                    "Ephemeral-Timer",
                    mail_builder::headers::raw::Raw::new(duration.to_string()).into(),
                ));
            }
        }

        let is_securejoin_message = if let Loaded::Message { msg, .. } = &self.loaded {
            msg.param.get_cmd() == SystemMessage::SecurejoinMessage
        } else {
            false
        };

        let message: MimePart<'static> = match &self.loaded {
            Loaded::Message { msg, .. } => {
                let msg = msg.clone();
                let (main_part, mut parts) = self
                    .render_message(context, &mut headers, &grpimage, is_encrypted)
                    .await?;
                if parts.is_empty() {
                    // Single part, render as regular message.
                    main_part
                } else {
                    parts.insert(0, main_part);

                    // Multiple parts, render as multipart.
                    if msg.param.get_cmd() == SystemMessage::MultiDeviceSync {
                        MimePart::new("multipart/report; report-type=multi-device-sync", parts)
                    } else if msg.param.get_cmd() == SystemMessage::WebxdcStatusUpdate {
                        MimePart::new("multipart/report; report-type=status-update", parts)
                    } else {
                        MimePart::new("multipart/mixed", parts)
                    }
                }
            }
            Loaded::Mdn { .. } => self.render_mdn()?,
        };

        // Split headers based on header confidentiality policy.

        // Headers that must go into IMF header section.
        //
        // These are standard headers such as Date, In-Reply-To, References, which cannot be placed
        // anywhere else according to the standard. Placing headers here also allows them to be fetched
        // individually over IMAP without downloading the message body. This is why Chat-Version is
        // placed here.
        let mut unprotected_headers: Vec<(&'static str, HeaderType<'static>)> = Vec::new();

        // Headers that MUST NOT (only) go into IMF header section:
        // - Large headers which may hit the header section size limit on the server, such as
        //   Chat-User-Avatar with a base64-encoded image inside.
        // - Headers duplicated here that servers mess up with in the IMF header section, like
        //   Message-ID.
        // - Nonstandard headers that should be DKIM-protected because e.g. OpenDKIM only signs
        //   known headers.
        //
        // The header should be hidden from MTA
        // by moving it either into protected part
        // in case of encrypted mails
        // or unprotected MIME preamble in case of unencrypted mails.
        let mut hidden_headers: Vec<(&'static str, HeaderType<'static>)> = Vec::new();

        // Opportunistically protected headers.
        //
        // These headers are placed into encrypted part *if* the message is encrypted. Place headers
        // which are not needed before decryption (e.g. Chat-Group-Name) or are not interesting if the
        // message cannot be decrypted (e.g. Chat-Disposition-Notification-To) here.
        //
        // If the message is not encrypted, these headers are placed into IMF header section, so make
        // sure that the message will be encrypted if you place any sensitive information here.
        let mut protected_headers: Vec<(&'static str, HeaderType<'static>)> = Vec::new();

        // MIME header <https://datatracker.ietf.org/doc/html/rfc2045>.
        unprotected_headers.push((
            "MIME-Version",
            mail_builder::headers::raw::Raw::new("1.0").into(),
        ));

        if self.pre_message_mode == PreMessageMode::Post {
            unprotected_headers.push((
                "Chat-Is-Post-Message",
                mail_builder::headers::raw::Raw::new("1").into(),
            ));
        } else if let PreMessageMode::Pre {
            post_msg_rfc724_mid,
        } = &self.pre_message_mode
        {
            protected_headers.push((
                "Chat-Post-Message-ID",
                mail_builder::headers::message_id::MessageId::new(post_msg_rfc724_mid.clone())
                    .into(),
            ));
        }

        for header @ (original_header_name, _header_value) in &headers {
            let header_name = original_header_name.to_lowercase();
            if header_name == "message-id" {
                unprotected_headers.push(header.clone());
                hidden_headers.push(header.clone());
            } else if is_hidden(&header_name) {
                hidden_headers.push(header.clone());
            } else if header_name == "from" {
                // Unencrypted securejoin messages should _not_ include the display name:
                if is_encrypted || !is_securejoin_message {
                    protected_headers.push(header.clone());
                }

                unprotected_headers.push((
                    original_header_name,
                    Address::new_address(None::<&'static str>, self.from_addr.clone()).into(),
                ));
            } else if header_name == "to" {
                protected_headers.push(header.clone());
                if is_encrypted {
                    unprotected_headers.push(("To", hidden_recipients().into()));
                } else {
                    unprotected_headers.push(header.clone());
                }
            } else if header_name == "chat-broadcast-secret" {
                if is_encrypted {
                    protected_headers.push(header.clone());
                } else {
                    bail!("Message is unecrypted, cannot include broadcast secret");
                }
            } else if is_encrypted && header_name == "date" {
                protected_headers.push(header.clone());

                // Randomized date goes to unprotected header.
                //
                // We cannot just send "Thu, 01 Jan 1970 00:00:00 +0000"
                // or omit the header because GMX then fails with
                //
                // host mx00.emig.gmx.net[212.227.15.9] said:
                // 554-Transaction failed
                // 554-Reject due to policy restrictions.
                // 554 For explanation visit https://postmaster.gmx.net/en/case?...
                // (in reply to end of DATA command)
                //
                // and the explanation page says
                // "The time information deviates too much from the actual time".
                //
                // We also limit the range to 6 days (518400 seconds)
                // because with a larger range we got
                // error "500 Date header far in the past/future"
                // which apparently originates from Symantec Messaging Gateway
                // and means the message has a Date that is more
                // than 7 days in the past:
                // <https://github.com/chatmail/core/issues/7466>
                let timestamp_offset = rand::random_range(0..518400);
                let protected_timestamp = self.timestamp.saturating_sub(timestamp_offset);
                let unprotected_date =
                    chrono::DateTime::<chrono::Utc>::from_timestamp(protected_timestamp, 0)
                        .unwrap()
                        .to_rfc2822();
                unprotected_headers.push((
                    "Date",
                    mail_builder::headers::raw::Raw::new(unprotected_date).into(),
                ));
            } else if is_encrypted {
                protected_headers.push(header.clone());

                match header_name.as_str() {
                    "subject" => {
                        unprotected_headers.push((
                            "Subject",
                            mail_builder::headers::raw::Raw::new("[...]").into(),
                        ));
                    }
                    "in-reply-to"
                    | "references"
                    | "auto-submitted"
                    | "chat-version"
                    | "autocrypt-setup-message" => {
                        unprotected_headers.push(header.clone());
                    }
                    _ => {
                        // Other headers are removed from unprotected part.
                    }
                }
            } else {
                // Copy the header to the protected headers
                // in case of signed-only message.
                // If the message is not signed, this value will not be used.
                protected_headers.push(header.clone());
                unprotected_headers.push(header.clone())
            }
        }

        let use_std_header_protection = context
            .get_config_bool(Config::StdHeaderProtectionComposing)
            .await?;
        let outer_message = if let Some(encryption_pubkeys) = self.encryption_pubkeys {
            // Store protected headers in the inner message.
            let message = protected_headers
                .into_iter()
                .fold(message, |message, (header, value)| {
                    message.header(header, value)
                });

            // Add hidden headers to encrypted payload.
            let mut message: MimePart<'static> = hidden_headers
                .into_iter()
                .fold(message, |message, (header, value)| {
                    message.header(header, value)
                });

            if use_std_header_protection {
                message = unprotected_headers
                    .iter()
                    // Structural headers shouldn't be added as "HP-Outer". They are defined in
                    // <https://www.rfc-editor.org/rfc/rfc9787.html#structural-header-fields>.
                    .filter(|(name, _)| {
                        !(name.eq_ignore_ascii_case("mime-version")
                            || name.eq_ignore_ascii_case("content-type")
                            || name.eq_ignore_ascii_case("content-transfer-encoding")
                            || name.eq_ignore_ascii_case("content-disposition"))
                    })
                    .fold(message, |message, (name, value)| {
                        message.header(format!("HP-Outer: {name}"), value.clone())
                    });
            }

            // Add gossip headers in chats with multiple recipients
            let multiple_recipients =
                encryption_pubkeys.len() > 1 || context.get_config_bool(Config::BccSelf).await?;

            let gossip_period = context.get_config_i64(Config::GossipPeriod).await?;
            let now = time();

            match &self.loaded {
                Loaded::Message { chat, msg } => {
                    if !should_hide_recipients(msg, chat) {
                        for (addr, key) in &encryption_pubkeys {
                            let fingerprint = key.dc_fingerprint().hex();
                            let cmd = msg.param.get_cmd();
                            if self.pre_message_mode == PreMessageMode::Post {
                                continue;
                            }

                            let should_do_gossip = cmd == SystemMessage::MemberAddedToGroup
                                || cmd == SystemMessage::SecurejoinMessage
                                || multiple_recipients && {
                                    let gossiped_timestamp: Option<i64> = context
                                        .sql
                                        .query_get_value(
                                            "SELECT timestamp
                                         FROM gossip_timestamp
                                         WHERE chat_id=? AND fingerprint=?",
                                            (chat.id, &fingerprint),
                                        )
                                        .await?;

                                    // `gossip_period == 0` is a special case for testing,
                                    // enabling gossip in every message.
                                    //
                                    // If current time is in the past compared to
                                    // `gossiped_timestamp`, we also gossip because
                                    // either the `gossiped_timestamp` or clock is wrong.
                                    gossip_period == 0
                                        || gossiped_timestamp
                                            .is_none_or(|ts| now >= ts + gossip_period || now < ts)
                                };

                            let verifier_id: Option<u32> = context
                                .sql
                                .query_get_value(
                                    "SELECT verifier FROM contacts WHERE fingerprint=?",
                                    (&fingerprint,),
                                )
                                .await?;

                            let is_verified =
                                verifier_id.is_some_and(|verifier_id| verifier_id != 0);

                            if !should_do_gossip {
                                continue;
                            }

                            let header = Aheader {
                                addr: addr.clone(),
                                public_key: key.clone(),
                                // Autocrypt 1.1.0 specification says that
                                // `prefer-encrypt` attribute SHOULD NOT be included.
                                prefer_encrypt: EncryptPreference::NoPreference,
                                verified: is_verified,
                            }
                            .to_string();

                            message = message.header(
                                "Autocrypt-Gossip",
                                mail_builder::headers::raw::Raw::new(header),
                            );

                            context
                                .sql
                                .execute(
                                    "INSERT INTO gossip_timestamp (chat_id, fingerprint, timestamp)
                                     VALUES                       (?, ?, ?)
                                     ON CONFLICT                  (chat_id, fingerprint)
                                     DO UPDATE SET timestamp=excluded.timestamp",
                                    (chat.id, &fingerprint, now),
                                )
                                .await?;
                        }
                    }
                }
                Loaded::Mdn { .. } => {
                    // Never gossip in MDNs.
                }
            }

            // Set the appropriate Content-Type for the inner message.
            for (h, v) in &mut message.headers {
                if h == "Content-Type"
                    && let mail_builder::headers::HeaderType::ContentType(ct) = v
                {
                    let mut ct_new = ct.clone();
                    ct_new = ct_new.attribute("protected-headers", "v1");
                    if use_std_header_protection {
                        ct_new = ct_new.attribute("hp", "cipher");
                    }
                    *ct = ct_new;
                    break;
                }
            }

            // Disable compression for SecureJoin to ensure
            // there are no compression side channels
            // leaking information about the tokens.
            let compress = match &self.loaded {
                Loaded::Message { msg, .. } => {
                    msg.param.get_cmd() != SystemMessage::SecurejoinMessage
                }
                Loaded::Mdn { .. } => true,
            };

            let shared_secret: Option<String> = match &self.loaded {
                Loaded::Message { chat, msg }
                    if should_encrypt_with_broadcast_secret(msg, chat) =>
                {
                    let secret = load_broadcast_secret(context, chat.id).await?;
                    if secret.is_none() {
                        // If there is no shared secret yet
                        // because this is an old broadcast channel,
                        // created before we had symmetric encryption,
                        // we show an error message.
                        let text = BROADCAST_INCOMPATIBILITY_MSG;
                        chat::add_info_msg(context, chat.id, text).await?;
                        bail!(text);
                    }
                    secret
                }
                _ => None,
            };

            // Do not anonymize OpenPGP recipients.
            //
            // This is disabled to avoid interoperability problems
            // with old core versions <1.160.0 that do not support
            // receiving messages with wildcard Key IDs:
            // <https://github.com/chatmail/core/issues/7378>
            //
            // The option should be changed to true
            // once new core versions are sufficiently deployed.
            let anonymous_recipients = false;

            if context.get_config_bool(Config::TestHooks).await?
                && let Some(hook) = &*context.pre_encrypt_mime_hook.lock()
            {
                message = hook(context, message);
            }

            let encrypted = if let Some(shared_secret) = shared_secret {
                encrypt_helper
                    .encrypt_symmetrically(context, &shared_secret, message, compress)
                    .await?
            } else {
                // Asymmetric encryption

                let seipd_version = if encryption_pubkeys.is_empty() {
                    // If message is sent only to self,
                    // use v2 SEIPD.
                    SeipdVersion::V2
                } else {
                    // If message is sent to others,
                    // they may not support v2 SEIPD yet,
                    // so use v1 SEIPD.
                    SeipdVersion::V1
                };

                // Encrypt to self unconditionally,
                // even for a single-device setup.
                let mut encryption_keyring = vec![encrypt_helper.public_key.clone()];
                encryption_keyring
                    .extend(encryption_pubkeys.iter().map(|(_addr, key)| (*key).clone()));

                encrypt_helper
                    .encrypt(
                        context,
                        encryption_keyring,
                        message,
                        compress,
                        anonymous_recipients,
                        seipd_version,
                    )
                    .await?
            };

            // XXX: additional newline is needed
            // to pass filtermail at
            // <https://github.com/deltachat/chatmail/blob/4d915f9800435bf13057d41af8d708abd34dbfa8/chatmaild/src/chatmaild/filtermail.py#L84-L86>:
            let encrypted = encrypted + "\n";

            // Set the appropriate Content-Type for the outer message
            MimePart::new(
                "multipart/encrypted; protocol=\"application/pgp-encrypted\"",
                vec![
                    // Autocrypt part 1
                    MimePart::new("application/pgp-encrypted", "Version: 1\r\n").header(
                        "Content-Description",
                        mail_builder::headers::raw::Raw::new("PGP/MIME version identification"),
                    ),
                    // Autocrypt part 2
                    MimePart::new(
                        "application/octet-stream; name=\"encrypted.asc\"",
                        encrypted,
                    )
                    .header(
                        "Content-Description",
                        mail_builder::headers::raw::Raw::new("OpenPGP encrypted message"),
                    )
                    .header(
                        "Content-Disposition",
                        mail_builder::headers::raw::Raw::new("inline; filename=\"encrypted.asc\";"),
                    ),
                ],
            )
        } else if matches!(self.loaded, Loaded::Mdn { .. }) {
            // Never add outer multipart/mixed wrapper to MDN
            // as multipart/report Content-Type is used to recognize MDNs
            // by Delta Chat receiver and Chatmail servers
            // allowing them to be unencrypted and not contain Autocrypt header
            // without resetting Autocrypt encryption or triggering Chatmail filter
            // that normally only allows encrypted mails.

            // Hidden headers are dropped.
            message
        } else {
            let message = hidden_headers
                .into_iter()
                .fold(message, |message, (header, value)| {
                    message.header(header, value)
                });
            let message = MimePart::new("multipart/mixed", vec![message]);
            let mut message = protected_headers
                .iter()
                .fold(message, |message, (header, value)| {
                    message.header(*header, value.clone())
                });

            if skip_autocrypt || !context.get_config_bool(Config::SignUnencrypted).await? {
                // Deduplicate unprotected headers that also are in the protected headers:
                let protected: HashSet<&str> =
                    HashSet::from_iter(protected_headers.iter().map(|(header, _value)| *header));
                unprotected_headers.retain(|(header, _value)| !protected.contains(header));

                message
            } else {
                for (h, v) in &mut message.headers {
                    if h == "Content-Type"
                        && let mail_builder::headers::HeaderType::ContentType(ct) = v
                    {
                        let mut ct_new = ct.clone();
                        ct_new = ct_new.attribute("protected-headers", "v1");
                        if use_std_header_protection {
                            ct_new = ct_new.attribute("hp", "clear");
                        }
                        *ct = ct_new;
                        break;
                    }
                }

                let signature = encrypt_helper.sign(context, &message).await?;
                MimePart::new(
                    "multipart/signed; protocol=\"application/pgp-signature\"; protected",
                    vec![
                        message,
                        MimePart::new(
                            "application/pgp-signature; name=\"signature.asc\"",
                            signature,
                        )
                        .header(
                            "Content-Description",
                            mail_builder::headers::raw::Raw::<'static>::new(
                                "OpenPGP digital signature",
                            ),
                        )
                        .attachment("signature"),
                    ],
                )
            }
        };

        // Store the unprotected headers on the outer message.
        let outer_message = unprotected_headers
            .into_iter()
            .fold(outer_message, |message, (header, value)| {
                message.header(header, value)
            });

        let MimeFactory {
            last_added_location_id,
            ..
        } = self;

        let mut buffer = Vec::new();
        let cursor = Cursor::new(&mut buffer);
        outer_message.clone().write_part(cursor).ok();
        let message = String::from_utf8_lossy(&buffer).to_string();

        Ok(RenderedEmail {
            message,
            // envelope: Envelope::new,
            is_encrypted,
            last_added_location_id,
            sync_ids_to_delete: self.sync_ids_to_delete,
            rfc724_mid,
            subject: subject_str,
        })
    }

    /// Returns MIME part with a `message.kml` attachment.
    fn get_message_kml_part(&self) -> Option<MimePart<'static>> {
        let Loaded::Message { msg, .. } = &self.loaded else {
            return None;
        };

        let latitude = msg.param.get_float(Param::SetLatitude)?;
        let longitude = msg.param.get_float(Param::SetLongitude)?;

        let kml_file = location::get_message_kml(msg.timestamp_sort, latitude, longitude);
        let part = MimePart::new("application/vnd.google-earth.kml+xml", kml_file)
            .attachment("message.kml");
        Some(part)
    }

    /// Returns MIME part with a `location.kml` attachment.
    async fn get_location_kml_part(
        &mut self,
        context: &Context,
    ) -> Result<Option<MimePart<'static>>> {
        let Loaded::Message { msg, .. } = &self.loaded else {
            return Ok(None);
        };

        let Some((kml_content, last_added_location_id)) =
            location::get_kml(context, msg.chat_id).await?
        else {
            return Ok(None);
        };

        let part = MimePart::new("application/vnd.google-earth.kml+xml", kml_content)
            .attachment("location.kml");
        if !msg.param.exists(Param::SetLatitude) {
            // otherwise, the independent location is already filed
            self.last_added_location_id = Some(last_added_location_id);
        }
        Ok(Some(part))
    }

    async fn render_message(
        &mut self,
        context: &Context,
        headers: &mut Vec<(&'static str, HeaderType<'static>)>,
        grpimage: &Option<String>,
        is_encrypted: bool,
    ) -> Result<(MimePart<'static>, Vec<MimePart<'static>>)> {
        let Loaded::Message { chat, msg } = &self.loaded else {
            bail!("Attempt to render MDN as a message");
        };
        let chat = chat.clone();
        let msg = msg.clone();
        let command = msg.param.get_cmd();
        let mut placeholdertext = None;

        let send_verified_headers = match chat.typ {
            Chattype::Single => true,
            Chattype::Group => true,
            // Mailinglists and broadcast channels can actually never be verified:
            Chattype::Mailinglist => false,
            Chattype::OutBroadcast | Chattype::InBroadcast => false,
        };

        if send_verified_headers {
            let was_protected: bool = context
                .sql
                .query_get_value("SELECT protected FROM chats WHERE id=?", (chat.id,))
                .await?
                .unwrap_or_default();

            if was_protected {
                let unverified_member_exists = context
                    .sql
                    .exists(
                        "SELECT COUNT(*)
                        FROM contacts, chats_contacts
                        WHERE chats_contacts.contact_id=contacts.id AND chats_contacts.chat_id=?
                        AND contacts.id>9
                        AND contacts.verifier=0",
                        (chat.id,),
                    )
                    .await?;

                if !unverified_member_exists {
                    headers.push((
                        "Chat-Verified",
                        mail_builder::headers::raw::Raw::new("1").into(),
                    ));
                }
            }
        }

        if chat.typ == Chattype::Group {
            // Send group ID unless it is an ad hoc group that has no ID.
            if !chat.grpid.is_empty() {
                headers.push((
                    "Chat-Group-ID",
                    mail_builder::headers::raw::Raw::new(chat.grpid.clone()).into(),
                ));
            }
        }

        if chat.typ == Chattype::Group
            || chat.typ == Chattype::OutBroadcast
            || chat.typ == Chattype::InBroadcast
        {
            headers.push((
                "Chat-Group-Name",
                mail_builder::headers::text::Text::new(chat.name.to_string()).into(),
            ));
            if let Some(ts) = chat.param.get_i64(Param::GroupNameTimestamp) {
                headers.push((
                    "Chat-Group-Name-Timestamp",
                    mail_builder::headers::text::Text::new(ts.to_string()).into(),
                ));
            }

            match command {
                SystemMessage::MemberRemovedFromGroup => {
                    let email_to_remove = msg.param.get(Param::Arg).unwrap_or_default();
                    let fingerprint_to_remove = msg.param.get(Param::Arg4).unwrap_or_default();

                    if email_to_remove
                        == context
                            .get_config(Config::ConfiguredAddr)
                            .await?
                            .unwrap_or_default()
                    {
                        placeholdertext = Some("I left the group.".to_string());
                    } else {
                        placeholdertext = Some(format!("I removed member {email_to_remove}."));
                    };

                    if !email_to_remove.is_empty() {
                        headers.push((
                            "Chat-Group-Member-Removed",
                            mail_builder::headers::raw::Raw::new(email_to_remove.to_string())
                                .into(),
                        ));
                    }

                    if !fingerprint_to_remove.is_empty() {
                        headers.push((
                            "Chat-Group-Member-Removed-Fpr",
                            mail_builder::headers::raw::Raw::new(fingerprint_to_remove.to_string())
                                .into(),
                        ));
                    }
                }
                SystemMessage::MemberAddedToGroup => {
                    let email_to_add = msg.param.get(Param::Arg).unwrap_or_default();
                    let fingerprint_to_add = msg.param.get(Param::Arg4).unwrap_or_default();

                    placeholdertext = Some(format!("I added member {email_to_add}."));

                    if !email_to_add.is_empty() {
                        headers.push((
                            "Chat-Group-Member-Added",
                            mail_builder::headers::raw::Raw::new(email_to_add.to_string()).into(),
                        ));
                    }
                    if !fingerprint_to_add.is_empty() {
                        headers.push((
                            "Chat-Group-Member-Added-Fpr",
                            mail_builder::headers::raw::Raw::new(fingerprint_to_add.to_string())
                                .into(),
                        ));
                    }
                    if 0 != msg.param.get_int(Param::Arg2).unwrap_or_default() & DC_FROM_HANDSHAKE {
                        let step = "vg-member-added";
                        info!(context, "Sending secure-join message {:?}.", step);
                        headers.push((
                            "Secure-Join",
                            mail_builder::headers::raw::Raw::new(step.to_string()).into(),
                        ));
                    }
                }
                SystemMessage::GroupNameChanged => {
                    let old_name = msg.param.get(Param::Arg).unwrap_or_default().to_string();
                    headers.push((
                        "Chat-Group-Name-Changed",
                        mail_builder::headers::text::Text::new(old_name).into(),
                    ));
                }
                SystemMessage::GroupDescriptionChanged => {
                    headers.push((
                        "Chat-Group-Description-Changed",
                        mail_builder::headers::text::Text::new("").into(),
                    ));
                }
                SystemMessage::GroupImageChanged => {
                    headers.push((
                        "Chat-Content",
                        mail_builder::headers::text::Text::new("group-avatar-changed").into(),
                    ));
                    if grpimage.is_none() && is_encrypted {
                        headers.push((
                            "Chat-Group-Avatar",
                            mail_builder::headers::raw::Raw::new("0").into(),
                        ));
                    }
                }
                _ => {}
            }

            if command == SystemMessage::GroupDescriptionChanged
                || command == SystemMessage::MemberAddedToGroup
                || msg
                    .param
                    .get_bool(Param::AttachChatAvatarAndDescription)
                    .unwrap_or_default()
            {
                let description = chat::get_chat_description(context, chat.id).await?;
                headers.push((
                    "Chat-Group-Description",
                    mail_builder::headers::text::Text::new(description.clone()).into(),
                ));
                if let Some(ts) = chat.param.get_i64(Param::GroupDescriptionTimestamp) {
                    headers.push((
                        "Chat-Group-Description-Timestamp",
                        mail_builder::headers::text::Text::new(ts.to_string()).into(),
                    ));
                }
            }
        }

        match command {
            SystemMessage::LocationStreamingEnabled => {
                headers.push((
                    "Chat-Content",
                    mail_builder::headers::raw::Raw::new("location-streaming-enabled").into(),
                ));
            }
            SystemMessage::EphemeralTimerChanged => {
                headers.push((
                    "Chat-Content",
                    mail_builder::headers::raw::Raw::new("ephemeral-timer-changed").into(),
                ));
            }
            SystemMessage::LocationOnly
            | SystemMessage::MultiDeviceSync
            | SystemMessage::WebxdcStatusUpdate => {
                // This should prevent automatic replies,
                // such as non-delivery reports.
                //
                // See <https://tools.ietf.org/html/rfc3834>
                //
                // Adding this header without encryption leaks some
                // information about the message contents, but it can
                // already be easily guessed from message timing and size.
                headers.push((
                    "Auto-Submitted",
                    mail_builder::headers::raw::Raw::new("auto-generated").into(),
                ));
            }
            SystemMessage::AutocryptSetupMessage => {
                headers.push((
                    "Autocrypt-Setup-Message",
                    mail_builder::headers::raw::Raw::new("v1").into(),
                ));

                placeholdertext = Some(ASM_SUBJECT.to_string());
            }
            SystemMessage::SecurejoinMessage => {
                let step = msg.param.get(Param::Arg).unwrap_or_default();
                if !step.is_empty() {
                    info!(context, "Sending secure-join message {step:?}.");
                    headers.push((
                        "Secure-Join",
                        mail_builder::headers::raw::Raw::new(step.to_string()).into(),
                    ));

                    let param2 = msg.param.get(Param::Arg2).unwrap_or_default();
                    if !param2.is_empty() {
                        headers.push((
                            if step == "vg-request-with-auth" || step == "vc-request-with-auth" {
                                "Secure-Join-Auth"
                            } else {
                                "Secure-Join-Invitenumber"
                            },
                            mail_builder::headers::text::Text::new(param2.to_string()).into(),
                        ));
                    }

                    let fingerprint = msg.param.get(Param::Arg3).unwrap_or_default();
                    if !fingerprint.is_empty() {
                        headers.push((
                            "Secure-Join-Fingerprint",
                            mail_builder::headers::raw::Raw::new(fingerprint.to_string()).into(),
                        ));
                    }
                    if let Some(id) = msg.param.get(Param::Arg4) {
                        headers.push((
                            "Secure-Join-Group",
                            mail_builder::headers::raw::Raw::new(id.to_string()).into(),
                        ));
                    };
                }
            }
            SystemMessage::ChatProtectionEnabled => {
                headers.push((
                    "Chat-Content",
                    mail_builder::headers::raw::Raw::new("protection-enabled").into(),
                ));
            }
            SystemMessage::ChatProtectionDisabled => {
                headers.push((
                    "Chat-Content",
                    mail_builder::headers::raw::Raw::new("protection-disabled").into(),
                ));
            }
            SystemMessage::IrohNodeAddr => {
                let node_addr = context
                    .get_or_try_init_peer_channel()
                    .await?
                    .get_node_addr()
                    .await?;

                // We should not send `null` as relay URL
                // as this is the only way to reach the node.
                debug_assert!(node_addr.relay_url().is_some());
                headers.push((
                    HeaderDef::IrohNodeAddr.into(),
                    mail_builder::headers::text::Text::new(serde_json::to_string(&node_addr)?)
                        .into(),
                ));
            }
            SystemMessage::CallAccepted => {
                headers.push((
                    "Chat-Content",
                    mail_builder::headers::raw::Raw::new("call-accepted").into(),
                ));
            }
            SystemMessage::CallEnded => {
                headers.push((
                    "Chat-Content",
                    mail_builder::headers::raw::Raw::new("call-ended").into(),
                ));
            }
            _ => {}
        }

        if let Some(grpimage) = grpimage
            && is_encrypted
        {
            info!(context, "setting group image '{}'", grpimage);
            let avatar = build_avatar_file(context, grpimage)
                .await
                .context("Cannot attach group image")?;
            headers.push((
                "Chat-Group-Avatar",
                mail_builder::headers::raw::Raw::new(format!("base64:{avatar}")).into(),
            ));
        }

        if msg.viewtype == Viewtype::Sticker {
            headers.push((
                "Chat-Content",
                mail_builder::headers::raw::Raw::new("sticker").into(),
            ));
        } else if msg.viewtype == Viewtype::Call {
            headers.push((
                "Chat-Content",
                mail_builder::headers::raw::Raw::new("call").into(),
            ));
            placeholdertext = Some(
                "[This is a 'Call'. The sender uses an experiment not supported on your version yet]".to_string(),
            );
        }

        if let Some(offer) = msg.param.get(Param::WebrtcRoom) {
            headers.push((
                "Chat-Webrtc-Room",
                mail_builder::headers::raw::Raw::new(b_encode(offer)).into(),
            ));
        } else if let Some(answer) = msg.param.get(Param::WebrtcAccepted) {
            headers.push((
                "Chat-Webrtc-Accepted",
                mail_builder::headers::raw::Raw::new(b_encode(answer)).into(),
            ));
        }
        if let Some(has_video) = msg.param.get(Param::WebrtcHasVideoInitially) {
            headers.push((
                "Chat-Webrtc-Has-Video-Initially",
                mail_builder::headers::raw::Raw::new(b_encode(has_video)).into(),
            ))
        }

        if msg.viewtype == Viewtype::Voice
            || msg.viewtype == Viewtype::Audio
            || msg.viewtype == Viewtype::Video
        {
            if msg.viewtype == Viewtype::Voice {
                headers.push((
                    "Chat-Voice-Message",
                    mail_builder::headers::raw::Raw::new("1").into(),
                ));
            }
            let duration_ms = msg.param.get_int(Param::Duration).unwrap_or_default();
            if duration_ms > 0 {
                let dur = duration_ms.to_string();
                headers.push((
                    "Chat-Duration",
                    mail_builder::headers::raw::Raw::new(dur).into(),
                ));
            }
        }

        // add text part - we even add empty text and force a MIME-multipart-message as:
        // - some Apps have problems with Non-text in the main part (eg. "Mail" from stock Android)
        // - we can add "forward hints" this way
        // - it looks better

        let afwd_email = msg.param.exists(Param::Forwarded);
        let fwdhint = if afwd_email {
            Some(
                "---------- Forwarded message ----------\r\n\
                 From: Delta Chat\r\n\
                 \r\n"
                    .to_string(),
            )
        } else {
            None
        };

        let final_text = placeholdertext.as_deref().unwrap_or(&msg.text);

        let mut quoted_text = None;
        if let Some(msg_quoted_text) = msg.quoted_text() {
            let mut some_quoted_text = String::new();
            for quoted_line in msg_quoted_text.split('\n') {
                some_quoted_text += "> ";
                some_quoted_text += quoted_line;
                some_quoted_text += "\r\n";
            }
            some_quoted_text += "\r\n";
            quoted_text = Some(some_quoted_text)
        }

        if !is_encrypted && msg.param.get_bool(Param::ProtectQuote).unwrap_or_default() {
            // Message is not encrypted but quotes encrypted message.
            quoted_text = Some("> ...\r\n\r\n".to_string());
        }
        if quoted_text.is_none() && final_text.starts_with('>') {
            // Insert empty line to avoid receiver treating user-sent quote as topquote inserted by
            // Delta Chat.
            quoted_text = Some("\r\n".to_string());
        }

        let is_reaction = msg.param.get_int(Param::Reaction).unwrap_or_default() != 0;

        let footer = if is_reaction { "" } else { &self.selfstatus };

        let message_text = if self.pre_message_mode == PreMessageMode::Post {
            "".to_string()
        } else {
            format!(
                "{}{}{}{}{}{}",
                fwdhint.unwrap_or_default(),
                quoted_text.unwrap_or_default(),
                escape_message_footer_marks(final_text),
                if !final_text.is_empty() && !footer.is_empty() {
                    "\r\n\r\n"
                } else {
                    ""
                },
                if !footer.is_empty() { "-- \r\n" } else { "" },
                footer
            )
        };

        let mut main_part = MimePart::new("text/plain", message_text);
        if is_reaction {
            main_part = main_part.header(
                "Content-Disposition",
                mail_builder::headers::raw::Raw::new("reaction"),
            );
        }

        let mut parts = Vec::new();

        if msg.has_html() {
            let html = if let Some(html) = msg.param.get(Param::SendHtml) {
                Some(html.to_string())
            } else if let Some(orig_msg_id) = msg.param.get_int(Param::Forwarded)
                && orig_msg_id != 0
            {
                // Legacy forwarded messages may not have `Param::SendHtml` set. Let's hope the
                // original message exists.
                MsgId::new(orig_msg_id.try_into()?)
                    .get_html(context)
                    .await?
            } else {
                None
            };
            if let Some(html) = html {
                main_part = MimePart::new(
                    "multipart/alternative",
                    vec![main_part, MimePart::new("text/html", html)],
                )
            }
        }

        // add attachment part
        if msg.viewtype.has_file() {
            if let PreMessageMode::Pre { .. } = self.pre_message_mode {
                let Some(metadata) = PostMsgMetadata::from_msg(context, &msg).await? else {
                    bail!("Failed to generate metadata for pre-message")
                };

                headers.push((
                    HeaderDef::ChatPostMessageMetadata.into(),
                    mail_builder::headers::raw::Raw::new(metadata.to_header_value()?).into(),
                ));
            } else {
                let file_part = build_body_file(context, &msg).await?;
                parts.push(file_part);
            }
        }

        if let Some(msg_kml_part) = self.get_message_kml_part() {
            parts.push(msg_kml_part);
        }

        if location::is_sending_locations_to_chat(context, Some(msg.chat_id)).await?
            && let Some(part) = self.get_location_kml_part(context).await?
        {
            parts.push(part);
        }

        // we do not piggyback sync-files to other self-sent-messages
        // to not risk files becoming too larger and being skipped by download-on-demand.
        if command == SystemMessage::MultiDeviceSync {
            let json = msg.param.get(Param::Arg).unwrap_or_default();
            let ids = msg.param.get(Param::Arg2).unwrap_or_default();
            parts.push(context.build_sync_part(json.to_string()));
            self.sync_ids_to_delete = Some(ids.to_string());
        } else if command == SystemMessage::WebxdcStatusUpdate {
            let json = msg.param.get(Param::Arg).unwrap_or_default();
            parts.push(context.build_status_update_part(json));
        } else if msg.viewtype == Viewtype::Webxdc {
            let topic = self
                .webxdc_topic
                .map(|top| BASE32_NOPAD.encode(top.as_bytes()).to_ascii_lowercase())
                .unwrap_or(create_iroh_header(context, msg.id).await?);
            headers.push((
                HeaderDef::IrohGossipTopic.get_headername(),
                mail_builder::headers::raw::Raw::new(topic).into(),
            ));
            if let (Some(json), _) = context
                .render_webxdc_status_update_object(
                    msg.id,
                    StatusUpdateSerial::MIN,
                    StatusUpdateSerial::MAX,
                    None,
                )
                .await?
            {
                parts.push(context.build_status_update_part(&json));
            }
        }

        self.attach_selfavatar =
            self.attach_selfavatar && self.pre_message_mode != PreMessageMode::Post;
        if self.attach_selfavatar {
            match context.get_config(Config::Selfavatar).await? {
                Some(path) => match build_avatar_file(context, &path).await {
                    Ok(avatar) => headers.push((
                        "Chat-User-Avatar",
                        mail_builder::headers::raw::Raw::new(format!("base64:{avatar}")).into(),
                    )),
                    Err(err) => warn!(context, "mimefactory: cannot attach selfavatar: {}", err),
                },
                None => headers.push((
                    "Chat-User-Avatar",
                    mail_builder::headers::raw::Raw::new("0").into(),
                )),
            }
        }

        Ok((main_part, parts))
    }

    /// Render an MDN
    #[expect(clippy::arithmetic_side_effects)]
    fn render_mdn(&mut self) -> Result<MimePart<'static>> {
        // RFC 6522, this also requires the `report-type` parameter which is equal
        // to the MIME subtype of the second body part of the multipart/report
        let Loaded::Mdn {
            rfc724_mid,
            additional_msg_ids,
        } = &self.loaded
        else {
            bail!("Attempt to render a message as MDN");
        };

        // first body part: always human-readable, always REQUIRED by RFC 6522.
        // untranslated to no reveal sender's language.
        // moreover, translations in unknown languages are confusing, and clients may not display them at all
        let text_part = MimePart::new("text/plain", "This is a receipt notification.");

        let mut message = MimePart::new(
            "multipart/report; report-type=disposition-notification",
            vec![text_part],
        );

        // second body part: machine-readable, always REQUIRED by RFC 6522
        let message_text2 = format!(
            "Original-Recipient: rfc822;{}\r\n\
             Final-Recipient: rfc822;{}\r\n\
             Original-Message-ID: <{}>\r\n\
             Disposition: manual-action/MDN-sent-automatically; displayed\r\n",
            self.from_addr, self.from_addr, rfc724_mid
        );

        let extension_fields = if additional_msg_ids.is_empty() {
            "".to_string()
        } else {
            "Additional-Message-IDs: ".to_string()
                + &additional_msg_ids
                    .iter()
                    .map(|mid| render_rfc724_mid(mid))
                    .collect::<Vec<String>>()
                    .join(" ")
                + "\r\n"
        };

        message.add_part(MimePart::new(
            "message/disposition-notification",
            message_text2 + &extension_fields,
        ));

        Ok(message)
    }

    pub fn will_be_encrypted(&self) -> bool {
        self.encryption_pubkeys.is_some()
    }

    pub fn set_as_post_message(&mut self) {
        self.pre_message_mode = PreMessageMode::Post;
    }

    pub fn set_as_pre_message_for(&mut self, post_message: &RenderedEmail) {
        self.pre_message_mode = PreMessageMode::Pre {
            post_msg_rfc724_mid: post_message.rfc724_mid.clone(),
        };
    }
}

fn hidden_recipients() -> Address<'static> {
    Address::new_group(Some("hidden-recipients".to_string()), Vec::new())
}

fn should_encrypt_with_broadcast_secret(msg: &Message, chat: &Chat) -> bool {
    chat.typ == Chattype::OutBroadcast && must_have_only_one_recipient(msg, chat).is_none()
}

fn should_hide_recipients(msg: &Message, chat: &Chat) -> bool {
    should_encrypt_with_broadcast_secret(msg, chat)
}

fn should_encrypt_symmetrically(msg: &Message, chat: &Chat) -> bool {
    should_encrypt_with_broadcast_secret(msg, chat)
}

/// Some messages sent into outgoing broadcast channels (member-added/member-removed)
/// should only go to a single recipient,
/// rather than all recipients.
/// This function returns the fingerprint of the recipient the message should be sent to.
fn must_have_only_one_recipient<'a>(msg: &'a Message, chat: &Chat) -> Option<Result<&'a str>> {
    if chat.typ == Chattype::OutBroadcast
        && matches!(
            msg.param.get_cmd(),
            SystemMessage::MemberRemovedFromGroup | SystemMessage::MemberAddedToGroup
        )
    {
        let Some(fp) = msg.param.get(Param::Arg4) else {
            return Some(Err(format_err!("Missing removed/added member")));
        };
        return Some(Ok(fp));
    }
    None
}

async fn build_body_file(context: &Context, msg: &Message) -> Result<MimePart<'static>> {
    let file_name = msg.get_filename().context("msg has no file")?;
    let blob = msg
        .param
        .get_file_blob(context)?
        .context("msg has no file")?;
    let mimetype = msg
        .param
        .get(Param::MimeType)
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = fs::read(blob.to_abs_path()).await?;

    // create mime part, for Content-Disposition, see RFC 2183.
    // `Content-Disposition: attachment` seems not to make a difference to `Content-Disposition: inline`
    // at least on tested Thunderbird and Gma'l in 2017.
    // But I've heard about problems with inline and outl'k, so we just use the attachment-type until we
    // run into other problems ...
    let mail = MimePart::new(mimetype, body).attachment(sanitize_bidi_characters(&file_name));

    Ok(mail)
}

async fn build_avatar_file(context: &Context, path: &str) -> Result<String> {
    let blob = match path.starts_with("$BLOBDIR/") {
        true => BlobObject::from_name(context, path)?,
        false => BlobObject::from_path(context, path.as_ref())?,
    };
    let body = fs::read(blob.to_abs_path()).await?;
    let encoded_body = base64::engine::general_purpose::STANDARD
        .encode(&body)
        .chars()
        .enumerate()
        .fold(String::new(), |mut res, (i, c)| {
            if i % 78 == 77 {
                res.push(' ')
            }
            res.push(c);
            res
        });
    Ok(encoded_body)
}

fn recipients_contain_addr(recipients: &[(String, String)], addr: &str) -> bool {
    let addr_lc = addr.to_lowercase();
    recipients
        .iter()
        .any(|(_, cur)| cur.to_lowercase() == addr_lc)
}

fn render_rfc724_mid(rfc724_mid: &str) -> String {
    let rfc724_mid = rfc724_mid.trim().to_string();

    if rfc724_mid.chars().next().unwrap_or_default() == '<' {
        rfc724_mid
    } else {
        format!("<{rfc724_mid}>")
    }
}

/// Encodes UTF-8 string as a single B-encoded-word.
///
/// We manually encode some headers because as of
/// version 0.4.4 mail-builder crate does not encode
/// newlines correctly if they appear in a text header.
fn b_encode(value: &str) -> String {
    format!(
        "=?utf-8?B?{}?=",
        base64::engine::general_purpose::STANDARD.encode(value)
    )
}

#[cfg(test)]
mod mimefactory_tests;
