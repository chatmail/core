//! # MIME message parsing module.

use std::cmp::min;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::str;
use std::str::FromStr;

use anyhow::{Context as _, Result, bail};
use deltachat_contact_tools::{addr_cmp, addr_normalize, sanitize_bidi_characters};
use deltachat_derive::{FromSql, ToSql};
use format_flowed::unformat_flowed;
use mailparse::{DispositionType, MailHeader, MailHeaderMap, SingleInfo, addrparse_header};
use mime::Mime;

use crate::aheader::Aheader;
use crate::authres::handle_authres;
use crate::blob::BlobObject;
use crate::chat::ChatId;
use crate::config::Config;
use crate::constants;
use crate::contact::ContactId;
use crate::context::Context;
use crate::decrypt::{try_decrypt, validate_detached_signature};
use crate::dehtml::dehtml;
use crate::download::PostMsgMetadata;
use crate::events::EventType;
use crate::headerdef::{HeaderDef, HeaderDefMap};
use crate::key::{self, DcKey, Fingerprint, SignedPublicKey, load_self_secret_keyring};
use crate::log::warn;
use crate::message::{self, Message, MsgId, Viewtype, get_vcard_summary, set_msg_failed};
use crate::param::{Param, Params};
use crate::simplify::{SimplifiedText, simplify};
use crate::sync::SyncItems;
use crate::tools::{
    get_filemeta, parse_receive_headers, smeared_time, time, truncate_msg_text, validate_id,
};
use crate::{chatlist_events, location, tools};

/// Public key extracted from `Autocrypt-Gossip`
/// header with associated information.
#[derive(Debug)]
pub struct GossipedKey {
    /// Public key extracted from `keydata` attribute.
    pub public_key: SignedPublicKey,

    /// True if `Autocrypt-Gossip` has a `_verified` attribute.
    pub verified: bool,
}

/// A parsed MIME message.
///
/// This represents the relevant information of a parsed MIME message
/// for deltachat.  The original MIME message might have had more
/// information but this representation should contain everything
/// needed for deltachat's purposes.
///
/// It is created by parsing the raw data of an actual MIME message
/// using the [MimeMessage::from_bytes] constructor.
#[derive(Debug)]
pub(crate) struct MimeMessage {
    /// Parsed MIME parts.
    pub parts: Vec<Part>,

    /// Message headers.
    headers: HashMap<String, String>,

    #[cfg(test)]
    /// Names of removed (ignored) headers. Used by `header_exists()` needed for tests.
    headers_removed: HashSet<String>,

    /// List of addresses from the `To` and `Cc` headers.
    ///
    /// Addresses are normalized and lowercase.
    pub recipients: Vec<SingleInfo>,

    /// List of addresses from the `Chat-Group-Past-Members` header.
    pub past_members: Vec<SingleInfo>,

    /// `From:` address.
    pub from: SingleInfo,

    /// Whether the message is incoming or outgoing (self-sent).
    pub incoming: bool,
    /// The List-Post address is only set for mailing lists. Users can send
    /// messages to this address to post them to the list.
    pub list_post: Option<String>,
    pub chat_disposition_notification_to: Option<SingleInfo>,
    pub decrypting_failed: bool,

    /// Valid signature fingerprint if a message is an
    /// Autocrypt encrypted and signed message and corresponding intended recipient fingerprints
    /// (<https://www.rfc-editor.org/rfc/rfc9580.html#name-intended-recipient-fingerpr>) if any.
    ///
    /// If a message is not encrypted or the signature is not valid,
    /// this is `None`.
    pub signature: Option<(Fingerprint, HashSet<Fingerprint>)>,

    /// The addresses for which there was a gossip header
    /// and their respective gossiped keys.
    pub gossiped_keys: BTreeMap<String, GossipedKey>,

    /// Fingerprint of the key in the Autocrypt header.
    ///
    /// It is not verified that the sender can use this key.
    pub autocrypt_fingerprint: Option<String>,

    /// True if the message is a forwarded message.
    pub is_forwarded: bool,
    pub is_system_message: SystemMessage,
    pub location_kml: Option<location::Kml>,
    pub message_kml: Option<location::Kml>,
    pub(crate) sync_items: Option<SyncItems>,
    pub(crate) webxdc_status_update: Option<String>,
    pub(crate) user_avatar: Option<AvatarAction>,
    pub(crate) group_avatar: Option<AvatarAction>,
    pub(crate) mdn_reports: Vec<Report>,
    pub(crate) delivery_report: Option<DeliveryReport>,

    /// Standard USENET signature, if any.
    ///
    /// `None` means no text part was received, empty string means a text part without a footer is
    /// received.
    pub(crate) footer: Option<String>,

    /// If set, this is a modified MIME message; clients should offer a way to view the original
    /// MIME message in this case.
    pub is_mime_modified: bool,

    /// Decrypted raw MIME structure.
    pub decoded_data: Vec<u8>,

    /// Hop info for debugging.
    pub(crate) hop_info: String,

    /// Whether the message is auto-generated.
    ///
    /// If chat message (with `Chat-Version` header) is auto-generated,
    /// the contact sending this should be marked as bot.
    ///
    /// If non-chat message is auto-generated,
    /// it could be a holiday notice auto-reply,
    /// in which case the message should be marked as bot-generated,
    /// but the contact should not be.
    pub(crate) is_bot: Option<bool>,

    /// When the message was received, in secs since epoch.
    pub(crate) timestamp_rcvd: i64,
    /// Sender timestamp in secs since epoch. Allowed to be in the future due to unsynchronized
    /// clocks, but not too much.
    pub(crate) timestamp_sent: i64,

    pub(crate) pre_message: PreMessageMode,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PreMessageMode {
    /// This is a post-message.
    /// It replaces its pre-message attachment if it exists already,
    /// and if the pre-message does not exist, it is treated as a normal message.
    Post,
    /// This is a Pre-Message,
    /// it adds a message preview for a Post-Message
    /// and it is ignored if the Post-Message was downloaded already
    Pre {
        post_msg_rfc724_mid: String,
        metadata: Option<PostMsgMetadata>,
    },
    /// Atomic ("normal") message.
    None,
}

#[derive(Debug, PartialEq)]
pub(crate) enum AvatarAction {
    Delete,
    Change(String),
}

/// System message type.
#[derive(
    Debug, Default, Display, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive, ToSql, FromSql,
)]
#[repr(u32)]
pub enum SystemMessage {
    /// Unknown type of system message.
    #[default]
    Unknown = 0,

    /// Group or broadcast channel name changed.
    GroupNameChanged = 2,

    /// Group or broadcast channel avatar changed.
    GroupImageChanged = 3,

    /// Member was added to the group.
    MemberAddedToGroup = 4,

    /// Member was removed from the group.
    MemberRemovedFromGroup = 5,

    /// Autocrypt Setup Message.
    AutocryptSetupMessage = 6,

    /// Secure-join message.
    SecurejoinMessage = 7,

    /// Location streaming is enabled.
    LocationStreamingEnabled = 8,

    /// Location-only message.
    LocationOnly = 9,

    /// Chat ephemeral message timer is changed.
    EphemeralTimerChanged = 10,

    /// "Messages are end-to-end encrypted."
    ChatProtectionEnabled = 11,

    /// "%1$s sent a message from another device.", deprecated 2025-07
    ChatProtectionDisabled = 12,

    /// Message can't be sent because of `Invalid unencrypted mail to <>`
    /// which is sent by chatmail servers.
    InvalidUnencryptedMail = 13,

    /// 1:1 chats info message telling that SecureJoin has started and the user should wait for it
    /// to complete.
    SecurejoinWait = 14,

    /// 1:1 chats info message telling that SecureJoin is still running, but the user may already
    /// send messages.
    SecurejoinWaitTimeout = 15,

    /// Self-sent-message that contains only json used for multi-device-sync;
    /// if possible, we attach that to other messages as for locations.
    MultiDeviceSync = 20,

    /// Sync message that contains a json payload
    /// sent to the other webxdc instances
    /// These messages are not shown in the chat.
    WebxdcStatusUpdate = 30,

    /// Webxdc info added with `info` set in `send_webxdc_status_update()`.
    WebxdcInfoMessage = 32,

    /// This message contains a users iroh node address.
    IrohNodeAddr = 40,

    /// "Messages are end-to-end encrypted."
    ChatE2ee = 50,

    /// Message indicating that a call was accepted.
    CallAccepted = 66,

    /// Message indicating that a call was ended.
    CallEnded = 67,

    /// Group or broadcast channel description changed.
    GroupDescriptionChanged = 70,
}

const MIME_AC_SETUP_FILE: &str = "application/autocrypt-setup";

impl MimeMessage {
    /// Parse a mime message.
    ///
    /// This method has some side-effects,
    /// such as saving blobs and saving found public keys to the database.
    #[expect(clippy::arithmetic_side_effects)]
    pub(crate) async fn from_bytes(context: &Context, body: &[u8]) -> Result<Self> {
        let mail = mailparse::parse_mail(body)?;

        let timestamp_rcvd = smeared_time(context);
        let mut timestamp_sent =
            Self::get_timestamp_sent(&mail.headers, timestamp_rcvd, timestamp_rcvd);
        let mut hop_info = parse_receive_headers(&mail.get_headers());

        let mut headers = Default::default();
        let mut headers_removed = HashSet::<String>::new();
        let mut recipients = Default::default();
        let mut past_members = Default::default();
        let mut from = Default::default();
        let mut list_post = Default::default();
        let mut chat_disposition_notification_to = None;

        // Parse IMF headers.
        MimeMessage::merge_headers(
            context,
            &mut headers,
            &mut headers_removed,
            &mut recipients,
            &mut past_members,
            &mut from,
            &mut list_post,
            &mut chat_disposition_notification_to,
            &mail,
        );
        headers_removed.extend(
            headers
                .extract_if(|k, _v| is_hidden(k))
                .map(|(k, _v)| k.to_string()),
        );

        // Parse hidden headers.
        let mimetype = mail.ctype.mimetype.parse::<Mime>()?;
        let (part, mimetype) =
            if mimetype.type_() == mime::MULTIPART && mimetype.subtype().as_str() == "signed" {
                if let Some(part) = mail.subparts.first() {
                    // We don't remove "subject" from `headers` because currently just signed
                    // messages are shown as unencrypted anyway.

                    timestamp_sent =
                        Self::get_timestamp_sent(&part.headers, timestamp_sent, timestamp_rcvd);
                    MimeMessage::merge_headers(
                        context,
                        &mut headers,
                        &mut headers_removed,
                        &mut recipients,
                        &mut past_members,
                        &mut from,
                        &mut list_post,
                        &mut chat_disposition_notification_to,
                        part,
                    );
                    (part, part.ctype.mimetype.parse::<Mime>()?)
                } else {
                    // Not a valid signed message, handle it as plaintext.
                    (&mail, mimetype)
                }
            } else {
                // Currently we do not sign unencrypted messages by default.
                (&mail, mimetype)
            };
        if mimetype.type_() == mime::MULTIPART
            && mimetype.subtype().as_str() == "mixed"
            && let Some(part) = part.subparts.first()
        {
            for field in &part.headers {
                let key = field.get_key().to_lowercase();
                if !headers.contains_key(&key) && is_hidden(&key) || key == "message-id" {
                    headers.insert(key.to_string(), field.get_value());
                }
            }
        }

        // Overwrite Message-ID with X-Microsoft-Original-Message-ID.
        // However if we later find Message-ID in the protected part,
        // it will overwrite both.
        if let Some(microsoft_message_id) = remove_header(
            &mut headers,
            HeaderDef::XMicrosoftOriginalMessageId.get_headername(),
            &mut headers_removed,
        ) {
            headers.insert(
                HeaderDef::MessageId.get_headername().to_string(),
                microsoft_message_id,
            );
        }

        // Remove headers that are allowed _only_ in the encrypted+signed part. It's ok to leave
        // them in signed-only emails, but has no value currently.
        Self::remove_secured_headers(&mut headers, &mut headers_removed);

        let mut from = from.context("No from in message")?;
        let private_keyring = load_self_secret_keyring(context).await?;

        let dkim_results = handle_authres(context, &mail, &from.addr).await?;

        let mut gossiped_keys = Default::default();
        hop_info += "\n\n";
        hop_info += &dkim_results.to_string();

        let incoming = !context.is_self_addr(&from.addr).await?;

        let mut aheader_values = mail.headers.get_all_values(HeaderDef::Autocrypt.into());

        let mut pre_message = if mail
            .headers
            .get_header_value(HeaderDef::ChatIsPostMessage)
            .is_some()
        {
            PreMessageMode::Post
        } else {
            PreMessageMode::None
        };

        let mail_raw; // Memory location for a possible decrypted message.
        let decrypted_msg; // Decrypted signed OpenPGP message.
        let secrets: Vec<String> = context
            .sql
            .query_map_vec("SELECT secret FROM broadcast_secrets", (), |row| {
                let secret: String = row.get(0)?;
                Ok(secret)
            })
            .await?;

        let (mail, is_encrypted) =
            match tokio::task::block_in_place(|| try_decrypt(&mail, &private_keyring, &secrets)) {
                Ok(Some(mut msg)) => {
                    mail_raw = msg.as_data_vec().unwrap_or_default();

                    let decrypted_mail = mailparse::parse_mail(&mail_raw)?;
                    if std::env::var(crate::DCC_MIME_DEBUG).is_ok() {
                        info!(
                            context,
                            "decrypted message mime-body:\n{}",
                            String::from_utf8_lossy(&mail_raw),
                        );
                    }

                    decrypted_msg = Some(msg);

                    timestamp_sent = Self::get_timestamp_sent(
                        &decrypted_mail.headers,
                        timestamp_sent,
                        timestamp_rcvd,
                    );

                    let protected_aheader_values = decrypted_mail
                        .headers
                        .get_all_values(HeaderDef::Autocrypt.into());
                    if !protected_aheader_values.is_empty() {
                        aheader_values = protected_aheader_values;
                    }

                    (Ok(decrypted_mail), true)
                }
                Ok(None) => {
                    mail_raw = Vec::new();
                    decrypted_msg = None;
                    (Ok(mail), false)
                }
                Err(err) => {
                    mail_raw = Vec::new();
                    decrypted_msg = None;
                    warn!(context, "decryption failed: {:#}", err);
                    (Err(err), false)
                }
            };

        let mut autocrypt_header = None;
        if incoming {
            // See `get_all_addresses_from_header()` for why we take the last valid header.
            for val in aheader_values.iter().rev() {
                autocrypt_header = match Aheader::from_str(val) {
                    Ok(header) if addr_cmp(&header.addr, &from.addr) => Some(header),
                    Ok(header) => {
                        warn!(
                            context,
                            "Autocrypt header address {:?} is not {:?}.", header.addr, from.addr
                        );
                        continue;
                    }
                    Err(err) => {
                        warn!(context, "Failed to parse Autocrypt header: {:#}.", err);
                        continue;
                    }
                };
                break;
            }
        }

        let autocrypt_fingerprint = if let Some(autocrypt_header) = &autocrypt_header {
            let fingerprint = autocrypt_header.public_key.dc_fingerprint().hex();
            let inserted = context
                .sql
                .execute(
                    "INSERT INTO public_keys (fingerprint, public_key)
                                 VALUES (?, ?)
                                 ON CONFLICT (fingerprint)
                                 DO NOTHING",
                    (&fingerprint, autocrypt_header.public_key.to_bytes()),
                )
                .await?;
            if inserted > 0 {
                info!(
                    context,
                    "Saved key with fingerprint {fingerprint} from the Autocrypt header"
                );
            }
            Some(fingerprint)
        } else {
            None
        };

        let mut public_keyring = if incoming {
            if let Some(autocrypt_header) = autocrypt_header {
                vec![autocrypt_header.public_key]
            } else {
                vec![]
            }
        } else {
            key::load_self_public_keyring(context).await?
        };

        if let Some(signature) = match &decrypted_msg {
            Some(pgp::composed::Message::Literal { .. }) => None,
            Some(pgp::composed::Message::Compressed { .. }) => {
                // One layer of compression should already be handled by now.
                // We don't decompress messages compressed multiple times.
                None
            }
            Some(pgp::composed::Message::Signed { reader, .. }) => reader.signature(0),
            Some(pgp::composed::Message::Encrypted { .. }) => {
                // The message is already decrypted once.
                None
            }
            None => None,
        } {
            for issuer_fingerprint in signature.issuer_fingerprint() {
                let issuer_fingerprint =
                    crate::key::Fingerprint::from(issuer_fingerprint.clone()).hex();
                if let Some(public_key_bytes) = context
                    .sql
                    .query_row_optional(
                        "SELECT public_key
                         FROM public_keys
                         WHERE fingerprint=?",
                        (&issuer_fingerprint,),
                        |row| {
                            let bytes: Vec<u8> = row.get(0)?;
                            Ok(bytes)
                        },
                    )
                    .await?
                {
                    let public_key = SignedPublicKey::from_slice(&public_key_bytes)?;
                    public_keyring.push(public_key)
                }
            }
        }

        let mut signatures = if let Some(ref decrypted_msg) = decrypted_msg {
            crate::pgp::valid_signature_fingerprints(decrypted_msg, &public_keyring)
        } else {
            HashMap::new()
        };

        let mail = mail.as_ref().map(|mail| {
            let (content, signatures_detached) = validate_detached_signature(mail, &public_keyring)
                .unwrap_or((mail, Default::default()));
            let signatures_detached = signatures_detached
                .into_iter()
                .map(|fp| (fp, Vec::new()))
                .collect::<HashMap<_, _>>();
            signatures.extend(signatures_detached);
            content
        });
        if let (Ok(mail), true) = (mail, is_encrypted) {
            if !signatures.is_empty() {
                // Unsigned "Subject" mustn't be prepended to messages shown as encrypted
                // (<https://github.com/deltachat/deltachat-core-rust/issues/1790>).
                // Other headers are removed by `MimeMessage::merge_headers()` except for "List-ID".
                remove_header(&mut headers, "subject", &mut headers_removed);
                remove_header(&mut headers, "list-id", &mut headers_removed);
            }

            // let known protected headers from the decrypted
            // part override the unencrypted top-level

            // Signature was checked for original From, so we
            // do not allow overriding it.
            let mut inner_from = None;

            MimeMessage::merge_headers(
                context,
                &mut headers,
                &mut headers_removed,
                &mut recipients,
                &mut past_members,
                &mut inner_from,
                &mut list_post,
                &mut chat_disposition_notification_to,
                mail,
            );

            if !signatures.is_empty() {
                // Handle any gossip headers if the mail was encrypted. See section
                // "3.6 Key Gossip" of <https://autocrypt.org/autocrypt-spec-1.1.0.pdf>
                // but only if the mail was correctly signed. Probably it's ok to not require
                // encryption here, but let's follow the standard.
                let gossip_headers = mail.headers.get_all_values("Autocrypt-Gossip");
                gossiped_keys =
                    parse_gossip_headers(context, &from.addr, &recipients, gossip_headers).await?;
            }

            if let Some(inner_from) = inner_from {
                if !addr_cmp(&inner_from.addr, &from.addr) {
                    // There is a From: header in the encrypted
                    // part, but it doesn't match the outer one.
                    // This _might_ be because the sender's mail server
                    // replaced the sending address, e.g. in a mailing list.
                    // Or it's because someone is doing some replay attack.
                    // Resending encrypted messages via mailing lists
                    // without reencrypting is not useful anyway,
                    // so we return an error below.
                    warn!(
                        context,
                        "From header in encrypted part doesn't match the outer one",
                    );

                    // Return an error from the parser.
                    // This will result in creating a tombstone
                    // and no further message processing
                    // as if the MIME structure is broken.
                    bail!("From header is forged");
                }
                from = inner_from;
            }
        }
        if signatures.is_empty() {
            Self::remove_secured_headers(&mut headers, &mut headers_removed);
        }
        if !is_encrypted {
            signatures.clear();
        }

        if let (Ok(mail), true) = (mail, is_encrypted)
            && let Some(post_msg_rfc724_mid) =
                mail.headers.get_header_value(HeaderDef::ChatPostMessageId)
        {
            let post_msg_rfc724_mid = parse_message_id(&post_msg_rfc724_mid)?;
            let metadata = if let Some(value) = mail
                .headers
                .get_header_value(HeaderDef::ChatPostMessageMetadata)
            {
                match PostMsgMetadata::try_from_header_value(&value) {
                    Ok(metadata) => Some(metadata),
                    Err(error) => {
                        error!(
                            context,
                            "Failed to parse metadata header in pre-message for {post_msg_rfc724_mid}: {error:#}."
                        );
                        None
                    }
                }
            } else {
                warn!(
                    context,
                    "Expected pre-message for {post_msg_rfc724_mid} to have metadata header."
                );
                None
            };

            pre_message = PreMessageMode::Pre {
                post_msg_rfc724_mid,
                metadata,
            };
        }

        let signature = signatures
            .into_iter()
            .last()
            .map(|(fp, recipient_fps)| (fp, recipient_fps.into_iter().collect::<HashSet<_>>()));
        let mut parser = MimeMessage {
            parts: Vec::new(),
            headers,
            #[cfg(test)]
            headers_removed,

            recipients,
            past_members,
            list_post,
            from,
            incoming,
            chat_disposition_notification_to,
            decrypting_failed: mail.is_err(),

            // only non-empty if it was a valid autocrypt message
            signature,
            autocrypt_fingerprint,
            gossiped_keys,
            is_forwarded: false,
            mdn_reports: Vec::new(),
            is_system_message: SystemMessage::Unknown,
            location_kml: None,
            message_kml: None,
            sync_items: None,
            webxdc_status_update: None,
            user_avatar: None,
            group_avatar: None,
            delivery_report: None,
            footer: None,
            is_mime_modified: false,
            decoded_data: Vec::new(),
            hop_info,
            is_bot: None,
            timestamp_rcvd,
            timestamp_sent,
            pre_message,
        };

        match mail {
            Ok(mail) => {
                parser.parse_mime_recursive(context, mail, false).await?;
            }
            Err(err) => {
                let txt = "[This message cannot be decrypted.\n\n• It might already help to simply reply to this message and ask the sender to send the message again.\n\n• If you just re-installed Delta Chat then it is best if you re-setup Delta Chat now and choose \"Add as second device\" or import a backup.]";

                let part = Part {
                    typ: Viewtype::Text,
                    msg_raw: Some(txt.to_string()),
                    msg: txt.to_string(),
                    // Don't change the error prefix for now,
                    // receive_imf.rs:lookup_chat_by_reply() checks it.
                    error: Some(format!("Decrypting failed: {err:#}")),
                    ..Default::default()
                };
                parser.do_add_single_part(part);
            }
        };

        let is_location_only = parser.location_kml.is_some() && parser.parts.is_empty();
        if parser.mdn_reports.is_empty()
            && !is_location_only
            && parser.sync_items.is_none()
            && parser.webxdc_status_update.is_none()
        {
            let is_bot =
                parser.headers.get("auto-submitted") == Some(&"auto-generated".to_string());
            parser.is_bot = Some(is_bot);
        }
        parser.maybe_remove_bad_parts();
        parser.maybe_remove_inline_mailinglist_footer();
        parser.heuristically_parse_ndn(context).await;
        parser.parse_headers(context).await?;
        parser.decoded_data = mail_raw;

        Ok(parser)
    }

    #[expect(clippy::arithmetic_side_effects)]
    fn get_timestamp_sent(
        hdrs: &[mailparse::MailHeader<'_>],
        default: i64,
        timestamp_rcvd: i64,
    ) -> i64 {
        hdrs.get_header_value(HeaderDef::Date)
            .and_then(|v| mailparse::dateparse(&v).ok())
            .map_or(default, |value| {
                min(value, timestamp_rcvd + constants::TIMESTAMP_SENT_TOLERANCE)
            })
    }

    /// Parses system messages.
    fn parse_system_message_headers(&mut self, context: &Context) {
        if self.get_header(HeaderDef::AutocryptSetupMessage).is_some() && !self.incoming {
            self.parts.retain(|part| {
                part.mimetype
                    .as_ref()
                    .is_none_or(|mimetype| mimetype.as_ref() == MIME_AC_SETUP_FILE)
            });

            if self.parts.len() == 1 {
                self.is_system_message = SystemMessage::AutocryptSetupMessage;
            } else {
                warn!(context, "could not determine ASM mime-part");
            }
        } else if let Some(value) = self.get_header(HeaderDef::ChatContent) {
            if value == "location-streaming-enabled" {
                self.is_system_message = SystemMessage::LocationStreamingEnabled;
            } else if value == "ephemeral-timer-changed" {
                self.is_system_message = SystemMessage::EphemeralTimerChanged;
            } else if value == "protection-enabled" {
                self.is_system_message = SystemMessage::ChatProtectionEnabled;
            } else if value == "protection-disabled" {
                self.is_system_message = SystemMessage::ChatProtectionDisabled;
            } else if value == "group-avatar-changed" {
                self.is_system_message = SystemMessage::GroupImageChanged;
            } else if value == "call-accepted" {
                self.is_system_message = SystemMessage::CallAccepted;
            } else if value == "call-ended" {
                self.is_system_message = SystemMessage::CallEnded;
            }
        } else if self.get_header(HeaderDef::ChatGroupMemberRemoved).is_some() {
            self.is_system_message = SystemMessage::MemberRemovedFromGroup;
        } else if self.get_header(HeaderDef::ChatGroupMemberAdded).is_some() {
            self.is_system_message = SystemMessage::MemberAddedToGroup;
        } else if self.get_header(HeaderDef::ChatGroupNameChanged).is_some() {
            self.is_system_message = SystemMessage::GroupNameChanged;
        } else if self
            .get_header(HeaderDef::ChatGroupDescriptionChanged)
            .is_some()
        {
            self.is_system_message = SystemMessage::GroupDescriptionChanged;
        }
    }

    /// Parses avatar action headers.
    fn parse_avatar_headers(&mut self, context: &Context) -> Result<()> {
        if let Some(header_value) = self.get_header(HeaderDef::ChatGroupAvatar) {
            self.group_avatar =
                self.avatar_action_from_header(context, header_value.to_string())?;
        }

        if let Some(header_value) = self.get_header(HeaderDef::ChatUserAvatar) {
            self.user_avatar = self.avatar_action_from_header(context, header_value.to_string())?;
        }
        Ok(())
    }

    fn parse_videochat_headers(&mut self) {
        let content = self
            .get_header(HeaderDef::ChatContent)
            .unwrap_or_default()
            .to_string();
        let room = self
            .get_header(HeaderDef::ChatWebrtcRoom)
            .map(|s| s.to_string());
        let accepted = self
            .get_header(HeaderDef::ChatWebrtcAccepted)
            .map(|s| s.to_string());
        let has_video = self
            .get_header(HeaderDef::ChatWebrtcHasVideoInitially)
            .map(|s| s.to_string());
        if let Some(part) = self.parts.first_mut() {
            if let Some(room) = room {
                if content == "call" {
                    part.typ = Viewtype::Call;
                    part.param.set(Param::WebrtcRoom, room);
                }
            } else if let Some(accepted) = accepted {
                part.param.set(Param::WebrtcAccepted, accepted);
            }
            if let Some(has_video) = has_video {
                part.param.set(Param::WebrtcHasVideoInitially, has_video);
            }
        }
    }

    /// Squashes mutitpart chat messages with attachment into single-part messages.
    ///
    /// Delta Chat sends attachments, such as images, in two-part messages, with the first message
    /// containing a description. If such a message is detected, text from the first part can be
    /// moved to the second part, and the first part dropped.
    fn squash_attachment_parts(&mut self) {
        if self.parts.len() == 2
            && self.parts.first().map(|textpart| textpart.typ) == Some(Viewtype::Text)
            && self
                .parts
                .get(1)
                .is_some_and(|filepart| match filepart.typ {
                    Viewtype::Image
                    | Viewtype::Gif
                    | Viewtype::Sticker
                    | Viewtype::Audio
                    | Viewtype::Voice
                    | Viewtype::Video
                    | Viewtype::Vcard
                    | Viewtype::File
                    | Viewtype::Webxdc => true,
                    Viewtype::Unknown | Viewtype::Text | Viewtype::Call => false,
                })
        {
            let mut parts = std::mem::take(&mut self.parts);
            let Some(mut filepart) = parts.pop() else {
                // Should never happen.
                return;
            };
            let Some(textpart) = parts.pop() else {
                // Should never happen.
                return;
            };

            filepart.msg.clone_from(&textpart.msg);
            if let Some(quote) = textpart.param.get(Param::Quote) {
                filepart.param.set(Param::Quote, quote);
            }

            self.parts = vec![filepart];
        }
    }

    /// Processes chat messages with attachments.
    fn parse_attachments(&mut self) {
        // Attachment messages should be squashed into a single part
        // before calling this function.
        if self.parts.len() != 1 {
            return;
        }

        if let Some(mut part) = self.parts.pop() {
            if part.typ == Viewtype::Audio && self.get_header(HeaderDef::ChatVoiceMessage).is_some()
            {
                part.typ = Viewtype::Voice;
            }
            if (part.typ == Viewtype::Image || part.typ == Viewtype::Gif)
                && let Some(value) = self.get_header(HeaderDef::ChatContent)
                && value == "sticker"
            {
                part.typ = Viewtype::Sticker;
            }
            if (part.typ == Viewtype::Audio
                || part.typ == Viewtype::Voice
                || part.typ == Viewtype::Video)
                && let Some(field_0) = self.get_header(HeaderDef::ChatDuration)
            {
                let duration_ms = field_0.parse().unwrap_or_default();
                if duration_ms > 0 && duration_ms < 24 * 60 * 60 * 1000 {
                    part.param.set_int(Param::Duration, duration_ms);
                }
            }

            self.parts.push(part);
        }
    }

    async fn parse_headers(&mut self, context: &Context) -> Result<()> {
        self.parse_system_message_headers(context);
        self.parse_avatar_headers(context)?;
        self.parse_videochat_headers();
        if self.delivery_report.is_none() {
            self.squash_attachment_parts();
        }

        if !context.get_config_bool(Config::Bot).await?
            && let Some(ref subject) = self.get_subject()
        {
            let mut prepend_subject = true;
            if !self.decrypting_failed {
                let colon = subject.find(':');
                if colon == Some(2)
                    || colon == Some(3)
                    || self.has_chat_version()
                    || subject.contains("Chat:")
                {
                    prepend_subject = false
                }
            }

            // For mailing lists, always add the subject because sometimes there are different topics
            // and otherwise it might be hard to keep track:
            if self.is_mailinglist_message() && !self.has_chat_version() {
                prepend_subject = true;
            }

            if prepend_subject && !subject.is_empty() {
                let part_with_text = self
                    .parts
                    .iter_mut()
                    .find(|part| !part.msg.is_empty() && !part.is_reaction);
                if let Some(part) = part_with_text {
                    // Message bubbles are small, so we use en dash to save space. In some
                    // languages there may be em dashes in the message text added by the author,
                    // they may look stronger than Subject separation, this is a known thing.
                    // Anyway, classic email support isn't a priority as of 2025.
                    part.msg = format!("{} – {}", subject, part.msg);
                }
            }
        }

        if self.is_forwarded {
            for part in &mut self.parts {
                part.param.set_int(Param::Forwarded, 1);
            }
        }

        self.parse_attachments();

        // See if an MDN is requested from the other side
        if !self.decrypting_failed
            && !self.parts.is_empty()
            && let Some(ref dn_to) = self.chat_disposition_notification_to
        {
            // Check that the message is not outgoing.
            let from = &self.from.addr;
            if !context.is_self_addr(from).await? {
                if from.to_lowercase() == dn_to.addr.to_lowercase() {
                    if let Some(part) = self.parts.last_mut() {
                        part.param.set_int(Param::WantsMdn, 1);
                    }
                } else {
                    warn!(
                        context,
                        "{} requested a read receipt to {}, ignoring", from, dn_to.addr
                    );
                }
            }
        }

        // If there were no parts, especially a non-DC mail user may
        // just have send a message in the subject with an empty body.
        // Besides, we want to show something in case our incoming-processing
        // failed to properly handle an incoming message.
        if self.parts.is_empty() && self.mdn_reports.is_empty() {
            let mut part = Part {
                typ: Viewtype::Text,
                ..Default::default()
            };

            if let Some(ref subject) = self.get_subject()
                && !self.has_chat_version()
                && self.webxdc_status_update.is_none()
            {
                part.msg = subject.to_string();
            }

            self.do_add_single_part(part);
        }

        if self.is_bot == Some(true) {
            for part in &mut self.parts {
                part.param.set(Param::Bot, "1");
            }
        }

        Ok(())
    }

    #[expect(clippy::arithmetic_side_effects)]
    fn avatar_action_from_header(
        &mut self,
        context: &Context,
        header_value: String,
    ) -> Result<Option<AvatarAction>> {
        let res = if header_value == "0" {
            Some(AvatarAction::Delete)
        } else if let Some(base64) = header_value
            .split_ascii_whitespace()
            .collect::<String>()
            .strip_prefix("base64:")
        {
            match BlobObject::store_from_base64(context, base64)? {
                Some(path) => Some(AvatarAction::Change(path)),
                None => {
                    warn!(context, "Could not decode avatar base64");
                    None
                }
            }
        } else {
            // Avatar sent in attachment, as previous versions of Delta Chat did.

            let mut i = 0;
            while let Some(part) = self.parts.get_mut(i) {
                if let Some(part_filename) = &part.org_filename
                    && part_filename == &header_value
                {
                    if let Some(blob) = part.param.get(Param::File) {
                        let res = Some(AvatarAction::Change(blob.to_string()));
                        self.parts.remove(i);
                        return Ok(res);
                    }
                    break;
                }
                i += 1;
            }
            None
        };
        Ok(res)
    }

    /// Returns true if the message was encrypted as defined in
    /// Autocrypt standard.
    ///
    /// This means the message was both encrypted and signed with a
    /// valid signature.
    pub fn was_encrypted(&self) -> bool {
        self.signature.is_some()
    }

    /// Returns whether the email contains a `chat-version` header.
    /// This indicates that the email is a DC-email.
    pub(crate) fn has_chat_version(&self) -> bool {
        self.headers.contains_key("chat-version")
    }

    pub(crate) fn get_subject(&self) -> Option<String> {
        self.get_header(HeaderDef::Subject)
            .map(|s| s.trim_start())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    }

    pub fn get_header(&self, headerdef: HeaderDef) -> Option<&str> {
        self.headers
            .get(headerdef.get_headername())
            .map(|s| s.as_str())
    }

    #[cfg(test)]
    /// Returns whether the header exists in any part of the parsed message.
    ///
    /// Use this to check for header absense. Header presense should be checked using
    /// `get_header(...).is_some()` as it also checks that the header isn't ignored.
    pub(crate) fn header_exists(&self, headerdef: HeaderDef) -> bool {
        let hname = headerdef.get_headername();
        self.headers.contains_key(hname) || self.headers_removed.contains(hname)
    }

    #[cfg(test)]
    /// Returns whether the decrypted data contains the given `&str`.
    pub(crate) fn decoded_data_contains(&self, s: &str) -> bool {
        assert!(!self.decrypting_failed);
        let decoded_str = str::from_utf8(&self.decoded_data).unwrap();
        decoded_str.contains(s)
    }

    /// Returns `Chat-Group-ID` header value if it is a valid group ID.
    pub fn get_chat_group_id(&self) -> Option<&str> {
        self.get_header(HeaderDef::ChatGroupId)
            .filter(|s| validate_id(s))
    }

    async fn parse_mime_recursive<'a>(
        &'a mut self,
        context: &'a Context,
        mail: &'a mailparse::ParsedMail<'a>,
        is_related: bool,
    ) -> Result<bool> {
        enum MimeS {
            Multiple,
            Single,
            Message,
        }

        let mimetype = mail.ctype.mimetype.to_lowercase();

        let m = if mimetype.starts_with("multipart") {
            if mail.ctype.params.contains_key("boundary") {
                MimeS::Multiple
            } else {
                MimeS::Single
            }
        } else if mimetype.starts_with("message") {
            if mimetype == "message/rfc822" && !is_attachment_disposition(mail) {
                MimeS::Message
            } else {
                MimeS::Single
            }
        } else {
            MimeS::Single
        };

        let is_related = is_related || mimetype == "multipart/related";
        match m {
            MimeS::Multiple => Box::pin(self.handle_multiple(context, mail, is_related)).await,
            MimeS::Message => {
                let raw = mail.get_body_raw()?;
                if raw.is_empty() {
                    return Ok(false);
                }
                let mail = mailparse::parse_mail(&raw).context("failed to parse mail")?;

                Box::pin(self.parse_mime_recursive(context, &mail, is_related)).await
            }
            MimeS::Single => {
                self.add_single_part_if_known(context, mail, is_related)
                    .await
            }
        }
    }

    async fn handle_multiple(
        &mut self,
        context: &Context,
        mail: &mailparse::ParsedMail<'_>,
        is_related: bool,
    ) -> Result<bool> {
        let mut any_part_added = false;
        let mimetype = get_mime_type(
            mail,
            &get_attachment_filename(context, mail)?,
            self.has_chat_version(),
        )?
        .0;
        match (mimetype.type_(), mimetype.subtype().as_str()) {
            (mime::MULTIPART, "alternative") => {
                // multipart/alternative is described in
                // <https://datatracker.ietf.org/doc/html/rfc2046#section-5.1.4>.
                // Specification says that last part should be preferred,
                // so we iterate over parts in reverse order.

                // Search for plain text or multipart part.
                //
                // If we find a multipart inside multipart/alternative
                // and it has usable subparts, we only parse multipart.
                // This happens e.g. in Apple Mail:
                // "plaintext" as an alternative to "html+PDF attachment".
                for cur_data in mail.subparts.iter().rev() {
                    let (mime_type, _viewtype) = get_mime_type(
                        cur_data,
                        &get_attachment_filename(context, cur_data)?,
                        self.has_chat_version(),
                    )?;

                    if mime_type == mime::TEXT_PLAIN || mime_type.type_() == mime::MULTIPART {
                        any_part_added = self
                            .parse_mime_recursive(context, cur_data, is_related)
                            .await?;
                        break;
                    }
                }

                // Explicitly look for a `text/calendar` part.
                // Messages conforming to <https://datatracker.ietf.org/doc/html/rfc6047>
                // contain `text/calendar` part as an alternative
                // to the text or HTML representation.
                //
                // While we cannot display `text/calendar` and therefore do not prefer it,
                // we still make it available by presenting as an attachment
                // with a generic filename.
                for cur_data in mail.subparts.iter().rev() {
                    let mimetype = cur_data.ctype.mimetype.parse::<Mime>()?;
                    if mimetype.type_() == mime::TEXT && mimetype.subtype() == "calendar" {
                        let filename = get_attachment_filename(context, cur_data)?
                            .unwrap_or_else(|| "calendar.ics".to_string());
                        self.do_add_single_file_part(
                            context,
                            Viewtype::File,
                            mimetype,
                            &mail.ctype.mimetype.to_lowercase(),
                            &mail.get_body_raw()?,
                            &filename,
                            is_related,
                        )
                        .await?;
                    }
                }

                if !any_part_added {
                    for cur_part in mail.subparts.iter().rev() {
                        if self
                            .parse_mime_recursive(context, cur_part, is_related)
                            .await?
                        {
                            any_part_added = true;
                            break;
                        }
                    }
                }
                if any_part_added && mail.subparts.len() > 1 {
                    // there are other alternative parts, likely HTML,
                    // so we might have missed some content on simplifying.
                    // set mime-modified to force the ui to display a show-message button.
                    self.is_mime_modified = true;
                }
            }
            (mime::MULTIPART, "signed") => {
                /* RFC 1847: "The multipart/signed content type
                contains exactly two body parts.  The first body
                part is the body part over which the digital signature was created [...]
                The second body part contains the control information necessary to
                verify the digital signature." We simply take the first body part and
                skip the rest.  (see
                <https://k9mail.app/2016/11/24/OpenPGP-Considerations-Part-I.html>
                for background information why we use encrypted+signed) */
                if let Some(first) = mail.subparts.first() {
                    any_part_added = self
                        .parse_mime_recursive(context, first, is_related)
                        .await?;
                }
            }
            (mime::MULTIPART, "report") => {
                /* RFC 6522: the first part is for humans, the second for machines */
                if mail.subparts.len() >= 2 {
                    match mail.ctype.params.get("report-type").map(|s| s as &str) {
                        Some("disposition-notification") => {
                            if let Some(report) = self.process_report(context, mail)? {
                                self.mdn_reports.push(report);
                            }

                            // Add MDN part so we can track it, avoid
                            // downloading the message again and
                            // delete if automatic message deletion is
                            // enabled.
                            let part = Part {
                                typ: Viewtype::Unknown,
                                ..Default::default()
                            };
                            self.parts.push(part);

                            any_part_added = true;
                        }
                        // Some providers, e.g. Tiscali, forget to set the report-type. So, if it's None, assume that it might be delivery-status
                        Some("delivery-status") | None => {
                            if let Some(report) = self.process_delivery_status(context, mail)? {
                                self.delivery_report = Some(report);
                            }

                            // Add all parts (we need another part, preferably text/plain, to show as an error message)
                            for cur_data in &mail.subparts {
                                if self
                                    .parse_mime_recursive(context, cur_data, is_related)
                                    .await?
                                {
                                    any_part_added = true;
                                }
                            }
                        }
                        Some("multi-device-sync") => {
                            if let Some(second) = mail.subparts.get(1) {
                                self.add_single_part_if_known(context, second, is_related)
                                    .await?;
                            }
                        }
                        Some("status-update") => {
                            if let Some(second) = mail.subparts.get(1) {
                                self.add_single_part_if_known(context, second, is_related)
                                    .await?;
                            }
                        }
                        Some(_) => {
                            for cur_data in &mail.subparts {
                                if self
                                    .parse_mime_recursive(context, cur_data, is_related)
                                    .await?
                                {
                                    any_part_added = true;
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // Add all parts (in fact, AddSinglePartIfKnown() later check if
                // the parts are really supported)
                for cur_data in &mail.subparts {
                    if self
                        .parse_mime_recursive(context, cur_data, is_related)
                        .await?
                    {
                        any_part_added = true;
                    }
                }
            }
        }

        Ok(any_part_added)
    }

    /// Returns true if any part was added, false otherwise.
    async fn add_single_part_if_known(
        &mut self,
        context: &Context,
        mail: &mailparse::ParsedMail<'_>,
        is_related: bool,
    ) -> Result<bool> {
        // return true if a part was added
        let filename = get_attachment_filename(context, mail)?;
        let (mime_type, msg_type) = get_mime_type(mail, &filename, self.has_chat_version())?;
        let raw_mime = mail.ctype.mimetype.to_lowercase();

        let old_part_count = self.parts.len();

        match filename {
            Some(filename) => {
                self.do_add_single_file_part(
                    context,
                    msg_type,
                    mime_type,
                    &raw_mime,
                    &mail.get_body_raw()?,
                    &filename,
                    is_related,
                )
                .await?;
            }
            None => {
                match mime_type.type_() {
                    mime::IMAGE | mime::AUDIO | mime::VIDEO | mime::APPLICATION => {
                        warn!(context, "Missing attachment");
                        return Ok(false);
                    }
                    mime::TEXT
                        if mail.get_content_disposition().disposition
                            == DispositionType::Extension("reaction".to_string()) =>
                    {
                        // Reaction.
                        let decoded_data = match mail.get_body() {
                            Ok(decoded_data) => decoded_data,
                            Err(err) => {
                                warn!(context, "Invalid body parsed {:#}", err);
                                // Note that it's not always an error - might be no data
                                return Ok(false);
                            }
                        };

                        let part = Part {
                            typ: Viewtype::Text,
                            mimetype: Some(mime_type),
                            msg: decoded_data,
                            is_reaction: true,
                            ..Default::default()
                        };
                        self.do_add_single_part(part);
                        return Ok(true);
                    }
                    mime::TEXT | mime::HTML => {
                        let decoded_data = match mail.get_body() {
                            Ok(decoded_data) => decoded_data,
                            Err(err) => {
                                warn!(context, "Invalid body parsed {:#}", err);
                                // Note that it's not always an error - might be no data
                                return Ok(false);
                            }
                        };

                        let is_plaintext = mime_type == mime::TEXT_PLAIN;
                        let mut dehtml_failed = false;

                        let SimplifiedText {
                            text: simplified_txt,
                            is_forwarded,
                            is_cut,
                            top_quote,
                            footer,
                        } = if decoded_data.is_empty() {
                            Default::default()
                        } else {
                            let is_html = mime_type == mime::TEXT_HTML;
                            if is_html {
                                self.is_mime_modified = true;
                                // NB: This unconditionally removes Legacy Display Elements (see
                                // <https://www.rfc-editor.org/rfc/rfc9788.html#section-4.5.3.3>). We
                                // don't check for the "hp-legacy-display" Content-Type parameter
                                // for simplicity.
                                if let Some(text) = dehtml(&decoded_data) {
                                    text
                                } else {
                                    dehtml_failed = true;
                                    SimplifiedText {
                                        text: decoded_data.clone(),
                                        ..Default::default()
                                    }
                                }
                            } else {
                                simplify(decoded_data.clone(), self.has_chat_version())
                            }
                        };

                        self.is_mime_modified = self.is_mime_modified
                            || ((is_forwarded || is_cut || top_quote.is_some())
                                && !self.has_chat_version());

                        let is_format_flowed = if let Some(format) = mail.ctype.params.get("format")
                        {
                            format.as_str().eq_ignore_ascii_case("flowed")
                        } else {
                            false
                        };

                        let (simplified_txt, simplified_quote) = if mime_type.type_() == mime::TEXT
                            && mime_type.subtype() == mime::PLAIN
                        {
                            // Don't check that we're inside an encrypted or signed part for
                            // simplicity.
                            let simplified_txt = match mail
                                .ctype
                                .params
                                .get("hp-legacy-display")
                                .is_some_and(|v| v == "1")
                            {
                                false => simplified_txt,
                                true => rm_legacy_display_elements(&simplified_txt),
                            };
                            if is_format_flowed {
                                let delsp = if let Some(delsp) = mail.ctype.params.get("delsp") {
                                    delsp.as_str().eq_ignore_ascii_case("yes")
                                } else {
                                    false
                                };
                                let unflowed_text = unformat_flowed(&simplified_txt, delsp);
                                let unflowed_quote = top_quote.map(|q| unformat_flowed(&q, delsp));
                                (unflowed_text, unflowed_quote)
                            } else {
                                (simplified_txt, top_quote)
                            }
                        } else {
                            (simplified_txt, top_quote)
                        };

                        let (simplified_txt, was_truncated) =
                            truncate_msg_text(context, simplified_txt).await?;
                        if was_truncated {
                            self.is_mime_modified = was_truncated;
                        }

                        if !simplified_txt.is_empty() || simplified_quote.is_some() {
                            let mut part = Part {
                                dehtml_failed,
                                typ: Viewtype::Text,
                                mimetype: Some(mime_type),
                                msg: simplified_txt,
                                ..Default::default()
                            };
                            if let Some(quote) = simplified_quote {
                                part.param.set(Param::Quote, quote);
                            }
                            part.msg_raw = Some(decoded_data);
                            self.do_add_single_part(part);
                        }

                        if is_forwarded {
                            self.is_forwarded = true;
                        }

                        if self.footer.is_none() && is_plaintext {
                            self.footer = Some(footer.unwrap_or_default());
                        }
                    }
                    _ => {}
                }
            }
        }

        // add object? (we do not add all objects, eg. signatures etc. are ignored)
        Ok(self.parts.len() > old_part_count)
    }

    #[expect(clippy::too_many_arguments)]
    #[expect(clippy::arithmetic_side_effects)]
    async fn do_add_single_file_part(
        &mut self,
        context: &Context,
        msg_type: Viewtype,
        mime_type: Mime,
        raw_mime: &str,
        decoded_data: &[u8],
        filename: &str,
        is_related: bool,
    ) -> Result<()> {
        // Process attached PGP keys.
        if mime_type.type_() == mime::APPLICATION
            && mime_type.subtype().as_str() == "pgp-keys"
            && Self::try_set_peer_key_from_file_part(context, decoded_data).await?
        {
            return Ok(());
        }
        let mut part = Part::default();
        let msg_type = if context
            .is_webxdc_file(filename, decoded_data)
            .await
            .unwrap_or(false)
        {
            Viewtype::Webxdc
        } else if filename.ends_with(".kml") {
            // XXX what if somebody sends eg an "location-highlights.kml"
            // attachment unrelated to location streaming?
            if filename.starts_with("location") || filename.starts_with("message") {
                let parsed = location::Kml::parse(decoded_data)
                    .map_err(|err| {
                        warn!(context, "failed to parse kml part: {:#}", err);
                    })
                    .ok();
                if filename.starts_with("location") {
                    self.location_kml = parsed;
                } else {
                    self.message_kml = parsed;
                }
                return Ok(());
            }
            msg_type
        } else if filename == "multi-device-sync.json" {
            if !context.get_config_bool(Config::SyncMsgs).await? {
                return Ok(());
            }
            let serialized = String::from_utf8_lossy(decoded_data)
                .parse()
                .unwrap_or_default();
            self.sync_items = context
                .parse_sync_items(serialized)
                .map_err(|err| {
                    warn!(context, "failed to parse sync data: {:#}", err);
                })
                .ok();
            return Ok(());
        } else if filename == "status-update.json" {
            let serialized = String::from_utf8_lossy(decoded_data)
                .parse()
                .unwrap_or_default();
            self.webxdc_status_update = Some(serialized);
            return Ok(());
        } else if msg_type == Viewtype::Vcard {
            if let Some(summary) = get_vcard_summary(decoded_data) {
                part.param.set(Param::Summary1, summary);
                msg_type
            } else {
                Viewtype::File
            }
        } else if msg_type == Viewtype::Image
            || msg_type == Viewtype::Gif
            || msg_type == Viewtype::Sticker
        {
            match get_filemeta(decoded_data) {
                // image size is known, not too big, keep msg_type:
                Ok((width, height)) if width * height <= constants::MAX_RCVD_IMAGE_PIXELS => {
                    part.param.set_i64(Param::Width, width.into());
                    part.param.set_i64(Param::Height, height.into());
                    msg_type
                }
                // image is too big or size is unknown, display as file:
                _ => Viewtype::File,
            }
        } else {
            msg_type
        };

        /* we have a regular file attachment,
        write decoded data to new blob object */

        let blob =
            match BlobObject::create_and_deduplicate_from_bytes(context, decoded_data, filename) {
                Ok(blob) => blob,
                Err(err) => {
                    error!(
                        context,
                        "Could not add blob for mime part {}, error {:#}", filename, err
                    );
                    return Ok(());
                }
            };
        info!(context, "added blobfile: {:?}", blob.as_name());

        part.typ = msg_type;
        part.org_filename = Some(filename.to_string());
        part.mimetype = Some(mime_type);
        part.bytes = decoded_data.len();
        part.param.set(Param::File, blob.as_name());
        part.param.set(Param::Filename, filename);
        part.param.set(Param::MimeType, raw_mime);
        part.is_related = is_related;

        self.do_add_single_part(part);
        Ok(())
    }

    /// Returns whether a key from the attachment was saved.
    async fn try_set_peer_key_from_file_part(
        context: &Context,
        decoded_data: &[u8],
    ) -> Result<bool> {
        let key = match str::from_utf8(decoded_data) {
            Err(err) => {
                warn!(context, "PGP key attachment is not a UTF-8 file: {}", err);
                return Ok(false);
            }
            Ok(key) => key,
        };
        let key = match SignedPublicKey::from_asc(key) {
            Err(err) => {
                warn!(
                    context,
                    "PGP key attachment is not an ASCII-armored file: {err:#}."
                );
                return Ok(false);
            }
            Ok(key) => key,
        };
        if let Err(err) = key.verify_bindings() {
            warn!(context, "Attached PGP key verification failed: {err:#}.");
            return Ok(false);
        }

        let fingerprint = key.dc_fingerprint().hex();
        context
            .sql
            .execute(
                "INSERT INTO public_keys (fingerprint, public_key)
                 VALUES (?, ?)
                 ON CONFLICT (fingerprint)
                 DO NOTHING",
                (&fingerprint, key.to_bytes()),
            )
            .await?;

        info!(context, "Imported PGP key {fingerprint} from attachment.");
        Ok(true)
    }

    pub(crate) fn do_add_single_part(&mut self, mut part: Part) {
        if self.was_encrypted() {
            part.param.set_int(Param::GuaranteeE2ee, 1);
        }
        self.parts.push(part);
    }

    pub(crate) fn get_mailinglist_header(&self) -> Option<&str> {
        if let Some(list_id) = self.get_header(HeaderDef::ListId) {
            // The message belongs to a mailing list and has a `ListId:`-header
            // that should be used to get a unique id.
            return Some(list_id);
        } else if let Some(chat_list_id) = self.get_header(HeaderDef::ChatListId) {
            return Some(chat_list_id);
        } else if let Some(sender) = self.get_header(HeaderDef::Sender) {
            // the `Sender:`-header alone is no indicator for mailing list
            // as also used for bot-impersonation via `set_override_sender_name()`
            if let Some(precedence) = self.get_header(HeaderDef::Precedence)
                && (precedence == "list" || precedence == "bulk")
            {
                // The message belongs to a mailing list, but there is no `ListId:`-header;
                // `Sender:`-header is be used to get a unique id.
                // This method is used by implementations as Majordomo.
                return Some(sender);
            }
        }
        None
    }

    pub(crate) fn is_mailinglist_message(&self) -> bool {
        self.get_mailinglist_header().is_some()
    }

    /// Detects Schleuder mailing list by List-Help header.
    pub(crate) fn is_schleuder_message(&self) -> bool {
        if let Some(list_help) = self.get_header(HeaderDef::ListHelp) {
            list_help == "<https://schleuder.org/>"
        } else {
            false
        }
    }

    /// Check if a message is a call.
    pub(crate) fn is_call(&self) -> bool {
        self.parts
            .first()
            .is_some_and(|part| part.typ == Viewtype::Call)
    }

    pub(crate) fn get_rfc724_mid(&self) -> Option<String> {
        self.get_header(HeaderDef::MessageId)
            .and_then(|msgid| parse_message_id(msgid).ok())
    }

    fn remove_secured_headers(
        headers: &mut HashMap<String, String>,
        removed: &mut HashSet<String>,
    ) {
        remove_header(headers, "secure-join-fingerprint", removed);
        remove_header(headers, "secure-join-auth", removed);
        remove_header(headers, "chat-verified", removed);
        remove_header(headers, "autocrypt-gossip", removed);

        // Secure-Join is secured unless it is an initial "vc-request"/"vg-request".
        if let Some(secure_join) = remove_header(headers, "secure-join", removed)
            && (secure_join == "vc-request" || secure_join == "vg-request")
        {
            headers.insert("secure-join".to_string(), secure_join);
        }
    }

    /// Merges headers from the email `part` into `headers` respecting header protection.
    /// Should only be called with nonempty `headers` if `part` is a root of the Cryptographic
    /// Payload as defined in <https://www.rfc-editor.org/rfc/rfc9788.html> "Header Protection for
    /// Cryptographically Protected Email", otherwise this may unnecessarily discard headers from
    /// outer parts.
    #[allow(clippy::too_many_arguments)]
    fn merge_headers(
        context: &Context,
        headers: &mut HashMap<String, String>,
        headers_removed: &mut HashSet<String>,
        recipients: &mut Vec<SingleInfo>,
        past_members: &mut Vec<SingleInfo>,
        from: &mut Option<SingleInfo>,
        list_post: &mut Option<String>,
        chat_disposition_notification_to: &mut Option<SingleInfo>,
        part: &mailparse::ParsedMail,
    ) {
        let fields = &part.headers;
        // See <https://www.rfc-editor.org/rfc/rfc9788.html>.
        let has_header_protection = part.ctype.params.contains_key("hp");

        headers_removed.extend(
            headers
                .extract_if(|k, _v| has_header_protection || is_protected(k))
                .map(|(k, _v)| k.to_string()),
        );
        for field in fields {
            // lowercasing all headers is technically not correct, but makes things work better
            let key = field.get_key().to_lowercase();
            if key == HeaderDef::ChatDispositionNotificationTo.get_headername() {
                match addrparse_header(field) {
                    Ok(addrlist) => {
                        *chat_disposition_notification_to = addrlist.extract_single_info();
                    }
                    Err(e) => warn!(context, "Could not read {} address: {}", key, e),
                }
            } else {
                let value = field.get_value();
                headers.insert(key.to_string(), value);
            }
        }
        let recipients_new = get_recipients(fields);
        if !recipients_new.is_empty() {
            *recipients = recipients_new;
        }
        let past_members_addresses =
            get_all_addresses_from_header(fields, "chat-group-past-members");
        if !past_members_addresses.is_empty() {
            *past_members = past_members_addresses;
        }
        let from_new = get_from(fields);
        if from_new.is_some() {
            *from = from_new;
        }
        let list_post_new = get_list_post(fields);
        if list_post_new.is_some() {
            *list_post = list_post_new;
        }
    }

    fn process_report(
        &self,
        context: &Context,
        report: &mailparse::ParsedMail<'_>,
    ) -> Result<Option<Report>> {
        // parse as mailheaders
        let report_body = if let Some(subpart) = report.subparts.get(1) {
            subpart.get_body_raw()?
        } else {
            bail!("Report does not have second MIME part");
        };
        let (report_fields, _) = mailparse::parse_headers(&report_body)?;

        // must be present
        if report_fields
            .get_header_value(HeaderDef::Disposition)
            .is_none()
        {
            warn!(
                context,
                "Ignoring unknown disposition-notification, Message-Id: {:?}.",
                report_fields.get_header_value(HeaderDef::MessageId)
            );
            return Ok(None);
        };

        let original_message_id = report_fields
            .get_header_value(HeaderDef::OriginalMessageId)
            // MS Exchange doesn't add an Original-Message-Id header. Instead, they put
            // the original message id into the In-Reply-To header:
            .or_else(|| report.headers.get_header_value(HeaderDef::InReplyTo))
            .and_then(|v| parse_message_id(&v).ok());
        let additional_message_ids = report_fields
            .get_header_value(HeaderDef::AdditionalMessageIds)
            .map_or_else(Vec::new, |v| {
                v.split(' ')
                    .filter_map(|s| parse_message_id(s).ok())
                    .collect()
            });

        Ok(Some(Report {
            original_message_id,
            additional_message_ids,
        }))
    }

    fn process_delivery_status(
        &self,
        context: &Context,
        report: &mailparse::ParsedMail<'_>,
    ) -> Result<Option<DeliveryReport>> {
        // Assume failure.
        let mut failure = true;

        if let Some(status_part) = report.subparts.get(1) {
            // RFC 3464 defines `message/delivery-status`
            // RFC 6533 defines `message/global-delivery-status`
            if status_part.ctype.mimetype != "message/delivery-status"
                && status_part.ctype.mimetype != "message/global-delivery-status"
            {
                warn!(
                    context,
                    "Second part of Delivery Status Notification is not message/delivery-status or message/global-delivery-status, ignoring"
                );
                return Ok(None);
            }

            let status_body = status_part.get_body_raw()?;

            // Skip per-message fields.
            let (_, sz) = mailparse::parse_headers(&status_body)?;

            // Parse first set of per-recipient fields
            if let Some(status_body) = status_body.get(sz..) {
                let (status_fields, _) = mailparse::parse_headers(status_body)?;
                if let Some(action) = status_fields.get_first_value("action") {
                    if action != "failed" {
                        info!(context, "DSN with {:?} action", action);
                        failure = false;
                    }
                } else {
                    warn!(context, "DSN without action");
                }
            } else {
                warn!(context, "DSN without per-recipient fields");
            }
        } else {
            // No message/delivery-status part.
            return Ok(None);
        }

        // parse as mailheaders
        if let Some(original_msg) = report.subparts.get(2).filter(|p| {
            p.ctype.mimetype.contains("rfc822")
                || p.ctype.mimetype == "message/global"
                || p.ctype.mimetype == "message/global-headers"
        }) {
            let report_body = original_msg.get_body_raw()?;
            let (report_fields, _) = mailparse::parse_headers(&report_body)?;

            if let Some(original_message_id) = report_fields
                .get_header_value(HeaderDef::MessageId)
                .and_then(|v| parse_message_id(&v).ok())
            {
                return Ok(Some(DeliveryReport {
                    rfc724_mid: original_message_id,
                    failure,
                }));
            }

            warn!(
                context,
                "ignoring unknown ndn-notification, Message-Id: {:?}",
                report_fields.get_header_value(HeaderDef::MessageId)
            );
        }

        Ok(None)
    }

    fn maybe_remove_bad_parts(&mut self) {
        let good_parts = self.parts.iter().filter(|p| !p.dehtml_failed).count();
        if good_parts == 0 {
            // We have no good part but show at least one bad part in order to show anything at all
            self.parts.truncate(1);
        } else if good_parts < self.parts.len() {
            self.parts.retain(|p| !p.dehtml_failed);
        }

        // remove images that are descendants of multipart/related but the first one:
        // - for newsletters or so, that is often the logo
        // - for user-generated html-mails, that may be some drag'n'drop photo,
        //   so, the recipient sees at least the first image directly
        // - all other images can be accessed by "show full message"
        // - to ensure, there is such a button, we do removal only if
        //   `is_mime_modified` is set
        if !self.has_chat_version() && self.is_mime_modified {
            fn is_related_image(p: &&Part) -> bool {
                (p.typ == Viewtype::Image || p.typ == Viewtype::Gif) && p.is_related
            }
            let related_image_cnt = self.parts.iter().filter(is_related_image).count();
            if related_image_cnt > 1 {
                let mut is_first_image = true;
                self.parts.retain(|p| {
                    let retain = is_first_image || !is_related_image(&p);
                    if p.typ == Viewtype::Image || p.typ == Viewtype::Gif {
                        is_first_image = false;
                    }
                    retain
                });
            }
        }
    }

    /// Remove unwanted, additional text parts used for mailing list footer.
    /// Some mailinglist software add footers as separate mimeparts
    /// eg. when the user-edited-content is html.
    /// As these footers would appear as repeated, separate text-bubbles,
    /// we remove them.
    ///
    /// We make an exception for Schleuder mailing lists
    /// because they typically create messages with two text parts,
    /// one for headers and one for the actual contents.
    fn maybe_remove_inline_mailinglist_footer(&mut self) {
        if self.is_mailinglist_message() && !self.is_schleuder_message() {
            let text_part_cnt = self
                .parts
                .iter()
                .filter(|p| p.typ == Viewtype::Text)
                .count();
            if text_part_cnt == 2
                && let Some(last_part) = self.parts.last()
                && last_part.typ == Viewtype::Text
            {
                self.parts.pop();
            }
        }
    }

    /// Some providers like GMX and Yahoo do not send standard NDNs (Non Delivery notifications).
    /// If you improve heuristics here you might also have to change prefetch_should_download() in imap/mod.rs.
    /// Also you should add a test in receive_imf.rs (there already are lots of test_parse_ndn_* tests).
    async fn heuristically_parse_ndn(&mut self, context: &Context) {
        let maybe_ndn = if let Some(from) = self.get_header(HeaderDef::From_) {
            let from = from.to_ascii_lowercase();
            from.contains("mailer-daemon") || from.contains("mail-daemon")
        } else {
            false
        };
        if maybe_ndn && self.delivery_report.is_none() {
            for original_message_id in self
                .parts
                .iter()
                .filter_map(|part| part.msg_raw.as_ref())
                .flat_map(|part| part.lines())
                .filter_map(|line| line.split_once("Message-ID:"))
                .filter_map(|(_, message_id)| parse_message_id(message_id).ok())
            {
                if let Ok(Some(_)) = message::rfc724_mid_exists(context, &original_message_id).await
                {
                    self.delivery_report = Some(DeliveryReport {
                        rfc724_mid: original_message_id,
                        failure: true,
                    })
                }
            }
        }
    }

    /// Handle reports
    /// (MDNs = Message Disposition Notification, the message was read
    /// and NDNs = Non delivery notification, the message could not be delivered)
    pub async fn handle_reports(&self, context: &Context, from_id: ContactId, parts: &[Part]) {
        for report in &self.mdn_reports {
            for original_message_id in report
                .original_message_id
                .iter()
                .chain(&report.additional_message_ids)
            {
                if let Err(err) =
                    handle_mdn(context, from_id, original_message_id, self.timestamp_sent).await
                {
                    warn!(context, "Could not handle MDN: {err:#}.");
                }
            }
        }

        if let Some(delivery_report) = &self.delivery_report
            && delivery_report.failure
        {
            let error = parts
                .iter()
                .find(|p| p.typ == Viewtype::Text)
                .map(|p| p.msg.clone());
            if let Err(err) = handle_ndn(context, delivery_report, error).await {
                warn!(context, "Could not handle NDN: {err:#}.");
            }
        }
    }

    /// Returns timestamp of the parent message.
    ///
    /// If there is no parent message or it is not found in the
    /// database, returns None.
    pub async fn get_parent_timestamp(&self, context: &Context) -> Result<Option<i64>> {
        let parent_timestamp = if let Some(field) = self
            .get_header(HeaderDef::InReplyTo)
            .and_then(|msgid| parse_message_id(msgid).ok())
        {
            context
                .sql
                .query_get_value("SELECT timestamp FROM msgs WHERE rfc724_mid=?", (field,))
                .await?
        } else {
            None
        };
        Ok(parent_timestamp)
    }

    /// Returns parsed `Chat-Group-Member-Timestamps` header contents.
    ///
    /// Returns `None` if there is no such header.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn chat_group_member_timestamps(&self) -> Option<Vec<i64>> {
        let now = time() + constants::TIMESTAMP_SENT_TOLERANCE;
        self.get_header(HeaderDef::ChatGroupMemberTimestamps)
            .map(|h| {
                h.split_ascii_whitespace()
                    .filter_map(|ts| ts.parse::<i64>().ok())
                    .map(|ts| std::cmp::min(now, ts))
                    .collect()
            })
    }

    /// Returns list of fingerprints from
    /// `Chat-Group-Member-Fpr` header.
    pub fn chat_group_member_fingerprints(&self) -> Vec<Fingerprint> {
        if let Some(header) = self.get_header(HeaderDef::ChatGroupMemberFpr) {
            header
                .split_ascii_whitespace()
                .filter_map(|fpr| Fingerprint::from_str(fpr).ok())
                .collect()
        } else {
            Vec::new()
        }
    }
}

fn rm_legacy_display_elements(text: &str) -> String {
    let mut res = None;
    for l in text.lines() {
        res = res.map(|r: String| match r.is_empty() {
            true => l.to_string(),
            false => r + "\r\n" + l,
        });
        if l.is_empty() {
            res = Some(String::new());
        }
    }
    res.unwrap_or_default()
}

fn remove_header(
    headers: &mut HashMap<String, String>,
    key: &str,
    removed: &mut HashSet<String>,
) -> Option<String> {
    if let Some((k, v)) = headers.remove_entry(key) {
        removed.insert(k);
        Some(v)
    } else {
        None
    }
}

/// Parses `Autocrypt-Gossip` headers from the email,
/// saves the keys into the `public_keys` table,
/// and returns them in a HashMap<address, public key>.
///
/// * `from`: The address which sent the message currently being parsed
async fn parse_gossip_headers(
    context: &Context,
    from: &str,
    recipients: &[SingleInfo],
    gossip_headers: Vec<String>,
) -> Result<BTreeMap<String, GossipedKey>> {
    // XXX split the parsing from the modification part
    let mut gossiped_keys: BTreeMap<String, GossipedKey> = Default::default();

    for value in &gossip_headers {
        let header = match value.parse::<Aheader>() {
            Ok(header) => header,
            Err(err) => {
                warn!(context, "Failed parsing Autocrypt-Gossip header: {}", err);
                continue;
            }
        };

        if !recipients
            .iter()
            .any(|info| addr_cmp(&info.addr, &header.addr))
        {
            warn!(
                context,
                "Ignoring gossiped \"{}\" as the address is not in To/Cc list.", &header.addr,
            );
            continue;
        }
        if addr_cmp(from, &header.addr) {
            // Non-standard, might not be necessary to have this check here
            warn!(
                context,
                "Ignoring gossiped \"{}\" as it equals the From address", &header.addr,
            );
            continue;
        }

        let fingerprint = header.public_key.dc_fingerprint().hex();
        context
            .sql
            .execute(
                "INSERT INTO public_keys (fingerprint, public_key)
                             VALUES (?, ?)
                             ON CONFLICT (fingerprint)
                             DO NOTHING",
                (&fingerprint, header.public_key.to_bytes()),
            )
            .await?;

        let gossiped_key = GossipedKey {
            public_key: header.public_key,

            verified: header.verified,
        };
        gossiped_keys.insert(header.addr.to_lowercase(), gossiped_key);
    }

    Ok(gossiped_keys)
}

/// Message Disposition Notification (RFC 8098)
#[derive(Debug)]
pub(crate) struct Report {
    /// Original-Message-ID header
    ///
    /// It MUST be present if the original message has a Message-ID according to RFC 8098.
    /// In case we can't find it (shouldn't happen), this is None.
    pub original_message_id: Option<String>,
    /// Additional-Message-IDs
    pub additional_message_ids: Vec<String>,
}

/// Delivery Status Notification (RFC 3464, RFC 6533)
#[derive(Debug)]
pub(crate) struct DeliveryReport {
    pub rfc724_mid: String,
    pub failure: bool,
}

pub(crate) fn parse_message_ids(ids: &str) -> Vec<String> {
    // take care with mailparse::msgidparse() that is pretty untolerant eg. wrt missing `<` or `>`
    let mut msgids = Vec::new();
    for id in ids.split_whitespace() {
        let mut id = id.to_string();
        if let Some(id_without_prefix) = id.strip_prefix('<') {
            id = id_without_prefix.to_string();
        };
        if let Some(id_without_suffix) = id.strip_suffix('>') {
            id = id_without_suffix.to_string();
        };
        if !id.is_empty() {
            msgids.push(id);
        }
    }
    msgids
}

pub(crate) fn parse_message_id(ids: &str) -> Result<String> {
    if let Some(id) = parse_message_ids(ids).first() {
        Ok(id.to_string())
    } else {
        bail!("could not parse message_id: {ids}");
    }
}

/// Returns whether the outer header value must be ignored if the message contains a signed (and
/// optionally encrypted) part. This is independent from the modern Header Protection defined in
/// <https://www.rfc-editor.org/rfc/rfc9788.html>.
///
/// NB: There are known cases when Subject and List-ID only appear in the outer headers of
/// signed-only messages. Such messages are shown as unencrypted anyway.
fn is_protected(key: &str) -> bool {
    key.starts_with("chat-")
        || matches!(
            key,
            "return-path"
                | "auto-submitted"
                | "autocrypt-setup-message"
                | "date"
                | "from"
                | "sender"
                | "reply-to"
                | "to"
                | "cc"
                | "bcc"
                | "message-id"
                | "in-reply-to"
                | "references"
                | "secure-join"
        )
}

/// Returns if the header is hidden and must be ignored in the IMF section.
pub(crate) fn is_hidden(key: &str) -> bool {
    matches!(
        key,
        "chat-user-avatar" | "chat-group-avatar" | "chat-delete" | "chat-edit"
    )
}

/// Parsed MIME part.
#[derive(Debug, Default, Clone)]
pub struct Part {
    /// Type of the MIME part determining how it should be displayed.
    pub typ: Viewtype,

    /// MIME type.
    pub mimetype: Option<Mime>,

    /// Message text to be displayed in the chat.
    pub msg: String,

    /// Message text to be displayed in message info.
    pub msg_raw: Option<String>,

    /// Size of the MIME part in bytes.
    pub bytes: usize,

    /// Parameters.
    pub param: Params,

    /// Attachment filename.
    pub(crate) org_filename: Option<String>,

    /// An error detected during parsing.
    pub error: Option<String>,

    /// True if conversion from HTML to plaintext failed.
    pub(crate) dehtml_failed: bool,

    /// the part is a child or a descendant of multipart/related.
    /// typically, these are images that are referenced from text/html part
    /// and should not displayed inside chat.
    ///
    /// note that multipart/related may contain further multipart nestings
    /// and all of them needs to be marked with `is_related`.
    pub(crate) is_related: bool,

    /// Part is an RFC 9078 reaction.
    pub(crate) is_reaction: bool,
}

/// Returns the mimetype and viewtype for a parsed mail.
///
/// This only looks at the metadata, not at the content;
/// the viewtype may later be corrected in `do_add_single_file_part()`.
fn get_mime_type(
    mail: &mailparse::ParsedMail<'_>,
    filename: &Option<String>,
    is_chat_msg: bool,
) -> Result<(Mime, Viewtype)> {
    let mimetype = mail.ctype.mimetype.parse::<Mime>()?;

    let viewtype = match mimetype.type_() {
        mime::TEXT => match mimetype.subtype() {
            mime::VCARD => Viewtype::Vcard,
            mime::PLAIN | mime::HTML if !is_attachment_disposition(mail) => Viewtype::Text,
            _ => Viewtype::File,
        },
        mime::IMAGE => match mimetype.subtype() {
            mime::GIF => Viewtype::Gif,
            mime::SVG => Viewtype::File,
            _ => Viewtype::Image,
        },
        mime::AUDIO => Viewtype::Audio,
        mime::VIDEO => Viewtype::Video,
        mime::MULTIPART => Viewtype::Unknown,
        mime::MESSAGE => {
            if is_attachment_disposition(mail) {
                Viewtype::File
            } else {
                // Enacapsulated messages, see <https://www.w3.org/Protocols/rfc1341/7_3_Message.html>
                // Also used as part "message/disposition-notification" of "multipart/report", which, however, will
                // be handled separately.
                // I've not seen any messages using this, so we do not attach these parts (maybe they're used to attach replies,
                // which are unwanted at all).
                // For now, we skip these parts at all; if desired, we could return DcMimeType::File/DC_MSG_File
                // for selected and known subparts.
                Viewtype::Unknown
            }
        }
        mime::APPLICATION => match mimetype.subtype() {
            mime::OCTET_STREAM => match filename {
                Some(filename) if !is_chat_msg => {
                    match message::guess_msgtype_from_path_suffix(Path::new(&filename)) {
                        Some((viewtype, _)) => viewtype,
                        None => Viewtype::File,
                    }
                }
                _ => Viewtype::File,
            },
            _ => Viewtype::File,
        },
        _ => Viewtype::Unknown,
    };

    Ok((mimetype, viewtype))
}

fn is_attachment_disposition(mail: &mailparse::ParsedMail<'_>) -> bool {
    let ct = mail.get_content_disposition();
    ct.disposition == DispositionType::Attachment
        && ct
            .params
            .iter()
            .any(|(key, _value)| key.starts_with("filename"))
}

/// Tries to get attachment filename.
///
/// If filename is explicitly specified in Content-Disposition, it is
/// returned. If Content-Disposition is "attachment" but filename is
/// not specified, filename is guessed. If Content-Disposition cannot
/// be parsed, returns an error.
fn get_attachment_filename(
    context: &Context,
    mail: &mailparse::ParsedMail,
) -> Result<Option<String>> {
    let ct = mail.get_content_disposition();

    // try to get file name as "encoded-words" from
    // `Content-Disposition: ... filename=...`
    let mut desired_filename = ct.params.get("filename").map(|s| s.to_string());

    if desired_filename.is_none()
        && let Some(name) = ct.params.get("filename*").map(|s| s.to_string())
    {
        // be graceful and just use the original name.
        // some MUA, including Delta Chat up to core1.50,
        // use `filename*` mistakenly for simple encoded-words without following rfc2231
        warn!(context, "apostrophed encoding invalid: {}", name);
        desired_filename = Some(name);
    }

    // if no filename is set, try `Content-Disposition: ... name=...`
    if desired_filename.is_none() {
        desired_filename = ct.params.get("name").map(|s| s.to_string());
    }

    // MS Outlook is known to specify filename in the "name" attribute of
    // Content-Type and omit Content-Disposition.
    if desired_filename.is_none() {
        desired_filename = mail.ctype.params.get("name").map(|s| s.to_string());
    }

    // If there is no filename, but part is an attachment, guess filename
    if desired_filename.is_none() && ct.disposition == DispositionType::Attachment {
        if let Some(subtype) = mail.ctype.mimetype.split('/').nth(1) {
            desired_filename = Some(format!("file.{subtype}",));
        } else {
            bail!(
                "could not determine attachment filename: {:?}",
                ct.disposition
            );
        };
    }

    let desired_filename = desired_filename.map(|filename| sanitize_bidi_characters(&filename));

    Ok(desired_filename)
}

/// Returned addresses are normalized and lowercased.
pub(crate) fn get_recipients(headers: &[MailHeader]) -> Vec<SingleInfo> {
    let to_addresses = get_all_addresses_from_header(headers, "to");
    let cc_addresses = get_all_addresses_from_header(headers, "cc");

    let mut res = to_addresses;
    res.extend(cc_addresses);
    res
}

/// Returned addresses are normalized and lowercased.
pub(crate) fn get_from(headers: &[MailHeader]) -> Option<SingleInfo> {
    let all = get_all_addresses_from_header(headers, "from");
    tools::single_value(all)
}

/// Returned addresses are normalized and lowercased.
pub(crate) fn get_list_post(headers: &[MailHeader]) -> Option<String> {
    get_all_addresses_from_header(headers, "list-post")
        .into_iter()
        .next()
        .map(|s| s.addr)
}

/// Extracts all addresses from the header named `header`.
///
/// If multiple headers with the same name are present,
/// the last one is taken.
/// This is because DKIM-Signatures apply to the last
/// headers, and more headers may be added
/// to the beginning of the messages
/// without invalidating the signature
/// unless the header is "oversigned",
/// i.e. included in the signature more times
/// than it appears in the mail.
fn get_all_addresses_from_header(headers: &[MailHeader], header: &str) -> Vec<SingleInfo> {
    let mut result: Vec<SingleInfo> = Default::default();

    if let Some(header) = headers
        .iter()
        .rev()
        .find(|h| h.get_key().to_lowercase() == header)
        && let Ok(addrs) = mailparse::addrparse_header(header)
    {
        for addr in addrs.iter() {
            match addr {
                mailparse::MailAddr::Single(info) => {
                    result.push(SingleInfo {
                        addr: addr_normalize(&info.addr).to_lowercase(),
                        display_name: info.display_name.clone(),
                    });
                }
                mailparse::MailAddr::Group(infos) => {
                    for info in &infos.addrs {
                        result.push(SingleInfo {
                            addr: addr_normalize(&info.addr).to_lowercase(),
                            display_name: info.display_name.clone(),
                        });
                    }
                }
            }
        }
    }

    result
}

async fn handle_mdn(
    context: &Context,
    from_id: ContactId,
    rfc724_mid: &str,
    timestamp_sent: i64,
) -> Result<()> {
    if from_id == ContactId::SELF {
        // MDNs to self are handled in receive_imf_inner().
        return Ok(());
    }

    let Some((msg_id, chat_id, has_mdns, is_dup)) = context
        .sql
        .query_row_optional(
            "SELECT
                m.id AS msg_id,
                c.id AS chat_id,
                mdns.contact_id AS mdn_contact
             FROM msgs m 
             LEFT JOIN chats c ON m.chat_id=c.id
             LEFT JOIN msgs_mdns mdns ON mdns.msg_id=m.id
             WHERE rfc724_mid=? AND from_id=1
             ORDER BY msg_id DESC, mdn_contact=? DESC
             LIMIT 1",
            (&rfc724_mid, from_id),
            |row| {
                let msg_id: MsgId = row.get("msg_id")?;
                let chat_id: ChatId = row.get("chat_id")?;
                let mdn_contact: Option<ContactId> = row.get("mdn_contact")?;
                Ok((
                    msg_id,
                    chat_id,
                    mdn_contact.is_some(),
                    mdn_contact == Some(from_id),
                ))
            },
        )
        .await?
    else {
        info!(
            context,
            "Ignoring MDN, found no message with Message-ID {rfc724_mid:?} sent by us in the database.",
        );
        return Ok(());
    };

    if is_dup {
        return Ok(());
    }
    context
        .sql
        .execute(
            "INSERT INTO msgs_mdns (msg_id, contact_id, timestamp_sent) VALUES (?, ?, ?)",
            (msg_id, from_id, timestamp_sent),
        )
        .await?;
    if !has_mdns {
        context.emit_event(EventType::MsgRead { chat_id, msg_id });
        // note(treefit): only matters if it is the last message in chat (but probably too expensive to check, debounce also solves it)
        chatlist_events::emit_chatlist_item_changed(context, chat_id);
    }
    Ok(())
}

/// Marks a message as failed after an ndn (non-delivery-notification) arrived.
/// Where appropriate, also adds an info message telling the user which of the recipients of a group message failed.
async fn handle_ndn(
    context: &Context,
    failed: &DeliveryReport,
    error: Option<String>,
) -> Result<()> {
    if failed.rfc724_mid.is_empty() {
        return Ok(());
    }

    // The NDN might be for a message-id that had attachments and was sent from a non-Delta Chat client.
    // In this case we need to mark multiple "msgids" as failed that all refer to the same message-id.
    let msg_ids = context
        .sql
        .query_map_vec(
            "SELECT id FROM msgs
                WHERE rfc724_mid=? AND from_id=1",
            (&failed.rfc724_mid,),
            |row| {
                let msg_id: MsgId = row.get(0)?;
                Ok(msg_id)
            },
        )
        .await?;

    let error = if let Some(error) = error {
        error
    } else {
        "Delivery to at least one recipient failed.".to_string()
    };
    let err_msg = &error;

    for msg_id in msg_ids {
        let mut message = Message::load_from_db(context, msg_id).await?;
        let aggregated_error = message
            .error
            .as_ref()
            .map(|err| format!("{err}\n\n{err_msg}"));
        set_msg_failed(
            context,
            &mut message,
            aggregated_error.as_ref().unwrap_or(err_msg),
        )
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod mimeparser_tests;
