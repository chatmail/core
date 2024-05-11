//! # QR code module.

mod dclogin_scheme;
use std::collections::BTreeMap;

use anyhow::{anyhow, bail, ensure, Context as _, Result};
pub use dclogin_scheme::LoginOptions;
use deltachat_contact_tools::{addr_normalize, may_be_valid_addr, ContactAddress};
use once_cell::sync::Lazy;
use percent_encoding::percent_decode_str;
use serde::Deserialize;

use self::dclogin_scheme::configure_from_login_qr;
use crate::chat::{get_chat_id_by_grpid, ChatIdBlocked};
use crate::config::Config;
use crate::constants::Blocked;
use crate::contact::{Contact, ContactId, Origin};
use crate::context::Context;
use crate::events::EventType;
use crate::key::Fingerprint;
use crate::message::Message;
use crate::peerstate::Peerstate;
use crate::socks::Socks5Config;
use crate::token;
use crate::tools::validate_id;
use iroh_old as iroh;

const OPENPGP4FPR_SCHEME: &str = "OPENPGP4FPR:"; // yes: uppercase
const IDELTACHAT_SCHEME: &str = "https://i.delta.chat/#";
const IDELTACHAT_NOSLASH_SCHEME: &str = "https://i.delta.chat#";
const DCACCOUNT_SCHEME: &str = "DCACCOUNT:";
pub(super) const DCLOGIN_SCHEME: &str = "DCLOGIN:";
const DCWEBRTC_SCHEME: &str = "DCWEBRTC:";
const MAILTO_SCHEME: &str = "mailto:";
const MATMSG_SCHEME: &str = "MATMSG:";
const VCARD_SCHEME: &str = "BEGIN:VCARD";
const SMTP_SCHEME: &str = "SMTP:";
const HTTP_SCHEME: &str = "http://";
const HTTPS_SCHEME: &str = "https://";
pub(crate) const DCBACKUP_SCHEME: &str = "DCBACKUP:";

/// Scanned QR code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Qr {
    /// Ask the user whether to verify the contact.
    ///
    /// If the user agrees, pass this QR code to [`crate::securejoin::join_securejoin`].
    AskVerifyContact {
        /// ID of the contact.
        contact_id: ContactId,

        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: Fingerprint,

        /// Invite number.
        invitenumber: String,

        /// Authentication code.
        authcode: String,
    },

    /// Ask the user whether to join the group.
    AskVerifyGroup {
        /// Group name.
        grpname: String,

        /// Group ID.
        grpid: String,

        /// ID of the contact.
        contact_id: ContactId,

        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: Fingerprint,

        /// Invite number.
        invitenumber: String,

        /// Authentication code.
        authcode: String,
    },

    /// Contact fingerprint is verified.
    ///
    /// Ask the user if they want to start chatting.
    FprOk {
        /// Contact ID.
        contact_id: ContactId,
    },

    /// Scanned fingerprint does not match the last seen fingerprint.
    FprMismatch {
        /// Contact ID.
        contact_id: Option<ContactId>,
    },

    /// The scanned QR code contains a fingerprint but no e-mail address.
    FprWithoutAddr {
        /// Key fingerprint.
        fingerprint: String,
    },

    /// Ask the user if they want to create an account on the given domain.
    Account {
        /// Server domain name.
        domain: String,
    },

    /// Provides a backup that can be retrieve.
    ///
    /// This contains all the data needed to connect to a device and download a backup from
    /// it to configure the receiving device with the same account.
    Backup {
        /// Printable version of the provider information.
        ///
        /// This is the printable version of a `sendme` ticket, which contains all the
        /// information to connect to and authenticate a backup provider.
        ///
        /// The format is somewhat opaque, but `sendme` can deserialise this.
        ticket: iroh::provider::Ticket,
    },

    /// Ask the user if they want to use the given service for video chats.
    WebrtcInstance {
        /// Server domain name.
        domain: String,

        /// URL pattern for video chat rooms.
        instance_pattern: String,
    },

    /// Contact address is scanned.
    ///
    /// Optionally, a draft message could be provided.
    /// Ask the user if they want to start chatting.
    Addr {
        /// Contact ID.
        contact_id: ContactId,

        /// Draft message.
        draft: Option<String>,
    },

    /// URL scanned.
    ///
    /// Ask the user if they want to open a browser or copy the URL to clipboard.
    Url {
        /// URL.
        url: String,
    },

    /// Text scanned.
    ///
    /// Ask the user if they want to copy the text to clipboard.
    Text {
        /// Scanned text.
        text: String,
    },

    /// Ask the user if they want to withdraw their own QR code.
    WithdrawVerifyContact {
        /// Contact ID.
        contact_id: ContactId,

        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: Fingerprint,

        /// Invite number.
        invitenumber: String,

        /// Authentication code.
        authcode: String,
    },

    /// Ask the user if they want to withdraw their own group invite QR code.
    WithdrawVerifyGroup {
        /// Group name.
        grpname: String,

        /// Group ID.
        grpid: String,

        /// Contact ID.
        contact_id: ContactId,

        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: Fingerprint,

        /// Invite number.
        invitenumber: String,

        /// Authentication code.
        authcode: String,
    },

    /// Ask the user if they want to revive their own QR code.
    ReviveVerifyContact {
        /// Contact ID.
        contact_id: ContactId,

        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: Fingerprint,

        /// Invite number.
        invitenumber: String,

        /// Authentication code.
        authcode: String,
    },

    /// Ask the user if they want to revive their own group invite QR code.
    ReviveVerifyGroup {
        /// Group name.
        grpname: String,

        /// Group ID.
        grpid: String,

        /// Contact ID.
        contact_id: ContactId,

        /// Fingerprint of the contact key as scanned from the QR code.
        fingerprint: Fingerprint,

        /// Invite number.
        invitenumber: String,

        /// Authentication code.
        authcode: String,
    },

    /// `dclogin:` scheme parameters.
    ///
    /// Ask the user if they want to login with the email address.
    Login {
        /// Email address.
        address: String,

        /// Login parameters.
        options: LoginOptions,
    },
}

fn starts_with_ignore_case(string: &str, pattern: &str) -> bool {
    string.to_lowercase().starts_with(&pattern.to_lowercase())
}

/// Checks a scanned QR code.
///
/// The function should be called after a QR code is scanned.
/// The function takes the raw text scanned and checks what can be done with it.
pub async fn check_qr(context: &Context, qr: &str) -> Result<Qr> {
    let qrcode = if starts_with_ignore_case(qr, OPENPGP4FPR_SCHEME) {
        decode_openpgp(context, qr)
            .await
            .context("failed to decode OPENPGP4FPR QR code")?
    } else if qr.starts_with(IDELTACHAT_SCHEME) {
        decode_ideltachat(context, IDELTACHAT_SCHEME, qr).await?
    } else if qr.starts_with(IDELTACHAT_NOSLASH_SCHEME) {
        decode_ideltachat(context, IDELTACHAT_NOSLASH_SCHEME, qr).await?
    } else if starts_with_ignore_case(qr, DCACCOUNT_SCHEME) {
        decode_account(qr)?
    } else if starts_with_ignore_case(qr, DCLOGIN_SCHEME) {
        dclogin_scheme::decode_login(qr)?
    } else if starts_with_ignore_case(qr, DCWEBRTC_SCHEME) {
        decode_webrtc_instance(context, qr)?
    } else if starts_with_ignore_case(qr, DCBACKUP_SCHEME) {
        decode_backup(qr)?
    } else if qr.starts_with(MAILTO_SCHEME) {
        decode_mailto(context, qr).await?
    } else if qr.starts_with(SMTP_SCHEME) {
        decode_smtp(context, qr).await?
    } else if qr.starts_with(MATMSG_SCHEME) {
        decode_matmsg(context, qr).await?
    } else if qr.starts_with(VCARD_SCHEME) {
        decode_vcard(context, qr).await?
    } else if qr.starts_with(HTTP_SCHEME) || qr.starts_with(HTTPS_SCHEME) {
        Qr::Url {
            url: qr.to_string(),
        }
    } else {
        Qr::Text {
            text: qr.to_string(),
        }
    };
    Ok(qrcode)
}

/// Formats the text of the [`Qr::Backup`] variant.
///
/// This is the inverse of [`check_qr`] for that variant only.
///
/// TODO: Refactor this so all variants have a correct [`Display`] and transform `check_qr`
/// into `FromStr`.
pub fn format_backup(qr: &Qr) -> Result<String> {
    match qr {
        Qr::Backup { ref ticket } => Ok(format!("{DCBACKUP_SCHEME}{ticket}")),
        _ => Err(anyhow!("Not a backup QR code")),
    }
}

/// scheme: `OPENPGP4FPR:FINGERPRINT#a=ADDR&n=NAME&i=INVITENUMBER&s=AUTH`
///     or: `OPENPGP4FPR:FINGERPRINT#a=ADDR&g=GROUPNAME&x=GROUPID&i=INVITENUMBER&s=AUTH`
///     or: `OPENPGP4FPR:FINGERPRINT#a=ADDR`
#[allow(clippy::indexing_slicing)]
async fn decode_openpgp(context: &Context, qr: &str) -> Result<Qr> {
    let payload = &qr[OPENPGP4FPR_SCHEME.len()..];

    // macOS and iOS sometimes replace the # with %23 (uri encode it), we should be able to parse this wrong format too.
    // see issue https://github.com/deltachat/deltachat-core-rust/issues/1969 for more info
    let (fingerprint, fragment) = match payload
        .split_once('#')
        .or_else(|| payload.split_once("%23"))
    {
        Some(pair) => pair,
        None => (payload, ""),
    };
    let fingerprint: Fingerprint = fingerprint
        .parse()
        .context("Failed to parse fingerprint in the QR code")?;

    let param: BTreeMap<&str, &str> = fragment
        .split('&')
        .filter_map(|s| {
            if let [key, value] = s.splitn(2, '=').collect::<Vec<_>>()[..] {
                Some((key, value))
            } else {
                None
            }
        })
        .collect();

    let addr = if let Some(addr) = param.get("a") {
        Some(normalize_address(addr)?)
    } else {
        None
    };

    let name = if let Some(encoded_name) = param.get("n") {
        let encoded_name = encoded_name.replace('+', "%20"); // sometimes spaces are encoded as `+`
        match percent_decode_str(&encoded_name).decode_utf8() {
            Ok(name) => name.to_string(),
            Err(err) => bail!("Invalid name: {}", err),
        }
    } else {
        "".to_string()
    };

    let invitenumber = param
        .get("i")
        .filter(|&s| validate_id(s))
        .map(|s| s.to_string());
    let authcode = param
        .get("s")
        .filter(|&s| validate_id(s))
        .map(|s| s.to_string());
    let grpid = param
        .get("x")
        .filter(|&s| validate_id(s))
        .map(|s| s.to_string());

    let grpname = if grpid.is_some() {
        if let Some(encoded_name) = param.get("g") {
            let encoded_name = encoded_name.replace('+', "%20"); // sometimes spaces are encoded as `+`
            match percent_decode_str(&encoded_name).decode_utf8() {
                Ok(name) => Some(name.to_string()),
                Err(err) => bail!("Invalid group name: {}", err),
            }
        } else {
            None
        }
    } else {
        None
    };

    // retrieve known state for this fingerprint
    let peerstate = Peerstate::from_fingerprint(context, &fingerprint)
        .await
        .context("Can't load peerstate")?;

    if let (Some(addr), Some(invitenumber), Some(authcode)) = (&addr, invitenumber, authcode) {
        let addr = ContactAddress::new(addr)?;
        let (contact_id, _) =
            Contact::add_or_lookup(context, &name, &addr, Origin::UnhandledQrScan)
                .await
                .with_context(|| format!("failed to add or lookup contact for address {addr:?}"))?;

        if let (Some(grpid), Some(grpname)) = (grpid, grpname) {
            if context
                .is_self_addr(&addr)
                .await
                .with_context(|| format!("can't check if address {addr:?} is our address"))?
            {
                if token::exists(context, token::Namespace::InviteNumber, &invitenumber).await? {
                    Ok(Qr::WithdrawVerifyGroup {
                        grpname,
                        grpid,
                        contact_id,
                        fingerprint,
                        invitenumber,
                        authcode,
                    })
                } else {
                    Ok(Qr::ReviveVerifyGroup {
                        grpname,
                        grpid,
                        contact_id,
                        fingerprint,
                        invitenumber,
                        authcode,
                    })
                }
            } else {
                Ok(Qr::AskVerifyGroup {
                    grpname,
                    grpid,
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                })
            }
        } else if context.is_self_addr(&addr).await? {
            if token::exists(context, token::Namespace::InviteNumber, &invitenumber).await? {
                Ok(Qr::WithdrawVerifyContact {
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                })
            } else {
                Ok(Qr::ReviveVerifyContact {
                    contact_id,
                    fingerprint,
                    invitenumber,
                    authcode,
                })
            }
        } else {
            Ok(Qr::AskVerifyContact {
                contact_id,
                fingerprint,
                invitenumber,
                authcode,
            })
        }
    } else if let Some(addr) = addr {
        if let Some(peerstate) = peerstate {
            let peerstate_addr = ContactAddress::new(&peerstate.addr)?;
            let (contact_id, _) =
                Contact::add_or_lookup(context, &name, &peerstate_addr, Origin::UnhandledQrScan)
                    .await
                    .context("add_or_lookup")?;
            ChatIdBlocked::get_for_contact(context, contact_id, Blocked::Request)
                .await
                .context("Failed to create (new) chat for contact")?;
            Ok(Qr::FprOk { contact_id })
        } else {
            let contact_id = Contact::lookup_id_by_addr(context, &addr, Origin::Unknown)
                .await
                .with_context(|| format!("Error looking up contact {addr:?}"))?;
            Ok(Qr::FprMismatch { contact_id })
        }
    } else {
        Ok(Qr::FprWithoutAddr {
            fingerprint: fingerprint.to_string(),
        })
    }
}

/// scheme: `https://i.delta.chat[/]#FINGERPRINT&a=ADDR[&OPTIONAL_PARAMS]`
async fn decode_ideltachat(context: &Context, prefix: &str, qr: &str) -> Result<Qr> {
    let qr = qr.replacen(prefix, OPENPGP4FPR_SCHEME, 1);
    let qr = qr.replacen('&', "#", 1);
    decode_openpgp(context, &qr)
        .await
        .context("failed to decode {prefix} QR code")
}

/// scheme: `DCACCOUNT:https://example.org/new_email?t=1w_7wDjgjelxeX884x96v3`
fn decode_account(qr: &str) -> Result<Qr> {
    let payload = qr
        .get(DCACCOUNT_SCHEME.len()..)
        .context("invalid DCACCOUNT payload")?;
    let url = url::Url::parse(payload).context("Invalid account URL")?;
    if url.scheme() == "http" || url.scheme() == "https" {
        Ok(Qr::Account {
            domain: url
                .host_str()
                .context("can't extract WebRTC instance domain")?
                .to_string(),
        })
    } else {
        bail!("Bad scheme for account URL: {:?}.", url.scheme());
    }
}

/// scheme: `DCWEBRTC:https://meet.jit.si/$ROOM`
fn decode_webrtc_instance(_context: &Context, qr: &str) -> Result<Qr> {
    let payload = qr
        .get(DCWEBRTC_SCHEME.len()..)
        .context("invalid DCWEBRTC payload")?;

    let (_type, url) = Message::parse_webrtc_instance(payload);
    let url = url::Url::parse(&url).context("Invalid WebRTC instance")?;

    if url.scheme() == "http" || url.scheme() == "https" {
        Ok(Qr::WebrtcInstance {
            domain: url
                .host_str()
                .context("can't extract WebRTC instance domain")?
                .to_string(),
            instance_pattern: payload.to_string(),
        })
    } else {
        bail!("Bad URL scheme for WebRTC instance: {:?}", url.scheme());
    }
}

/// Decodes a [`DCBACKUP_SCHEME`] QR code.
///
/// The format of this scheme is `DCBACKUP:<encoded ticket>`.  The encoding is the
/// [`iroh::provider::Ticket`]'s `Display` impl.
fn decode_backup(qr: &str) -> Result<Qr> {
    let payload = qr
        .strip_prefix(DCBACKUP_SCHEME)
        .ok_or_else(|| anyhow!("invalid DCBACKUP scheme"))?;
    let ticket: iroh::provider::Ticket = payload.parse().context("invalid DCBACKUP payload")?;
    Ok(Qr::Backup { ticket })
}

#[derive(Debug, Deserialize)]
struct CreateAccountSuccessResponse {
    /// Email address.
    email: String,

    /// Password.
    password: String,
}
#[derive(Debug, Deserialize)]
struct CreateAccountErrorResponse {
    /// Reason for the failure to create account returned by the server.
    reason: String,
}

/// take a qr of the type DC_QR_ACCOUNT, parse it's parameters,
/// download additional information from the contained url and set the parameters.
/// on success, a configure::configure() should be able to log in to the account
#[allow(clippy::indexing_slicing)]
async fn set_account_from_qr(context: &Context, qr: &str) -> Result<()> {
    let url_str = &qr[DCACCOUNT_SCHEME.len()..];
    let socks5_config = Socks5Config::from_database(&context.sql).await?;
    let response = crate::net::http::get_client(socks5_config)?
        .post(url_str)
        .send()
        .await?;
    let response_status = response.status();
    let response_text = response
        .text()
        .await
        .context("Cannot create account, request failed: empty response")?;

    if response_status.is_success() {
        let CreateAccountSuccessResponse { password, email } = serde_json::from_str(&response_text)
            .with_context(|| {
                format!("Cannot create account, response is malformed:\n{response_text:?}")
            })?;
        context
            .set_config_internal(Config::Addr, Some(&email))
            .await?;
        context
            .set_config_internal(Config::MailPw, Some(&password))
            .await?;

        Ok(())
    } else {
        match serde_json::from_str::<CreateAccountErrorResponse>(&response_text) {
            Ok(error) => Err(anyhow!(error.reason)),
            Err(parse_error) => {
                context.emit_event(EventType::Error(format!(
                    "Cannot create account, server response could not be parsed:\n{parse_error:#}\nraw response:\n{response_text}"
                )));
                bail!(
                    "Cannot create account, unexpected server response:\n{:?}",
                    response_text
                )
            }
        }
    }
}

/// Sets configuration values from a QR code.
pub async fn set_config_from_qr(context: &Context, qr: &str) -> Result<()> {
    match check_qr(context, qr).await? {
        Qr::Account { .. } => set_account_from_qr(context, qr).await?,
        Qr::WebrtcInstance {
            domain: _,
            instance_pattern,
        } => {
            context
                .set_config_internal(Config::WebrtcInstance, Some(&instance_pattern))
                .await?;
        }
        Qr::WithdrawVerifyContact {
            invitenumber,
            authcode,
            ..
        } => {
            token::delete(context, token::Namespace::InviteNumber, &invitenumber).await?;
            token::delete(context, token::Namespace::Auth, &authcode).await?;
            context
                .sync_qr_code_token_deletion(invitenumber, authcode)
                .await?;
            context.send_sync_msg().await?;
        }
        Qr::WithdrawVerifyGroup {
            invitenumber,
            authcode,
            ..
        } => {
            token::delete(context, token::Namespace::InviteNumber, &invitenumber).await?;
            token::delete(context, token::Namespace::Auth, &authcode).await?;
            context
                .sync_qr_code_token_deletion(invitenumber, authcode)
                .await?;
            context.send_sync_msg().await?;
        }
        Qr::ReviveVerifyContact {
            invitenumber,
            authcode,
            ..
        } => {
            token::save(context, token::Namespace::InviteNumber, None, &invitenumber).await?;
            token::save(context, token::Namespace::Auth, None, &authcode).await?;
            context.sync_qr_code_tokens(None).await?;
            context.send_sync_msg().await?;
        }
        Qr::ReviveVerifyGroup {
            invitenumber,
            authcode,
            grpid,
            ..
        } => {
            let chat_id = get_chat_id_by_grpid(context, &grpid)
                .await?
                .map(|(chat_id, _protected, _blocked)| chat_id);
            token::save(
                context,
                token::Namespace::InviteNumber,
                chat_id,
                &invitenumber,
            )
            .await?;
            token::save(context, token::Namespace::Auth, chat_id, &authcode).await?;
            context.sync_qr_code_tokens(chat_id).await?;
            context.send_sync_msg().await?;
        }
        Qr::Login { address, options } => {
            configure_from_login_qr(context, &address, options).await?
        }
        _ => bail!("QR code does not contain config"),
    }

    Ok(())
}

/// Extract address for the mailto scheme.
///
/// Scheme: `mailto:addr...?subject=...&body=..`
#[allow(clippy::indexing_slicing)]
async fn decode_mailto(context: &Context, qr: &str) -> Result<Qr> {
    let payload = &qr[MAILTO_SCHEME.len()..];

    let (addr, query) = if let Some(query_index) = payload.find('?') {
        (&payload[..query_index], &payload[query_index + 1..])
    } else {
        (payload, "")
    };

    let param: BTreeMap<&str, &str> = query
        .split('&')
        .filter_map(|s| {
            if let [key, value] = s.splitn(2, '=').collect::<Vec<_>>()[..] {
                Some((key, value))
            } else {
                None
            }
        })
        .collect();

    let subject = if let Some(subject) = param.get("subject") {
        subject.to_string()
    } else {
        "".to_string()
    };
    let draft = if let Some(body) = param.get("body") {
        if subject.is_empty() {
            body.to_string()
        } else {
            subject + "\n" + body
        }
    } else {
        subject
    };
    let draft = draft.replace('+', "%20"); // sometimes spaces are encoded as `+`
    let draft = match percent_decode_str(&draft).decode_utf8() {
        Ok(decoded_draft) => decoded_draft.to_string(),
        Err(_err) => draft,
    };

    let addr = normalize_address(addr)?;
    let name = "";
    Qr::from_address(
        context,
        name,
        &addr,
        if draft.is_empty() { None } else { Some(draft) },
    )
    .await
}

/// Extract address for the smtp scheme.
///
/// Scheme: `SMTP:addr...:subject...:body...`
#[allow(clippy::indexing_slicing)]
async fn decode_smtp(context: &Context, qr: &str) -> Result<Qr> {
    let payload = &qr[SMTP_SCHEME.len()..];

    let addr = if let Some(query_index) = payload.find(':') {
        &payload[..query_index]
    } else {
        bail!("Invalid SMTP found");
    };

    let addr = normalize_address(addr)?;
    let name = "";
    Qr::from_address(context, name, &addr, None).await
}

/// Extract address for the matmsg scheme.
///
/// Scheme: `MATMSG:TO:addr...;SUB:subject...;BODY:body...;`
///
/// There may or may not be linebreaks after the fields.
#[allow(clippy::indexing_slicing)]
async fn decode_matmsg(context: &Context, qr: &str) -> Result<Qr> {
    // Does not work when the text `TO:` is used in subject/body _and_ TO: is not the first field.
    // we ignore this case.
    let addr = if let Some(to_index) = qr.find("TO:") {
        let addr = qr[to_index + 3..].trim();
        if let Some(semi_index) = addr.find(';') {
            addr[..semi_index].trim()
        } else {
            addr
        }
    } else {
        bail!("Invalid MATMSG found");
    };

    let addr = normalize_address(addr)?;
    let name = "";
    Qr::from_address(context, name, &addr, None).await
}

static VCARD_NAME_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(?m)^N:([^;]*);([^;\n]*)").unwrap());
static VCARD_EMAIL_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(?m)^EMAIL([^:\n]*):([^;\n]*)").unwrap());

/// Extract address for the vcard scheme.
///
/// Scheme: `VCARD:BEGIN\nN:last name;first name;...;\nEMAIL;<type>:addr...;`
#[allow(clippy::indexing_slicing)]
async fn decode_vcard(context: &Context, qr: &str) -> Result<Qr> {
    let name = VCARD_NAME_RE
        .captures(qr)
        .and_then(|caps| {
            let last_name = caps.get(1)?.as_str().trim();
            let first_name = caps.get(2)?.as_str().trim();

            Some(format!("{first_name} {last_name}"))
        })
        .unwrap_or_default();

    let addr = if let Some(caps) = VCARD_EMAIL_RE.captures(qr) {
        normalize_address(caps[2].trim())?
    } else {
        bail!("Bad e-mail address");
    };

    Qr::from_address(context, &name, &addr, None).await
}

impl Qr {
    /// Creates a new scanned QR code of a contact address.
    ///
    /// May contain a message draft.
    pub async fn from_address(
        context: &Context,
        name: &str,
        addr: &str,
        draft: Option<String>,
    ) -> Result<Self> {
        let addr = ContactAddress::new(addr)?;
        let (contact_id, _) =
            Contact::add_or_lookup(context, name, &addr, Origin::UnhandledQrScan).await?;
        Ok(Qr::Addr { contact_id, draft })
    }
}

/// URL decodes a given address, does basic email validation on the result.
fn normalize_address(addr: &str) -> Result<String> {
    // urldecoding is needed at least for OPENPGP4FPR but should not hurt in the other cases
    let new_addr = percent_decode_str(addr).decode_utf8()?;
    let new_addr = addr_normalize(&new_addr);

    ensure!(may_be_valid_addr(&new_addr), "Bad e-mail address");

    Ok(new_addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aheader::EncryptPreference;
    use crate::chat::{create_group_chat, ProtectionStatus};
    use crate::key::DcKey;
    use crate::securejoin::get_securejoin_qr;
    use crate::test_utils::{alice_keypair, TestContext};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_http() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(&ctx.ctx, "http://www.hello.com").await?;
        assert_eq!(
            qr,
            Qr::Url {
                url: "http://www.hello.com".to_string()
            }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_https() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(&ctx.ctx, "https://www.hello.com").await?;
        assert_eq!(
            qr,
            Qr::Url {
                url: "https://www.hello.com".to_string()
            }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_text() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(&ctx.ctx, "I am so cool").await?;
        assert_eq!(
            qr,
            Qr::Text {
                text: "I am so cool".to_string()
            }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_vcard() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "BEGIN:VCARD\nVERSION:3.0\nN:Last;First\nEMAIL;TYPE=INTERNET:stress@test.local\nEND:VCARD"
        ).await?;

        if let Qr::Addr { contact_id, draft } = qr {
            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "stress@test.local");
            assert_eq!(contact.get_name(), "First Last");
            assert_eq!(contact.get_authname(), "");
            assert_eq!(contact.get_display_name(), "First Last");
            assert!(draft.is_none());
        } else {
            bail!("Wrong QR code type");
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_matmsg() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "MATMSG:TO:\n\nstress@test.local ; \n\nSUB:\n\nSubject here\n\nBODY:\n\nhelloworld\n;;",
        )
        .await?;

        if let Qr::Addr { contact_id, draft } = qr {
            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "stress@test.local");
            assert!(draft.is_none());
        } else {
            bail!("Wrong QR code type");
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_mailto() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "mailto:stress@test.local?subject=hello&body=beautiful+world",
        )
        .await?;
        if let Qr::Addr { contact_id, draft } = qr {
            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "stress@test.local");
            assert_eq!(draft.unwrap(), "hello\nbeautiful world");
        } else {
            bail!("Wrong QR code type");
        }

        let res = check_qr(&ctx.ctx, "mailto:no-questionmark@example.org").await?;
        if let Qr::Addr { contact_id, draft } = res {
            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "no-questionmark@example.org");
            assert!(draft.is_none());
        } else {
            bail!("Wrong QR code type");
        }

        let res = check_qr(&ctx.ctx, "mailto:no-addr").await;
        assert!(res.is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_smtp() -> Result<()> {
        let ctx = TestContext::new().await;

        if let Qr::Addr { contact_id, draft } =
            check_qr(&ctx.ctx, "SMTP:stress@test.local:subjecthello:bodyworld").await?
        {
            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "stress@test.local");
            assert!(draft.is_none());
        } else {
            bail!("Wrong QR code type");
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_ideltachat_link() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "https://i.delta.chat/#79252762C34C5096AF57958F4FC3D21A81B0F0A7&a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
        ).await?;
        assert!(matches!(qr, Qr::AskVerifyGroup { .. }));

        let qr = check_qr(
            &ctx.ctx,
            "https://i.delta.chat#79252762C34C5096AF57958F4FC3D21A81B0F0A7&a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
        ).await?;
        assert!(matches!(qr, Qr::AskVerifyGroup { .. }));

        Ok(())
    }

    // macOS and iOS sometimes replace the # with %23 (uri encode it), we should be able to parse this wrong format too.
    // see issue https://github.com/deltachat/deltachat-core-rust/issues/1969 for more info
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_openpgp_tolerance_for_issue_1969() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7%23a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
        ).await?;

        assert!(matches!(qr, Qr::AskVerifyGroup { .. }));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_openpgp_group() -> Result<()> {
        let ctx = TestContext::new().await;
        let qr = check_qr(
            &ctx.ctx,
            "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
        ).await?;
        if let Qr::AskVerifyGroup {
            contact_id,
            grpname,
            ..
        } = qr
        {
            assert_ne!(contact_id, ContactId::UNDEFINED);
            assert_eq!(grpname, "test ? test !");
        } else {
            bail!("Wrong QR code type");
        }

        // Test it again with lowercased "openpgp4fpr:" uri scheme
        let ctx = TestContext::new().await;
        let qr = check_qr(
            &ctx.ctx,
            "openpgp4fpr:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL9cxRL"
        ).await?;
        if let Qr::AskVerifyGroup {
            contact_id,
            grpname,
            ..
        } = qr
        {
            assert_ne!(contact_id, ContactId::UNDEFINED);
            assert_eq!(grpname, "test ? test !");

            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "cli@deltachat.de");
        } else {
            bail!("Wrong QR code type");
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_openpgp_invalid_token() -> Result<()> {
        let ctx = TestContext::new().await;

        // Token cannot contain "/"
        let qr = check_qr(
            &ctx.ctx,
            "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&g=test%20%3F+test%20%21&x=h-0oKQf2CDK&i=9JEXlxAqGM0&s=0V7LzL/cxRL"
        ).await?;

        assert!(matches!(qr, Qr::FprMismatch { .. }));

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_openpgp_secure_join() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "OPENPGP4FPR:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&n=J%C3%B6rn%20P.+P.&i=TbnwJ6lSvD5&s=0ejvbdFSQxB"
        ).await?;

        if let Qr::AskVerifyContact { contact_id, .. } = qr {
            assert_ne!(contact_id, ContactId::UNDEFINED);
        } else {
            bail!("Wrong QR code type");
        }

        // Test it again with lowercased "openpgp4fpr:" uri scheme
        let qr = check_qr(
            &ctx.ctx,
            "openpgp4fpr:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&n=J%C3%B6rn%20P.+P.&i=TbnwJ6lSvD5&s=0ejvbdFSQxB"
        ).await?;

        if let Qr::AskVerifyContact { contact_id, .. } = qr {
            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "cli@deltachat.de");
            assert_eq!(contact.get_name(), "Jörn P. P.");
        } else {
            bail!("Wrong QR code type");
        }

        // Regression test
        let ctx = TestContext::new().await;
        let qr = check_qr(
            &ctx.ctx,
            "openpgp4fpr:79252762C34C5096AF57958F4FC3D21A81B0F0A7#a=cli%40deltachat.de&n=&i=TbnwJ6lSvD5&s=0ejvbdFSQxB"
        ).await?;

        if let Qr::AskVerifyContact { contact_id, .. } = qr {
            let contact = Contact::get_by_id(&ctx.ctx, contact_id).await?;
            assert_eq!(contact.get_addr(), "cli@deltachat.de");
            assert_eq!(contact.get_name(), "");
        } else {
            bail!("Wrong QR code type");
        }

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_openpgp_fingerprint() -> Result<()> {
        let ctx = TestContext::new().await;

        let alice_contact_id = Contact::create(&ctx, "Alice", "alice@example.org")
            .await
            .context("failed to create contact")?;
        let pub_key = alice_keypair().public;
        let peerstate = Peerstate {
            addr: "alice@example.org".to_string(),
            last_seen: 1,
            last_seen_autocrypt: 1,
            prefer_encrypt: EncryptPreference::Mutual,
            public_key: Some(pub_key.clone()),
            public_key_fingerprint: Some(pub_key.fingerprint()),
            gossip_key: None,
            gossip_timestamp: 0,
            gossip_key_fingerprint: None,
            verified_key: None,
            verified_key_fingerprint: None,
            verifier: None,
            secondary_verified_key: None,
            secondary_verified_key_fingerprint: None,
            secondary_verifier: None,
            backward_verified_key_id: None,
            fingerprint_changed: false,
        };
        assert!(
            peerstate.save_to_db(&ctx.ctx.sql).await.is_ok(),
            "failed to save peerstate"
        );

        let qr = check_qr(
            &ctx.ctx,
            "OPENPGP4FPR:1234567890123456789012345678901234567890#a=alice@example.org",
        )
        .await?;
        if let Qr::FprMismatch { contact_id, .. } = qr {
            assert_eq!(contact_id, Some(alice_contact_id));
        } else {
            bail!("Wrong QR code type");
        }

        let qr = check_qr(
            &ctx.ctx,
            &format!("OPENPGP4FPR:{}#a=alice@example.org", pub_key.fingerprint()),
        )
        .await?;
        if let Qr::FprOk { contact_id, .. } = qr {
            assert_eq!(contact_id, alice_contact_id);
        } else {
            bail!("Wrong QR code type");
        }

        assert_eq!(
            check_qr(
                &ctx.ctx,
                "OPENPGP4FPR:1234567890123456789012345678901234567890#a=bob@example.org",
            )
            .await?,
            Qr::FprMismatch { contact_id: None }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_openpgp_without_addr() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "OPENPGP4FPR:1234567890123456789012345678901234567890",
        )
        .await?;
        assert_eq!(
            qr,
            Qr::FprWithoutAddr {
                fingerprint: "1234 5678 9012 3456 7890\n1234 5678 9012 3456 7890".to_string()
            }
        );

        // Test it again with lowercased "openpgp4fpr:" uri scheme

        let qr = check_qr(
            &ctx.ctx,
            "openpgp4fpr:1234567890123456789012345678901234567890",
        )
        .await?;
        assert_eq!(
            qr,
            Qr::FprWithoutAddr {
                fingerprint: "1234 5678 9012 3456 7890\n1234 5678 9012 3456 7890".to_string()
            }
        );

        let res = check_qr(&ctx.ctx, "OPENPGP4FPR:12345678901234567890").await;
        assert!(res.is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_withdraw_verifycontact() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let qr = get_securejoin_qr(&alice, None).await?;

        // scanning own verify-contact code offers withdrawing
        assert!(matches!(
            check_qr(&alice, &qr).await?,
            Qr::WithdrawVerifyContact { .. }
        ));
        set_config_from_qr(&alice, &qr).await?;

        // scanning withdrawn verify-contact code offers reviving
        assert!(matches!(
            check_qr(&alice, &qr).await?,
            Qr::ReviveVerifyContact { .. }
        ));
        set_config_from_qr(&alice, &qr).await?;
        assert!(matches!(
            check_qr(&alice, &qr).await?,
            Qr::WithdrawVerifyContact { .. }
        ));

        // someone else always scans as ask-verify-contact
        let bob = TestContext::new_bob().await;
        assert!(matches!(
            check_qr(&bob, &qr).await?,
            Qr::AskVerifyContact { .. }
        ));
        assert!(set_config_from_qr(&bob, &qr).await.is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_withdraw_verifygroup() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "foo").await?;
        let qr = get_securejoin_qr(&alice, Some(chat_id)).await?;

        // scanning own verify-group code offers withdrawing
        if let Qr::WithdrawVerifyGroup { grpname, .. } = check_qr(&alice, &qr).await? {
            assert_eq!(grpname, "foo");
        } else {
            bail!("Wrong QR type, expected WithdrawVerifyGroup");
        }
        set_config_from_qr(&alice, &qr).await?;

        // scanning withdrawn verify-group code offers reviving
        if let Qr::ReviveVerifyGroup { grpname, .. } = check_qr(&alice, &qr).await? {
            assert_eq!(grpname, "foo");
        } else {
            bail!("Wrong QR type, expected ReviveVerifyGroup");
        }

        // someone else always scans as ask-verify-group
        let bob = TestContext::new_bob().await;
        if let Qr::AskVerifyGroup { grpname, .. } = check_qr(&bob, &qr).await? {
            assert_eq!(grpname, "foo");
        } else {
            bail!("Wrong QR type, expected AskVerifyGroup");
        }
        assert!(set_config_from_qr(&bob, &qr).await.is_err());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_and_apply_dclogin() -> Result<()> {
        let ctx = TestContext::new().await;

        let result = check_qr(&ctx.ctx, "dclogin:usename+extension@host?p=1234&v=1").await?;
        if let Qr::Login { address, options } = result {
            assert_eq!(address, "usename+extension@host".to_owned());

            if let LoginOptions::V1 { mail_pw, .. } = options {
                assert_eq!(mail_pw, "1234".to_owned());
            } else {
                bail!("wrong type")
            }
        } else {
            bail!("wrong type")
        }

        assert!(ctx.ctx.get_config(Config::Addr).await?.is_none());
        assert!(ctx.ctx.get_config(Config::MailPw).await?.is_none());

        set_config_from_qr(&ctx.ctx, "dclogin:username+extension@host?p=1234&v=1").await?;
        assert_eq!(
            ctx.ctx.get_config(Config::Addr).await?,
            Some("username+extension@host".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::MailPw).await?,
            Some("1234".to_owned())
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_and_apply_dclogin_advanced_options() -> Result<()> {
        let ctx = TestContext::new().await;
        set_config_from_qr(&ctx.ctx, "dclogin:username+extension@host?p=1234&spw=4321&sh=send.host&sp=7273&su=SendUser&ih=host.tld&ip=4343&iu=user&ipw=password&is=ssl&ic=1&sc=3&ss=plain&v=1").await?;
        assert_eq!(
            ctx.ctx.get_config(Config::Addr).await?,
            Some("username+extension@host".to_owned())
        );

        // `p=1234` is ignored, because `ipw=password` is set

        assert_eq!(
            ctx.ctx.get_config(Config::MailServer).await?,
            Some("host.tld".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::MailPort).await?,
            Some("4343".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::MailUser).await?,
            Some("user".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::MailPw).await?,
            Some("password".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::MailSecurity).await?,
            Some("1".to_owned()) // ssl
        );
        assert_eq!(
            ctx.ctx.get_config(Config::ImapCertificateChecks).await?,
            Some("1".to_owned())
        );

        assert_eq!(
            ctx.ctx.get_config(Config::SendPw).await?,
            Some("4321".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::SendServer).await?,
            Some("send.host".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::SendPort).await?,
            Some("7273".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::SendUser).await?,
            Some("SendUser".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::SmtpCertificateChecks).await?,
            Some("3".to_owned())
        );
        assert_eq!(
            ctx.ctx.get_config(Config::SendSecurity).await?,
            Some("3".to_owned()) // plain
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_account() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(
            &ctx.ctx,
            "DCACCOUNT:https://example.org/new_email?t=1w_7wDjgjelxeX884x96v3",
        )
        .await?;
        assert_eq!(
            qr,
            Qr::Account {
                domain: "example.org".to_string()
            }
        );

        // Test it again with lowercased "dcaccount:" uri scheme
        let qr = check_qr(
            &ctx.ctx,
            "dcaccount:https://example.org/new_email?t=1w_7wDjgjelxeX884x96v3",
        )
        .await?;
        assert_eq!(
            qr,
            Qr::Account {
                domain: "example.org".to_string()
            }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_webrtc_instance() -> Result<()> {
        let ctx = TestContext::new().await;

        let qr = check_qr(&ctx.ctx, "DCWEBRTC:basicwebrtc:https://basicurl.com/$ROOM").await?;
        assert_eq!(
            qr,
            Qr::WebrtcInstance {
                domain: "basicurl.com".to_string(),
                instance_pattern: "basicwebrtc:https://basicurl.com/$ROOM".to_string()
            }
        );

        // Test it again with mixcased "dcWebRTC:" uri scheme
        let qr = check_qr(&ctx.ctx, "dcWebRTC:https://example.org/").await?;
        assert_eq!(
            qr,
            Qr::WebrtcInstance {
                domain: "example.org".to_string(),
                instance_pattern: "https://example.org/".to_string()
            }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_decode_account_bad_scheme() {
        let ctx = TestContext::new().await;
        let res = check_qr(
            &ctx.ctx,
            "DCACCOUNT:ftp://example.org/new_email?t=1w_7wDjgjelxeX884x96v3",
        )
        .await;
        assert!(res.is_err());

        // Test it again with lowercased "dcaccount:" uri scheme
        let res = check_qr(
            &ctx.ctx,
            "dcaccount:ftp://example.org/new_email?t=1w_7wDjgjelxeX884x96v3",
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_set_config_from_qr() -> Result<()> {
        let ctx = TestContext::new().await;

        assert!(ctx.ctx.get_config(Config::WebrtcInstance).await?.is_none());

        let res = set_config_from_qr(&ctx.ctx, "badqr:https://example.org/").await;
        assert!(res.is_err());
        assert!(ctx.ctx.get_config(Config::WebrtcInstance).await?.is_none());

        let res = set_config_from_qr(&ctx.ctx, "https://no.qr").await;
        assert!(res.is_err());
        assert!(ctx.ctx.get_config(Config::WebrtcInstance).await?.is_none());

        let res = set_config_from_qr(&ctx.ctx, "dcwebrtc:https://example.org/").await;
        assert!(res.is_ok());
        assert_eq!(
            ctx.ctx.get_config(Config::WebrtcInstance).await?.unwrap(),
            "https://example.org/"
        );

        let res =
            set_config_from_qr(&ctx.ctx, "DCWEBRTC:basicwebrtc:https://foo.bar/?$ROOM&test").await;
        assert!(res.is_ok());
        assert_eq!(
            ctx.ctx.get_config(Config::WebrtcInstance).await?.unwrap(),
            "basicwebrtc:https://foo.bar/?$ROOM&test"
        );

        Ok(())
    }
}
