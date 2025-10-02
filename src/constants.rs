//! # Constants.

#![allow(missing_docs)]

use std::sync::LazyLock;

use deltachat_derive::{FromSql, ToSql};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

use crate::chat::ChatId;

pub static DC_VERSION_STR: LazyLock<String> =
    LazyLock::new(|| env!("CARGO_PKG_VERSION").to_string());

/// Set of characters to percent-encode in email addresses and names.
pub(crate) const NON_ALPHANUMERIC_WITHOUT_DOT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'.');

#[derive(
    Debug,
    Default,
    Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    FromPrimitive,
    ToPrimitive,
    FromSql,
    ToSql,
    Serialize,
    Deserialize,
)]
#[repr(i8)]
pub enum Blocked {
    #[default]
    Not = 0,
    Yes = 1,
    Request = 2,
}

#[derive(
    Debug, Default, Display, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive, FromSql, ToSql,
)]
#[repr(u8)]
pub enum ShowEmails {
    Off = 0,
    AcceptedContacts = 1,
    #[default] // also change Config.ShowEmails props(default) on changes
    All = 2,
}

#[derive(
    Debug, Default, Display, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive, FromSql, ToSql,
)]
#[repr(u8)]
pub enum MediaQuality {
    #[default] // also change Config.MediaQuality props(default) on changes
    Balanced = 0,
    Worse = 1,
}

pub const DC_HANDSHAKE_CONTINUE_NORMAL_PROCESSING: i32 = 0x01;
pub const DC_HANDSHAKE_STOP_NORMAL_PROCESSING: i32 = 0x02;
pub const DC_HANDSHAKE_ADD_DELETE_JOB: i32 = 0x04;

pub(crate) const DC_FROM_HANDSHAKE: i32 = 0x01;

pub const DC_GCL_ARCHIVED_ONLY: usize = 0x01;
pub const DC_GCL_NO_SPECIALS: usize = 0x02;
pub const DC_GCL_ADD_ALLDONE_HINT: usize = 0x04;
pub const DC_GCL_FOR_FORWARDING: usize = 0x08;

pub const DC_GCL_ADD_SELF: u32 = 0x02;
pub const DC_GCL_ADDRESS: u32 = 0x04;

// unchanged user avatars are resent to the recipients every some days
pub(crate) const DC_RESEND_USER_AVATAR_DAYS: i64 = 14;

// warn about an outdated app after a given number of days.
// reference is the release date.
// as not all system get speedy updates,
// do not use too small value that will annoy users checking for nonexistent updates.
// "90 days" has proven to be too short at some point (user were informed but there was no update)
pub(crate) const DC_OUTDATED_WARNING_DAYS: i64 = 183;

/// messages that should be deleted get this chat_id; the messages are deleted from the working thread later then. This is also needed as rfc724_mid should be preset as long as the message is not deleted on the server (otherwise it is downloaded again)
pub const DC_CHAT_ID_TRASH: ChatId = ChatId::new(3);
/// only an indicator in a chatlist
pub const DC_CHAT_ID_ARCHIVED_LINK: ChatId = ChatId::new(6);
/// only an indicator in a chatlist
pub const DC_CHAT_ID_ALLDONE_HINT: ChatId = ChatId::new(7);
/// larger chat IDs are "real" chats, their messages are "real" messages.
pub const DC_CHAT_ID_LAST_SPECIAL: ChatId = ChatId::new(9);

/// Chat type.
#[derive(
    Debug,
    Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    FromPrimitive,
    ToPrimitive,
    FromSql,
    ToSql,
    IntoStaticStr,
    Serialize,
    Deserialize,
)]
#[repr(u32)]
pub enum Chattype {
    /// A 1:1 chat, i.e. a normal chat with a single contact.
    ///
    /// Created by [`ChatId::create_for_contact`].
    Single = 100,

    /// Group chat.
    ///
    /// Created by [`crate::chat::create_group_chat`].
    Group = 120,

    /// An (unencrypted) mailing list,
    /// created by an incoming mailing list email.
    Mailinglist = 140,

    /// Outgoing broadcast channel, called "Channel" in the UI.
    ///
    /// The user can send into this chat,
    /// and all recipients will receive messages
    /// in an `InBroadcast`.
    ///
    /// Called `broadcast` here rather than `channel`,
    /// because the word "channel" already appears a lot in the code,
    /// which would make it hard to grep for it.
    ///
    /// Created by [`crate::chat::create_broadcast`].
    OutBroadcast = 160,

    /// Incoming broadcast channel, called "Channel" in the UI.
    ///
    /// This chat is read-only,
    /// and we do not know who the other recipients are.
    ///
    /// This is similar to a `MailingList`,
    /// with the main difference being that
    /// `InBroadcast`s are encrypted.
    ///
    /// Called `broadcast` here rather than `channel`,
    /// because the word "channel" already appears a lot in the code,
    /// which would make it hard to grep for it.
    InBroadcast = 165,
}

pub const DC_MSG_ID_DAYMARKER: u32 = 9;
pub const DC_MSG_ID_LAST_SPECIAL: u32 = 9;

/// String that indicates that something is left out or truncated.
pub(crate) const DC_ELLIPSIS: &str = "[...]";
// how many lines desktop can display when fullscreen (fullscreen at zoomlevel 1x)
// (taken from "subjective" testing what looks ok)
pub const DC_DESIRED_TEXT_LINES: usize = 38;
// how many chars desktop can display per line (from "subjective" testing)
pub const DC_DESIRED_TEXT_LINE_LEN: usize = 100;

/// Message length limit.
///
/// To keep bubbles and chat flow usable and to avoid problems with controls using very long texts,
/// we limit the text length to `DC_DESIRED_TEXT_LEN`.  If the text is longer, the full text can be
/// retrieved using has_html()/get_html().
///
/// Note that for simplicity maximum length is defined as the number of Unicode Scalar Values (Rust
/// `char`s), not Unicode Grapheme Clusters.
pub const DC_DESIRED_TEXT_LEN: usize = DC_DESIRED_TEXT_LINE_LEN * DC_DESIRED_TEXT_LINES;

// Flags for configuring IMAP and SMTP servers.
// These flags are optional
// and may be set together with the username, password etc.
// via dc_set_config() using the key "server_flags".

/// Force OAuth2 authorization.
///
/// This flag does not skip automatic configuration.
/// Before calling configure() with DC_LP_AUTH_OAUTH2 set,
/// the user has to confirm access at the URL returned by dc_get_oauth2_url().
pub const DC_LP_AUTH_OAUTH2: i32 = 0x2;

/// Force NORMAL authorization, this is the default.
/// If this flag is set, automatic configuration is skipped.
pub const DC_LP_AUTH_NORMAL: i32 = 0x4;

/// if none of these flags are set, the default is chosen
pub const DC_LP_AUTH_FLAGS: i32 = DC_LP_AUTH_OAUTH2 | DC_LP_AUTH_NORMAL;

// max. weight of images to send w/o recoding
pub const BALANCED_IMAGE_BYTES: usize = 500_000;
pub const WORSE_IMAGE_BYTES: usize = 130_000;

// max. width/height and bytes of an avatar
pub(crate) const BALANCED_AVATAR_SIZE: u32 = 512;
pub(crate) const BALANCED_AVATAR_BYTES: usize = 60_000;
pub(crate) const WORSE_AVATAR_SIZE: u32 = 128;
pub(crate) const WORSE_AVATAR_BYTES: usize = 20_000; // this also fits to Outlook servers don't allowing headers larger than 32k.

// max. width/height of images scaled down because of being too huge
pub const BALANCED_IMAGE_SIZE: u32 = 1280;
pub const WORSE_IMAGE_SIZE: u32 = 640;

/// Limit for received images size. Bigger images become `Viewtype::File` to avoid excessive memory
/// usage by UIs.
pub const MAX_RCVD_IMAGE_PIXELS: u32 = 50_000_000;

// Key for the folder configuration version (see below).
pub(crate) const DC_FOLDERS_CONFIGURED_KEY: &str = "folders_configured";
// this value can be increased if the folder configuration is changed and must be redone on next program start
pub(crate) const DC_FOLDERS_CONFIGURED_VERSION: i32 = 5;

// If more recipients are needed in SMTP's `RCPT TO:` header, the recipient list is split into
// chunks. This does not affect MIME's `To:` header. Can be overwritten by setting
// `max_smtp_rcpt_to` in the provider db.
pub(crate) const DEFAULT_MAX_SMTP_RCPT_TO: usize = 50;

/// How far the last quota check needs to be in the past to be checked by the background function (in seconds).
pub(crate) const DC_BACKGROUND_FETCH_QUOTA_CHECK_RATELIMIT: u64 = 12 * 60 * 60; // 12 hours

/// How far in the future the sender timestamp of a message is allowed to be, in seconds. Also used
/// in the group membership consistency algo to reject outdated membership changes.
pub(crate) const TIMESTAMP_SENT_TOLERANCE: i64 = 60;

// To make text edits clearer for Non-Delta-MUA or old Delta Chats, edited text will be prefixed by EDITED_PREFIX.
// Newer Delta Chats will remove the prefix as needed.
pub(crate) const EDITED_PREFIX: &str = "✏️";

// Strings needed to render the Autocrypt Setup Message.
// Left untranslated as not being supported/recommended workflow and as translations would require deep knowledge.
pub(crate) const ASM_SUBJECT: &str = "Autocrypt Setup Message";
pub(crate) const ASM_BODY: &str = "This is the Autocrypt Setup Message \
    used to transfer your end-to-end setup between clients.

    To decrypt and use your setup, \
    open the message in an Autocrypt-compliant client \
    and enter the setup code presented on the generating device.

    If you see this message in a chatmail client (Delta Chat, Arcane Chat, Delta Touch ...), \
    use \"Settings / Add Second Device\" instead.";

/// Period between `sql::housekeeping()` runs.
pub(crate) const HOUSEKEEPING_PERIOD: i64 = 24 * 60 * 60;

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;

    #[test]
    fn test_chattype_values() {
        // values may be written to disk and must not change
        assert_eq!(Chattype::Single, Chattype::from_i32(100).unwrap());
        assert_eq!(Chattype::Group, Chattype::from_i32(120).unwrap());
        assert_eq!(Chattype::Mailinglist, Chattype::from_i32(140).unwrap());
        assert_eq!(Chattype::OutBroadcast, Chattype::from_i32(160).unwrap());
    }

    #[test]
    fn test_showemails_values() {
        // values may be written to disk and must not change
        assert_eq!(ShowEmails::All, ShowEmails::default());
        assert_eq!(ShowEmails::Off, ShowEmails::from_i32(0).unwrap());
        assert_eq!(
            ShowEmails::AcceptedContacts,
            ShowEmails::from_i32(1).unwrap()
        );
        assert_eq!(ShowEmails::All, ShowEmails::from_i32(2).unwrap());
    }

    #[test]
    fn test_blocked_values() {
        // values may be written to disk and must not change
        assert_eq!(Blocked::Not, Blocked::default());
        assert_eq!(Blocked::Not, Blocked::from_i32(0).unwrap());
        assert_eq!(Blocked::Yes, Blocked::from_i32(1).unwrap());
        assert_eq!(Blocked::Request, Blocked::from_i32(2).unwrap());
    }

    #[test]
    fn test_mediaquality_values() {
        // values may be written to disk and must not change
        assert_eq!(MediaQuality::Balanced, MediaQuality::default());
        assert_eq!(MediaQuality::Balanced, MediaQuality::from_i32(0).unwrap());
        assert_eq!(MediaQuality::Worse, MediaQuality::from_i32(1).unwrap());
    }
}
