//! # Constants.

#![allow(missing_docs)]

use deltachat_derive::{FromSql, ToSql};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};

pub static DC_VERSION_STR: &str = env!("CARGO_PKG_VERSION");

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

/// Chat type.
#[derive(
    Debug,
    Display,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
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
    /// A single chat (a chat with a single contact).
    ///
    /// Created by [`crate::chat::ChatId::create_for_contact`].
    Single = 100,

    /// Group chat.
    ///
    /// Created by [`crate::chat::create_group`].
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

// max. weight of images to send w/o recoding
pub const BALANCED_IMAGE_BYTES: usize = 500_000;
pub const WORSE_IMAGE_BYTES: usize = 130_000;

// max. width/height and bytes of an avatar
pub(crate) const BALANCED_AVATAR_SIZE: u32 = 512;
pub(crate) const BALANCED_AVATAR_BYTES: usize = 60_000;
pub(crate) const WORSE_AVATAR_SIZE: u32 = 256;
pub(crate) const WORSE_AVATAR_BYTES: usize = 20_000; // this also fits to Outlook servers don't allowing headers larger than 32k.

// max. width/height of images scaled down because of being too huge
pub const BALANCED_IMAGE_SIZE: u32 = 1280;
pub const WORSE_IMAGE_SIZE: u32 = 640;

/// Limit for received images size. Bigger images become `Viewtype::File` to avoid excessive memory
/// usage by UIs.
pub const MAX_RCVD_IMAGE_PIXELS: u32 = 50_000_000;

// Fallback for the maximum number of recipients in SMTP's `RCPT TO:`;
// recipient lists exceeding the limit are sent in chunks.
// Relays typically advertise their limit via IMAP METADATA.
pub(crate) const DEFAULT_MAX_SMTP_RCPT_TO: u32 = 50;

/// How far the last quota check needs to be in the past to be checked by the background function (in seconds).
pub(crate) const DC_BACKGROUND_FETCH_QUOTA_CHECK_RATELIMIT: u64 = 12 * 60 * 60; // 12 hours

/// How far in the future the sender timestamp of a message is allowed to be, in seconds. Also used
/// in the group membership consistency algo to reject outdated membership changes.
pub(crate) const TIMESTAMP_SENT_TOLERANCE: i64 = 60;

// To make text edits clearer for Non-Delta-MUA or old Delta Chats, edited text will be prefixed by EDITED_PREFIX.
// Newer Delta Chats will remove the prefix as needed.
pub(crate) const EDITED_PREFIX: &str = "✏️";

/// Period between `sql::housekeeping()` runs.
pub(crate) const HOUSEKEEPING_PERIOD: i64 = 24 * 60 * 60;

/// Number of recent messages that should be resent to a new broadcast member.
/// Additionally, up to this amount of pinned messages will be resent.
pub(crate) const N_MSGS_TO_NEW_BROADCAST_MEMBER: usize = 10;

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
