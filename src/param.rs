use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str;

use anyhow::ensure;
use anyhow::{Error, Result, bail};
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};

use crate::blob::BlobObject;
use crate::context::Context;
use crate::mimeparser::SystemMessage;

/// Available param keys.
#[derive(
    PartialEq, Eq, Debug, Clone, Copy, Hash, PartialOrd, Ord, FromPrimitive, Serialize, Deserialize,
)]
#[repr(u8)]
pub enum Param {
    /// For messages
    File = b'f',

    /// For messages: original filename (as shown in chat)
    Filename = b'v',

    /// For messages: This name should be shown instead of contact.get_display_name()
    /// (used if this is a mailinglist
    /// or explicitly set using set_override_sender_name(), eg. by bots)
    OverrideSenderDisplayname = b'O',

    /// For Messages
    Width = b'w',

    /// For Messages
    Height = b'h',

    /// For Messages
    Duration = b'd',

    /// For Messages
    MimeType = b'm',

    /// For Messages: HTML to be written to the database and to be send.
    /// `SendHtml` param is not used for received messages.
    /// Use `MsgId::get_html()` to get HTML of received messages.
    SendHtml = b'T',

    /// For Messages: message is encrypted, outgoing: guarantee E2EE or the message is not send
    GuaranteeE2ee = b'c',

    /// For Messages: quoted message is encrypted.
    ///
    /// If this message is sent unencrypted, quote text should be replaced.
    ProtectQuote = b'0',

    /// For Messages: decrypted with validation errors or without mutual set, if neither
    /// 'c' nor 'e' are preset, the messages is only transport encrypted.
    ///
    /// Deprecated on 2024-12-25.
    ErroneousE2ee = b'e',

    /// For Messages: force unencrypted message, a value from `ForcePlaintext` enum.
    ForcePlaintext = b'u',

    /// For Messages: do not include Autocrypt header.
    SkipAutocrypt = b'o',

    /// For Messages
    WantsMdn = b'r',

    /// For Messages: the message is a reaction.
    Reaction = b'x',

    /// For Chats: the timestamp of the last reaction.
    LastReactionTimestamp = b'y',

    /// For Chats: Message ID of the last reaction.
    LastReactionMsgId = b'Y',

    /// For Chats: Contact ID of the last reaction.
    LastReactionContactId = b'1',

    /// For Messages: a message with "Auto-Submitted: auto-generated" header ("bot").
    Bot = b'b',

    /// For Messages: unset or 0=not forwarded,
    /// 1=forwarded from unknown msg_id, >9 forwarded from msg_id
    Forwarded = b'a',

    /// For Messages: quoted text.
    Quote = b'q',

    /// For Messages: the 1st part of summary text (i.e. before the dash if any).
    Summary1 = b'4',

    /// For Messages
    Cmd = b'S',

    /// For Messages
    ///
    /// For "MemberAddedToGroup" and "MemberRemovedFromGroup",
    /// this is the email address added to / removed from the group.
    ///
    /// For securejoin messages other than `vg-member-added`, this is the step,
    /// which is put into the `Secure-Join` header.
    Arg = b'E',

    /// For Messages
    ///
    /// For `BobHandshakeMsg::Request`, this is the `Secure-Join-Invitenumber` header.
    ///
    /// For `BobHandshakeMsg::RequestWithAuth`, this is the `Secure-Join-Auth` header.
    ///
    /// For [`SystemMessage::MultiDeviceSync`], this contains the ids that are synced.
    ///
    /// For [`SystemMessage::MemberAddedToGroup`],
    /// this is '1' if it was added because of a securejoin-handshake, and '0' otherwise.
    ///
    /// For call messages, this is the accept timestamp.
    Arg2 = b'F',

    /// For Messages
    ///
    /// For `BobHandshakeMsg::RequestWithAuth`,
    /// this contains the `Secure-Join-Fingerprint` header.
    ///
    /// For [`SystemMessage::MemberAddedToGroup`] that add to a broadcast channel,
    /// this contains the broadcast channel's shared secret.
    Arg3 = b'G',

    /// For Messages
    ///
    /// Deprecated `Secure-Join-Group` header for `BobHandshakeMsg::RequestWithAuth` messages.
    ///
    /// For "MemberAddedToGroup" and "MemberRemovedFromGroup",
    /// this is the fingerprint added to / removed from the group.
    ///
    /// For call messages, this is the end timsetamp.
    Arg4 = b'H',

    /// For Messages
    AttachGroupImage = b'A',

    /// For Messages
    WebrtcRoom = b'V',

    /// For Messages
    WebrtcAccepted = b'7',

    /// For Messages: space-separated list of messaged IDs of forwarded copies.
    ///
    /// This is used when a [crate::message::Message] is in the
    /// [crate::message::MessageState::OutPending] state but is already forwarded.
    /// In this case the forwarded messages are written to the
    /// database and their message IDs are added to this parameter of
    /// the original message, which is also saved in the database.
    /// When the original message is then finally sent this parameter
    /// is used to also send all the forwarded messages.
    PrepForwards = b'P',

    /// For Messages
    SetLatitude = b'l',

    /// For Messages
    SetLongitude = b'n',

    /// For Groups
    ///
    /// An unpromoted group has not had any messages sent to it and thus only exists on the
    /// creator's device.  Any changes made to an unpromoted group do not need to send
    /// system messages to the group members to update them of the changes.  Once a message
    /// has been sent to a group it is promoted and group changes require sending system
    /// messages to all members.
    Unpromoted = b'U',

    /// For Groups and Contacts
    ProfileImage = b'i',

    /// For Chats
    /// Signals whether the chat is the `saved messages` chat
    Selftalk = b'K',

    /// For Chats: On sending a new message we set the subject to `Re: <last subject>`.
    /// Usually we just use the subject of the parent message, but if the parent message
    /// is deleted, we use the LastSubject of the chat.
    LastSubject = b't',

    /// For Chats
    Devicetalk = b'D',

    /// For Chats: If this is a mailing list chat, contains the List-Post address.
    /// None if there simply is no `List-Post` header in the mailing list.
    /// Some("") if the mailing list is using multiple different List-Post headers.
    ///
    /// The List-Post address is the email address where the user can write to in order to
    /// post something to the mailing list.
    ListPost = b'p',

    /// For Contacts: If this is the List-Post address of a mailing list, contains
    /// the List-Id of the mailing list (which is also used as the group id of the chat).
    ListId = b's',

    /// For Contacts: timestamp of status (aka signature or footer) update.
    StatusTimestamp = b'j',

    /// For Contacts and Chats: timestamp of avatar update.
    AvatarTimestamp = b'J',

    /// For Chats: timestamp of status/signature/footer update.
    EphemeralSettingsTimestamp = b'B',

    /// For Chats: timestamp of subject update.
    SubjectTimestamp = b'C',

    /// For Chats: timestamp of group name update.
    GroupNameTimestamp = b'g',

    /// For Chats: timestamp of member list update.
    MemberListTimestamp = b'k',

    /// For Webxdc Message Instances: Current document name
    WebxdcDocument = b'R',

    /// For Webxdc Message Instances: timestamp of document name update.
    WebxdcDocumentTimestamp = b'W',

    /// For Webxdc Message Instances: Current summary
    WebxdcSummary = b'N',

    /// For Webxdc Message Instances: timestamp of summary update.
    WebxdcSummaryTimestamp = b'Q',

    /// For Webxdc Message Instances: Webxdc is an integration, see init_webxdc_integration()
    WebxdcIntegration = b'3',

    /// For Webxdc Message Instances: Chat to integrate the Webxdc for.
    WebxdcIntegrateFor = b'2',

    /// For messages: Whether [crate::message::Viewtype::Sticker] should be forced.
    ForceSticker = b'X',

    /// For messages: Message is a deletion request. The value is a list of rfc724_mid of the messages to delete.
    DeleteRequestFor = b'M',

    /// For messages: Message is a text edit message. the value of this parameter is the rfc724_mid of the original message.
    TextEditFor = b'I',

    /// For messages: Message text was edited.
    IsEdited = b'L',

    /// For info messages: Contact ID in added or removed to a group.
    ContactAddedRemoved = b'5',
}

/// An object for handling key=value parameter lists.
///
/// The structure is serialized by calling `to_string()` on it.
///
/// Only for library-internal use.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Params {
    inner: BTreeMap<Param, String>,
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (key, value)) in self.inner.iter().enumerate() {
            if i > 0 {
                writeln!(f)?;
            }
            write!(
                f,
                "{}={}",
                *key as u8 as char,
                value.split('\n').collect::<Vec<&str>>().join("\n\n")
            )?;
        }
        Ok(())
    }
}

impl str::FromStr for Params {
    type Err = Error;

    /// Parse a raw string to Param.
    ///
    /// Silently ignore unknown keys:
    /// they may come from a downgrade (when a shortly new version adds a key)
    /// or from an upgrade (when a key is dropped but was used in the past)
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut inner = BTreeMap::new();
        let mut lines = s.split('\n').peekable();

        while let Some(line) = lines.next() {
            if let [key, value] = line.splitn(2, '=').collect::<Vec<_>>()[..] {
                let key = key.to_string();
                let mut value = value.to_string();
                while let Some(s) = lines.peek() {
                    if !s.is_empty() {
                        break;
                    }
                    lines.next();
                    value.push('\n');
                    value += lines.next().unwrap_or_default();
                }

                if let Some(key) = key.as_bytes().first().and_then(|key| Param::from_u8(*key)) {
                    inner.insert(key, value);
                }
            } else {
                bail!("Not a key-value pair: {line:?}");
            }
        }

        Ok(Params { inner })
    }
}

impl Params {
    /// Create new empty params.
    pub fn new() -> Self {
        Default::default()
    }

    /// Get the value of the given key, return `None` if no value is set.
    pub fn get(&self, key: Param) -> Option<&str> {
        self.inner.get(&key).map(|s| s.as_str())
    }

    /// Check if the given key is set.
    pub fn exists(&self, key: Param) -> bool {
        self.inner.contains_key(&key)
    }

    /// Set the given key to the passed in value.
    pub fn set(&mut self, key: Param, value: impl ToString) -> &mut Self {
        if key == Param::File {
            debug_assert!(value.to_string().starts_with("$BLOBDIR/"));
        }
        self.inner.insert(key, value.to_string());
        self
    }

    /// Removes the given key, if it exists.
    pub fn remove(&mut self, key: Param) -> &mut Self {
        self.inner.remove(&key);
        self
    }

    /// Sets the given key from an optional value.
    /// Removes the key if the value is `None`.
    pub fn set_optional(&mut self, key: Param, value: Option<impl ToString>) -> &mut Self {
        if let Some(value) = value {
            self.set(key, value)
        } else {
            self.remove(key)
        }
    }

    /// Check if there are any values in this.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns how many key-value pairs are set.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Get the given parameter and parse as `i32`.
    pub fn get_int(&self, key: Param) -> Option<i32> {
        self.get(key).and_then(|s| s.parse().ok())
    }

    /// Get the given parameter and parse as `i64`.
    pub fn get_i64(&self, key: Param) -> Option<i64> {
        self.get(key).and_then(|s| s.parse().ok())
    }

    /// Get the given parameter and parse as `bool`.
    pub fn get_bool(&self, key: Param) -> Option<bool> {
        self.get_int(key).map(|v| v != 0)
    }

    /// Get the parameter behind `Param::Cmd` interpreted as `SystemMessage`.
    pub fn get_cmd(&self) -> SystemMessage {
        self.get_int(Param::Cmd)
            .and_then(SystemMessage::from_i32)
            .unwrap_or_default()
    }

    /// Set the parameter behind `Param::Cmd`.
    pub fn set_cmd(&mut self, value: SystemMessage) {
        self.set_int(Param::Cmd, value as i32);
    }

    /// Get the given parameter and parse as `f64`.
    pub fn get_float(&self, key: Param) -> Option<f64> {
        self.get(key).and_then(|s| s.parse().ok())
    }

    /// Returns a [BlobObject] for the [Param::File] parameter.
    pub fn get_file_blob<'a>(&self, context: &'a Context) -> Result<Option<BlobObject<'a>>> {
        let Some(val) = self.get(Param::File) else {
            return Ok(None);
        };
        ensure!(val.starts_with("$BLOBDIR/"));
        let blob = BlobObject::from_name(context, val)?;
        Ok(Some(blob))
    }

    /// Returns a [PathBuf] for the [Param::File] parameter.
    pub fn get_file_path(&self, context: &Context) -> Result<Option<PathBuf>> {
        let blob = self.get_file_blob(context)?;
        Ok(blob.map(|p| p.to_abs_path()))
    }

    /// Set the given parameter to the passed in `i32`.
    pub fn set_int(&mut self, key: Param, value: i32) -> &mut Self {
        self.set(key, format!("{value}"));
        self
    }

    /// Set the given parameter to the passed in `i64`.
    pub fn set_i64(&mut self, key: Param, value: i64) -> &mut Self {
        self.set(key, value.to_string());
        self
    }

    /// Set the given parameter to the passed in `f64` .
    pub fn set_float(&mut self, key: Param, value: f64) -> &mut Self {
        self.set(key, format!("{value}"));
        self
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_dc_param() {
        let mut p1: Params = "a=1\nw=2\nc=3".parse().unwrap();

        assert_eq!(p1.get_int(Param::Forwarded), Some(1));
        assert_eq!(p1.get_int(Param::Width), Some(2));
        assert_eq!(p1.get_int(Param::Height), None);
        assert!(!p1.exists(Param::Height));

        p1.set_int(Param::Duration, 4);

        assert_eq!(p1.get_int(Param::Duration), Some(4));

        let mut p1 = Params::new();

        p1.set(Param::Forwarded, "foo")
            .set_int(Param::Width, 2)
            .remove(Param::GuaranteeE2ee)
            .set_int(Param::Duration, 4);

        assert_eq!(p1.to_string(), "a=foo\nd=4\nw=2");

        p1.remove(Param::Width);

        assert_eq!(p1.to_string(), "a=foo\nd=4",);
        assert_eq!(p1.len(), 2);

        p1.remove(Param::Forwarded);
        p1.remove(Param::Duration);

        assert_eq!(p1.to_string(), "",);

        assert!(p1.is_empty());
        assert_eq!(p1.len(), 0)
    }

    #[test]
    fn test_roundtrip() {
        let mut params = Params::new();
        params.set(Param::Height, "foo\nbar=baz\nquux");
        params.set(Param::Width, "\n\n\na=\n=");
        params.set(Param::WebrtcRoom, "foo\r\nbar\r\n\r\nbaz\r\n");
        assert_eq!(params.to_string().parse::<Params>().unwrap(), params);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_params_unknown_key() -> Result<()> {
        // 'Z' is used as a key that is known to be unused; these keys should be ignored silently by definition.
        let p = Params::from_str("w=12\nZ=13\nh=14")?;
        assert_eq!(p.len(), 2);
        assert_eq!(p.get(Param::Width), Some("12"));
        assert_eq!(p.get(Param::Height), Some("14"));
        Ok(())
    }
}
