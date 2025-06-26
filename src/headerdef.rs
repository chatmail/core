//! # List of email headers.

use mailparse::{MailHeader, MailHeaderMap};

#[derive(Debug, Display, Clone, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "kebab_case")]
#[allow(missing_docs)]
pub enum HeaderDef {
    MessageId,
    Subject,
    Date,
    From_,
    To,
    AutoSubmitted,

    /// Carbon copy.
    Cc,
    Disposition,

    /// Used in the "Body Part Header" of MDNs as of RFC 8098.
    /// Indicates the Message-ID of the message for which the MDN is being issued.
    OriginalMessageId,

    /// Delta Chat extension for message IDs in combined MDNs
    AdditionalMessageIds,

    /// Outlook-SMTP-server replace the `Message-ID:`-header
    /// and write the original ID to `X-Microsoft-Original-Message-ID`.
    /// To sort things correctly and to not show outgoing messages twice,
    /// we need to check that header as well.
    XMicrosoftOriginalMessageId,

    /// Thunderbird header used to store Draft information.
    ///
    /// Thunderbird 78.11.0 does not set \Draft flag on messages saved as "Template", but sets this
    /// header, so it can be used to ignore such messages.
    XMozillaDraftInfo,

    /// Mailing list ID defined in [RFC 2919](https://tools.ietf.org/html/rfc2919).
    ListId,
    ListPost,

    /// List-Help header defined in [RFC 2369](https://datatracker.ietf.org/doc/html/rfc2369).
    ListHelp,
    References,

    /// In-Reply-To header containing Message-ID of the parent message.
    InReplyTo,

    /// Used to detect mailing lists if contains "list" value
    /// as described in [RFC 3834](https://tools.ietf.org/html/rfc3834)
    Precedence,

    ContentType,
    ContentId,
    ChatVersion,
    ChatGroupId,
    ChatGroupName,
    ChatGroupNameChanged,
    ChatGroupNameTimestamp,
    ChatVerified,
    ChatGroupAvatar,
    ChatUserAvatar,
    ChatVoiceMessage,
    ChatGroupMemberRemoved,
    ChatGroupMemberAdded,
    ChatContent,

    /// Past members of the group.
    ChatGroupPastMembers,

    /// Space-separated timestamps of member addition
    /// for members listed in the `To` field
    /// followed by timestamps of member removal
    /// for members listed in the `Chat-Group-Past-Members` field.
    ChatGroupMemberTimestamps,

    /// Space-separated PGP key fingerprints
    /// of group members listed in the `To` field
    /// followed by fingerprints
    /// of past members listed in the `Chat-Group-Past-Members` field.
    ChatGroupMemberFpr,

    /// Duration of the attached media file.
    ChatDuration,

    ChatDispositionNotificationTo,
    ChatWebrtcRoom,

    /// This message deletes the messages listed in the value by rfc724_mid.
    ChatDelete,

    /// This message obsoletes the text of the message defined here by rfc724_mid.
    ChatEdit,

    /// [Autocrypt](https://autocrypt.org/) header.
    Autocrypt,
    AutocryptGossip,
    AutocryptSetupMessage,
    SecureJoin,

    /// Deprecated header containing Group-ID in `vg-request-with-auth` message.
    ///
    /// It is not used by Alice as Alice knows the group corresponding to the AUTH token.
    /// Bob still sends it for backwards compatibility.
    SecureJoinGroup,
    SecureJoinFingerprint,
    SecureJoinInvitenumber,
    SecureJoinAuth,
    Sender,

    /// Ephemeral message timer.
    EphemeralTimer,
    Received,

    /// A header that includes the results of the DKIM, SPF and DMARC checks.
    /// See <https://datatracker.ietf.org/doc/html/rfc8601>
    AuthenticationResults,

    /// Node address from iroh where direct addresses have been removed.
    IrohNodeAddr,

    /// Advertised gossip topic for one webxdc.
    IrohGossipTopic,

    #[cfg(test)]
    TestHeader,
}

impl HeaderDef {
    /// Returns the corresponding header string.
    pub fn get_headername(&self) -> &'static str {
        self.into()
    }
}

#[allow(missing_docs)]
pub trait HeaderDefMap {
    /// Returns requested header value if it exists.
    fn get_header_value(&self, headerdef: HeaderDef) -> Option<String>;

    /// Returns requested header if it exists.
    fn get_header(&self, headerdef: HeaderDef) -> Option<&MailHeader<'_>>;
}

impl HeaderDefMap for [MailHeader<'_>] {
    fn get_header_value(&self, headerdef: HeaderDef) -> Option<String> {
        self.get_first_value(headerdef.get_headername())
    }
    fn get_header(&self, headerdef: HeaderDef) -> Option<&MailHeader<'_>> {
        self.get_first_header(headerdef.get_headername())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Test that kebab_case serialization works as expected
    fn kebab_test() {
        assert_eq!(HeaderDef::From_.get_headername(), "from");

        assert_eq!(HeaderDef::TestHeader.get_headername(), "test-header");
    }

    #[test]
    /// Test that headers are parsed case-insensitively
    fn test_get_header_value_case() {
        let (headers, _) =
            mailparse::parse_headers(b"fRoM: Bob\naUtoCryPt-SeTup-MessAge: v99").unwrap();
        assert_eq!(
            headers.get_header_value(HeaderDef::AutocryptSetupMessage),
            Some("v99".to_string())
        );
        assert_eq!(
            headers.get_header_value(HeaderDef::From_),
            Some("Bob".to_string())
        );
        assert_eq!(headers.get_header_value(HeaderDef::Autocrypt), None);
    }
}
