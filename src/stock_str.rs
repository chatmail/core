//! Module to work with translatable stock strings.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, bail};
use parking_lot::RwLock;
use strum::EnumProperty as EnumPropertyTrait;
use strum_macros::EnumProperty;

use crate::accounts::Accounts;
use crate::blob::BlobObject;
use crate::chat::{self, Chat, ChatId};
use crate::config::Config;
use crate::contact::{Contact, ContactId};
use crate::context::Context;
use crate::message::{Message, Viewtype};
use crate::param::Param;

/// Storage for string translations.
#[derive(Debug, Clone)]
pub struct StockStrings {
    /// Map from stock string ID to the translation.
    translated_stockstrings: Arc<RwLock<HashMap<usize, String>>>,
}

/// Stock strings
///
/// These identify the string to return in [Context.stock_str].  The
/// numbers must stay in sync with `deltachat.h` `DC_STR_*` constants.
///
/// See the `stock_*` methods on [Context] to use these.
///
/// [Context]: crate::context::Context
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive, EnumProperty)]
#[repr(u32)]
pub enum StockMessage {
    #[strum(props(fallback = "No messages."))]
    NoMessages = 1,

    #[strum(props(fallback = "Me"))]
    SelfMsg = 2,

    #[strum(props(fallback = "Draft"))]
    Draft = 3,

    #[strum(props(fallback = "Voice message"))]
    VoiceMessage = 7,

    #[strum(props(fallback = "Image"))]
    Image = 9,

    #[strum(props(fallback = "Video"))]
    Video = 10,

    #[strum(props(fallback = "Audio"))]
    Audio = 11,

    #[strum(props(fallback = "File"))]
    File = 12,

    #[strum(props(fallback = "GIF"))]
    Gif = 23,

    #[strum(props(fallback = "No encryption."))]
    EncrNone = 28,

    #[strum(props(fallback = "Fingerprints"))]
    FingerPrints = 30,

    #[strum(props(fallback = "%1$s verified."))]
    ContactVerified = 35,

    #[strum(props(fallback = "Archived chats"))]
    ArchivedChats = 40,

    #[strum(props(
        fallback = "Cannot login as \"%1$s\". Please check if the email address and the password are correct."
    ))]
    CannotLogin = 60,

    #[strum(props(fallback = "Location streaming enabled."))]
    MsgLocationEnabled = 64,

    #[strum(props(fallback = "Location streaming disabled."))]
    MsgLocationDisabled = 65,

    #[strum(props(fallback = "Location"))]
    Location = 66,

    #[strum(props(fallback = "Sticker"))]
    Sticker = 67,

    #[strum(props(fallback = "Device messages"))]
    DeviceMessages = 68,

    #[strum(props(fallback = "Saved messages"))]
    SavedMessages = 69,

    #[strum(props(
        fallback = "Messages in this chat are generated locally by your Delta Chat app. \
                    Its makers use it to inform about app updates and problems during usage."
    ))]
    DeviceMessagesHint = 70,

    #[strum(props(fallback = "Get in contact!\n\n\
                    🙌 Tap \"QR code\" on the main screen of both devices. \
                    Choose \"Scan QR Code\" on one device, and point it at the other\n\n\
                    🌍 If not in the same room, \
                    scan via video call or share an invite link from \"Scan QR code\"\n\n\
                    Then: Enjoy your decentralized messenger experience. \
                    In contrast to other popular apps, \
                    without central control or tracking or selling you, \
                    friends, colleagues or family out to large organizations."))]
    WelcomeMessage = 71,

    #[strum(props(fallback = "Message from %1$s"))]
    SubjectForNewContact = 73,

    /// Unused. Was used in group chat status messages.
    #[strum(props(fallback = "Failed to send message to %1$s."))]
    FailedSendingTo = 74,

    #[strum(props(fallback = "Error:\n\n“%1$s”"))]
    ConfigurationFailed = 84,

    #[strum(props(
        fallback = "⚠️ Date or time of your device seem to be inaccurate (%1$s).\n\n\
                    Adjust your clock ⏰🔧 to ensure your messages are received correctly."
    ))]
    BadTimeMsgBody = 85,

    #[strum(props(fallback = "⚠️ Your Delta Chat version might be outdated.\n\n\
                    This may cause problems because your chat partners use newer versions - \
                    and you are missing the latest features 😳\n\
                    Please check https://get.delta.chat or your app store for updates."))]
    UpdateReminderMsgBody = 86,

    #[strum(props(
        fallback = "Could not find your mail server.\n\nPlease check your internet connection."
    ))]
    ErrorNoNetwork = 87,

    // used in summaries, a noun, not a verb (not: "to reply")
    #[strum(props(fallback = "Reply"))]
    ReplyNoun = 90,

    #[strum(props(fallback = "You deleted the \"Saved messages\" chat.\n\n\
                    To use the \"Saved messages\" feature again, create a new chat with yourself."))]
    SelfDeletedMsgBody = 91,

    #[strum(props(fallback = "Forwarded"))]
    Forwarded = 97,

    #[strum(props(
        fallback = "⚠️ Your provider's storage is about to exceed, already %1$s%% are used.\n\n\
                    You may not be able to receive message when the storage is 100%% used.\n\n\
                    👉 Please check if you can delete old data in the provider's webinterface \
                    and consider to enable \"Settings / Delete Old Messages\". \
                    You can check your current storage usage anytime at \"Settings / Connectivity\"."
    ))]
    QuotaExceedingMsgBody = 98,

    #[strum(props(fallback = "Multi Device Synchronization"))]
    SyncMsgSubject = 101,

    #[strum(props(
        fallback = "This message is used to synchronize data between your devices.\n\n\
                    👉 If you see this message in Delta Chat, please update your Delta Chat apps on all devices."
    ))]
    SyncMsgBody = 102,

    #[strum(props(fallback = "Incoming Messages"))]
    IncomingMessages = 103,

    #[strum(props(fallback = "Outgoing Messages"))]
    OutgoingMessages = 104,

    #[strum(props(fallback = "Storage on %1$s"))]
    StorageOnDomain = 105,

    #[strum(props(fallback = "Connected"))]
    Connected = 107,

    #[strum(props(fallback = "Connecting…"))]
    Connecting = 108,

    #[strum(props(fallback = "Updating…"))]
    Updating = 109,

    #[strum(props(fallback = "Sending…"))]
    Sending = 110,

    #[strum(props(fallback = "Your last message was sent successfully."))]
    LastMsgSentSuccessfully = 111,

    #[strum(props(fallback = "Error: %1$s"))]
    Error = 112,

    #[strum(props(fallback = "Not supported by your provider."))]
    NotSupportedByProvider = 113,

    #[strum(props(fallback = "Messages"))]
    Messages = 114,

    #[strum(props(fallback = "%1$s of %2$s used"))]
    PartOfTotallUsed = 116,

    #[strum(props(fallback = "%1$s invited you to join this group.\n\n\
                             Waiting for the device of %2$s to reply…"))]
    SecureJoinStarted = 117,

    #[strum(props(fallback = "%1$s replied, waiting for being added to the group…"))]
    SecureJoinReplies = 118,

    #[strum(props(fallback = "Scan to chat with %1$s"))]
    SetupContactQRDescription = 119,

    #[strum(props(fallback = "Scan to join group %1$s"))]
    SecureJoinGroupQRDescription = 120,

    #[strum(props(fallback = "Not connected"))]
    NotConnected = 121,

    #[strum(props(fallback = "You changed group name from \"%1$s\" to \"%2$s\"."))]
    MsgYouChangedGrpName = 124,

    #[strum(props(fallback = "Group name changed from \"%1$s\" to \"%2$s\" by %3$s."))]
    MsgGrpNameChangedBy = 125,

    #[strum(props(fallback = "You changed the group image."))]
    MsgYouChangedGrpImg = 126,

    #[strum(props(fallback = "Group image changed by %1$s."))]
    MsgGrpImgChangedBy = 127,

    #[strum(props(fallback = "You added member %1$s."))]
    MsgYouAddMember = 128,

    #[strum(props(fallback = "Member %1$s added by %2$s."))]
    MsgAddMemberBy = 129,

    #[strum(props(fallback = "You removed member %1$s."))]
    MsgYouDelMember = 130,

    #[strum(props(fallback = "Member %1$s removed by %2$s."))]
    MsgDelMemberBy = 131,

    #[strum(props(fallback = "You left the group."))]
    MsgYouLeftGroup = 132,

    #[strum(props(fallback = "Group left by %1$s."))]
    MsgGroupLeftBy = 133,

    #[strum(props(fallback = "You deleted the group image."))]
    MsgYouDeletedGrpImg = 134,

    #[strum(props(fallback = "Group image deleted by %1$s."))]
    MsgGrpImgDeletedBy = 135,

    #[strum(props(fallback = "You enabled location streaming."))]
    MsgYouEnabledLocation = 136,

    #[strum(props(fallback = "Location streaming enabled by %1$s."))]
    MsgLocationEnabledBy = 137,

    #[strum(props(fallback = "You disabled message deletion timer."))]
    MsgYouDisabledEphemeralTimer = 138,

    #[strum(props(fallback = "Message deletion timer is disabled by %1$s."))]
    MsgEphemeralTimerDisabledBy = 139,

    // A fallback message for unknown timer values.
    // "s" stands for "second" SI unit here.
    #[strum(props(fallback = "You set message deletion timer to %1$s s."))]
    MsgYouEnabledEphemeralTimer = 140,

    #[strum(props(fallback = "Message deletion timer is set to %1$s s by %2$s."))]
    MsgEphemeralTimerEnabledBy = 141,

    #[strum(props(fallback = "You set message deletion timer to 1 hour."))]
    MsgYouEphemeralTimerHour = 144,

    #[strum(props(fallback = "Message deletion timer is set to 1 hour by %1$s."))]
    MsgEphemeralTimerHourBy = 145,

    #[strum(props(fallback = "You set message deletion timer to 1 day."))]
    MsgYouEphemeralTimerDay = 146,

    #[strum(props(fallback = "Message deletion timer is set to 1 day by %1$s."))]
    MsgEphemeralTimerDayBy = 147,

    #[strum(props(fallback = "You set message deletion timer to 1 week."))]
    MsgYouEphemeralTimerWeek = 148,

    #[strum(props(fallback = "Message deletion timer is set to 1 week by %1$s."))]
    MsgEphemeralTimerWeekBy = 149,

    #[strum(props(fallback = "You set message deletion timer to %1$s minutes."))]
    MsgYouEphemeralTimerMinutes = 150,

    #[strum(props(fallback = "Message deletion timer is set to %1$s minutes by %2$s."))]
    MsgEphemeralTimerMinutesBy = 151,

    #[strum(props(fallback = "You set message deletion timer to %1$s hours."))]
    MsgYouEphemeralTimerHours = 152,

    #[strum(props(fallback = "Message deletion timer is set to %1$s hours by %2$s."))]
    MsgEphemeralTimerHoursBy = 153,

    #[strum(props(fallback = "You set message deletion timer to %1$s days."))]
    MsgYouEphemeralTimerDays = 154,

    #[strum(props(fallback = "Message deletion timer is set to %1$s days by %2$s."))]
    MsgEphemeralTimerDaysBy = 155,

    #[strum(props(fallback = "You set message deletion timer to %1$s weeks."))]
    MsgYouEphemeralTimerWeeks = 156,

    #[strum(props(fallback = "Message deletion timer is set to %1$s weeks by %2$s."))]
    MsgEphemeralTimerWeeksBy = 157,

    #[strum(props(fallback = "You set message deletion timer to 1 year."))]
    MsgYouEphemeralTimerYear = 158,

    #[strum(props(fallback = "Message deletion timer is set to 1 year by %1$s."))]
    MsgEphemeralTimerYearBy = 159,

    #[strum(props(fallback = "Scan to set up second device for %1$s"))]
    BackupTransferQr = 162,

    #[strum(props(fallback = "ℹ️ Account transferred to your second device."))]
    BackupTransferMsgBody = 163,

    #[strum(props(fallback = "Messages are end-to-end encrypted."))]
    ChatProtectionEnabled = 170,

    #[strum(props(fallback = "Others will only see this group after you sent a first message."))]
    NewGroupSendFirstMessage = 172,

    #[strum(props(fallback = "Member %1$s added."))]
    MsgAddMember = 173,

    #[strum(props(
        fallback = "⚠️ Your email provider %1$s requires end-to-end encryption which is not setup yet."
    ))]
    InvalidUnencryptedMail = 174,

    #[strum(props(fallback = "You reacted %1$s to \"%2$s\""))]
    MsgYouReacted = 176,

    #[strum(props(fallback = "%1$s reacted %2$s to \"%3$s\""))]
    MsgReactedBy = 177,

    #[strum(props(fallback = "Member %1$s removed."))]
    MsgDelMember = 178,

    #[strum(props(fallback = "Establishing connection, please wait…"))]
    SecurejoinWait = 190,

    #[strum(props(fallback = "❤️ Seems you're enjoying Delta Chat!

Please consider donating to help that Delta Chat stays free for everyone.

While Delta Chat is free to use and open source, development costs money.
Help keeping us to keep Delta Chat independent and make it more awesome in the future.

https://delta.chat/donate"))]
    DonationRequest = 193,

    #[strum(props(fallback = "Declined call"))]
    DeclinedCall = 196,

    #[strum(props(fallback = "Canceled call"))]
    CanceledCall = 197,

    #[strum(props(fallback = "Missed call"))]
    MissedCall = 198,

    #[strum(props(fallback = "You left the channel."))]
    MsgYouLeftBroadcast = 200,

    #[strum(props(fallback = "Scan to join channel %1$s"))]
    SecureJoinBrodcastQRDescription = 201,

    #[strum(props(fallback = "You joined the channel."))]
    MsgYouJoinedBroadcast = 202,

    #[strum(props(fallback = "%1$s invited you to join this channel.\n\n\
                             Waiting for the device of %2$s to reply…"))]
    SecureJoinBroadcastStarted = 203,

    #[strum(props(fallback = "Channel name changed from \"%1$s\" to \"%2$s\"."))]
    MsgBroadcastNameChanged = 204,

    #[strum(props(fallback = "Channel image changed."))]
    MsgBroadcastImgChanged = 205,

    #[strum(props(
        fallback = "The attachment contains anonymous usage statistics, which helps us improve Delta Chat. Thank you!"
    ))]
    StatsMsgBody = 210,

    #[strum(props(fallback = "Proxy Enabled"))]
    ProxyEnabled = 220,

    #[strum(props(
        fallback = "You are using a proxy. If you're having trouble connecting, try a different proxy."
    ))]
    ProxyEnabledDescription = 221,

    #[strum(props(fallback = "Messages in this chat use classic email and are not encrypted."))]
    ChatUnencryptedExplanation = 230,

    #[strum(props(
        fallback = "You are using the legacy option \"Settings → Advanced → Move automatically to DeltaChat Folder\".\n\nThis option will be removed in a few weeks and you should disable it already today.\n\nIf having chat messages mixed into your inbox is a problem, see https://delta.chat/legacy-move"
    ))]
    MvboxMoveDeprecation = 231,

    #[strum(props(fallback = "Outgoing audio call"))]
    OutgoingAudioCall = 232,

    #[strum(props(fallback = "Outgoing video call"))]
    OutgoingVideoCall = 233,

    #[strum(props(fallback = "Incoming audio call"))]
    IncomingAudioCall = 234,

    #[strum(props(fallback = "Incoming video call"))]
    IncomingVideoCall = 235,

    #[strum(props(fallback = "You changed the chat description."))]
    MsgYouChangedDescription = 240,

    #[strum(props(fallback = "Chat description changed by %1$s."))]
    MsgChatDescriptionChangedBy = 241,

    #[strum(props(fallback = "Messages are end-to-end encrypted."))]
    MessagesAreE2ee = 242,
}

impl StockMessage {
    /// Default untranslated strings for stock messages.
    ///
    /// These could be used in logging calls, so no logging here.
    fn fallback(self) -> &'static str {
        self.get_str("fallback").unwrap_or_default()
    }
}

impl Default for StockStrings {
    fn default() -> Self {
        StockStrings::new()
    }
}

impl StockStrings {
    /// Creates a new translated string storage.
    pub fn new() -> Self {
        Self {
            translated_stockstrings: Arc::new(RwLock::new(Default::default())),
        }
    }

    fn translated(&self, id: StockMessage) -> String {
        self.translated_stockstrings
            .read()
            .get(&(id as usize))
            .map(AsRef::as_ref)
            .unwrap_or_else(|| id.fallback())
            .to_string()
    }

    fn set_stock_translation(&self, id: StockMessage, stockstring: String) -> Result<()> {
        if stockstring.contains("%1") && !id.fallback().contains("%1") {
            bail!(
                "translation {} contains invalid %1 placeholder, default is {}",
                stockstring,
                id.fallback()
            );
        }
        if stockstring.contains("%2") && !id.fallback().contains("%2") {
            bail!(
                "translation {} contains invalid %2 placeholder, default is {}",
                stockstring,
                id.fallback()
            );
        }
        self.translated_stockstrings
            .write()
            .insert(id as usize, stockstring);
        Ok(())
    }
}

fn translated(context: &Context, id: StockMessage) -> String {
    context.translated_stockstrings.translated(id)
}

/// Helper trait only meant to be implemented for [`String`].
trait StockStringMods: AsRef<str> + Sized {
    /// Substitutes the first replacement value if one is present.
    fn replace1(&self, replacement: &str) -> String {
        self.as_ref()
            .replacen("%1$s", replacement, 1)
            .replacen("%1$d", replacement, 1)
            .replacen("%1$@", replacement, 1)
    }

    /// Substitutes the second replacement value if one is present.
    ///
    /// Be aware you probably should have also called [`StockStringMods::replace1`] if
    /// you are calling this.
    fn replace2(&self, replacement: &str) -> String {
        self.as_ref()
            .replacen("%2$s", replacement, 1)
            .replacen("%2$d", replacement, 1)
            .replacen("%2$@", replacement, 1)
    }

    /// Substitutes the third replacement value if one is present.
    ///
    /// Be aware you probably should have also called [`StockStringMods::replace1`] and
    /// [`StockStringMods::replace2`] if you are calling this.
    fn replace3(&self, replacement: &str) -> String {
        self.as_ref()
            .replacen("%3$s", replacement, 1)
            .replacen("%3$d", replacement, 1)
            .replacen("%3$@", replacement, 1)
    }
}

impl ContactId {
    /// Get contact name, e.g. `Bob`, or `bob@example.net` if no name is set.
    async fn get_stock_name(self, context: &Context) -> String {
        Contact::get_by_id(context, self)
            .await
            .map(|contact| contact.get_display_name().to_string())
            .unwrap_or_else(|_| self.to_string())
    }
}

impl StockStringMods for String {}

/// Stock string: `No messages.`.
pub(crate) fn no_messages(context: &Context) -> String {
    translated(context, StockMessage::NoMessages)
}

/// Stock string: `Me`.
pub(crate) fn self_msg(context: &Context) -> String {
    translated(context, StockMessage::SelfMsg)
}

/// Stock string: `Draft`.
pub(crate) fn draft(context: &Context) -> String {
    translated(context, StockMessage::Draft)
}

/// Stock string: `Voice message`.
pub(crate) fn voice_message(context: &Context) -> String {
    translated(context, StockMessage::VoiceMessage)
}

/// Stock string: `Image`.
pub(crate) fn image(context: &Context) -> String {
    translated(context, StockMessage::Image)
}

/// Stock string: `Video`.
pub(crate) fn video(context: &Context) -> String {
    translated(context, StockMessage::Video)
}

/// Stock string: `Audio`.
pub(crate) fn audio(context: &Context) -> String {
    translated(context, StockMessage::Audio)
}

/// Stock string: `File`.
pub(crate) fn file(context: &Context) -> String {
    translated(context, StockMessage::File)
}

/// Stock string: `Group name changed from "%1$s" to "%2$s".`.
pub(crate) async fn msg_grp_name(
    context: &Context,
    from_group: &str,
    to_group: &str,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouChangedGrpName)
            .replace1(from_group)
            .replace2(to_group)
    } else {
        translated(context, StockMessage::MsgGrpNameChangedBy)
            .replace1(from_group)
            .replace2(to_group)
            .replace3(&by_contact.get_stock_name(context).await)
    }
}

pub(crate) async fn msg_grp_img_changed(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouChangedGrpImg)
    } else {
        translated(context, StockMessage::MsgGrpImgChangedBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

pub(crate) async fn msg_chat_description_changed(
    context: &Context,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouChangedDescription)
    } else {
        translated(context, StockMessage::MsgChatDescriptionChangedBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Member %1$s added.`, `You added member %1$s.` or `Member %1$s added by %2$s.`.
///
/// The `added_member` and `by_contact` contacts
/// are looked up in the database to get the display names.
pub(crate) async fn msg_add_member_local(
    context: &Context,
    added_member: ContactId,
    by_contact: ContactId,
) -> String {
    let whom = added_member.get_stock_name(context).await;
    if by_contact == ContactId::UNDEFINED {
        translated(context, StockMessage::MsgAddMember).replace1(&whom)
    } else if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouAddMember).replace1(&whom)
    } else {
        translated(context, StockMessage::MsgAddMemberBy)
            .replace1(&whom)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Member %1$s removed.` or `You removed member %1$s.` or `Member %1$s removed by %2$s.`
///
/// The `removed_member` and `by_contact` contacts
/// are looked up in the database to get the display names.
pub(crate) async fn msg_del_member_local(
    context: &Context,
    removed_member: ContactId,
    by_contact: ContactId,
) -> String {
    let whom = removed_member.get_stock_name(context).await;
    if by_contact == ContactId::UNDEFINED {
        translated(context, StockMessage::MsgDelMember).replace1(&whom)
    } else if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouDelMember).replace1(&whom)
    } else {
        translated(context, StockMessage::MsgDelMemberBy)
            .replace1(&whom)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `You left the group.` or `Group left by %1$s.`.
pub(crate) async fn msg_group_left_local(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouLeftGroup)
    } else {
        translated(context, StockMessage::MsgGroupLeftBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `You left the channel.`
pub(crate) fn msg_you_left_broadcast(context: &Context) -> String {
    translated(context, StockMessage::MsgYouLeftBroadcast)
}

/// Stock string: `You joined the channel.`
pub(crate) fn msg_you_joined_broadcast(context: &Context) -> String {
    translated(context, StockMessage::MsgYouJoinedBroadcast)
}

/// Stock string: `%1$s invited you to join this channel. Waiting for the device of %2$s to reply…`.
pub(crate) async fn secure_join_broadcast_started(
    context: &Context,
    inviter_contact_id: ContactId,
) -> String {
    if let Ok(contact) = Contact::get_by_id(context, inviter_contact_id).await {
        translated(context, StockMessage::SecureJoinBroadcastStarted)
            .replace1(contact.get_display_name())
            .replace2(contact.get_display_name())
    } else {
        format!("secure_join_started: unknown contact {inviter_contact_id}")
    }
}

/// Stock string: `Channel name changed from "1%s" to "2$s".`
pub(crate) fn msg_broadcast_name_changed(context: &Context, from: &str, to: &str) -> String {
    translated(context, StockMessage::MsgBroadcastNameChanged)
        .replace1(from)
        .replace2(to)
}

/// Stock string `Channel image changed.`
pub(crate) fn msg_broadcast_img_changed(context: &Context) -> String {
    translated(context, StockMessage::MsgBroadcastImgChanged)
}

/// Stock string: `You reacted %1$s to "%2$s"` or `%1$s reacted %2$s to "%3$s"`.
pub(crate) async fn msg_reacted(
    context: &Context,
    by_contact: ContactId,
    reaction: &str,
    summary: &str,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouReacted)
            .replace1(reaction)
            .replace2(summary)
    } else {
        translated(context, StockMessage::MsgReactedBy)
            .replace1(&by_contact.get_stock_name(context).await)
            .replace2(reaction)
            .replace3(summary)
    }
}

/// Stock string: `GIF`.
pub(crate) fn gif(context: &Context) -> String {
    translated(context, StockMessage::Gif)
}

/// Stock string: `No encryption.`.
pub(crate) fn encr_none(context: &Context) -> String {
    translated(context, StockMessage::EncrNone)
}

/// Stock string: `Fingerprints`.
pub(crate) fn finger_prints(context: &Context) -> String {
    translated(context, StockMessage::FingerPrints)
}

/// Stock string: `Group image deleted.`.
pub(crate) async fn msg_grp_img_deleted(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouDeletedGrpImg)
    } else {
        translated(context, StockMessage::MsgGrpImgDeletedBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `%1$s invited you to join this group. Waiting for the device of %2$s to reply…`.
pub(crate) async fn secure_join_started(
    context: &Context,
    inviter_contact_id: ContactId,
) -> String {
    if let Ok(contact) = Contact::get_by_id(context, inviter_contact_id).await {
        translated(context, StockMessage::SecureJoinStarted)
            .replace1(contact.get_display_name())
            .replace2(contact.get_display_name())
    } else {
        format!("secure_join_started: unknown contact {inviter_contact_id}")
    }
}

/// Stock string: `%1$s replied, waiting for being added to the group…`.
pub(crate) async fn secure_join_replies(context: &Context, contact_id: ContactId) -> String {
    translated(context, StockMessage::SecureJoinReplies)
        .replace1(&contact_id.get_stock_name(context).await)
}

/// Stock string: `Establishing connection, please wait…`.
pub(crate) fn securejoin_wait(context: &Context) -> String {
    translated(context, StockMessage::SecurejoinWait)
}

/// Stock string: `❤️ Seems you're enjoying Delta Chat!`…
pub(crate) fn donation_request(context: &Context) -> String {
    translated(context, StockMessage::DonationRequest)
}

/// Stock string: `Outgoing video call` or `Outgoing audio call`.
pub(crate) fn outgoing_call(context: &Context, has_video: bool) -> String {
    translated(
        context,
        if has_video {
            StockMessage::OutgoingVideoCall
        } else {
            StockMessage::OutgoingAudioCall
        },
    )
}

/// Stock string: `Incoming video call` or `Incoming audio call`.
pub(crate) fn incoming_call(context: &Context, has_video: bool) -> String {
    translated(
        context,
        if has_video {
            StockMessage::IncomingVideoCall
        } else {
            StockMessage::IncomingAudioCall
        },
    )
}

/// Stock string: `Declined call`.
pub(crate) fn declined_call(context: &Context) -> String {
    translated(context, StockMessage::DeclinedCall)
}

/// Stock string: `Canceled call`.
pub(crate) fn canceled_call(context: &Context) -> String {
    translated(context, StockMessage::CanceledCall)
}

/// Stock string: `Missed call`.
pub(crate) fn missed_call(context: &Context) -> String {
    translated(context, StockMessage::MissedCall)
}

/// Stock string: `Scan to chat with %1$s`.
pub(crate) fn setup_contact_qr_description(
    context: &Context,
    display_name: &str,
    addr: &str,
) -> String {
    let name = if display_name.is_empty() {
        addr.to_owned()
    } else {
        display_name.to_owned()
    };
    translated(context, StockMessage::SetupContactQRDescription).replace1(&name)
}

/// Stock string: `Scan to join group %1$s`.
pub(crate) fn secure_join_group_qr_description(context: &Context, chat: &Chat) -> String {
    translated(context, StockMessage::SecureJoinGroupQRDescription).replace1(chat.get_name())
}

/// Stock string: `Scan to join channel %1$s`.
pub(crate) fn secure_join_broadcast_qr_description(context: &Context, chat: &Chat) -> String {
    translated(context, StockMessage::SecureJoinBrodcastQRDescription).replace1(chat.get_name())
}

/// Stock string: `%1$s verified.`.
#[allow(dead_code)]
pub(crate) fn contact_verified(context: &Context, contact: &Contact) -> String {
    let addr = contact.get_display_name();
    translated(context, StockMessage::ContactVerified).replace1(addr)
}

/// Stock string: `Archived chats`.
pub(crate) fn archived_chats(context: &Context) -> String {
    translated(context, StockMessage::ArchivedChats)
}

/// Stock string: `Multi Device Synchronization`.
pub(crate) fn sync_msg_subject(context: &Context) -> String {
    translated(context, StockMessage::SyncMsgSubject)
}

/// Stock string: `This message is used to synchronize data between your devices.`.
pub(crate) fn sync_msg_body(context: &Context) -> String {
    translated(context, StockMessage::SyncMsgBody)
}

/// Stock string: `Cannot login as \"%1$s\". Please check...`.
pub(crate) fn cannot_login(context: &Context, user: &str) -> String {
    translated(context, StockMessage::CannotLogin).replace1(user)
}

/// Stock string: `Location streaming enabled.`.
pub(crate) fn msg_location_enabled(context: &Context) -> String {
    translated(context, StockMessage::MsgLocationEnabled)
}

/// Stock string: `Location streaming enabled by ...`.
pub(crate) async fn msg_location_enabled_by(context: &Context, contact: ContactId) -> String {
    if contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEnabledLocation)
    } else {
        translated(context, StockMessage::MsgLocationEnabledBy)
            .replace1(&contact.get_stock_name(context).await)
    }
}

/// Stock string: `Location streaming disabled.`.
pub(crate) fn msg_location_disabled(context: &Context) -> String {
    translated(context, StockMessage::MsgLocationDisabled)
}

/// Stock string: `Location`.
pub(crate) fn location(context: &Context) -> String {
    translated(context, StockMessage::Location)
}

/// Stock string: `Sticker`.
pub(crate) fn sticker(context: &Context) -> String {
    translated(context, StockMessage::Sticker)
}

/// Stock string: `Device messages`.
pub(crate) fn device_messages(context: &Context) -> String {
    translated(context, StockMessage::DeviceMessages)
}

/// Stock string: `Saved messages`.
pub(crate) fn saved_messages(context: &Context) -> String {
    translated(context, StockMessage::SavedMessages)
}

/// Stock string: `Messages in this chat are generated locally by...`.
pub(crate) fn device_messages_hint(context: &Context) -> String {
    translated(context, StockMessage::DeviceMessagesHint)
}

/// Stock string: `Welcome to Delta Chat! – ...`.
pub(crate) fn welcome_message(context: &Context) -> String {
    translated(context, StockMessage::WelcomeMessage)
}

/// Stock string: `Message from %1$s`.
// TODO: This can compute `self_name` itself instead of asking the caller to do this.
pub(crate) fn subject_for_new_contact(context: &Context, self_name: &str) -> String {
    translated(context, StockMessage::SubjectForNewContact).replace1(self_name)
}

/// Stock string: `Message deletion timer is disabled.`.
pub(crate) async fn msg_ephemeral_timer_disabled(
    context: &Context,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouDisabledEphemeralTimer)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerDisabledBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to %1$s s.`.
pub(crate) async fn msg_ephemeral_timer_enabled(
    context: &Context,
    timer: &str,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEnabledEphemeralTimer).replace1(timer)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerEnabledBy)
            .replace1(timer)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 hour.`.
pub(crate) async fn msg_ephemeral_timer_hour(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerHour)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerHourBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 day.`.
pub(crate) async fn msg_ephemeral_timer_day(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerDay)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerDayBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 week.`.
pub(crate) async fn msg_ephemeral_timer_week(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerWeek)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerWeekBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 year.`.
pub(crate) async fn msg_ephemeral_timer_year(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerYear)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerYearBy)
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Error:\n\n“%1$s”`.
pub(crate) fn configuration_failed(context: &Context, details: &str) -> String {
    translated(context, StockMessage::ConfigurationFailed).replace1(details)
}

/// Stock string: `⚠️ Date or time of your device seem to be inaccurate (%1$s)...`.
// TODO: This could compute now itself.
pub(crate) fn bad_time_msg_body(context: &Context, now: &str) -> String {
    translated(context, StockMessage::BadTimeMsgBody).replace1(now)
}

/// Stock string: `⚠️ Your Delta Chat version might be outdated...`.
pub(crate) fn update_reminder_msg_body(context: &Context) -> String {
    translated(context, StockMessage::UpdateReminderMsgBody)
}

/// Stock string: `Could not find your mail server...`.
pub(crate) fn error_no_network(context: &Context) -> String {
    translated(context, StockMessage::ErrorNoNetwork)
}

/// Stock string: `Messages are end-to-end encrypted.`, used in info-messages, UI may add smth. as `Tap to learn more.`
pub(crate) fn messages_e2ee_info_msg(context: &Context) -> String {
    translated(context, StockMessage::ChatProtectionEnabled)
}

/// Stock string: `Messages are end-to-end encrypted.`
pub(crate) fn messages_are_e2ee(context: &Context) -> String {
    translated(context, StockMessage::MessagesAreE2ee)
}

/// Stock string: `Reply`.
pub(crate) fn reply_noun(context: &Context) -> String {
    translated(context, StockMessage::ReplyNoun)
}

/// Stock string: `You deleted the \"Saved messages\" chat...`.
pub(crate) fn self_deleted_msg_body(context: &Context) -> String {
    translated(context, StockMessage::SelfDeletedMsgBody)
}

/// Stock string: `Message deletion timer is set to %1$s minutes.`.
pub(crate) async fn msg_ephemeral_timer_minutes(
    context: &Context,
    minutes: &str,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerMinutes).replace1(minutes)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerMinutesBy)
            .replace1(minutes)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to %1$s hours.`.
pub(crate) async fn msg_ephemeral_timer_hours(
    context: &Context,
    hours: &str,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerHours).replace1(hours)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerHoursBy)
            .replace1(hours)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to %1$s days.`.
pub(crate) async fn msg_ephemeral_timer_days(
    context: &Context,
    days: &str,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerDays).replace1(days)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerDaysBy)
            .replace1(days)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to %1$s weeks.`.
pub(crate) async fn msg_ephemeral_timer_weeks(
    context: &Context,
    weeks: &str,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerWeeks).replace1(weeks)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerWeeksBy)
            .replace1(weeks)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Forwarded`.
pub(crate) fn forwarded(context: &Context) -> String {
    translated(context, StockMessage::Forwarded)
}

/// Stock string: `⚠️ Your provider's storage is about to exceed...`.
pub(crate) fn quota_exceeding(context: &Context, highest_usage: u64) -> String {
    translated(context, StockMessage::QuotaExceedingMsgBody)
        .replace1(&format!("{highest_usage}"))
        .replace("%%", "%")
}

/// Stock string: `Incoming Messages`.
pub(crate) fn incoming_messages(context: &Context) -> String {
    translated(context, StockMessage::IncomingMessages)
}

/// Stock string: `Outgoing Messages`.
pub(crate) fn outgoing_messages(context: &Context) -> String {
    translated(context, StockMessage::OutgoingMessages)
}

/// Stock string: `Not connected`.
pub(crate) fn not_connected(context: &Context) -> String {
    translated(context, StockMessage::NotConnected)
}

/// Stock string: `Connected`.
pub(crate) fn connected(context: &Context) -> String {
    translated(context, StockMessage::Connected)
}

/// Stock string: `Connecting…`.
pub(crate) fn connecting(context: &Context) -> String {
    translated(context, StockMessage::Connecting)
}

/// Stock string: `Updating…`.
pub(crate) fn updating(context: &Context) -> String {
    translated(context, StockMessage::Updating)
}

/// Stock string: `Sending…`.
pub(crate) fn sending(context: &Context) -> String {
    translated(context, StockMessage::Sending)
}

/// Stock string: `Your last message was sent successfully.`.
pub(crate) fn last_msg_sent_successfully(context: &Context) -> String {
    translated(context, StockMessage::LastMsgSentSuccessfully)
}

/// Stock string: `Error: %1$s…`.
/// `%1$s` will be replaced by a possibly more detailed, typically english, error description.
pub(crate) fn error(context: &Context, error: &str) -> String {
    translated(context, StockMessage::Error).replace1(error)
}

/// Stock string: `Not supported by your provider.`.
pub(crate) fn not_supported_by_provider(context: &Context) -> String {
    translated(context, StockMessage::NotSupportedByProvider)
}

/// Stock string: `Messages`.
/// Used as a subtitle in quota context; can be plural always.
pub(crate) fn messages(context: &Context) -> String {
    translated(context, StockMessage::Messages)
}

/// Stock string: `%1$s of %2$s used`.
pub(crate) fn part_of_total_used(context: &Context, part: &str, total: &str) -> String {
    translated(context, StockMessage::PartOfTotallUsed)
        .replace1(part)
        .replace2(total)
}

/// Stock string: `⚠️ Your email provider %1$s requires end-to-end encryption which is not setup yet. Tap to learn more.`.
pub(crate) async fn unencrypted_email(context: &Context, provider: &str) -> String {
    translated(context, StockMessage::InvalidUnencryptedMail).replace1(provider)
}

/// Stock string: `The attachment contains anonymous usage statistics, which helps us improve Delta Chat. Thank you!`
pub(crate) fn stats_msg_body(context: &Context) -> String {
    translated(context, StockMessage::StatsMsgBody)
}

/// Stock string: `Others will only see this group after you sent a first message.`.
pub(crate) fn new_group_send_first_message(context: &Context) -> String {
    translated(context, StockMessage::NewGroupSendFirstMessage)
}

/// Text to put in the [`Qr::Backup2`] rendered SVG image.
///
/// The default is "Scan to set up second device for NAME".
/// The account name (or address as fallback) are looked up from the context.
///
/// [`Qr::Backup2`]: crate::qr::Qr::Backup2
pub(crate) async fn backup_transfer_qr(context: &Context) -> Result<String> {
    let name = if let Some(name) = context.get_config(Config::Displayname).await? {
        name
    } else {
        context.get_primary_self_addr().await?
    };
    Ok(translated(context, StockMessage::BackupTransferQr).replace1(&name))
}

pub(crate) fn backup_transfer_msg_body(context: &Context) -> String {
    translated(context, StockMessage::BackupTransferMsgBody)
}

/// Stock string: `Proxy Enabled`.
pub(crate) fn proxy_enabled(context: &Context) -> String {
    translated(context, StockMessage::ProxyEnabled)
}

/// Stock string: `You are using a proxy. If you're having trouble connecting, try a different proxy.`.
pub(crate) fn proxy_description(context: &Context) -> String {
    translated(context, StockMessage::ProxyEnabledDescription)
}

/// Stock string: `Messages in this chat use classic email and are not encrypted.`.
pub(crate) fn chat_unencrypted_explanation(context: &Context) -> String {
    translated(context, StockMessage::ChatUnencryptedExplanation)
}

/// Stock string: `You are using the legacy option "Move automatically to DeltaChat Folder`…
pub(crate) fn mvbox_move_deprecation(context: &Context) -> String {
    translated(context, StockMessage::MvboxMoveDeprecation)
}

impl Viewtype {
    /// returns Localized name for message viewtype
    pub fn to_locale_string(&self, context: &Context) -> String {
        match self {
            Viewtype::Image => image(context),
            Viewtype::Gif => gif(context),
            Viewtype::Sticker => sticker(context),
            Viewtype::Audio => audio(context),
            Viewtype::Voice => voice_message(context),
            Viewtype::Video => video(context),
            Viewtype::File => file(context),
            Viewtype::Webxdc => "Mini App".to_owned(),
            Viewtype::Vcard => "👤".to_string(),
            // The following shouldn't normally be shown to users, so translations aren't needed.
            Viewtype::Unknown | Viewtype::Text | Viewtype::Call => self.to_string(),
        }
    }
}

impl Context {
    /// Set the stock string for the [StockMessage].
    ///
    pub fn set_stock_translation(&self, id: StockMessage, stockstring: String) -> Result<()> {
        self.translated_stockstrings
            .set_stock_translation(id, stockstring)?;
        Ok(())
    }

    pub(crate) async fn update_device_chats(&self) -> Result<()> {
        if self.get_config_bool(Config::Bot).await? {
            return Ok(());
        }

        // create saved-messages chat; we do this only once, if the user has deleted the chat,
        // he can recreate it manually (make sure we do not re-add it when configure() was called a second time)
        if !self.sql.get_raw_config_bool("self-chat-added").await? {
            self.sql
                .set_raw_config_bool("self-chat-added", true)
                .await?;
            ChatId::create_for_contact(self, ContactId::SELF).await?;
        }

        // add welcome-messages. by the label, this is done only once,
        // if the user has deleted the message or the chat, it is not added again.
        let image = include_bytes!("../assets/welcome-image.jpg");
        let blob = BlobObject::create_and_deduplicate_from_bytes(self, image, "welcome.jpg")?;
        let mut msg = Message::new(Viewtype::Image);
        msg.param.set(Param::File, blob.as_name());
        msg.param.set(Param::Filename, "welcome-image.jpg");
        chat::add_device_msg(self, Some("core-welcome-image"), Some(&mut msg)).await?;

        let mut msg = Message::new_text(welcome_message(self));
        chat::add_device_msg(self, Some("core-welcome"), Some(&mut msg)).await?;
        Ok(())
    }
}

impl Accounts {
    /// Set the stock string for the [StockMessage].
    ///
    pub fn set_stock_translation(&self, id: StockMessage, stockstring: String) -> Result<()> {
        self.stockstrings.set_stock_translation(id, stockstring)?;
        Ok(())
    }
}

#[cfg(test)]
mod stock_str_tests;
