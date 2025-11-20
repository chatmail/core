//! Module to work with translatable stock strings.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, bail};
use humansize::{BINARY, format_size};
use strum::EnumProperty as EnumPropertyTrait;
use strum_macros::EnumProperty;
use tokio::sync::RwLock;

use crate::accounts::Accounts;
use crate::blob::BlobObject;
use crate::chat::{self, Chat, ChatId};
use crate::config::Config;
use crate::contact::{Contact, ContactId, Origin};
use crate::context::Context;
use crate::message::{Message, Viewtype};
use crate::param::Param;
use crate::tools::timestamp_to_str;

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

    #[strum(props(fallback = "End-to-end encryption available"))]
    E2eAvailable = 25,

    #[strum(props(fallback = "No encryption"))]
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

    #[strum(props(fallback = "Welcome to Delta Chat! – \
                    Delta Chat looks and feels like other popular messenger apps, \
                    but does not involve centralized control, \
                    tracking or selling you, friends, colleagues or family out to large organizations.\n\n\
                    Technically, Delta Chat is an email application with a modern chat interface. \
                    Email in a new dress if you will 👻\n\n\
                    Use Delta Chat with anyone out of billions of people: just use their e-mail address. \
                    Recipients don't need to install Delta Chat, visit websites or sign up anywhere - \
                    however, of course, if they like, you may point them to 👉 https://get.delta.chat"))]
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

    #[strum(props(
        fallback = "⚠️ The \"Delete messages from server\" feature now also deletes messages in folders other than Inbox, DeltaChat and Sent.\n\n\
                    ℹ️ To avoid accidentally deleting messages, we turned it off for you. Please turn it on again at \
                    Settings → \"Chats and Media\" → \"Delete messages from server\" to continue using it."
    ))]
    DeleteServerTurnedOff = 92,

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

    #[strum(props(fallback = "%1$s message"))]
    PartialDownloadMsgBody = 99,

    #[strum(props(fallback = "Download maximum available until %1$s"))]
    DownloadAvailability = 100,

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

    #[strum(props(
        fallback = "You changed your email address from %1$s to %2$s.\n\nIf you now send a message to a verified group, contacts there will automatically replace the old with your new address.\n\nIt's highly advised to set up your old email provider to forward all emails to your new email address. Otherwise you might miss messages of contacts who did not get your new address yet."
    ))]
    AeapExplanationAndLink = 123,

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

    #[strum(props(fallback = "I added member %1$s."))]
    MsgIAddMember = 164,

    #[strum(props(fallback = "I removed member %1$s."))]
    MsgIDelMember = 165,

    #[strum(props(fallback = "I left the group."))]
    MsgILeftGroup = 166,

    #[strum(props(fallback = "Messages are end-to-end encrypted."))]
    ChatProtectionEnabled = 170,

    // deprecated 2025-07
    #[strum(props(fallback = "%1$s sent a message from another device."))]
    ChatProtectionDisabled = 171,

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

    #[strum(props(fallback = "Outgoing call"))]
    OutgoingCall = 194,

    #[strum(props(fallback = "Incoming call"))]
    IncomingCall = 195,

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

    async fn translated(&self, id: StockMessage) -> String {
        self.translated_stockstrings
            .read()
            .await
            .get(&(id as usize))
            .map(AsRef::as_ref)
            .unwrap_or_else(|| id.fallback())
            .to_string()
    }

    async fn set_stock_translation(&self, id: StockMessage, stockstring: String) -> Result<()> {
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
            .await
            .insert(id as usize, stockstring);
        Ok(())
    }
}

async fn translated(context: &Context, id: StockMessage) -> String {
    context.translated_stockstrings.translated(id).await
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
pub(crate) async fn no_messages(context: &Context) -> String {
    translated(context, StockMessage::NoMessages).await
}

/// Stock string: `Me`.
pub(crate) async fn self_msg(context: &Context) -> String {
    translated(context, StockMessage::SelfMsg).await
}

/// Stock string: `Draft`.
pub(crate) async fn draft(context: &Context) -> String {
    translated(context, StockMessage::Draft).await
}

/// Stock string: `Voice message`.
pub(crate) async fn voice_message(context: &Context) -> String {
    translated(context, StockMessage::VoiceMessage).await
}

/// Stock string: `Image`.
pub(crate) async fn image(context: &Context) -> String {
    translated(context, StockMessage::Image).await
}

/// Stock string: `Video`.
pub(crate) async fn video(context: &Context) -> String {
    translated(context, StockMessage::Video).await
}

/// Stock string: `Audio`.
pub(crate) async fn audio(context: &Context) -> String {
    translated(context, StockMessage::Audio).await
}

/// Stock string: `File`.
pub(crate) async fn file(context: &Context) -> String {
    translated(context, StockMessage::File).await
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
            .await
            .replace1(from_group)
            .replace2(to_group)
    } else {
        translated(context, StockMessage::MsgGrpNameChangedBy)
            .await
            .replace1(from_group)
            .replace2(to_group)
            .replace3(&by_contact.get_stock_name(context).await)
    }
}

pub(crate) async fn msg_grp_img_changed(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouChangedGrpImg).await
    } else {
        translated(context, StockMessage::MsgGrpImgChangedBy)
            .await
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `I added member %1$s.`.
/// This one is for sending in group chats.
///
/// The `added_member_addr` parameter should be an email address and is looked up in the
/// contacts to combine with the authorized display name.
pub(crate) async fn msg_add_member_remote(context: &Context, added_member_addr: &str) -> String {
    let addr = added_member_addr;
    let whom = &match Contact::lookup_id_by_addr(context, addr, Origin::Unknown).await {
        Ok(Some(contact_id)) => Contact::get_by_id(context, contact_id)
            .await
            .map(|contact| contact.get_authname_or_addr())
            .unwrap_or_else(|_| addr.to_string()),
        _ => addr.to_string(),
    };
    translated(context, StockMessage::MsgIAddMember)
        .await
        .replace1(whom)
}

/// Stock string: `You added member %1$s.` or `Member %1$s added by %2$s.`.
///
/// The `added_member_addr` parameter should be an email address and is looked up in the
/// contacts to combine with the display name.
pub(crate) async fn msg_add_member_local(
    context: &Context,
    added_member: ContactId,
    by_contact: ContactId,
) -> String {
    let whom = added_member.get_stock_name(context).await;
    if by_contact == ContactId::UNDEFINED {
        translated(context, StockMessage::MsgAddMember)
            .await
            .replace1(&whom)
    } else if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouAddMember)
            .await
            .replace1(&whom)
    } else {
        translated(context, StockMessage::MsgAddMemberBy)
            .await
            .replace1(&whom)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `I removed member %1$s.`.
///
/// The `removed_member_addr` parameter should be an email address and is looked up in
/// the contacts to combine with the display name.
pub(crate) async fn msg_del_member_remote(context: &Context, removed_member_addr: &str) -> String {
    let addr = removed_member_addr;
    let whom = &match Contact::lookup_id_by_addr(context, addr, Origin::Unknown).await {
        Ok(Some(contact_id)) => Contact::get_by_id(context, contact_id)
            .await
            .map(|contact| contact.get_authname_or_addr())
            .unwrap_or_else(|_| addr.to_string()),
        _ => addr.to_string(),
    };
    translated(context, StockMessage::MsgIDelMember)
        .await
        .replace1(whom)
}

/// Stock string: `I added member %1$s.` or `Member %1$s removed by %2$s.`.
///
/// The `removed_member_addr` parameter should be an email address and is looked up in
/// the contacts to combine with the display name.
pub(crate) async fn msg_del_member_local(
    context: &Context,
    removed_member: ContactId,
    by_contact: ContactId,
) -> String {
    let whom = removed_member.get_stock_name(context).await;
    if by_contact == ContactId::UNDEFINED {
        translated(context, StockMessage::MsgDelMember)
            .await
            .replace1(&whom)
    } else if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouDelMember)
            .await
            .replace1(&whom)
    } else {
        translated(context, StockMessage::MsgDelMemberBy)
            .await
            .replace1(&whom)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `I left the group.`.
pub(crate) async fn msg_group_left_remote(context: &Context) -> String {
    translated(context, StockMessage::MsgILeftGroup).await
}

/// Stock string: `You left the group.` or `Group left by %1$s.`.
pub(crate) async fn msg_group_left_local(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouLeftGroup).await
    } else {
        translated(context, StockMessage::MsgGroupLeftBy)
            .await
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `You left the channel.`
pub(crate) async fn msg_you_left_broadcast(context: &Context) -> String {
    translated(context, StockMessage::MsgYouLeftBroadcast).await
}

/// Stock string: `You joined the channel.`
pub(crate) async fn msg_you_joined_broadcast(context: &Context) -> String {
    translated(context, StockMessage::MsgYouJoinedBroadcast).await
}

/// Stock string: `%1$s invited you to join this channel. Waiting for the device of %2$s to reply…`.
pub(crate) async fn secure_join_broadcast_started(
    context: &Context,
    inviter_contact_id: ContactId,
) -> String {
    if let Ok(contact) = Contact::get_by_id(context, inviter_contact_id).await {
        translated(context, StockMessage::SecureJoinBroadcastStarted)
            .await
            .replace1(contact.get_display_name())
            .replace2(contact.get_display_name())
    } else {
        format!("secure_join_started: unknown contact {inviter_contact_id}")
    }
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
            .await
            .replace1(reaction)
            .replace2(summary)
    } else {
        translated(context, StockMessage::MsgReactedBy)
            .await
            .replace1(&by_contact.get_stock_name(context).await)
            .replace2(reaction)
            .replace3(summary)
    }
}

/// Stock string: `GIF`.
pub(crate) async fn gif(context: &Context) -> String {
    translated(context, StockMessage::Gif).await
}

/// Stock string: `End-to-end encryption available.`.
pub(crate) async fn e2e_available(context: &Context) -> String {
    translated(context, StockMessage::E2eAvailable).await
}

/// Stock string: `No encryption.`.
pub(crate) async fn encr_none(context: &Context) -> String {
    translated(context, StockMessage::EncrNone).await
}

/// Stock string: `Fingerprints`.
pub(crate) async fn finger_prints(context: &Context) -> String {
    translated(context, StockMessage::FingerPrints).await
}

/// Stock string: `Group image deleted.`.
pub(crate) async fn msg_grp_img_deleted(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouDeletedGrpImg).await
    } else {
        translated(context, StockMessage::MsgGrpImgDeletedBy)
            .await
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
            .await
            .replace1(contact.get_display_name())
            .replace2(contact.get_display_name())
    } else {
        format!("secure_join_started: unknown contact {inviter_contact_id}")
    }
}

/// Stock string: `%1$s replied, waiting for being added to the group…`.
pub(crate) async fn secure_join_replies(context: &Context, contact_id: ContactId) -> String {
    translated(context, StockMessage::SecureJoinReplies)
        .await
        .replace1(&contact_id.get_stock_name(context).await)
}

/// Stock string: `Establishing connection, please wait…`.
pub(crate) async fn securejoin_wait(context: &Context) -> String {
    translated(context, StockMessage::SecurejoinWait).await
}

/// Stock string: `❤️ Seems you're enjoying Delta Chat!`…
pub(crate) async fn donation_request(context: &Context) -> String {
    translated(context, StockMessage::DonationRequest).await
}

/// Stock string: `Outgoing call`.
pub(crate) async fn outgoing_call(context: &Context) -> String {
    translated(context, StockMessage::OutgoingCall).await
}

/// Stock string: `Incoming call`.
pub(crate) async fn incoming_call(context: &Context) -> String {
    translated(context, StockMessage::IncomingCall).await
}

/// Stock string: `Declined call`.
pub(crate) async fn declined_call(context: &Context) -> String {
    translated(context, StockMessage::DeclinedCall).await
}

/// Stock string: `Canceled call`.
pub(crate) async fn canceled_call(context: &Context) -> String {
    translated(context, StockMessage::CanceledCall).await
}

/// Stock string: `Missed call`.
pub(crate) async fn missed_call(context: &Context) -> String {
    translated(context, StockMessage::MissedCall).await
}

/// Stock string: `Scan to chat with %1$s`.
pub(crate) async fn setup_contact_qr_description(
    context: &Context,
    display_name: &str,
    addr: &str,
) -> String {
    let name = if display_name.is_empty() {
        addr.to_owned()
    } else {
        display_name.to_owned()
    };
    translated(context, StockMessage::SetupContactQRDescription)
        .await
        .replace1(&name)
}

/// Stock string: `Scan to join group %1$s`.
pub(crate) async fn secure_join_group_qr_description(context: &Context, chat: &Chat) -> String {
    translated(context, StockMessage::SecureJoinGroupQRDescription)
        .await
        .replace1(chat.get_name())
}

/// Stock string: `Scan to join channel %1$s`.
pub(crate) async fn secure_join_broadcast_qr_description(context: &Context, chat: &Chat) -> String {
    translated(context, StockMessage::SecureJoinBrodcastQRDescription)
        .await
        .replace1(chat.get_name())
}

/// Stock string: `%1$s verified.`.
#[allow(dead_code)]
pub(crate) async fn contact_verified(context: &Context, contact: &Contact) -> String {
    let addr = contact.get_display_name();
    translated(context, StockMessage::ContactVerified)
        .await
        .replace1(addr)
}

/// Stock string: `Archived chats`.
pub(crate) async fn archived_chats(context: &Context) -> String {
    translated(context, StockMessage::ArchivedChats).await
}

/// Stock string: `Multi Device Synchronization`.
pub(crate) async fn sync_msg_subject(context: &Context) -> String {
    translated(context, StockMessage::SyncMsgSubject).await
}

/// Stock string: `This message is used to synchronize data between your devices.`.
pub(crate) async fn sync_msg_body(context: &Context) -> String {
    translated(context, StockMessage::SyncMsgBody).await
}

/// Stock string: `Cannot login as \"%1$s\". Please check...`.
pub(crate) async fn cannot_login(context: &Context, user: &str) -> String {
    translated(context, StockMessage::CannotLogin)
        .await
        .replace1(user)
}

/// Stock string: `Location streaming enabled.`.
pub(crate) async fn msg_location_enabled(context: &Context) -> String {
    translated(context, StockMessage::MsgLocationEnabled).await
}

/// Stock string: `Location streaming enabled by ...`.
pub(crate) async fn msg_location_enabled_by(context: &Context, contact: ContactId) -> String {
    if contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEnabledLocation).await
    } else {
        translated(context, StockMessage::MsgLocationEnabledBy)
            .await
            .replace1(&contact.get_stock_name(context).await)
    }
}

/// Stock string: `Location streaming disabled.`.
pub(crate) async fn msg_location_disabled(context: &Context) -> String {
    translated(context, StockMessage::MsgLocationDisabled).await
}

/// Stock string: `Location`.
pub(crate) async fn location(context: &Context) -> String {
    translated(context, StockMessage::Location).await
}

/// Stock string: `Sticker`.
pub(crate) async fn sticker(context: &Context) -> String {
    translated(context, StockMessage::Sticker).await
}

/// Stock string: `Device messages`.
pub(crate) async fn device_messages(context: &Context) -> String {
    translated(context, StockMessage::DeviceMessages).await
}

/// Stock string: `Saved messages`.
pub(crate) async fn saved_messages(context: &Context) -> String {
    translated(context, StockMessage::SavedMessages).await
}

/// Stock string: `Messages in this chat are generated locally by...`.
pub(crate) async fn device_messages_hint(context: &Context) -> String {
    translated(context, StockMessage::DeviceMessagesHint).await
}

/// Stock string: `Welcome to Delta Chat! – ...`.
pub(crate) async fn welcome_message(context: &Context) -> String {
    translated(context, StockMessage::WelcomeMessage).await
}

/// Stock string: `Message from %1$s`.
// TODO: This can compute `self_name` itself instead of asking the caller to do this.
pub(crate) async fn subject_for_new_contact(context: &Context, self_name: &str) -> String {
    translated(context, StockMessage::SubjectForNewContact)
        .await
        .replace1(self_name)
}

/// Stock string: `Message deletion timer is disabled.`.
pub(crate) async fn msg_ephemeral_timer_disabled(
    context: &Context,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouDisabledEphemeralTimer).await
    } else {
        translated(context, StockMessage::MsgEphemeralTimerDisabledBy)
            .await
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
        translated(context, StockMessage::MsgYouEnabledEphemeralTimer)
            .await
            .replace1(timer)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerEnabledBy)
            .await
            .replace1(timer)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 hour.`.
pub(crate) async fn msg_ephemeral_timer_hour(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerHour).await
    } else {
        translated(context, StockMessage::MsgEphemeralTimerHourBy)
            .await
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 day.`.
pub(crate) async fn msg_ephemeral_timer_day(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerDay).await
    } else {
        translated(context, StockMessage::MsgEphemeralTimerDayBy)
            .await
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 week.`.
pub(crate) async fn msg_ephemeral_timer_week(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerWeek).await
    } else {
        translated(context, StockMessage::MsgEphemeralTimerWeekBy)
            .await
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Message deletion timer is set to 1 year.`.
pub(crate) async fn msg_ephemeral_timer_year(context: &Context, by_contact: ContactId) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerYear).await
    } else {
        translated(context, StockMessage::MsgEphemeralTimerYearBy)
            .await
            .replace1(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Error:\n\n“%1$s”`.
pub(crate) async fn configuration_failed(context: &Context, details: &str) -> String {
    translated(context, StockMessage::ConfigurationFailed)
        .await
        .replace1(details)
}

/// Stock string: `⚠️ Date or time of your device seem to be inaccurate (%1$s)...`.
// TODO: This could compute now itself.
pub(crate) async fn bad_time_msg_body(context: &Context, now: &str) -> String {
    translated(context, StockMessage::BadTimeMsgBody)
        .await
        .replace1(now)
}

/// Stock string: `⚠️ Your Delta Chat version might be outdated...`.
pub(crate) async fn update_reminder_msg_body(context: &Context) -> String {
    translated(context, StockMessage::UpdateReminderMsgBody).await
}

/// Stock string: `Could not find your mail server...`.
pub(crate) async fn error_no_network(context: &Context) -> String {
    translated(context, StockMessage::ErrorNoNetwork).await
}

/// Stock string: `Messages are end-to-end encrypted.`
pub(crate) async fn messages_e2e_encrypted(context: &Context) -> String {
    translated(context, StockMessage::ChatProtectionEnabled).await
}

/// Stock string: `Reply`.
pub(crate) async fn reply_noun(context: &Context) -> String {
    translated(context, StockMessage::ReplyNoun).await
}

/// Stock string: `You deleted the \"Saved messages\" chat...`.
pub(crate) async fn self_deleted_msg_body(context: &Context) -> String {
    translated(context, StockMessage::SelfDeletedMsgBody).await
}

/// Stock string: `⚠️ The "Delete messages from server" feature now also...`.
pub(crate) async fn delete_server_turned_off(context: &Context) -> String {
    translated(context, StockMessage::DeleteServerTurnedOff).await
}

/// Stock string: `Message deletion timer is set to %1$s minutes.`.
pub(crate) async fn msg_ephemeral_timer_minutes(
    context: &Context,
    minutes: &str,
    by_contact: ContactId,
) -> String {
    if by_contact == ContactId::SELF {
        translated(context, StockMessage::MsgYouEphemeralTimerMinutes)
            .await
            .replace1(minutes)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerMinutesBy)
            .await
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
        translated(context, StockMessage::MsgYouEphemeralTimerHours)
            .await
            .replace1(hours)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerHoursBy)
            .await
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
        translated(context, StockMessage::MsgYouEphemeralTimerDays)
            .await
            .replace1(days)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerDaysBy)
            .await
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
        translated(context, StockMessage::MsgYouEphemeralTimerWeeks)
            .await
            .replace1(weeks)
    } else {
        translated(context, StockMessage::MsgEphemeralTimerWeeksBy)
            .await
            .replace1(weeks)
            .replace2(&by_contact.get_stock_name(context).await)
    }
}

/// Stock string: `Forwarded`.
pub(crate) async fn forwarded(context: &Context) -> String {
    translated(context, StockMessage::Forwarded).await
}

/// Stock string: `⚠️ Your provider's storage is about to exceed...`.
pub(crate) async fn quota_exceeding(context: &Context, highest_usage: u64) -> String {
    translated(context, StockMessage::QuotaExceedingMsgBody)
        .await
        .replace1(&format!("{highest_usage}"))
        .replace("%%", "%")
}

/// Stock string: `%1$s message` with placeholder replaced by human-readable size.
pub(crate) async fn partial_download_msg_body(context: &Context, org_bytes: u32) -> String {
    let size = &format_size(org_bytes, BINARY);
    translated(context, StockMessage::PartialDownloadMsgBody)
        .await
        .replace1(size)
}

/// Stock string: `Download maximum available until %1$s`.
pub(crate) async fn download_availability(context: &Context, timestamp: i64) -> String {
    translated(context, StockMessage::DownloadAvailability)
        .await
        .replace1(&timestamp_to_str(timestamp))
}

/// Stock string: `Incoming Messages`.
pub(crate) async fn incoming_messages(context: &Context) -> String {
    translated(context, StockMessage::IncomingMessages).await
}

/// Stock string: `Outgoing Messages`.
pub(crate) async fn outgoing_messages(context: &Context) -> String {
    translated(context, StockMessage::OutgoingMessages).await
}

/// Stock string: `Storage on %1$s`.
/// `%1$s` will be replaced by the domain of the configured email-address.
pub(crate) async fn storage_on_domain(context: &Context, domain: &str) -> String {
    translated(context, StockMessage::StorageOnDomain)
        .await
        .replace1(domain)
}

/// Stock string: `Not connected`.
pub(crate) async fn not_connected(context: &Context) -> String {
    translated(context, StockMessage::NotConnected).await
}

/// Stock string: `Connected`.
pub(crate) async fn connected(context: &Context) -> String {
    translated(context, StockMessage::Connected).await
}

/// Stock string: `Connecting…`.
pub(crate) async fn connecting(context: &Context) -> String {
    translated(context, StockMessage::Connecting).await
}

/// Stock string: `Updating…`.
pub(crate) async fn updating(context: &Context) -> String {
    translated(context, StockMessage::Updating).await
}

/// Stock string: `Sending…`.
pub(crate) async fn sending(context: &Context) -> String {
    translated(context, StockMessage::Sending).await
}

/// Stock string: `Your last message was sent successfully.`.
pub(crate) async fn last_msg_sent_successfully(context: &Context) -> String {
    translated(context, StockMessage::LastMsgSentSuccessfully).await
}

/// Stock string: `Error: %1$s…`.
/// `%1$s` will be replaced by a possibly more detailed, typically english, error description.
pub(crate) async fn error(context: &Context, error: &str) -> String {
    translated(context, StockMessage::Error)
        .await
        .replace1(error)
}

/// Stock string: `Not supported by your provider.`.
pub(crate) async fn not_supported_by_provider(context: &Context) -> String {
    translated(context, StockMessage::NotSupportedByProvider).await
}

/// Stock string: `Messages`.
/// Used as a subtitle in quota context; can be plural always.
pub(crate) async fn messages(context: &Context) -> String {
    translated(context, StockMessage::Messages).await
}

/// Stock string: `%1$s of %2$s used`.
pub(crate) async fn part_of_total_used(context: &Context, part: &str, total: &str) -> String {
    translated(context, StockMessage::PartOfTotallUsed)
        .await
        .replace1(part)
        .replace2(total)
}

/// Stock string: `⚠️ Your email provider %1$s requires end-to-end encryption which is not setup yet. Tap to learn more.`.
pub(crate) async fn unencrypted_email(context: &Context, provider: &str) -> String {
    translated(context, StockMessage::InvalidUnencryptedMail)
        .await
        .replace1(provider)
}

/// Stock string: `The attachment contains anonymous usage statistics, which helps us improve Delta Chat. Thank you!`
pub(crate) async fn stats_msg_body(context: &Context) -> String {
    translated(context, StockMessage::StatsMsgBody).await
}

pub(crate) async fn aeap_explanation_and_link(
    context: &Context,
    old_addr: &str,
    new_addr: &str,
) -> String {
    translated(context, StockMessage::AeapExplanationAndLink)
        .await
        .replace1(old_addr)
        .replace2(new_addr)
}

/// Stock string: `Others will only see this group after you sent a first message.`.
pub(crate) async fn new_group_send_first_message(context: &Context) -> String {
    translated(context, StockMessage::NewGroupSendFirstMessage).await
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
    Ok(translated(context, StockMessage::BackupTransferQr)
        .await
        .replace1(&name))
}

pub(crate) async fn backup_transfer_msg_body(context: &Context) -> String {
    translated(context, StockMessage::BackupTransferMsgBody).await
}

/// Stock string: `Proxy Enabled`.
pub(crate) async fn proxy_enabled(context: &Context) -> String {
    translated(context, StockMessage::ProxyEnabled).await
}

/// Stock string: `You are using a proxy. If you're having trouble connecting, try a different proxy.`.
pub(crate) async fn proxy_description(context: &Context) -> String {
    translated(context, StockMessage::ProxyEnabledDescription).await
}

/// Stock string: `Messages in this chat use classic email and are not encrypted.`.
pub(crate) async fn chat_unencrypted_explanation(context: &Context) -> String {
    translated(context, StockMessage::ChatUnencryptedExplanation).await
}

impl Context {
    /// Set the stock string for the [StockMessage].
    ///
    pub async fn set_stock_translation(&self, id: StockMessage, stockstring: String) -> Result<()> {
        self.translated_stockstrings
            .set_stock_translation(id, stockstring)
            .await?;
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

        let mut msg = Message::new_text(welcome_message(self).await);
        chat::add_device_msg(self, Some("core-welcome"), Some(&mut msg)).await?;
        Ok(())
    }
}

impl Accounts {
    /// Set the stock string for the [StockMessage].
    ///
    pub async fn set_stock_translation(&self, id: StockMessage, stockstring: String) -> Result<()> {
        self.stockstrings
            .set_stock_translation(id, stockstring)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod stock_str_tests;
