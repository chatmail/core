"""Constants module."""

from enum import Enum, IntEnum

COMMAND_PREFIX = "/"


class ContactFlag(IntEnum):
    """Bit flags for get_contacts() method."""

    ADD_SELF = 0x02


class ChatlistFlag(IntEnum):
    """Bit flags for get_chatlist() method."""

    ARCHIVED_ONLY = 0x01
    NO_SPECIALS = 0x02
    ADD_ALLDONE_HINT = 0x04
    FOR_FORWARDING = 0x08


class SpecialContactId(IntEnum):
    """Special contact IDs."""

    SELF = 1
    INFO = 2  # centered messages as "member added", used in all chats
    DEVICE = 5  #  messages "update info" in the device-chat
    LAST_SPECIAL = 9


class EventType(str, Enum):
    """Core event types."""

    INFO = "Info"
    SMTP_CONNECTED = "SmtpConnected"
    IMAP_CONNECTED = "ImapConnected"
    SMTP_MESSAGE_SENT = "SmtpMessageSent"
    IMAP_MESSAGE_DELETED = "ImapMessageDeleted"
    IMAP_MESSAGE_MOVED = "ImapMessageMoved"
    IMAP_INBOX_IDLE = "ImapInboxIdle"
    NEW_BLOB_FILE = "NewBlobFile"
    DELETED_BLOB_FILE = "DeletedBlobFile"
    WARNING = "Warning"
    ERROR = "Error"
    ERROR_SELF_NOT_IN_GROUP = "ErrorSelfNotInGroup"
    MSGS_CHANGED = "MsgsChanged"
    REACTIONS_CHANGED = "ReactionsChanged"
    INCOMING_MSG = "IncomingMsg"
    INCOMING_MSG_BUNCH = "IncomingMsgBunch"
    INCOMING_REACTION = "IncomingReaction"
    MSGS_NOTICED = "MsgsNoticed"
    MSG_DELIVERED = "MsgDelivered"
    MSG_FAILED = "MsgFailed"
    MSG_READ = "MsgRead"
    MSG_DELETED = "MsgDeleted"
    CHAT_MODIFIED = "ChatModified"
    CHAT_DELETED = "ChatDeleted"
    CHAT_EPHEMERAL_TIMER_MODIFIED = "ChatEphemeralTimerModified"
    CONTACTS_CHANGED = "ContactsChanged"
    LOCATION_CHANGED = "LocationChanged"
    CONFIGURE_PROGRESS = "ConfigureProgress"
    IMEX_PROGRESS = "ImexProgress"
    IMEX_FILE_WRITTEN = "ImexFileWritten"
    SECUREJOIN_INVITER_PROGRESS = "SecurejoinInviterProgress"
    SECUREJOIN_JOINER_PROGRESS = "SecurejoinJoinerProgress"
    CONNECTIVITY_CHANGED = "ConnectivityChanged"
    SELFAVATAR_CHANGED = "SelfavatarChanged"
    WEBXDC_STATUS_UPDATE = "WebxdcStatusUpdate"
    WEBXDC_INSTANCE_DELETED = "WebxdcInstanceDeleted"
    CHATLIST_CHANGED = "ChatlistChanged"
    CHATLIST_ITEM_CHANGED = "ChatlistItemChanged"
    ACCOUNTS_CHANGED = "AccountsChanged"
    ACCOUNTS_ITEM_CHANGED = "AccountsItemChanged"
    CONFIG_SYNCED = "ConfigSynced"
    WEBXDC_REALTIME_DATA = "WebxdcRealtimeData"
    WEBXDC_REALTIME_ADVERTISEMENT_RECEIVED = "WebxdcRealtimeAdvertisementReceived"


class ChatId(IntEnum):
    """Special chat IDs."""

    TRASH = 3
    ARCHIVED_LINK = 6
    ALLDONE_HINT = 7
    LAST_SPECIAL = 9


class ChatType(IntEnum):
    """Chat type."""

    UNDEFINED = 0
    SINGLE = 100
    GROUP = 120
    MAILINGLIST = 140
    BROADCAST = 160


class ChatVisibility(str, Enum):
    """Chat visibility types."""

    NORMAL = "Normal"
    ARCHIVED = "Archived"
    PINNED = "Pinned"


class DownloadState(str, Enum):
    """Message download state."""

    DONE = "Done"
    AVAILABLE = "Available"
    FAILURE = "Failure"
    IN_PROGRESS = "InProgress"


class ViewType(str, Enum):
    """Message view type."""

    UNKNOWN = "Unknown"
    TEXT = "Text"
    IMAGE = "Image"
    GIF = "Gif"
    STICKER = "Sticker"
    AUDIO = "Audio"
    VOICE = "Voice"
    VIDEO = "Video"
    FILE = "File"
    VIDEOCHAT_INVITATION = "VideochatInvitation"
    WEBXDC = "Webxdc"
    VCARD = "Vcard"


class SystemMessageType(str, Enum):
    """System message type."""

    UNKNOWN = "Unknown"
    GROUP_NAME_CHANGED = "GroupNameChanged"
    GROUP_IMAGE_CHANGED = "GroupImageChanged"
    MEMBER_ADDED_TO_GROUP = "MemberAddedToGroup"
    MEMBER_REMOVED_FROM_GROUP = "MemberRemovedFromGroup"
    AUTOCRYPT_SETUP_MESSAGE = "AutocryptSetupMessage"
    SECUREJOIN_MESSAGE = "SecurejoinMessage"
    LOCATION_STREAMING_ENABLED = "LocationStreamingEnabled"
    LOCATION_ONLY = "LocationOnly"
    CHAT_PROTECTION_ENABLED = "ChatProtectionEnabled"
    CHAT_PROTECTION_DISABLED = "ChatProtectionDisabled"
    WEBXDC_STATUS_UPDATE = "WebxdcStatusUpdate"
    EPHEMERAL_TIMER_CHANGED = "EphemeralTimerChanged"
    MULTI_DEVICE_SYNC = "MultiDeviceSync"
    WEBXDC_INFO_MESSAGE = "WebxdcInfoMessage"


class MessageState(IntEnum):
    """State of the message."""

    UNDEFINED = 0
    IN_FRESH = 10
    IN_NOTICED = 13
    IN_SEEN = 16
    OUT_PREPARING = 18
    OUT_DRAFT = 19
    OUT_PENDING = 20
    OUT_FAILED = 24
    OUT_DELIVERED = 26
    OUT_MDN_RCVD = 28


class MessageId(IntEnum):
    """Special message IDs."""

    DAYMARKER = 9
    LAST_SPECIAL = 9


class CertificateChecks(IntEnum):
    """Certificate checks mode."""

    AUTOMATIC = 0
    STRICT = 1
    ACCEPT_INVALID_CERTIFICATES = 3


class Connectivity(IntEnum):
    """Connectivity states."""

    NOT_CONNECTED = 1000
    CONNECTING = 2000
    WORKING = 3000
    CONNECTED = 4000


class KeyGenType(IntEnum):
    """Type of the key to generate."""

    DEFAULT = 0
    RSA2048 = 1
    ED25519 = 2
    RSA4096 = 3


# "Lp" means "login parameters"
class LpAuthFlag(IntEnum):
    """Authorization flags."""

    OAUTH2 = 0x2
    NORMAL = 0x4


class MediaQuality(IntEnum):
    """Media quality setting."""

    BALANCED = 0
    WORSE = 1


class ProviderStatus(IntEnum):
    """Provider status according to manual testing."""

    OK = 1
    PREPARATION = 2
    BROKEN = 3


class PushNotifyState(IntEnum):
    """Push notifications state."""

    NOT_CONNECTED = 0
    HEARTBEAT = 1
    CONNECTED = 2


class ShowEmails(IntEnum):
    """Show emails mode."""

    OFF = 0
    ACCEPTED_CONTACTS = 1
    ALL = 2


class SocketSecurity(IntEnum):
    """Socket security."""

    AUTOMATIC = 0
    SSL = 1
    STARTTLS = 2
    PLAIN = 3


class VideochatType(IntEnum):
    """Video chat URL type."""

    UNKNOWN = 0
    BASICWEBRTC = 1
    JITSI = 2
