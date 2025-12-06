//! # Event payloads.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::chat::ChatId;
use crate::config::Config;
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::ephemeral::Timer as EphemeralTimer;
use crate::message::MsgId;
use crate::reaction::Reaction;
use crate::webxdc::StatusUpdateSerial;

/// Event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    /// The library-user may write an informational string to the log.
    ///
    /// This event should *not* be reported to the end-user using a popup or something like
    /// that.
    Info(String),

    /// Emitted when SMTP connection is established and login was successful.
    SmtpConnected(String),

    /// Emitted when IMAP connection is established and login was successful.
    ImapConnected(String),

    /// Emitted when a message was successfully sent to the SMTP server.
    SmtpMessageSent(String),

    /// Emitted when an IMAP message has been marked as deleted
    ImapMessageDeleted(String),

    /// Emitted when an IMAP message has been moved
    ImapMessageMoved(String),

    /// Emitted before going into IDLE on the Inbox folder.
    ImapInboxIdle,

    /// Emitted when an new file in the $BLOBDIR was created
    NewBlobFile(String),

    /// Emitted when an file in the $BLOBDIR was deleted
    DeletedBlobFile(String),

    /// The library-user should write a warning string to the log.
    ///
    /// This event should *not* be reported to the end-user using a popup or something like
    /// that.
    Warning(String),

    /// The library-user should report an error to the end-user.
    ///
    /// As most things are asynchronous, things may go wrong at any time and the user
    /// should not be disturbed by a dialog or so.  Instead, use a bubble or so.
    ///
    /// However, for ongoing processes (eg. configure())
    /// or for functions that are expected to fail (eg. dc_continue_key_transfer())
    /// it might be better to delay showing these events until the function has really
    /// failed (returned false). It should be sufficient to report only the *last* error
    /// in a message box then.
    Error(String),

    /// An action cannot be performed because the user is not in the group.
    /// Reported eg. after a call to
    /// dc_set_chat_name(), dc_set_chat_profile_image(),
    /// dc_add_contact_to_chat(), dc_remove_contact_from_chat(),
    /// dc_send_text_msg() or another sending function.
    ErrorSelfNotInGroup(String),

    /// Messages or chats changed.  One or more messages or chats changed for various
    /// reasons in the database:
    /// - Messages sent, received or removed
    /// - Chats created, deleted or archived
    /// - A draft has been set
    ///
    MsgsChanged {
        /// Set if only a single chat is affected by the changes, otherwise 0.
        chat_id: ChatId,

        /// Set if only a single message is affected by the changes, otherwise 0.
        msg_id: MsgId,
    },

    /// Reactions for the message changed.
    ReactionsChanged {
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,

        /// ID of the message for which reactions were changed.
        msg_id: MsgId,

        /// ID of the contact whose reaction set is changed.
        contact_id: ContactId,
    },

    /// A reaction to one's own sent message received.
    /// Typically, the UI will show a notification for that.
    ///
    /// In addition to this event, ReactionsChanged is emitted.
    IncomingReaction {
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,

        /// ID of the contact whose reaction set is changed.
        contact_id: ContactId,

        /// ID of the message for which reactions were changed.
        msg_id: MsgId,

        /// The reaction.
        reaction: Reaction,
    },

    /// A webxdc wants an info message or a changed summary to be notified.
    IncomingWebxdcNotify {
        /// ID of the chat.
        chat_id: ChatId,

        /// ID of the contact sending.
        contact_id: ContactId,

        /// ID of the added info message or webxdc instance in case of summary change.
        msg_id: MsgId,

        /// Text to notify.
        text: String,

        /// Link assigned to this notification, if any.
        href: Option<String>,
    },

    /// There is a fresh message. Typically, the user will show an notification
    /// when receiving this message.
    ///
    /// There is no extra #DC_EVENT_MSGS_CHANGED event send together with this event.
    IncomingMsg {
        /// ID of the chat where the message is assigned.
        chat_id: ChatId,

        /// ID of the message.
        msg_id: MsgId,
    },

    /// Downloading a bunch of messages just finished.
    IncomingMsgBunch,

    /// Messages were seen or noticed.
    /// chat id is always set.
    MsgsNoticed(ChatId),

    /// A single message is sent successfully. State changed from  DC_STATE_OUT_PENDING to
    /// DC_STATE_OUT_DELIVERED, see dc_msg_get_state().
    MsgDelivered {
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,

        /// ID of the message that was successfully sent.
        msg_id: MsgId,
    },

    /// A single message could not be sent. State changed from DC_STATE_OUT_PENDING or DC_STATE_OUT_DELIVERED to
    /// DC_STATE_OUT_FAILED, see dc_msg_get_state().
    MsgFailed {
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,

        /// ID of the message that could not be sent.
        msg_id: MsgId,
    },

    /// A single message is read by the receiver. State changed from DC_STATE_OUT_DELIVERED to
    /// DC_STATE_OUT_MDN_RCVD, see dc_msg_get_state().
    MsgRead {
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,

        /// ID of the message that was read.
        msg_id: MsgId,
    },

    /// A single message was deleted.
    ///
    /// This event means that the message will no longer appear in the messagelist.
    /// UI should remove the message from the messagelist
    /// in response to this event if the message is currently displayed.
    ///
    /// The message may have been explicitly deleted by the user or expired.
    /// Internally the message may have been removed from the database,
    /// moved to the trash chat or hidden.
    ///
    /// This event does not indicate the message
    /// deletion from the server.
    MsgDeleted {
        /// ID of the chat where the message was prior to deletion.
        /// Never 0 or trash chat.
        chat_id: ChatId,

        /// ID of the deleted message. Never 0.
        msg_id: MsgId,
    },

    /// Chat changed.  The name or the image of a chat group was changed or members were added or removed.
    /// Or the verify state of a chat has changed.
    /// See dc_set_chat_name(), dc_set_chat_profile_image(), dc_add_contact_to_chat()
    /// and dc_remove_contact_from_chat().
    ///
    /// This event does not include ephemeral timer modification, which
    /// is a separate event.
    ChatModified(ChatId),

    /// Chat ephemeral timer changed.
    ChatEphemeralTimerModified {
        /// Chat ID.
        chat_id: ChatId,

        /// New ephemeral timer value.
        timer: EphemeralTimer,
    },

    /// Chat was deleted.
    ChatDeleted {
        /// Chat ID.
        chat_id: ChatId,
    },

    /// Contact(s) created, renamed, blocked, deleted or changed their "recently seen" status.
    ///
    /// @param data1 (int) If set, this is the contact_id of an added contact that should be selected.
    ContactsChanged(Option<ContactId>),

    /// Location of one or more contact has changed.
    ///
    /// @param data1 (u32) contact_id of the contact for which the location has changed.
    ///     If the locations of several contacts have been changed,
    ///     eg. after calling dc_delete_all_locations(), this parameter is set to `None`.
    LocationChanged(Option<ContactId>),

    /// Inform about the configuration progress started by configure().
    ConfigureProgress {
        /// Progress.
        ///
        /// 0=error, 1-999=progress in permille, 1000=success and done
        progress: u16,

        /// Progress comment or error, something to display to the user.
        comment: Option<String>,
    },

    /// Inform about the import/export progress started by imex().
    ///
    /// @param data1 (usize) 0=error, 1-999=progress in permille, 1000=success and done
    /// @param data2 0
    ImexProgress(u16),

    /// A file has been exported. A file has been written by imex().
    /// This event may be sent multiple times by a single call to imex().
    ///
    /// A typical purpose for a handler of this event may be to make the file public to some system
    /// services.
    ///
    /// @param data2 0
    ImexFileWritten(PathBuf),

    /// Progress information of a secure-join handshake from the view of the inviter
    /// (Alice, the person who shows the QR code).
    ///
    /// These events are typically sent after a joiner has scanned the QR code
    /// generated by dc_get_securejoin_qr().
    SecurejoinInviterProgress {
        /// ID of the contact that wants to join.
        contact_id: ContactId,

        /// ID of the chat in case of success.
        chat_id: ChatId,

        /// The type of the joined chat.
        chat_type: Chattype,

        /// Progress, always 1000.
        progress: u16,
    },

    /// Progress information of a secure-join handshake from the view of the joiner
    /// (Bob, the person who scans the QR code).
    /// The events are typically sent while dc_join_securejoin(), which
    /// may take some time, is executed.
    SecurejoinJoinerProgress {
        /// ID of the inviting contact.
        contact_id: ContactId,

        /// Progress as:
        /// 400=vg-/vc-request-with-auth sent, typically shown as "alice@addr verified, introducing myself."
        /// (Bob has verified alice and waits until Alice does the same for him)
        /// 1000=vg-member-added/vc-contact-confirm received
        progress: u16,
    },

    /// The connectivity to the server changed.
    /// This means that you should refresh the connectivity view
    /// and possibly the connectivtiy HTML; see dc_get_connectivity() and
    /// dc_get_connectivity_html() for details.
    ConnectivityChanged,

    /// The user's avatar changed.
    /// Deprecated by `ConfigSynced`.
    SelfavatarChanged,

    /// A multi-device synced config value changed. Maybe the app needs to refresh smth. For
    /// uniformity this is emitted on the source device too. The value isn't here, otherwise it
    /// would be logged which might not be good for privacy.
    ConfigSynced {
        /// Configuration key.
        key: Config,
    },

    /// Webxdc status update received.
    WebxdcStatusUpdate {
        /// Message ID.
        msg_id: MsgId,

        /// Status update ID.
        status_update_serial: StatusUpdateSerial,
    },

    /// Data received over an ephemeral peer channel.
    WebxdcRealtimeData {
        /// Message ID.
        msg_id: MsgId,

        /// Realtime data.
        data: Vec<u8>,
    },

    /// Advertisement received over an ephemeral peer channel.
    /// This can be used by bots to initiate peer-to-peer communication from their side.
    WebxdcRealtimeAdvertisementReceived {
        /// Message ID of the webxdc instance.
        msg_id: MsgId,
    },

    /// Inform that a message containing a webxdc instance has been deleted.
    WebxdcInstanceDeleted {
        /// ID of the deleted message.
        msg_id: MsgId,
    },

    /// Tells that the Background fetch was completed (or timed out).
    /// This event acts as a marker, when you reach this event you can be sure
    /// that all events emitted during the background fetch were processed.
    ///
    /// This event is only emitted by the account manager
    AccountsBackgroundFetchDone,
    /// Inform that set of chats or the order of the chats in the chatlist has changed.
    ///
    /// Sometimes this is emitted together with `UIChatlistItemChanged`.
    ChatlistChanged,

    /// Inform that a single chat list item changed and needs to be rerendered.
    /// If `chat_id` is set to None, then all currently visible chats need to be rerendered, and all not-visible items need to be cleared from cache if the UI has a cache.
    ChatlistItemChanged {
        /// ID of the changed chat
        chat_id: Option<ChatId>,
    },

    /// Inform that the list of accounts has changed (an account removed or added or (not yet implemented) the account order changes)
    ///
    /// This event is only emitted by the account manager
    AccountsChanged,

    /// Inform that an account property that might be shown in the account list changed, namely:
    /// - is_configured (see [crate::context::Context::is_configured])
    /// - displayname
    /// - selfavatar
    /// - private_tag
    ///
    /// This event is emitted from the account whose property changed.
    AccountsItemChanged,

    /// Incoming call.
    IncomingCall {
        /// ID of the message referring to the call.
        msg_id: MsgId,
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,
        /// User-defined info as passed to place_outgoing_call()
        place_call_info: String,
        /// True if incoming call is a video call.
        has_video: bool,
    },

    /// Incoming call accepted.
    IncomingCallAccepted {
        /// ID of the message referring to the call.
        msg_id: MsgId,
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,
    },

    /// Outgoing call accepted.
    OutgoingCallAccepted {
        /// ID of the message referring to the call.
        msg_id: MsgId,
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,
        /// User-defined info as passed to accept_incoming_call()
        accept_call_info: String,
    },

    /// Call ended.
    CallEnded {
        /// ID of the message referring to the call.
        msg_id: MsgId,
        /// ID of the chat which the message belongs to.
        chat_id: ChatId,
    },

    /// One or more transports has changed.
    ///
    /// This event is used for tests to detect when transport
    /// synchronization messages arrives.
    /// UIs don't need to use it, it is unlikely
    /// that user modifies transports on multiple
    /// devices simultaneously.
    TransportsModified,

    /// Event for using in tests, e.g. as a fence between normally generated events.
    #[cfg(test)]
    Test,

    /// Inform than some events have been skipped due to event channel overflow.
    EventChannelOverflow {
        /// Number of events skipped.
        n: u64,
    },
}
