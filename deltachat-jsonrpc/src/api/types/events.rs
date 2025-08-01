use deltachat::{Event as CoreEvent, EventType as CoreEventType};
use serde::Serialize;
use typescript_type_def::TypeDef;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    /// Event payload.
    event: EventType,

    /// Account ID.
    context_id: u32,
}

impl From<CoreEvent> for Event {
    fn from(event: CoreEvent) -> Self {
        Event {
            event: event.typ.into(),
            context_id: event.id,
        }
    }
}

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(tag = "kind")]
pub enum EventType {
    /// The library-user may write an informational string to the log.
    ///
    /// This event should *not* be reported to the end-user using a popup or something like
    /// that.
    Info { msg: String },

    /// Emitted when SMTP connection is established and login was successful.
    SmtpConnected { msg: String },

    /// Emitted when IMAP connection is established and login was successful.
    ImapConnected { msg: String },

    /// Emitted when a message was successfully sent to the SMTP server.
    SmtpMessageSent { msg: String },

    /// Emitted when an IMAP message has been marked as deleted
    ImapMessageDeleted { msg: String },

    /// Emitted when an IMAP message has been moved
    ImapMessageMoved { msg: String },

    /// Emitted before going into IDLE on the Inbox folder.
    ImapInboxIdle,

    /// Emitted when an new file in the $BLOBDIR was created
    NewBlobFile { file: String },

    /// Emitted when an file in the $BLOBDIR was deleted
    DeletedBlobFile { file: String },

    /// The library-user should write a warning string to the log.
    ///
    /// This event should *not* be reported to the end-user using a popup or something like
    /// that.
    Warning { msg: String },

    /// The library-user should report an error to the end-user.
    ///
    /// As most things are asynchronous, things may go wrong at any time and the user
    /// should not be disturbed by a dialog or so.  Instead, use a bubble or so.
    ///
    /// However, for ongoing processes (eg. configure())
    /// or for functions that are expected to fail (eg. autocryptContinueKeyTransfer())
    /// it might be better to delay showing these events until the function has really
    /// failed (returned false). It should be sufficient to report only the *last* error
    /// in a message box then.
    Error { msg: String },

    /// An action cannot be performed because the user is not in the group.
    /// Reported eg. after a call to
    /// setChatName(), setChatProfileImage(),
    /// addContactToChat(), removeContactFromChat(),
    /// and messages sending functions.
    ErrorSelfNotInGroup { msg: String },

    /// Messages or chats changed.  One or more messages or chats changed for various
    /// reasons in the database:
    /// - Messages sent, received or removed
    /// - Chats created, deleted or archived
    /// - A draft has been set
    #[serde(rename_all = "camelCase")]
    MsgsChanged {
        /// Set if only a single chat is affected by the changes, otherwise 0.
        chat_id: u32,

        /// Set if only a single message is affected by the changes, otherwise 0.
        msg_id: u32,
    },

    /// Reactions for the message changed.
    #[serde(rename_all = "camelCase")]
    ReactionsChanged {
        /// ID of the chat which the message belongs to.
        chat_id: u32,

        /// ID of the message for which reactions were changed.
        msg_id: u32,

        /// ID of the contact whose reaction set is changed.
        contact_id: u32,
    },

    /// A reaction to one's own sent message received.
    /// Typically, the UI will show a notification for that.
    ///
    /// In addition to this event, ReactionsChanged is emitted.
    #[serde(rename_all = "camelCase")]
    IncomingReaction {
        /// ID of the chat which the message belongs to.
        chat_id: u32,

        /// ID of the contact whose reaction set is changed.
        contact_id: u32,

        /// ID of the message for which reactions were changed.
        msg_id: u32,

        /// The reaction.
        reaction: String,
    },

    /// Incoming webxdc info or summary update, should be notified.
    #[serde(rename_all = "camelCase")]
    IncomingWebxdcNotify {
        /// ID of the chat.
        chat_id: u32,

        /// ID of the contact sending.
        contact_id: u32,

        /// ID of the added info message or webxdc instance in case of summary change.
        msg_id: u32,

        /// Text to notify.
        text: String,

        /// Link assigned to this notification, if any.
        href: Option<String>,
    },

    /// There is a fresh message. Typically, the user will show a notification
    /// when receiving this message.
    ///
    /// There is no extra #DC_EVENT_MSGS_CHANGED event sent together with this event.
    #[serde(rename_all = "camelCase")]
    IncomingMsg {
        /// ID of the chat where the message is assigned.
        chat_id: u32,

        /// ID of the message.
        msg_id: u32,
    },

    /// Downloading a bunch of messages just finished. This is an
    /// event to allow the UI to only show one notification per message bunch,
    /// instead of cluttering the user with many notifications.
    #[serde(rename_all = "camelCase")]
    IncomingMsgBunch,

    /// Messages were seen or noticed.
    /// chat id is always set.
    #[serde(rename_all = "camelCase")]
    MsgsNoticed { chat_id: u32 },

    /// A single message is sent successfully. State changed from  DC_STATE_OUT_PENDING to
    /// DC_STATE_OUT_DELIVERED, see `Message.state`.
    #[serde(rename_all = "camelCase")]
    MsgDelivered {
        /// ID of the chat which the message belongs to.
        chat_id: u32,

        /// ID of the message that was successfully sent.
        msg_id: u32,
    },

    /// A single message could not be sent. State changed from DC_STATE_OUT_PENDING or DC_STATE_OUT_DELIVERED to
    /// DC_STATE_OUT_FAILED, see `Message.state`.
    #[serde(rename_all = "camelCase")]
    MsgFailed {
        /// ID of the chat which the message belongs to.
        chat_id: u32,

        /// ID of the message that could not be sent.
        msg_id: u32,
    },

    /// A single message is read by the receiver. State changed from DC_STATE_OUT_DELIVERED to
    /// DC_STATE_OUT_MDN_RCVD, see `Message.state`.
    #[serde(rename_all = "camelCase")]
    MsgRead {
        /// ID of the chat which the message belongs to.
        chat_id: u32,

        /// ID of the message that was read.
        msg_id: u32,
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
    #[serde(rename_all = "camelCase")]
    MsgDeleted {
        /// ID of the chat where the message was prior to deletion.
        /// Never 0.
        chat_id: u32,

        /// ID of the deleted message. Never 0.
        msg_id: u32,
    },

    /// Chat changed.  The name or the image of a chat group was changed or members were added or removed.
    /// See setChatName(), setChatProfileImage(), addContactToChat()
    /// and removeContactFromChat().
    ///
    /// This event does not include ephemeral timer modification, which
    /// is a separate event.
    #[serde(rename_all = "camelCase")]
    ChatModified { chat_id: u32 },

    /// Chat ephemeral timer changed.
    #[serde(rename_all = "camelCase")]
    ChatEphemeralTimerModified {
        /// Chat ID.
        chat_id: u32,

        /// New ephemeral timer value.
        timer: u32,
    },

    /// Chat deleted.
    ChatDeleted {
        /// Chat ID.
        chat_id: u32,
    },

    /// Contact(s) created, renamed, blocked or deleted.
    #[serde(rename_all = "camelCase")]
    ContactsChanged {
        /// If set, this is the contact_id of an added contact that should be selected.
        contact_id: Option<u32>,
    },

    /// Location of one or more contact has changed.
    #[serde(rename_all = "camelCase")]
    LocationChanged {
        /// contact_id of the contact for which the location has changed.
        /// If the locations of several contacts have been changed,
        /// this parameter is set to `None`.
        contact_id: Option<u32>,
    },

    /// Inform about the configuration progress started by configure().
    ConfigureProgress {
        /// Progress.
        ///
        /// 0=error, 1-999=progress in permille, 1000=success and done
        progress: usize,

        /// Progress comment or error, something to display to the user.
        comment: Option<String>,
    },

    /// Inform about the import/export progress started by imex().
    ///
    #[serde(rename_all = "camelCase")]
    ImexProgress {
        /// 0=error, 1-999=progress in permille, 1000=success and done
        progress: usize,
    },

    /// A file has been exported. A file has been written by imex().
    /// This event may be sent multiple times by a single call to imex().
    ///
    /// A typical purpose for a handler of this event may be to make the file public to some system
    /// services.
    ///
    /// @param data2 0
    #[serde(rename_all = "camelCase")]
    ImexFileWritten { path: String },

    /// Progress information of a secure-join handshake from the view of the inviter
    /// (Alice, the person who shows the QR code).
    ///
    /// These events are typically sent after a joiner has scanned the QR code
    /// generated by getChatSecurejoinQrCodeSvg().
    #[serde(rename_all = "camelCase")]
    SecurejoinInviterProgress {
        /// ID of the contact that wants to join.
        contact_id: u32,

        /// Progress as:
        /// 300=vg-/vc-request received, typically shown as "bob@addr joins".
        /// 600=vg-/vc-request-with-auth received, vg-member-added/vc-contact-confirm sent, typically shown as "bob@addr verified".
        /// 800=contact added to chat, shown as "bob@addr securely joined GROUP". Only for the verified-group-protocol.
        /// 1000=Protocol finished for this contact.
        progress: usize,
    },

    /// Progress information of a secure-join handshake from the view of the joiner
    /// (Bob, the person who scans the QR code).
    /// The events are typically sent while secureJoin(), which
    /// may take some time, is executed.
    #[serde(rename_all = "camelCase")]
    SecurejoinJoinerProgress {
        /// ID of the inviting contact.
        contact_id: u32,

        /// Progress as:
        /// 400=vg-/vc-request-with-auth sent, typically shown as "alice@addr verified, introducing myself."
        /// (Bob has verified alice and waits until Alice does the same for him)
        /// 1000=vg-member-added/vc-contact-confirm received
        progress: usize,
    },

    /// The connectivity to the server changed.
    /// This means that you should refresh the connectivity view
    /// and possibly the connectivtiy HTML; see getConnectivity() and
    /// getConnectivityHtml() for details.
    ConnectivityChanged,

    /// Deprecated by `ConfigSynced`.
    SelfavatarChanged,

    /// A multi-device synced config value changed. Maybe the app needs to refresh smth. For
    /// uniformity this is emitted on the source device too. The value isn't here, otherwise it
    /// would be logged which might not be good for privacy.
    ConfigSynced {
        /// Configuration key.
        key: String,
    },

    #[serde(rename_all = "camelCase")]
    WebxdcStatusUpdate {
        /// Message ID.
        msg_id: u32,

        /// Status update ID.
        status_update_serial: u32,
    },

    /// Data received over an ephemeral peer channel.
    #[serde(rename_all = "camelCase")]
    WebxdcRealtimeData {
        /// Message ID.
        msg_id: u32,

        /// Realtime data.
        data: Vec<u8>,
    },

    /// Advertisement received over an ephemeral peer channel.
    /// This can be used by bots to initiate peer-to-peer communication from their side.
    #[serde(rename_all = "camelCase")]
    WebxdcRealtimeAdvertisementReceived {
        /// Message ID of the webxdc instance.
        msg_id: u32,
    },

    /// Inform that a message containing a webxdc instance has been deleted
    #[serde(rename_all = "camelCase")]
    WebxdcInstanceDeleted {
        /// ID of the deleted message.
        msg_id: u32,
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
    #[serde(rename_all = "camelCase")]
    ChatlistItemChanged {
        /// ID of the changed chat
        chat_id: Option<u32>,
    },

    /// Inform that the list of accounts has changed (an account removed or added or (not yet implemented) the account order changes)
    ///
    /// This event is only emitted by the account manager
    AccountsChanged,

    /// Inform that an account property that might be shown in the account list changed, namely:
    /// - is_configured (see is_configured())
    /// - displayname
    /// - selfavatar
    /// - private_tag
    ///
    /// This event is emitted from the account whose property changed.
    AccountsItemChanged,

    /// Inform than some events have been skipped due to event channel overflow.
    EventChannelOverflow {
        /// Number of events skipped.
        n: u64,
    },
}

impl From<CoreEventType> for EventType {
    fn from(event: CoreEventType) -> Self {
        use EventType::*;
        match event {
            CoreEventType::Info(msg) => Info { msg },
            CoreEventType::SmtpConnected(msg) => SmtpConnected { msg },
            CoreEventType::ImapConnected(msg) => ImapConnected { msg },
            CoreEventType::SmtpMessageSent(msg) => SmtpMessageSent { msg },
            CoreEventType::ImapMessageDeleted(msg) => ImapMessageDeleted { msg },
            CoreEventType::ImapMessageMoved(msg) => ImapMessageMoved { msg },
            CoreEventType::ImapInboxIdle => ImapInboxIdle,
            CoreEventType::NewBlobFile(file) => NewBlobFile { file },
            CoreEventType::DeletedBlobFile(file) => DeletedBlobFile { file },
            CoreEventType::Warning(msg) => Warning { msg },
            CoreEventType::Error(msg) => Error { msg },
            CoreEventType::ErrorSelfNotInGroup(msg) => ErrorSelfNotInGroup { msg },
            CoreEventType::MsgsChanged { chat_id, msg_id } => MsgsChanged {
                chat_id: chat_id.to_u32(),
                msg_id: msg_id.to_u32(),
            },
            CoreEventType::ReactionsChanged {
                chat_id,
                msg_id,
                contact_id,
            } => ReactionsChanged {
                chat_id: chat_id.to_u32(),
                msg_id: msg_id.to_u32(),
                contact_id: contact_id.to_u32(),
            },
            CoreEventType::IncomingReaction {
                chat_id,
                contact_id,
                msg_id,
                reaction,
            } => IncomingReaction {
                chat_id: chat_id.to_u32(),
                contact_id: contact_id.to_u32(),
                msg_id: msg_id.to_u32(),
                reaction: reaction.as_str().to_string(),
            },
            CoreEventType::IncomingWebxdcNotify {
                chat_id,
                contact_id,
                msg_id,
                text,
                href,
            } => IncomingWebxdcNotify {
                chat_id: chat_id.to_u32(),
                contact_id: contact_id.to_u32(),
                msg_id: msg_id.to_u32(),
                text,
                href,
            },
            CoreEventType::IncomingMsg { chat_id, msg_id } => IncomingMsg {
                chat_id: chat_id.to_u32(),
                msg_id: msg_id.to_u32(),
            },
            CoreEventType::IncomingMsgBunch => IncomingMsgBunch,
            CoreEventType::MsgsNoticed(chat_id) => MsgsNoticed {
                chat_id: chat_id.to_u32(),
            },
            CoreEventType::MsgDelivered { chat_id, msg_id } => MsgDelivered {
                chat_id: chat_id.to_u32(),
                msg_id: msg_id.to_u32(),
            },
            CoreEventType::MsgFailed { chat_id, msg_id } => MsgFailed {
                chat_id: chat_id.to_u32(),
                msg_id: msg_id.to_u32(),
            },
            CoreEventType::MsgRead { chat_id, msg_id } => MsgRead {
                chat_id: chat_id.to_u32(),
                msg_id: msg_id.to_u32(),
            },
            CoreEventType::MsgDeleted { chat_id, msg_id } => MsgDeleted {
                chat_id: chat_id.to_u32(),
                msg_id: msg_id.to_u32(),
            },
            CoreEventType::ChatModified(chat_id) => ChatModified {
                chat_id: chat_id.to_u32(),
            },
            CoreEventType::ChatEphemeralTimerModified { chat_id, timer } => {
                ChatEphemeralTimerModified {
                    chat_id: chat_id.to_u32(),
                    timer: timer.to_u32(),
                }
            }
            CoreEventType::ChatDeleted { chat_id } => ChatDeleted {
                chat_id: chat_id.to_u32(),
            },
            CoreEventType::ContactsChanged(contact) => ContactsChanged {
                contact_id: contact.map(|c| c.to_u32()),
            },
            CoreEventType::LocationChanged(contact) => LocationChanged {
                contact_id: contact.map(|c| c.to_u32()),
            },
            CoreEventType::ConfigureProgress { progress, comment } => {
                ConfigureProgress { progress, comment }
            }
            CoreEventType::ImexProgress(progress) => ImexProgress { progress },
            CoreEventType::ImexFileWritten(path) => ImexFileWritten {
                path: path.to_str().unwrap_or_default().to_owned(),
            },
            CoreEventType::SecurejoinInviterProgress {
                contact_id,
                progress,
            } => SecurejoinInviterProgress {
                contact_id: contact_id.to_u32(),
                progress,
            },
            CoreEventType::SecurejoinJoinerProgress {
                contact_id,
                progress,
            } => SecurejoinJoinerProgress {
                contact_id: contact_id.to_u32(),
                progress,
            },
            CoreEventType::ConnectivityChanged => ConnectivityChanged,
            CoreEventType::SelfavatarChanged => SelfavatarChanged,
            CoreEventType::ConfigSynced { key } => ConfigSynced {
                key: key.to_string(),
            },
            CoreEventType::WebxdcStatusUpdate {
                msg_id,
                status_update_serial,
            } => WebxdcStatusUpdate {
                msg_id: msg_id.to_u32(),
                status_update_serial: status_update_serial.to_u32(),
            },
            CoreEventType::WebxdcRealtimeData { msg_id, data } => WebxdcRealtimeData {
                msg_id: msg_id.to_u32(),
                data,
            },
            CoreEventType::WebxdcRealtimeAdvertisementReceived { msg_id } => {
                WebxdcRealtimeAdvertisementReceived {
                    msg_id: msg_id.to_u32(),
                }
            }
            CoreEventType::WebxdcInstanceDeleted { msg_id } => WebxdcInstanceDeleted {
                msg_id: msg_id.to_u32(),
            },
            CoreEventType::AccountsBackgroundFetchDone => AccountsBackgroundFetchDone,
            CoreEventType::ChatlistItemChanged { chat_id } => ChatlistItemChanged {
                chat_id: chat_id.map(|id| id.to_u32()),
            },
            CoreEventType::ChatlistChanged => ChatlistChanged,
            CoreEventType::EventChannelOverflow { n } => EventChannelOverflow { n },
            CoreEventType::AccountsChanged => AccountsChanged,
            CoreEventType::AccountsItemChanged => AccountsItemChanged,
            #[allow(unreachable_patterns)]
            #[cfg(test)]
            _ => unreachable!("This is just to silence a rust_analyzer false-positive"),
        }
    }
}
