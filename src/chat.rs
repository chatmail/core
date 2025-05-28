//! # Chat module.

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Cursor;
use std::marker::Sync;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, ensure, Context as _, Result};
use deltachat_contact_tools::{sanitize_bidi_characters, sanitize_single_line, ContactAddress};
use deltachat_derive::{FromSql, ToSql};
use mail_builder::mime::MimePart;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;
use tokio::task;

use crate::aheader::EncryptPreference;
use crate::blob::BlobObject;
use crate::chatlist::Chatlist;
use crate::color::str_to_color;
use crate::config::Config;
use crate::constants::{
    self, Blocked, Chattype, DC_CHAT_ID_ALLDONE_HINT, DC_CHAT_ID_ARCHIVED_LINK,
    DC_CHAT_ID_LAST_SPECIAL, DC_CHAT_ID_TRASH, DC_RESEND_USER_AVATAR_DAYS, EDITED_PREFIX,
    TIMESTAMP_SENT_TOLERANCE,
};
use crate::contact::{self, Contact, ContactId, Origin};
use crate::context::Context;
use crate::debug_logging::maybe_set_logging_xdc;
use crate::download::DownloadState;
use crate::ephemeral::{start_chat_ephemeral_timers, Timer as EphemeralTimer};
use crate::events::EventType;
use crate::location;
use crate::log::LogExt;
use crate::message::{self, Message, MessageState, MsgId, Viewtype};
use crate::mimefactory::MimeFactory;
use crate::mimeparser::SystemMessage;
use crate::param::{Param, Params};
use crate::peerstate::Peerstate;
use crate::receive_imf::ReceivedMsg;
use crate::smtp::send_msg_to_smtp;
use crate::stock_str;
use crate::sync::{self, Sync::*, SyncData};
use crate::tools::{
    buf_compress, create_id, create_outgoing_rfc724_mid, create_smeared_timestamp,
    create_smeared_timestamps, get_abs_path, gm2local_offset, smeared_time, time,
    truncate_msg_text, IsNoneOrEmpty, SystemTime,
};
use crate::webxdc::StatusUpdateSerial;
use crate::{chatlist_events, imap};

/// An chat item, such as a message or a marker.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ChatItem {
    /// Chat message stored in the database.
    Message {
        /// Database ID of the message.
        msg_id: MsgId,
    },

    /// Day marker, separating messages that correspond to different
    /// days according to local time.
    DayMarker {
        /// Marker timestamp, for day markers
        timestamp: i64,
    },
}

/// Chat protection status.
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
    IntoStaticStr,
    Serialize,
    Deserialize,
)]
#[repr(u32)]
pub enum ProtectionStatus {
    /// Chat is not protected.
    #[default]
    Unprotected = 0,

    /// Chat is protected.
    ///
    /// All members of the chat must be verified.
    Protected = 1,

    /// The chat was protected, but now a new message came in
    /// which was not encrypted / signed correctly.
    /// The user has to confirm that this is OK.
    ///
    /// We only do this in 1:1 chats; in group chats, the chat just
    /// stays protected.
    ProtectionBroken = 3, // `2` was never used as a value.
}

/// The reason why messages cannot be sent to the chat.
///
/// The reason is mainly for logging and displaying in debug REPL, thus not translated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CantSendReason {
    /// Special chat.
    SpecialChat,

    /// The chat is a device chat.
    DeviceChat,

    /// The chat is a contact request, it needs to be accepted before sending a message.
    ContactRequest,

    /// The chat was protected, but now a new message came in
    /// which was not encrypted / signed correctly.
    ProtectionBroken,

    /// Mailing list without known List-Post header.
    ReadOnlyMailingList,

    /// Not a member of the chat.
    NotAMember,

    /// Temporary state for 1:1 chats while SecureJoin is in progress.
    SecurejoinWait,
}

impl fmt::Display for CantSendReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SpecialChat => write!(f, "the chat is a special chat"),
            Self::DeviceChat => write!(f, "the chat is a device chat"),
            Self::ContactRequest => write!(
                f,
                "contact request chat should be accepted before sending messages"
            ),
            Self::ProtectionBroken => write!(
                f,
                "accept that the encryption isn't verified anymore before sending messages"
            ),
            Self::ReadOnlyMailingList => {
                write!(f, "mailing list does not have a know post address")
            }
            Self::NotAMember => write!(f, "not a member of the chat"),
            Self::SecurejoinWait => write!(f, "awaiting SecureJoin for 1:1 chat"),
        }
    }
}

/// Chat ID, including reserved IDs.
///
/// Some chat IDs are reserved to identify special chat types.  This
/// type can represent both the special as well as normal chats.
#[derive(
    Debug, Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize, Hash, PartialOrd, Ord,
)]
pub struct ChatId(u32);

impl ChatId {
    /// Create a new [ChatId].
    pub const fn new(id: u32) -> ChatId {
        ChatId(id)
    }

    /// An unset ChatId
    ///
    /// This is transitional and should not be used in new code.
    pub fn is_unset(self) -> bool {
        self.0 == 0
    }

    /// Whether the chat ID signifies a special chat.
    ///
    /// This kind of chat ID can not be used for real chats.
    pub fn is_special(self) -> bool {
        (0..=DC_CHAT_ID_LAST_SPECIAL.0).contains(&self.0)
    }

    /// Chat ID for messages which need to be deleted.
    ///
    /// Messages which should be deleted get this chat ID and are
    /// deleted later.  Deleted messages need to stay around as long
    /// as they are not deleted on the server so that their rfc724_mid
    /// remains known and downloading them again can be avoided.
    pub fn is_trash(self) -> bool {
        self == DC_CHAT_ID_TRASH
    }

    /// Chat ID signifying there are **any** number of archived chats.
    ///
    /// This chat ID can be returned in a [`Chatlist`] and signals to
    /// the UI to include a link to the archived chats.
    ///
    /// [`Chatlist`]: crate::chatlist::Chatlist
    pub fn is_archived_link(self) -> bool {
        self == DC_CHAT_ID_ARCHIVED_LINK
    }

    /// Virtual chat ID signalling there are **only** archived chats.
    ///
    /// This can be included in the chatlist if the
    /// [`DC_GCL_ADD_ALLDONE_HINT`] flag is used to build the
    /// [`Chatlist`].
    ///
    /// [`DC_GCL_ADD_ALLDONE_HINT`]: crate::constants::DC_GCL_ADD_ALLDONE_HINT
    /// [`Chatlist`]: crate::chatlist::Chatlist
    pub fn is_alldone_hint(self) -> bool {
        self == DC_CHAT_ID_ALLDONE_HINT
    }

    /// Returns [`ChatId`] of a chat that `msg` belongs to.
    pub(crate) fn lookup_by_message(msg: &Message) -> Option<Self> {
        if msg.chat_id == DC_CHAT_ID_TRASH {
            return None;
        }
        if msg.download_state == DownloadState::Undecipherable {
            return None;
        }
        Some(msg.chat_id)
    }

    /// Returns the [`ChatId`] for the 1:1 chat with `contact_id`
    /// if it exists and is not blocked.
    ///
    /// If the chat does not exist or is blocked, `None` is returned.
    pub async fn lookup_by_contact(
        context: &Context,
        contact_id: ContactId,
    ) -> Result<Option<Self>> {
        let Some(chat_id_blocked) = ChatIdBlocked::lookup_by_contact(context, contact_id).await?
        else {
            return Ok(None);
        };

        let chat_id = match chat_id_blocked.blocked {
            Blocked::Not | Blocked::Request => Some(chat_id_blocked.id),
            Blocked::Yes => None,
        };
        Ok(chat_id)
    }

    /// Returns the [`ChatId`] for the 1:1 chat with `contact_id`.
    ///
    /// If the chat does not yet exist an unblocked chat ([`Blocked::Not`]) is created.
    ///
    /// This is an internal API, if **a user action** needs to get a chat
    /// [`ChatId::create_for_contact`] should be used as this also scales up the
    /// [`Contact`]'s origin.
    pub(crate) async fn get_for_contact(context: &Context, contact_id: ContactId) -> Result<Self> {
        ChatIdBlocked::get_for_contact(context, contact_id, Blocked::Not)
            .await
            .map(|chat| chat.id)
    }

    /// Returns the unblocked 1:1 chat with `contact_id`.
    ///
    /// This should be used when **a user action** creates a chat 1:1, it ensures the chat
    /// exists, is unblocked and scales the [`Contact`]'s origin.
    pub async fn create_for_contact(context: &Context, contact_id: ContactId) -> Result<Self> {
        ChatId::create_for_contact_with_blocked(context, contact_id, Blocked::Not).await
    }

    /// Same as `create_for_contact()` with an additional `create_blocked` parameter
    /// that is used in case the chat does not exist or to unblock existing chats.
    /// `create_blocked` won't block already unblocked chats again.
    pub(crate) async fn create_for_contact_with_blocked(
        context: &Context,
        contact_id: ContactId,
        create_blocked: Blocked,
    ) -> Result<Self> {
        let chat_id = match ChatIdBlocked::lookup_by_contact(context, contact_id).await? {
            Some(chat) => {
                if create_blocked != Blocked::Not || chat.blocked == Blocked::Not {
                    return Ok(chat.id);
                }
                chat.id.set_blocked(context, Blocked::Not).await?;
                chat.id
            }
            None => {
                if Contact::real_exists_by_id(context, contact_id).await?
                    || contact_id == ContactId::SELF
                {
                    let chat_id =
                        ChatIdBlocked::get_for_contact(context, contact_id, create_blocked)
                            .await
                            .map(|chat| chat.id)?;
                    ContactId::scaleup_origin(context, &[contact_id], Origin::CreateChat).await?;
                    chat_id
                } else {
                    warn!(
                        context,
                        "Cannot create chat, contact {contact_id} does not exist."
                    );
                    bail!("Can not create chat for non-existing contact");
                }
            }
        };
        context.emit_msgs_changed_without_ids();
        chatlist_events::emit_chatlist_changed(context);
        chatlist_events::emit_chatlist_item_changed(context, chat_id);
        Ok(chat_id)
    }

    /// Create a group or mailinglist raw database record with the given parameters.
    /// The function does not add SELF nor checks if the record already exists.
    #[expect(clippy::too_many_arguments)]
    pub(crate) async fn create_multiuser_record(
        context: &Context,
        chattype: Chattype,
        grpid: &str,
        grpname: &str,
        create_blocked: Blocked,
        create_protected: ProtectionStatus,
        param: Option<String>,
        timestamp: i64,
    ) -> Result<Self> {
        let grpname = sanitize_single_line(grpname);
        let timestamp = cmp::min(timestamp, smeared_time(context));
        let row_id =
            context.sql.insert(
                "INSERT INTO chats (type, name, grpid, blocked, created_timestamp, protected, param) VALUES(?, ?, ?, ?, ?, ?, ?);",
                (
                    chattype,
                    &grpname,
                    grpid,
                    create_blocked,
                    timestamp,
                    create_protected,
                    param.unwrap_or_default(),
                ),
            ).await?;

        let chat_id = ChatId::new(u32::try_from(row_id)?);

        if create_protected == ProtectionStatus::Protected {
            chat_id
                .add_protection_msg(context, ProtectionStatus::Protected, None, timestamp)
                .await?;
        }

        info!(
            context,
            "Created group/mailinglist '{}' grpid={} as {}, blocked={}, protected={create_protected}.",
            &grpname,
            grpid,
            chat_id,
            create_blocked,
        );

        Ok(chat_id)
    }

    async fn set_selfavatar_timestamp(self, context: &Context, timestamp: i64) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE contacts
                 SET selfavatar_sent=?
                 WHERE id IN(SELECT contact_id FROM chats_contacts WHERE chat_id=? AND add_timestamp >= remove_timestamp)",
                (timestamp, self),
            )
            .await?;
        Ok(())
    }

    /// Updates chat blocked status.
    ///
    /// Returns true if the value was modified.
    pub(crate) async fn set_blocked(self, context: &Context, new_blocked: Blocked) -> Result<bool> {
        if self.is_special() {
            bail!("ignoring setting of Block-status for {}", self);
        }
        let count = context
            .sql
            .execute(
                "UPDATE chats SET blocked=?1 WHERE id=?2 AND blocked != ?1",
                (new_blocked, self),
            )
            .await?;
        Ok(count > 0)
    }

    /// Blocks the chat as a result of explicit user action.
    pub async fn block(self, context: &Context) -> Result<()> {
        self.block_ex(context, Sync).await
    }

    pub(crate) async fn block_ex(self, context: &Context, sync: sync::Sync) -> Result<()> {
        let chat = Chat::load_from_db(context, self).await?;
        let mut delete = false;

        match chat.typ {
            Chattype::Broadcast => {
                bail!("Can't block chat of type {:?}", chat.typ)
            }
            Chattype::Single => {
                for contact_id in get_chat_contacts(context, self).await? {
                    if contact_id != ContactId::SELF {
                        info!(
                            context,
                            "Blocking the contact {contact_id} to block 1:1 chat."
                        );
                        contact::set_blocked(context, Nosync, contact_id, true).await?;
                    }
                }
            }
            Chattype::Group => {
                info!(context, "Can't block groups yet, deleting the chat.");
                delete = true;
            }
            Chattype::Mailinglist => {
                if self.set_blocked(context, Blocked::Yes).await? {
                    context.emit_event(EventType::ChatModified(self));
                }
            }
        }
        chatlist_events::emit_chatlist_changed(context);

        if sync.into() {
            // NB: For a 1:1 chat this currently triggers `Contact::block()` on other devices.
            chat.sync(context, SyncAction::Block)
                .await
                .log_err(context)
                .ok();
        }
        if delete {
            self.delete_ex(context, Nosync).await?;
        }
        Ok(())
    }

    /// Unblocks the chat.
    pub async fn unblock(self, context: &Context) -> Result<()> {
        self.unblock_ex(context, Sync).await
    }

    pub(crate) async fn unblock_ex(self, context: &Context, sync: sync::Sync) -> Result<()> {
        self.set_blocked(context, Blocked::Not).await?;

        chatlist_events::emit_chatlist_changed(context);

        if sync.into() {
            let chat = Chat::load_from_db(context, self).await?;
            // TODO: For a 1:1 chat this currently triggers `Contact::unblock()` on other devices.
            // Maybe we should unblock the contact locally too, this would also resolve discrepancy
            // with `block()` which also blocks the contact.
            chat.sync(context, SyncAction::Unblock)
                .await
                .log_err(context)
                .ok();
        }

        Ok(())
    }

    /// Accept the contact request.
    ///
    /// Unblocks the chat and scales up origin of contacts.
    pub async fn accept(self, context: &Context) -> Result<()> {
        self.accept_ex(context, Sync).await
    }

    pub(crate) async fn accept_ex(self, context: &Context, sync: sync::Sync) -> Result<()> {
        let chat = Chat::load_from_db(context, self).await?;

        match chat.typ {
            Chattype::Single
                if chat.blocked == Blocked::Not
                    && chat.protected == ProtectionStatus::ProtectionBroken =>
            {
                // The protection was broken, then the user clicked 'Accept'/'OK',
                // so, now we want to set the status to Unprotected again:
                chat.id
                    .inner_set_protection(context, ProtectionStatus::Unprotected)
                    .await?;
            }
            Chattype::Single | Chattype::Group | Chattype::Broadcast => {
                // User has "created a chat" with all these contacts.
                //
                // Previously accepting a chat literally created a chat because unaccepted chats
                // went to "contact requests" list rather than normal chatlist.
                for contact_id in get_chat_contacts(context, self).await? {
                    if contact_id != ContactId::SELF {
                        ContactId::scaleup_origin(context, &[contact_id], Origin::CreateChat)
                            .await?;
                    }
                }
            }
            Chattype::Mailinglist => {
                // If the message is from a mailing list, the contacts are not counted as "known"
            }
        }

        if self.set_blocked(context, Blocked::Not).await? {
            context.emit_event(EventType::ChatModified(self));
            chatlist_events::emit_chatlist_item_changed(context, self);
        }

        if sync.into() {
            chat.sync(context, SyncAction::Accept)
                .await
                .log_err(context)
                .ok();
        }
        Ok(())
    }

    /// Sets protection without sending a message.
    ///
    /// Returns whether the protection status was actually modified.
    pub(crate) async fn inner_set_protection(
        self,
        context: &Context,
        protect: ProtectionStatus,
    ) -> Result<bool> {
        ensure!(!self.is_special(), "Invalid chat-id {self}.");

        let chat = Chat::load_from_db(context, self).await?;

        if protect == chat.protected {
            info!(context, "Protection status unchanged for {}.", self);
            return Ok(false);
        }

        match protect {
            ProtectionStatus::Protected => match chat.typ {
                Chattype::Single | Chattype::Group | Chattype::Broadcast => {}
                Chattype::Mailinglist => bail!("Cannot protect mailing lists"),
            },
            ProtectionStatus::Unprotected | ProtectionStatus::ProtectionBroken => {}
        };

        context
            .sql
            .execute("UPDATE chats SET protected=? WHERE id=?;", (protect, self))
            .await?;

        context.emit_event(EventType::ChatModified(self));
        chatlist_events::emit_chatlist_item_changed(context, self);

        // make sure, the receivers will get all keys
        self.reset_gossiped_timestamp(context).await?;

        Ok(true)
    }

    /// Adds an info message to the chat, telling the user that the protection status changed.
    ///
    /// Params:
    ///
    /// * `contact_id`: In a 1:1 chat, pass the chat partner's contact id.
    /// * `timestamp_sort` is used as the timestamp of the added message
    ///   and should be the timestamp of the change happening.
    pub(crate) async fn add_protection_msg(
        self,
        context: &Context,
        protect: ProtectionStatus,
        contact_id: Option<ContactId>,
        timestamp_sort: i64,
    ) -> Result<()> {
        if contact_id == Some(ContactId::SELF) {
            // Do not add protection messages to Saved Messages chat.
            // This chat never gets protected and unprotected,
            // we do not want the first message
            // to be a protection message with an arbitrary timestamp.
            return Ok(());
        }

        let text = context.stock_protection_msg(protect, contact_id).await;
        let cmd = match protect {
            ProtectionStatus::Protected => SystemMessage::ChatProtectionEnabled,
            ProtectionStatus::Unprotected => SystemMessage::ChatProtectionDisabled,
            ProtectionStatus::ProtectionBroken => SystemMessage::ChatProtectionDisabled,
        };
        add_info_msg_with_cmd(
            context,
            self,
            &text,
            cmd,
            timestamp_sort,
            None,
            None,
            None,
            None,
        )
        .await?;

        Ok(())
    }

    /// Sets protection and adds a message.
    ///
    /// `timestamp_sort` is used as the timestamp of the added message
    /// and should be the timestamp of the change happening.
    async fn set_protection_for_timestamp_sort(
        self,
        context: &Context,
        protect: ProtectionStatus,
        timestamp_sort: i64,
        contact_id: Option<ContactId>,
    ) -> Result<()> {
        let protection_status_modified = self
            .inner_set_protection(context, protect)
            .await
            .with_context(|| format!("Cannot set protection for {self}"))?;
        if protection_status_modified {
            self.add_protection_msg(context, protect, contact_id, timestamp_sort)
                .await?;
            chatlist_events::emit_chatlist_item_changed(context, self);
        }
        Ok(())
    }

    /// Sets protection and sends or adds a message.
    ///
    /// `timestamp_sent` is the "sent" timestamp of a message caused the protection state change.
    pub(crate) async fn set_protection(
        self,
        context: &Context,
        protect: ProtectionStatus,
        timestamp_sent: i64,
        contact_id: Option<ContactId>,
    ) -> Result<()> {
        let sort_to_bottom = true;
        let (received, incoming) = (false, false);
        let ts = self
            .calc_sort_timestamp(context, timestamp_sent, sort_to_bottom, received, incoming)
            .await?
            // Always sort protection messages below `SystemMessage::SecurejoinWait{,Timeout}` ones
            // in case of race conditions.
            .saturating_add(1);
        self.set_protection_for_timestamp_sort(context, protect, ts, contact_id)
            .await
    }

    /// Sets the 1:1 chat with the given address to ProtectionStatus::Protected,
    /// and posts a `SystemMessage::ChatProtectionEnabled` into it.
    ///
    /// If necessary, creates a hidden chat for this.
    pub(crate) async fn set_protection_for_contact(
        context: &Context,
        contact_id: ContactId,
        timestamp: i64,
    ) -> Result<()> {
        let chat_id = ChatId::create_for_contact_with_blocked(context, contact_id, Blocked::Yes)
            .await
            .with_context(|| format!("can't create chat for {contact_id}"))?;
        chat_id
            .set_protection(
                context,
                ProtectionStatus::Protected,
                timestamp,
                Some(contact_id),
            )
            .await?;
        Ok(())
    }

    /// Archives or unarchives a chat.
    pub async fn set_visibility(self, context: &Context, visibility: ChatVisibility) -> Result<()> {
        self.set_visibility_ex(context, Sync, visibility).await
    }

    pub(crate) async fn set_visibility_ex(
        self,
        context: &Context,
        sync: sync::Sync,
        visibility: ChatVisibility,
    ) -> Result<()> {
        ensure!(
            !self.is_special(),
            "bad chat_id, can not be special chat: {}",
            self
        );

        context
            .sql
            .transaction(move |transaction| {
                if visibility == ChatVisibility::Archived {
                    transaction.execute(
                        "UPDATE msgs SET state=? WHERE chat_id=? AND state=?;",
                        (MessageState::InNoticed, self, MessageState::InFresh),
                    )?;
                }
                transaction.execute(
                    "UPDATE chats SET archived=? WHERE id=?;",
                    (visibility, self),
                )?;
                Ok(())
            })
            .await?;

        if visibility == ChatVisibility::Archived {
            start_chat_ephemeral_timers(context, self).await?;
        }

        context.emit_msgs_changed_without_ids();
        chatlist_events::emit_chatlist_changed(context);
        chatlist_events::emit_chatlist_item_changed(context, self);

        if sync.into() {
            let chat = Chat::load_from_db(context, self).await?;
            chat.sync(context, SyncAction::SetVisibility(visibility))
                .await
                .log_err(context)
                .ok();
        }
        Ok(())
    }

    /// Unarchives a chat that is archived and not muted.
    /// Needed after a message is added to a chat so that the chat gets a normal visibility again.
    /// `msg_state` is the state of the message. Matters only for incoming messages currently. For
    /// multiple outgoing messages the function may be called once with MessageState::Undefined.
    /// Sending an appropriate event is up to the caller.
    /// Also emits DC_EVENT_MSGS_CHANGED for DC_CHAT_ID_ARCHIVED_LINK when the number of archived
    /// chats with unread messages increases (which is possible if the chat is muted).
    pub async fn unarchive_if_not_muted(
        self,
        context: &Context,
        msg_state: MessageState,
    ) -> Result<()> {
        if msg_state != MessageState::InFresh {
            context
                .sql
                .execute(
                    "UPDATE chats SET archived=0 WHERE id=? AND archived=1 \
                AND NOT(muted_until=-1 OR muted_until>?)",
                    (self, time()),
                )
                .await?;
            return Ok(());
        }
        let chat = Chat::load_from_db(context, self).await?;
        if chat.visibility != ChatVisibility::Archived {
            return Ok(());
        }
        if chat.is_muted() {
            let unread_cnt = context
                .sql
                .count(
                    "SELECT COUNT(*)
                FROM msgs
                WHERE state=?
                AND hidden=0
                AND chat_id=?",
                    (MessageState::InFresh, self),
                )
                .await?;
            if unread_cnt == 1 {
                // Added the first unread message in the chat.
                context.emit_msgs_changed_without_msg_id(DC_CHAT_ID_ARCHIVED_LINK);
            }
            return Ok(());
        }
        context
            .sql
            .execute("UPDATE chats SET archived=0 WHERE id=?", (self,))
            .await?;
        Ok(())
    }

    /// Emits an appropriate event for a message. `important` is whether a notification should be
    /// shown.
    pub(crate) fn emit_msg_event(self, context: &Context, msg_id: MsgId, important: bool) {
        if important {
            debug_assert!(!msg_id.is_unset());

            context.emit_incoming_msg(self, msg_id);
        } else {
            context.emit_msgs_changed(self, msg_id);
        }
    }

    /// Deletes a chat.
    pub async fn delete(self, context: &Context) -> Result<()> {
        self.delete_ex(context, Sync).await
    }

    pub(crate) async fn delete_ex(self, context: &Context, sync: sync::Sync) -> Result<()> {
        ensure!(
            !self.is_special(),
            "bad chat_id, can not be a special chat: {}",
            self
        );

        let chat = Chat::load_from_db(context, self).await?;
        let delete_msgs_target = context.get_delete_msgs_target().await?;
        let sync_id = match sync {
            Nosync => None,
            Sync => chat.get_sync_id(context).await?,
        };

        context
            .sql
            .transaction(|transaction| {
                transaction.execute(
                    "UPDATE imap SET target=? WHERE rfc724_mid IN (SELECT rfc724_mid FROM msgs WHERE chat_id=?)",
                    (delete_msgs_target, self,),
                )?;
                transaction.execute(
                    "DELETE FROM smtp WHERE msg_id IN (SELECT id FROM msgs WHERE chat_id=?)",
                    (self,),
                )?;
                transaction.execute(
                    "DELETE FROM msgs_mdns WHERE msg_id IN (SELECT id FROM msgs WHERE chat_id=?)",
                    (self,),
                )?;
                transaction.execute("DELETE FROM msgs WHERE chat_id=?", (self,))?;
                transaction.execute("DELETE FROM chats_contacts WHERE chat_id=?", (self,))?;
                transaction.execute("DELETE FROM chats WHERE id=?", (self,))?;
                Ok(())
            })
            .await?;

        context.emit_event(EventType::ChatDeleted { chat_id: self });
        context.emit_msgs_changed_without_ids();

        if let Some(id) = sync_id {
            self::sync(context, id, SyncAction::Delete)
                .await
                .log_err(context)
                .ok();
        }

        if chat.is_self_talk() {
            let mut msg = Message::new_text(stock_str::self_deleted_msg_body(context).await);
            add_device_msg(context, None, Some(&mut msg)).await?;
        }
        chatlist_events::emit_chatlist_changed(context);

        context
            .set_config_internal(Config::LastHousekeeping, None)
            .await?;
        context.scheduler.interrupt_inbox().await;

        Ok(())
    }

    /// Sets draft message.
    ///
    /// Passing `None` as message just deletes the draft
    pub async fn set_draft(self, context: &Context, mut msg: Option<&mut Message>) -> Result<()> {
        if self.is_special() {
            return Ok(());
        }

        let changed = match &mut msg {
            None => self.maybe_delete_draft(context).await?,
            Some(msg) => self.do_set_draft(context, msg).await?,
        };

        if changed {
            if msg.is_some() {
                match self.get_draft_msg_id(context).await? {
                    Some(msg_id) => context.emit_msgs_changed(self, msg_id),
                    None => context.emit_msgs_changed_without_msg_id(self),
                }
            } else {
                context.emit_msgs_changed_without_msg_id(self)
            }
        }

        Ok(())
    }

    /// Returns ID of the draft message, if there is one.
    async fn get_draft_msg_id(self, context: &Context) -> Result<Option<MsgId>> {
        let msg_id: Option<MsgId> = context
            .sql
            .query_get_value(
                "SELECT id FROM msgs WHERE chat_id=? AND state=?;",
                (self, MessageState::OutDraft),
            )
            .await?;
        Ok(msg_id)
    }

    /// Returns draft message, if there is one.
    pub async fn get_draft(self, context: &Context) -> Result<Option<Message>> {
        if self.is_special() {
            return Ok(None);
        }
        match self.get_draft_msg_id(context).await? {
            Some(draft_msg_id) => {
                let msg = Message::load_from_db(context, draft_msg_id).await?;
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    /// Deletes draft message, if there is one.
    ///
    /// Returns `true`, if message was deleted, `false` otherwise.
    async fn maybe_delete_draft(self, context: &Context) -> Result<bool> {
        Ok(context
            .sql
            .execute(
                "DELETE FROM msgs WHERE chat_id=? AND state=?",
                (self, MessageState::OutDraft),
            )
            .await?
            > 0)
    }

    /// Set provided message as draft message for specified chat.
    /// Returns true if the draft was added or updated in place.
    async fn do_set_draft(self, context: &Context, msg: &mut Message) -> Result<bool> {
        match msg.viewtype {
            Viewtype::Unknown => bail!("Can not set draft of unknown type."),
            Viewtype::Text => {
                if msg.text.is_empty() && msg.in_reply_to.is_none_or_empty() {
                    bail!("No text and no quote in draft");
                }
            }
            _ => {
                if msg.viewtype == Viewtype::File {
                    if let Some((better_type, _)) = message::guess_msgtype_from_suffix(msg)
                        // We do not do an automatic conversion to other viewtypes here so that
                        // users can send images as "files" to preserve the original quality
                        // (usually we compress images). The remaining conversions are done by
                        // `prepare_msg_blob()` later.
                        .filter(|&(vt, _)| vt == Viewtype::Webxdc || vt == Viewtype::Vcard)
                    {
                        msg.viewtype = better_type;
                    }
                }
                if msg.viewtype == Viewtype::Vcard {
                    let blob = msg
                        .param
                        .get_file_blob(context)?
                        .context("no file stored in params")?;
                    msg.try_set_vcard(context, &blob.to_abs_path()).await?;
                }
            }
        }

        // set back draft information to allow identifying the draft later on -
        // no matter if message object is reused or reloaded from db
        msg.state = MessageState::OutDraft;
        msg.chat_id = self;

        // if possible, replace existing draft and keep id
        if !msg.id.is_special() {
            if let Some(old_draft) = self.get_draft(context).await? {
                if old_draft.id == msg.id
                    && old_draft.chat_id == self
                    && old_draft.state == MessageState::OutDraft
                {
                    let affected_rows = context
                        .sql.execute(
                                "UPDATE msgs
                                SET timestamp=?1,type=?2,txt=?3,txt_normalized=?4,param=?5,mime_in_reply_to=?6
                                WHERE id=?7
                                AND (type <> ?2 
                                    OR txt <> ?3 
                                    OR txt_normalized <> ?4
                                    OR param <> ?5
                                    OR mime_in_reply_to <> ?6);",
                                (
                                    time(),
                                    msg.viewtype,
                                    &msg.text,
                                    message::normalize_text(&msg.text),
                                    msg.param.to_string(),
                                    msg.in_reply_to.as_deref().unwrap_or_default(),
                                    msg.id,
                                ),
                            ).await?;
                    return Ok(affected_rows > 0);
                }
            }
        }

        let row_id = context
            .sql
            .transaction(|transaction| {
                // Delete existing draft if it exists.
                transaction.execute(
                    "DELETE FROM msgs WHERE chat_id=? AND state=?",
                    (self, MessageState::OutDraft),
                )?;

                // Insert new draft.
                transaction.execute(
                    "INSERT INTO msgs (
                 chat_id,
                 rfc724_mid,
                 from_id,
                 timestamp,
                 type,
                 state,
                 txt,
                 txt_normalized,
                 param,
                 hidden,
                 mime_in_reply_to)
         VALUES (?,?,?,?,?,?,?,?,?,?,?);",
                    (
                        self,
                        &msg.rfc724_mid,
                        ContactId::SELF,
                        time(),
                        msg.viewtype,
                        MessageState::OutDraft,
                        &msg.text,
                        message::normalize_text(&msg.text),
                        msg.param.to_string(),
                        1,
                        msg.in_reply_to.as_deref().unwrap_or_default(),
                    ),
                )?;

                Ok(transaction.last_insert_rowid())
            })
            .await?;
        msg.id = MsgId::new(row_id.try_into()?);
        Ok(true)
    }

    /// Returns number of messages in a chat.
    pub async fn get_msg_cnt(self, context: &Context) -> Result<usize> {
        let count = context
            .sql
            .count(
                "SELECT COUNT(*) FROM msgs WHERE hidden=0 AND chat_id=?",
                (self,),
            )
            .await?;
        Ok(count)
    }

    /// Returns the number of fresh messages in the chat.
    pub async fn get_fresh_msg_cnt(self, context: &Context) -> Result<usize> {
        // this function is typically used to show a badge counter beside _each_ chatlist item.
        // to make this as fast as possible, esp. on older devices, we added an combined index over the rows used for querying.
        // so if you alter the query here, you may want to alter the index over `(state, hidden, chat_id)` in `sql.rs`.
        //
        // the impact of the index is significant once the database grows:
        // - on an older android4 with 18k messages, query-time decreased from 110ms to 2ms
        // - on an mid-class moto-g or iphone7 with 50k messages, query-time decreased from 26ms or 6ms to 0-1ms
        // the times are average, no matter if there are fresh messages or not -
        // and have to be multiplied by the number of items shown at once on the chatlist,
        // so savings up to 2 seconds are possible on older devices - newer ones will feel "snappier" :)
        let count = if self.is_archived_link() {
            context
                .sql
                .count(
                    "SELECT COUNT(DISTINCT(m.chat_id))
                    FROM msgs m
                    LEFT JOIN chats c ON m.chat_id=c.id
                    WHERE m.state=10
                    and m.hidden=0
                    AND m.chat_id>9
                    AND c.blocked=0
                    AND c.archived=1
                    ",
                    (),
                )
                .await?
        } else {
            context
                .sql
                .count(
                    "SELECT COUNT(*)
                FROM msgs
                WHERE state=?
                AND hidden=0
                AND chat_id=?;",
                    (MessageState::InFresh, self),
                )
                .await?
        };
        Ok(count)
    }

    pub(crate) async fn created_timestamp(self, context: &Context) -> Result<i64> {
        Ok(context
            .sql
            .query_get_value("SELECT created_timestamp FROM chats WHERE id=?", (self,))
            .await?
            .unwrap_or(0))
    }

    /// Returns timestamp of the latest message in the chat,
    /// including hidden messages or a draft if there is one.
    pub(crate) async fn get_timestamp(self, context: &Context) -> Result<Option<i64>> {
        let timestamp = context
            .sql
            .query_get_value(
                "SELECT MAX(timestamp)
                 FROM msgs
                 WHERE chat_id=?
                 HAVING COUNT(*) > 0",
                (self,),
            )
            .await?;
        Ok(timestamp)
    }

    /// Returns a list of active similar chat IDs sorted by similarity metric.
    ///
    /// Jaccard similarity coefficient is used to estimate similarity of chat member sets.
    ///
    /// Chat is considered active if something was posted there within the last 42 days.
    pub async fn get_similar_chat_ids(self, context: &Context) -> Result<Vec<(ChatId, f64)>> {
        // Count number of common members in this and other chats.
        let intersection: Vec<(ChatId, f64)> = context
            .sql
            .query_map(
                "SELECT y.chat_id, SUM(x.contact_id = y.contact_id)
                 FROM chats_contacts as x
                 JOIN chats_contacts as y
                 WHERE x.contact_id > 9
                   AND y.contact_id > 9
                   AND x.add_timestamp >= x.remove_timestamp
                   AND y.add_timestamp >= y.remove_timestamp
                   AND x.chat_id=?
                   AND y.chat_id<>x.chat_id
                   AND y.chat_id>?
                 GROUP BY y.chat_id",
                (self, DC_CHAT_ID_LAST_SPECIAL),
                |row| {
                    let chat_id: ChatId = row.get(0)?;
                    let intersection: f64 = row.get(1)?;
                    Ok((chat_id, intersection))
                },
                |rows| {
                    rows.collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(Into::into)
                },
            )
            .await
            .context("failed to calculate member set intersections")?;

        let chat_size: HashMap<ChatId, f64> = context
            .sql
            .query_map(
                "SELECT chat_id, count(*) AS n
                 FROM chats_contacts
                 WHERE contact_id > ? AND chat_id > ?
                 AND add_timestamp >= remove_timestamp
                 GROUP BY chat_id",
                (ContactId::LAST_SPECIAL, DC_CHAT_ID_LAST_SPECIAL),
                |row| {
                    let chat_id: ChatId = row.get(0)?;
                    let size: f64 = row.get(1)?;
                    Ok((chat_id, size))
                },
                |rows| {
                    rows.collect::<std::result::Result<HashMap<ChatId, f64>, _>>()
                        .map_err(Into::into)
                },
            )
            .await
            .context("failed to count chat member sizes")?;

        let our_chat_size = chat_size.get(&self).copied().unwrap_or_default();
        let mut chats_with_metrics = Vec::new();
        for (chat_id, intersection_size) in intersection {
            if intersection_size > 0.0 {
                let other_chat_size = chat_size.get(&chat_id).copied().unwrap_or_default();
                let union_size = our_chat_size + other_chat_size - intersection_size;
                let metric = intersection_size / union_size;
                chats_with_metrics.push((chat_id, metric))
            }
        }
        chats_with_metrics.sort_unstable_by(|(chat_id1, metric1), (chat_id2, metric2)| {
            metric2
                .partial_cmp(metric1)
                .unwrap_or(chat_id2.cmp(chat_id1))
        });

        // Select up to five similar active chats.
        let mut res = Vec::new();
        let now = time();
        for (chat_id, metric) in chats_with_metrics {
            if let Some(chat_timestamp) = chat_id.get_timestamp(context).await? {
                if now > chat_timestamp + 42 * 24 * 3600 {
                    // Chat was inactive for 42 days, skip.
                    continue;
                }
            }

            if metric < 0.1 {
                // Chat is unrelated.
                break;
            }

            let chat = Chat::load_from_db(context, chat_id).await?;
            if chat.typ != Chattype::Group {
                continue;
            }

            match chat.visibility {
                ChatVisibility::Normal | ChatVisibility::Pinned => {}
                ChatVisibility::Archived => continue,
            }

            res.push((chat_id, metric));
            if res.len() >= 5 {
                break;
            }
        }

        Ok(res)
    }

    /// Returns similar chats as a [`Chatlist`].
    ///
    /// [`Chatlist`]: crate::chatlist::Chatlist
    pub async fn get_similar_chatlist(self, context: &Context) -> Result<Chatlist> {
        let chat_ids: Vec<ChatId> = self
            .get_similar_chat_ids(context)
            .await
            .context("failed to get similar chat IDs")?
            .into_iter()
            .map(|(chat_id, _metric)| chat_id)
            .collect();
        let chatlist = Chatlist::from_chat_ids(context, &chat_ids).await?;
        Ok(chatlist)
    }

    pub(crate) async fn get_param(self, context: &Context) -> Result<Params> {
        let res: Option<String> = context
            .sql
            .query_get_value("SELECT param FROM chats WHERE id=?", (self,))
            .await?;
        Ok(res
            .map(|s| s.parse().unwrap_or_default())
            .unwrap_or_default())
    }

    /// Returns true if the chat is not promoted.
    pub(crate) async fn is_unpromoted(self, context: &Context) -> Result<bool> {
        let param = self.get_param(context).await?;
        let unpromoted = param.get_bool(Param::Unpromoted).unwrap_or_default();
        Ok(unpromoted)
    }

    /// Returns true if the chat is promoted.
    pub(crate) async fn is_promoted(self, context: &Context) -> Result<bool> {
        let promoted = !self.is_unpromoted(context).await?;
        Ok(promoted)
    }

    /// Returns true if chat is a saved messages chat.
    pub async fn is_self_talk(self, context: &Context) -> Result<bool> {
        Ok(self.get_param(context).await?.exists(Param::Selftalk))
    }

    /// Returns true if chat is a device chat.
    pub async fn is_device_talk(self, context: &Context) -> Result<bool> {
        Ok(self.get_param(context).await?.exists(Param::Devicetalk))
    }

    async fn parent_query<T, F>(
        self,
        context: &Context,
        fields: &str,
        state_out_min: MessageState,
        f: F,
    ) -> Result<Option<T>>
    where
        F: Send + FnOnce(&rusqlite::Row) -> rusqlite::Result<T>,
        T: Send + 'static,
    {
        let sql = &context.sql;
        let query = format!(
            "SELECT {fields} \
             FROM msgs \
             WHERE chat_id=? \
             AND ((state BETWEEN {} AND {}) OR (state >= {})) \
             AND NOT hidden \
             AND download_state={} \
             AND from_id != {} \
             ORDER BY timestamp DESC, id DESC \
             LIMIT 1;",
            MessageState::InFresh as u32,
            MessageState::InSeen as u32,
            state_out_min as u32,
            // Do not reply to not fully downloaded messages. Such a message could be a group chat
            // message that we assigned to 1:1 chat.
            DownloadState::Done as u32,
            // Do not reference info messages, they are not actually sent out
            // and have Message-IDs unknown to other chat members.
            ContactId::INFO.to_u32(),
        );
        sql.query_row_optional(&query, (self,), f).await
    }

    async fn get_parent_mime_headers(
        self,
        context: &Context,
        state_out_min: MessageState,
    ) -> Result<Option<(String, String, String)>> {
        self.parent_query(
            context,
            "rfc724_mid, mime_in_reply_to, IFNULL(mime_references, '')",
            state_out_min,
            |row: &rusqlite::Row| {
                let rfc724_mid: String = row.get(0)?;
                let mime_in_reply_to: String = row.get(1)?;
                let mime_references: String = row.get(2)?;
                Ok((rfc724_mid, mime_in_reply_to, mime_references))
            },
        )
        .await
    }

    /// Returns multi-line text summary of encryption preferences of all chat contacts.
    ///
    /// This can be used to find out if encryption is not available because
    /// keys for some users are missing or simply because the majority of the users in a group
    /// prefer plaintext emails.
    ///
    /// To get more verbose summary for a contact, including its key fingerprint, use [`Contact::get_encrinfo`].
    pub async fn get_encryption_info(self, context: &Context) -> Result<String> {
        let mut ret_available = String::new();
        let mut ret_reset = String::new();

        for contact_id in get_chat_contacts(context, self)
            .await?
            .iter()
            .filter(|&contact_id| !contact_id.is_special())
        {
            let contact = Contact::get_by_id(context, *contact_id).await?;
            let addr = contact.get_addr();
            let peerstate = Peerstate::from_addr(context, addr).await?;

            match peerstate
                .filter(|peerstate| peerstate.peek_key(false).is_some())
                .map(|peerstate| peerstate.prefer_encrypt)
            {
                Some(EncryptPreference::Mutual) | Some(EncryptPreference::NoPreference) => {
                    ret_available += &format!("{addr}\n")
                }
                Some(EncryptPreference::Reset) | None => ret_reset += &format!("{addr}\n"),
            };
        }

        let mut ret = String::new();
        if !ret_reset.is_empty() {
            ret += &stock_str::encr_none(context).await;
            ret.push(':');
            ret.push('\n');
            ret += &ret_reset;
        }
        if !ret_available.is_empty() {
            if !ret.is_empty() {
                ret.push('\n');
            }
            ret += &stock_str::e2e_available(context).await;
            ret.push(':');
            ret.push('\n');
            ret += &ret_available;
        }

        Ok(ret.trim().to_string())
    }

    /// Bad evil escape hatch.
    ///
    /// Avoid using this, eventually types should be cleaned up enough
    /// that it is no longer necessary.
    pub fn to_u32(self) -> u32 {
        self.0
    }

    pub(crate) async fn reset_gossiped_timestamp(self, context: &Context) -> Result<()> {
        context
            .sql
            .execute("DELETE FROM gossip_timestamp WHERE chat_id=?", (self,))
            .await?;
        Ok(())
    }

    /// Returns true if the chat is protected.
    pub async fn is_protected(self, context: &Context) -> Result<ProtectionStatus> {
        let protection_status = context
            .sql
            .query_get_value("SELECT protected FROM chats WHERE id=?", (self,))
            .await?
            .unwrap_or_default();
        Ok(protection_status)
    }

    /// Returns the sort timestamp for a new message in the chat.
    ///
    /// `message_timestamp` should be either the message "sent" timestamp or a timestamp of the
    /// corresponding event in case of a system message (usually the current system time).
    /// `always_sort_to_bottom` makes this adjust the returned timestamp up so that the message goes
    /// to the chat bottom.
    /// `received` -- whether the message is received. Otherwise being sent.
    /// `incoming` -- whether the message is incoming.
    pub(crate) async fn calc_sort_timestamp(
        self,
        context: &Context,
        message_timestamp: i64,
        always_sort_to_bottom: bool,
        received: bool,
        incoming: bool,
    ) -> Result<i64> {
        let mut sort_timestamp = cmp::min(message_timestamp, smeared_time(context));

        let last_msg_time: Option<i64> = if always_sort_to_bottom {
            // get newest message for this chat

            // Let hidden messages also be ordered with protection messages because hidden messages
            // also can be or not be verified, so let's preserve this information -- even it's not
            // used currently, it can be useful in the future versions.
            context
                .sql
                .query_get_value(
                    "SELECT MAX(timestamp)
                     FROM msgs
                     WHERE chat_id=? AND state!=?
                     HAVING COUNT(*) > 0",
                    (self, MessageState::OutDraft),
                )
                .await?
        } else if received {
            // Received messages shouldn't mingle with just sent ones and appear somewhere in the
            // middle of the chat, so we go after the newest non fresh message.
            //
            // But if a received outgoing message is older than some seen message, better sort the
            // received message purely by timestamp. We could place it just before that seen
            // message, but anyway the user may not notice it.
            //
            // NB: Received outgoing messages may break sorting of fresh incoming ones, but this
            // shouldn't happen frequently. Seen incoming messages don't really break sorting of
            // fresh ones, they rather mean that older incoming messages are actually seen as well.
            context
                .sql
                .query_row_optional(
                    "SELECT MAX(timestamp), MAX(IIF(state=?,timestamp_sent,0))
                     FROM msgs
                     WHERE chat_id=? AND hidden=0 AND state>?
                     HAVING COUNT(*) > 0",
                    (MessageState::InSeen, self, MessageState::InFresh),
                    |row| {
                        let ts: i64 = row.get(0)?;
                        let ts_sent_seen: i64 = row.get(1)?;
                        Ok((ts, ts_sent_seen))
                    },
                )
                .await?
                .and_then(|(ts, ts_sent_seen)| {
                    match incoming || ts_sent_seen <= message_timestamp {
                        true => Some(ts),
                        false => None,
                    }
                })
        } else {
            None
        };

        if let Some(last_msg_time) = last_msg_time {
            if last_msg_time > sort_timestamp {
                sort_timestamp = last_msg_time;
            }
        }

        Ok(sort_timestamp)
    }

    /// Spawns a task checking after a timeout whether the SecureJoin has finished for the 1:1 chat
    /// and otherwise notifying the user accordingly.
    pub(crate) fn spawn_securejoin_wait(self, context: &Context, timeout: u64) {
        let context = context.clone();
        task::spawn(async move {
            tokio::time::sleep(Duration::from_secs(timeout)).await;
            let chat = Chat::load_from_db(&context, self).await?;
            chat.check_securejoin_wait(&context, 0).await?;
            Result::<()>::Ok(())
        });
    }
}

impl std::fmt::Display for ChatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_trash() {
            write!(f, "Chat#Trash")
        } else if self.is_archived_link() {
            write!(f, "Chat#ArchivedLink")
        } else if self.is_alldone_hint() {
            write!(f, "Chat#AlldoneHint")
        } else if self.is_special() {
            write!(f, "Chat#Special{}", self.0)
        } else {
            write!(f, "Chat#{}", self.0)
        }
    }
}

/// Allow converting [ChatId] to an SQLite type.
///
/// This allows you to directly store [ChatId] into the database as
/// well as query for a [ChatId].
impl rusqlite::types::ToSql for ChatId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput> {
        let val = rusqlite::types::Value::Integer(i64::from(self.0));
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

/// Allow converting an SQLite integer directly into [ChatId].
impl rusqlite::types::FromSql for ChatId {
    fn column_result(value: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        i64::column_result(value).and_then(|val| {
            if 0 <= val && val <= i64::from(u32::MAX) {
                Ok(ChatId::new(val as u32))
            } else {
                Err(rusqlite::types::FromSqlError::OutOfRange(val))
            }
        })
    }
}

/// An object representing a single chat in memory.
/// Chat objects are created using eg. `Chat::load_from_db`
/// and are not updated on database changes;
/// if you want an update, you have to recreate the object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Chat {
    /// Database ID.
    pub id: ChatId,

    /// Chat type, e.g. 1:1 chat, group chat, mailing list.
    pub typ: Chattype,

    /// Chat name.
    pub name: String,

    /// Whether the chat is archived or pinned.
    pub visibility: ChatVisibility,

    /// Group ID. For [`Chattype::Mailinglist`] -- mailing list address. Empty for 1:1 chats and
    /// ad-hoc groups.
    pub grpid: String,

    /// Whether the chat is blocked, unblocked or a contact request.
    pub blocked: Blocked,

    /// Additional chat parameters stored in the database.
    pub param: Params,

    /// If location streaming is enabled in the chat.
    is_sending_locations: bool,

    /// Duration of the chat being muted.
    pub mute_duration: MuteDuration,

    /// If the chat is protected (verified).
    pub(crate) protected: ProtectionStatus,
}

impl Chat {
    /// Loads chat from the database by its ID.
    pub async fn load_from_db(context: &Context, chat_id: ChatId) -> Result<Self> {
        let mut chat = context
            .sql
            .query_row(
                "SELECT c.type, c.name, c.grpid, c.param, c.archived,
                    c.blocked, c.locations_send_until, c.muted_until, c.protected
             FROM chats c
             WHERE c.id=?;",
                (chat_id,),
                |row| {
                    let c = Chat {
                        id: chat_id,
                        typ: row.get(0)?,
                        name: row.get::<_, String>(1)?,
                        grpid: row.get::<_, String>(2)?,
                        param: row.get::<_, String>(3)?.parse().unwrap_or_default(),
                        visibility: row.get(4)?,
                        blocked: row.get::<_, Option<_>>(5)?.unwrap_or_default(),
                        is_sending_locations: row.get(6)?,
                        mute_duration: row.get(7)?,
                        protected: row.get(8)?,
                    };
                    Ok(c)
                },
            )
            .await
            .context(format!("Failed loading chat {chat_id} from database"))?;

        if chat.id.is_archived_link() {
            chat.name = stock_str::archived_chats(context).await;
        } else {
            if chat.typ == Chattype::Single && chat.name.is_empty() {
                // chat.name is set to contact.display_name on changes,
                // however, if things went wrong somehow, we do this here explicitly.
                let mut chat_name = "Err [Name not found]".to_owned();
                match get_chat_contacts(context, chat.id).await {
                    Ok(contacts) => {
                        if let Some(contact_id) = contacts.first() {
                            if let Ok(contact) = Contact::get_by_id(context, *contact_id).await {
                                contact.get_display_name().clone_into(&mut chat_name);
                            }
                        }
                    }
                    Err(err) => {
                        error!(
                            context,
                            "Failed to load contacts for {}: {:#}.", chat.id, err
                        );
                    }
                }
                chat.name = chat_name;
            }
            if chat.param.exists(Param::Selftalk) {
                chat.name = stock_str::saved_messages(context).await;
            } else if chat.param.exists(Param::Devicetalk) {
                chat.name = stock_str::device_messages(context).await;
            }
        }

        Ok(chat)
    }

    /// Returns whether this is the `saved messages` chat
    pub fn is_self_talk(&self) -> bool {
        self.param.exists(Param::Selftalk)
    }

    /// Returns true if chat is a device chat.
    pub fn is_device_talk(&self) -> bool {
        self.param.exists(Param::Devicetalk)
    }

    /// Returns true if chat is a mailing list.
    pub fn is_mailing_list(&self) -> bool {
        self.typ == Chattype::Mailinglist
    }

    /// Returns None if user can send messages to this chat.
    ///
    /// Otherwise returns a reason useful for logging.
    pub(crate) async fn why_cant_send(&self, context: &Context) -> Result<Option<CantSendReason>> {
        self.why_cant_send_ex(context, &|_| false).await
    }

    pub(crate) async fn why_cant_send_ex(
        &self,
        context: &Context,
        skip_fn: &(dyn Send + Sync + Fn(&CantSendReason) -> bool),
    ) -> Result<Option<CantSendReason>> {
        use CantSendReason::*;
        // NB: Don't forget to update Chatlist::try_load() when changing this function!

        if self.id.is_special() {
            let reason = SpecialChat;
            if !skip_fn(&reason) {
                return Ok(Some(reason));
            }
        }
        if self.is_device_talk() {
            let reason = DeviceChat;
            if !skip_fn(&reason) {
                return Ok(Some(reason));
            }
        }
        if self.is_contact_request() {
            let reason = ContactRequest;
            if !skip_fn(&reason) {
                return Ok(Some(reason));
            }
        }
        if self.is_protection_broken() {
            let reason = ProtectionBroken;
            if !skip_fn(&reason) {
                return Ok(Some(reason));
            }
        }
        if self.is_mailing_list() && self.get_mailinglist_addr().is_none_or_empty() {
            let reason = ReadOnlyMailingList;
            if !skip_fn(&reason) {
                return Ok(Some(reason));
            }
        }

        // Do potentially slow checks last and after calls to `skip_fn` which should be fast.
        let reason = NotAMember;
        if !skip_fn(&reason) && !self.is_self_in_chat(context).await? {
            return Ok(Some(reason));
        }
        let reason = SecurejoinWait;
        if !skip_fn(&reason)
            && self
                .check_securejoin_wait(context, constants::SECUREJOIN_WAIT_TIMEOUT)
                .await?
                > 0
        {
            return Ok(Some(reason));
        }
        Ok(None)
    }

    /// Returns true if can send to the chat.
    ///
    /// This function can be used by the UI to decide whether to display the input box.
    pub async fn can_send(&self, context: &Context) -> Result<bool> {
        Ok(self.why_cant_send(context).await?.is_none())
    }

    /// Returns the remaining timeout for the 1:1 chat in-progress SecureJoin.
    ///
    /// If the timeout has expired, adds an info message with additional information.
    /// See also [`CantSendReason::SecurejoinWait`].
    pub(crate) async fn check_securejoin_wait(
        &self,
        context: &Context,
        timeout: u64,
    ) -> Result<u64> {
        if self.typ != Chattype::Single || self.protected != ProtectionStatus::Unprotected {
            return Ok(0);
        }

        // chat is single and unprotected:
        // get last info message of type SecurejoinWait or SecurejoinWaitTimeout
        let (mut param_wait, mut param_timeout) = (Params::new(), Params::new());
        param_wait.set_cmd(SystemMessage::SecurejoinWait);
        param_timeout.set_cmd(SystemMessage::SecurejoinWaitTimeout);
        let (param_wait, param_timeout) = (param_wait.to_string(), param_timeout.to_string());
        let Some((param, ts_sort, ts_start)) = context
            .sql
            .query_row_optional(
                "SELECT param, timestamp, timestamp_sent FROM msgs WHERE id=\
                 (SELECT MAX(id) FROM msgs WHERE chat_id=? AND param IN (?, ?))",
                (self.id, &param_wait, &param_timeout),
                |row| {
                    let param: String = row.get(0)?;
                    let ts_sort: i64 = row.get(1)?;
                    let ts_start: i64 = row.get(2)?;
                    Ok((param, ts_sort, ts_start))
                },
            )
            .await?
        else {
            return Ok(0);
        };
        if param == param_timeout {
            return Ok(0);
        }

        let now = time();
        // Don't await SecureJoin if the clock was set back.
        if ts_start <= now {
            let timeout = ts_start
                .saturating_add(timeout.try_into()?)
                .saturating_sub(now);
            if timeout > 0 {
                return Ok(timeout as u64);
            }
        }
        add_info_msg_with_cmd(
            context,
            self.id,
            &stock_str::securejoin_takes_longer(context).await,
            SystemMessage::SecurejoinWaitTimeout,
            // Use the sort timestamp of the "please wait" message, this way the added message is
            // never sorted below the protection message if the SecureJoin finishes in parallel.
            ts_sort,
            Some(now),
            None,
            None,
            None,
        )
        .await?;
        context.emit_event(EventType::ChatModified(self.id));
        Ok(0)
    }

    /// Checks if the user is part of a chat
    /// and has basically the permissions to edit the chat therefore.
    /// The function does not check if the chat type allows editing of concrete elements.
    pub(crate) async fn is_self_in_chat(&self, context: &Context) -> Result<bool> {
        match self.typ {
            Chattype::Single | Chattype::Broadcast | Chattype::Mailinglist => Ok(true),
            Chattype::Group => is_contact_in_chat(context, self.id, ContactId::SELF).await,
        }
    }

    pub(crate) async fn update_param(&mut self, context: &Context) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE chats SET param=? WHERE id=?",
                (self.param.to_string(), self.id),
            )
            .await?;
        Ok(())
    }

    /// Returns chat ID.
    pub fn get_id(&self) -> ChatId {
        self.id
    }

    /// Returns chat type.
    pub fn get_type(&self) -> Chattype {
        self.typ
    }

    /// Returns chat name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns mailing list address where messages are sent to.
    pub fn get_mailinglist_addr(&self) -> Option<&str> {
        self.param.get(Param::ListPost)
    }

    /// Returns profile image path for the chat.
    pub async fn get_profile_image(&self, context: &Context) -> Result<Option<PathBuf>> {
        if let Some(image_rel) = self.param.get(Param::ProfileImage) {
            if !image_rel.is_empty() {
                return Ok(Some(get_abs_path(context, Path::new(&image_rel))));
            }
        } else if self.id.is_archived_link() {
            if let Ok(image_rel) = get_archive_icon(context).await {
                return Ok(Some(get_abs_path(context, Path::new(&image_rel))));
            }
        } else if self.typ == Chattype::Single {
            let contacts = get_chat_contacts(context, self.id).await?;
            if let Some(contact_id) = contacts.first() {
                if let Ok(contact) = Contact::get_by_id(context, *contact_id).await {
                    return contact.get_profile_image(context).await;
                }
            }
        } else if self.typ == Chattype::Broadcast {
            if let Ok(image_rel) = get_broadcast_icon(context).await {
                return Ok(Some(get_abs_path(context, Path::new(&image_rel))));
            }
        }
        Ok(None)
    }

    /// Returns chat avatar color.
    ///
    /// For 1:1 chats, the color is calculated from the contact's address.
    /// For group chats the color is calculated from the chat name.
    pub async fn get_color(&self, context: &Context) -> Result<u32> {
        let mut color = 0;

        if self.typ == Chattype::Single {
            let contacts = get_chat_contacts(context, self.id).await?;
            if let Some(contact_id) = contacts.first() {
                if let Ok(contact) = Contact::get_by_id(context, *contact_id).await {
                    color = contact.get_color();
                }
            }
        } else {
            color = str_to_color(&self.name);
        }

        Ok(color)
    }

    /// Returns a struct describing the current state of the chat.
    ///
    /// This is somewhat experimental, even more so than the rest of
    /// deltachat, and the data returned is still subject to change.
    pub async fn get_info(&self, context: &Context) -> Result<ChatInfo> {
        let draft = match self.id.get_draft(context).await? {
            Some(message) => message.text,
            _ => String::new(),
        };
        Ok(ChatInfo {
            id: self.id,
            type_: self.typ as u32,
            name: self.name.clone(),
            archived: self.visibility == ChatVisibility::Archived,
            param: self.param.to_string(),
            is_sending_locations: self.is_sending_locations,
            color: self.get_color(context).await?,
            profile_image: self
                .get_profile_image(context)
                .await?
                .unwrap_or_else(std::path::PathBuf::new),
            draft,
            is_muted: self.is_muted(),
            ephemeral_timer: self.id.get_ephemeral_timer(context).await?,
        })
    }

    /// Returns chat visibilitiy, e.g. whether it is archived or pinned.
    pub fn get_visibility(&self) -> ChatVisibility {
        self.visibility
    }

    /// Returns true if chat is a contact request.
    ///
    /// Messages cannot be sent to such chat and read receipts are not
    /// sent until the chat is manually unblocked.
    pub fn is_contact_request(&self) -> bool {
        self.blocked == Blocked::Request
    }

    /// Returns true if the chat is not promoted.
    pub fn is_unpromoted(&self) -> bool {
        self.param.get_bool(Param::Unpromoted).unwrap_or_default()
    }

    /// Returns true if the chat is promoted.
    /// This means a message has been sent to it and it _not_ only exists on the users device.
    pub fn is_promoted(&self) -> bool {
        !self.is_unpromoted()
    }

    /// Returns true if chat protection is enabled.
    ///
    /// UI should display a green checkmark
    /// in the chat title,
    /// in the chat profile title and
    /// in the chatlist item
    /// if chat protection is enabled.
    /// UI should also display a green checkmark
    /// in the contact profile
    /// if 1:1 chat with this contact exists and is protected.
    pub fn is_protected(&self) -> bool {
        self.protected == ProtectionStatus::Protected
    }

    /// Returns true if the chat was protected, and then an incoming message broke this protection.
    ///
    /// This function is only useful if the UI enabled the `verified_one_on_one_chats` feature flag,
    /// otherwise it will return false for all chats.
    ///
    /// 1:1 chats are automatically set as protected when a contact is verified.
    /// When a message comes in that is not encrypted / signed correctly,
    /// the chat is automatically set as unprotected again.
    /// `is_protection_broken()` will return true until `chat_id.accept()` is called.
    ///
    /// The UI should let the user confirm that this is OK with a message like
    /// `Bob sent a message from another device. Tap to learn more`
    /// and then call `chat_id.accept()`.
    pub fn is_protection_broken(&self) -> bool {
        match self.protected {
            ProtectionStatus::Protected => false,
            ProtectionStatus::Unprotected => false,
            ProtectionStatus::ProtectionBroken => true,
        }
    }

    /// Returns true if location streaming is enabled in the chat.
    pub fn is_sending_locations(&self) -> bool {
        self.is_sending_locations
    }

    /// Returns true if the chat is currently muted.
    pub fn is_muted(&self) -> bool {
        match self.mute_duration {
            MuteDuration::NotMuted => false,
            MuteDuration::Forever => true,
            MuteDuration::Until(when) => when > SystemTime::now(),
        }
    }

    /// Returns chat member list timestamp.
    pub(crate) async fn member_list_timestamp(&self, context: &Context) -> Result<i64> {
        if let Some(member_list_timestamp) = self.param.get_i64(Param::MemberListTimestamp) {
            Ok(member_list_timestamp)
        } else {
            Ok(self.id.created_timestamp(context).await?)
        }
    }

    /// Returns true if member list is stale,
    /// i.e. has not been updated for 60 days.
    ///
    /// This is used primarily to detect the case
    /// where the user just restored an old backup.
    pub(crate) async fn member_list_is_stale(&self, context: &Context) -> Result<bool> {
        let now = time();
        let member_list_ts = self.member_list_timestamp(context).await?;
        let is_stale = now.saturating_add(TIMESTAMP_SENT_TOLERANCE)
            >= member_list_ts.saturating_add(60 * 24 * 3600);
        Ok(is_stale)
    }

    /// Adds missing values to the msg object,
    /// writes the record to the database and returns its msg_id.
    ///
    /// If `update_msg_id` is set, that record is reused;
    /// if `update_msg_id` is None, a new record is created.
    async fn prepare_msg_raw(
        &mut self,
        context: &Context,
        msg: &mut Message,
        update_msg_id: Option<MsgId>,
        timestamp: i64,
    ) -> Result<MsgId> {
        let mut to_id = 0;
        let mut location_id = 0;

        if msg.rfc724_mid.is_empty() {
            msg.rfc724_mid = create_outgoing_rfc724_mid();
        }

        if self.typ == Chattype::Single {
            if let Some(id) = context
                .sql
                .query_get_value(
                    "SELECT contact_id FROM chats_contacts WHERE chat_id=?;",
                    (self.id,),
                )
                .await?
            {
                to_id = id;
            } else {
                error!(
                    context,
                    "Cannot send message, contact for {} not found.", self.id,
                );
                bail!("Cannot set message, contact for {} not found.", self.id);
            }
        } else if self.typ == Chattype::Group
            && self.param.get_int(Param::Unpromoted).unwrap_or_default() == 1
        {
            msg.param.set_int(Param::AttachGroupImage, 1);
            self.param
                .remove(Param::Unpromoted)
                .set_i64(Param::GroupNameTimestamp, timestamp);
            self.update_param(context).await?;
            // TODO: Remove this compat code needed because Core <= v1.143:
            // - doesn't accept synchronization of QR code tokens for unpromoted groups, so we also
            //   send them when the group is promoted.
            // - doesn't sync QR code tokens for unpromoted groups and the group might be created
            //   before an upgrade.
            context
                .sync_qr_code_tokens(Some(self.grpid.as_str()))
                .await
                .log_err(context)
                .ok();
        }

        let is_bot = context.get_config_bool(Config::Bot).await?;
        msg.param
            .set_optional(Param::Bot, Some("1").filter(|_| is_bot));

        // Set "In-Reply-To:" to identify the message to which the composed message is a reply.
        // Set "References:" to identify the "thread" of the conversation.
        // Both according to [RFC 5322 3.6.4, page 25](https://www.rfc-editor.org/rfc/rfc5322#section-3.6.4).
        let new_references;
        if self.is_self_talk() {
            // As self-talks are mainly used to transfer data between devices,
            // we do not set In-Reply-To/References in this case.
            new_references = String::new();
        } else if let Some((parent_rfc724_mid, parent_in_reply_to, parent_references)) =
            // We don't filter `OutPending` and `OutFailed` messages because the new message for
            // which `parent_query()` is done may assume that it will be received in a context
            // affected by those messages, e.g. they could add new members to a group and the
            // new message will contain them in "To:". Anyway recipients must be prepared to
            // orphaned references.
            self
                .id
                .get_parent_mime_headers(context, MessageState::OutPending)
                .await?
        {
            // "In-Reply-To:" is not changed if it is set manually.
            // This does not affect "References:" header, it will contain "default parent" (the
            // latest message in the thread) anyway.
            if msg.in_reply_to.is_none() && !parent_rfc724_mid.is_empty() {
                msg.in_reply_to = Some(parent_rfc724_mid.clone());
            }

            // Use parent `In-Reply-To` as a fallback
            // in case parent message has no `References` header
            // as specified in RFC 5322:
            // > If the parent message does not contain
            // > a "References:" field but does have an "In-Reply-To:" field
            // > containing a single message identifier, then the "References:" field
            // > will contain the contents of the parent's "In-Reply-To:" field
            // > followed by the contents of the parent's "Message-ID:" field (if
            // > any).
            let parent_references = if parent_references.is_empty() {
                parent_in_reply_to
            } else {
                parent_references
            };

            // The whole list of messages referenced may be huge.
            // Only take 2 recent references and add third from `In-Reply-To`.
            let mut references_vec: Vec<&str> = parent_references.rsplit(' ').take(2).collect();
            references_vec.reverse();

            if !parent_rfc724_mid.is_empty()
                && !references_vec.contains(&parent_rfc724_mid.as_str())
            {
                references_vec.push(&parent_rfc724_mid)
            }

            if references_vec.is_empty() {
                // As a fallback, use our Message-ID,
                // same as in the case of top-level message.
                new_references = msg.rfc724_mid.clone();
            } else {
                new_references = references_vec.join(" ");
            }
        } else {
            // This is a top-level message.
            // Add our Message-ID as first references.
            // This allows us to identify replies to our message even if
            // email server such as Outlook changes `Message-ID:` header.
            // MUAs usually keep the first Message-ID in `References:` header unchanged.
            new_references = msg.rfc724_mid.clone();
        }

        // add independent location to database
        if msg.param.exists(Param::SetLatitude) {
            if let Ok(row_id) = context
                .sql
                .insert(
                    "INSERT INTO locations \
                     (timestamp,from_id,chat_id, latitude,longitude,independent)\
                     VALUES (?,?,?, ?,?,1);",
                    (
                        timestamp,
                        ContactId::SELF,
                        self.id,
                        msg.param.get_float(Param::SetLatitude).unwrap_or_default(),
                        msg.param.get_float(Param::SetLongitude).unwrap_or_default(),
                    ),
                )
                .await
            {
                location_id = row_id;
            }
        }

        let ephemeral_timer = if msg.param.get_cmd() == SystemMessage::EphemeralTimerChanged {
            EphemeralTimer::Disabled
        } else {
            self.id.get_ephemeral_timer(context).await?
        };
        let ephemeral_timestamp = match ephemeral_timer {
            EphemeralTimer::Disabled => 0,
            EphemeralTimer::Enabled { duration } => time().saturating_add(duration.into()),
        };

        let (msg_text, was_truncated) = truncate_msg_text(context, msg.text.clone()).await?;
        let new_mime_headers = if msg.has_html() {
            if msg.param.exists(Param::Forwarded) {
                msg.get_id().get_html(context).await?
            } else {
                msg.param.get(Param::SendHtml).map(|s| s.to_string())
            }
        } else {
            None
        };
        let new_mime_headers: Option<String> = new_mime_headers.map(|s| {
            let html_part = MimePart::new("text/html", s);
            let mut buffer = Vec::new();
            let cursor = Cursor::new(&mut buffer);
            html_part.write_part(cursor).ok();
            String::from_utf8_lossy(&buffer).to_string()
        });
        let new_mime_headers = new_mime_headers.or_else(|| match was_truncated {
            // We need to add some headers so that they are stripped before formatting HTML by
            // `MsgId::get_html()`, not a part of the actual text. Let's add "Content-Type", it's
            // anyway a useful metadata about the stored text.
            true => Some("Content-Type: text/plain; charset=utf-8\r\n\r\n".to_string() + &msg.text),
            false => None,
        });
        let new_mime_headers = match new_mime_headers {
            Some(h) => Some(tokio::task::block_in_place(move || {
                buf_compress(h.as_bytes())
            })?),
            None => None,
        };

        msg.chat_id = self.id;
        msg.from_id = ContactId::SELF;
        msg.timestamp_sort = timestamp;

        // add message to the database
        if let Some(update_msg_id) = update_msg_id {
            context
                .sql
                .execute(
                    "UPDATE msgs
                     SET rfc724_mid=?, chat_id=?, from_id=?, to_id=?, timestamp=?, type=?,
                         state=?, txt=?, txt_normalized=?, subject=?, param=?,
                         hidden=?, mime_in_reply_to=?, mime_references=?, mime_modified=?,
                         mime_headers=?, mime_compressed=1, location_id=?, ephemeral_timer=?,
                         ephemeral_timestamp=?
                     WHERE id=?;",
                    params_slice![
                        msg.rfc724_mid,
                        msg.chat_id,
                        msg.from_id,
                        to_id,
                        msg.timestamp_sort,
                        msg.viewtype,
                        msg.state,
                        msg_text,
                        message::normalize_text(&msg_text),
                        &msg.subject,
                        msg.param.to_string(),
                        msg.hidden,
                        msg.in_reply_to.as_deref().unwrap_or_default(),
                        new_references,
                        new_mime_headers.is_some(),
                        new_mime_headers.unwrap_or_default(),
                        location_id as i32,
                        ephemeral_timer,
                        ephemeral_timestamp,
                        update_msg_id
                    ],
                )
                .await?;
            msg.id = update_msg_id;
        } else {
            let raw_id = context
                .sql
                .insert(
                    "INSERT INTO msgs (
                        rfc724_mid,
                        chat_id,
                        from_id,
                        to_id,
                        timestamp,
                        type,
                        state,
                        txt,
                        txt_normalized,
                        subject,
                        param,
                        hidden,
                        mime_in_reply_to,
                        mime_references,
                        mime_modified,
                        mime_headers,
                        mime_compressed,
                        location_id,
                        ephemeral_timer,
                        ephemeral_timestamp)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?);",
                    params_slice![
                        msg.rfc724_mid,
                        msg.chat_id,
                        msg.from_id,
                        to_id,
                        msg.timestamp_sort,
                        msg.viewtype,
                        msg.state,
                        msg_text,
                        message::normalize_text(&msg_text),
                        &msg.subject,
                        msg.param.to_string(),
                        msg.hidden,
                        msg.in_reply_to.as_deref().unwrap_or_default(),
                        new_references,
                        new_mime_headers.is_some(),
                        new_mime_headers.unwrap_or_default(),
                        location_id as i32,
                        ephemeral_timer,
                        ephemeral_timestamp
                    ],
                )
                .await?;
            context.new_msgs_notify.notify_one();
            msg.id = MsgId::new(u32::try_from(raw_id)?);

            maybe_set_logging_xdc(context, msg, self.id).await?;
            context
                .update_webxdc_integration_database(msg, context)
                .await?;
        }
        context.scheduler.interrupt_ephemeral_task().await;
        Ok(msg.id)
    }

    /// Sends a `SyncAction` synchronising chat contacts to other devices.
    pub(crate) async fn sync_contacts(&self, context: &Context) -> Result<()> {
        let addrs = context
            .sql
            .query_map(
                "SELECT c.addr \
                FROM contacts c INNER JOIN chats_contacts cc \
                ON c.id=cc.contact_id \
                WHERE cc.chat_id=? AND cc.add_timestamp >= cc.remove_timestamp",
                (self.id,),
                |row| row.get::<_, String>(0),
                |addrs| addrs.collect::<Result<Vec<_>, _>>().map_err(Into::into),
            )
            .await?;
        self.sync(context, SyncAction::SetContacts(addrs)).await
    }

    /// Returns chat id for the purpose of synchronisation across devices.
    async fn get_sync_id(&self, context: &Context) -> Result<Option<SyncId>> {
        match self.typ {
            Chattype::Single => {
                if self.is_device_talk() {
                    return Ok(Some(SyncId::Device));
                }

                let mut r = None;
                for contact_id in get_chat_contacts(context, self.id).await? {
                    if contact_id == ContactId::SELF && !self.is_self_talk() {
                        continue;
                    }
                    if r.is_some() {
                        return Ok(None);
                    }
                    let contact = Contact::get_by_id(context, contact_id).await?;
                    r = Some(SyncId::ContactAddr(contact.get_addr().to_string()));
                }
                Ok(r)
            }
            Chattype::Broadcast | Chattype::Group | Chattype::Mailinglist => {
                if !self.grpid.is_empty() {
                    return Ok(Some(SyncId::Grpid(self.grpid.clone())));
                }

                let Some((parent_rfc724_mid, parent_in_reply_to, _)) = self
                    .id
                    .get_parent_mime_headers(context, MessageState::OutDelivered)
                    .await?
                else {
                    warn!(
                        context,
                        "Chat::get_sync_id({}): No good message identifying the chat found.",
                        self.id
                    );
                    return Ok(None);
                };
                Ok(Some(SyncId::Msgids(vec![
                    parent_in_reply_to,
                    parent_rfc724_mid,
                ])))
            }
        }
    }

    /// Synchronises a chat action to other devices.
    pub(crate) async fn sync(&self, context: &Context, action: SyncAction) -> Result<()> {
        if let Some(id) = self.get_sync_id(context).await? {
            sync(context, id, action).await?;
        }
        Ok(())
    }
}

pub(crate) async fn sync(context: &Context, id: SyncId, action: SyncAction) -> Result<()> {
    context
        .add_sync_item(SyncData::AlterChat { id, action })
        .await?;
    context.scheduler.interrupt_inbox().await;
    Ok(())
}

/// Whether the chat is pinned or archived.
#[derive(Debug, Copy, Eq, PartialEq, Clone, Serialize, Deserialize, EnumIter)]
#[repr(i8)]
pub enum ChatVisibility {
    /// Chat is neither archived nor pinned.
    Normal = 0,

    /// Chat is archived.
    Archived = 1,

    /// Chat is pinned to the top of the chatlist.
    Pinned = 2,
}

impl rusqlite::types::ToSql for ChatVisibility {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput> {
        let val = rusqlite::types::Value::Integer(*self as i64);
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

impl rusqlite::types::FromSql for ChatVisibility {
    fn column_result(value: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        i64::column_result(value).map(|val| {
            match val {
                2 => ChatVisibility::Pinned,
                1 => ChatVisibility::Archived,
                0 => ChatVisibility::Normal,
                // fallback to Normal for unknown values, may happen eg. on imports created by a newer version.
                _ => ChatVisibility::Normal,
            }
        })
    }
}

/// The current state of a chat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChatInfo {
    /// The chat ID.
    pub id: ChatId,

    /// The type of chat as a `u32` representation of [Chattype].
    ///
    /// On the C API this number is one of the
    /// `DC_CHAT_TYPE_UNDEFINED`, `DC_CHAT_TYPE_SINGLE`,
    /// or `DC_CHAT_TYPE_GROUP`
    /// constants.
    #[serde(rename = "type")]
    pub type_: u32,

    /// The name of the chat.
    pub name: String,

    /// Whether the chat is archived.
    pub archived: bool,

    /// The "params" of the chat.
    ///
    /// This is the string-serialised version of `Params` currently.
    pub param: String,

    /// Whether this chat is currently sending location-stream messages.
    pub is_sending_locations: bool,

    /// Colour this chat should be represented in by the UI.
    ///
    /// Yes, spelling colour is hard.
    pub color: u32,

    /// The path to the profile image.
    ///
    /// If there is no profile image set this will be an empty string
    /// currently.
    pub profile_image: std::path::PathBuf,

    /// The draft message text.
    ///
    /// If the chat has not draft this is an empty string.
    ///
    /// TODO: This doesn't seem rich enough, it can not handle drafts
    ///       which contain non-text parts.  Perhaps it should be a
    ///       simple `has_draft` bool instead.
    pub draft: String,

    /// Whether the chat is muted
    ///
    /// The exact time its muted can be found out via the `chat.mute_duration` property
    pub is_muted: bool,

    /// Ephemeral message timer.
    pub ephemeral_timer: EphemeralTimer,
    // ToDo:
    // - [ ] summary,
    // - [ ] lastUpdated,
    // - [ ] freshMessageCounter,
    // - [ ] email
}

pub(crate) async fn update_saved_messages_icon(context: &Context) -> Result<()> {
    if let Some(ChatIdBlocked { id: chat_id, .. }) =
        ChatIdBlocked::lookup_by_contact(context, ContactId::SELF).await?
    {
        let icon = include_bytes!("../assets/icon-saved-messages.png");
        let blob =
            BlobObject::create_and_deduplicate_from_bytes(context, icon, "saved-messages.png")?;
        let icon = blob.as_name().to_string();

        let mut chat = Chat::load_from_db(context, chat_id).await?;
        chat.param.set(Param::ProfileImage, icon);
        chat.update_param(context).await?;
    }
    Ok(())
}

pub(crate) async fn update_device_icon(context: &Context) -> Result<()> {
    if let Some(ChatIdBlocked { id: chat_id, .. }) =
        ChatIdBlocked::lookup_by_contact(context, ContactId::DEVICE).await?
    {
        let icon = include_bytes!("../assets/icon-device.png");
        let blob = BlobObject::create_and_deduplicate_from_bytes(context, icon, "device.png")?;
        let icon = blob.as_name().to_string();

        let mut chat = Chat::load_from_db(context, chat_id).await?;
        chat.param.set(Param::ProfileImage, &icon);
        chat.update_param(context).await?;

        let mut contact = Contact::get_by_id(context, ContactId::DEVICE).await?;
        contact.param.set(Param::ProfileImage, icon);
        contact.update_param(context).await?;
    }
    Ok(())
}

pub(crate) async fn get_broadcast_icon(context: &Context) -> Result<String> {
    if let Some(icon) = context.sql.get_raw_config("icon-broadcast").await? {
        return Ok(icon);
    }

    let icon = include_bytes!("../assets/icon-broadcast.png");
    let blob = BlobObject::create_and_deduplicate_from_bytes(context, icon, "broadcast.png")?;
    let icon = blob.as_name().to_string();
    context
        .sql
        .set_raw_config("icon-broadcast", Some(&icon))
        .await?;
    Ok(icon)
}

pub(crate) async fn get_archive_icon(context: &Context) -> Result<String> {
    if let Some(icon) = context.sql.get_raw_config("icon-archive").await? {
        return Ok(icon);
    }

    let icon = include_bytes!("../assets/icon-archive.png");
    let blob = BlobObject::create_and_deduplicate_from_bytes(context, icon, "archive.png")?;
    let icon = blob.as_name().to_string();
    context
        .sql
        .set_raw_config("icon-archive", Some(&icon))
        .await?;
    Ok(icon)
}

async fn update_special_chat_name(
    context: &Context,
    contact_id: ContactId,
    name: String,
) -> Result<()> {
    if let Some(ChatIdBlocked { id: chat_id, .. }) =
        ChatIdBlocked::lookup_by_contact(context, contact_id).await?
    {
        // the `!= name` condition avoids unneeded writes
        context
            .sql
            .execute(
                "UPDATE chats SET name=? WHERE id=? AND name!=?",
                (&name, chat_id, &name),
            )
            .await?;
    }
    Ok(())
}

pub(crate) async fn update_special_chat_names(context: &Context) -> Result<()> {
    update_special_chat_name(
        context,
        ContactId::DEVICE,
        stock_str::device_messages(context).await,
    )
    .await?;
    update_special_chat_name(
        context,
        ContactId::SELF,
        stock_str::saved_messages(context).await,
    )
    .await?;
    Ok(())
}

/// Checks if there is a 1:1 chat in-progress SecureJoin for Bob and, if necessary, schedules a task
/// unblocking the chat and notifying the user accordingly.
pub(crate) async fn resume_securejoin_wait(context: &Context) -> Result<()> {
    let chat_ids: Vec<ChatId> = context
        .sql
        .query_map(
            "SELECT chat_id FROM bobstate",
            (),
            |row| {
                let chat_id: ChatId = row.get(0)?;
                Ok(chat_id)
            },
            |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await?;

    for chat_id in chat_ids {
        let chat = Chat::load_from_db(context, chat_id).await?;
        let timeout = chat
            .check_securejoin_wait(context, constants::SECUREJOIN_WAIT_TIMEOUT)
            .await?;
        if timeout > 0 {
            chat_id.spawn_securejoin_wait(context, timeout);
        }
    }
    Ok(())
}

/// Handle a [`ChatId`] and its [`Blocked`] status at once.
///
/// This struct is an optimisation to read a [`ChatId`] and its [`Blocked`] status at once
/// from the database.  It [`Deref`]s to [`ChatId`] so it can be used as an extension to
/// [`ChatId`].
///
/// [`Deref`]: std::ops::Deref
#[derive(Debug)]
pub(crate) struct ChatIdBlocked {
    /// Chat ID.
    pub id: ChatId,

    /// Whether the chat is blocked, unblocked or a contact request.
    pub blocked: Blocked,
}

impl ChatIdBlocked {
    /// Searches the database for the 1:1 chat with this contact.
    ///
    /// If no chat is found `None` is returned.
    pub async fn lookup_by_contact(
        context: &Context,
        contact_id: ContactId,
    ) -> Result<Option<Self>> {
        ensure!(context.sql.is_open().await, "Database not available");
        ensure!(
            contact_id != ContactId::UNDEFINED,
            "Invalid contact id requested"
        );

        context
            .sql
            .query_row_optional(
                "SELECT c.id, c.blocked
                   FROM chats c
                  INNER JOIN chats_contacts j
                          ON c.id=j.chat_id
                  WHERE c.type=100  -- 100 = Chattype::Single
                    AND c.id>9      -- 9 = DC_CHAT_ID_LAST_SPECIAL
                    AND j.contact_id=?;",
                (contact_id,),
                |row| {
                    let id: ChatId = row.get(0)?;
                    let blocked: Blocked = row.get(1)?;
                    Ok(ChatIdBlocked { id, blocked })
                },
            )
            .await
    }

    /// Returns the chat for the 1:1 chat with this contact.
    ///
    /// If the chat does not yet exist a new one is created, using the provided [`Blocked`]
    /// state.
    pub async fn get_for_contact(
        context: &Context,
        contact_id: ContactId,
        create_blocked: Blocked,
    ) -> Result<Self> {
        ensure!(context.sql.is_open().await, "Database not available");
        ensure!(
            contact_id != ContactId::UNDEFINED,
            "Invalid contact id requested"
        );

        if let Some(res) = Self::lookup_by_contact(context, contact_id).await? {
            // Already exists, no need to create.
            return Ok(res);
        }

        let contact = Contact::get_by_id(context, contact_id).await?;
        let chat_name = contact.get_display_name().to_string();
        let mut params = Params::new();
        match contact_id {
            ContactId::SELF => {
                params.set_int(Param::Selftalk, 1);
            }
            ContactId::DEVICE => {
                params.set_int(Param::Devicetalk, 1);
            }
            _ => (),
        }

        let protected = contact_id == ContactId::SELF || {
            let peerstate = Peerstate::from_addr(context, contact.get_addr()).await?;
            peerstate.is_some_and(|p| {
                p.is_using_verified_key() && p.prefer_encrypt == EncryptPreference::Mutual
            })
        };
        let smeared_time = create_smeared_timestamp(context);

        let chat_id = context
            .sql
            .transaction(move |transaction| {
                transaction.execute(
                    "INSERT INTO chats
                     (type, name, param, blocked, created_timestamp, protected)
                     VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        Chattype::Single,
                        chat_name,
                        params.to_string(),
                        create_blocked as u8,
                        smeared_time,
                        if protected {
                            ProtectionStatus::Protected
                        } else {
                            ProtectionStatus::Unprotected
                        },
                    ),
                )?;
                let chat_id = ChatId::new(
                    transaction
                        .last_insert_rowid()
                        .try_into()
                        .context("chat table rowid overflows u32")?,
                );

                transaction.execute(
                    "INSERT INTO chats_contacts
                 (chat_id, contact_id)
                 VALUES((SELECT last_insert_rowid()), ?)",
                    (contact_id,),
                )?;

                Ok(chat_id)
            })
            .await?;

        if protected {
            chat_id
                .add_protection_msg(
                    context,
                    ProtectionStatus::Protected,
                    Some(contact_id),
                    smeared_time,
                )
                .await?;
        }

        match contact_id {
            ContactId::SELF => update_saved_messages_icon(context).await?,
            ContactId::DEVICE => update_device_icon(context).await?,
            _ => (),
        }

        Ok(Self {
            id: chat_id,
            blocked: create_blocked,
        })
    }
}

async fn prepare_msg_blob(context: &Context, msg: &mut Message) -> Result<()> {
    if msg.viewtype == Viewtype::Text || msg.viewtype == Viewtype::VideochatInvitation {
        // the caller should check if the message text is empty
    } else if msg.viewtype.has_file() {
        let mut blob = msg
            .param
            .get_file_blob(context)?
            .with_context(|| format!("attachment missing for message of type #{}", msg.viewtype))?;
        let send_as_is = msg.viewtype == Viewtype::File;

        if msg.viewtype == Viewtype::File
            || msg.viewtype == Viewtype::Image
            || msg.viewtype == Viewtype::Sticker && !msg.param.exists(Param::ForceSticker)
        {
            // Correct the type, take care not to correct already very special
            // formats as GIF or VOICE.
            //
            // Typical conversions:
            // - from FILE to AUDIO/VIDEO/IMAGE
            // - from FILE/IMAGE to GIF */
            if let Some((better_type, _)) = message::guess_msgtype_from_suffix(msg) {
                if msg.viewtype == Viewtype::Sticker {
                    if better_type != Viewtype::Image {
                        // UIs don't want conversions of `Sticker` to anything other than `Image`.
                        msg.param.set_int(Param::ForceSticker, 1);
                    }
                } else if better_type != Viewtype::Webxdc
                    || context
                        .ensure_sendable_webxdc_file(&blob.to_abs_path())
                        .await
                        .is_ok()
                {
                    msg.viewtype = better_type;
                }
            }
        } else if msg.viewtype == Viewtype::Webxdc {
            context
                .ensure_sendable_webxdc_file(&blob.to_abs_path())
                .await?;
        }

        if msg.viewtype == Viewtype::Vcard {
            msg.try_set_vcard(context, &blob.to_abs_path()).await?;
        }

        let mut maybe_sticker = msg.viewtype == Viewtype::Sticker;
        if !send_as_is
            && (msg.viewtype == Viewtype::Image
                || maybe_sticker && !msg.param.exists(Param::ForceSticker))
        {
            let new_name = blob
                .recode_to_image_size(context, msg.get_filename(), &mut maybe_sticker)
                .await?;
            msg.param.set(Param::Filename, new_name);
            msg.param.set(Param::File, blob.as_name());

            if !maybe_sticker {
                msg.viewtype = Viewtype::Image;
            }
        }

        if !msg.param.exists(Param::MimeType) {
            if let Some((_, mime)) = message::guess_msgtype_from_suffix(msg) {
                msg.param.set(Param::MimeType, mime);
            }
        }

        msg.try_calc_and_set_dimensions(context).await?;

        info!(
            context,
            "Attaching \"{}\" for message type #{}.",
            blob.to_abs_path().display(),
            msg.viewtype
        );
    } else {
        bail!("Cannot send messages of type #{}.", msg.viewtype);
    }
    Ok(())
}

/// Returns whether a contact is in a chat or not.
pub async fn is_contact_in_chat(
    context: &Context,
    chat_id: ChatId,
    contact_id: ContactId,
) -> Result<bool> {
    // this function works for group and for normal chats, however, it is more useful
    // for group chats.
    // ContactId::SELF may be used to check, if the user itself is in a group
    // chat (ContactId::SELF is not added to normal chats)

    let exists = context
        .sql
        .exists(
            "SELECT COUNT(*) FROM chats_contacts
             WHERE chat_id=? AND contact_id=?
             AND add_timestamp >= remove_timestamp",
            (chat_id, contact_id),
        )
        .await?;
    Ok(exists)
}

/// Sends a message object to a chat.
///
/// Sends the event #DC_EVENT_MSGS_CHANGED on success.
/// However, this does not imply, the message really reached the recipient -
/// sending may be delayed eg. due to network problems. However, from your
/// view, you're done with the message. Sooner or later it will find its way.
pub async fn send_msg(context: &Context, chat_id: ChatId, msg: &mut Message) -> Result<MsgId> {
    ensure!(
        !chat_id.is_special(),
        "chat_id cannot be a special chat: {chat_id}"
    );

    if msg.state != MessageState::Undefined && msg.state != MessageState::OutPreparing {
        msg.param.remove(Param::GuaranteeE2ee);
        msg.param.remove(Param::ForcePlaintext);
        msg.update_param(context).await?;
    }

    // protect all system messages against RTLO attacks
    if msg.is_system_message() {
        msg.text = sanitize_bidi_characters(&msg.text);
    }

    if !prepare_send_msg(context, chat_id, msg).await?.is_empty() {
        if !msg.hidden {
            context.emit_msgs_changed(msg.chat_id, msg.id);
        }

        if msg.param.exists(Param::SetLatitude) {
            context.emit_location_changed(Some(ContactId::SELF)).await?;
        }

        context.scheduler.interrupt_smtp().await;
    }

    Ok(msg.id)
}

/// Tries to send a message synchronously.
///
/// Creates jobs in the `smtp` table, then drectly opens an SMTP connection and sends the
/// message. If this fails, the jobs remain in the database for later sending.
pub async fn send_msg_sync(context: &Context, chat_id: ChatId, msg: &mut Message) -> Result<MsgId> {
    let rowids = prepare_send_msg(context, chat_id, msg).await?;
    if rowids.is_empty() {
        return Ok(msg.id);
    }
    let mut smtp = crate::smtp::Smtp::new();
    for rowid in rowids {
        send_msg_to_smtp(context, &mut smtp, rowid)
            .await
            .context("failed to send message, queued for later sending")?;
    }
    context.emit_msgs_changed(msg.chat_id, msg.id);
    Ok(msg.id)
}

/// Prepares a message to be sent out.
///
/// Returns row ids of the `smtp` table.
async fn prepare_send_msg(
    context: &Context,
    chat_id: ChatId,
    msg: &mut Message,
) -> Result<Vec<i64>> {
    let mut chat = Chat::load_from_db(context, chat_id).await?;

    let skip_fn = |reason: &CantSendReason| match reason {
        CantSendReason::ProtectionBroken
        | CantSendReason::ContactRequest
        | CantSendReason::SecurejoinWait => {
            // Allow securejoin messages, they are supposed to repair the verification.
            // If the chat is a contact request, let the user accept it later.
            msg.param.get_cmd() == SystemMessage::SecurejoinMessage
        }
        // Allow to send "Member removed" messages so we can leave the group.
        // Necessary checks should be made anyway before removing contact
        // from the chat.
        CantSendReason::NotAMember => msg.param.get_cmd() == SystemMessage::MemberRemovedFromGroup,
        _ => false,
    };
    if let Some(reason) = chat.why_cant_send_ex(context, &skip_fn).await? {
        bail!("Cannot send to {chat_id}: {reason}");
    }

    // Check a quote reply is not leaking data from other chats.
    // This is meant as a last line of defence, the UI should check that before as well.
    // (We allow Chattype::Single in general for "Reply Privately";
    // checking for exact contact_id will produce false positives when ppl just left the group)
    if chat.typ != Chattype::Single && !context.get_config_bool(Config::Bot).await? {
        if let Some(quoted_message) = msg.quoted_message(context).await? {
            if quoted_message.chat_id != chat_id {
                bail!("Bad quote reply");
            }
        }
    }

    // check current MessageState for drafts (to keep msg_id) ...
    let update_msg_id = if msg.state == MessageState::OutDraft {
        msg.hidden = false;
        if !msg.id.is_special() && msg.chat_id == chat_id {
            Some(msg.id)
        } else {
            None
        }
    } else {
        None
    };

    // ... then change the MessageState in the message object
    msg.state = MessageState::OutPending;

    prepare_msg_blob(context, msg).await?;
    if !msg.hidden {
        chat_id.unarchive_if_not_muted(context, msg.state).await?;
    }
    msg.id = chat
        .prepare_msg_raw(
            context,
            msg,
            update_msg_id,
            create_smeared_timestamp(context),
        )
        .await?;
    msg.chat_id = chat_id;

    let row_ids = create_send_msg_jobs(context, msg)
        .await
        .context("Failed to create send jobs")?;
    Ok(row_ids)
}

/// Constructs jobs for sending a message and inserts them into the appropriate table.
///
/// Returns row ids if `smtp` table jobs were created or an empty `Vec` otherwise.
///
/// The caller has to interrupt SMTP loop or otherwise process new rows.
pub(crate) async fn create_send_msg_jobs(context: &Context, msg: &mut Message) -> Result<Vec<i64>> {
    if msg.param.get_cmd() == SystemMessage::GroupNameChanged {
        msg.chat_id
            .update_timestamp(context, Param::GroupNameTimestamp, msg.timestamp_sort)
            .await?;
    }

    let needs_encryption = msg.param.get_bool(Param::GuaranteeE2ee).unwrap_or_default();
    let mimefactory = MimeFactory::from_msg(context, msg.clone()).await?;
    let attach_selfavatar = mimefactory.attach_selfavatar;
    let mut recipients = mimefactory.recipients();

    let from = context.get_primary_self_addr().await?;
    let lowercase_from = from.to_lowercase();

    // Send BCC to self if it is enabled.
    //
    // Previous versions of Delta Chat did not send BCC self
    // if DeleteServerAfter was set to immediately delete messages
    // from the server. This is not the case anymore
    // because BCC-self messages are also used to detect
    // that message was sent if SMTP server is slow to respond
    // and connection is frequently lost
    // before receiving status line. NB: This is not a problem for chatmail servers, so `BccSelf`
    // disabled by default is fine.
    //
    // `from` must be the last addr, see `receive_imf_inner()` why.
    recipients.retain(|x| x.to_lowercase() != lowercase_from);
    if (context.get_config_bool(Config::BccSelf).await?
        || msg.param.get_cmd() == SystemMessage::AutocryptSetupMessage)
        && (context.get_config_delete_server_after().await? != Some(0) || !recipients.is_empty())
    {
        recipients.push(from);
    }

    // Default Webxdc integrations are hidden messages and must not be sent out
    if msg.param.get_int(Param::WebxdcIntegration).is_some() && msg.hidden {
        recipients.clear();
    }

    if recipients.is_empty() {
        // may happen eg. for groups with only SELF and bcc_self disabled
        info!(
            context,
            "Message {} has no recipient, skipping smtp-send.", msg.id
        );
        msg.param.set_int(Param::GuaranteeE2ee, 1);
        msg.update_param(context).await?;
        msg.id.set_delivered(context).await?;
        msg.state = MessageState::OutDelivered;
        return Ok(Vec::new());
    }

    let rendered_msg = match mimefactory.render(context).await {
        Ok(res) => Ok(res),
        Err(err) => {
            message::set_msg_failed(context, msg, &err.to_string()).await?;
            Err(err)
        }
    }?;

    if needs_encryption && !rendered_msg.is_encrypted {
        /* unrecoverable */
        message::set_msg_failed(
            context,
            msg,
            "End-to-end-encryption unavailable unexpectedly.",
        )
        .await?;
        bail!(
            "e2e encryption unavailable {} - {:?}",
            msg.id,
            needs_encryption
        );
    }

    let now = smeared_time(context);

    if rendered_msg.last_added_location_id.is_some() {
        if let Err(err) = location::set_kml_sent_timestamp(context, msg.chat_id, now).await {
            error!(context, "Failed to set kml sent_timestamp: {err:#}.");
        }
    }

    if attach_selfavatar {
        if let Err(err) = msg.chat_id.set_selfavatar_timestamp(context, now).await {
            error!(context, "Failed to set selfavatar timestamp: {err:#}.");
        }
    }

    if rendered_msg.is_encrypted && !needs_encryption {
        msg.param.set_int(Param::GuaranteeE2ee, 1);
        msg.update_param(context).await?;
    }

    msg.subject.clone_from(&rendered_msg.subject);
    msg.update_subject(context).await?;
    let chunk_size = context.get_max_smtp_rcpt_to().await?;
    let trans_fn = |t: &mut rusqlite::Transaction| {
        let mut row_ids = Vec::<i64>::new();
        if let Some(sync_ids) = rendered_msg.sync_ids_to_delete {
            t.execute(
                &format!("DELETE FROM multi_device_sync WHERE id IN ({sync_ids})"),
                (),
            )?;
            t.execute(
                "INSERT INTO imap_send (mime, msg_id) VALUES (?, ?)",
                (&rendered_msg.message, msg.id),
            )?;
        } else {
            for recipients_chunk in recipients.chunks(chunk_size) {
                let recipients_chunk = recipients_chunk.join(" ");
                let row_id = t.execute(
                    "INSERT INTO smtp (rfc724_mid, recipients, mime, msg_id) \
                    VALUES            (?1,         ?2,         ?3,   ?4)",
                    (
                        &rendered_msg.rfc724_mid,
                        recipients_chunk,
                        &rendered_msg.message,
                        msg.id,
                    ),
                )?;
                row_ids.push(row_id.try_into()?);
            }
        }
        Ok(row_ids)
    };
    context.sql.transaction(trans_fn).await
}

/// Sends a text message to the given chat.
///
/// Returns database ID of the sent message.
pub async fn send_text_msg(
    context: &Context,
    chat_id: ChatId,
    text_to_send: String,
) -> Result<MsgId> {
    ensure!(
        !chat_id.is_special(),
        "bad chat_id, can not be a special chat: {}",
        chat_id
    );

    let mut msg = Message::new_text(text_to_send);
    send_msg(context, chat_id, &mut msg).await
}

/// Sends chat members a request to edit the given message's text.
pub async fn send_edit_request(context: &Context, msg_id: MsgId, new_text: String) -> Result<()> {
    let mut original_msg = Message::load_from_db(context, msg_id).await?;
    ensure!(
        original_msg.from_id == ContactId::SELF,
        "Can edit only own messages"
    );
    ensure!(!original_msg.is_info(), "Cannot edit info messages");
    ensure!(!original_msg.has_html(), "Cannot edit HTML messages");
    ensure!(
        original_msg.viewtype != Viewtype::VideochatInvitation,
        "Cannot edit videochat invitations"
    );
    ensure!(
        !original_msg.text.is_empty(), // avoid complexity in UI element changes. focus is typos and rewordings
        "Cannot add text"
    );
    ensure!(!new_text.trim().is_empty(), "Edited text cannot be empty");
    if original_msg.text == new_text {
        info!(context, "Text unchanged.");
        return Ok(());
    }

    save_text_edit_to_db(context, &mut original_msg, &new_text).await?;

    let mut edit_msg = Message::new_text(EDITED_PREFIX.to_owned() + &new_text); // prefix only set for nicer display in Non-Delta-MUAs
    edit_msg.set_quote(context, Some(&original_msg)).await?; // quote only set for nicer display in Non-Delta-MUAs
    if original_msg.get_showpadlock() {
        edit_msg.param.set_int(Param::GuaranteeE2ee, 1);
    }
    edit_msg
        .param
        .set(Param::TextEditFor, original_msg.rfc724_mid);
    edit_msg.hidden = true;
    send_msg(context, original_msg.chat_id, &mut edit_msg).await?;
    Ok(())
}

pub(crate) async fn save_text_edit_to_db(
    context: &Context,
    original_msg: &mut Message,
    new_text: &str,
) -> Result<()> {
    original_msg.param.set_int(Param::IsEdited, 1);
    context
        .sql
        .execute(
            "UPDATE msgs SET txt=?, txt_normalized=?, param=? WHERE id=?",
            (
                new_text,
                message::normalize_text(new_text),
                original_msg.param.to_string(),
                original_msg.id,
            ),
        )
        .await?;
    context.emit_msgs_changed(original_msg.chat_id, original_msg.id);
    Ok(())
}

/// Sends invitation to a videochat.
pub async fn send_videochat_invitation(context: &Context, chat_id: ChatId) -> Result<MsgId> {
    ensure!(
        !chat_id.is_special(),
        "video chat invitation cannot be sent to special chat: {}",
        chat_id
    );

    let instance = if let Some(instance) = context.get_config(Config::WebrtcInstance).await? {
        if !instance.is_empty() {
            instance
        } else {
            bail!("webrtc_instance is empty");
        }
    } else {
        bail!("webrtc_instance not set");
    };

    let instance = Message::create_webrtc_instance(&instance, &create_id());

    let mut msg = Message::new(Viewtype::VideochatInvitation);
    msg.param.set(Param::WebrtcRoom, &instance);
    msg.text =
        stock_str::videochat_invite_msg_body(context, &Message::parse_webrtc_instance(&instance).1)
            .await;
    send_msg(context, chat_id, &mut msg).await
}

/// Chat message list request options.
#[derive(Debug)]
pub struct MessageListOptions {
    /// Return only info messages.
    pub info_only: bool,

    /// Add day markers before each date regarding the local timezone.
    pub add_daymarker: bool,
}

/// Returns all messages belonging to the chat.
pub async fn get_chat_msgs(context: &Context, chat_id: ChatId) -> Result<Vec<ChatItem>> {
    get_chat_msgs_ex(
        context,
        chat_id,
        MessageListOptions {
            info_only: false,
            add_daymarker: false,
        },
    )
    .await
}

/// Returns messages belonging to the chat according to the given options.
pub async fn get_chat_msgs_ex(
    context: &Context,
    chat_id: ChatId,
    options: MessageListOptions,
) -> Result<Vec<ChatItem>> {
    let MessageListOptions {
        info_only,
        add_daymarker,
    } = options;
    let process_row = if info_only {
        |row: &rusqlite::Row| {
            // is_info logic taken from Message.is_info()
            let params = row.get::<_, String>("param")?;
            let (from_id, to_id) = (
                row.get::<_, ContactId>("from_id")?,
                row.get::<_, ContactId>("to_id")?,
            );
            let is_info_msg: bool = from_id == ContactId::INFO
                || to_id == ContactId::INFO
                || match Params::from_str(&params) {
                    Ok(p) => {
                        let cmd = p.get_cmd();
                        cmd != SystemMessage::Unknown && cmd != SystemMessage::AutocryptSetupMessage
                    }
                    _ => false,
                };

            Ok((
                row.get::<_, i64>("timestamp")?,
                row.get::<_, MsgId>("id")?,
                !is_info_msg,
            ))
        }
    } else {
        |row: &rusqlite::Row| {
            Ok((
                row.get::<_, i64>("timestamp")?,
                row.get::<_, MsgId>("id")?,
                false,
            ))
        }
    };
    let process_rows = |rows: rusqlite::MappedRows<_>| {
        // It is faster to sort here rather than
        // let sqlite execute an ORDER BY clause.
        let mut sorted_rows = Vec::new();
        for row in rows {
            let (ts, curr_id, exclude_message): (i64, MsgId, bool) = row?;
            if !exclude_message {
                sorted_rows.push((ts, curr_id));
            }
        }
        sorted_rows.sort_unstable();

        let mut ret = Vec::new();
        let mut last_day = 0;
        let cnv_to_local = gm2local_offset();

        for (ts, curr_id) in sorted_rows {
            if add_daymarker {
                let curr_local_timestamp = ts + cnv_to_local;
                let curr_day = curr_local_timestamp / 86400;
                if curr_day != last_day {
                    ret.push(ChatItem::DayMarker {
                        timestamp: curr_day * 86400, // Convert day back to Unix timestamp
                    });
                    last_day = curr_day;
                }
            }
            ret.push(ChatItem::Message { msg_id: curr_id });
        }
        Ok(ret)
    };

    let items = if info_only {
        context
            .sql
            .query_map(
        // GLOB is used here instead of LIKE because it is case-sensitive
                "SELECT m.id AS id, m.timestamp AS timestamp, m.param AS param, m.from_id AS from_id, m.to_id AS to_id
               FROM msgs m
              WHERE m.chat_id=?
                AND m.hidden=0
                AND (
                    m.param GLOB \"*S=*\"
                    OR m.from_id == ?
                    OR m.to_id == ?
                );",
                (chat_id, ContactId::INFO, ContactId::INFO),
                process_row,
                process_rows,
            )
            .await?
    } else {
        context
            .sql
            .query_map(
                "SELECT m.id AS id, m.timestamp AS timestamp
               FROM msgs m
              WHERE m.chat_id=?
                AND m.hidden=0;",
                (chat_id,),
                process_row,
                process_rows,
            )
            .await?
    };
    Ok(items)
}

/// Marks all messages in the chat as noticed.
/// If the given chat-id is the archive-link, marks all messages in all archived chats as noticed.
pub async fn marknoticed_chat(context: &Context, chat_id: ChatId) -> Result<()> {
    // "WHERE" below uses the index `(state, hidden, chat_id)`, see get_fresh_msg_cnt() for reasoning
    // the additional SELECT statement may speed up things as no write-blocking is needed.
    if chat_id.is_archived_link() {
        let chat_ids_in_archive = context
            .sql
            .query_map(
                "SELECT DISTINCT(m.chat_id) FROM msgs m
                    LEFT JOIN chats c ON m.chat_id=c.id
                    WHERE m.state=10 AND m.hidden=0 AND m.chat_id>9 AND c.archived=1",
                (),
                |row| row.get::<_, ChatId>(0),
                |ids| ids.collect::<Result<Vec<_>, _>>().map_err(Into::into),
            )
            .await?;
        if chat_ids_in_archive.is_empty() {
            return Ok(());
        }

        context
            .sql
            .transaction(|transaction| {
                let mut stmt = transaction.prepare(
                    "UPDATE msgs SET state=13 WHERE state=10 AND hidden=0 AND chat_id = ?",
                )?;
                for chat_id_in_archive in &chat_ids_in_archive {
                    stmt.execute((chat_id_in_archive,))?;
                }
                Ok(())
            })
            .await?;

        for chat_id_in_archive in chat_ids_in_archive {
            start_chat_ephemeral_timers(context, chat_id_in_archive).await?;
            context.emit_event(EventType::MsgsNoticed(chat_id_in_archive));
            chatlist_events::emit_chatlist_item_changed(context, chat_id_in_archive);
        }
    } else {
        start_chat_ephemeral_timers(context, chat_id).await?;

        let noticed_msgs_count = context
            .sql
            .execute(
                "UPDATE msgs
            SET state=?
          WHERE state=?
            AND hidden=0
            AND chat_id=?;",
                (MessageState::InNoticed, MessageState::InFresh, chat_id),
            )
            .await?;

        // This is to trigger emitting `MsgsNoticed` on other devices when reactions are noticed
        // locally (i.e. when the chat was opened locally).
        let hidden_messages = context
            .sql
            .query_map(
                "SELECT id, rfc724_mid FROM msgs
                    WHERE state=?
                      AND hidden=1
                      AND chat_id=?
                    ORDER BY id LIMIT 100", // LIMIT to 100 in order to avoid blocking the UI too long, usually there will be less than 100 messages anyway
                (MessageState::InFresh, chat_id), // No need to check for InNoticed messages, because reactions are never InNoticed
                |row| {
                    let msg_id: MsgId = row.get(0)?;
                    let rfc724_mid: String = row.get(1)?;
                    Ok((msg_id, rfc724_mid))
                },
                |rows| {
                    rows.collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(Into::into)
                },
            )
            .await?;
        for (msg_id, rfc724_mid) in &hidden_messages {
            message::update_msg_state(context, *msg_id, MessageState::InSeen).await?;
            imap::markseen_on_imap_table(context, rfc724_mid).await?;
        }

        if noticed_msgs_count == 0 {
            return Ok(());
        }
    }

    context.emit_event(EventType::MsgsNoticed(chat_id));
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    context.on_archived_chats_maybe_noticed();
    Ok(())
}

/// Marks messages preceding outgoing messages as noticed.
///
/// In a chat, if there is an outgoing message, it can be assumed that all previous
/// messages were noticed. So, this function takes a Vec of messages that were
/// just received, and for all the outgoing messages, it marks all
/// previous messages as noticed.
pub(crate) async fn mark_old_messages_as_noticed(
    context: &Context,
    mut msgs: Vec<ReceivedMsg>,
) -> Result<()> {
    msgs.retain(|m| m.state.is_outgoing());
    if msgs.is_empty() {
        return Ok(());
    }

    let mut msgs_by_chat: HashMap<ChatId, ReceivedMsg> = HashMap::new();
    for msg in msgs {
        let chat_id = msg.chat_id;
        if let Some(existing_msg) = msgs_by_chat.get(&chat_id) {
            if msg.sort_timestamp > existing_msg.sort_timestamp {
                msgs_by_chat.insert(chat_id, msg);
            }
        } else {
            msgs_by_chat.insert(chat_id, msg);
        }
    }

    let changed_chats = context
        .sql
        .transaction(|transaction| {
            let mut changed_chats = Vec::new();
            for (_, msg) in msgs_by_chat {
                let changed_rows = transaction.execute(
                    "UPDATE msgs
            SET state=?
          WHERE state=?
            AND hidden=0
            AND chat_id=?
            AND timestamp<=?;",
                    (
                        MessageState::InNoticed,
                        MessageState::InFresh,
                        msg.chat_id,
                        msg.sort_timestamp,
                    ),
                )?;
                if changed_rows > 0 {
                    changed_chats.push(msg.chat_id);
                }
            }
            Ok(changed_chats)
        })
        .await?;

    if !changed_chats.is_empty() {
        info!(
            context,
            "Marking chats as noticed because there are newer outgoing messages: {changed_chats:?}."
        );
        context.on_archived_chats_maybe_noticed();
    }

    for c in changed_chats {
        start_chat_ephemeral_timers(context, c).await?;
        context.emit_event(EventType::MsgsNoticed(c));
        chatlist_events::emit_chatlist_item_changed(context, c);
    }

    Ok(())
}

/// Returns all database message IDs of the given types.
///
/// If `chat_id` is None, return messages from any chat.
///
/// `Viewtype::Unknown` can be used for `msg_type2` and `msg_type3`
/// if less than 3 viewtypes are requested.
pub async fn get_chat_media(
    context: &Context,
    chat_id: Option<ChatId>,
    msg_type: Viewtype,
    msg_type2: Viewtype,
    msg_type3: Viewtype,
) -> Result<Vec<MsgId>> {
    let list = if msg_type == Viewtype::Webxdc
        && msg_type2 == Viewtype::Unknown
        && msg_type3 == Viewtype::Unknown
    {
        context
            .sql
            .query_map(
                "SELECT id
               FROM msgs
              WHERE (1=? OR chat_id=?)
                AND chat_id != ?
                AND type = ?
                AND hidden=0
              ORDER BY max(timestamp, timestamp_rcvd), id;",
                (
                    chat_id.is_none(),
                    chat_id.unwrap_or_else(|| ChatId::new(0)),
                    DC_CHAT_ID_TRASH,
                    Viewtype::Webxdc,
                ),
                |row| row.get::<_, MsgId>(0),
                |ids| Ok(ids.flatten().collect()),
            )
            .await?
    } else {
        context
            .sql
            .query_map(
                "SELECT id
               FROM msgs
              WHERE (1=? OR chat_id=?)
                AND chat_id != ?
                AND type IN (?, ?, ?)
                AND hidden=0
              ORDER BY timestamp, id;",
                (
                    chat_id.is_none(),
                    chat_id.unwrap_or_else(|| ChatId::new(0)),
                    DC_CHAT_ID_TRASH,
                    msg_type,
                    if msg_type2 != Viewtype::Unknown {
                        msg_type2
                    } else {
                        msg_type
                    },
                    if msg_type3 != Viewtype::Unknown {
                        msg_type3
                    } else {
                        msg_type
                    },
                ),
                |row| row.get::<_, MsgId>(0),
                |ids| Ok(ids.flatten().collect()),
            )
            .await?
    };
    Ok(list)
}

/// Returns a vector of contact IDs for given chat ID.
pub async fn get_chat_contacts(context: &Context, chat_id: ChatId) -> Result<Vec<ContactId>> {
    // Normal chats do not include SELF.  Group chats do (as it may happen that one is deleted from a
    // groupchat but the chats stays visible, moreover, this makes displaying lists easier)

    let list = context
        .sql
        .query_map(
            "SELECT cc.contact_id
               FROM chats_contacts cc
               LEFT JOIN contacts c
                      ON c.id=cc.contact_id
              WHERE cc.chat_id=? AND cc.add_timestamp >= cc.remove_timestamp
              ORDER BY c.id=1, c.last_seen DESC, c.id DESC;",
            (chat_id,),
            |row| row.get::<_, ContactId>(0),
            |ids| ids.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await?;

    Ok(list)
}

/// Returns a vector of contact IDs for given chat ID that are no longer part of the group.
///
/// Members that have been removed recently are in the beginning of the list.
pub async fn get_past_chat_contacts(context: &Context, chat_id: ChatId) -> Result<Vec<ContactId>> {
    let now = time();
    let list = context
        .sql
        .query_map(
            "SELECT cc.contact_id
             FROM chats_contacts cc
             LEFT JOIN contacts c
                  ON c.id=cc.contact_id
             WHERE cc.chat_id=?
             AND cc.add_timestamp < cc.remove_timestamp
             AND ? < cc.remove_timestamp
             ORDER BY c.id=1, cc.remove_timestamp DESC, c.id DESC",
            (chat_id, now.saturating_sub(60 * 24 * 3600)),
            |row| row.get::<_, ContactId>(0),
            |ids| ids.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .await?;

    Ok(list)
}

/// Creates a group chat with a given `name`.
pub async fn create_group_chat(
    context: &Context,
    protect: ProtectionStatus,
    chat_name: &str,
) -> Result<ChatId> {
    let chat_name = sanitize_single_line(chat_name);
    ensure!(!chat_name.is_empty(), "Invalid chat name");

    let grpid = create_id();

    let timestamp = create_smeared_timestamp(context);
    let row_id = context
        .sql
        .insert(
            "INSERT INTO chats
        (type, name, grpid, param, created_timestamp)
        VALUES(?, ?, ?, \'U=1\', ?);",
            (Chattype::Group, chat_name, grpid, timestamp),
        )
        .await?;

    let chat_id = ChatId::new(u32::try_from(row_id)?);
    add_to_chat_contacts_table(context, timestamp, chat_id, &[ContactId::SELF]).await?;

    context.emit_msgs_changed_without_ids();
    chatlist_events::emit_chatlist_changed(context);
    chatlist_events::emit_chatlist_item_changed(context, chat_id);

    if protect == ProtectionStatus::Protected {
        chat_id
            .set_protection_for_timestamp_sort(context, protect, timestamp, None)
            .await?;
    }

    if !context.get_config_bool(Config::Bot).await?
        && !context.get_config_bool(Config::SkipStartMessages).await?
    {
        let text = stock_str::new_group_send_first_message(context).await;
        add_info_msg(context, chat_id, &text, create_smeared_timestamp(context)).await?;
    }

    Ok(chat_id)
}

/// Finds an unused name for a new broadcast list.
async fn find_unused_broadcast_list_name(context: &Context) -> Result<String> {
    let base_name = stock_str::broadcast_list(context).await;
    for attempt in 1..1000 {
        let better_name = if attempt > 1 {
            format!("{base_name} {attempt}")
        } else {
            base_name.clone()
        };
        if !context
            .sql
            .exists(
                "SELECT COUNT(*) FROM chats WHERE type=? AND name=?;",
                (Chattype::Broadcast, &better_name),
            )
            .await?
        {
            return Ok(better_name);
        }
    }
    Ok(base_name)
}

/// Creates a new broadcast list.
pub async fn create_broadcast_list(context: &Context) -> Result<ChatId> {
    let chat_name = find_unused_broadcast_list_name(context).await?;
    let grpid = create_id();
    create_broadcast_list_ex(context, Sync, grpid, chat_name).await
}

pub(crate) async fn create_broadcast_list_ex(
    context: &Context,
    sync: sync::Sync,
    grpid: String,
    chat_name: String,
) -> Result<ChatId> {
    let row_id = {
        let chat_name = &chat_name;
        let grpid = &grpid;
        let trans_fn = |t: &mut rusqlite::Transaction| {
            let cnt = t.execute("UPDATE chats SET name=? WHERE grpid=?", (chat_name, grpid))?;
            ensure!(cnt <= 1, "{cnt} chats exist with grpid {grpid}");
            if cnt == 1 {
                return Ok(t.query_row(
                    "SELECT id FROM chats WHERE grpid=? AND type=?",
                    (grpid, Chattype::Broadcast),
                    |row| {
                        let id: isize = row.get(0)?;
                        Ok(id)
                    },
                )?);
            }
            t.execute(
                "INSERT INTO chats \
                (type, name, grpid, param, created_timestamp) \
                VALUES(?, ?, ?, \'U=1\', ?);",
                (
                    Chattype::Broadcast,
                    &chat_name,
                    &grpid,
                    create_smeared_timestamp(context),
                ),
            )?;
            Ok(t.last_insert_rowid().try_into()?)
        };
        context.sql.transaction(trans_fn).await?
    };
    let chat_id = ChatId::new(u32::try_from(row_id)?);

    context.emit_msgs_changed_without_ids();
    chatlist_events::emit_chatlist_changed(context);

    if sync.into() {
        let id = SyncId::Grpid(grpid);
        let action = SyncAction::CreateBroadcast(chat_name);
        self::sync(context, id, action).await.log_err(context).ok();
    }

    Ok(chat_id)
}

/// Set chat contacts in the `chats_contacts` table.
pub(crate) async fn update_chat_contacts_table(
    context: &Context,
    timestamp: i64,
    id: ChatId,
    contacts: &HashSet<ContactId>,
) -> Result<()> {
    context
        .sql
        .transaction(move |transaction| {
            // Bump `remove_timestamp` to at least `now`
            // even for members from `contacts`.
            // We add members from `contacts` back below.
            transaction.execute(
                "UPDATE chats_contacts
                 SET remove_timestamp=MAX(add_timestamp+1, ?)
                 WHERE chat_id=?",
                (timestamp, id),
            )?;

            if !contacts.is_empty() {
                let mut statement = transaction.prepare(
                    "INSERT INTO chats_contacts (chat_id, contact_id, add_timestamp)
                     VALUES                     (?1,      ?2,         ?3)
                     ON CONFLICT (chat_id, contact_id)
                     DO UPDATE SET add_timestamp=remove_timestamp",
                )?;

                for contact_id in contacts {
                    // We bumped `add_timestamp` for existing rows above,
                    // so on conflict it is enough to set `add_timestamp = remove_timestamp`
                    // and this guarantees that `add_timestamp` is no less than `timestamp`.
                    statement.execute((id, contact_id, timestamp))?;
                }
            }
            Ok(())
        })
        .await?;
    Ok(())
}

/// Adds contacts to the `chats_contacts` table.
pub(crate) async fn add_to_chat_contacts_table(
    context: &Context,
    timestamp: i64,
    chat_id: ChatId,
    contact_ids: &[ContactId],
) -> Result<()> {
    context
        .sql
        .transaction(move |transaction| {
            let mut add_statement = transaction.prepare(
                "INSERT INTO chats_contacts (chat_id, contact_id, add_timestamp) VALUES(?1, ?2, ?3)
                 ON CONFLICT (chat_id, contact_id)
                 DO UPDATE SET add_timestamp=MAX(remove_timestamp, ?3)",
            )?;

            for contact_id in contact_ids {
                add_statement.execute((chat_id, contact_id, timestamp))?;
            }
            Ok(())
        })
        .await?;

    Ok(())
}

/// Removes a contact from the chat
/// by updating the `remove_timestamp`.
pub(crate) async fn remove_from_chat_contacts_table(
    context: &Context,
    chat_id: ChatId,
    contact_id: ContactId,
) -> Result<()> {
    let now = time();
    context
        .sql
        .execute(
            "UPDATE chats_contacts
             SET remove_timestamp=MAX(add_timestamp+1, ?)
             WHERE chat_id=? AND contact_id=?",
            (now, chat_id, contact_id),
        )
        .await?;
    Ok(())
}

/// Adds a contact to the chat.
/// If the group is promoted, also sends out a system message to all group members
pub async fn add_contact_to_chat(
    context: &Context,
    chat_id: ChatId,
    contact_id: ContactId,
) -> Result<()> {
    add_contact_to_chat_ex(context, Sync, chat_id, contact_id, false).await?;
    Ok(())
}

pub(crate) async fn add_contact_to_chat_ex(
    context: &Context,
    mut sync: sync::Sync,
    chat_id: ChatId,
    contact_id: ContactId,
    from_handshake: bool,
) -> Result<bool> {
    ensure!(!chat_id.is_special(), "can not add member to special chats");
    let contact = Contact::get_by_id(context, contact_id).await?;
    let mut msg = Message::new(Viewtype::default());

    chat_id.reset_gossiped_timestamp(context).await?;

    // this also makes sure, no contacts are added to special or normal chats
    let mut chat = Chat::load_from_db(context, chat_id).await?;
    ensure!(
        chat.typ == Chattype::Group || chat.typ == Chattype::Broadcast,
        "{} is not a group/broadcast where one can add members",
        chat_id
    );
    ensure!(
        Contact::real_exists_by_id(context, contact_id).await? || contact_id == ContactId::SELF,
        "invalid contact_id {} for adding to group",
        contact_id
    );
    ensure!(!chat.is_mailing_list(), "Mailing lists can't be changed");
    ensure!(
        chat.typ != Chattype::Broadcast || contact_id != ContactId::SELF,
        "Cannot add SELF to broadcast."
    );

    if !chat.is_self_in_chat(context).await? {
        context.emit_event(EventType::ErrorSelfNotInGroup(
            "Cannot add contact to group; self not in group.".into(),
        ));
        bail!("can not add contact because the account is not part of the group/broadcast");
    }

    let sync_qr_code_tokens;
    if from_handshake && chat.param.get_int(Param::Unpromoted).unwrap_or_default() == 1 {
        chat.param
            .remove(Param::Unpromoted)
            .set_i64(Param::GroupNameTimestamp, smeared_time(context));
        chat.update_param(context).await?;
        sync_qr_code_tokens = true;
    } else {
        sync_qr_code_tokens = false;
    }

    if context.is_self_addr(contact.get_addr()).await? {
        // ourself is added using ContactId::SELF, do not add this address explicitly.
        // if SELF is not in the group, members cannot be added at all.
        warn!(
            context,
            "Invalid attempt to add self e-mail address to group."
        );
        return Ok(false);
    }

    if is_contact_in_chat(context, chat_id, contact_id).await? {
        if !from_handshake {
            return Ok(true);
        }
    } else {
        // else continue and send status mail
        if chat.is_protected() && !contact.is_verified(context).await? {
            error!(
                context,
                "Cannot add non-bidirectionally verified contact {contact_id} to protected chat {chat_id}."
            );
            return Ok(false);
        }
        if is_contact_in_chat(context, chat_id, contact_id).await? {
            return Ok(false);
        }
        add_to_chat_contacts_table(context, time(), chat_id, &[contact_id]).await?;
    }
    if chat.typ == Chattype::Group && chat.is_promoted() {
        msg.viewtype = Viewtype::Text;

        let contact_addr = contact.get_addr().to_lowercase();
        msg.text = stock_str::msg_add_member_local(context, &contact_addr, ContactId::SELF).await;
        msg.param.set_cmd(SystemMessage::MemberAddedToGroup);
        msg.param.set(Param::Arg, contact_addr);
        msg.param.set_int(Param::Arg2, from_handshake.into());
        msg.param
            .set_int(Param::ContactAddedRemoved, contact.id.to_u32() as i32);
        send_msg(context, chat_id, &mut msg).await?;

        sync = Nosync;
        // TODO: Remove this compat code needed because Core <= v1.143:
        // - doesn't accept synchronization of QR code tokens for unpromoted groups, so we also send
        //   them when the group is promoted.
        // - doesn't sync QR code tokens for unpromoted groups and the group might be created before
        //   an upgrade.
        if sync_qr_code_tokens
            && context
                .sync_qr_code_tokens(Some(chat.grpid.as_str()))
                .await
                .log_err(context)
                .is_ok()
        {
            context.scheduler.interrupt_inbox().await;
        }
    }
    context.emit_event(EventType::ChatModified(chat_id));
    if sync.into() {
        chat.sync_contacts(context).await.log_err(context).ok();
    }
    Ok(true)
}

/// Returns true if an avatar should be attached in the given chat.
///
/// This function does not check if the avatar is set.
/// If avatar is not set and this function returns `true`,
/// a `Chat-User-Avatar: 0` header should be sent to reset the avatar.
pub(crate) async fn shall_attach_selfavatar(context: &Context, chat_id: ChatId) -> Result<bool> {
    let timestamp_some_days_ago = time() - DC_RESEND_USER_AVATAR_DAYS * 24 * 60 * 60;
    let needs_attach = context
        .sql
        .query_map(
            "SELECT c.selfavatar_sent
             FROM chats_contacts cc
             LEFT JOIN contacts c ON c.id=cc.contact_id
             WHERE cc.chat_id=? AND cc.contact_id!=? AND cc.add_timestamp >= cc.remove_timestamp",
            (chat_id, ContactId::SELF),
            |row| Ok(row.get::<_, i64>(0)),
            |rows| {
                let mut needs_attach = false;
                for row in rows {
                    let row = row?;
                    let selfavatar_sent = row?;
                    if selfavatar_sent < timestamp_some_days_ago {
                        needs_attach = true;
                    }
                }
                Ok(needs_attach)
            },
        )
        .await?;
    Ok(needs_attach)
}

/// Chat mute duration.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MuteDuration {
    /// Chat is not muted.
    NotMuted,

    /// Chat is muted until the user unmutes the chat.
    Forever,

    /// Chat is muted for a limited period of time.
    Until(std::time::SystemTime),
}

impl rusqlite::types::ToSql for MuteDuration {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput> {
        let duration: i64 = match &self {
            MuteDuration::NotMuted => 0,
            MuteDuration::Forever => -1,
            MuteDuration::Until(when) => {
                let duration = when
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?;
                i64::try_from(duration.as_secs())
                    .map_err(|err| rusqlite::Error::ToSqlConversionFailure(Box::new(err)))?
            }
        };
        let val = rusqlite::types::Value::Integer(duration);
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

impl rusqlite::types::FromSql for MuteDuration {
    fn column_result(value: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        // Negative values other than -1 should not be in the
        // database.  If found they'll be NotMuted.
        match i64::column_result(value)? {
            0 => Ok(MuteDuration::NotMuted),
            -1 => Ok(MuteDuration::Forever),
            n if n > 0 => match SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(n as u64)) {
                Some(t) => Ok(MuteDuration::Until(t)),
                None => Err(rusqlite::types::FromSqlError::OutOfRange(n)),
            },
            _ => Ok(MuteDuration::NotMuted),
        }
    }
}

/// Mutes the chat for a given duration or unmutes it.
pub async fn set_muted(context: &Context, chat_id: ChatId, duration: MuteDuration) -> Result<()> {
    set_muted_ex(context, Sync, chat_id, duration).await
}

pub(crate) async fn set_muted_ex(
    context: &Context,
    sync: sync::Sync,
    chat_id: ChatId,
    duration: MuteDuration,
) -> Result<()> {
    ensure!(!chat_id.is_special(), "Invalid chat ID");
    context
        .sql
        .execute(
            "UPDATE chats SET muted_until=? WHERE id=?;",
            (duration, chat_id),
        )
        .await
        .context(format!("Failed to set mute duration for {chat_id}"))?;
    context.emit_event(EventType::ChatModified(chat_id));
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    if sync.into() {
        let chat = Chat::load_from_db(context, chat_id).await?;
        chat.sync(context, SyncAction::SetMuted(duration))
            .await
            .log_err(context)
            .ok();
    }
    Ok(())
}

/// Removes contact from the chat.
pub async fn remove_contact_from_chat(
    context: &Context,
    chat_id: ChatId,
    contact_id: ContactId,
) -> Result<()> {
    ensure!(
        !chat_id.is_special(),
        "bad chat_id, can not be special chat: {}",
        chat_id
    );
    ensure!(
        !contact_id.is_special() || contact_id == ContactId::SELF,
        "Cannot remove special contact"
    );

    let mut msg = Message::new(Viewtype::default());

    let chat = Chat::load_from_db(context, chat_id).await?;
    if chat.typ == Chattype::Group || chat.typ == Chattype::Broadcast {
        if !chat.is_self_in_chat(context).await? {
            let err_msg = format!(
                "Cannot remove contact {contact_id} from chat {chat_id}: self not in group."
            );
            context.emit_event(EventType::ErrorSelfNotInGroup(err_msg.clone()));
            bail!("{}", err_msg);
        } else {
            let mut sync = Nosync;

            if chat.is_promoted() {
                remove_from_chat_contacts_table(context, chat_id, contact_id).await?;
            } else {
                context
                    .sql
                    .execute(
                        "DELETE FROM chats_contacts
                         WHERE chat_id=? AND contact_id=?",
                        (chat_id, contact_id),
                    )
                    .await?;
            }

            // We do not return an error if the contact does not exist in the database.
            // This allows to delete dangling references to deleted contacts
            // in case of the database becoming inconsistent due to a bug.
            if let Some(contact) = Contact::get_by_id_optional(context, contact_id).await? {
                if chat.typ == Chattype::Group && chat.is_promoted() {
                    msg.viewtype = Viewtype::Text;
                    if contact_id == ContactId::SELF {
                        msg.text = stock_str::msg_group_left_local(context, ContactId::SELF).await;
                    } else {
                        msg.text = stock_str::msg_del_member_local(
                            context,
                            contact.get_addr(),
                            ContactId::SELF,
                        )
                        .await;
                    }
                    msg.param.set_cmd(SystemMessage::MemberRemovedFromGroup);
                    msg.param.set(Param::Arg, contact.get_addr().to_lowercase());
                    msg.param
                        .set(Param::ContactAddedRemoved, contact.id.to_u32() as i32);
                    let res = send_msg(context, chat_id, &mut msg).await;
                    if contact_id == ContactId::SELF {
                        res?;
                        set_group_explicitly_left(context, &chat.grpid).await?;
                    } else if let Err(e) = res {
                        warn!(context, "remove_contact_from_chat({chat_id}, {contact_id}): send_msg() failed: {e:#}.");
                    }
                } else {
                    sync = Sync;
                }
            }
            context.emit_event(EventType::ChatModified(chat_id));
            if sync.into() {
                chat.sync_contacts(context).await.log_err(context).ok();
            }
        }
    } else {
        bail!("Cannot remove members from non-group chats.");
    }

    Ok(())
}

async fn set_group_explicitly_left(context: &Context, grpid: &str) -> Result<()> {
    if !is_group_explicitly_left(context, grpid).await? {
        context
            .sql
            .execute("INSERT INTO leftgrps (grpid) VALUES(?);", (grpid,))
            .await?;
    }

    Ok(())
}

pub(crate) async fn is_group_explicitly_left(context: &Context, grpid: &str) -> Result<bool> {
    let exists = context
        .sql
        .exists("SELECT COUNT(*) FROM leftgrps WHERE grpid=?;", (grpid,))
        .await?;
    Ok(exists)
}

/// Sets group or mailing list chat name.
pub async fn set_chat_name(context: &Context, chat_id: ChatId, new_name: &str) -> Result<()> {
    rename_ex(context, Sync, chat_id, new_name).await
}

async fn rename_ex(
    context: &Context,
    mut sync: sync::Sync,
    chat_id: ChatId,
    new_name: &str,
) -> Result<()> {
    let new_name = sanitize_single_line(new_name);
    /* the function only sets the names of group chats; normal chats get their names from the contacts */
    let mut success = false;

    ensure!(!new_name.is_empty(), "Invalid name");
    ensure!(!chat_id.is_special(), "Invalid chat ID");

    let chat = Chat::load_from_db(context, chat_id).await?;
    let mut msg = Message::new(Viewtype::default());

    if chat.typ == Chattype::Group
        || chat.typ == Chattype::Mailinglist
        || chat.typ == Chattype::Broadcast
    {
        if chat.name == new_name {
            success = true;
        } else if !chat.is_self_in_chat(context).await? {
            context.emit_event(EventType::ErrorSelfNotInGroup(
                "Cannot set chat name; self not in group".into(),
            ));
        } else {
            context
                .sql
                .execute(
                    "UPDATE chats SET name=? WHERE id=?;",
                    (new_name.to_string(), chat_id),
                )
                .await?;
            if chat.is_promoted()
                && !chat.is_mailing_list()
                && chat.typ != Chattype::Broadcast
                && sanitize_single_line(&chat.name) != new_name
            {
                msg.viewtype = Viewtype::Text;
                msg.text =
                    stock_str::msg_grp_name(context, &chat.name, &new_name, ContactId::SELF).await;
                msg.param.set_cmd(SystemMessage::GroupNameChanged);
                if !chat.name.is_empty() {
                    msg.param.set(Param::Arg, &chat.name);
                }
                msg.id = send_msg(context, chat_id, &mut msg).await?;
                context.emit_msgs_changed(chat_id, msg.id);
                sync = Nosync;
            }
            context.emit_event(EventType::ChatModified(chat_id));
            chatlist_events::emit_chatlist_item_changed(context, chat_id);
            success = true;
        }
    }

    if !success {
        bail!("Failed to set name");
    }
    if sync.into() && chat.name != new_name {
        let sync_name = new_name.to_string();
        chat.sync(context, SyncAction::Rename(sync_name))
            .await
            .log_err(context)
            .ok();
    }
    Ok(())
}

/// Sets a new profile image for the chat.
///
/// The profile image can only be set when you are a member of the
/// chat.  To remove the profile image pass an empty string for the
/// `new_image` parameter.
pub async fn set_chat_profile_image(
    context: &Context,
    chat_id: ChatId,
    new_image: &str, // XXX use PathBuf
) -> Result<()> {
    ensure!(!chat_id.is_special(), "Invalid chat ID");
    let mut chat = Chat::load_from_db(context, chat_id).await?;
    ensure!(
        chat.typ == Chattype::Group || chat.typ == Chattype::Mailinglist,
        "Failed to set profile image; group does not exist"
    );
    /* we should respect this - whatever we send to the group, it gets discarded anyway! */
    if !is_contact_in_chat(context, chat_id, ContactId::SELF).await? {
        context.emit_event(EventType::ErrorSelfNotInGroup(
            "Cannot set chat profile image; self not in group.".into(),
        ));
        bail!("Failed to set profile image");
    }
    let mut msg = Message::new(Viewtype::Text);
    msg.param
        .set_int(Param::Cmd, SystemMessage::GroupImageChanged as i32);
    if new_image.is_empty() {
        chat.param.remove(Param::ProfileImage);
        msg.param.remove(Param::Arg);
        msg.text = stock_str::msg_grp_img_deleted(context, ContactId::SELF).await;
    } else {
        let mut image_blob = BlobObject::create_and_deduplicate(
            context,
            Path::new(new_image),
            Path::new(new_image),
        )?;
        image_blob.recode_to_avatar_size(context).await?;
        chat.param.set(Param::ProfileImage, image_blob.as_name());
        msg.param.set(Param::Arg, image_blob.as_name());
        msg.text = stock_str::msg_grp_img_changed(context, ContactId::SELF).await;
    }
    chat.update_param(context).await?;
    if chat.is_promoted() && !chat.is_mailing_list() {
        msg.id = send_msg(context, chat_id, &mut msg).await?;
        context.emit_msgs_changed(chat_id, msg.id);
    }
    context.emit_event(EventType::ChatModified(chat_id));
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    Ok(())
}

/// Forwards multiple messages to a chat.
pub async fn forward_msgs(context: &Context, msg_ids: &[MsgId], chat_id: ChatId) -> Result<()> {
    ensure!(!msg_ids.is_empty(), "empty msgs_ids: nothing to forward");
    ensure!(!chat_id.is_special(), "can not forward to special chat");

    let mut created_msgs: Vec<MsgId> = Vec::new();
    let mut curr_timestamp: i64;

    chat_id
        .unarchive_if_not_muted(context, MessageState::Undefined)
        .await?;
    let mut chat = Chat::load_from_db(context, chat_id).await?;
    if let Some(reason) = chat.why_cant_send(context).await? {
        bail!("cannot send to {}: {}", chat_id, reason);
    }
    curr_timestamp = create_smeared_timestamps(context, msg_ids.len());
    let mut msgs = Vec::with_capacity(msg_ids.len());
    for id in msg_ids {
        let ts: i64 = context
            .sql
            .query_get_value("SELECT timestamp FROM msgs WHERE id=?", (id,))
            .await?
            .context("No message {id}")?;
        msgs.push((ts, *id));
    }
    msgs.sort_unstable();
    for (_, id) in msgs {
        let src_msg_id: MsgId = id;
        let mut msg = Message::load_from_db(context, src_msg_id).await?;
        if msg.state == MessageState::OutDraft {
            bail!("cannot forward drafts.");
        }

        // we tested a sort of broadcast
        // by not marking own forwarded messages as such,
        // however, this turned out to be to confusing and unclear.

        if msg.get_viewtype() != Viewtype::Sticker {
            msg.param
                .set_int(Param::Forwarded, src_msg_id.to_u32() as i32);
        }

        msg.param.remove(Param::GuaranteeE2ee);
        msg.param.remove(Param::ForcePlaintext);
        msg.param.remove(Param::Cmd);
        msg.param.remove(Param::OverrideSenderDisplayname);
        msg.param.remove(Param::WebxdcDocument);
        msg.param.remove(Param::WebxdcDocumentTimestamp);
        msg.param.remove(Param::WebxdcSummary);
        msg.param.remove(Param::WebxdcSummaryTimestamp);
        msg.param.remove(Param::IsEdited);
        msg.in_reply_to = None;

        // do not leak data as group names; a default subject is generated by mimefactory
        msg.subject = "".to_string();

        msg.state = MessageState::OutPending;
        msg.rfc724_mid = create_outgoing_rfc724_mid();
        let new_msg_id = chat
            .prepare_msg_raw(context, &mut msg, None, curr_timestamp)
            .await?;

        curr_timestamp += 1;
        if !create_send_msg_jobs(context, &mut msg).await?.is_empty() {
            context.scheduler.interrupt_smtp().await;
        }
        created_msgs.push(new_msg_id);
    }
    for msg_id in created_msgs {
        context.emit_msgs_changed(chat_id, msg_id);
    }
    Ok(())
}

/// Save a copy of the message in "Saved Messages"
/// and send a sync messages so that other devices save the message as well, unless deleted there.
pub async fn save_msgs(context: &Context, msg_ids: &[MsgId]) -> Result<()> {
    for src_msg_id in msg_ids {
        let dest_rfc724_mid = create_outgoing_rfc724_mid();
        let src_rfc724_mid = save_copy_in_self_talk(context, src_msg_id, &dest_rfc724_mid).await?;
        context
            .add_sync_item(SyncData::SaveMessage {
                src: src_rfc724_mid,
                dest: dest_rfc724_mid,
            })
            .await?;
    }
    context.scheduler.interrupt_inbox().await;
    Ok(())
}

/// Saves a copy of the given message in "Saved Messages" using the given RFC724 id.
/// To allow UIs to have a "show in context" button,
/// the copy contains a reference to the original message
/// as well as to the original chat in case the original message gets deleted.
/// Returns data needed to add a `SaveMessage` sync item.
pub(crate) async fn save_copy_in_self_talk(
    context: &Context,
    src_msg_id: &MsgId,
    dest_rfc724_mid: &String,
) -> Result<String> {
    let dest_chat_id = ChatId::create_for_contact(context, ContactId::SELF).await?;
    let mut msg = Message::load_from_db(context, *src_msg_id).await?;
    msg.param.remove(Param::Cmd);
    msg.param.remove(Param::WebxdcDocument);
    msg.param.remove(Param::WebxdcDocumentTimestamp);
    msg.param.remove(Param::WebxdcSummary);
    msg.param.remove(Param::WebxdcSummaryTimestamp);

    if !msg.original_msg_id.is_unset() {
        bail!("message already saved.");
    }

    let copy_fields = "from_id, to_id, timestamp_sent, timestamp_rcvd, type, txt, \
                             mime_modified, mime_headers, mime_compressed, mime_in_reply_to, subject, msgrmsg";
    let row_id = context
        .sql
        .insert(
            &format!(
                "INSERT INTO msgs ({copy_fields}, chat_id, rfc724_mid, state, timestamp, param, starred) \
                            SELECT {copy_fields}, ?, ?, ?, ?, ?, ? \
                            FROM msgs WHERE id=?;"
            ),
            (
                dest_chat_id,
                dest_rfc724_mid,
                if msg.from_id == ContactId::SELF {
                    MessageState::OutDelivered
                } else {
                    MessageState::InSeen
                },
                create_smeared_timestamp(context),
                msg.param.to_string(),
                src_msg_id,
                src_msg_id,
            ),
        )
        .await?;
    let dest_msg_id = MsgId::new(row_id.try_into()?);

    context.emit_msgs_changed(msg.chat_id, *src_msg_id);
    context.emit_msgs_changed(dest_chat_id, dest_msg_id);
    chatlist_events::emit_chatlist_changed(context);
    chatlist_events::emit_chatlist_item_changed(context, dest_chat_id);

    Ok(msg.rfc724_mid)
}

/// Resends given messages with the same Message-ID.
///
/// This is primarily intended to make existing webxdcs available to new chat members.
pub async fn resend_msgs(context: &Context, msg_ids: &[MsgId]) -> Result<()> {
    let mut chat_id = None;
    let mut msgs: Vec<Message> = Vec::new();
    for msg_id in msg_ids {
        let msg = Message::load_from_db(context, *msg_id).await?;
        if let Some(chat_id) = chat_id {
            ensure!(
                chat_id == msg.chat_id,
                "messages to resend needs to be in the same chat"
            );
        } else {
            chat_id = Some(msg.chat_id);
        }
        ensure!(
            msg.from_id == ContactId::SELF,
            "can resend only own messages"
        );
        ensure!(!msg.is_info(), "cannot resend info messages");
        msgs.push(msg)
    }

    let Some(chat_id) = chat_id else {
        return Ok(());
    };

    let chat = Chat::load_from_db(context, chat_id).await?;
    for mut msg in msgs {
        if msg.get_showpadlock() && !chat.is_protected() {
            msg.param.remove(Param::GuaranteeE2ee);
            msg.update_param(context).await?;
        }
        match msg.get_state() {
            // `get_state()` may return an outdated `OutPending`, so update anyway.
            MessageState::OutPending
            | MessageState::OutFailed
            | MessageState::OutDelivered
            | MessageState::OutMdnRcvd => {
                message::update_msg_state(context, msg.id, MessageState::OutPending).await?
            }
            msg_state => bail!("Unexpected message state {msg_state}"),
        }
        context.emit_event(EventType::MsgsChanged {
            chat_id: msg.chat_id,
            msg_id: msg.id,
        });
        msg.timestamp_sort = create_smeared_timestamp(context);
        // note(treefit): only matters if it is the last message in chat (but probably to expensive to check, debounce also solves it)
        chatlist_events::emit_chatlist_item_changed(context, msg.chat_id);
        if create_send_msg_jobs(context, &mut msg).await?.is_empty() {
            continue;
        }
        if msg.viewtype == Viewtype::Webxdc {
            let conn_fn = |conn: &mut rusqlite::Connection| {
                let range = conn.query_row(
                    "SELECT IFNULL(min(id), 1), IFNULL(max(id), 0) \
                     FROM msgs_status_updates WHERE msg_id=?",
                    (msg.id,),
                    |row| {
                        let min_id: StatusUpdateSerial = row.get(0)?;
                        let max_id: StatusUpdateSerial = row.get(1)?;
                        Ok((min_id, max_id))
                    },
                )?;
                if range.0 > range.1 {
                    return Ok(());
                };
                // `first_serial` must be decreased, otherwise if `Context::flush_status_updates()`
                // runs in parallel, it would miss the race and instead of resending just remove the
                // updates thinking that they have been already sent.
                conn.execute(
                    "INSERT INTO smtp_status_updates (msg_id, first_serial, last_serial, descr) \
                     VALUES(?, ?, ?, '') \
                     ON CONFLICT(msg_id) \
                     DO UPDATE SET first_serial=min(first_serial - 1, excluded.first_serial)",
                    (msg.id, range.0, range.1),
                )?;
                Ok(())
            };
            context.sql.call_write(conn_fn).await?;
        }
        context.scheduler.interrupt_smtp().await;
    }
    Ok(())
}

pub(crate) async fn get_chat_cnt(context: &Context) -> Result<usize> {
    if context.sql.is_open().await {
        // no database, no chats - this is no error (needed eg. for information)
        let count = context
            .sql
            .count("SELECT COUNT(*) FROM chats WHERE id>9 AND blocked=0;", ())
            .await?;
        Ok(count)
    } else {
        Ok(0)
    }
}

/// Returns a tuple of `(chatid, is_protected, blocked)`.
pub(crate) async fn get_chat_id_by_grpid(
    context: &Context,
    grpid: &str,
) -> Result<Option<(ChatId, bool, Blocked)>> {
    context
        .sql
        .query_row_optional(
            "SELECT id, blocked, protected FROM chats WHERE grpid=?;",
            (grpid,),
            |row| {
                let chat_id = row.get::<_, ChatId>(0)?;

                let b = row.get::<_, Option<Blocked>>(1)?.unwrap_or_default();
                let p = row
                    .get::<_, Option<ProtectionStatus>>(2)?
                    .unwrap_or_default();
                Ok((chat_id, p == ProtectionStatus::Protected, b))
            },
        )
        .await
}

/// Adds a message to device chat.
///
/// Optional `label` can be provided to ensure that message is added only once.
/// If `important` is true, a notification will be sent.
pub async fn add_device_msg_with_importance(
    context: &Context,
    label: Option<&str>,
    msg: Option<&mut Message>,
    important: bool,
) -> Result<MsgId> {
    ensure!(
        label.is_some() || msg.is_some(),
        "device-messages need label, msg or both"
    );
    let mut chat_id = ChatId::new(0);
    let mut msg_id = MsgId::new_unset();

    if let Some(label) = label {
        if was_device_msg_ever_added(context, label).await? {
            info!(context, "Device-message {label} already added.");
            return Ok(msg_id);
        }
    }

    if let Some(msg) = msg {
        chat_id = ChatId::get_for_contact(context, ContactId::DEVICE).await?;

        let rfc724_mid = create_outgoing_rfc724_mid();
        prepare_msg_blob(context, msg).await?;

        let timestamp_sent = create_smeared_timestamp(context);

        // makes sure, the added message is the last one,
        // even if the date is wrong (useful esp. when warning about bad dates)
        let mut timestamp_sort = timestamp_sent;
        if let Some(last_msg_time) = chat_id.get_timestamp(context).await? {
            if timestamp_sort <= last_msg_time {
                timestamp_sort = last_msg_time + 1;
            }
        }

        let state = MessageState::InFresh;
        let row_id = context
            .sql
            .insert(
                "INSERT INTO msgs (
            chat_id,
            from_id,
            to_id,
            timestamp,
            timestamp_sent,
            timestamp_rcvd,
            type,state,
            txt,
            txt_normalized,
            param,
            rfc724_mid)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
                (
                    chat_id,
                    ContactId::DEVICE,
                    ContactId::SELF,
                    timestamp_sort,
                    timestamp_sent,
                    timestamp_sent, // timestamp_sent equals timestamp_rcvd
                    msg.viewtype,
                    state,
                    &msg.text,
                    message::normalize_text(&msg.text),
                    msg.param.to_string(),
                    rfc724_mid,
                ),
            )
            .await?;
        context.new_msgs_notify.notify_one();

        msg_id = MsgId::new(u32::try_from(row_id)?);
        if !msg.hidden {
            chat_id.unarchive_if_not_muted(context, state).await?;
        }
    }

    if let Some(label) = label {
        context
            .sql
            .execute("INSERT INTO devmsglabels (label) VALUES (?);", (label,))
            .await?;
    }

    if !msg_id.is_unset() {
        chat_id.emit_msg_event(context, msg_id, important);
    }

    Ok(msg_id)
}

/// Adds a message to device chat.
pub async fn add_device_msg(
    context: &Context,
    label: Option<&str>,
    msg: Option<&mut Message>,
) -> Result<MsgId> {
    add_device_msg_with_importance(context, label, msg, false).await
}

/// Returns true if device message with a given label was ever added to the device chat.
pub async fn was_device_msg_ever_added(context: &Context, label: &str) -> Result<bool> {
    ensure!(!label.is_empty(), "empty label");
    let exists = context
        .sql
        .exists(
            "SELECT COUNT(label) FROM devmsglabels WHERE label=?",
            (label,),
        )
        .await?;

    Ok(exists)
}

// needed on device-switches during export/import;
// - deletion in `msgs` with `ContactId::DEVICE` makes sure,
//   no wrong information are shown in the device chat
// - deletion in `devmsglabels` makes sure,
//   deleted messages are reset and useful messages can be added again
// - we reset the config-option `QuotaExceeding`
//   that is used as a helper to drive the corresponding device message.
pub(crate) async fn delete_and_reset_all_device_msgs(context: &Context) -> Result<()> {
    context
        .sql
        .execute("DELETE FROM msgs WHERE from_id=?;", (ContactId::DEVICE,))
        .await?;
    context.sql.execute("DELETE FROM devmsglabels;", ()).await?;

    // Insert labels for welcome messages to avoid them being re-added on reconfiguration.
    context
        .sql
        .execute(
            r#"INSERT INTO devmsglabels (label) VALUES ("core-welcome-image"), ("core-welcome")"#,
            (),
        )
        .await?;
    context
        .set_config_internal(Config::QuotaExceeding, None)
        .await?;
    Ok(())
}

/// Adds an informational message to chat.
///
/// For example, it can be a message showing that a member was added to a group.
/// Doesn't fail if the chat doesn't exist.
#[expect(clippy::too_many_arguments)]
pub(crate) async fn add_info_msg_with_cmd(
    context: &Context,
    chat_id: ChatId,
    text: &str,
    cmd: SystemMessage,
    timestamp_sort: i64,
    // Timestamp to show to the user (if this is None, `timestamp_sort` will be shown to the user)
    timestamp_sent_rcvd: Option<i64>,
    parent: Option<&Message>,
    from_id: Option<ContactId>,
    added_removed_id: Option<ContactId>,
) -> Result<MsgId> {
    let rfc724_mid = create_outgoing_rfc724_mid();
    let ephemeral_timer = chat_id.get_ephemeral_timer(context).await?;

    let mut param = Params::new();
    if cmd != SystemMessage::Unknown {
        param.set_cmd(cmd);
    }
    if let Some(contact_id) = added_removed_id {
        param.set(Param::ContactAddedRemoved, contact_id.to_u32().to_string());
    }

    let row_id =
    context.sql.insert(
        "INSERT INTO msgs (chat_id,from_id,to_id,timestamp,timestamp_sent,timestamp_rcvd,type,state,txt,txt_normalized,rfc724_mid,ephemeral_timer,param,mime_in_reply_to)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
        (
            chat_id,
            from_id.unwrap_or(ContactId::INFO),
            ContactId::INFO,
            timestamp_sort,
            timestamp_sent_rcvd.unwrap_or(0),
            timestamp_sent_rcvd.unwrap_or(0),
            Viewtype::Text,
            MessageState::InNoticed,
            text,
            message::normalize_text(text),
            rfc724_mid,
            ephemeral_timer,
            param.to_string(),
            parent.map(|msg|msg.rfc724_mid.clone()).unwrap_or_default()
        )
    ).await?;
    context.new_msgs_notify.notify_one();

    let msg_id = MsgId::new(row_id.try_into()?);
    context.emit_msgs_changed(chat_id, msg_id);

    Ok(msg_id)
}

/// Adds info message with a given text and `timestamp` to the chat.
pub(crate) async fn add_info_msg(
    context: &Context,
    chat_id: ChatId,
    text: &str,
    timestamp: i64,
) -> Result<MsgId> {
    add_info_msg_with_cmd(
        context,
        chat_id,
        text,
        SystemMessage::Unknown,
        timestamp,
        None,
        None,
        None,
        None,
    )
    .await
}

pub(crate) async fn update_msg_text_and_timestamp(
    context: &Context,
    chat_id: ChatId,
    msg_id: MsgId,
    text: &str,
    timestamp: i64,
) -> Result<()> {
    context
        .sql
        .execute(
            "UPDATE msgs SET txt=?, txt_normalized=?, timestamp=? WHERE id=?;",
            (text, message::normalize_text(text), timestamp, msg_id),
        )
        .await?;
    context.emit_msgs_changed(chat_id, msg_id);
    Ok(())
}

/// Set chat contacts by their addresses creating the corresponding contacts if necessary.
async fn set_contacts_by_addrs(context: &Context, id: ChatId, addrs: &[String]) -> Result<()> {
    let chat = Chat::load_from_db(context, id).await?;
    ensure!(
        chat.typ == Chattype::Broadcast,
        "{id} is not a broadcast list",
    );
    let mut contacts = HashSet::new();
    for addr in addrs {
        let contact_addr = ContactAddress::new(addr)?;
        let contact = Contact::add_or_lookup(context, "", &contact_addr, Origin::Hidden)
            .await?
            .0;
        contacts.insert(contact);
    }
    let contacts_old = HashSet::<ContactId>::from_iter(get_chat_contacts(context, id).await?);
    if contacts == contacts_old {
        return Ok(());
    }
    context
        .sql
        .transaction(move |transaction| {
            transaction.execute("DELETE FROM chats_contacts WHERE chat_id=?", (id,))?;

            // We do not care about `add_timestamp` column
            // because timestamps are not used for broadcast lists.
            let mut statement = transaction
                .prepare("INSERT INTO chats_contacts (chat_id, contact_id) VALUES (?, ?)")?;
            for contact_id in &contacts {
                statement.execute((id, contact_id))?;
            }
            Ok(())
        })
        .await?;
    context.emit_event(EventType::ChatModified(id));
    Ok(())
}

/// A cross-device chat id used for synchronisation.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) enum SyncId {
    ContactAddr(String),
    Grpid(String),
    /// "Message-ID"-s, from oldest to latest. Used for ad-hoc groups.
    Msgids(Vec<String>),

    // Special id for device chat.
    Device,
}

/// An action synchronised to other devices.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub(crate) enum SyncAction {
    Block,
    Unblock,
    Accept,
    SetVisibility(ChatVisibility),
    SetMuted(MuteDuration),
    /// Create broadcast list with the given name.
    CreateBroadcast(String),
    Rename(String),
    /// Set chat contacts by their addresses.
    SetContacts(Vec<String>),
    Delete,
}

impl Context {
    /// Executes [`SyncData::AlterChat`] item sent by other device.
    pub(crate) async fn sync_alter_chat(&self, id: &SyncId, action: &SyncAction) -> Result<()> {
        let chat_id = match id {
            SyncId::ContactAddr(addr) => {
                if let SyncAction::Rename(to) = action {
                    Contact::create_ex(self, Nosync, to, addr).await?;
                    return Ok(());
                }
                let addr = ContactAddress::new(addr).context("Invalid address")?;
                let (contact_id, _) =
                    Contact::add_or_lookup(self, "", &addr, Origin::Hidden).await?;
                match action {
                    SyncAction::Block => {
                        return contact::set_blocked(self, Nosync, contact_id, true).await
                    }
                    SyncAction::Unblock => {
                        return contact::set_blocked(self, Nosync, contact_id, false).await
                    }
                    _ => (),
                }
                // Use `Request` so that even if the program crashes, the user doesn't have to look
                // into the blocked contacts.
                ChatIdBlocked::get_for_contact(self, contact_id, Blocked::Request)
                    .await?
                    .id
            }
            SyncId::Grpid(grpid) => {
                if let SyncAction::CreateBroadcast(name) = action {
                    create_broadcast_list_ex(self, Nosync, grpid.clone(), name.clone()).await?;
                    return Ok(());
                }
                get_chat_id_by_grpid(self, grpid)
                    .await?
                    .with_context(|| format!("No chat for grpid '{grpid}'"))?
                    .0
            }
            SyncId::Msgids(msgids) => {
                let msg = message::get_by_rfc724_mids(self, msgids)
                    .await?
                    .with_context(|| format!("No message found for Message-IDs {msgids:?}"))?;
                ChatId::lookup_by_message(&msg)
                    .with_context(|| format!("No chat found for Message-IDs {msgids:?}"))?
            }
            SyncId::Device => ChatId::get_for_contact(self, ContactId::DEVICE).await?,
        };
        match action {
            SyncAction::Block => chat_id.block_ex(self, Nosync).await,
            SyncAction::Unblock => chat_id.unblock_ex(self, Nosync).await,
            SyncAction::Accept => chat_id.accept_ex(self, Nosync).await,
            SyncAction::SetVisibility(v) => chat_id.set_visibility_ex(self, Nosync, *v).await,
            SyncAction::SetMuted(duration) => set_muted_ex(self, Nosync, chat_id, *duration).await,
            SyncAction::CreateBroadcast(_) => {
                Err(anyhow!("sync_alter_chat({id:?}, {action:?}): Bad request."))
            }
            SyncAction::Rename(to) => rename_ex(self, Nosync, chat_id, to).await,
            SyncAction::SetContacts(addrs) => set_contacts_by_addrs(self, chat_id, addrs).await,
            SyncAction::Delete => chat_id.delete_ex(self, Nosync).await,
        }
    }

    /// Emits the appropriate `MsgsChanged` event. Should be called if the number of unnoticed
    /// archived chats could decrease. In general we don't want to make an extra db query to know if
    /// a noticed chat is archived. Emitting events should be cheap, a false-positive `MsgsChanged`
    /// is ok.
    pub(crate) fn on_archived_chats_maybe_noticed(&self) {
        self.emit_msgs_changed_without_msg_id(DC_CHAT_ID_ARCHIVED_LINK);
    }
}

#[cfg(test)]
mod chat_tests;
