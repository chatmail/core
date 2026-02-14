//! # Chat module.

use std::cmp;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Cursor;
use std::marker::Sync;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use chrono::TimeZone;
use deltachat_contact_tools::{ContactAddress, sanitize_bidi_characters, sanitize_single_line};
use humansize::{BINARY, format_size};
use mail_builder::mime::MimePart;
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::blob::BlobObject;
use crate::chatlist::Chatlist;
use crate::chatlist_events;
use crate::color::str_to_color;
use crate::config::Config;
use crate::constants::{
    Blocked, Chattype, DC_CHAT_ID_ALLDONE_HINT, DC_CHAT_ID_ARCHIVED_LINK, DC_CHAT_ID_LAST_SPECIAL,
    DC_CHAT_ID_TRASH, DC_RESEND_USER_AVATAR_DAYS, EDITED_PREFIX, TIMESTAMP_SENT_TOLERANCE,
};
use crate::contact::{self, Contact, ContactId, Origin};
use crate::context::Context;
use crate::debug_logging::maybe_set_logging_xdc;
use crate::download::{
    DownloadState, PRE_MSG_ATTACHMENT_SIZE_THRESHOLD, PRE_MSG_SIZE_WARNING_THRESHOLD,
};
use crate::ephemeral::{Timer as EphemeralTimer, start_chat_ephemeral_timers};
use crate::events::EventType;
use crate::key::self_fingerprint;
use crate::location;
use crate::log::{LogExt, warn};
use crate::logged_debug_assert;
use crate::message::{self, Message, MessageState, MsgId, Viewtype};
use crate::mimefactory::{MimeFactory, RenderedEmail};
use crate::mimeparser::SystemMessage;
use crate::param::{Param, Params};
use crate::receive_imf::ReceivedMsg;
use crate::smtp::{self, send_msg_to_smtp};
use crate::stock_str;
use crate::sync::{self, Sync::*, SyncData};
use crate::tools::{
    IsNoneOrEmpty, SystemTime, buf_compress, create_broadcast_secret, create_id,
    create_outgoing_rfc724_mid, create_smeared_timestamp, create_smeared_timestamps, get_abs_path,
    gm2local_offset, normalize_text, smeared_time, time, truncate_msg_text,
};
use crate::webxdc::StatusUpdateSerial;

pub(crate) const PARAM_BROADCAST_SECRET: Param = Param::Arg3;

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

    /// Mailing list without known List-Post header.
    ReadOnlyMailingList,

    /// Incoming broadcast channel where the user can't send messages.
    InBroadcast,

    /// Not a member of the chat.
    NotAMember,

    /// State for 1:1 chat with a key-contact that does not have a key.
    MissingKey,
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
            Self::ReadOnlyMailingList => {
                write!(f, "mailing list does not have a know post address")
            }
            Self::InBroadcast => {
                write!(f, "Broadcast channel is read-only")
            }
            Self::NotAMember => write!(f, "not a member of the chat"),
            Self::MissingKey => write!(f, "key is missing"),
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
    pub(crate) async fn create_multiuser_record(
        context: &Context,
        chattype: Chattype,
        grpid: &str,
        grpname: &str,
        create_blocked: Blocked,
        param: Option<String>,
        timestamp: i64,
    ) -> Result<Self> {
        let grpname = sanitize_single_line(grpname);
        let timestamp = cmp::min(timestamp, smeared_time(context));
        let row_id =
            context.sql.insert(
                "INSERT INTO chats (type, name, name_normalized, grpid, blocked, created_timestamp, protected, param) VALUES(?, ?, ?, ?, ?, ?, 0, ?)",
                (
                    chattype,
                    &grpname,
                    normalize_text(&grpname),
                    grpid,
                    create_blocked,
                    timestamp,
                    param.unwrap_or_default(),
                ),
            ).await?;

        let chat_id = ChatId::new(u32::try_from(row_id)?);
        let chat = Chat::load_from_db(context, chat_id).await?;

        if chat.is_encrypted(context).await? {
            chat_id.add_e2ee_notice(context, timestamp).await?;
        }

        info!(
            context,
            "Created group/broadcast '{}' grpid={} as {}, blocked={}.",
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
            bail!("ignoring setting of Block-status for {self}");
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
            Chattype::OutBroadcast => {
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
            Chattype::Mailinglist | Chattype::InBroadcast => {
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
            Chattype::Single | Chattype::Group | Chattype::OutBroadcast | Chattype::InBroadcast => {
                // Previously accepting a chat literally created a chat because unaccepted chats
                // went to "contact requests" list rather than normal chatlist.
                // But for groups we use lower origin because users don't always check all members
                // before accepting a chat and may not want to have the group members mixed with
                // existing contacts. `IncomingTo` fits here by its definition.
                let origin = match chat.typ {
                    Chattype::Group => Origin::IncomingTo,
                    _ => Origin::CreateChat,
                };
                for contact_id in get_chat_contacts(context, self).await? {
                    if contact_id != ContactId::SELF {
                        ContactId::scaleup_origin(context, &[contact_id], origin).await?;
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

    /// Adds message "Messages are end-to-end encrypted".
    pub(crate) async fn add_e2ee_notice(self, context: &Context, timestamp: i64) -> Result<()> {
        let text = stock_str::messages_e2e_encrypted(context).await;
        add_info_msg_with_cmd(
            context,
            self,
            &text,
            SystemMessage::ChatE2ee,
            Some(timestamp),
            timestamp,
            None,
            None,
            None,
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
            "bad chat_id, can not be special chat: {self}"
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
    ///
    /// Messages are deleted from the device and the chat database entry is deleted.
    /// After that, a `MsgsChanged` event is emitted.
    /// Messages are deleted from the server in background.
    pub async fn delete(self, context: &Context) -> Result<()> {
        self.delete_ex(context, Sync).await
    }

    pub(crate) async fn delete_ex(self, context: &Context, sync: sync::Sync) -> Result<()> {
        ensure!(
            !self.is_special(),
            "bad chat_id, can not be a special chat: {self}"
        );

        let chat = Chat::load_from_db(context, self).await?;
        let sync_id = match sync {
            Nosync => None,
            Sync => chat.get_sync_id(context).await?,
        };

        context
            .sql
            .transaction(|transaction| {
                transaction.execute(
                    "UPDATE imap SET target='' WHERE rfc724_mid IN (SELECT rfc724_mid FROM msgs WHERE chat_id=? AND rfc724_mid!='')",
                    (self,),
                )?;
                transaction.execute(
                    "UPDATE imap SET target='' WHERE rfc724_mid IN (SELECT pre_rfc724_mid FROM msgs WHERE chat_id=? AND pre_rfc724_mid!='')",
                    (self,),
                )?;
                transaction.execute(
                    "DELETE FROM msgs_mdns WHERE msg_id IN (SELECT id FROM msgs WHERE chat_id=?)",
                    (self,),
                )?;
                // If you change which information is preserved here, also change `MsgId::trash()`
                // and other places it references.
                transaction.execute(
                    "
INSERT OR REPLACE INTO msgs (id, rfc724_mid, pre_rfc724_mid, timestamp, chat_id, deleted)
SELECT id, rfc724_mid, pre_rfc724_mid, timestamp, ?, 1 FROM msgs WHERE chat_id=?
                    ",
                    (DC_CHAT_ID_TRASH, self),
                )?;
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
        context.scheduler.interrupt_smtp().await;

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
                if msg.viewtype == Viewtype::File
                    && let Some((better_type, _)) = message::guess_msgtype_from_suffix(msg)
                        // We do not do an automatic conversion to other viewtypes here so that
                        // users can send images as "files" to preserve the original quality
                        // (usually we compress images). The remaining conversions are done by
                        // `prepare_msg_blob()` later.
                        .filter(|&(vt, _)| vt == Viewtype::Webxdc || vt == Viewtype::Vcard)
                {
                    msg.viewtype = better_type;
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
        if !msg.id.is_special()
            && let Some(old_draft) = self.get_draft(context).await?
            && old_draft.id == msg.id
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
                                    normalize_text(&msg.text),
                                    msg.param.to_string(),
                                    msg.in_reply_to.as_deref().unwrap_or_default(),
                                    msg.id,
                                ),
                            ).await?;
            return Ok(affected_rows > 0);
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
                        normalize_text(&msg.text),
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
    #[expect(clippy::arithmetic_side_effects)]
    pub async fn get_similar_chat_ids(self, context: &Context) -> Result<Vec<(ChatId, f64)>> {
        // Count number of common members in this and other chats.
        let intersection = context
            .sql
            .query_map_vec(
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
            )
            .await
            .context("failed to calculate member set intersections")?;

        let chat_size: HashMap<ChatId, f64> = context
            .sql
            .query_map_collect(
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
            if let Some(chat_timestamp) = chat_id.get_timestamp(context).await?
                && now > chat_timestamp + 42 * 24 * 3600
            {
                // Chat was inactive for 42 days, skip.
                continue;
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
    #[expect(clippy::arithmetic_side_effects)]
    pub async fn get_encryption_info(self, context: &Context) -> Result<String> {
        let chat = Chat::load_from_db(context, self).await?;
        if !chat.is_encrypted(context).await? {
            return Ok(stock_str::encr_none(context).await);
        }

        let mut ret = stock_str::messages_e2e_encrypted(context).await + "\n";

        for &contact_id in get_chat_contacts(context, self)
            .await?
            .iter()
            .filter(|&contact_id| !contact_id.is_special())
        {
            let contact = Contact::get_by_id(context, contact_id).await?;
            let addr = contact.get_addr();
            logged_debug_assert!(
                context,
                contact.is_key_contact(),
                "get_encryption_info: contact {contact_id} is not a key-contact."
            );
            let fingerprint = contact
                .fingerprint()
                .context("Contact does not have a fingerprint in encrypted chat")?;
            if contact.public_key(context).await?.is_some() {
                ret += &format!("\n{addr}\n{fingerprint}\n");
            } else {
                ret += &format!("\n{addr}\n(key missing)\n{fingerprint}\n");
            }
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

        if let Some(last_msg_time) = last_msg_time
            && last_msg_time > sort_timestamp
        {
            sort_timestamp = last_msg_time;
        }

        Ok(sort_timestamp)
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
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
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
}

impl Chat {
    /// Loads chat from the database by its ID.
    pub async fn load_from_db(context: &Context, chat_id: ChatId) -> Result<Self> {
        let mut chat = context
            .sql
            .query_row(
                "SELECT c.type, c.name, c.grpid, c.param, c.archived,
                    c.blocked, c.locations_send_until, c.muted_until
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
                        if let Some(contact_id) = contacts.first()
                            && let Ok(contact) = Contact::get_by_id(context, *contact_id).await
                        {
                            contact.get_display_name().clone_into(&mut chat_name);
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
        if self.is_mailing_list() && self.get_mailinglist_addr().is_none_or_empty() {
            let reason = ReadOnlyMailingList;
            if !skip_fn(&reason) {
                return Ok(Some(reason));
            }
        }
        if self.typ == Chattype::InBroadcast {
            let reason = InBroadcast;
            if !skip_fn(&reason) {
                return Ok(Some(reason));
            }
        }

        // Do potentially slow checks last and after calls to `skip_fn` which should be fast.
        let reason = NotAMember;
        if !skip_fn(&reason) && !self.is_self_in_chat(context).await? {
            return Ok(Some(reason));
        }

        let reason = MissingKey;
        if !skip_fn(&reason) && self.typ == Chattype::Single {
            let contact_ids = get_chat_contacts(context, self.id).await?;
            if let Some(contact_id) = contact_ids.first() {
                let contact = Contact::get_by_id(context, *contact_id).await?;
                if contact.is_key_contact() && contact.public_key(context).await?.is_none() {
                    return Ok(Some(reason));
                }
            }
        }

        Ok(None)
    }

    /// Returns true if can send to the chat.
    ///
    /// This function can be used by the UI to decide whether to display the input box.
    pub async fn can_send(&self, context: &Context) -> Result<bool> {
        Ok(self.why_cant_send(context).await?.is_none())
    }

    /// Checks if the user is part of a chat
    /// and has basically the permissions to edit the chat therefore.
    /// The function does not check if the chat type allows editing of concrete elements.
    pub async fn is_self_in_chat(&self, context: &Context) -> Result<bool> {
        match self.typ {
            Chattype::Single | Chattype::OutBroadcast | Chattype::Mailinglist => Ok(true),
            Chattype::Group | Chattype::InBroadcast => {
                is_contact_in_chat(context, self.id, ContactId::SELF).await
            }
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
        if self.id.is_archived_link() {
            // This is not a real chat, but the "Archive" button
            // that is shown at the top of the chats list
            return Ok(Some(get_archive_icon(context).await?));
        } else if self.is_device_talk() {
            return Ok(Some(get_device_icon(context).await?));
        } else if self.is_self_talk() {
            return Ok(Some(get_saved_messages_icon(context).await?));
        } else if !self.is_encrypted(context).await? {
            // This is an unencrypted chat, show a special avatar that marks it as such.
            return Ok(Some(get_abs_path(
                context,
                Path::new(&get_unencrypted_icon(context).await?),
            )));
        } else if self.typ == Chattype::Single {
            // For 1:1 chats, we always use the same avatar as for the contact
            // This is before the `self.is_encrypted()` check, because that function
            // has two database calls, i.e. it's slow
            let contacts = get_chat_contacts(context, self.id).await?;
            if let Some(contact_id) = contacts.first() {
                let contact = Contact::get_by_id(context, *contact_id).await?;
                return contact.get_profile_image(context).await;
            }
        } else if let Some(image_rel) = self.param.get(Param::ProfileImage) {
            // Load the group avatar, or the device-chat / saved-messages icon
            if !image_rel.is_empty() {
                return Ok(Some(get_abs_path(context, Path::new(&image_rel))));
            }
        }
        Ok(None)
    }

    /// Returns chat avatar color.
    ///
    /// For 1:1 chats, the color is calculated from the contact's address
    /// for address-contacts and from the OpenPGP key fingerprint for key-contacts.
    /// For group chats the color is calculated from the grpid, if present, or the chat name.
    pub async fn get_color(&self, context: &Context) -> Result<u32> {
        let mut color = 0;

        if self.typ == Chattype::Single {
            let contacts = get_chat_contacts(context, self.id).await?;
            if let Some(contact_id) = contacts.first()
                && let Ok(contact) = Contact::get_by_id(context, *contact_id).await
            {
                color = contact.get_color();
            }
        } else if !self.grpid.is_empty() {
            color = str_to_color(&self.grpid);
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

    /// Returns true if the chat is encrypted.
    pub async fn is_encrypted(&self, context: &Context) -> Result<bool> {
        let is_encrypted = self.is_self_talk()
            || match self.typ {
                Chattype::Single => {
                    match context
                        .sql
                        .query_row_optional(
                            "SELECT cc.contact_id, c.fingerprint<>''
                             FROM chats_contacts cc LEFT JOIN contacts c
                                 ON c.id=cc.contact_id
                             WHERE cc.chat_id=?
                            ",
                            (self.id,),
                            |row| {
                                let id: ContactId = row.get(0)?;
                                let is_key: bool = row.get(1)?;
                                Ok((id, is_key))
                            },
                        )
                        .await?
                    {
                        Some((id, is_key)) => is_key || id == ContactId::DEVICE,
                        None => true,
                    }
                }
                Chattype::Group => {
                    // Do not encrypt ad-hoc groups.
                    !self.grpid.is_empty()
                }
                Chattype::Mailinglist => false,
                Chattype::OutBroadcast | Chattype::InBroadcast => true,
            };
        Ok(is_encrypted)
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
    /// writes the record to the database.
    ///
    /// If `update_msg_id` is set, that record is reused;
    /// if `update_msg_id` is None, a new record is created.
    #[expect(clippy::arithmetic_side_effects)]
    async fn prepare_msg_raw(
        &mut self,
        context: &Context,
        msg: &mut Message,
        update_msg_id: Option<MsgId>,
    ) -> Result<()> {
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
        } else if matches!(self.typ, Chattype::Group | Chattype::OutBroadcast)
            && self.param.get_int(Param::Unpromoted).unwrap_or_default() == 1
        {
            msg.param.set_int(Param::AttachChatAvatarAndDescription, 1);
            self.param
                .remove(Param::Unpromoted)
                .set_i64(Param::GroupNameTimestamp, msg.timestamp_sort)
                .set_i64(Param::GroupDescriptionTimestamp, msg.timestamp_sort);
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
        if msg.param.exists(Param::SetLatitude)
            && let Ok(row_id) = context
                .sql
                .insert(
                    "INSERT INTO locations \
                     (timestamp,from_id,chat_id, latitude,longitude,independent)\
                     VALUES (?,?,?, ?,?,1);",
                    (
                        msg.timestamp_sort,
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
            msg.param.get(Param::SendHtml).map(|s| s.to_string())
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
                        normalize_text(&msg_text),
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
                        normalize_text(&msg_text),
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
        Ok(())
    }

    /// Sends a `SyncAction` synchronising chat contacts to other devices.
    pub(crate) async fn sync_contacts(&self, context: &Context) -> Result<()> {
        if self.is_encrypted(context).await? {
            let self_fp = self_fingerprint(context).await?;
            let fingerprint_addrs = context
                .sql
                .query_map_vec(
                    "SELECT c.id, c.fingerprint, c.addr
                     FROM contacts c INNER JOIN chats_contacts cc
                     ON c.id=cc.contact_id
                     WHERE cc.chat_id=? AND cc.add_timestamp >= cc.remove_timestamp",
                    (self.id,),
                    |row| {
                        if row.get::<_, ContactId>(0)? == ContactId::SELF {
                            return Ok((self_fp.to_string(), String::new()));
                        }
                        let fingerprint = row.get(1)?;
                        let addr = row.get(2)?;
                        Ok((fingerprint, addr))
                    },
                )
                .await?;
            self.sync(context, SyncAction::SetPgpContacts(fingerprint_addrs))
                .await?;
        } else {
            let addrs = context
                .sql
                .query_map_vec(
                    "SELECT c.addr \
                    FROM contacts c INNER JOIN chats_contacts cc \
                    ON c.id=cc.contact_id \
                    WHERE cc.chat_id=? AND cc.add_timestamp >= cc.remove_timestamp",
                    (self.id,),
                    |row| {
                        let addr: String = row.get(0)?;
                        Ok(addr)
                    },
                )
                .await?;
            self.sync(context, SyncAction::SetContacts(addrs)).await?;
        }
        Ok(())
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
                    if let Some(fingerprint) = contact.fingerprint() {
                        r = Some(SyncId::ContactFingerprint(fingerprint.hex()));
                    } else {
                        r = Some(SyncId::ContactAddr(contact.get_addr().to_string()));
                    }
                }
                Ok(r)
            }
            Chattype::OutBroadcast
            | Chattype::InBroadcast
            | Chattype::Group
            | Chattype::Mailinglist => {
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
    context.scheduler.interrupt_smtp().await;
    Ok(())
}

/// Whether the chat is pinned or archived.
#[derive(Debug, Copy, Eq, PartialEq, Clone, Serialize, Deserialize, EnumIter, Default)]
#[repr(i8)]
pub enum ChatVisibility {
    /// Chat is neither archived nor pinned.
    #[default]
    Normal = 0,

    /// Chat is archived.
    Archived = 1,

    /// Chat is pinned to the top of the chatlist.
    Pinned = 2,
}

impl rusqlite::types::ToSql for ChatVisibility {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
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

async fn get_asset_icon(context: &Context, name: &str, bytes: &[u8]) -> Result<PathBuf> {
    ensure!(name.starts_with("icon-"));
    if let Some(icon) = context.sql.get_raw_config(name).await? {
        return Ok(get_abs_path(context, Path::new(&icon)));
    }

    let blob =
        BlobObject::create_and_deduplicate_from_bytes(context, bytes, &format!("{name}.png"))?;
    let icon = blob.as_name().to_string();
    context.sql.set_raw_config(name, Some(&icon)).await?;

    Ok(get_abs_path(context, Path::new(&icon)))
}

pub(crate) async fn get_saved_messages_icon(context: &Context) -> Result<PathBuf> {
    get_asset_icon(
        context,
        "icon-saved-messages",
        include_bytes!("../assets/icon-saved-messages.png"),
    )
    .await
}

pub(crate) async fn get_device_icon(context: &Context) -> Result<PathBuf> {
    get_asset_icon(
        context,
        "icon-device",
        include_bytes!("../assets/icon-device.png"),
    )
    .await
}

pub(crate) async fn get_archive_icon(context: &Context) -> Result<PathBuf> {
    get_asset_icon(
        context,
        "icon-archive",
        include_bytes!("../assets/icon-archive.png"),
    )
    .await
}

/// Returns path to the icon
/// indicating unencrypted chats and address-contacts.
pub(crate) async fn get_unencrypted_icon(context: &Context) -> Result<PathBuf> {
    get_asset_icon(
        context,
        "icon-unencrypted",
        include_bytes!("../assets/icon-unencrypted.png"),
    )
    .await
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
                "UPDATE chats SET name=?, name_normalized=? WHERE id=? AND name!=?",
                (&name, normalize_text(&name), chat_id, &name),
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

        let smeared_time = create_smeared_timestamp(context);

        let chat_id = context
            .sql
            .transaction(move |transaction| {
                transaction.execute(
                    "INSERT INTO chats
                     (type, name, name_normalized, param, blocked, created_timestamp)
                     VALUES(?, ?, ?, ?, ?, ?)",
                    (
                        Chattype::Single,
                        &chat_name,
                        normalize_text(&chat_name),
                        params.to_string(),
                        create_blocked as u8,
                        smeared_time,
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

        let chat = Chat::load_from_db(context, chat_id).await?;
        if chat.is_encrypted(context).await?
            && !chat.param.exists(Param::Devicetalk)
            && !chat.param.exists(Param::Selftalk)
        {
            chat_id.add_e2ee_notice(context, smeared_time).await?;
        }

        Ok(Self {
            id: chat_id,
            blocked: create_blocked,
        })
    }
}

async fn prepare_msg_blob(context: &Context, msg: &mut Message) -> Result<()> {
    if msg.viewtype == Viewtype::Text || msg.viewtype == Viewtype::Call {
        // the caller should check if the message text is empty
    } else if msg.viewtype.has_file() {
        let viewtype_orig = msg.viewtype;
        let mut blob = msg
            .param
            .get_file_blob(context)?
            .with_context(|| format!("attachment missing for message of type #{}", msg.viewtype))?;
        let mut maybe_image = false;

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
                } else if better_type == Viewtype::Image {
                    maybe_image = true;
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
        if msg.viewtype == Viewtype::File && maybe_image
            || msg.viewtype == Viewtype::Image
            || msg.viewtype == Viewtype::Sticker && !msg.param.exists(Param::ForceSticker)
        {
            let new_name = blob
                .check_or_recode_image(context, msg.get_filename(), &mut msg.viewtype)
                .await?;
            msg.param.set(Param::Filename, new_name);
            msg.param.set(Param::File, blob.as_name());
        }

        if !msg.param.exists(Param::MimeType)
            && let Some((viewtype, mime)) = message::guess_msgtype_from_suffix(msg)
        {
            // If we unexpectedly didn't recognize the file as image, don't send it as such,
            // either the format is unsupported or the image is corrupted.
            let mime = match viewtype != Viewtype::Image
                || matches!(msg.viewtype, Viewtype::Image | Viewtype::Sticker)
            {
                true => mime,
                false => "application/octet-stream",
            };
            msg.param.set(Param::MimeType, mime);
        }

        msg.try_calc_and_set_dimensions(context).await?;

        let filename = msg.get_filename().context("msg has no file")?;
        let suffix = Path::new(&filename)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("dat");
        // Get file name to use for sending. For privacy purposes, we do not transfer the original
        // filenames e.g. for images; these names are normally not needed and contain timestamps,
        // running numbers, etc.
        let filename: String = match viewtype_orig {
            Viewtype::Voice => format!(
                "voice-messsage_{}.{}",
                chrono::Utc
                    .timestamp_opt(msg.timestamp_sort, 0)
                    .single()
                    .map_or_else(
                        || "YY-mm-dd_hh:mm:ss".to_string(),
                        |ts| ts.format("%Y-%m-%d_%H-%M-%S").to_string()
                    ),
                &suffix
            ),
            Viewtype::Image | Viewtype::Gif => format!(
                "image_{}.{}",
                chrono::Utc
                    .timestamp_opt(msg.timestamp_sort, 0)
                    .single()
                    .map_or_else(
                        || "YY-mm-dd_hh:mm:ss".to_string(),
                        |ts| ts.format("%Y-%m-%d_%H-%M-%S").to_string(),
                    ),
                &suffix,
            ),
            Viewtype::Video => format!(
                "video_{}.{}",
                chrono::Utc
                    .timestamp_opt(msg.timestamp_sort, 0)
                    .single()
                    .map_or_else(
                        || "YY-mm-dd_hh:mm:ss".to_string(),
                        |ts| ts.format("%Y-%m-%d_%H-%M-%S").to_string()
                    ),
                &suffix
            ),
            _ => filename,
        };
        msg.param.set(Param::Filename, filename);

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
    // ContactId::SELF may be used to check whether oneself
    // is in a group or incoming broadcast chat
    // (ContactId::SELF is not added to 1:1 chats or outgoing broadcast channels)

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
        CantSendReason::ContactRequest => {
            // Allow securejoin messages, they are supposed to repair the verification.
            // If the chat is a contact request, let the user accept it later.
            msg.param.get_cmd() == SystemMessage::SecurejoinMessage
        }
        // Allow to send "Member removed" messages so we can leave the group/broadcast.
        // Necessary checks should be made anyway before removing contact
        // from the chat.
        CantSendReason::NotAMember => msg.param.get_cmd() == SystemMessage::MemberRemovedFromGroup,
        CantSendReason::InBroadcast => {
            matches!(
                msg.param.get_cmd(),
                SystemMessage::MemberRemovedFromGroup | SystemMessage::SecurejoinMessage
            )
        }
        CantSendReason::MissingKey => msg
            .param
            .get_bool(Param::ForcePlaintext)
            .unwrap_or_default(),
        _ => false,
    };
    if let Some(reason) = chat.why_cant_send_ex(context, &skip_fn).await? {
        bail!("Cannot send to {chat_id}: {reason}");
    }

    // Check a quote reply is not leaking data from other chats.
    // This is meant as a last line of defence, the UI should check that before as well.
    // (We allow Chattype::Single in general for "Reply Privately";
    // checking for exact contact_id will produce false positives when ppl just left the group)
    if chat.typ != Chattype::Single
        && !context.get_config_bool(Config::Bot).await?
        && let Some(quoted_message) = msg.quoted_message(context).await?
        && quoted_message.chat_id != chat_id
    {
        bail!(
            "Quote of message from {} cannot be sent to {chat_id}",
            quoted_message.chat_id
        );
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

    msg.timestamp_sort = create_smeared_timestamp(context);
    prepare_msg_blob(context, msg).await?;
    if !msg.hidden {
        chat_id.unarchive_if_not_muted(context, msg.state).await?;
    }
    chat.prepare_msg_raw(context, msg, update_msg_id).await?;

    let row_ids = create_send_msg_jobs(context, msg)
        .await
        .context("Failed to create send jobs")?;
    if !row_ids.is_empty() {
        donation_request_maybe(context).await.log_err(context).ok();
    }
    Ok(row_ids)
}

/// Renders the Message or splits it into Pre- and Post-Message.
///
/// Pre-Message is a small message with metadata which announces a larger Post-Message.
/// Post-Messages are not downloaded in the background.
///
/// If pre-message is not nessesary, this returns `None` as the 0th value.
async fn render_mime_message_and_pre_message(
    context: &Context,
    msg: &mut Message,
    mimefactory: MimeFactory,
) -> Result<(Option<RenderedEmail>, RenderedEmail)> {
    let needs_pre_message = msg.viewtype.has_file()
        && mimefactory.will_be_encrypted() // unencrypted is likely email, we don't want to spam by sending multiple messages
        && msg
            .get_filebytes(context)
            .await?
            .context("filebytes not available, even though message has attachment")?
            > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD;

    if needs_pre_message {
        info!(
            context,
            "Message {} is large and will be split into pre- and post-messages.", msg.id,
        );

        let mut mimefactory_post_msg = mimefactory.clone();
        mimefactory_post_msg.set_as_post_message();
        let rendered_msg = mimefactory_post_msg
            .render(context)
            .await
            .context("Failed to render post-message")?;

        let mut mimefactory_pre_msg = mimefactory;
        mimefactory_pre_msg.set_as_pre_message_for(&rendered_msg);
        let rendered_pre_msg = mimefactory_pre_msg
            .render(context)
            .await
            .context("pre-message failed to render")?;

        if rendered_pre_msg.message.len() > PRE_MSG_SIZE_WARNING_THRESHOLD {
            warn!(
                context,
                "Pre-message for message {} is larger than expected: {}.",
                msg.id,
                rendered_pre_msg.message.len()
            );
        }

        Ok((Some(rendered_pre_msg), rendered_msg))
    } else {
        Ok((None, mimefactory.render(context).await?))
    }
}

/// Constructs jobs for sending a message and inserts them into the `smtp` table.
///
/// Updates the message `GuaranteeE2ee` parameter and persists it
/// in the database depending on whether the message
/// is added to the outgoing queue as encrypted or not.
///
/// Returns row ids if `smtp` table jobs were created or an empty `Vec` otherwise.
///
/// The caller has to interrupt SMTP loop or otherwise process new rows.
pub(crate) async fn create_send_msg_jobs(context: &Context, msg: &mut Message) -> Result<Vec<i64>> {
    let cmd = msg.param.get_cmd();
    if cmd == SystemMessage::GroupNameChanged || cmd == SystemMessage::GroupDescriptionChanged {
        msg.chat_id
            .update_timestamp(
                context,
                if cmd == SystemMessage::GroupNameChanged {
                    Param::GroupNameTimestamp
                } else {
                    Param::GroupDescriptionTimestamp
                },
                msg.timestamp_sort,
            )
            .await?;
    }

    let needs_encryption = msg.param.get_bool(Param::GuaranteeE2ee).unwrap_or_default();
    let mimefactory = match MimeFactory::from_msg(context, msg.clone()).await {
        Ok(mf) => mf,
        Err(err) => {
            // Mark message as failed
            message::set_msg_failed(context, msg, &err.to_string())
                .await
                .ok();
            return Err(err);
        }
    };
    let attach_selfavatar = mimefactory.attach_selfavatar;
    let mut recipients = mimefactory.recipients();

    let from = context.get_primary_self_addr().await?;
    let lowercase_from = from.to_lowercase();

    recipients.retain(|x| x.to_lowercase() != lowercase_from);
    if context.get_config_bool(Config::BccSelf).await?
        || msg.param.get_cmd() == SystemMessage::AutocryptSetupMessage
    {
        smtp::add_self_recipients(context, &mut recipients, needs_encryption).await?;
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

    let (rendered_pre_msg, rendered_msg) =
        match render_mime_message_and_pre_message(context, msg, mimefactory).await {
            Ok(res) => Ok(res),
            Err(err) => {
                message::set_msg_failed(context, msg, &err.to_string()).await?;
                Err(err)
            }
        }?;

    if let (post_msg, Some(pre_msg)) = (&rendered_msg, &rendered_pre_msg) {
        info!(
            context,
            "Message {} sizes: pre-message: {}; post-message: {}.",
            msg.id,
            format_size(pre_msg.message.len(), BINARY),
            format_size(post_msg.message.len(), BINARY),
        );
        msg.pre_rfc724_mid = pre_msg.rfc724_mid.clone();
    } else {
        info!(
            context,
            "Message {} will be sent in one shot (no pre- and post-message). Size: {}.",
            msg.id,
            format_size(rendered_msg.message.len(), BINARY),
        );
    }

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

    if rendered_msg.last_added_location_id.is_some()
        && let Err(err) = location::set_kml_sent_timestamp(context, msg.chat_id, now).await
    {
        error!(context, "Failed to set kml sent_timestamp: {err:#}.");
    }

    if attach_selfavatar && let Err(err) = msg.chat_id.set_selfavatar_timestamp(context, now).await
    {
        error!(context, "Failed to set selfavatar timestamp: {err:#}.");
    }

    if rendered_msg.is_encrypted {
        msg.param.set_int(Param::GuaranteeE2ee, 1);
    } else {
        msg.param.remove(Param::GuaranteeE2ee);
    }
    msg.subject.clone_from(&rendered_msg.subject);
    context
        .sql
        .execute(
            "UPDATE msgs SET pre_rfc724_mid=?, subject=?, param=? WHERE id=?",
            (
                &msg.pre_rfc724_mid,
                &msg.subject,
                msg.param.to_string(),
                msg.id,
            ),
        )
        .await?;

    let chunk_size = context.get_max_smtp_rcpt_to().await?;
    let trans_fn = |t: &mut rusqlite::Transaction| {
        let mut row_ids = Vec::<i64>::new();

        if let Some(sync_ids) = rendered_msg.sync_ids_to_delete {
            t.execute(
                &format!("DELETE FROM multi_device_sync WHERE id IN ({sync_ids})"),
                (),
            )?;
        }
        let mut stmt = t.prepare(
            "INSERT INTO smtp (rfc724_mid, recipients, mime, msg_id)
            VALUES            (?1,         ?2,         ?3,   ?4)",
        )?;
        for recipients_chunk in recipients.chunks(chunk_size) {
            let recipients_chunk = recipients_chunk.join(" ");
            if let Some(pre_msg) = &rendered_pre_msg {
                let row_id = stmt.execute((
                    &pre_msg.rfc724_mid,
                    &recipients_chunk,
                    &pre_msg.message,
                    msg.id,
                ))?;
                row_ids.push(row_id.try_into()?);
            }
            let row_id = stmt.execute((
                &rendered_msg.rfc724_mid,
                &recipients_chunk,
                &rendered_msg.message,
                msg.id,
            ))?;
            row_ids.push(row_id.try_into()?);
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
        "bad chat_id, can not be a special chat: {chat_id}"
    );

    let mut msg = Message::new_text(text_to_send);
    send_msg(context, chat_id, &mut msg).await
}

/// Sends chat members a request to edit the given message's text.
#[expect(clippy::arithmetic_side_effects)]
pub async fn send_edit_request(context: &Context, msg_id: MsgId, new_text: String) -> Result<()> {
    let mut original_msg = Message::load_from_db(context, msg_id).await?;
    ensure!(
        original_msg.from_id == ContactId::SELF,
        "Can edit only own messages"
    );
    ensure!(!original_msg.is_info(), "Cannot edit info messages");
    ensure!(!original_msg.has_html(), "Cannot edit HTML messages");
    ensure!(original_msg.viewtype != Viewtype::Call, "Cannot edit calls");
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
                normalize_text(new_text),
                original_msg.param.to_string(),
                original_msg.id,
            ),
        )
        .await?;
    context.emit_msgs_changed(original_msg.chat_id, original_msg.id);
    Ok(())
}

async fn donation_request_maybe(context: &Context) -> Result<()> {
    let secs_between_checks = 30 * 24 * 60 * 60;
    let now = time();
    let ts = context
        .get_config_i64(Config::DonationRequestNextCheck)
        .await?;
    if ts > now {
        return Ok(());
    }
    let msg_cnt = context.sql.count(
        "SELECT COUNT(*) FROM msgs WHERE state>=? AND hidden=0",
        (MessageState::OutDelivered,),
    );
    let ts = if ts == 0 || msg_cnt.await? < 100 {
        now.saturating_add(secs_between_checks)
    } else {
        let mut msg = Message::new_text(stock_str::donation_request(context).await);
        add_device_msg(context, None, Some(&mut msg)).await?;
        i64::MAX
    };
    context
        .set_config_internal(Config::DonationRequestNextCheck, Some(&ts.to_string()))
        .await
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
#[expect(clippy::arithmetic_side_effects)]
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
    let process_rows = |rows: rusqlite::AndThenRows<_>| {
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
                let secs_in_day = 86400;
                let curr_day = curr_local_timestamp / secs_in_day;
                if curr_day != last_day {
                    ret.push(ChatItem::DayMarker {
                        timestamp: curr_day * secs_in_day - cnv_to_local,
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
                    m.param GLOB '*\nS=*' OR param GLOB 'S=*'
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

/// Marks all unread messages in all chats as noticed.
/// Ignores messages from blocked contacts, but does not ignore messages in muted chats.
pub async fn marknoticed_all_chats(context: &Context) -> Result<()> {
    // The sql statement here is similar to the one in get_fresh_msgs
    let list = context
        .sql
        .query_map_vec(
            "SELECT DISTINCT(c.id)
                 FROM msgs m
                 INNER JOIN chats c
                        ON m.chat_id=c.id
                 WHERE m.state=?
                   AND m.hidden=0
                   AND m.chat_id>9
                   AND c.blocked=0;",
            (MessageState::InFresh,),
            |row| {
                let msg_id: ChatId = row.get(0)?;
                Ok(msg_id)
            },
        )
        .await?;

    for chat_id in list {
        marknoticed_chat(context, chat_id).await?;
    }

    Ok(())
}

/// Marks all messages in the chat as noticed.
/// If the given chat-id is the archive-link, marks all messages in all archived chats as noticed.
pub async fn marknoticed_chat(context: &Context, chat_id: ChatId) -> Result<()> {
    // "WHERE" below uses the index `(state, hidden, chat_id)`, see get_fresh_msg_cnt() for reasoning
    // the additional SELECT statement may speed up things as no write-blocking is needed.
    if chat_id.is_archived_link() {
        let chat_ids_in_archive = context
            .sql
            .query_map_vec(
                "SELECT DISTINCT(m.chat_id) FROM msgs m
                    LEFT JOIN chats c ON m.chat_id=c.id
                    WHERE m.state=10 AND m.hidden=0 AND m.chat_id>9 AND c.archived=1",
                (),
                |row| {
                    let chat_id: ChatId = row.get(0)?;
                    Ok(chat_id)
                },
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
            .query_map_vec(
                "SELECT id FROM msgs
                    WHERE state=?
                      AND hidden=1
                      AND chat_id=?
                    ORDER BY id LIMIT 100", // LIMIT to 100 in order to avoid blocking the UI too long, usually there will be less than 100 messages anyway
                (MessageState::InFresh, chat_id), // No need to check for InNoticed messages, because reactions are never InNoticed
                |row| {
                    let msg_id: MsgId = row.get(0)?;
                    Ok(msg_id)
                },
            )
            .await?;
        message::markseen_msgs(context, hidden_messages).await?;
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
    if context.get_config_bool(Config::TeamProfile).await? {
        return Ok(());
    }

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
            .query_map_vec(
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
                |row| {
                    let msg_id: MsgId = row.get(0)?;
                    Ok(msg_id)
                },
            )
            .await?
    } else {
        context
            .sql
            .query_map_vec(
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
                |row| {
                    let msg_id: MsgId = row.get(0)?;
                    Ok(msg_id)
                },
            )
            .await?
    };
    Ok(list)
}

/// Returns a vector of contact IDs for given chat ID.
pub async fn get_chat_contacts(context: &Context, chat_id: ChatId) -> Result<Vec<ContactId>> {
    // Normal chats do not include SELF.  Group chats do (as it may happen that one is deleted from a
    // groupchat but the chats stays visible, moreover, this makes displaying lists easier)
    context
        .sql
        .query_map_vec(
            "SELECT cc.contact_id
               FROM chats_contacts cc
               LEFT JOIN contacts c
                      ON c.id=cc.contact_id
              WHERE cc.chat_id=? AND cc.add_timestamp >= cc.remove_timestamp
              ORDER BY c.id=1, c.last_seen DESC, c.id DESC;",
            (chat_id,),
            |row| {
                let contact_id: ContactId = row.get(0)?;
                Ok(contact_id)
            },
        )
        .await
}

/// Returns a vector of contact IDs for given chat ID that are no longer part of the group.
///
/// Members that have been removed recently are in the beginning of the list.
pub async fn get_past_chat_contacts(context: &Context, chat_id: ChatId) -> Result<Vec<ContactId>> {
    let now = time();
    context
        .sql
        .query_map_vec(
            "SELECT cc.contact_id
             FROM chats_contacts cc
             LEFT JOIN contacts c
                  ON c.id=cc.contact_id
             WHERE cc.chat_id=?
             AND cc.add_timestamp < cc.remove_timestamp
             AND ? < cc.remove_timestamp
             ORDER BY c.id=1, cc.remove_timestamp DESC, c.id DESC",
            (chat_id, now.saturating_sub(60 * 24 * 3600)),
            |row| {
                let contact_id: ContactId = row.get(0)?;
                Ok(contact_id)
            },
        )
        .await
}

/// Creates an encrypted group chat.
pub async fn create_group(context: &Context, name: &str) -> Result<ChatId> {
    create_group_ex(context, Sync, create_id(), name).await
}

/// Creates an unencrypted group chat.
pub async fn create_group_unencrypted(context: &Context, name: &str) -> Result<ChatId> {
    create_group_ex(context, Sync, String::new(), name).await
}

/// Creates a group chat.
///
/// * `sync` - Whether a multi-device synchronization message should be sent. Ignored for
///   unencrypted chats currently.
/// * `grpid` - Group ID. Iff nonempty, the chat is encrypted (with key-contacts).
/// * `name` - Chat name.
pub(crate) async fn create_group_ex(
    context: &Context,
    sync: sync::Sync,
    grpid: String,
    name: &str,
) -> Result<ChatId> {
    let mut chat_name = sanitize_single_line(name);
    if chat_name.is_empty() {
        // We can't just fail because the user would lose the work already done in the UI like
        // selecting members.
        error!(context, "Invalid chat name: {name}.");
        chat_name = "…".to_string();
    }

    let timestamp = create_smeared_timestamp(context);
    let row_id = context
        .sql
        .insert(
            "INSERT INTO chats
        (type, name, name_normalized, grpid, param, created_timestamp)
        VALUES(?, ?, ?, ?, \'U=1\', ?)",
            (
                Chattype::Group,
                &chat_name,
                normalize_text(&chat_name),
                &grpid,
                timestamp,
            ),
        )
        .await?;

    let chat_id = ChatId::new(u32::try_from(row_id)?);
    add_to_chat_contacts_table(context, timestamp, chat_id, &[ContactId::SELF]).await?;

    context.emit_msgs_changed_without_ids();
    chatlist_events::emit_chatlist_changed(context);
    chatlist_events::emit_chatlist_item_changed(context, chat_id);

    if !grpid.is_empty() {
        // Add "Messages are end-to-end encrypted." message.
        chat_id.add_e2ee_notice(context, timestamp).await?;
    }

    if !context.get_config_bool(Config::Bot).await?
        && !context.get_config_bool(Config::SkipStartMessages).await?
    {
        let text = if !grpid.is_empty() {
            // Add "Others will only see this group after you sent a first message." message.
            stock_str::new_group_send_first_message(context).await
        } else {
            // Add "Messages in this chat use classic email and are not encrypted." message.
            stock_str::chat_unencrypted_explanation(context).await
        };
        add_info_msg(context, chat_id, &text).await?;
    }
    if let (true, true) = (sync.into(), !grpid.is_empty()) {
        let id = SyncId::Grpid(grpid);
        let action = SyncAction::CreateGroupEncrypted(chat_name);
        self::sync(context, id, action).await.log_err(context).ok();
    }
    Ok(chat_id)
}

/// Create a new, outgoing **broadcast channel**
/// (called "Channel" in the UI).
///
/// Broadcast channels are similar to groups on the sending device,
/// however, recipients get the messages in a read-only chat
/// and will not see who the other members are.
///
/// Called `broadcast` here rather than `channel`,
/// because the word "channel" already appears a lot in the code,
/// which would make it hard to grep for it.
///
/// After creation, the chat contains no recipients and is in _unpromoted_ state;
/// see [`create_group`] for more information on the unpromoted state.
///
/// Returns the created chat's id.
pub async fn create_broadcast(context: &Context, chat_name: String) -> Result<ChatId> {
    let grpid = create_id();
    let secret = create_broadcast_secret();
    create_out_broadcast_ex(context, Sync, grpid, chat_name, secret).await
}

const SQL_INSERT_BROADCAST_SECRET: &str =
    "INSERT INTO broadcast_secrets (chat_id, secret) VALUES (?, ?)
    ON CONFLICT(chat_id) DO UPDATE SET secret=excluded.secret";

pub(crate) async fn create_out_broadcast_ex(
    context: &Context,
    sync: sync::Sync,
    grpid: String,
    chat_name: String,
    secret: String,
) -> Result<ChatId> {
    let chat_name = sanitize_single_line(&chat_name);
    if chat_name.is_empty() {
        bail!("Invalid broadcast channel name: {chat_name}.");
    }

    let timestamp = create_smeared_timestamp(context);
    let trans_fn = |t: &mut rusqlite::Transaction| -> Result<ChatId> {
        let cnt: u32 = t.query_row(
            "SELECT COUNT(*) FROM chats WHERE grpid=?",
            (&grpid,),
            |row| row.get(0),
        )?;
        ensure!(cnt == 0, "{cnt} chats exist with grpid {grpid}");

        t.execute(
            "INSERT INTO chats
            (type, name, name_normalized, grpid, created_timestamp)
            VALUES(?, ?, ?, ?, ?)",
            (
                Chattype::OutBroadcast,
                &chat_name,
                normalize_text(&chat_name),
                &grpid,
                timestamp,
            ),
        )?;
        let chat_id = ChatId::new(t.last_insert_rowid().try_into()?);

        t.execute(SQL_INSERT_BROADCAST_SECRET, (chat_id, &secret))?;
        Ok(chat_id)
    };
    let chat_id = context.sql.transaction(trans_fn).await?;
    chat_id.add_e2ee_notice(context, timestamp).await?;

    context.emit_msgs_changed_without_ids();
    chatlist_events::emit_chatlist_changed(context);
    chatlist_events::emit_chatlist_item_changed(context, chat_id);

    if sync.into() {
        let id = SyncId::Grpid(grpid);
        let action = SyncAction::CreateOutBroadcast { chat_name, secret };
        self::sync(context, id, action).await.log_err(context).ok();
    }

    Ok(chat_id)
}

pub(crate) async fn load_broadcast_secret(
    context: &Context,
    chat_id: ChatId,
) -> Result<Option<String>> {
    context
        .sql
        .query_get_value(
            "SELECT secret FROM broadcast_secrets WHERE chat_id=?",
            (chat_id,),
        )
        .await
}

pub(crate) async fn save_broadcast_secret(
    context: &Context,
    chat_id: ChatId,
    secret: &str,
) -> Result<()> {
    info!(context, "Saving broadcast secret for chat {chat_id}");
    context
        .sql
        .execute(SQL_INSERT_BROADCAST_SECRET, (chat_id, secret))
        .await?;

    Ok(())
}

pub(crate) async fn delete_broadcast_secret(context: &Context, chat_id: ChatId) -> Result<()> {
    info!(context, "Removing broadcast secret for chat {chat_id}");
    context
        .sql
        .execute("DELETE FROM broadcast_secrets WHERE chat_id=?", (chat_id,))
        .await?;

    Ok(())
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

/// Removes a contact from the chat
/// without leaving a trace.
///
/// Note that if we call this function,
/// and then receive a message from another device
/// that doesn't know that this this member was removed
/// then the group membership algorithm will wrongly re-add this member.
pub(crate) async fn remove_from_chat_contacts_table_without_trace(
    context: &Context,
    chat_id: ChatId,
    contact_id: ContactId,
) -> Result<()> {
    context
        .sql
        .execute(
            "DELETE FROM chats_contacts
            WHERE chat_id=? AND contact_id=?",
            (chat_id, contact_id),
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
        chat.typ == Chattype::Group || (from_handshake && chat.typ == Chattype::OutBroadcast),
        "{chat_id} is not a group where one can add members",
    );
    ensure!(
        Contact::real_exists_by_id(context, contact_id).await? || contact_id == ContactId::SELF,
        "invalid contact_id {contact_id} for adding to group"
    );
    ensure!(
        chat.typ != Chattype::OutBroadcast || contact_id != ContactId::SELF,
        "Cannot add SELF to broadcast channel."
    );
    match chat.is_encrypted(context).await? {
        true => ensure!(
            contact.is_key_contact(),
            "Only key-contacts can be added to encrypted chats"
        ),
        false => ensure!(
            !contact.is_key_contact(),
            "Only address-contacts can be added to unencrypted chats"
        ),
    }

    if !chat.is_self_in_chat(context).await? {
        context.emit_event(EventType::ErrorSelfNotInGroup(
            "Cannot add contact to group; self not in group.".into(),
        ));
        warn!(
            context,
            "Can not add contact because the account is not part of the group/broadcast."
        );
        return Ok(false);
    }

    let sync_qr_code_tokens;
    if from_handshake && chat.param.get_int(Param::Unpromoted).unwrap_or_default() == 1 {
        let smeared_time = smeared_time(context);
        chat.param
            .remove(Param::Unpromoted)
            .set_i64(Param::GroupNameTimestamp, smeared_time)
            .set_i64(Param::GroupDescriptionTimestamp, smeared_time);
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
        add_to_chat_contacts_table(context, time(), chat_id, &[contact_id]).await?;
    }
    if chat.is_promoted() {
        msg.viewtype = Viewtype::Text;

        let contact_addr = contact.get_addr().to_lowercase();
        let added_by = if from_handshake && chat.typ == Chattype::OutBroadcast {
            // The contact was added via a QR code rather than explicit user action,
            // so it could be confusing to say 'You added member Alice'.
            // And in a broadcast, SELF is the only one who can add members,
            // so, no information is lost by just writing 'Member Alice added' instead.
            ContactId::UNDEFINED
        } else {
            ContactId::SELF
        };
        msg.text = stock_str::msg_add_member_local(context, contact.id, added_by).await;
        msg.param.set_cmd(SystemMessage::MemberAddedToGroup);
        msg.param.set(Param::Arg, contact_addr);
        msg.param.set_int(Param::Arg2, from_handshake.into());
        let fingerprint = contact.fingerprint().map(|f| f.hex());
        msg.param.set_optional(Param::Arg4, fingerprint);
        msg.param
            .set_int(Param::ContactAddedRemoved, contact.id.to_u32() as i32);
        if chat.typ == Chattype::OutBroadcast {
            let secret = load_broadcast_secret(context, chat_id)
                .await?
                .context("Failed to find broadcast shared secret")?;
            msg.param.set(PARAM_BROADCAST_SECRET, secret);
        }
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
            context.scheduler.interrupt_smtp().await;
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
#[expect(clippy::arithmetic_side_effects)]
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
            |row| {
                let selfavatar_sent: i64 = row.get(0)?;
                Ok(selfavatar_sent)
            },
            |rows| {
                let mut needs_attach = false;
                for row in rows {
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
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
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
        "bad chat_id, can not be special chat: {chat_id}"
    );
    ensure!(
        !contact_id.is_special() || contact_id == ContactId::SELF,
        "Cannot remove special contact"
    );

    let chat = Chat::load_from_db(context, chat_id).await?;
    if chat.typ == Chattype::InBroadcast {
        ensure!(
            contact_id == ContactId::SELF,
            "Cannot remove other member from incoming broadcast channel"
        );
        delete_broadcast_secret(context, chat_id).await?;
    }

    if matches!(
        chat.typ,
        Chattype::Group | Chattype::OutBroadcast | Chattype::InBroadcast
    ) {
        if !chat.is_self_in_chat(context).await? {
            let err_msg = format!(
                "Cannot remove contact {contact_id} from chat {chat_id}: self not in group."
            );
            context.emit_event(EventType::ErrorSelfNotInGroup(err_msg.clone()));
            bail!("{err_msg}");
        } else {
            let mut sync = Nosync;

            if chat.is_promoted() && chat.typ != Chattype::OutBroadcast {
                remove_from_chat_contacts_table(context, chat_id, contact_id).await?;
            } else {
                remove_from_chat_contacts_table_without_trace(context, chat_id, contact_id).await?;
            }

            // We do not return an error if the contact does not exist in the database.
            // This allows to delete dangling references to deleted contacts
            // in case of the database becoming inconsistent due to a bug.
            if let Some(contact) = Contact::get_by_id_optional(context, contact_id).await? {
                if chat.is_promoted() {
                    let addr = contact.get_addr();
                    let fingerprint = contact.fingerprint().map(|f| f.hex());

                    let res = send_member_removal_msg(
                        context,
                        &chat,
                        contact_id,
                        addr,
                        fingerprint.as_deref(),
                    )
                    .await;

                    if contact_id == ContactId::SELF {
                        res?;
                    } else if let Err(e) = res {
                        warn!(
                            context,
                            "remove_contact_from_chat({chat_id}, {contact_id}): send_msg() failed: {e:#}."
                        );
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

async fn send_member_removal_msg(
    context: &Context,
    chat: &Chat,
    contact_id: ContactId,
    addr: &str,
    fingerprint: Option<&str>,
) -> Result<MsgId> {
    let mut msg = Message::new(Viewtype::Text);

    if contact_id == ContactId::SELF {
        if chat.typ == Chattype::InBroadcast {
            msg.text = stock_str::msg_you_left_broadcast(context).await;
        } else {
            msg.text = stock_str::msg_group_left_local(context, ContactId::SELF).await;
        }
    } else {
        msg.text = stock_str::msg_del_member_local(context, contact_id, ContactId::SELF).await;
    }

    msg.param.set_cmd(SystemMessage::MemberRemovedFromGroup);
    msg.param.set(Param::Arg, addr.to_lowercase());
    msg.param.set_optional(Param::Arg4, fingerprint);
    msg.param
        .set(Param::ContactAddedRemoved, contact_id.to_u32());

    send_msg(context, chat.id, &mut msg).await
}

/// Set group or broadcast channel description.
///
/// If the group is already _promoted_ (any message was sent to the group),
/// or if this is a brodacast channel,
/// all members are informed by a special status message that is sent automatically by this function.
///
/// Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
///
/// See also [`get_chat_description`]
pub async fn set_chat_description(
    context: &Context,
    chat_id: ChatId,
    new_description: &str,
) -> Result<()> {
    set_chat_description_ex(context, Sync, chat_id, new_description).await
}

async fn set_chat_description_ex(
    context: &Context,
    mut sync: sync::Sync,
    chat_id: ChatId,
    new_description: &str,
) -> Result<()> {
    let new_description = sanitize_bidi_characters(new_description.trim());

    ensure!(!chat_id.is_special(), "Invalid chat ID");

    let chat = Chat::load_from_db(context, chat_id).await?;
    ensure!(
        chat.typ == Chattype::Group || chat.typ == Chattype::OutBroadcast,
        "Can only set description for groups / broadcasts"
    );
    ensure!(
        !chat.grpid.is_empty(),
        "Cannot set description for ad hoc groups"
    );
    if !chat.is_self_in_chat(context).await? {
        context.emit_event(EventType::ErrorSelfNotInGroup(
            "Cannot set chat description; self not in group".into(),
        ));
        bail!("Cannot set chat description; self not in group");
    }

    let affected_rows = context
        .sql
        .execute(
            "INSERT INTO chats_descriptions(chat_id, description) VALUES(?, ?)
            ON CONFLICT(chat_id) DO UPDATE
            SET description=excluded.description WHERE description<>excluded.description",
            (chat_id, &new_description),
        )
        .await?;

    if affected_rows == 0 {
        return Ok(());
    }

    if chat.is_promoted() {
        let mut msg = Message::new(Viewtype::Text);
        msg.text = stock_str::msg_chat_description_changed(context, ContactId::SELF).await;
        msg.param.set_cmd(SystemMessage::GroupDescriptionChanged);

        msg.id = send_msg(context, chat_id, &mut msg).await?;
        context.emit_msgs_changed(chat_id, msg.id);
        sync = Nosync;
    }
    context.emit_event(EventType::ChatModified(chat_id));

    if sync.into() {
        chat.sync(context, SyncAction::SetDescription(new_description))
            .await
            .log_err(context)
            .ok();
    }

    Ok(())
}

/// Load the chat description from the database.
///
/// UIs show this in the profile page of the chat,
/// it is settable by [`set_chat_description`]
pub async fn get_chat_description(context: &Context, chat_id: ChatId) -> Result<String> {
    let description = context
        .sql
        .query_get_value(
            "SELECT description FROM chats_descriptions WHERE chat_id=?",
            (chat_id,),
        )
        .await?
        .unwrap_or_default();
    Ok(description)
}

/// Sets group, mailing list, or broadcast channel chat name.
///
/// If the group is already _promoted_ (any message was sent to the group),
/// or if this is a brodacast channel,
/// all members are informed by a special status message that is sent automatically by this function.
///
/// Sends out #DC_EVENT_CHAT_MODIFIED and #DC_EVENT_MSGS_CHANGED if a status message was sent.
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
        || chat.typ == Chattype::OutBroadcast
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
                    "UPDATE chats SET name=?, name_normalized=? WHERE id=?",
                    (&new_name, normalize_text(&new_name), chat_id),
                )
                .await?;
            if chat.is_promoted()
                && !chat.is_mailing_list()
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
        chat.typ == Chattype::Group || chat.typ == Chattype::OutBroadcast,
        "Can only set profile image for groups / broadcasts"
    );
    ensure!(
        !chat.grpid.is_empty(),
        "Cannot set profile image for ad hoc groups"
    );
    /* we should respect this - whatever we send to the group, it gets discarded anyway! */
    if !chat.is_self_in_chat(context).await? {
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
    if chat.is_promoted() {
        msg.id = send_msg(context, chat_id, &mut msg).await?;
        context.emit_msgs_changed(chat_id, msg.id);
    }
    context.emit_event(EventType::ChatModified(chat_id));
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    Ok(())
}

/// Forwards multiple messages to a chat.
pub async fn forward_msgs(context: &Context, msg_ids: &[MsgId], chat_id: ChatId) -> Result<()> {
    forward_msgs_2ctx(context, msg_ids, context, chat_id).await
}

/// Forwards multiple messages to a chat in another context.
#[expect(clippy::arithmetic_side_effects)]
pub async fn forward_msgs_2ctx(
    ctx_src: &Context,
    msg_ids: &[MsgId],
    ctx_dst: &Context,
    chat_id: ChatId,
) -> Result<()> {
    ensure!(!msg_ids.is_empty(), "empty msgs_ids: nothing to forward");
    ensure!(!chat_id.is_special(), "can not forward to special chat");

    let mut created_msgs: Vec<MsgId> = Vec::new();
    let mut curr_timestamp: i64;

    chat_id
        .unarchive_if_not_muted(ctx_dst, MessageState::Undefined)
        .await?;
    let mut chat = Chat::load_from_db(ctx_dst, chat_id).await?;
    if let Some(reason) = chat.why_cant_send(ctx_dst).await? {
        bail!("cannot send to {chat_id}: {reason}");
    }
    curr_timestamp = create_smeared_timestamps(ctx_dst, msg_ids.len());
    let mut msgs = Vec::with_capacity(msg_ids.len());
    for id in msg_ids {
        let ts: i64 = ctx_src
            .sql
            .query_get_value("SELECT timestamp FROM msgs WHERE id=?", (id,))
            .await?
            .with_context(|| format!("No message {id}"))?;
        msgs.push((ts, *id));
    }
    msgs.sort_unstable();
    for (_, id) in msgs {
        let src_msg_id: MsgId = id;
        let mut msg = Message::load_from_db(ctx_src, src_msg_id).await?;
        if msg.state == MessageState::OutDraft {
            bail!("cannot forward drafts.");
        }

        let mut param = msg.param;
        msg.param = Params::new();

        if msg.get_viewtype() != Viewtype::Sticker {
            let forwarded_msg_id = match ctx_src.blobdir == ctx_dst.blobdir {
                true => src_msg_id,
                false => MsgId::new_unset(),
            };
            msg.param
                .set_int(Param::Forwarded, forwarded_msg_id.to_u32() as i32);
        }

        if msg.get_viewtype() == Viewtype::Call {
            msg.viewtype = Viewtype::Text;
        }
        msg.text += &msg.additional_text;

        let param = &mut param;

        // When forwarding between different accounts, blob files must be physically copied
        // because each account has its own blob directory.
        if ctx_src.blobdir == ctx_dst.blobdir {
            msg.param.steal(param, Param::File);
        } else if let Some(src_path) = param.get_file_path(ctx_src)? {
            let new_blob = BlobObject::create_and_deduplicate(ctx_dst, &src_path, &src_path)
                .context("Failed to copy blob file to destination account")?;
            msg.param.set(Param::File, new_blob.as_name());
        }
        msg.param.steal(param, Param::Filename);
        msg.param.steal(param, Param::Width);
        msg.param.steal(param, Param::Height);
        msg.param.steal(param, Param::Duration);
        msg.param.steal(param, Param::MimeType);
        msg.param.steal(param, Param::ProtectQuote);
        msg.param.steal(param, Param::Quote);
        msg.param.steal(param, Param::Summary1);
        if msg.has_html() {
            msg.set_html(src_msg_id.get_html(ctx_src).await?);
        }
        msg.in_reply_to = None;

        // do not leak data as group names; a default subject is generated by mimefactory
        msg.subject = "".to_string();

        msg.state = MessageState::OutPending;
        msg.rfc724_mid = create_outgoing_rfc724_mid();
        msg.timestamp_sort = curr_timestamp;
        chat.prepare_msg_raw(ctx_dst, &mut msg, None).await?;

        curr_timestamp += 1;
        if !create_send_msg_jobs(ctx_dst, &mut msg).await?.is_empty() {
            ctx_dst.scheduler.interrupt_smtp().await;
        }
        created_msgs.push(msg.id);
    }
    for msg_id in created_msgs {
        ctx_dst.emit_msgs_changed(chat_id, msg_id);
    }
    Ok(())
}

/// Save a copy of the message in "Saved Messages"
/// and send a sync messages so that other devices save the message as well, unless deleted there.
pub async fn save_msgs(context: &Context, msg_ids: &[MsgId]) -> Result<()> {
    let mut msgs = Vec::with_capacity(msg_ids.len());
    for id in msg_ids {
        let ts: i64 = context
            .sql
            .query_get_value("SELECT timestamp FROM msgs WHERE id=?", (id,))
            .await?
            .with_context(|| format!("No message {id}"))?;
        msgs.push((ts, *id));
    }
    msgs.sort_unstable();
    for (_, src_msg_id) in msgs {
        let dest_rfc724_mid = create_outgoing_rfc724_mid();
        let src_rfc724_mid = save_copy_in_self_talk(context, src_msg_id, &dest_rfc724_mid).await?;
        context
            .add_sync_item(SyncData::SaveMessage {
                src: src_rfc724_mid,
                dest: dest_rfc724_mid,
            })
            .await?;
    }
    context.scheduler.interrupt_smtp().await;
    Ok(())
}

/// Saves a copy of the given message in "Saved Messages" using the given RFC724 id.
/// To allow UIs to have a "show in context" button,
/// the copy contains a reference to the original message
/// as well as to the original chat in case the original message gets deleted.
/// Returns data needed to add a `SaveMessage` sync item.
#[expect(clippy::arithmetic_side_effects)]
pub(crate) async fn save_copy_in_self_talk(
    context: &Context,
    src_msg_id: MsgId,
    dest_rfc724_mid: &String,
) -> Result<String> {
    let dest_chat_id = ChatId::create_for_contact(context, ContactId::SELF).await?;
    let mut msg = Message::load_from_db(context, src_msg_id).await?;
    msg.param.remove(Param::Cmd);
    msg.param.remove(Param::WebxdcDocument);
    msg.param.remove(Param::WebxdcDocumentTimestamp);
    msg.param.remove(Param::WebxdcSummary);
    msg.param.remove(Param::WebxdcSummaryTimestamp);
    msg.param.remove(Param::PostMessageFileBytes);
    msg.param.remove(Param::PostMessageViewtype);

    msg.text += &msg.additional_text;

    if !msg.original_msg_id.is_unset() {
        bail!("message already saved.");
    }

    let copy_fields = "from_id, to_id, timestamp_rcvd, type,
                       mime_modified, mime_headers, mime_compressed, mime_in_reply_to, subject, msgrmsg";
    let row_id = context
        .sql
        .insert(
            &format!(
                "INSERT INTO msgs ({copy_fields},
                                   timestamp_sent,
                                   txt, chat_id, rfc724_mid, state, timestamp, param, starred)
                 SELECT            {copy_fields},
                                   -- Outgoing messages on originating device
                                   -- have timestamp_sent == 0.
                                   -- We copy sort timestamp instead
                                   -- so UIs display the same timestamp
                                   -- for saved and original message.
                                   IIF(timestamp_sent == 0, timestamp, timestamp_sent),
                                   ?, ?, ?, ?, ?, ?, ?
                 FROM msgs WHERE id=?;"
            ),
            (
                msg.text,
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

    context.emit_msgs_changed(msg.chat_id, src_msg_id);
    context.emit_msgs_changed(dest_chat_id, dest_msg_id);
    chatlist_events::emit_chatlist_changed(context);
    chatlist_events::emit_chatlist_item_changed(context, dest_chat_id);

    Ok(msg.rfc724_mid)
}

/// Resends given messages with the same Message-ID.
///
/// This is primarily intended to make existing webxdcs available to new chat members.
pub async fn resend_msgs(context: &Context, msg_ids: &[MsgId]) -> Result<()> {
    let mut msgs: Vec<Message> = Vec::new();
    for msg_id in msg_ids {
        let msg = Message::load_from_db(context, *msg_id).await?;
        ensure!(
            msg.from_id == ContactId::SELF,
            "can resend only own messages"
        );
        ensure!(!msg.is_info(), "cannot resend info messages");
        msgs.push(msg)
    }

    for mut msg in msgs {
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
        msg.timestamp_sort = create_smeared_timestamp(context);
        if create_send_msg_jobs(context, &mut msg).await?.is_empty() {
            continue;
        }

        // Emit the event only after `create_send_msg_jobs`
        // because `create_send_msg_jobs` may change the message
        // encryption status and call `msg.update_param`.
        context.emit_event(EventType::MsgsChanged {
            chat_id: msg.chat_id,
            msg_id: msg.id,
        });
        // note(treefit): only matters if it is the last message in chat (but probably to expensive to check, debounce also solves it)
        chatlist_events::emit_chatlist_item_changed(context, msg.chat_id);

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

/// Returns a tuple of `(chatid, blocked)`.
pub(crate) async fn get_chat_id_by_grpid(
    context: &Context,
    grpid: &str,
) -> Result<Option<(ChatId, Blocked)>> {
    context
        .sql
        .query_row_optional(
            "SELECT id, blocked FROM chats WHERE grpid=?;",
            (grpid,),
            |row| {
                let chat_id = row.get::<_, ChatId>(0)?;

                let b = row.get::<_, Option<Blocked>>(1)?.unwrap_or_default();
                Ok((chat_id, b))
            },
        )
        .await
}

/// Adds a message to device chat.
///
/// Optional `label` can be provided to ensure that message is added only once.
/// If `important` is true, a notification will be sent.
#[expect(clippy::arithmetic_side_effects)]
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

    if let Some(label) = label
        && was_device_msg_ever_added(context, label).await?
    {
        info!(context, "Device-message {label} already added.");
        return Ok(msg_id);
    }

    if let Some(msg) = msg {
        chat_id = ChatId::get_for_contact(context, ContactId::DEVICE).await?;

        let rfc724_mid = create_outgoing_rfc724_mid();
        let timestamp_sent = create_smeared_timestamp(context);

        // makes sure, the added message is the last one,
        // even if the date is wrong (useful esp. when warning about bad dates)
        msg.timestamp_sort = timestamp_sent;
        if let Some(last_msg_time) = chat_id.get_timestamp(context).await?
            && msg.timestamp_sort <= last_msg_time
        {
            msg.timestamp_sort = last_msg_time + 1;
        }
        prepare_msg_blob(context, msg).await?;
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
                    msg.timestamp_sort,
                    timestamp_sent,
                    timestamp_sent, // timestamp_sent equals timestamp_rcvd
                    msg.viewtype,
                    state,
                    &msg.text,
                    normalize_text(&msg.text),
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
    // Timestamp where in the chat the message will be sorted.
    // If this is None, the message will be sorted to the bottom.
    timestamp_sort: Option<i64>,
    // Timestamp to show to the user
    timestamp_sent_rcvd: i64,
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

    let timestamp_sort = if let Some(ts) = timestamp_sort {
        ts
    } else {
        let sort_to_bottom = true;
        let (received, incoming) = (false, false);
        chat_id
            .calc_sort_timestamp(
                context,
                smeared_time(context),
                sort_to_bottom,
                received,
                incoming,
            )
            .await?
    };

    let row_id =
    context.sql.insert(
        "INSERT INTO msgs (chat_id,from_id,to_id,timestamp,timestamp_sent,timestamp_rcvd,type,state,txt,txt_normalized,rfc724_mid,ephemeral_timer,param,mime_in_reply_to)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
        (
            chat_id,
            from_id.unwrap_or(ContactId::INFO),
            ContactId::INFO,
            timestamp_sort,
            timestamp_sent_rcvd,
            timestamp_sent_rcvd,
            Viewtype::Text,
            MessageState::InNoticed,
            text,
            normalize_text(text),
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
pub(crate) async fn add_info_msg(context: &Context, chat_id: ChatId, text: &str) -> Result<MsgId> {
    add_info_msg_with_cmd(
        context,
        chat_id,
        text,
        SystemMessage::Unknown,
        None,
        time(),
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
            (text, normalize_text(text), timestamp, msg_id),
        )
        .await?;
    context.emit_msgs_changed(chat_id, msg_id);
    Ok(())
}

/// Set chat contacts by their addresses creating the corresponding contacts if necessary.
async fn set_contacts_by_addrs(context: &Context, id: ChatId, addrs: &[String]) -> Result<()> {
    let chat = Chat::load_from_db(context, id).await?;
    ensure!(
        !chat.is_encrypted(context).await?,
        "Cannot add address-contacts to encrypted chat {id}"
    );
    ensure!(
        chat.typ == Chattype::OutBroadcast,
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
            // because timestamps are not used for broadcast channels.
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

/// Set chat contacts by their fingerprints creating the corresponding contacts if necessary.
///
/// `fingerprint_addrs` is a list of pairs of fingerprint and address.
async fn set_contacts_by_fingerprints(
    context: &Context,
    id: ChatId,
    fingerprint_addrs: &[(String, String)],
) -> Result<()> {
    let chat = Chat::load_from_db(context, id).await?;
    ensure!(
        chat.is_encrypted(context).await?,
        "Cannot add key-contacts to unencrypted chat {id}"
    );
    ensure!(
        matches!(chat.typ, Chattype::Group | Chattype::OutBroadcast),
        "{id} is not a group or broadcast",
    );
    let mut contacts = HashSet::new();
    for (fingerprint, addr) in fingerprint_addrs {
        let contact = Contact::add_or_lookup_ex(context, "", addr, fingerprint, Origin::Hidden)
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
            // For broadcast channels, we only add members,
            // because we don't use the membership consistency algorithm,
            // and are using sync messages as a basic way to ensure consistency between devices.
            // For groups, we also remove members,
            // because the sync message is used in order to sync unpromoted groups.
            if chat.typ != Chattype::OutBroadcast {
                transaction.execute("DELETE FROM chats_contacts WHERE chat_id=?", (id,))?;
            }

            // We do not care about `add_timestamp` column
            // because timestamps are not used for broadcast channels.
            let mut statement = transaction.prepare(
                "INSERT OR IGNORE INTO chats_contacts (chat_id, contact_id) VALUES (?, ?)",
            )?;
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
    /// E-mail address of the contact.
    ContactAddr(String),

    /// OpenPGP key fingerprint of the contact.
    ContactFingerprint(String),

    Grpid(String),
    /// "Message-ID"-s, from oldest to latest. Used for ad-hoc groups.
    Msgids(Vec<String>),

    /// Special id for device chat.
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
    /// Create broadcast channel with the given name.
    CreateOutBroadcast {
        chat_name: String,
        secret: String,
    },
    /// Create encrypted group chat with the given name.
    CreateGroupEncrypted(String),
    Rename(String),
    /// Set chat contacts by their addresses.
    SetContacts(Vec<String>),
    /// Set chat contacts by their fingerprints.
    ///
    /// The list is a list of pairs of fingerprint and address.
    SetPgpContacts(Vec<(String, String)>),
    SetDescription(String),
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
                        return contact::set_blocked(self, Nosync, contact_id, true).await;
                    }
                    SyncAction::Unblock => {
                        return contact::set_blocked(self, Nosync, contact_id, false).await;
                    }
                    _ => (),
                }
                // Use `Request` so that even if the program crashes, the user doesn't have to look
                // into the blocked contacts.
                ChatIdBlocked::get_for_contact(self, contact_id, Blocked::Request)
                    .await?
                    .id
            }
            SyncId::ContactFingerprint(fingerprint) => {
                let name = "";
                let addr = "";
                let (contact_id, _) =
                    Contact::add_or_lookup_ex(self, name, addr, fingerprint, Origin::Hidden)
                        .await?;
                match action {
                    SyncAction::Rename(to) => {
                        contact_id.set_name_ex(self, Nosync, to).await?;
                        self.emit_event(EventType::ContactsChanged(Some(contact_id)));
                        return Ok(());
                    }
                    SyncAction::Block => {
                        return contact::set_blocked(self, Nosync, contact_id, true).await;
                    }
                    SyncAction::Unblock => {
                        return contact::set_blocked(self, Nosync, contact_id, false).await;
                    }
                    _ => (),
                }
                ChatIdBlocked::get_for_contact(self, contact_id, Blocked::Request)
                    .await?
                    .id
            }
            SyncId::Grpid(grpid) => {
                match action {
                    SyncAction::CreateOutBroadcast { chat_name, secret } => {
                        create_out_broadcast_ex(
                            self,
                            Nosync,
                            grpid.to_string(),
                            chat_name.clone(),
                            secret.to_string(),
                        )
                        .await?;
                        return Ok(());
                    }
                    SyncAction::CreateGroupEncrypted(name) => {
                        create_group_ex(self, Nosync, grpid.clone(), name).await?;
                        return Ok(());
                    }
                    _ => {}
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
            SyncAction::CreateOutBroadcast { .. } | SyncAction::CreateGroupEncrypted(..) => {
                // Create action should have been handled above already.
                Err(anyhow!("sync_alter_chat({id:?}, {action:?}): Bad request."))
            }
            SyncAction::Rename(to) => rename_ex(self, Nosync, chat_id, to).await,
            SyncAction::SetDescription(to) => {
                set_chat_description_ex(self, Nosync, chat_id, to).await
            }
            SyncAction::SetContacts(addrs) => set_contacts_by_addrs(self, chat_id, addrs).await,
            SyncAction::SetPgpContacts(fingerprint_addrs) => {
                set_contacts_by_fingerprints(self, chat_id, fingerprint_addrs).await
            }
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
