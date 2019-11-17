//! # Chat module

use std::path::{Path, PathBuf};

use itertools::Itertools;
use num_traits::FromPrimitive;

use crate::blob::{BlobErrorKind, BlobObject};
use crate::chatlist::*;
use crate::config::*;
use crate::constants::*;
use crate::contact::*;
use crate::context::Context;
use crate::dc_mimeparser::SystemMessage;
use crate::dc_tools::*;
use crate::error::Error;
use crate::events::Event;
use crate::job::*;
use crate::message::{self, InvalidMsgId, Message, MessageState, MsgId};
use crate::param::*;
use crate::sql::{self, Sql};
use crate::stock::StockMessage;

/// An object representing a single chat in memory.
/// Chat objects are created using eg. `Chat::load_from_db`
/// and are not updated on database changes;
/// if you want an update, you have to recreate the object.
#[derive(Debug, Clone)]
pub struct Chat {
    pub id: u32,
    pub typ: Chattype,
    pub name: String,
    archived: bool,
    pub grpid: String,
    blocked: Blocked,
    pub param: Params,
    pub gossiped_timestamp: i64,
    is_sending_locations: bool,
}

impl Chat {
    /// Loads chat from the database by its ID.
    pub fn load_from_db(context: &Context, chat_id: u32) -> Result<Self, Error> {
        let res = context.sql.query_row(
            "SELECT c.id,c.type,c.name, c.grpid,c.param,c.archived, \
             c.blocked, c.gossiped_timestamp, c.locations_send_until  \
             FROM chats c WHERE c.id=?;",
            params![chat_id as i32],
            |row| {
                let c = Chat {
                    id: row.get(0)?,
                    typ: row.get(1)?,
                    name: row.get::<_, String>(2)?,
                    grpid: row.get::<_, String>(3)?,
                    param: row.get::<_, String>(4)?.parse().unwrap_or_default(),
                    archived: row.get(5)?,
                    blocked: row.get::<_, Option<_>>(6)?.unwrap_or_default(),
                    gossiped_timestamp: row.get(7)?,
                    is_sending_locations: row.get(8)?,
                };

                Ok(c)
            },
        );

        match res {
            Err(err @ crate::error::Error::Sql(rusqlite::Error::QueryReturnedNoRows)) => Err(err),
            Err(err) => {
                error!(
                    context,
                    "chat: failed to load from db {}: {:?}", chat_id, err
                );
                Err(err)
            }
            Ok(mut chat) => {
                match chat.id {
                    DC_CHAT_ID_DEADDROP => {
                        chat.name = context.stock_str(StockMessage::DeadDrop).into();
                    }
                    DC_CHAT_ID_ARCHIVED_LINK => {
                        let tempname = context.stock_str(StockMessage::ArchivedChats);
                        let cnt = dc_get_archived_cnt(context);
                        chat.name = format!("{} ({})", tempname, cnt);
                    }
                    DC_CHAT_ID_STARRED => {
                        chat.name = context.stock_str(StockMessage::StarredMsgs).into();
                    }
                    _ => {
                        if chat.typ == Chattype::Single {
                            let contacts = get_chat_contacts(context, chat.id);
                            let mut chat_name = "Err [Name not found]".to_owned();

                            if !(*contacts).is_empty() {
                                if let Ok(contact) = Contact::get_by_id(context, contacts[0]) {
                                    chat_name = contact.get_display_name().to_owned();
                                }
                            }

                            chat.name = chat_name;
                        }

                        if chat.param.exists(Param::Selftalk) {
                            chat.name = context.stock_str(StockMessage::SavedMessages).into();
                        } else if chat.param.exists(Param::Devicetalk) {
                            chat.name = context.stock_str(StockMessage::DeviceMessages).into();
                        }
                    }
                }
                Ok(chat)
            }
        }
    }

    pub fn is_self_talk(&self) -> bool {
        self.param.exists(Param::Selftalk)
    }

    pub fn is_device_talk(&self) -> bool {
        self.param.exists(Param::Devicetalk)
    }

    pub fn can_send(&self) -> bool {
        self.id > DC_CHAT_ID_LAST_SPECIAL && !self.is_device_talk()
    }

    pub fn update_param(&mut self, context: &Context) -> Result<(), Error> {
        sql::execute(
            context,
            &context.sql,
            "UPDATE chats SET param=? WHERE id=?",
            params![self.param.to_string(), self.id as i32],
        )
    }

    pub fn get_id(&self) -> u32 {
        self.id
    }

    pub fn get_type(&self) -> Chattype {
        self.typ
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_subtitle(&self, context: &Context) -> String {
        // returns either the address or the number of chat members

        if self.typ == Chattype::Single && self.param.exists(Param::Selftalk) {
            return context.stock_str(StockMessage::SelfTalkSubTitle).into();
        }

        if self.typ == Chattype::Single {
            return context
                .sql
                .query_get_value(
                    context,
                    "SELECT c.addr FROM chats_contacts cc  \
                     LEFT JOIN contacts c ON c.id=cc.contact_id  \
                     WHERE cc.chat_id=?;",
                    params![self.id as i32],
                )
                .unwrap_or_else(|| "Err".into());
        }

        if self.typ == Chattype::Group || self.typ == Chattype::VerifiedGroup {
            if self.id == 1 {
                return context.stock_str(StockMessage::DeadDrop).into();
            }
            let cnt = get_chat_contact_cnt(context, self.id);
            return context.stock_string_repl_int(StockMessage::Member, cnt as i32);
        }

        "Err".to_string()
    }

    pub fn get_parent_mime_headers(&self, context: &Context) -> Option<(String, String, String)> {
        let collect = |row: &rusqlite::Row| Ok((row.get(0)?, row.get(1)?, row.get(2)?));
        let params = params![self.id as i32, DC_CONTACT_ID_SELF as i32];
        let sql = &context.sql;

        // use the last messsage of another user in the group as the parent
        let main_query = "SELECT rfc724_mid, mime_in_reply_to, mime_references \
                          FROM msgs WHERE chat_id=?1 AND timestamp=(SELECT max(timestamp) \
                          FROM msgs WHERE chat_id=?1 AND from_id!=?2);";

        // there are no messages of other users - use the first message if SELF as parent
        let fallback_query = "SELECT rfc724_mid, mime_in_reply_to, mime_references \
                              FROM msgs WHERE chat_id=?1 AND timestamp=(SELECT min(timestamp) \
                              FROM msgs WHERE chat_id=?1 AND from_id==?2);";

        sql.query_row(main_query, params, collect)
            .or_else(|_| sql.query_row(fallback_query, params, collect))
            .ok()
    }

    pub fn get_profile_image(&self, context: &Context) -> Option<PathBuf> {
        if let Some(image_rel) = self.param.get(Param::ProfileImage) {
            if !image_rel.is_empty() {
                return Some(dc_get_abs_path(context, image_rel));
            }
        } else if self.typ == Chattype::Single {
            let contacts = get_chat_contacts(context, self.id);
            if !contacts.is_empty() {
                if let Ok(contact) = Contact::get_by_id(context, contacts[0]) {
                    return contact.get_profile_image(context);
                }
            }
        }

        None
    }

    pub fn get_color(&self, context: &Context) -> u32 {
        let mut color = 0;

        if self.typ == Chattype::Single {
            let contacts = get_chat_contacts(context, self.id);
            if !contacts.is_empty() {
                if let Ok(contact) = Contact::get_by_id(context, contacts[0]) {
                    color = contact.get_color();
                }
            }
        } else {
            color = dc_str_to_color(&self.name);
        }

        color
    }

    /// Returns true if the chat is archived.
    pub fn is_archived(&self) -> bool {
        self.archived
    }

    pub fn is_unpromoted(&self) -> bool {
        self.param.get_int(Param::Unpromoted).unwrap_or_default() == 1
    }

    pub fn is_promoted(&self) -> bool {
        !self.is_unpromoted()
    }

    pub fn is_verified(&self) -> bool {
        (self.typ == Chattype::VerifiedGroup)
    }

    pub fn is_sending_locations(&self) -> bool {
        self.is_sending_locations
    }

    fn prepare_msg_raw(
        &mut self,
        context: &Context,
        msg: &mut Message,
        timestamp: i64,
    ) -> Result<MsgId, Error> {
        let mut do_guarantee_e2ee: bool;
        let e2ee_enabled: bool;
        let mut new_references = "".into();
        let mut new_in_reply_to = "".into();
        let mut msg_id = 0;
        let mut to_id = 0;
        let mut location_id = 0;

        if !(self.typ == Chattype::Single
            || self.typ == Chattype::Group
            || self.typ == Chattype::VerifiedGroup)
        {
            error!(context, "Cannot send to chat type #{}.", self.typ,);
            bail!("Cannot set to chat type #{}", self.typ);
        }

        if (self.typ == Chattype::Group || self.typ == Chattype::VerifiedGroup)
            && !is_contact_in_chat(context, self.id, DC_CONTACT_ID_SELF)
        {
            emit_event!(
                context,
                Event::ErrorSelfNotInGroup("Cannot send message; self not in group.".into())
            );
            bail!("Cannot set message; self not in group.");
        }

        if let Some(from) = context.get_config(Config::ConfiguredAddr) {
            let new_rfc724_mid = {
                let grpid = match self.typ {
                    Chattype::Group | Chattype::VerifiedGroup => Some(self.grpid.as_str()),
                    _ => None,
                };
                dc_create_outgoing_rfc724_mid(grpid, &from)
            };

            if self.typ == Chattype::Single {
                if let Some(id) = context.sql.query_get_value(
                    context,
                    "SELECT contact_id FROM chats_contacts WHERE chat_id=?;",
                    params![self.id as i32],
                ) {
                    to_id = id;
                } else {
                    error!(
                        context,
                        "Cannot send message, contact for chat #{} not found.", self.id,
                    );
                    bail!(
                        "Cannot set message, contact for chat #{} not found.",
                        self.id
                    );
                }
            } else {
                if self.typ == Chattype::Group || self.typ == Chattype::VerifiedGroup {
                    if self.param.get_int(Param::Unpromoted).unwrap_or_default() == 1 {
                        self.param.remove(Param::Unpromoted);
                        self.update_param(context)?;
                    }
                }
            }

            /* check if we can guarantee E2EE for this message.
            if we guarantee E2EE, and circumstances change
            so that E2EE is no longer available at a later point (reset, changed settings),
            we do not send the message out at all */
            do_guarantee_e2ee = false;
            e2ee_enabled = context.get_config_bool(Config::E2eeEnabled);
            if e2ee_enabled && msg.param.get_int(Param::ForcePlaintext).unwrap_or_default() == 0 {
                let mut can_encrypt = true;
                let mut all_mutual = true;

                // take care that this statement returns NULL rows
                // if there is no peerstates for a chat member!
                // for DC_PARAM_SELFTALK this statement does not return any row
                let res = context.sql.query_map(
                    "SELECT ps.prefer_encrypted, c.addr \
                     FROM chats_contacts cc  \
                     LEFT JOIN contacts c ON cc.contact_id=c.id  \
                     LEFT JOIN acpeerstates ps ON c.addr=ps.addr  \
                     WHERE cc.chat_id=?  AND cc.contact_id>9;",
                    params![self.id],
                    |row| {
                        let addr: String = row.get(1)?;

                        if let Some(prefer_encrypted) = row.get::<_, Option<i32>>(0)? {
                            // the peerstate exist, so we have either public_key or gossip_key
                            // and can encrypt potentially
                            if prefer_encrypted != 1 {
                                info!(
                                    context,
                                    "[autocrypt] peerstate for {} is {}",
                                    addr,
                                    if prefer_encrypted == 0 {
                                        "NOPREFERENCE"
                                    } else {
                                        "RESET"
                                    },
                                );
                                all_mutual = false;
                            }
                        } else {
                            info!(context, "[autocrypt] no peerstate for {}", addr,);
                            can_encrypt = false;
                            all_mutual = false;
                        }
                        Ok(())
                    },
                    |rows| rows.collect::<Result<Vec<_>, _>>().map_err(Into::into),
                );
                match res {
                    Ok(_) => {}
                    Err(err) => {
                        warn!(context, "chat: failed to load peerstates: {:?}", err);
                    }
                }

                if can_encrypt {
                    if all_mutual {
                        do_guarantee_e2ee = true;
                    } else if last_msg_in_chat_encrypted(context, &context.sql, self.id) {
                        do_guarantee_e2ee = true;
                    }
                }
            }
            if do_guarantee_e2ee {
                msg.param.set_int(Param::GuaranteeE2ee, 1);
            }
            // reset eg. for forwarding
            msg.param.remove(Param::ErroneousE2ee);

            // set "In-Reply-To:" to identify the message to which the composed message is a reply;
            // set "References:" to identify the "thread" of the conversation;
            // both according to RFC 5322 3.6.4, page 25
            //
            // as self-talks are mainly used to transfer data between devices,
            // we do not set In-Reply-To/References in this case.
            if !self.is_self_talk() {
                if let Some((parent_rfc724_mid, parent_in_reply_to, parent_references)) =
                    self.get_parent_mime_headers(context)
                {
                    if !parent_rfc724_mid.is_empty() {
                        new_in_reply_to = parent_rfc724_mid.clone();
                    }

                    // the whole list of messages referenced may be huge;
                    // only use the oldest and and the parent message
                    let parent_references = if let Some(n) = parent_references.find(' ') {
                        &parent_references[0..n]
                    } else {
                        &parent_references
                    };

                    if !parent_references.is_empty() && !parent_rfc724_mid.is_empty() {
                        // angle brackets are added by the mimefactory later
                        new_references = format!("{} {}", parent_references, parent_rfc724_mid);
                    } else if !parent_references.is_empty() {
                        new_references = parent_references.to_string();
                    } else if !parent_in_reply_to.is_empty() && !parent_rfc724_mid.is_empty() {
                        new_references = format!("{} {}", parent_in_reply_to, parent_rfc724_mid);
                    } else if !parent_in_reply_to.is_empty() {
                        new_references = parent_in_reply_to.clone();
                    }
                }
            }

            // add independent location to database

            if msg.param.exists(Param::SetLatitude) {
                if sql::execute(
                    context,
                    &context.sql,
                    "INSERT INTO locations \
                     (timestamp,from_id,chat_id, latitude,longitude,independent)\
                     VALUES (?,?,?, ?,?,1);", // 1=DC_CONTACT_ID_SELF
                    params![
                        timestamp,
                        DC_CONTACT_ID_SELF,
                        self.id as i32,
                        msg.param.get_float(Param::SetLatitude).unwrap_or_default(),
                        msg.param.get_float(Param::SetLongitude).unwrap_or_default(),
                    ],
                )
                .is_ok()
                {
                    location_id = sql::get_rowid2(
                        context,
                        &context.sql,
                        "locations",
                        "timestamp",
                        timestamp,
                        "from_id",
                        DC_CONTACT_ID_SELF as i32,
                    );
                }
            }

            // add message to the database

            if sql::execute(
                        context,
                        &context.sql,
                        "INSERT INTO msgs (rfc724_mid, chat_id, from_id, to_id, timestamp, type, state, txt, param, hidden, mime_in_reply_to, mime_references, location_id) VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?,?);",
                        params![
                            new_rfc724_mid,
                            self.id as i32,
                            DC_CONTACT_ID_SELF,
                            to_id as i32,
                            timestamp,
                            msg.type_0,
                            msg.state,
                            msg.text.as_ref().map_or("", String::as_str),
                            msg.param.to_string(),
                            msg.hidden,
                            new_in_reply_to,
                            new_references,
                            location_id as i32,
                        ]
                    ).is_ok() {
                        msg_id = sql::get_rowid(
                            context,
                            &context.sql,
                            "msgs",
                            "rfc724_mid",
                            new_rfc724_mid,
                        );
                    } else {
                        error!(
                            context,
                            "Cannot send message, cannot insert to database (chat #{}).",
                            self.id,
                        );
                    }
        } else {
            error!(context, "Cannot send message, not configured.",);
        }

        Ok(MsgId::new(msg_id))
    }
}

/// Create a normal chat or a group chat by a messages ID that comes typically
/// from the deaddrop, DC_CHAT_ID_DEADDROP (1).
///
/// If the given message ID already belongs to a normal chat or to a group chat,
/// the chat ID of this chat is returned and no new chat is created.
/// If a new chat is created, the given message ID is moved to this chat, however,
/// there may be more messages moved to the chat from the deaddrop. To get the
/// chat messages, use dc_get_chat_msgs().
///
/// If the user is asked before creation, he should be
/// asked whether he wants to chat with the _contact_ belonging to the message;
/// the group names may be really weird when taken from the subject of implicit
/// groups and this may look confusing.
///
/// Moreover, this function also scales up the origin of the contact belonging
/// to the message and, depending on the contacts origin, messages from the
/// same group may be shown or not - so, all in all, it is fine to show the
/// contact name only.
pub fn create_by_msg_id(context: &Context, msg_id: MsgId) -> Result<u32, Error> {
    let mut chat_id = 0;
    let mut send_event = false;

    if let Ok(msg) = Message::load_from_db(context, msg_id) {
        if let Ok(chat) = Chat::load_from_db(context, msg.chat_id) {
            if chat.id > DC_CHAT_ID_LAST_SPECIAL {
                chat_id = chat.id;
                if chat.blocked != Blocked::Not {
                    unblock(context, chat.id);
                    send_event = true;
                }
                Contact::scaleup_origin_by_id(context, msg.from_id, Origin::CreateChat);
            }
        }
    }

    if send_event {
        context.call_cb(Event::MsgsChanged {
            chat_id: 0,
            msg_id: MsgId::new(0),
        });
    }

    ensure!(chat_id > 0, "failed to load create chat");

    Ok(chat_id)
}

/// Create a normal chat with a single user.  To create group chats,
/// see dc_create_group_chat().
///
/// If a chat already exists, this ID is returned, otherwise a new chat is created;
/// this new chat may already contain messages, eg. from the deaddrop, to get the
/// chat messages, use dc_get_chat_msgs().
pub fn create_by_contact_id(context: &Context, contact_id: u32) -> Result<u32, Error> {
    let chat_id = match lookup_by_contact_id(context, contact_id) {
        Ok((chat_id, chat_blocked)) => {
            if chat_blocked != Blocked::Not {
                // unblock chat (typically move it from the deaddrop to view
                unblock(context, chat_id);
            }
            chat_id
        }
        Err(err) => {
            if !Contact::real_exists_by_id(context, contact_id) && contact_id != DC_CONTACT_ID_SELF
            {
                warn!(
                    context,
                    "Cannot create chat, contact {} does not exist.", contact_id,
                );
                return Err(err);
            } else {
                let (chat_id, _) =
                    create_or_lookup_by_contact_id(context, contact_id, Blocked::Not)?;
                Contact::scaleup_origin_by_id(context, contact_id, Origin::CreateChat);
                chat_id
            }
        }
    };

    context.call_cb(Event::MsgsChanged {
        chat_id: 0,
        msg_id: MsgId::new(0),
    });

    Ok(chat_id)
}

pub fn unblock(context: &Context, chat_id: u32) {
    set_blocking(context, chat_id, Blocked::Not);
}

pub fn set_blocking(context: &Context, chat_id: u32, new_blocking: Blocked) -> bool {
    sql::execute(
        context,
        &context.sql,
        "UPDATE chats SET blocked=? WHERE id=?;",
        params![new_blocking, chat_id as i32],
    )
    .is_ok()
}

fn copy_device_icon_to_blobs(context: &Context) -> Result<String, Error> {
    let icon = include_bytes!("../assets/icon-device.png");
    let blob = BlobObject::create(context, "icon-device.png".to_string(), icon)?;
    Ok(blob.as_name().to_string())
}

pub fn update_saved_messages_icon(context: &Context) -> Result<(), Error> {
    // if there is no saved-messages chat, there is nothing to update. this is no error.
    if let Ok((chat_id, _)) = lookup_by_contact_id(context, DC_CONTACT_ID_SELF) {
        let icon = include_bytes!("../assets/icon-saved-messages.png");
        let blob = BlobObject::create(context, "icon-saved-messages.png".to_string(), icon)?;
        let icon = blob.as_name().to_string();

        let mut chat = Chat::load_from_db(context, chat_id)?;
        chat.param.set(Param::ProfileImage, icon);
        chat.update_param(context)?;
    }
    Ok(())
}

pub fn create_or_lookup_by_contact_id(
    context: &Context,
    contact_id: u32,
    create_blocked: Blocked,
) -> Result<(u32, Blocked), Error> {
    ensure!(context.sql.is_open(), "Database not available");
    ensure!(contact_id > 0, "Invalid contact id requested");

    if let Ok((chat_id, chat_blocked)) = lookup_by_contact_id(context, contact_id) {
        // Already exists, no need to create.
        return Ok((chat_id, chat_blocked));
    }

    let contact = Contact::load_from_db(context, contact_id)?;
    let chat_name = contact.get_display_name();

    sql::execute(
        context,
        &context.sql,
        format!(
            "INSERT INTO chats (type, name, param, blocked, grpid) VALUES({}, '{}', '{}', {}, '{}')",
            100,
            chat_name,
            match contact_id {
                DC_CONTACT_ID_SELF => "K=1".to_string(), // K = Param::Selftalk
                DC_CONTACT_ID_DEVICE => {
                    let icon = copy_device_icon_to_blobs(context)?;
                    format!("D=1\ni={}", icon) // D = Param::Devicetalk, i = Param::ProfileImage
                },
                _ => "".to_string()
            },
            create_blocked as u8,
            contact.get_addr(),
        ),
        params![],
    )?;

    let chat_id = sql::get_rowid(context, &context.sql, "chats", "grpid", contact.get_addr());

    sql::execute(
        context,
        &context.sql,
        format!(
            "INSERT INTO chats_contacts (chat_id, contact_id) VALUES({}, {})",
            chat_id, contact_id
        ),
        params![],
    )?;

    if contact_id == DC_CONTACT_ID_SELF {
        update_saved_messages_icon(context)?;
    }

    Ok((chat_id, create_blocked))
}

pub fn lookup_by_contact_id(context: &Context, contact_id: u32) -> Result<(u32, Blocked), Error> {
    ensure!(context.sql.is_open(), "Database not available");

    context.sql.query_row(
        "SELECT c.id, c.blocked FROM chats c INNER JOIN chats_contacts j ON c.id=j.chat_id WHERE c.type=100 AND c.id>9 AND j.contact_id=?;",
        params![contact_id as i32],
        |row| Ok((row.get(0)?, row.get::<_, Option<_>>(1)?.unwrap_or_default())),
    )
}

pub fn get_by_contact_id(context: &Context, contact_id: u32) -> Result<u32, Error> {
    let (chat_id, blocked) = lookup_by_contact_id(context, contact_id)?;
    ensure_eq!(blocked, Blocked::Not, "Requested contact is blocked");

    Ok(chat_id)
}

pub fn prepare_msg<'a>(
    context: &'a Context,
    chat_id: u32,
    msg: &mut Message,
) -> Result<MsgId, Error> {
    ensure!(
        chat_id > DC_CHAT_ID_LAST_SPECIAL,
        "Cannot prepare message for special chat"
    );

    msg.state = MessageState::OutPreparing;
    let msg_id = prepare_msg_common(context, chat_id, msg)?;
    context.call_cb(Event::MsgsChanged {
        chat_id: msg.chat_id,
        msg_id: msg.id,
    });

    Ok(msg_id)
}

pub fn msgtype_has_file(msgtype: Viewtype) -> bool {
    match msgtype {
        Viewtype::Unknown => false,
        Viewtype::Text => false,
        Viewtype::Image => true,
        Viewtype::Gif => true,
        Viewtype::Sticker => true,
        Viewtype::Audio => true,
        Viewtype::Voice => true,
        Viewtype::Video => true,
        Viewtype::File => true,
    }
}

fn prepare_msg_blob(context: &Context, msg: &mut Message) -> Result<(), Error> {
    if msg.type_0 == Viewtype::Text {
        // the caller should check if the message text is empty
    } else if msgtype_has_file(msg.type_0) {
        let blob = msg
            .param
            .get_blob(Param::File, context, !msg.is_increation())?
            .ok_or_else(|| format_err!("Attachment missing for message of type #{}", msg.type_0))?;
        msg.param.set(Param::File, blob.as_name());
        if msg.type_0 == Viewtype::File || msg.type_0 == Viewtype::Image {
            // Correct the type, take care not to correct already very special
            // formats as GIF or VOICE.
            //
            // Typical conversions:
            // - from FILE to AUDIO/VIDEO/IMAGE
            // - from FILE/IMAGE to GIF */
            if let Some((better_type, better_mime)) =
                message::guess_msgtype_from_suffix(&blob.to_abs_path())
            {
                msg.type_0 = better_type;
                msg.param.set(Param::MimeType, better_mime);
            }
        } else if !msg.param.exists(Param::MimeType) {
            if let Some((_, mime)) = message::guess_msgtype_from_suffix(&blob.to_abs_path()) {
                msg.param.set(Param::MimeType, mime);
            }
        }
        info!(
            context,
            "Attaching \"{}\" for message type #{}.",
            blob.to_abs_path().display(),
            msg.type_0
        );
    } else {
        bail!("Cannot send messages of type #{}.", msg.type_0);
    }
    Ok(())
}

fn prepare_msg_common(context: &Context, chat_id: u32, msg: &mut Message) -> Result<MsgId, Error> {
    msg.id = MsgId::new_unset();
    prepare_msg_blob(context, msg)?;
    unarchive(context, chat_id)?;

    let mut chat = Chat::load_from_db(context, chat_id)?;
    ensure!(chat.can_send(), "cannot send to chat #{}", chat_id);

    // The OutPreparing state is set by dc_prepare_msg() before it
    // calls this function and the message is left in the OutPreparing
    // state.  Otherwise we got called by send_msg() and we change the
    // state to OutPending.
    if msg.state != MessageState::OutPreparing {
        msg.state = MessageState::OutPending;
    }

    msg.id = chat.prepare_msg_raw(context, msg, dc_create_smeared_timestamp(context))?;
    msg.chat_id = chat_id;

    Ok(msg.id)
}

fn last_msg_in_chat_encrypted(context: &Context, sql: &Sql, chat_id: u32) -> bool {
    let packed: Option<String> = sql.query_get_value(
        context,
        "SELECT param  \
         FROM msgs  WHERE timestamp=(SELECT MAX(timestamp) FROM msgs WHERE chat_id=?)  \
         ORDER BY id DESC;",
        params![chat_id as i32],
    );

    if let Some(ref packed) = packed {
        match packed.parse::<Params>() {
            Ok(param) => param.exists(Param::GuaranteeE2ee),
            Err(err) => {
                error!(context, "invalid params stored: '{}', {:?}", packed, err);
                false
            }
        }
    } else {
        false
    }
}

pub fn is_contact_in_chat(context: &Context, chat_id: u32, contact_id: u32) -> bool {
    /* this function works for group and for normal chats, however, it is more useful for group chats.
    DC_CONTACT_ID_SELF may be used to check, if the user itself is in a group chat (DC_CONTACT_ID_SELF is not added to normal chats) */

    context
        .sql
        .exists(
            "SELECT contact_id FROM chats_contacts WHERE chat_id=? AND contact_id=?;",
            params![chat_id as i32, contact_id as i32],
        )
        .unwrap_or_default()
}

// note that unarchive() is not the same as archive(false) -
// eg. unarchive() does not send events as done for archive(false).
pub fn unarchive(context: &Context, chat_id: u32) -> Result<(), Error> {
    sql::execute(
        context,
        &context.sql,
        "UPDATE chats SET archived=0 WHERE id=?",
        params![chat_id as i32],
    )
}

/// Send a message defined by a dc_msg_t object to a chat.
///
/// Sends the event #DC_EVENT_MSGS_CHANGED on succcess.
/// However, this does not imply, the message really reached the recipient -
/// sending may be delayed eg. due to network problems. However, from your
/// view, you're done with the message. Sooner or later it will find its way.
pub fn send_msg(context: &Context, chat_id: u32, msg: &mut Message) -> Result<MsgId, Error> {
    // dc_prepare_msg() leaves the message state to OutPreparing, we
    // only have to change the state to OutPending in this case.
    // Otherwise we still have to prepare the message, which will set
    // the state to OutPending.
    if msg.state != MessageState::OutPreparing {
        // automatically prepare normal messages
        prepare_msg_common(context, chat_id, msg)?;
    } else {
        // update message state of separately prepared messages
        ensure!(
            chat_id == 0 || chat_id == msg.chat_id,
            "Inconsistent chat ID"
        );
        message::update_msg_state(context, msg.id, MessageState::OutPending);
    }

    job_send_msg(context, msg.id)?;

    context.call_cb(Event::MsgsChanged {
        chat_id: msg.chat_id,
        msg_id: msg.id,
    });

    if msg.param.exists(Param::SetLatitude) {
        context.call_cb(Event::LocationChanged(Some(DC_CONTACT_ID_SELF)));
    }

    if 0 == chat_id {
        let forwards = msg.param.get(Param::PrepForwards);
        if let Some(forwards) = forwards {
            for forward in forwards.split(' ') {
                match forward
                    .parse::<u32>()
                    .map_err(|_| InvalidMsgId)
                    .map(|id| MsgId::new(id))
                {
                    Ok(msg_id) => {
                        if let Ok(mut msg) = Message::load_from_db(context, msg_id) {
                            send_msg(context, 0, &mut msg)?;
                        };
                    }
                    Err(_) => (),
                }
            }
            msg.param.remove(Param::PrepForwards);
            msg.save_param_to_disk(context);
        }
    }

    Ok(msg.id)
}

pub fn send_text_msg(
    context: &Context,
    chat_id: u32,
    text_to_send: String,
) -> Result<MsgId, Error> {
    ensure!(
        chat_id > DC_CHAT_ID_LAST_SPECIAL,
        "bad chat_id = {} <= DC_CHAT_ID_LAST_SPECIAL",
        chat_id
    );

    let mut msg = Message::new(Viewtype::Text);
    msg.text = Some(text_to_send);
    send_msg(context, chat_id, &mut msg)
}

// passing `None` as message jsut deletes the draft
pub fn set_draft(context: &Context, chat_id: u32, msg: Option<&mut Message>) {
    if chat_id <= DC_CHAT_ID_LAST_SPECIAL {
        return;
    }

    let changed = match msg {
        None => maybe_delete_draft(context, chat_id),
        Some(msg) => set_draft_raw(context, chat_id, msg),
    };

    if changed {
        context.call_cb(Event::MsgsChanged {
            chat_id,
            msg_id: MsgId::new(0),
        });
    }
}

/// Delete draft message in specified chat, if there is one.
///
/// Return {true}, if message was deleted, {false} otherwise.
fn maybe_delete_draft(context: &Context, chat_id: u32) -> bool {
    match get_draft_msg_id(context, chat_id) {
        Some(msg_id) => {
            Message::delete_from_db(context, msg_id);
            true
        }
        None => false,
    }
}

/// Set provided message as draft message for specified chat.
///
/// Return true on success, false on database error.
fn do_set_draft(context: &Context, chat_id: u32, msg: &mut Message) -> Result<(), Error> {
    match msg.type_0 {
        Viewtype::Unknown => bail!("Can not set draft of unknown type."),
        Viewtype::Text => match msg.text.as_ref() {
            Some(text) => {
                if text.is_empty() {
                    bail!("No text in draft");
                }
            }
            None => bail!("No text in draft"),
        },
        _ => {
            let blob = msg
                .param
                .get_blob(Param::File, context, !msg.is_increation())?
                .ok_or_else(|| format_err!("No file stored in params"))?;
            msg.param.set(Param::File, blob.as_name());
        }
    }
    sql::execute(
        context,
        &context.sql,
        "INSERT INTO msgs (chat_id, from_id, timestamp, type, state, txt, param, hidden) \
         VALUES (?,?,?, ?,?,?,?,?);",
        params![
            chat_id as i32,
            DC_CONTACT_ID_SELF,
            time(),
            msg.type_0,
            MessageState::OutDraft,
            msg.text.as_ref().map(String::as_str).unwrap_or(""),
            msg.param.to_string(),
            1,
        ],
    )
}

// similar to as dc_set_draft() but does not emit an event
fn set_draft_raw(context: &Context, chat_id: u32, msg: &mut Message) -> bool {
    let deleted = maybe_delete_draft(context, chat_id);
    let set = do_set_draft(context, chat_id, msg).is_ok();

    // Can't inline. Both functions above must be called, no shortcut!
    deleted || set
}

fn get_draft_msg_id(context: &Context, chat_id: u32) -> Option<MsgId> {
    context.sql.query_get_value::<_, MsgId>(
        context,
        "SELECT id FROM msgs WHERE chat_id=? AND state=?;",
        params![chat_id as i32, MessageState::OutDraft],
    )
}

pub fn get_draft(context: &Context, chat_id: u32) -> Result<Option<Message>, Error> {
    if chat_id <= DC_CHAT_ID_LAST_SPECIAL {
        return Ok(None);
    }
    match get_draft_msg_id(context, chat_id) {
        Some(draft_msg_id) => Ok(Some(Message::load_from_db(context, draft_msg_id)?)),
        None => Ok(None),
    }
}

pub fn get_chat_msgs(
    context: &Context,
    chat_id: u32,
    flags: u32,
    marker1before: Option<MsgId>,
) -> Vec<MsgId> {
    let process_row =
        |row: &rusqlite::Row| Ok((row.get::<_, MsgId>("id")?, row.get::<_, i64>("timestamp")?));
    let process_rows = |rows: rusqlite::MappedRows<_>| {
        let mut ret = Vec::new();
        let mut last_day = 0;
        let cnv_to_local = dc_gm2local_offset();
        for row in rows {
            let (curr_id, ts) = row?;
            if let Some(marker_id) = marker1before {
                if curr_id == marker_id {
                    ret.push(MsgId::new(DC_MSG_ID_MARKER1));
                }
            }
            if (flags & DC_GCM_ADDDAYMARKER) != 0 {
                let curr_local_timestamp = ts + cnv_to_local;
                let curr_day = curr_local_timestamp / 86400;
                if curr_day != last_day {
                    ret.push(MsgId::new(DC_MSG_ID_DAYMARKER));
                    last_day = curr_day;
                }
            }
            ret.push(curr_id);
        }
        Ok(ret)
    };
    let success = if chat_id == DC_CHAT_ID_DEADDROP {
        let show_emails =
            ShowEmails::from_i32(context.get_config_int(Config::ShowEmails)).unwrap_or_default();
        context.sql.query_map(
            concat!(
                "SELECT m.id AS id, m.timestamp AS timestamp",
                " FROM msgs m",
                " LEFT JOIN chats",
                "        ON m.chat_id=chats.id",
                " LEFT JOIN contacts",
                "        ON m.from_id=contacts.id",
                " WHERE m.from_id!=1", // 1=DC_CONTACT_ID_SELF
                "   AND m.from_id!=2", // 2=DC_CONTACT_ID_INFO
                "   AND m.hidden=0",
                "   AND chats.blocked=2",
                "   AND contacts.blocked=0",
                "   AND m.msgrmsg>=?",
                " ORDER BY m.timestamp,m.id;"
            ),
            params![if show_emails == ShowEmails::All { 0 } else { 1 }],
            process_row,
            process_rows,
        )
    } else if chat_id == DC_CHAT_ID_STARRED {
        context.sql.query_map(
            concat!(
                "SELECT m.id AS id, m.timestamp AS timestamp",
                " FROM msgs m",
                " LEFT JOIN contacts ct",
                "        ON m.from_id=ct.id",
                " WHERE m.starred=1",
                "   AND m.hidden=0",
                "   AND ct.blocked=0",
                " ORDER BY m.timestamp,m.id;"
            ),
            params![],
            process_row,
            process_rows,
        )
    } else {
        context.sql.query_map(
            concat!(
                "SELECT m.id AS id, m.timestamp AS timestamp",
                " FROM msgs m",
                " WHERE m.chat_id=?",
                "   AND m.hidden=0",
                " ORDER BY m.timestamp, m.id;"
            ),
            params![chat_id as i32],
            process_row,
            process_rows,
        )
    };
    match success {
        Ok(ret) => ret,
        Err(e) => {
            error!(context, "Failed to get chat messages: {}", e);
            Vec::new()
        }
    }
}

pub fn get_msg_cnt(context: &Context, chat_id: u32) -> usize {
    context
        .sql
        .query_get_value::<_, i32>(
            context,
            "SELECT COUNT(*) FROM msgs WHERE chat_id=?;",
            params![chat_id as i32],
        )
        .unwrap_or_default() as usize
}

pub fn get_fresh_msg_cnt(context: &Context, chat_id: u32) -> usize {
    context
        .sql
        .query_get_value::<_, i32>(
            context,
            "SELECT COUNT(*) FROM msgs  \
             WHERE state=10   \
             AND hidden=0    \
             AND chat_id=?;",
            params![chat_id as i32],
        )
        .unwrap_or_default() as usize
}

pub fn marknoticed_chat(context: &Context, chat_id: u32) -> Result<(), Error> {
    if !context.sql.exists(
        "SELECT id FROM msgs  WHERE chat_id=? AND state=?;",
        params![chat_id as i32, MessageState::InFresh],
    )? {
        return Ok(());
    }

    sql::execute(
        context,
        &context.sql,
        "UPDATE msgs    \
         SET state=13 WHERE chat_id=? AND state=10;",
        params![chat_id as i32],
    )?;

    context.call_cb(Event::MsgsChanged {
        chat_id: 0,
        msg_id: MsgId::new(0),
    });

    Ok(())
}

pub fn marknoticed_all_chats(context: &Context) -> Result<(), Error> {
    if !context.sql.exists(
        "SELECT id FROM msgs  \
         WHERE state=10;",
        params![],
    )? {
        return Ok(());
    }

    sql::execute(
        context,
        &context.sql,
        "UPDATE msgs    \
         SET state=13 WHERE state=10;",
        params![],
    )?;

    context.call_cb(Event::MsgsChanged {
        msg_id: MsgId::new(0),
        chat_id: 0,
    });

    Ok(())
}

pub fn get_chat_media(
    context: &Context,
    chat_id: u32,
    msg_type: Viewtype,
    msg_type2: Viewtype,
    msg_type3: Viewtype,
) -> Vec<MsgId> {
    context
        .sql
        .query_map(
            concat!(
                "SELECT",
                "    id",
                " FROM msgs",
                " WHERE chat_id=? AND (type=? OR type=? OR type=?)",
                " ORDER BY timestamp, id;"
            ),
            params![
                chat_id as i32,
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
            ],
            |row| row.get::<_, MsgId>(0),
            |ids| {
                let mut ret = Vec::new();
                for id in ids {
                    match id {
                        Ok(msg_id) => ret.push(msg_id),
                        Err(_) => (),
                    }
                }
                Ok(ret)
            },
        )
        .unwrap_or_default()
}

/// Indicates the direction over which to iterate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(i32)]
pub enum Direction {
    Forward = 1,
    Backward = -1,
}

pub fn get_next_media(
    context: &Context,
    curr_msg_id: MsgId,
    direction: Direction,
    msg_type: Viewtype,
    msg_type2: Viewtype,
    msg_type3: Viewtype,
) -> Option<MsgId> {
    let mut ret: Option<MsgId> = None;

    if let Ok(msg) = Message::load_from_db(context, curr_msg_id) {
        let list: Vec<MsgId> = get_chat_media(
            context,
            msg.chat_id,
            if msg_type != Viewtype::Unknown {
                msg_type
            } else {
                msg.type_0
            },
            msg_type2,
            msg_type3,
        );
        for i in 0..list.len() {
            if curr_msg_id == list[i] {
                match direction {
                    Direction::Forward => {
                        if i + 1 < list.len() {
                            ret = Some(list[i + 1]);
                        }
                    }
                    Direction::Backward => {
                        if i >= 1 {
                            ret = Some(list[i - 1]);
                        }
                    }
                }
                break;
            }
        }
    }
    ret
}

pub fn archive(context: &Context, chat_id: u32, archive: bool) -> Result<(), Error> {
    ensure!(
        chat_id > DC_CHAT_ID_LAST_SPECIAL,
        "bad chat_id = {} <= DC_CHAT_ID_LAST_SPECIAL",
        chat_id
    );

    if archive {
        sql::execute(
            context,
            &context.sql,
            "UPDATE msgs SET state=? WHERE chat_id=? AND state=?;",
            params![
                MessageState::InNoticed,
                chat_id as i32,
                MessageState::InFresh
            ],
        )?;
    }

    sql::execute(
        context,
        &context.sql,
        "UPDATE chats SET archived=? WHERE id=?;",
        params![archive, chat_id as i32],
    )?;

    context.call_cb(Event::MsgsChanged {
        msg_id: MsgId::new(0),
        chat_id: 0,
    });

    Ok(())
}

pub fn delete(context: &Context, chat_id: u32) -> Result<(), Error> {
    ensure!(
        chat_id > DC_CHAT_ID_LAST_SPECIAL,
        "bad chat_id = {} <= DC_CHAT_ID_LAST_SPECIAL",
        chat_id
    );
    /* Up to 2017-11-02 deleting a group also implied leaving it, see above why we have changed this. */

    let _chat = Chat::load_from_db(context, chat_id)?;
    sql::execute(
        context,
        &context.sql,
        "DELETE FROM msgs_mdns WHERE msg_id IN (SELECT id FROM msgs WHERE chat_id=?);",
        params![chat_id as i32],
    )?;

    sql::execute(
        context,
        &context.sql,
        "DELETE FROM msgs WHERE chat_id=?;",
        params![chat_id as i32],
    )?;

    sql::execute(
        context,
        &context.sql,
        "DELETE FROM chats_contacts WHERE chat_id=?;",
        params![chat_id as i32],
    )?;

    sql::execute(
        context,
        &context.sql,
        "DELETE FROM chats WHERE id=?;",
        params![chat_id as i32],
    )?;

    context.call_cb(Event::MsgsChanged {
        msg_id: MsgId::new(0),
        chat_id: 0,
    });

    job_kill_action(context, Action::Housekeeping);
    job_add(context, Action::Housekeeping, 0, Params::new(), 10);

    Ok(())
}

pub fn get_chat_contacts(context: &Context, chat_id: u32) -> Vec<u32> {
    /* Normal chats do not include SELF.  Group chats do (as it may happen that one is deleted from a
    groupchat but the chats stays visible, moreover, this makes displaying lists easier) */

    if chat_id == 1 {
        return Vec::new();
    }

    // we could also create a list for all contacts in the deaddrop by searching contacts belonging to chats with
    // chats.blocked=2, however, currently this is not needed

    context
        .sql
        .query_map(
            "SELECT cc.contact_id FROM chats_contacts cc \
             LEFT JOIN contacts c ON c.id=cc.contact_id WHERE cc.chat_id=? \
             ORDER BY c.id=1, LOWER(c.name||c.addr), c.id;",
            params![chat_id],
            |row| row.get::<_, u32>(0),
            |ids| ids.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )
        .unwrap_or_default()
}

pub fn create_group_chat(
    context: &Context,
    verified: VerifiedStatus,
    chat_name: impl AsRef<str>,
) -> Result<u32, Error> {
    ensure!(!chat_name.as_ref().is_empty(), "Invalid chat name");

    let draft_txt = context.stock_string_repl_str(StockMessage::NewGroupDraft, &chat_name);
    let grpid = dc_create_id();

    sql::execute(
        context,
        &context.sql,
        "INSERT INTO chats (type, name, grpid, param) VALUES(?, ?, ?, \'U=1\');",
        params![
            if verified != VerifiedStatus::Unverified {
                Chattype::VerifiedGroup
            } else {
                Chattype::Group
            },
            chat_name.as_ref(),
            grpid
        ],
    )?;

    let chat_id = sql::get_rowid(context, &context.sql, "chats", "grpid", grpid);

    if chat_id != 0 {
        if add_to_chat_contacts_table(context, chat_id, DC_CONTACT_ID_SELF) {
            let mut draft_msg = Message::new(Viewtype::Text);
            draft_msg.set_text(Some(draft_txt));
            set_draft_raw(context, chat_id, &mut draft_msg);
        }

        context.call_cb(Event::MsgsChanged {
            msg_id: MsgId::new(0),
            chat_id: 0,
        });
    }

    Ok(chat_id)
}

/* you MUST NOT modify this or the following strings */
// Context functions to work with chats
pub fn add_to_chat_contacts_table(context: &Context, chat_id: u32, contact_id: u32) -> bool {
    // add a contact to a chat; the function does not check the type or if any of the record exist or are already
    // added to the chat!
    sql::execute(
        context,
        &context.sql,
        "INSERT INTO chats_contacts (chat_id, contact_id) VALUES(?, ?)",
        params![chat_id as i32, contact_id as i32],
    )
    .is_ok()
}

pub fn add_contact_to_chat(context: &Context, chat_id: u32, contact_id: u32) -> bool {
    match add_contact_to_chat_ex(context, chat_id, contact_id, false) {
        Ok(res) => res,
        Err(err) => {
            error!(context, "failed to add contact: {}", err);
            false
        }
    }
}

#[allow(non_snake_case)]
pub(crate) fn add_contact_to_chat_ex(
    context: &Context,
    chat_id: u32,
    contact_id: u32,
    from_handshake: bool,
) -> Result<bool, Error> {
    ensure!(
        chat_id > DC_CHAT_ID_LAST_SPECIAL,
        "can not add member to special chats"
    );
    let contact = Contact::get_by_id(context, contact_id)?;
    let mut msg = Message::default();

    reset_gossiped_timestamp(context, chat_id);

    /*this also makes sure, not contacts are added to special or normal chats*/
    let mut chat = Chat::load_from_db(context, chat_id)?;
    ensure!(
        real_group_exists(context, chat_id),
        "chat_id {} is not a group where one can add members",
        chat_id
    );
    ensure!(
        Contact::real_exists_by_id(context, contact_id) || contact_id == DC_CONTACT_ID_SELF,
        "invalid contact_id {} for adding to group",
        contact_id
    );

    if !is_contact_in_chat(context, chat_id, DC_CONTACT_ID_SELF as u32) {
        /* we should respect this - whatever we send to the group, it gets discarded anyway! */
        emit_event!(
            context,
            Event::ErrorSelfNotInGroup("Cannot add contact to group; self not in group.".into())
        );
        bail!("can not add contact because our account is not part of it");
    }
    if from_handshake && chat.param.get_int(Param::Unpromoted).unwrap_or_default() == 1 {
        chat.param.remove(Param::Unpromoted);
        chat.update_param(context)?;
    }
    let self_addr = context
        .get_config(Config::ConfiguredAddr)
        .unwrap_or_default();
    if contact.get_addr() == &self_addr {
        // ourself is added using DC_CONTACT_ID_SELF, do not add this address explicitly.
        // if SELF is not in the group, members cannot be added at all.
        warn!(
            context,
            "invalid attempt to add self e-mail address to group"
        );
        return Ok(false);
    }

    if is_contact_in_chat(context, chat_id, contact_id) {
        if !from_handshake {
            return Ok(true);
        }
    } else {
        // else continue and send status mail
        if chat.typ == Chattype::VerifiedGroup
            && contact.is_verified(context) != VerifiedStatus::BidirectVerified
        {
            error!(
                context,
                "Only bidirectional verified contacts can be added to verified groups."
            );
            return Ok(false);
        }
        if !add_to_chat_contacts_table(context, chat_id, contact_id) {
            return Ok(false);
        }
    }
    if chat.param.get_int(Param::Unpromoted).unwrap_or_default() == 0 {
        msg.type_0 = Viewtype::Text;
        msg.text = Some(context.stock_system_msg(
            StockMessage::MsgAddMember,
            contact.get_addr(),
            "",
            DC_CONTACT_ID_SELF as u32,
        ));
        msg.param.set_cmd(SystemMessage::MemberAddedToGroup);
        msg.param.set(Param::Arg, contact.get_addr());
        msg.param.set_int(Param::Arg2, from_handshake.into());
        msg.id = send_msg(context, chat_id, &mut msg)?;
        context.call_cb(Event::MsgsChanged {
            chat_id,
            msg_id: MsgId::from(msg.id),
        });
    }
    context.call_cb(Event::MsgsChanged {
        chat_id,
        msg_id: MsgId::new(0),
    });
    Ok(true)
}

fn real_group_exists(context: &Context, chat_id: u32) -> bool {
    // check if a group or a verified group exists under the given ID
    if !context.sql.is_open() || chat_id <= DC_CHAT_ID_LAST_SPECIAL {
        return false;
    }

    context
        .sql
        .exists(
            "SELECT id FROM chats  WHERE id=?    AND (type=120 OR type=130);",
            params![chat_id as i32],
        )
        .unwrap_or_default()
}

pub fn reset_gossiped_timestamp(context: &Context, chat_id: u32) {
    set_gossiped_timestamp(context, chat_id, 0);
}

// Should return Result
pub fn set_gossiped_timestamp(context: &Context, chat_id: u32, timestamp: i64) {
    if 0 != chat_id {
        info!(
            context,
            "set gossiped_timestamp for chat #{} to {}.", chat_id, timestamp,
        );

        sql::execute(
            context,
            &context.sql,
            "UPDATE chats SET gossiped_timestamp=? WHERE id=?;",
            params![timestamp, chat_id as i32],
        )
        .ok();
    } else {
        info!(
            context,
            "set gossiped_timestamp for all chats to {}.", timestamp,
        );
        sql::execute(
            context,
            &context.sql,
            "UPDATE chats SET gossiped_timestamp=?;",
            params![timestamp],
        )
        .ok();
    }
}

pub fn remove_contact_from_chat(
    context: &Context,
    chat_id: u32,
    contact_id: u32,
) -> Result<(), Error> {
    ensure!(
        chat_id > DC_CHAT_ID_LAST_SPECIAL,
        "bad chat_id = {} <= DC_CHAT_ID_LAST_SPECIAL",
        chat_id
    );
    ensure!(
        contact_id > DC_CONTACT_ID_LAST_SPECIAL || contact_id == DC_CONTACT_ID_SELF,
        "Cannot remove special contact"
    );

    let mut msg = Message::default();
    let mut success = false;

    /* we do not check if "contact_id" exists but just delete all records with the id from chats_contacts */
    /* this allows to delete pending references to deleted contacts.  Of course, this should _not_ happen. */
    if let Ok(chat) = Chat::load_from_db(context, chat_id) {
        if real_group_exists(context, chat_id) {
            if !is_contact_in_chat(context, chat_id, DC_CONTACT_ID_SELF) {
                emit_event!(
                    context,
                    Event::ErrorSelfNotInGroup(
                        "Cannot remove contact from chat; self not in group.".into()
                    )
                );
            } else {
                /* we should respect this - whatever we send to the group, it gets discarded anyway! */
                if let Ok(contact) = Contact::get_by_id(context, contact_id) {
                    if chat.is_promoted() {
                        msg.type_0 = Viewtype::Text;
                        if contact.id == DC_CONTACT_ID_SELF {
                            set_group_explicitly_left(context, chat.grpid)?;
                            msg.text = Some(context.stock_system_msg(
                                StockMessage::MsgGroupLeft,
                                "",
                                "",
                                DC_CONTACT_ID_SELF,
                            ));
                        } else {
                            msg.text = Some(context.stock_system_msg(
                                StockMessage::MsgDelMember,
                                contact.get_addr(),
                                "",
                                DC_CONTACT_ID_SELF,
                            ));
                        }
                        msg.param.set_cmd(SystemMessage::MemberRemovedFromGroup);
                        msg.param.set(Param::Arg, contact.get_addr());
                        msg.id = send_msg(context, chat_id, &mut msg)?;
                        context.call_cb(Event::MsgsChanged {
                            chat_id,
                            msg_id: msg.id,
                        });
                    }
                }
                if sql::execute(
                    context,
                    &context.sql,
                    "DELETE FROM chats_contacts WHERE chat_id=? AND contact_id=?;",
                    params![chat_id as i32, contact_id as i32],
                )
                .is_ok()
                {
                    context.call_cb(Event::ChatModified(chat_id));
                    success = true;
                }
            }
        }
    }

    if !success {
        bail!("Failed to remove contact");
    }

    Ok(())
}

fn set_group_explicitly_left(context: &Context, grpid: impl AsRef<str>) -> Result<(), Error> {
    if !is_group_explicitly_left(context, grpid.as_ref())? {
        sql::execute(
            context,
            &context.sql,
            "INSERT INTO leftgrps (grpid) VALUES(?);",
            params![grpid.as_ref()],
        )?;
    }

    Ok(())
}

pub fn is_group_explicitly_left(context: &Context, grpid: impl AsRef<str>) -> Result<bool, Error> {
    context.sql.exists(
        "SELECT id FROM leftgrps WHERE grpid=?;",
        params![grpid.as_ref()],
    )
}

pub fn set_chat_name(
    context: &Context,
    chat_id: u32,
    new_name: impl AsRef<str>,
) -> Result<(), Error> {
    /* the function only sets the names of group chats; normal chats get their names from the contacts */
    let mut success = false;

    ensure!(!new_name.as_ref().is_empty(), "Invalid name");
    ensure!(chat_id > DC_CHAT_ID_LAST_SPECIAL, "Invalid chat ID");

    let chat = Chat::load_from_db(context, chat_id)?;
    let mut msg = Message::default();

    if real_group_exists(context, chat_id) {
        if chat.name == new_name.as_ref() {
            success = true;
        } else if !is_contact_in_chat(context, chat_id, DC_CONTACT_ID_SELF) {
            emit_event!(
                context,
                Event::ErrorSelfNotInGroup("Cannot set chat name; self not in group".into())
            );
        } else {
            /* we should respect this - whatever we send to the group, it gets discarded anyway! */
            if sql::execute(
                context,
                &context.sql,
                format!(
                    "UPDATE chats SET name='{}' WHERE id={};",
                    new_name.as_ref(),
                    chat_id as i32
                ),
                params![],
            )
            .is_ok()
            {
                if chat.is_promoted() {
                    msg.type_0 = Viewtype::Text;
                    msg.text = Some(context.stock_system_msg(
                        StockMessage::MsgGrpName,
                        &chat.name,
                        new_name.as_ref(),
                        DC_CONTACT_ID_SELF,
                    ));
                    msg.param.set_cmd(SystemMessage::GroupNameChanged);
                    if !chat.name.is_empty() {
                        msg.param.set(Param::Arg, &chat.name);
                    }
                    msg.id = send_msg(context, chat_id, &mut msg)?;
                    context.call_cb(Event::MsgsChanged {
                        chat_id,
                        msg_id: msg.id,
                    });
                }
                context.call_cb(Event::ChatModified(chat_id));
                success = true;
            }
        }
    }

    if !success {
        bail!("Failed to set name");
    }

    Ok(())
}

/// Set a new profile image for the chat.
///
/// The profile image can only be set when you are a member of the
/// chat.  To remove the profile image pass an empty string for the
/// `new_image` parameter.
#[allow(non_snake_case)]
pub fn set_chat_profile_image(
    context: &Context,
    chat_id: u32,
    new_image: impl AsRef<str>, // XXX use PathBuf
) -> Result<(), Error> {
    ensure!(chat_id > DC_CHAT_ID_LAST_SPECIAL, "Invalid chat ID");
    let mut chat = Chat::load_from_db(context, chat_id)?;
    ensure!(
        real_group_exists(context, chat_id),
        "Failed to set profile image; group does not exist"
    );
    /* we should respect this - whatever we send to the group, it gets discarded anyway! */
    if !is_contact_in_chat(context, chat_id, DC_CONTACT_ID_SELF) {
        emit_event!(
            context,
            Event::ErrorSelfNotInGroup("Cannot set chat profile image; self not in group.".into())
        );
        bail!("Failed to set profile image");
    }
    let mut msg = Message::new(Viewtype::Text);
    msg.param
        .set_int(Param::Cmd, SystemMessage::GroupImageChanged as i32);
    if new_image.as_ref().is_empty() {
        chat.param.remove(Param::ProfileImage);
        msg.param.remove(Param::Arg);
        msg.text = Some(context.stock_system_msg(
            StockMessage::MsgGrpImgDeleted,
            "",
            "",
            DC_CONTACT_ID_SELF,
        ));
    } else {
        let image_blob = BlobObject::from_path(context, Path::new(new_image.as_ref())).or_else(
            |err| match err.kind() {
                BlobErrorKind::WrongBlobdir => {
                    BlobObject::create_and_copy(context, Path::new(new_image.as_ref()))
                }
                _ => Err(err),
            },
        )?;
        chat.param.set(Param::ProfileImage, image_blob.as_name());
        msg.param.set(Param::Arg, image_blob.as_name());
        msg.text = Some(context.stock_system_msg(
            StockMessage::MsgGrpImgChanged,
            "",
            "",
            DC_CONTACT_ID_SELF,
        ));
    }
    chat.update_param(context)?;
    if chat.is_promoted() {
        msg.id = send_msg(context, chat_id, &mut msg)?;
        emit_event!(
            context,
            Event::MsgsChanged {
                chat_id,
                msg_id: msg.id
            }
        );
    }
    emit_event!(context, Event::ChatModified(chat_id));
    Ok(())
}

pub fn forward_msgs(context: &Context, msg_ids: &[MsgId], chat_id: u32) -> Result<(), Error> {
    ensure!(!msg_ids.is_empty(), "empty msgs_ids: nothing to forward");
    ensure!(
        chat_id > DC_CHAT_ID_LAST_SPECIAL,
        "can not forward to special chat"
    );

    let mut created_chats: Vec<u32> = Vec::new();
    let mut created_msgs: Vec<MsgId> = Vec::new();
    let mut curr_timestamp: i64;

    unarchive(context, chat_id)?;
    if let Ok(mut chat) = Chat::load_from_db(context, chat_id) {
        curr_timestamp = dc_create_smeared_timestamps(context, msg_ids.len());
        let ids = context.sql.query_map(
            format!(
                "SELECT id FROM msgs WHERE id IN({}) ORDER BY timestamp,id",
                msg_ids.iter().map(|_| "?").join(",")
            ),
            msg_ids,
            |row| row.get::<_, MsgId>(0),
            |ids| ids.collect::<Result<Vec<_>, _>>().map_err(Into::into),
        )?;

        for id in ids {
            let src_msg_id: MsgId = id;
            let msg = Message::load_from_db(context, src_msg_id);
            if msg.is_err() {
                break;
            }
            let mut msg = msg.unwrap();
            let original_param = msg.param.clone();

            // we tested a sort of broadcast
            // by not marking own forwarded messages as such,
            // however, this turned out to be to confusing and unclear.
            msg.param.set_int(Param::Forwarded, 1);

            msg.param.remove(Param::GuaranteeE2ee);
            msg.param.remove(Param::ForcePlaintext);
            msg.param.remove(Param::Cmd);

            let new_msg_id: MsgId;
            if msg.state == MessageState::OutPreparing {
                let fresh9 = curr_timestamp;
                curr_timestamp += 1;
                new_msg_id = chat.prepare_msg_raw(context, &mut msg, fresh9)?;
                let save_param = msg.param.clone();
                msg.param = original_param;
                msg.id = src_msg_id;

                if let Some(old_fwd) = msg.param.get(Param::PrepForwards) {
                    let new_fwd = format!("{} {}", old_fwd, new_msg_id.to_u32());
                    msg.param.set(Param::PrepForwards, new_fwd);
                } else {
                    msg.param
                        .set(Param::PrepForwards, new_msg_id.to_u32().to_string());
                }

                msg.save_param_to_disk(context);
                msg.param = save_param;
            } else {
                msg.state = MessageState::OutPending;
                let fresh10 = curr_timestamp;
                curr_timestamp += 1;
                new_msg_id = chat.prepare_msg_raw(context, &mut msg, fresh10)?;
                job_send_msg(context, new_msg_id)?;
            }
            created_chats.push(chat_id);
            created_msgs.push(new_msg_id);
        }
    }
    for (chat_id, msg_id) in created_chats.iter().zip(created_msgs.iter()) {
        context.call_cb(Event::MsgsChanged {
            chat_id: *chat_id,
            msg_id: *msg_id,
        });
    }
    Ok(())
}

pub fn get_chat_contact_cnt(context: &Context, chat_id: u32) -> usize {
    context
        .sql
        .query_get_value::<_, isize>(
            context,
            "SELECT COUNT(*) FROM chats_contacts WHERE chat_id=?;",
            params![chat_id as i32],
        )
        .unwrap_or_default() as usize
}

pub fn get_chat_cnt(context: &Context) -> usize {
    if context.sql.is_open() {
        /* no database, no chats - this is no error (needed eg. for information) */
        context
            .sql
            .query_get_value::<_, isize>(
                context,
                "SELECT COUNT(*) FROM chats WHERE id>9 AND blocked=0;",
                params![],
            )
            .unwrap_or_default() as usize
    } else {
        0
    }
}

pub fn get_chat_id_by_grpid(context: &Context, grpid: impl AsRef<str>) -> (u32, bool, Blocked) {
    context
        .sql
        .query_row(
            "SELECT id, blocked, type FROM chats WHERE grpid=?;",
            params![grpid.as_ref()],
            |row| {
                let chat_id = row.get(0)?;

                let b = row.get::<_, Option<Blocked>>(1)?.unwrap_or_default();
                let v = row.get::<_, Option<Chattype>>(2)?.unwrap_or_default();
                Ok((chat_id, v == Chattype::VerifiedGroup, b))
            },
        )
        .unwrap_or((0, false, Blocked::Not))
}

pub fn add_device_msg(context: &Context, msg: &mut Message) -> Result<MsgId, Error> {
    add_device_msg_maybe_labelled(context, None, msg)
}

pub fn add_device_msg_once(
    context: &Context,
    label: &str,
    msg: &mut Message,
) -> Result<MsgId, Error> {
    add_device_msg_maybe_labelled(context, Some(label), msg)
}

fn add_device_msg_maybe_labelled(
    context: &Context,
    label: Option<&str>,
    msg: &mut Message,
) -> Result<MsgId, Error> {
    let (chat_id, _blocked) =
        create_or_lookup_by_contact_id(context, DC_CONTACT_ID_DEVICE, Blocked::Not)?;
    let rfc724_mid = dc_create_outgoing_rfc724_mid(None, "@device");

    // chat_id has an sql-index so it makes sense to add this although redundant
    if let Some(label) = label {
        if let Ok(msg_id) = context.sql.query_row(
            "SELECT id FROM msgs WHERE chat_id=? AND label=?",
            params![chat_id, label],
            |row| {
                let msg_id: MsgId = row.get(0)?;
                Ok(msg_id)
            },
        ) {
            info!(
                context,
                "device-message {} already exist as {}", label, msg_id
            );
            return Ok(msg_id);
        }
    }

    prepare_msg_blob(context, msg)?;
    unarchive(context, chat_id)?;

    context.sql.execute(
        "INSERT INTO msgs (chat_id,from_id,to_id, timestamp,type,state, txt,param,rfc724_mid,label) \
         VALUES (?,?,?, ?,?,?, ?,?,?,?);",
        params![
            chat_id,
            DC_CONTACT_ID_DEVICE,
            DC_CONTACT_ID_SELF,
            dc_create_smeared_timestamp(context),
            msg.type_0,
            MessageState::InFresh,
            msg.text.as_ref().map_or("", String::as_str),
            msg.param.to_string(),
            rfc724_mid,
            label.unwrap_or_default(),
        ],
    )?;

    let row_id = sql::get_rowid(context, &context.sql, "msgs", "rfc724_mid", &rfc724_mid);
    let msg_id = MsgId::new(row_id);
    context.call_cb(Event::IncomingMsg { chat_id, msg_id });
    info!(
        context,
        "device-message {} added as {}",
        label.unwrap_or("without label"),
        msg_id
    );

    Ok(msg_id)
}

pub fn add_info_msg(context: &Context, chat_id: u32, text: impl AsRef<str>) {
    let rfc724_mid = dc_create_outgoing_rfc724_mid(None, "@device");

    if context.sql.execute(
        "INSERT INTO msgs (chat_id,from_id,to_id, timestamp,type,state, txt,rfc724_mid) VALUES (?,?,?, ?,?,?, ?,?);",
        params![
            chat_id as i32,
            DC_CONTACT_ID_INFO,
            DC_CONTACT_ID_INFO,
            dc_create_smeared_timestamp(context),
            Viewtype::Text,
            MessageState::InNoticed,
            text.as_ref(),
            rfc724_mid,
        ]
    ).is_err() {
        return;
    }

    let row_id = sql::get_rowid(context, &context.sql, "msgs", "rfc724_mid", &rfc724_mid);
    context.call_cb(Event::MsgsChanged {
        chat_id,
        msg_id: MsgId::new(row_id),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils::*;

    #[test]
    fn test_get_draft_no_draft() {
        let t = dummy_context();
        let chat_id = create_by_contact_id(&t.ctx, DC_CONTACT_ID_SELF).unwrap();
        let draft = get_draft(&t.ctx, chat_id).unwrap();
        assert!(draft.is_none());
    }

    #[test]
    fn test_get_draft_special_chat_id() {
        let t = dummy_context();
        let draft = get_draft(&t.ctx, DC_CHAT_ID_LAST_SPECIAL).unwrap();
        assert!(draft.is_none());
    }

    #[test]
    fn test_get_draft_no_chat() {
        // This is a weird case, maybe this should be an error but we
        // do not get this info from the database currently.
        let t = dummy_context();
        let draft = get_draft(&t.ctx, 42).unwrap();
        assert!(draft.is_none());
    }

    #[test]
    fn test_get_draft() {
        let t = dummy_context();
        let chat_id = create_by_contact_id(&t.ctx, DC_CONTACT_ID_SELF).unwrap();
        let mut msg = Message::new(Viewtype::Text);
        msg.set_text(Some("hello".to_string()));
        set_draft(&t.ctx, chat_id, Some(&mut msg));
        let draft = get_draft(&t.ctx, chat_id).unwrap().unwrap();
        let msg_text = msg.get_text();
        let draft_text = draft.get_text();
        assert_eq!(msg_text, draft_text);
    }

    #[test]
    fn test_add_contact_to_chat_ex_add_self() {
        // Adding self to a contact should succeed, even though it's pointless.
        let t = test_context(Some(Box::new(logging_cb)));
        let chat_id = create_group_chat(&t.ctx, VerifiedStatus::Unverified, "foo").unwrap();
        let added = add_contact_to_chat_ex(&t.ctx, chat_id, DC_CONTACT_ID_SELF, false).unwrap();
        assert_eq!(added, false);
    }

    #[test]
    fn test_self_talk() {
        let t = dummy_context();
        let chat_id = create_by_contact_id(&t.ctx, DC_CONTACT_ID_SELF).unwrap();
        assert_eq!(DC_CONTACT_ID_SELF, 1);
        assert!(chat_id > DC_CHAT_ID_LAST_SPECIAL);
        let chat = Chat::load_from_db(&t.ctx, chat_id).unwrap();
        assert_eq!(chat.id, chat_id);
        assert!(chat.is_self_talk());
        assert!(!chat.archived);
        assert!(!chat.is_device_talk());
        assert!(chat.can_send());
        assert_eq!(chat.name, t.ctx.stock_str(StockMessage::SelfMsg));
    }

    #[test]
    fn test_deaddrop_chat() {
        let t = dummy_context();
        let chat = Chat::load_from_db(&t.ctx, DC_CHAT_ID_DEADDROP).unwrap();
        assert_eq!(DC_CHAT_ID_DEADDROP, 1);
        assert_eq!(chat.id, DC_CHAT_ID_DEADDROP);
        assert!(!chat.is_self_talk());
        assert!(!chat.archived);
        assert!(!chat.is_device_talk());
        assert!(!chat.can_send());
        assert_eq!(chat.name, t.ctx.stock_str(StockMessage::DeadDrop));
    }

    #[test]
    fn test_add_device_msg() {
        let t = test_context(Some(Box::new(logging_cb)));

        // add two device-messages
        let mut msg1 = Message::new(Viewtype::Text);
        msg1.text = Some("first message".to_string());
        let msg1_id = add_device_msg(&t.ctx, &mut msg1);
        assert!(msg1_id.is_ok());

        let mut msg2 = Message::new(Viewtype::Text);
        msg2.text = Some("second message".to_string());
        let msg2_id = add_device_msg(&t.ctx, &mut msg2);
        assert!(msg2_id.is_ok());
        assert_ne!(msg1_id.as_ref().unwrap(), msg2_id.as_ref().unwrap());

        // check added messages
        let msg1 = message::Message::load_from_db(&t.ctx, msg1_id.unwrap());
        assert!(msg1.is_ok());
        let msg1 = msg1.unwrap();
        assert_eq!(msg1.text.as_ref().unwrap(), "first message");
        assert_eq!(msg1.from_id, DC_CONTACT_ID_DEVICE);
        assert_eq!(msg1.to_id, DC_CONTACT_ID_SELF);
        assert!(!msg1.is_info());
        assert!(!msg1.is_setupmessage());

        let msg2 = message::Message::load_from_db(&t.ctx, msg2_id.unwrap());
        assert!(msg2.is_ok());
        let msg2 = msg2.unwrap();
        assert_eq!(msg2.text.as_ref().unwrap(), "second message");

        // check device chat
        assert_eq!(get_msg_cnt(&t.ctx, msg2.chat_id), 2);
    }

    #[test]
    fn test_add_device_msg_once() {
        let t = test_context(Some(Box::new(logging_cb)));

        // add two device-messages with the same label (second attempt is not added)
        let mut msg1 = Message::new(Viewtype::Text);
        msg1.text = Some("first message".to_string());
        let msg1_id = add_device_msg_once(&t.ctx, "any-label", &mut msg1);
        assert!(msg1_id.is_ok());

        let mut msg2 = Message::new(Viewtype::Text);
        msg2.text = Some("second message".to_string());
        let msg2_id = add_device_msg_once(&t.ctx, "any-label", &mut msg2);
        assert!(msg2_id.is_ok());
        assert_eq!(msg1_id.as_ref().unwrap(), msg2_id.as_ref().unwrap());

        // check added message
        let msg2 = message::Message::load_from_db(&t.ctx, msg2_id.unwrap());
        assert!(msg2.is_ok());
        let msg2 = msg2.unwrap();
        assert_eq!(msg1_id.unwrap(), msg2.id);
        assert_eq!(msg2.text.as_ref().unwrap(), "first message");
        assert_eq!(msg2.from_id, DC_CONTACT_ID_DEVICE);
        assert_eq!(msg2.to_id, DC_CONTACT_ID_SELF);
        assert!(!msg2.is_info());
        assert!(!msg2.is_setupmessage());

        // check device chat
        let chat_id = msg2.chat_id;
        assert_eq!(get_msg_cnt(&t.ctx, chat_id), 1);
        assert!(chat_id > DC_CHAT_ID_LAST_SPECIAL);
        let chat = Chat::load_from_db(&t.ctx, chat_id);
        assert!(chat.is_ok());
        let chat = chat.unwrap();
        assert!(chat.is_device_talk());
        assert!(!chat.is_self_talk());
        assert!(!chat.can_send());
        assert_eq!(chat.name, t.ctx.stock_str(StockMessage::DeviceMessages));
        assert!(chat.get_profile_image(&t.ctx).is_some());
    }

    fn chatlist_len(ctx: &Context, listflags: usize) -> usize {
        Chatlist::try_load(ctx, listflags, None, None)
            .unwrap()
            .len()
    }

    #[test]
    fn test_archive() {
        // create two chats
        let t = dummy_context();
        let mut msg = Message::new(Viewtype::Text);
        msg.text = Some("foo".to_string());
        let msg_id = add_device_msg(&t.ctx, &mut msg).unwrap();
        let chat_id1 = message::Message::load_from_db(&t.ctx, msg_id)
            .unwrap()
            .chat_id;
        let chat_id2 = create_by_contact_id(&t.ctx, DC_CONTACT_ID_SELF).unwrap();
        assert!(chat_id1 > DC_CHAT_ID_LAST_SPECIAL);
        assert!(chat_id2 > DC_CHAT_ID_LAST_SPECIAL);
        assert_eq!(get_chat_cnt(&t.ctx), 2);
        assert_eq!(chatlist_len(&t.ctx, 0), 2);
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_NO_SPECIALS), 2);
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_ARCHIVED_ONLY), 0);
        assert_eq!(DC_GCL_ARCHIVED_ONLY, 0x01);
        assert_eq!(DC_GCL_NO_SPECIALS, 0x02);

        // archive first chat
        assert!(archive(&t.ctx, chat_id1, true).is_ok());
        assert!(Chat::load_from_db(&t.ctx, chat_id1).unwrap().is_archived());
        assert!(!Chat::load_from_db(&t.ctx, chat_id2).unwrap().is_archived());
        assert_eq!(get_chat_cnt(&t.ctx), 2);
        assert_eq!(chatlist_len(&t.ctx, 0), 2); // including DC_CHAT_ID_ARCHIVED_LINK now
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_NO_SPECIALS), 1);
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_ARCHIVED_ONLY), 1);

        // archive second chat
        assert!(archive(&t.ctx, chat_id2, true).is_ok());
        assert!(Chat::load_from_db(&t.ctx, chat_id1).unwrap().is_archived());
        assert!(Chat::load_from_db(&t.ctx, chat_id2).unwrap().is_archived());
        assert_eq!(get_chat_cnt(&t.ctx), 2);
        assert_eq!(chatlist_len(&t.ctx, 0), 1); // only DC_CHAT_ID_ARCHIVED_LINK now
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_NO_SPECIALS), 0);
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_ARCHIVED_ONLY), 2);

        // archive already archived first chat, unarchive second chat two times
        assert!(archive(&t.ctx, chat_id1, true).is_ok());
        assert!(archive(&t.ctx, chat_id2, false).is_ok());
        assert!(archive(&t.ctx, chat_id2, false).is_ok());
        assert!(Chat::load_from_db(&t.ctx, chat_id1).unwrap().is_archived());
        assert!(!Chat::load_from_db(&t.ctx, chat_id2).unwrap().is_archived());
        assert_eq!(get_chat_cnt(&t.ctx), 2);
        assert_eq!(chatlist_len(&t.ctx, 0), 2);
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_NO_SPECIALS), 1);
        assert_eq!(chatlist_len(&t.ctx, DC_GCL_ARCHIVED_ONLY), 1);
    }
}
