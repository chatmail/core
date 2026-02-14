//! # Messages and their identifiers.

use std::collections::BTreeSet;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str;

use anyhow::{Context as _, Result, ensure, format_err};
use deltachat_contact_tools::{VcardContact, parse_vcard};
use deltachat_derive::{FromSql, ToSql};
use humansize::BINARY;
use humansize::format_size;
use num_traits::FromPrimitive;
use serde::{Deserialize, Serialize};
use tokio::{fs, io};

use crate::blob::BlobObject;
use crate::chat::{Chat, ChatId, ChatIdBlocked, ChatVisibility, send_msg};
use crate::chatlist_events;
use crate::config::Config;
use crate::constants::{Blocked, Chattype, DC_CHAT_ID_TRASH, DC_MSG_ID_LAST_SPECIAL};
use crate::contact::{self, Contact, ContactId};
use crate::context::Context;
use crate::debug_logging::set_debug_logging_xdc;
use crate::download::DownloadState;
use crate::ephemeral::{Timer as EphemeralTimer, start_ephemeral_timers_msgids};
use crate::events::EventType;
use crate::imap::markseen_on_imap_table;
use crate::location::delete_poi_location;
use crate::log::warn;
use crate::mimeparser::{SystemMessage, parse_message_id};
use crate::param::{Param, Params};
use crate::pgp::split_armored_data;
use crate::reaction::get_msg_reactions;
use crate::sql;
use crate::summary::Summary;
use crate::sync::SyncData;
use crate::tools::create_outgoing_rfc724_mid;
use crate::tools::{
    buf_compress, buf_decompress, get_filebytes, get_filemeta, gm2local_offset, read_file,
    sanitize_filename, time, timestamp_to_str,
};

/// Message ID, including reserved IDs.
///
/// Some message IDs are reserved to identify special message types.
/// This type can represent both the special as well as normal
/// messages.
#[derive(
    Debug, Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct MsgId(u32);

impl MsgId {
    /// Create a new [MsgId].
    pub fn new(id: u32) -> MsgId {
        MsgId(id)
    }

    /// Create a new unset [MsgId].
    pub fn new_unset() -> MsgId {
        MsgId(0)
    }

    /// Whether the message ID signifies a special message.
    ///
    /// This kind of message ID can not be used for real messages.
    pub fn is_special(self) -> bool {
        self.0 <= DC_MSG_ID_LAST_SPECIAL
    }

    /// Whether the message ID is unset.
    ///
    /// When a message is created it initially has a ID of `0`, which
    /// is filled in by a real message ID once the message is saved in
    /// the database.  This returns true while the message has not
    /// been saved and thus not yet been given an actual message ID.
    ///
    /// When this is `true`, [MsgId::is_special] will also always be
    /// `true`.
    pub fn is_unset(self) -> bool {
        self.0 == 0
    }

    /// Returns message state.
    pub async fn get_state(self, context: &Context) -> Result<MessageState> {
        let result = context
            .sql
            .query_row_optional(
                "SELECT m.state, mdns.msg_id
                  FROM msgs m LEFT JOIN msgs_mdns mdns ON mdns.msg_id=m.id
                  WHERE id=?
                  LIMIT 1",
                (self,),
                |row| {
                    let state: MessageState = row.get(0)?;
                    let mdn_msg_id: Option<MsgId> = row.get(1)?;
                    Ok(state.with_mdns(mdn_msg_id.is_some()))
                },
            )
            .await?
            .unwrap_or_default();
        Ok(result)
    }

    pub(crate) async fn get_param(self, context: &Context) -> Result<Params> {
        let res: Option<String> = context
            .sql
            .query_get_value("SELECT param FROM msgs WHERE id=?", (self,))
            .await?;
        Ok(res
            .map(|s| s.parse().unwrap_or_default())
            .unwrap_or_default())
    }

    /// Put message into trash chat and delete message text.
    ///
    /// It means the message is deleted locally, but not on the server.
    /// We keep some infos to
    /// 1. not download the same message again
    /// 2. be able to delete the message on the server if we want to
    ///
    /// * `on_server`: Delete the message on the server also if it is seen on IMAP later, but only
    ///   if all parts of the message are trashed with this flag. `true` if the user explicitly
    ///   deletes the message. As for trashing a partially downloaded message when replacing it with
    ///   a fully downloaded one, see `receive_imf::add_parts()`.
    pub(crate) async fn trash(self, context: &Context, on_server: bool) -> Result<()> {
        context
            .sql
            .execute(
                // If you change which information is preserved here, also change
                // `ChatId::delete_ex()`, `delete_expired_messages()` and which information
                // `receive_imf::add_parts()` still adds to the db if chat_id is TRASH.
                "
INSERT OR REPLACE INTO msgs (id, rfc724_mid, pre_rfc724_mid, timestamp, chat_id, deleted)
SELECT ?1, rfc724_mid, pre_rfc724_mid, timestamp, ?, ? FROM msgs WHERE id=?1
                ",
                (self, DC_CHAT_ID_TRASH, on_server),
            )
            .await?;

        Ok(())
    }

    pub(crate) async fn set_delivered(self, context: &Context) -> Result<()> {
        update_msg_state(context, self, MessageState::OutDelivered).await?;
        let chat_id: Option<ChatId> = context
            .sql
            .query_get_value("SELECT chat_id FROM msgs WHERE id=?", (self,))
            .await?;
        context.emit_event(EventType::MsgDelivered {
            chat_id: chat_id.unwrap_or_default(),
            msg_id: self,
        });
        if let Some(chat_id) = chat_id {
            chatlist_events::emit_chatlist_item_changed(context, chat_id);
        }
        Ok(())
    }

    /// Bad evil escape hatch.
    ///
    /// Avoid using this, eventually types should be cleaned up enough
    /// that it is no longer necessary.
    pub fn to_u32(self) -> u32 {
        self.0
    }

    /// Returns server foldernames and UIDs of a message, used for message info
    pub async fn get_info_server_urls(
        context: &Context,
        rfc724_mid: String,
    ) -> Result<Vec<String>> {
        context
            .sql
            .query_map_vec(
                "SELECT transports.addr, imap.folder, imap.uid
                 FROM imap
                 LEFT JOIN transports
                 ON transports.id = imap.transport_id
                 WHERE imap.rfc724_mid=?",
                (rfc724_mid,),
                |row| {
                    let addr: String = row.get(0)?;
                    let folder: String = row.get(1)?;
                    let uid: u32 = row.get(2)?;
                    Ok(format!("<{addr}/{folder}/;UID={uid}>"))
                },
            )
            .await
    }

    /// Returns information about hops of a message, used for message info
    pub async fn hop_info(self, context: &Context) -> Result<String> {
        let hop_info = context
            .sql
            .query_get_value("SELECT IFNULL(hop_info, '') FROM msgs WHERE id=?", (self,))
            .await?
            .with_context(|| format!("Message {self} not found"))?;
        Ok(hop_info)
    }

    /// Returns detailed message information in a multi-line text form.
    #[expect(clippy::arithmetic_side_effects)]
    pub async fn get_info(self, context: &Context) -> Result<String> {
        let msg = Message::load_from_db(context, self).await?;

        let mut ret = String::new();

        let fts = timestamp_to_str(msg.get_timestamp());
        ret += &format!("Sent: {fts}");

        let from_contact = Contact::get_by_id(context, msg.from_id).await?;
        let name = from_contact.get_display_name();
        if let Some(override_sender_name) = msg.get_override_sender_name() {
            ret += &format!(" by ~{override_sender_name}");
        } else {
            ret += &format!(" by {name}");
        }
        ret += "\n";

        if msg.from_id != ContactId::SELF {
            let s = timestamp_to_str(if 0 != msg.timestamp_rcvd {
                msg.timestamp_rcvd
            } else {
                msg.timestamp_sort
            });
            ret += &format!("Received: {}", &s);
            ret += "\n";
        }

        if let EphemeralTimer::Enabled { duration } = msg.ephemeral_timer {
            ret += &format!("Ephemeral timer: {duration}\n");
        }

        if msg.ephemeral_timestamp != 0 {
            ret += &format!("Expires: {}\n", timestamp_to_str(msg.ephemeral_timestamp));
        }

        if msg.from_id == ContactId::INFO || msg.to_id == ContactId::INFO {
            // device-internal message, no further details needed
            return Ok(ret);
        }

        if let Ok(rows) = context
            .sql
            .query_map_vec(
                "SELECT contact_id, timestamp_sent FROM msgs_mdns WHERE msg_id=?",
                (self,),
                |row| {
                    let contact_id: ContactId = row.get(0)?;
                    let ts: i64 = row.get(1)?;
                    Ok((contact_id, ts))
                },
            )
            .await
        {
            for (contact_id, ts) in rows {
                let fts = timestamp_to_str(ts);
                ret += &format!("Read: {fts}");

                let name = Contact::get_by_id(context, contact_id)
                    .await
                    .map(|contact| contact.get_display_name().to_owned())
                    .unwrap_or_default();

                ret += &format!(" by {name}");
                ret += "\n";
            }
        }

        ret += &format!("State: {}", msg.state);

        if msg.has_location() {
            ret += ", Location sent";
        }

        if 0 != msg.param.get_int(Param::GuaranteeE2ee).unwrap_or_default() {
            ret += ", Encrypted";
        }

        ret += "\n";

        let reactions = get_msg_reactions(context, self).await?;
        if !reactions.is_empty() {
            ret += &format!("Reactions: {reactions}\n");
        }

        if let Some(error) = msg.error.as_ref() {
            ret += &format!("Error: {error}");
        }

        if let Some(path) = msg.get_file(context) {
            let bytes = get_filebytes(context, &path).await?;
            ret += &format!(
                "\nFile: {}, name: {}, {} bytes\n",
                path.display(),
                msg.get_filename().unwrap_or_default(),
                bytes
            );
        }

        if msg.viewtype != Viewtype::Text {
            ret += "Type: ";
            ret += &format!("{}", msg.viewtype);
            ret += "\n";
            ret += &format!("Mimetype: {}\n", &msg.get_filemime().unwrap_or_default());
        }
        let w = msg.param.get_int(Param::Width).unwrap_or_default();
        let h = msg.param.get_int(Param::Height).unwrap_or_default();
        if w != 0 || h != 0 {
            ret += &format!("Dimension: {w} x {h}\n",);
        }
        let duration = msg.param.get_int(Param::Duration).unwrap_or_default();
        if duration != 0 {
            ret += &format!("Duration: {duration} ms\n",);
        }
        if !msg.rfc724_mid.is_empty() {
            ret += &format!("\nMessage-ID: {}", msg.rfc724_mid);

            let server_urls = Self::get_info_server_urls(context, msg.rfc724_mid).await?;
            for server_url in server_urls {
                // Format as RFC 5092 relative IMAP URL.
                ret += &format!("\nServer-URL: {server_url}");
            }
        }
        let hop_info = self.hop_info(context).await?;

        ret += "\n\n";
        if hop_info.is_empty() {
            ret += "No Hop Info";
        } else {
            ret += &hop_info;
        }

        Ok(ret)
    }
}

impl std::fmt::Display for MsgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Msg#{}", self.0)
    }
}

/// Allow converting [MsgId] to an SQLite type.
///
/// This allows you to directly store [MsgId] into the database.
///
/// # Errors
///
/// This **does** ensure that no special message IDs are written into
/// the database and the conversion will fail if this is not the case.
impl rusqlite::types::ToSql for MsgId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        if self.0 <= DC_MSG_ID_LAST_SPECIAL {
            return Err(rusqlite::Error::ToSqlConversionFailure(
                format_err!("Invalid MsgId {}", self.0).into(),
            ));
        }
        let val = rusqlite::types::Value::Integer(i64::from(self.0));
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

/// Allow converting an SQLite integer directly into [MsgId].
impl rusqlite::types::FromSql for MsgId {
    fn column_result(value: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        // Would be nice if we could use match here, but alas.
        i64::column_result(value).and_then(|val| {
            if 0 <= val && val <= i64::from(u32::MAX) {
                Ok(MsgId::new(val as u32))
            } else {
                Err(rusqlite::types::FromSqlError::OutOfRange(val))
            }
        })
    }
}

#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    FromPrimitive,
    ToPrimitive,
    FromSql,
    ToSql,
    Serialize,
    Deserialize,
    Default,
)]
#[repr(u8)]
pub(crate) enum MessengerMessage {
    #[default]
    No = 0,
    Yes = 1,

    /// No, but reply to messenger message.
    Reply = 2,
}

/// An object representing a single message in memory.
/// The message object is not updated.
/// If you want an update, you have to recreate the object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Message {
    /// Message ID.
    pub(crate) id: MsgId,

    /// `From:` contact ID.
    pub(crate) from_id: ContactId,

    /// ID of the first contact in the `To:` header.
    pub(crate) to_id: ContactId,

    /// ID of the chat message belongs to.
    pub(crate) chat_id: ChatId,

    /// Type of the message.
    pub(crate) viewtype: Viewtype,

    /// State of the message.
    pub(crate) state: MessageState,
    pub(crate) download_state: DownloadState,

    /// Whether the message is hidden.
    pub(crate) hidden: bool,
    pub(crate) timestamp_sort: i64,
    pub(crate) timestamp_sent: i64,
    pub(crate) timestamp_rcvd: i64,
    pub(crate) ephemeral_timer: EphemeralTimer,
    pub(crate) ephemeral_timestamp: i64,
    pub(crate) text: String,
    /// Text that is added to the end of Message.text
    ///
    /// Currently used for adding the download information on pre-messages
    pub(crate) additional_text: String,

    /// Message subject.
    ///
    /// If empty, a default subject will be generated when sending.
    pub(crate) subject: String,

    /// `Message-ID` header value.
    pub(crate) rfc724_mid: String,
    /// `Message-ID` header value of the pre-message, if any.
    pub(crate) pre_rfc724_mid: String,

    /// `In-Reply-To` header value.
    pub(crate) in_reply_to: Option<String>,
    pub(crate) is_dc_message: MessengerMessage,
    pub(crate) original_msg_id: MsgId,
    pub(crate) mime_modified: bool,
    pub(crate) chat_visibility: ChatVisibility,
    pub(crate) chat_blocked: Blocked,
    pub(crate) location_id: u32,
    pub(crate) error: Option<String>,
    pub(crate) param: Params,
}

impl Message {
    /// Creates a new message with given view type.
    pub fn new(viewtype: Viewtype) -> Self {
        Message {
            viewtype,
            rfc724_mid: create_outgoing_rfc724_mid(),
            ..Default::default()
        }
    }

    /// Creates a new message with Viewtype::Text.
    pub fn new_text(text: String) -> Self {
        Message {
            viewtype: Viewtype::Text,
            text,
            rfc724_mid: create_outgoing_rfc724_mid(),
            ..Default::default()
        }
    }

    /// Loads message with given ID from the database.
    ///
    /// Returns an error if the message does not exist.
    pub async fn load_from_db(context: &Context, id: MsgId) -> Result<Message> {
        let message = Self::load_from_db_optional(context, id)
            .await?
            .with_context(|| format!("Message {id} does not exist"))?;
        Ok(message)
    }

    /// Loads message with given ID from the database.
    ///
    /// Returns `None` if the message does not exist.
    pub async fn load_from_db_optional(context: &Context, id: MsgId) -> Result<Option<Message>> {
        ensure!(
            !id.is_special(),
            "Can not load special message ID {id} from DB"
        );
        let mut msg = context
            .sql
            .query_row_optional(
                "SELECT
                    m.id AS id,
                    rfc724_mid AS rfc724mid,
                    pre_rfc724_mid AS pre_rfc724mid,
                    m.mime_in_reply_to AS mime_in_reply_to,
                    m.chat_id AS chat_id,
                    m.from_id AS from_id,
                    m.to_id AS to_id,
                    m.timestamp AS timestamp,
                    m.timestamp_sent AS timestamp_sent,
                    m.timestamp_rcvd AS timestamp_rcvd,
                    m.ephemeral_timer AS ephemeral_timer,
                    m.ephemeral_timestamp AS ephemeral_timestamp,
                    m.type AS type,
                    m.state AS state,
                    mdns.msg_id AS mdn_msg_id,
                    m.download_state AS download_state,
                    m.error AS error,
                    m.msgrmsg AS msgrmsg,
                    m.starred AS original_msg_id,
                    m.mime_modified AS mime_modified,
                    m.txt AS txt,
                    m.subject AS subject,
                    m.param AS param,
                    m.hidden AS hidden,
                    m.location_id AS location,
                    c.archived AS visibility,
                    c.blocked AS blocked
                 FROM msgs m
                 LEFT JOIN chats c ON c.id=m.chat_id
                 LEFT JOIN msgs_mdns mdns ON mdns.msg_id=m.id
                 WHERE m.id=? AND chat_id!=3
                 LIMIT 1",
                (id,),
                |row| {
                    let state: MessageState = row.get("state")?;
                    let mdn_msg_id: Option<MsgId> = row.get("mdn_msg_id")?;
                    let text = match row.get_ref("txt")? {
                        rusqlite::types::ValueRef::Text(buf) => {
                            match String::from_utf8(buf.to_vec()) {
                                Ok(t) => t,
                                Err(_) => {
                                    warn!(
                                        context,
                                        concat!(
                                            "dc_msg_load_from_db: could not get ",
                                            "text column as non-lossy utf8 id {}"
                                        ),
                                        id
                                    );
                                    String::from_utf8_lossy(buf).into_owned()
                                }
                            }
                        }
                        _ => String::new(),
                    };
                    let msg = Message {
                        id: row.get("id")?,
                        rfc724_mid: row.get::<_, String>("rfc724mid")?,
                        pre_rfc724_mid: row.get::<_, String>("pre_rfc724mid")?,
                        in_reply_to: row
                            .get::<_, Option<String>>("mime_in_reply_to")?
                            .and_then(|in_reply_to| parse_message_id(&in_reply_to).ok()),
                        chat_id: row.get("chat_id")?,
                        from_id: row.get("from_id")?,
                        to_id: row.get("to_id")?,
                        timestamp_sort: row.get("timestamp")?,
                        timestamp_sent: row.get("timestamp_sent")?,
                        timestamp_rcvd: row.get("timestamp_rcvd")?,
                        ephemeral_timer: row.get("ephemeral_timer")?,
                        ephemeral_timestamp: row.get("ephemeral_timestamp")?,
                        viewtype: row.get("type").unwrap_or_default(),
                        state: state.with_mdns(mdn_msg_id.is_some()),
                        download_state: row.get("download_state")?,
                        error: Some(row.get::<_, String>("error")?)
                            .filter(|error| !error.is_empty()),
                        is_dc_message: row.get("msgrmsg")?,
                        original_msg_id: row.get("original_msg_id")?,
                        mime_modified: row.get("mime_modified")?,
                        text,
                        additional_text: String::new(),
                        subject: row.get("subject")?,
                        param: row.get::<_, String>("param")?.parse().unwrap_or_default(),
                        hidden: row.get("hidden")?,
                        location_id: row.get("location")?,
                        chat_visibility: row.get::<_, Option<_>>("visibility")?.unwrap_or_default(),
                        chat_blocked: row
                            .get::<_, Option<Blocked>>("blocked")?
                            .unwrap_or_default(),
                    };
                    Ok(msg)
                },
            )
            .await
            .with_context(|| format!("failed to load message {id} from the database"))?;

        if let Some(msg) = &mut msg {
            msg.additional_text =
                Self::get_additional_text(context, msg.download_state, &msg.param).await?;
        }

        Ok(msg)
    }

    /// Returns additional text which is appended to the message's text field
    /// when it is loaded from the database.
    /// Currently this is used to add infomation to pre-messages of what the download will be and how large it is
    async fn get_additional_text(
        context: &Context,
        download_state: DownloadState,
        param: &Params,
    ) -> Result<String> {
        if download_state != DownloadState::Done {
            let file_size = param
                .get(Param::PostMessageFileBytes)
                .and_then(|s| s.parse().ok())
                .map(|file_size: usize| format_size(file_size, BINARY))
                .unwrap_or("?".to_owned());
            let viewtype = param
                .get_i64(Param::PostMessageViewtype)
                .and_then(Viewtype::from_i64)
                .unwrap_or(Viewtype::Unknown);
            let file_name = param
                .get(Param::Filename)
                .map(sanitize_filename)
                .unwrap_or("?".to_owned());

            return match viewtype {
                Viewtype::File => Ok(format!(" [{file_name} – {file_size}]")),
                _ => {
                    let translated_viewtype = viewtype.to_locale_string(context).await;
                    Ok(format!(" [{translated_viewtype} – {file_size}]"))
                }
            };
        }
        Ok(String::new())
    }

    /// Returns the MIME type of an attached file if it exists.
    ///
    /// If the MIME type is not known, the function guesses the MIME type
    /// from the extension. `application/octet-stream` is used as a fallback
    /// if MIME type is not known, but `None` is only returned if no file
    /// is attached.
    pub fn get_filemime(&self) -> Option<String> {
        if let Some(m) = self.param.get(Param::MimeType) {
            return Some(m.to_string());
        } else if self.param.exists(Param::File) {
            if let Some((_, mime)) = guess_msgtype_from_suffix(self) {
                return Some(mime.to_string());
            }
            // we have a file but no mimetype, let's use a generic one
            return Some("application/octet-stream".to_string());
        }
        // no mimetype and no file
        None
    }

    /// Returns the full path to the file associated with a message.
    pub fn get_file(&self, context: &Context) -> Option<PathBuf> {
        self.param.get_file_path(context).unwrap_or(None)
    }

    /// Returns vector of vcards if the file has a vCard attachment.
    pub async fn vcard_contacts(&self, context: &Context) -> Result<Vec<VcardContact>> {
        if self.viewtype != Viewtype::Vcard {
            return Ok(Vec::new());
        }

        let path = self
            .get_file(context)
            .context("vCard message does not have an attachment")?;
        let bytes = tokio::fs::read(path).await?;
        let vcard_contents = std::str::from_utf8(&bytes).context("vCard is not a valid UTF-8")?;
        Ok(parse_vcard(vcard_contents))
    }

    /// Save file copy at the user-provided path.
    pub async fn save_file(&self, context: &Context, path: &Path) -> Result<()> {
        let path_src = self.get_file(context).context("No file")?;
        let mut src = fs::OpenOptions::new().read(true).open(path_src).await?;
        let mut dst = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .await?;
        io::copy(&mut src, &mut dst).await?;
        Ok(())
    }

    /// If message is an image or gif, set Param::Width and Param::Height
    pub(crate) async fn try_calc_and_set_dimensions(&mut self, context: &Context) -> Result<()> {
        if self.viewtype.has_file() {
            let file_param = self.param.get_file_path(context)?;
            if let Some(path_and_filename) = file_param
                && matches!(
                    self.viewtype,
                    Viewtype::Image | Viewtype::Gif | Viewtype::Sticker
                )
                && !self.param.exists(Param::Width)
            {
                let buf = read_file(context, &path_and_filename).await?;

                match get_filemeta(&buf) {
                    Ok((width, height)) => {
                        self.param.set_int(Param::Width, width as i32);
                        self.param.set_int(Param::Height, height as i32);
                    }
                    Err(err) => {
                        self.param.set_int(Param::Width, 0);
                        self.param.set_int(Param::Height, 0);
                        warn!(
                            context,
                            "Failed to get width and height for {}: {err:#}.",
                            path_and_filename.display()
                        );
                    }
                }

                if !self.id.is_unset() {
                    self.update_param(context).await?;
                }
            }
        }
        Ok(())
    }

    /// Check if a message has a POI location bound to it.
    /// These locations are also returned by [`location::get_range()`].
    /// The UI may decide to display a special icon beside such messages.
    ///
    /// [`location::get_range()`]: crate::location::get_range
    pub fn has_location(&self) -> bool {
        self.location_id != 0
    }

    /// Set any location that should be bound to the message object.
    /// The function is useful to add a marker to the map
    /// at a position different from the self-location.
    /// You should not call this function
    /// if you want to bind the current self-location to a message;
    /// this is done by [`location::set()`] and [`send_locations_to_chat()`].
    ///
    /// Typically results in the event [`LocationChanged`] with
    /// `contact_id` set to [`ContactId::SELF`].
    ///
    /// `latitude` is the North-south position of the location.
    /// `longitude` is the East-west position of the location.
    ///
    /// [`location::set()`]: crate::location::set
    /// [`send_locations_to_chat()`]: crate::location::send_locations_to_chat
    /// [`LocationChanged`]: crate::events::EventType::LocationChanged
    pub fn set_location(&mut self, latitude: f64, longitude: f64) {
        if latitude == 0.0 && longitude == 0.0 {
            return;
        }

        self.param.set_float(Param::SetLatitude, latitude);
        self.param.set_float(Param::SetLongitude, longitude);
    }

    /// Returns the message timestamp for display in the UI
    /// as a unix timestamp in seconds.
    pub fn get_timestamp(&self) -> i64 {
        if 0 != self.timestamp_sent {
            self.timestamp_sent
        } else {
            self.timestamp_sort
        }
    }

    /// Returns the message ID.
    pub fn get_id(&self) -> MsgId {
        self.id
    }

    /// Returns the rfc724 message ID
    /// May be empty
    pub fn rfc724_mid(&self) -> &str {
        &self.rfc724_mid
    }

    /// Returns the ID of the contact who wrote the message.
    pub fn get_from_id(&self) -> ContactId {
        self.from_id
    }

    /// Returns the chat ID.
    pub fn get_chat_id(&self) -> ChatId {
        self.chat_id
    }

    /// Returns the type of the message.
    pub fn get_viewtype(&self) -> Viewtype {
        self.viewtype
    }

    /// Forces the message to **keep** [Viewtype::Sticker]
    /// e.g the message will not be converted to a [Viewtype::Image].
    pub fn force_sticker(&mut self) {
        self.param.set_int(Param::ForceSticker, 1);
    }

    /// Returns the state of the message.
    pub fn get_state(&self) -> MessageState {
        self.state
    }

    /// Returns the message receive time as a unix timestamp in seconds.
    pub fn get_received_timestamp(&self) -> i64 {
        self.timestamp_rcvd
    }

    /// Returns the timestamp of the message for sorting.
    pub fn get_sort_timestamp(&self) -> i64 {
        self.timestamp_sort
    }

    /// Returns the text of the message.
    ///
    /// Currently this includes `additional_text`, but this may change in future, when the UIs show
    /// the necessary info themselves.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn get_text(&self) -> String {
        self.text.clone() + &self.additional_text
    }

    /// Returns message subject.
    pub fn get_subject(&self) -> &str {
        &self.subject
    }

    /// Returns original filename (as shown in chat).
    ///
    /// To get the full path, use [`Self::get_file()`].
    pub fn get_filename(&self) -> Option<String> {
        if let Some(name) = self.param.get(Param::Filename) {
            return Some(sanitize_filename(name));
        }
        self.param
            .get(Param::File)
            .and_then(|file| Path::new(file).file_name())
            .map(|name| sanitize_filename(&name.to_string_lossy()))
    }

    /// Returns the size of the file in bytes, if applicable.
    /// If message is a pre-message, then this returns the size of the file to be downloaded.
    pub async fn get_filebytes(&self, context: &Context) -> Result<Option<u64>> {
        if self.download_state != DownloadState::Done
            && let Some(file_size) = self
                .param
                .get(Param::PostMessageFileBytes)
                .and_then(|s| s.parse().ok())
        {
            return Ok(Some(file_size));
        }
        if let Some(path) = self.param.get_file_path(context)? {
            Ok(Some(get_filebytes(context, &path).await.with_context(
                || format!("failed to get {} size in bytes", path.display()),
            )?))
        } else {
            Ok(None)
        }
    }

    /// If message is a Pre-Message,
    /// then this returns the viewtype it will have when it is downloaded.
    #[cfg(test)]
    pub(crate) fn get_post_message_viewtype(&self) -> Option<Viewtype> {
        if self.download_state != DownloadState::Done {
            return self
                .param
                .get_i64(Param::PostMessageViewtype)
                .and_then(Viewtype::from_i64);
        }
        None
    }

    /// Returns width of associated image or video file.
    pub fn get_width(&self) -> i32 {
        self.param.get_int(Param::Width).unwrap_or_default()
    }

    /// Returns height of associated image or video file.
    pub fn get_height(&self) -> i32 {
        self.param.get_int(Param::Height).unwrap_or_default()
    }

    /// Returns duration of associated audio or video file.
    pub fn get_duration(&self) -> i32 {
        self.param.get_int(Param::Duration).unwrap_or_default()
    }

    /// Returns true if padlock indicating message encryption should be displayed in the UI.
    pub fn get_showpadlock(&self) -> bool {
        self.param.get_int(Param::GuaranteeE2ee).unwrap_or_default() != 0
            || self.from_id == ContactId::DEVICE
    }

    /// Returns true if message is auto-generated.
    pub fn is_bot(&self) -> bool {
        self.param.get_bool(Param::Bot).unwrap_or_default()
    }

    /// Return the ephemeral timer duration for a message.
    pub fn get_ephemeral_timer(&self) -> EphemeralTimer {
        self.ephemeral_timer
    }

    /// Returns the timestamp of the epehemeral message removal.
    pub fn get_ephemeral_timestamp(&self) -> i64 {
        self.ephemeral_timestamp
    }

    /// Returns message summary for display in the search results.
    pub async fn get_summary(&self, context: &Context, chat: Option<&Chat>) -> Result<Summary> {
        let chat_loaded: Chat;
        let chat = if let Some(chat) = chat {
            chat
        } else {
            let chat = Chat::load_from_db(context, self.chat_id).await?;
            chat_loaded = chat;
            &chat_loaded
        };

        let contact = if self.from_id != ContactId::SELF {
            match chat.typ {
                Chattype::Group | Chattype::Mailinglist => {
                    Some(Contact::get_by_id(context, self.from_id).await?)
                }
                Chattype::Single | Chattype::OutBroadcast | Chattype::InBroadcast => None,
            }
        } else {
            None
        };

        Summary::new(context, self, chat, contact.as_ref()).await
    }

    // It's a little unfortunate that the UI has to first call `dc_msg_get_override_sender_name` and then if it was `NULL`, call
    // `dc_contact_get_display_name` but this was the best solution:
    // - We could load a Contact struct from the db here to call `dc_get_display_name` instead of returning `None`, but then we had a db
    //   call every time (and this fn is called a lot while the user is scrolling through a group), so performance would be bad
    // - We could pass both a Contact struct and a Message struct in the FFI, but at least on Android we would need to handle raw
    //   C-data in the Java code (i.e. a `long` storing a C pointer)
    // - We can't make a param `SenderDisplayname` for messages as sometimes the display name of a contact changes, and we want to show
    //   the same display name over all messages from the same sender.
    /// Returns the name that should be shown over the message instead of the contact display ame.
    pub fn get_override_sender_name(&self) -> Option<String> {
        self.param
            .get(Param::OverrideSenderDisplayname)
            .map(|name| name.to_string())
    }

    // Exposing this function over the ffi instead of get_override_sender_name() would mean that at least Android Java code has
    // to handle raw C-data (as it is done for msg_get_summary())
    pub(crate) fn get_sender_name(&self, contact: &Contact) -> String {
        self.get_override_sender_name()
            .unwrap_or_else(|| contact.get_display_name().to_string())
    }

    /// Returns true if a message has a deviating timestamp.
    ///
    /// A message has a deviating timestamp when it is sent on
    /// another day as received/sorted by.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn has_deviating_timestamp(&self) -> bool {
        let cnv_to_local = gm2local_offset();
        let sort_timestamp = self.get_sort_timestamp() + cnv_to_local;
        let send_timestamp = self.get_timestamp() + cnv_to_local;

        sort_timestamp / 86400 != send_timestamp / 86400
    }

    /// Returns true if the message was successfully delivered to the outgoing server or even
    /// received a read receipt.
    pub fn is_sent(&self) -> bool {
        self.state >= MessageState::OutDelivered
    }

    /// Returns true if the message is a forwarded message.
    pub fn is_forwarded(&self) -> bool {
        self.param.get_int(Param::Forwarded).is_some()
    }

    /// Returns true if the message is edited.
    pub fn is_edited(&self) -> bool {
        self.param.get_bool(Param::IsEdited).unwrap_or_default()
    }

    /// Returns true if the message is an informational message.
    pub fn is_info(&self) -> bool {
        let cmd = self.param.get_cmd();
        self.from_id == ContactId::INFO
            || self.to_id == ContactId::INFO
            || cmd != SystemMessage::Unknown && cmd != SystemMessage::AutocryptSetupMessage
    }

    /// Returns the type of an informational message.
    pub fn get_info_type(&self) -> SystemMessage {
        self.param.get_cmd()
    }

    /// Return the contact ID of the profile to open when tapping the info message.
    pub async fn get_info_contact_id(&self, context: &Context) -> Result<Option<ContactId>> {
        match self.param.get_cmd() {
            SystemMessage::GroupNameChanged
            | SystemMessage::GroupDescriptionChanged
            | SystemMessage::GroupImageChanged
            | SystemMessage::EphemeralTimerChanged => {
                if self.from_id != ContactId::INFO {
                    Ok(Some(self.from_id))
                } else {
                    Ok(None)
                }
            }

            SystemMessage::MemberAddedToGroup | SystemMessage::MemberRemovedFromGroup => {
                if let Some(contact_i32) = self.param.get_int(Param::ContactAddedRemoved) {
                    let contact_id = ContactId::new(contact_i32.try_into()?);
                    if contact_id == ContactId::SELF
                        || Contact::real_exists_by_id(context, contact_id).await?
                    {
                        Ok(Some(contact_id))
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }

            SystemMessage::AutocryptSetupMessage
            | SystemMessage::SecurejoinMessage
            | SystemMessage::LocationStreamingEnabled
            | SystemMessage::LocationOnly
            | SystemMessage::ChatE2ee
            | SystemMessage::ChatProtectionEnabled
            | SystemMessage::ChatProtectionDisabled
            | SystemMessage::InvalidUnencryptedMail
            | SystemMessage::SecurejoinWait
            | SystemMessage::SecurejoinWaitTimeout
            | SystemMessage::MultiDeviceSync
            | SystemMessage::WebxdcStatusUpdate
            | SystemMessage::WebxdcInfoMessage
            | SystemMessage::IrohNodeAddr
            | SystemMessage::CallAccepted
            | SystemMessage::CallEnded
            | SystemMessage::Unknown => Ok(None),
        }
    }

    /// Returns true if the message is a system message.
    pub fn is_system_message(&self) -> bool {
        let cmd = self.param.get_cmd();
        cmd != SystemMessage::Unknown
    }

    /// Returns true if the message is an Autocrypt Setup Message.
    pub fn is_setupmessage(&self) -> bool {
        if self.viewtype != Viewtype::File {
            return false;
        }

        self.param.get_cmd() == SystemMessage::AutocryptSetupMessage
    }

    /// Returns the first characters of the setup code.
    ///
    /// This is used to pre-fill the first entry field of the setup code.
    pub async fn get_setupcodebegin(&self, context: &Context) -> Option<String> {
        if !self.is_setupmessage() {
            return None;
        }

        if let Some(filename) = self.get_file(context)
            && let Ok(ref buf) = read_file(context, &filename).await
            && let Ok((typ, headers, _)) = split_armored_data(buf)
            && typ == pgp::armor::BlockType::Message
        {
            return headers.get(crate::pgp::HEADER_SETUPCODE).cloned();
        }

        None
    }

    /// Sets or unsets message text.
    pub fn set_text(&mut self, text: String) {
        self.text = text;
    }

    /// Sets the email's subject. If it's empty, a default subject
    /// will be used (e.g. `Message from Alice` or `Re: <last subject>`).
    pub fn set_subject(&mut self, subject: String) {
        self.subject = subject;
    }

    /// Sets the file associated with a message, deduplicating files with the same name.
    ///
    /// If `name` is Some, it is used as the file name
    /// and the actual current name of the file is ignored.
    ///
    /// If the source file is already in the blobdir, it will be renamed,
    /// otherwise it will be copied to the blobdir first.
    ///
    /// In order to deduplicate files that contain the same data,
    /// the file will be named `<hash>.<extension>`, e.g. `ce940175885d7b78f7b7e9f1396611f.jpg`.
    ///
    /// NOTE:
    /// - This function will rename the file. To get the new file path, call `get_file()`.
    /// - The file must not be modified after this function was called.
    pub fn set_file_and_deduplicate(
        &mut self,
        context: &Context,
        file: &Path,
        name: Option<&str>,
        filemime: Option<&str>,
    ) -> Result<()> {
        let name = if let Some(name) = name {
            name.to_string()
        } else {
            file.file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "unknown_file".to_string())
        };

        let blob = BlobObject::create_and_deduplicate(context, file, Path::new(&name))?;
        self.param.set(Param::File, blob.as_name());

        self.param.set(Param::Filename, name);
        self.param.set_optional(Param::MimeType, filemime);

        Ok(())
    }

    /// Creates a new blob and sets it as a file associated with a message.
    ///
    /// In order to deduplicate files that contain the same data,
    /// the file will be named `<hash>.<extension>`, e.g. `ce940175885d7b78f7b7e9f1396611f.jpg`.
    ///
    /// NOTE: The file must not be modified after this function was called.
    pub fn set_file_from_bytes(
        &mut self,
        context: &Context,
        name: &str,
        data: &[u8],
        filemime: Option<&str>,
    ) -> Result<()> {
        let blob = BlobObject::create_and_deduplicate_from_bytes(context, data, name)?;
        self.param.set(Param::Filename, name);
        self.param.set(Param::File, blob.as_name());
        self.param.set_optional(Param::MimeType, filemime);

        Ok(())
    }

    /// Makes message a vCard-containing message using the specified contacts.
    pub async fn make_vcard(&mut self, context: &Context, contacts: &[ContactId]) -> Result<()> {
        ensure!(
            matches!(self.viewtype, Viewtype::File | Viewtype::Vcard),
            "Wrong viewtype for vCard: {}",
            self.viewtype,
        );
        let vcard = contact::make_vcard(context, contacts).await?;
        self.set_file_from_bytes(context, "vcard.vcf", vcard.as_bytes(), None)
    }

    /// Updates message state from the vCard attachment.
    pub(crate) async fn try_set_vcard(&mut self, context: &Context, path: &Path) -> Result<()> {
        let vcard = fs::read(path)
            .await
            .with_context(|| format!("Could not read {path:?}"))?;
        if let Some(summary) = get_vcard_summary(&vcard) {
            self.param.set(Param::Summary1, summary);
        } else {
            warn!(context, "try_set_vcard: Not a valid DeltaChat vCard.");
            self.viewtype = Viewtype::File;
        }
        Ok(())
    }

    /// Set different sender name for a message.
    /// This overrides the name set by the `set_config()`-option `displayname`.
    pub fn set_override_sender_name(&mut self, name: Option<String>) {
        self.param
            .set_optional(Param::OverrideSenderDisplayname, name);
    }

    /// Sets the dimensions of associated image or video file.
    pub fn set_dimension(&mut self, width: i32, height: i32) {
        self.param.set_int(Param::Width, width);
        self.param.set_int(Param::Height, height);
    }

    /// Sets the duration of associated audio or video file.
    pub fn set_duration(&mut self, duration: i32) {
        self.param.set_int(Param::Duration, duration);
    }

    /// Marks the message as reaction.
    pub(crate) fn set_reaction(&mut self) {
        self.param.set_int(Param::Reaction, 1);
    }

    /// Changes the message width, height or duration,
    /// and stores it into the database.
    pub async fn latefiling_mediasize(
        &mut self,
        context: &Context,
        width: i32,
        height: i32,
        duration: i32,
    ) -> Result<()> {
        if width > 0 && height > 0 {
            self.param.set_int(Param::Width, width);
            self.param.set_int(Param::Height, height);
        }
        if duration > 0 {
            self.param.set_int(Param::Duration, duration);
        }
        self.update_param(context).await?;
        Ok(())
    }

    /// Sets message quote text.
    ///
    /// If `text` is `Some((text_str, protect))`, `protect` specifies whether `text_str` should only
    /// be sent encrypted. If it should, but the message is unencrypted, `text_str` is replaced with
    /// "...".
    pub fn set_quote_text(&mut self, text: Option<(String, bool)>) {
        let Some((text, protect)) = text else {
            self.param.remove(Param::Quote);
            self.param.remove(Param::ProtectQuote);
            return;
        };
        self.param.set(Param::Quote, text);
        self.param.set_optional(
            Param::ProtectQuote,
            match protect {
                true => Some("1"),
                false => None,
            },
        );
    }

    /// Sets message quote.
    ///
    /// Message-Id is used to set Reply-To field, message text is used for quote.
    ///
    /// Encryption is required if quoted message was encrypted.
    ///
    /// The message itself is not required to exist in the database,
    /// it may even be deleted from the database by the time the message is prepared.
    pub async fn set_quote(&mut self, context: &Context, quote: Option<&Message>) -> Result<()> {
        if let Some(quote) = quote {
            ensure!(
                !quote.rfc724_mid.is_empty(),
                "Message without Message-Id cannot be quoted"
            );
            self.in_reply_to = Some(quote.rfc724_mid.clone());

            let text = quote.get_text();
            let text = if text.is_empty() {
                // Use summary, similar to "Image" to avoid sending empty quote.
                quote
                    .get_summary(context, None)
                    .await?
                    .truncated_text(500)
                    .to_string()
            } else {
                text
            };
            self.set_quote_text(Some((
                text,
                quote
                    .param
                    .get_bool(Param::GuaranteeE2ee)
                    .unwrap_or_default(),
            )));
        } else {
            self.in_reply_to = None;
            self.set_quote_text(None);
        }

        Ok(())
    }

    /// Returns quoted message text, if any.
    pub fn quoted_text(&self) -> Option<String> {
        self.param.get(Param::Quote).map(|s| s.to_string())
    }

    /// Returns quoted message, if any.
    pub async fn quoted_message(&self, context: &Context) -> Result<Option<Message>> {
        if self.param.get(Param::Quote).is_some() && !self.is_forwarded() {
            return self.parent(context).await;
        }
        Ok(None)
    }

    /// Returns parent message according to the `In-Reply-To` header
    /// if it exists in the database and is not trashed.
    ///
    /// `References` header is not taken into account.
    pub async fn parent(&self, context: &Context) -> Result<Option<Message>> {
        if let Some(in_reply_to) = &self.in_reply_to
            && let Some(msg_id) = rfc724_mid_exists(context, in_reply_to).await?
        {
            let msg = Message::load_from_db_optional(context, msg_id).await?;
            return Ok(msg);
        }
        Ok(None)
    }

    /// Returns original message ID for message from "Saved Messages".
    pub async fn get_original_msg_id(&self, context: &Context) -> Result<Option<MsgId>> {
        if !self.original_msg_id.is_special()
            && let Some(msg) = Message::load_from_db_optional(context, self.original_msg_id).await?
        {
            return if msg.chat_id.is_trash() {
                Ok(None)
            } else {
                Ok(Some(msg.id))
            };
        }
        Ok(None)
    }

    /// Check if the message was saved and returns the corresponding message inside "Saved Messages".
    /// UI can use this to show a symbol beside the message, indicating it was saved.
    /// The message can be un-saved by deleting the returned message.
    pub async fn get_saved_msg_id(&self, context: &Context) -> Result<Option<MsgId>> {
        let res: Option<MsgId> = context
            .sql
            .query_get_value(
                "SELECT id FROM msgs WHERE starred=? AND chat_id!=?",
                (self.id, DC_CHAT_ID_TRASH),
            )
            .await?;
        Ok(res)
    }

    /// Force the message to be sent in plain text.
    pub fn force_plaintext(&mut self) {
        self.param.set_int(Param::ForcePlaintext, 1);
    }

    /// Updates `param` column of the message in the database without changing other columns.
    pub async fn update_param(&self, context: &Context) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE msgs SET param=? WHERE id=?;",
                (self.param.to_string(), self.id),
            )
            .await?;
        Ok(())
    }

    /// Gets the error status of the message.
    ///
    /// A message can have an associated error status if something went wrong when sending or
    /// receiving message itself.  The error status is free-form text and should not be further parsed,
    /// rather it's presence is meant to indicate *something* went wrong with the message and the
    /// text of the error is detailed information on what.
    ///
    /// Some common reasons error can be associated with messages are:
    /// * Lack of valid signature on an e2ee message, usually for received messages.
    /// * Failure to decrypt an e2ee message, usually for received messages.
    /// * When a message could not be delivered to one or more recipients the non-delivery
    ///   notification text can be stored in the error status.
    pub fn error(&self) -> Option<String> {
        self.error.clone()
    }
}

/// State of the message.
/// For incoming messages, stores the information on whether the message was read or not.
/// For outgoing message, the message could be pending, already delivered or confirmed.
#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    FromPrimitive,
    ToPrimitive,
    ToSql,
    FromSql,
    Serialize,
    Deserialize,
)]
#[repr(u32)]
pub enum MessageState {
    /// Undefined message state.
    #[default]
    Undefined = 0,

    /// Incoming *fresh* message. Fresh messages are neither noticed
    /// nor seen and are typically shown in notifications.
    InFresh = 10,

    /// Incoming *noticed* message. E.g. chat opened but message not
    /// yet read - noticed messages are not counted as unread but did
    /// not marked as read nor resulted in MDNs.
    InNoticed = 13,

    /// Incoming message, really *seen* by the user. Marked as read on
    /// IMAP and MDN may be sent.
    InSeen = 16,

    /// For files which need time to be prepared before they can be
    /// sent, the message enters this state before
    /// OutPending.
    OutPreparing = 18,

    /// Message saved as draft.
    OutDraft = 19,

    /// The user has pressed the "send" button but the message is not
    /// yet sent and is pending in some way. Maybe we're offline (no
    /// checkmark).
    OutPending = 20,

    /// *Unrecoverable* error (*recoverable* errors result in pending
    /// messages).
    OutFailed = 24,

    /// Outgoing message successfully delivered to server (one
    /// checkmark). Note, that already delivered messages may get into
    /// the OutFailed state if we get such a hint from the server.
    OutDelivered = 26,

    /// Outgoing message read by the recipient (two checkmarks; this
    /// requires goodwill on the receiver's side). Not used in the db for new messages.
    OutMdnRcvd = 28,
}

impl std::fmt::Display for MessageState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Undefined => "Undefined",
                Self::InFresh => "Fresh",
                Self::InNoticed => "Noticed",
                Self::InSeen => "Seen",
                Self::OutPreparing => "Preparing",
                Self::OutDraft => "Draft",
                Self::OutPending => "Pending",
                Self::OutFailed => "Failed",
                Self::OutDelivered => "Delivered",
                Self::OutMdnRcvd => "Read",
            }
        )
    }
}

impl MessageState {
    /// Returns true if the message can transition to `OutFailed` state from the current state.
    pub fn can_fail(self) -> bool {
        use MessageState::*;
        matches!(
            self,
            OutPreparing | OutPending | OutDelivered | OutMdnRcvd // OutMdnRcvd can still fail because it could be a group message and only some recipients failed.
        )
    }

    /// Returns true for any outgoing message states.
    pub fn is_outgoing(self) -> bool {
        use MessageState::*;
        matches!(
            self,
            OutPreparing | OutDraft | OutPending | OutFailed | OutDelivered | OutMdnRcvd
        )
    }

    /// Returns adjusted message state if the message has MDNs.
    pub(crate) fn with_mdns(self, has_mdns: bool) -> Self {
        if self == MessageState::OutDelivered && has_mdns {
            return MessageState::OutMdnRcvd;
        }
        self
    }
}

/// Returns contacts that sent read receipts and the time of reading.
pub async fn get_msg_read_receipts(
    context: &Context,
    msg_id: MsgId,
) -> Result<Vec<(ContactId, i64)>> {
    context
        .sql
        .query_map_vec(
            "SELECT contact_id, timestamp_sent FROM msgs_mdns WHERE msg_id=?",
            (msg_id,),
            |row| {
                let contact_id: ContactId = row.get(0)?;
                let ts: i64 = row.get(1)?;
                Ok((contact_id, ts))
            },
        )
        .await
}

/// Returns count of read receipts on message.
///
/// This view count is meant as a feedback measure for the channel owner only.
pub async fn get_msg_read_receipt_count(context: &Context, msg_id: MsgId) -> Result<usize> {
    context
        .sql
        .count("SELECT COUNT(*) FROM msgs_mdns WHERE msg_id=?", (msg_id,))
        .await
}

pub(crate) fn guess_msgtype_from_suffix(msg: &Message) -> Option<(Viewtype, &'static str)> {
    msg.param
        .get(Param::Filename)
        .or_else(|| msg.param.get(Param::File))
        .and_then(|file| guess_msgtype_from_path_suffix(Path::new(file)))
}

pub(crate) fn guess_msgtype_from_path_suffix(path: &Path) -> Option<(Viewtype, &'static str)> {
    let extension: &str = &path.extension()?.to_str()?.to_lowercase();
    let info = match extension {
        // before using viewtype other than Viewtype::File,
        // make sure, all target UIs support that type.
        //
        // it is a non-goal to support as many formats as possible in-app.
        // additional parser come at security and maintainance costs and
        // should only be added when strictly neccessary,
        // eg. when a format comes from the camera app on a significant number of devices.
        // it is okay, when eg. dragging some video from a browser results in a "File"
        // for everyone, sender as well as all receivers.
        //
        // if in doubt, it is better to default to Viewtype::File that passes handing to an external app.
        // (cmp. <https://developer.android.com/guide/topics/media/media-formats>)
        "3gp" => (Viewtype::Video, "video/3gpp"),
        "aac" => (Viewtype::Audio, "audio/aac"),
        "avi" => (Viewtype::Video, "video/x-msvideo"),
        "avif" => (Viewtype::File, "image/avif"), // supported since Android 12 / iOS 16
        "doc" => (Viewtype::File, "application/msword"),
        "docx" => (
            Viewtype::File,
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ),
        "epub" => (Viewtype::File, "application/epub+zip"),
        "flac" => (Viewtype::Audio, "audio/flac"),
        "gif" => (Viewtype::Gif, "image/gif"),
        "heic" => (Viewtype::File, "image/heic"), // supported since Android 10 / iOS 11
        "heif" => (Viewtype::File, "image/heif"), // supported since Android 10 / iOS 11
        "html" => (Viewtype::File, "text/html"),
        "htm" => (Viewtype::File, "text/html"),
        "ico" => (Viewtype::File, "image/vnd.microsoft.icon"),
        "jar" => (Viewtype::File, "application/java-archive"),
        "jpeg" => (Viewtype::Image, "image/jpeg"),
        "jpe" => (Viewtype::Image, "image/jpeg"),
        "jpg" => (Viewtype::Image, "image/jpeg"),
        "json" => (Viewtype::File, "application/json"),
        "mov" => (Viewtype::Video, "video/quicktime"),
        "m4a" => (Viewtype::Audio, "audio/m4a"),
        "mp3" => (Viewtype::Audio, "audio/mpeg"),
        "mp4" => (Viewtype::Video, "video/mp4"),
        "odp" => (
            Viewtype::File,
            "application/vnd.oasis.opendocument.presentation",
        ),
        "ods" => (
            Viewtype::File,
            "application/vnd.oasis.opendocument.spreadsheet",
        ),
        "odt" => (Viewtype::File, "application/vnd.oasis.opendocument.text"),
        "oga" => (Viewtype::Audio, "audio/ogg"),
        "ogg" => (Viewtype::Audio, "audio/ogg"),
        "ogv" => (Viewtype::File, "video/ogg"),
        "opus" => (Viewtype::File, "audio/ogg"), // supported since Android 10
        "otf" => (Viewtype::File, "font/otf"),
        "pdf" => (Viewtype::File, "application/pdf"),
        "png" => (Viewtype::Image, "image/png"),
        "ppt" => (Viewtype::File, "application/vnd.ms-powerpoint"),
        "pptx" => (
            Viewtype::File,
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ),
        "rar" => (Viewtype::File, "application/vnd.rar"),
        "rtf" => (Viewtype::File, "application/rtf"),
        "spx" => (Viewtype::File, "audio/ogg"), // Ogg Speex Profile
        "svg" => (Viewtype::File, "image/svg+xml"),
        "tgs" => (Viewtype::File, "application/x-tgsticker"),
        "tiff" => (Viewtype::File, "image/tiff"),
        "tif" => (Viewtype::File, "image/tiff"),
        "ttf" => (Viewtype::File, "font/ttf"),
        "txt" => (Viewtype::File, "text/plain"),
        "vcard" => (Viewtype::Vcard, "text/vcard"),
        "vcf" => (Viewtype::Vcard, "text/vcard"),
        "wav" => (Viewtype::Audio, "audio/wav"),
        "weba" => (Viewtype::File, "audio/webm"),
        "webm" => (Viewtype::File, "video/webm"), // not supported natively by iOS nor by SDWebImage
        "webp" => (Viewtype::Image, "image/webp"), // iOS via SDWebImage, Android since 4.0
        "wmv" => (Viewtype::Video, "video/x-ms-wmv"),
        "xdc" => (Viewtype::Webxdc, "application/webxdc+zip"),
        "xhtml" => (Viewtype::File, "application/xhtml+xml"),
        "xls" => (Viewtype::File, "application/vnd.ms-excel"),
        "xlsx" => (
            Viewtype::File,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ),
        "xml" => (Viewtype::File, "application/xml"),
        "zip" => (Viewtype::File, "application/zip"),
        _ => {
            return None;
        }
    };
    Some(info)
}

/// Get the raw mime-headers of the given message.
/// Raw headers are saved for large messages
/// that need a "Show full message..."
/// to see HTML part.
///
/// Returns an empty vector if there are no headers saved for the given message.
pub(crate) async fn get_mime_headers(context: &Context, msg_id: MsgId) -> Result<Vec<u8>> {
    let (headers, compressed) = context
        .sql
        .query_row(
            "SELECT mime_headers, mime_compressed FROM msgs WHERE id=?",
            (msg_id,),
            |row| {
                let headers = sql::row_get_vec(row, 0)?;
                let compressed: bool = row.get(1)?;
                Ok((headers, compressed))
            },
        )
        .await?;
    if compressed {
        return buf_decompress(&headers);
    }

    let headers2 = headers.clone();
    let compressed = match tokio::task::block_in_place(move || buf_compress(&headers2)) {
        Err(e) => {
            warn!(context, "get_mime_headers: buf_compress() failed: {}", e);
            return Ok(headers);
        }
        Ok(o) => o,
    };
    let update = |conn: &mut rusqlite::Connection| {
        match conn.execute(
            "\
            UPDATE msgs SET mime_headers=?, mime_compressed=1 \
            WHERE id=? AND mime_headers!='' AND mime_compressed=0",
            (compressed, msg_id),
        ) {
            Ok(rows_updated) => ensure!(rows_updated <= 1),
            Err(e) => {
                warn!(context, "get_mime_headers: UPDATE failed: {}", e);
                return Err(e.into());
            }
        }
        Ok(())
    };
    if let Err(e) = context.sql.call_write(update).await {
        warn!(
            context,
            "get_mime_headers: failed to update mime_headers: {}", e
        );
    }

    Ok(headers)
}

/// Delete a single message from the database, including references in other tables.
/// This may be called in batches; the final events are emitted in delete_msgs_locally_done() then.
pub(crate) async fn delete_msg_locally(context: &Context, msg: &Message) -> Result<()> {
    if msg.location_id > 0 {
        delete_poi_location(context, msg.location_id).await?;
    }
    let on_server = true;
    msg.id
        .trash(context, on_server)
        .await
        .with_context(|| format!("Unable to trash message {}", msg.id))?;

    context.emit_event(EventType::MsgDeleted {
        chat_id: msg.chat_id,
        msg_id: msg.id,
    });

    if msg.viewtype == Viewtype::Webxdc {
        context.emit_event(EventType::WebxdcInstanceDeleted { msg_id: msg.id });
    }

    let logging_xdc_id = context
        .debug_logging
        .read()
        .expect("RwLock is poisoned")
        .as_ref()
        .map(|dl| dl.msg_id);
    if let Some(id) = logging_xdc_id
        && id == msg.id
    {
        set_debug_logging_xdc(context, None).await?;
    }

    Ok(())
}

/// Do final events and jobs after batch deletion using calls to delete_msg_locally().
/// To avoid additional database queries, collecting data is up to the caller.
pub(crate) async fn delete_msgs_locally_done(
    context: &Context,
    msg_ids: &[MsgId],
    modified_chat_ids: HashSet<ChatId>,
) -> Result<()> {
    for modified_chat_id in modified_chat_ids {
        context.emit_msgs_changed_without_msg_id(modified_chat_id);
        chatlist_events::emit_chatlist_item_changed(context, modified_chat_id);
    }
    if !msg_ids.is_empty() {
        context.emit_msgs_changed_without_ids();
        chatlist_events::emit_chatlist_changed(context);
        // Run housekeeping to delete unused blobs.
        context
            .set_config_internal(Config::LastHousekeeping, None)
            .await?;
    }
    Ok(())
}

/// Delete messages on all devices and on IMAP.
pub async fn delete_msgs(context: &Context, msg_ids: &[MsgId]) -> Result<()> {
    delete_msgs_ex(context, msg_ids, false).await
}

/// Delete messages on all devices, on IMAP and optionally for all chat members.
/// Deleted messages are moved to the trash chat and scheduling for deletion on IMAP.
/// When deleting messages for others, all messages must be self-sent and in the same chat.
pub async fn delete_msgs_ex(
    context: &Context,
    msg_ids: &[MsgId],
    delete_for_all: bool,
) -> Result<()> {
    let mut modified_chat_ids = HashSet::new();
    let mut deleted_rfc724_mid = Vec::new();
    let mut res = Ok(());

    for &msg_id in msg_ids {
        let msg = Message::load_from_db(context, msg_id).await?;
        ensure!(
            !delete_for_all || msg.from_id == ContactId::SELF,
            "Can delete only own messages for others"
        );
        ensure!(
            !delete_for_all || msg.get_showpadlock(),
            "Cannot request deletion of unencrypted message for others"
        );

        modified_chat_ids.insert(msg.chat_id);
        deleted_rfc724_mid.push(msg.rfc724_mid.clone());

        let update_db = |trans: &mut rusqlite::Transaction| {
            let mut stmt = trans.prepare("UPDATE imap SET target='' WHERE rfc724_mid=?")?;
            stmt.execute((&msg.rfc724_mid,))?;
            if !msg.pre_rfc724_mid.is_empty() {
                stmt.execute((&msg.pre_rfc724_mid,))?;
            }
            trans.execute("DELETE FROM smtp WHERE msg_id=?", (msg_id,))?;
            trans.execute(
                "DELETE FROM download WHERE rfc724_mid=?",
                (&msg.rfc724_mid,),
            )?;
            trans.execute(
                "DELETE FROM available_post_msgs WHERE rfc724_mid=?",
                (&msg.rfc724_mid,),
            )?;
            Ok(())
        };
        if let Err(e) = context.sql.transaction(update_db).await {
            error!(context, "delete_msgs: failed to update db: {e:#}.");
            res = Err(e);
            continue;
        }
    }
    res?;

    if delete_for_all {
        ensure!(
            modified_chat_ids.len() == 1,
            "Can delete only from same chat."
        );
        if let Some(chat_id) = modified_chat_ids.iter().next() {
            let mut msg = Message::new_text("🚮".to_owned());
            // We don't want to send deletion requests in chats w/o encryption:
            // - These are usually chats with non-DC clients who won't respect deletion requests
            //   anyway and display a weird trash bin message instead.
            // - Deletion of world-visible unencrypted messages seems not very useful.
            msg.param.set_int(Param::GuaranteeE2ee, 1);
            msg.param
                .set(Param::DeleteRequestFor, deleted_rfc724_mid.join(" "));
            msg.hidden = true;
            send_msg(context, *chat_id, &mut msg).await?;
        }
    } else {
        context
            .add_sync_item(SyncData::DeleteMessages {
                msgs: deleted_rfc724_mid,
            })
            .await?;
        context.scheduler.interrupt_smtp().await;
    }

    for &msg_id in msg_ids {
        let msg = Message::load_from_db(context, msg_id).await?;
        delete_msg_locally(context, &msg).await?;
    }
    delete_msgs_locally_done(context, msg_ids, modified_chat_ids).await?;

    // Interrupt Inbox loop to start message deletion, run housekeeping and call send_sync_msg().
    context.scheduler.interrupt_inbox().await;

    Ok(())
}

/// Marks requested messages as seen.
pub async fn markseen_msgs(context: &Context, msg_ids: Vec<MsgId>) -> Result<()> {
    if msg_ids.is_empty() {
        return Ok(());
    }

    let old_last_msg_id = MsgId::new(context.get_config_u32(Config::LastMsgId).await?);
    let last_msg_id = msg_ids.iter().fold(&old_last_msg_id, std::cmp::max);
    context
        .set_config_internal(Config::LastMsgId, Some(&last_msg_id.to_u32().to_string()))
        .await?;

    let mut msgs = Vec::with_capacity(msg_ids.len());
    for &id in &msg_ids {
        if let Some(msg) = context
            .sql
            .query_row_optional(
                "SELECT
                    m.chat_id AS chat_id,
                    m.state AS state,
                    m.ephemeral_timer AS ephemeral_timer,
                    m.param AS param,
                    m.from_id AS from_id,
                    m.rfc724_mid AS rfc724_mid,
                    m.hidden AS hidden,
                    c.archived AS archived,
                    c.blocked AS blocked
                 FROM msgs m LEFT JOIN chats c ON c.id=m.chat_id
                 WHERE m.id=? AND m.chat_id>9",
                (id,),
                |row| {
                    let chat_id: ChatId = row.get("chat_id")?;
                    let state: MessageState = row.get("state")?;
                    let param: Params = row.get::<_, String>("param")?.parse().unwrap_or_default();
                    let from_id: ContactId = row.get("from_id")?;
                    let rfc724_mid: String = row.get("rfc724_mid")?;
                    let hidden: bool = row.get("hidden")?;
                    let visibility: ChatVisibility = row.get("archived")?;
                    let blocked: Option<Blocked> = row.get("blocked")?;
                    let ephemeral_timer: EphemeralTimer = row.get("ephemeral_timer")?;
                    Ok((
                        (
                            id,
                            chat_id,
                            state,
                            param,
                            from_id,
                            rfc724_mid,
                            hidden,
                            visibility,
                            blocked.unwrap_or_default(),
                        ),
                        ephemeral_timer,
                    ))
                },
            )
            .await?
        {
            msgs.push(msg);
        }
    }

    if msgs
        .iter()
        .any(|(_, ephemeral_timer)| *ephemeral_timer != EphemeralTimer::Disabled)
    {
        start_ephemeral_timers_msgids(context, &msg_ids)
            .await
            .context("failed to start ephemeral timers")?;
    }

    let mut updated_chat_ids = BTreeSet::new();
    let mut archived_chats_maybe_noticed = false;
    for (
        (
            id,
            curr_chat_id,
            curr_state,
            curr_param,
            curr_from_id,
            curr_rfc724_mid,
            curr_hidden,
            curr_visibility,
            curr_blocked,
        ),
        _curr_ephemeral_timer,
    ) in msgs
    {
        if curr_state == MessageState::InFresh || curr_state == MessageState::InNoticed {
            update_msg_state(context, id, MessageState::InSeen).await?;
            info!(context, "Seen message {}.", id);

            markseen_on_imap_table(context, &curr_rfc724_mid).await?;

            // Read receipts for system messages are never sent to contacts.
            // These messages have no place to display received read receipt
            // anyway. And since their text is locally generated,
            // quoting them is dangerous as it may contain contact names. E.g., for original message
            // "Group left by me", a read receipt will quote "Group left by <name>", and the name can
            // be a display name stored in address book rather than the name sent in the From field by
            // the user.
            //
            // We also don't send read receipts for contact requests.
            // Read receipts will not be sent even after accepting the chat.
            let to_id = if curr_blocked == Blocked::Not
                && curr_param.get_bool(Param::WantsMdn).unwrap_or_default()
                && curr_param.get_cmd() == SystemMessage::Unknown
                && context.should_send_mdns().await?
            {
                Some(curr_from_id)
            } else if context.get_config_bool(Config::BccSelf).await? {
                Some(ContactId::SELF)
            } else {
                None
            };
            if let Some(to_id) = to_id {
                context
                    .sql
                    .execute(
                        "INSERT INTO smtp_mdns (msg_id, from_id, rfc724_mid) VALUES(?, ?, ?)",
                        (id, to_id, curr_rfc724_mid),
                    )
                    .await
                    .context("failed to insert into smtp_mdns")?;
                context.scheduler.interrupt_smtp().await;
            }
            if !curr_hidden {
                updated_chat_ids.insert(curr_chat_id);
            }
        }
        archived_chats_maybe_noticed |= curr_state == MessageState::InFresh
            && !curr_hidden
            && curr_visibility == ChatVisibility::Archived;
    }

    for updated_chat_id in updated_chat_ids {
        context.emit_event(EventType::MsgsNoticed(updated_chat_id));
        chatlist_events::emit_chatlist_item_changed(context, updated_chat_id);
    }
    if archived_chats_maybe_noticed {
        context.on_archived_chats_maybe_noticed();
    }

    Ok(())
}

/// Checks if the messages with given IDs exist.
///
/// Returns IDs of existing messages.
pub async fn get_existing_msg_ids(context: &Context, ids: &[MsgId]) -> Result<Vec<MsgId>> {
    let query_only = true;
    let res = context
        .sql
        .transaction_ex(query_only, |transaction| {
            let mut res: Vec<MsgId> = Vec::new();
            for id in ids {
                if transaction.query_one(
                    "SELECT COUNT(*) > 0 FROM msgs WHERE id=? AND chat_id!=3",
                    (id,),
                    |row| {
                        let exists: bool = row.get(0)?;
                        Ok(exists)
                    },
                )? {
                    res.push(*id);
                }
            }
            Ok(res)
        })
        .await?;
    Ok(res)
}

pub(crate) async fn update_msg_state(
    context: &Context,
    msg_id: MsgId,
    state: MessageState,
) -> Result<()> {
    ensure!(
        state != MessageState::OutMdnRcvd,
        "Update msgs_mdns table instead!"
    );
    ensure!(state != MessageState::OutFailed, "use set_msg_failed()!");
    let error_subst = match state >= MessageState::OutPending {
        true => ", error=''",
        false => "",
    };
    context
        .sql
        .execute(
            &format!("UPDATE msgs SET state=? {error_subst} WHERE id=?"),
            (state, msg_id),
        )
        .await?;
    Ok(())
}

// as we do not cut inside words, this results in about 32-42 characters.
// Do not use too long subjects - we add a tag after the subject which gets truncated by the clients otherwise.
// It should also be very clear, the subject is _not_ the whole message.
// The value is also used for CC:-summaries

// Context functions to work with messages

pub(crate) async fn set_msg_failed(
    context: &Context,
    msg: &mut Message,
    error: &str,
) -> Result<()> {
    if msg.state.can_fail() {
        msg.state = MessageState::OutFailed;
        warn!(context, "{} failed: {}", msg.id, error);
    } else {
        warn!(
            context,
            "{} seems to have failed ({}), but state is {}", msg.id, error, msg.state
        )
    }
    msg.error = Some(error.to_string());

    let exists = context
        .sql
        .execute(
            "UPDATE msgs SET state=?, error=? WHERE id=?;",
            (msg.state, error, msg.id),
        )
        .await?
        > 0;
    context.emit_event(EventType::MsgFailed {
        chat_id: msg.chat_id,
        msg_id: msg.id,
    });
    if exists {
        chatlist_events::emit_chatlist_item_changed(context, msg.chat_id);
    }
    Ok(())
}

/// The number of messages assigned to unblocked chats
pub async fn get_unblocked_msg_cnt(context: &Context) -> usize {
    match context
        .sql
        .count(
            "SELECT COUNT(*) \
         FROM msgs m  LEFT JOIN chats c ON c.id=m.chat_id \
         WHERE m.id>9 AND m.chat_id>9 AND c.blocked=0;",
            (),
        )
        .await
    {
        Ok(res) => res,
        Err(err) => {
            error!(context, "get_unblocked_msg_cnt() failed. {:#}", err);
            0
        }
    }
}

/// Returns the number of messages in contact request chats.
pub async fn get_request_msg_cnt(context: &Context) -> usize {
    match context
        .sql
        .count(
            "SELECT COUNT(*) \
         FROM msgs m LEFT JOIN chats c ON c.id=m.chat_id \
         WHERE c.blocked=2;",
            (),
        )
        .await
    {
        Ok(res) => res,
        Err(err) => {
            error!(context, "get_request_msg_cnt() failed. {:#}", err);
            0
        }
    }
}

/// Estimates the number of messages that will be deleted
/// by the options `delete_device_after` or `delete_server_after`.
///
/// This is typically used to show the estimated impact to the user
/// before actually enabling deletion of old messages.
///
/// If `from_server` is true,
/// estimate deletion count for server,
/// otherwise estimate deletion count for device.
///
/// Count messages older than the given number of `seconds`.
///
/// Returns the number of messages that are older than the given number of seconds.
/// This includes e-mails downloaded due to the `show_emails` option.
/// Messages in the "saved messages" folder are not counted as they will not be deleted automatically.
#[expect(clippy::arithmetic_side_effects)]
pub async fn estimate_deletion_cnt(
    context: &Context,
    from_server: bool,
    seconds: i64,
) -> Result<usize> {
    let self_chat_id = ChatIdBlocked::lookup_by_contact(context, ContactId::SELF)
        .await?
        .map(|c| c.id)
        .unwrap_or_default();
    let threshold_timestamp = time() - seconds;

    let cnt = if from_server {
        context
            .sql
            .count(
                "SELECT COUNT(*)
             FROM msgs m
             WHERE m.id > ?
               AND timestamp < ?
               AND chat_id != ?
               AND EXISTS (SELECT * FROM imap WHERE rfc724_mid=m.rfc724_mid);",
                (DC_MSG_ID_LAST_SPECIAL, threshold_timestamp, self_chat_id),
            )
            .await?
    } else {
        context
            .sql
            .count(
                "SELECT COUNT(*)
             FROM msgs m
             WHERE m.id > ?
               AND timestamp < ?
               AND chat_id != ?
               AND chat_id != ? AND hidden = 0;",
                (
                    DC_MSG_ID_LAST_SPECIAL,
                    threshold_timestamp,
                    self_chat_id,
                    DC_CHAT_ID_TRASH,
                ),
            )
            .await?
    };
    Ok(cnt)
}

/// See [`rfc724_mid_exists_ex()`].
pub(crate) async fn rfc724_mid_exists(
    context: &Context,
    rfc724_mid: &str,
) -> Result<Option<MsgId>> {
    Ok(rfc724_mid_exists_ex(context, rfc724_mid, "1")
        .await?
        .map(|(id, _)| id))
}

/// Returns [MsgId] of the most recent message with given `rfc724_mid`
/// (Message-ID header) and bool `expr` result if such messages exists in the db.
///
/// * `expr`: SQL expression additionally passed into `SELECT`. Evaluated to `true` iff it is true
///   for all messages with the given `rfc724_mid`.
pub(crate) async fn rfc724_mid_exists_ex(
    context: &Context,
    rfc724_mid: &str,
    expr: &str,
) -> Result<Option<(MsgId, bool)>> {
    let rfc724_mid = rfc724_mid.trim_start_matches('<').trim_end_matches('>');
    if rfc724_mid.is_empty() {
        warn!(context, "Empty rfc724_mid passed to rfc724_mid_exists");
        return Ok(None);
    }

    let res = context
        .sql
        .query_row_optional(
            &("SELECT id, timestamp_sent, MIN(".to_string()
                + expr
                + ") FROM msgs WHERE rfc724_mid=?1 OR pre_rfc724_mid=?1
              HAVING COUNT(*) > 0 -- Prevent MIN(expr) from returning NULL when there are no rows.
              ORDER BY timestamp_sent DESC"),
            (rfc724_mid,),
            |row| {
                let msg_id: MsgId = row.get(0)?;
                let expr_res: bool = row.get(2)?;
                Ok((msg_id, expr_res))
            },
        )
        .await?;

    Ok(res)
}

/// Returns `true` iff there is a message
/// with the given `rfc724_mid`
/// and a download state other than `DownloadState::Available`,
/// i.e. it was already tried to download the message or it's sent locally.
pub(crate) async fn rfc724_mid_download_tried(context: &Context, rfc724_mid: &str) -> Result<bool> {
    let rfc724_mid = rfc724_mid.trim_start_matches('<').trim_end_matches('>');
    if rfc724_mid.is_empty() {
        warn!(
            context,
            "Empty rfc724_mid passed to rfc724_mid_download_tried"
        );
        return Ok(false);
    }

    let res = context
        .sql
        .exists(
            "SELECT COUNT(*) FROM msgs
             WHERE rfc724_mid=? AND download_state<>?",
            (rfc724_mid, DownloadState::Available),
        )
        .await?;

    Ok(res)
}

/// Given a list of Message-IDs, returns the most relevant message found in the database.
///
/// Relevance here is `(download_state == Done, index)`, where `index` is an index of Message-ID in
/// `mids`. This means Message-IDs should be ordered from the least late to the latest one (like in
/// the References header).
/// Only messages that are not in the trash chat are considered.
pub(crate) async fn get_by_rfc724_mids(
    context: &Context,
    mids: &[String],
) -> Result<Option<Message>> {
    let mut latest = None;
    for id in mids.iter().rev() {
        let Some(msg_id) = rfc724_mid_exists(context, id).await? else {
            continue;
        };
        let Some(msg) = Message::load_from_db_optional(context, msg_id).await? else {
            continue;
        };
        if msg.download_state == DownloadState::Done {
            return Ok(Some(msg));
        }
        latest.get_or_insert(msg);
    }
    Ok(latest)
}

/// Returns the 1st part of summary text (i.e. before the dash if any) for a valid DeltaChat vCard.
pub(crate) fn get_vcard_summary(vcard: &[u8]) -> Option<String> {
    let vcard = str::from_utf8(vcard).ok()?;
    let contacts = deltachat_contact_tools::parse_vcard(vcard);
    let [c] = &contacts[..] else {
        return None;
    };
    if !deltachat_contact_tools::may_be_valid_addr(&c.addr) {
        return None;
    }
    Some(c.display_name().to_string())
}

/// How a message is primarily displayed.
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
    Serialize,
    Deserialize,
)]
#[repr(u32)]
pub enum Viewtype {
    /// Unknown message type.
    #[default]
    Unknown = 0,

    /// Text message.
    /// The text of the message is set using dc_msg_set_text() and retrieved with dc_msg_get_text().
    Text = 10,

    /// Image message.
    /// If the image is a GIF and has the appropriate extension, the viewtype is auto-changed to
    /// `Gif` when sending the message.
    /// File, width and height are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_dimension()
    /// and retrieved via dc_msg_get_file(), dc_msg_get_height(), dc_msg_get_width().
    Image = 20,

    /// Animated GIF message.
    /// File, width and height are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_dimension()
    /// and retrieved via dc_msg_get_file(), dc_msg_get_width(), dc_msg_get_height().
    Gif = 21,

    /// Message containing a sticker, similar to image.
    /// NB: When sending, the message viewtype may be changed to `Image` by some heuristics like
    /// checking for transparent pixels. Use `Message::force_sticker()` to disable them.
    ///
    /// If possible, the ui should display the image without borders in a transparent way.
    /// A click on a sticker will offer to install the sticker set in some future.
    Sticker = 23,

    /// Message containing an Audio file.
    /// File and duration are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_duration()
    /// and retrieved via dc_msg_get_file(), dc_msg_get_duration().
    Audio = 40,

    /// A voice message that was directly recorded by the user.
    /// For all other audio messages, the type #DC_MSG_AUDIO should be used.
    /// File and duration are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_duration()
    /// and retrieved via dc_msg_get_file(), dc_msg_get_duration()
    Voice = 41,

    /// Video messages.
    /// File, width, height and durarion
    /// are set via dc_msg_set_file_and_deduplicate(), dc_msg_set_dimension(), dc_msg_set_duration()
    /// and retrieved via
    /// dc_msg_get_file(), dc_msg_get_width(),
    /// dc_msg_get_height(), dc_msg_get_duration().
    Video = 50,

    /// Message containing any file, eg. a PDF.
    /// The file is set via dc_msg_set_file_and_deduplicate()
    /// and retrieved via dc_msg_get_file().
    File = 60,

    /// Message is an incoming or outgoing call.
    Call = 71,

    /// Message is an webxdc instance.
    Webxdc = 80,

    /// Message containing shared contacts represented as a vCard (virtual contact file)
    /// with email addresses and possibly other fields.
    /// Use `parse_vcard()` to retrieve them.
    Vcard = 90,
}

impl Viewtype {
    /// Whether a message with this [`Viewtype`] should have a file attachment.
    pub fn has_file(&self) -> bool {
        match self {
            Viewtype::Unknown => false,
            Viewtype::Text => false,
            Viewtype::Image => true,
            Viewtype::Gif => true,
            Viewtype::Sticker => true,
            Viewtype::Audio => true,
            Viewtype::Voice => true,
            Viewtype::Video => true,
            Viewtype::File => true,
            Viewtype::Call => false,
            Viewtype::Webxdc => true,
            Viewtype::Vcard => true,
        }
    }
}

#[cfg(test)]
mod message_tests;
