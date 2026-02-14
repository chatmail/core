//! # Handle webxdc messages.
//!
//! Internally status updates are stored in the `msgs_status_updates` SQL table.
//! `msgs_status_updates` contains the following columns:
//! - `id` - status update serial number
//! - `msg_id` - ID of the message in the `msgs` table
//! - `update_item` - JSON representation of the status update
//! - `uid` - "id" field of the update, used for deduplication
//!
//! Status updates are scheduled for sending by adding a record
//! to `smtp_status_updates_table` SQL table.
//! `smtp_status_updates` contains the following columns:
//! - `msg_id` - ID of the message in the `msgs` table
//! - `first_serial` - serial number of the first status update to send
//! - `last_serial` - serial number of the last status update to send
//! - `descr` - not used, set to empty string

mod integration;
mod maps_integration;

use std::cmp::max;
use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, Result, anyhow, bail, ensure, format_err};

use async_zip::tokio::read::seek::ZipFileReader as SeekZipFileReader;
use deltachat_contact_tools::sanitize_bidi_characters;
use deltachat_derive::FromSql;
use mail_builder::mime::MimePart;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::BufReader};

use crate::chat::{self, Chat};
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::context::Context;
use crate::events::EventType;
use crate::key::self_fingerprint;
use crate::log::warn;
use crate::message::{Message, MessageState, MsgId, Viewtype};
use crate::mimefactory::RECOMMENDED_FILE_SIZE;
use crate::mimeparser::SystemMessage;
use crate::param::Param;
use crate::param::Params;
use crate::tools::{create_id, create_smeared_timestamp, get_abs_path};

/// The current API version.
/// If `min_api` in manifest.toml is set to a larger value,
/// the Webxdc's index.html is replaced by an error message.
/// In the future, that may be useful to avoid new Webxdc being loaded on old Delta Chats.
const WEBXDC_API_VERSION: u32 = 1;

/// Suffix used to recognize webxdc files.
pub const WEBXDC_SUFFIX: &str = "xdc";
const WEBXDC_DEFAULT_ICON: &str = "__webxdc__/default-icon.png";

/// Text shown to classic e-mail users in the visible e-mail body.
const BODY_DESCR: &str = "Webxdc Status Update";

/// Raw information read from manifest.toml
#[derive(Debug, Deserialize, Default)]
#[non_exhaustive]
pub struct WebxdcManifest {
    /// Webxdc name, used on icons or page titles.
    pub name: Option<String>,

    /// Minimum API version required to run this webxdc.
    pub min_api: Option<u32>,

    /// Optional URL of webxdc source code.
    pub source_code_url: Option<String>,

    /// Set to "map" to request integration.
    pub request_integration: Option<String>,
}

/// Parsed information from WebxdcManifest and fallbacks.
#[derive(Debug, Serialize)]
pub struct WebxdcInfo {
    /// The name of the app.
    /// Defaults to filename if not set in the manifest.
    pub name: String,

    /// Filename of the app icon.
    pub icon: String,

    /// If the webxdc represents a document and allows to edit it,
    /// this is the document name.
    /// Otherwise an empty string.
    pub document: String,

    /// Short description of the webxdc state.
    /// For example, "7 votes".
    pub summary: String,

    /// URL of webxdc source code or an empty string.
    pub source_code_url: String,

    /// Set to "map" to request integration, otherwise an empty string.
    pub request_integration: String,

    /// If the webxdc is allowed to access the network.
    /// It should request access, be encrypted
    /// and sent to self for this.
    pub internet_access: bool,

    /// Address to be used for `window.webxdc.selfAddr` in JS land.
    pub self_addr: String,

    /// Milliseconds to wait before calling `sendUpdate()` again since the last call.
    /// Should be exposed to `window.sendUpdateInterval` in JS land.
    pub send_update_interval: usize,

    /// Maximum number of bytes accepted for a serialized update object.
    /// Should be exposed to `window.sendUpdateMaxSize` in JS land.
    pub send_update_max_size: usize,
}

/// Status Update ID.
#[derive(
    Debug,
    Copy,
    Clone,
    Default,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    FromSql,
    FromPrimitive,
)]
pub struct StatusUpdateSerial(u32);

impl StatusUpdateSerial {
    /// Create a new [StatusUpdateSerial].
    pub fn new(id: u32) -> StatusUpdateSerial {
        StatusUpdateSerial(id)
    }

    /// Minimum value.
    pub const MIN: Self = Self(1);
    /// Maximum value.
    pub const MAX: Self = Self(u32::MAX - 1);

    /// Gets StatusUpdateSerial as untyped integer.
    /// Avoid using this outside ffi.
    pub fn to_u32(self) -> u32 {
        self.0
    }
}

impl rusqlite::types::ToSql for StatusUpdateSerial {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let val = rusqlite::types::Value::Integer(i64::from(self.0));
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

// Array of update items as sent on the wire.
#[derive(Debug, Deserialize)]
struct StatusUpdates {
    updates: Vec<StatusUpdateItem>,
}

/// Update items as sent on the wire and as stored in the database.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StatusUpdateItem {
    /// The playload of the status update.
    pub payload: Value,

    /// Optional short info message that will be displayed in the chat.
    /// For example "Alice added an item" or "Bob voted for option x".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,

    /// Optional link the info message will point to.
    /// Used to set `window.location.href` in JS land.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,

    /// The new name of the editing document.
    /// This is not needed if the webxdc doesn't edit documents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<String>,

    /// Optional summary of the status update which will be shown next to the
    /// app icon. This should be short and can be something like "8 votes"
    /// for a voting app.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Unique ID for deduplication.
    /// This can be used if the message is sent over multiple transports.
    ///
    /// If there is no ID, message is always considered to be unique.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// Array of other users `selfAddr` that should be notified about this update.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<HashMap<String, String>>,
}

/// Update items as passed to the UIs.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StatusUpdateItemAndSerial {
    #[serde(flatten)]
    item: StatusUpdateItem,

    serial: StatusUpdateSerial,
    max_serial: StatusUpdateSerial,
}

/// Returns an entry index and a reference.
fn find_zip_entry<'a>(
    file: &'a async_zip::ZipFile,
    name: &str,
) -> Option<(usize, &'a async_zip::StoredZipEntry)> {
    for (i, ent) in file.entries().iter().enumerate() {
        if ent.filename().as_bytes() == name.as_bytes() {
            return Some((i, ent));
        }
    }
    None
}

/// Status update JSON size soft limit.
const STATUS_UPDATE_SIZE_MAX: usize = 100 << 10;

impl Context {
    /// check if a file is an acceptable webxdc for sending or receiving.
    pub(crate) async fn is_webxdc_file(&self, filename: &str, file: &[u8]) -> Result<bool> {
        if !filename.ends_with(WEBXDC_SUFFIX) {
            return Ok(false);
        }

        let archive = match async_zip::base::read::mem::ZipFileReader::new(file.to_vec()).await {
            Ok(archive) => archive,
            Err(_) => {
                info!(self, "{} cannot be opened as zip-file", &filename);
                return Ok(false);
            }
        };

        if find_zip_entry(archive.file(), "index.html").is_none() {
            info!(self, "{} misses index.html", &filename);
            return Ok(false);
        }

        Ok(true)
    }

    /// Ensure that a file is an acceptable webxdc for sending.
    pub(crate) async fn ensure_sendable_webxdc_file(&self, path: &Path) -> Result<()> {
        let filename = path.to_str().unwrap_or_default();

        let file = BufReader::new(File::open(path).await?);
        let valid = match SeekZipFileReader::with_tokio(file).await {
            Ok(archive) => {
                if find_zip_entry(archive.file(), "index.html").is_none() {
                    warn!(self, "{} misses index.html", filename);
                    false
                } else {
                    true
                }
            }
            Err(_) => {
                warn!(self, "{} cannot be opened as zip-file", filename);
                false
            }
        };

        if !valid {
            bail!("{filename} is not a valid webxdc file");
        }

        Ok(())
    }

    /// Check if the last message of a chat is an info message belonging to the given instance and sender.
    /// If so, the id of this message is returned.
    async fn get_overwritable_info_msg_id(
        &self,
        instance: &Message,
        from_id: ContactId,
    ) -> Result<Option<MsgId>> {
        if let Some((last_msg_id, last_from_id, last_param, last_in_repl_to)) = self
            .sql
            .query_row_optional(
                r#"SELECT id, from_id, param, mime_in_reply_to
                    FROM msgs
                    WHERE chat_id=?1 AND hidden=0
                    ORDER BY timestamp DESC, id DESC LIMIT 1"#,
                (instance.chat_id,),
                |row| {
                    let last_msg_id: MsgId = row.get(0)?;
                    let last_from_id: ContactId = row.get(1)?;
                    let last_param: Params = row.get::<_, String>(2)?.parse().unwrap_or_default();
                    let last_in_repl_to: String = row.get(3)?;
                    Ok((last_msg_id, last_from_id, last_param, last_in_repl_to))
                },
            )
            .await?
            && last_from_id == from_id
            && last_param.get_cmd() == SystemMessage::WebxdcInfoMessage
            && last_in_repl_to == instance.rfc724_mid
        {
            return Ok(Some(last_msg_id));
        }
        Ok(None)
    }

    /// Takes an update-json as `{payload: PAYLOAD}`
    /// writes it to the database and handles events, info-messages, document name and summary.
    async fn create_status_update_record(
        &self,
        instance: &Message,
        status_update_item: StatusUpdateItem,
        timestamp: i64,
        can_info_msg: bool,
        from_id: ContactId,
    ) -> Result<Option<StatusUpdateSerial>> {
        let Some(status_update_serial) = self
            .write_status_update_inner(&instance.id, &status_update_item, timestamp)
            .await?
        else {
            return Ok(None);
        };

        let mut notify_msg_id = instance.id;
        let mut param_changed = false;

        let mut instance = instance.clone();
        if let Some(ref document) = status_update_item.document
            && instance
                .param
                .update_timestamp(Param::WebxdcDocumentTimestamp, timestamp)?
        {
            instance.param.set(Param::WebxdcDocument, document);
            param_changed = true;
        }

        if let Some(ref summary) = status_update_item.summary
            && instance
                .param
                .update_timestamp(Param::WebxdcSummaryTimestamp, timestamp)?
        {
            let summary = sanitize_bidi_characters(summary);
            instance.param.set(Param::WebxdcSummary, summary.clone());
            param_changed = true;
        }

        if can_info_msg && let Some(ref info) = status_update_item.info {
            let info_msg_id = self
                .get_overwritable_info_msg_id(&instance, from_id)
                .await?;

            if let (Some(info_msg_id), None) = (info_msg_id, &status_update_item.href) {
                chat::update_msg_text_and_timestamp(
                    self,
                    instance.chat_id,
                    info_msg_id,
                    info.as_str(),
                    timestamp,
                )
                .await?;
                notify_msg_id = info_msg_id;
            } else {
                notify_msg_id = chat::add_info_msg_with_cmd(
                    self,
                    instance.chat_id,
                    info.as_str(),
                    SystemMessage::WebxdcInfoMessage,
                    Some(timestamp),
                    timestamp,
                    Some(&instance),
                    Some(from_id),
                    None,
                )
                .await?;
            }

            if let Some(ref href) = status_update_item.href {
                let mut notify_msg = Message::load_from_db(self, notify_msg_id).await?;
                notify_msg.param.set(Param::Arg, href);
                notify_msg.update_param(self).await?;
            }
        }

        if param_changed {
            instance.update_param(self).await?;
            self.emit_msgs_changed(instance.chat_id, instance.id);
        }

        if instance.viewtype == Viewtype::Webxdc {
            self.emit_event(EventType::WebxdcStatusUpdate {
                msg_id: instance.id,
                status_update_serial,
            });
        }

        if from_id != ContactId::SELF
            && let Some(notify_list) = status_update_item.notify
        {
            let self_addr = instance.get_webxdc_self_addr(self).await?;
            let notify_text = if let Some(notify_text) = notify_list.get(&self_addr) {
                Some(notify_text)
            } else if let Some(notify_text) = notify_list.get("*")
                && !Chat::load_from_db(self, instance.chat_id).await?.is_muted()
            {
                Some(notify_text)
            } else {
                None
            };
            if let Some(notify_text) = notify_text {
                self.emit_event(EventType::IncomingWebxdcNotify {
                    chat_id: instance.chat_id,
                    contact_id: from_id,
                    msg_id: notify_msg_id,
                    text: notify_text.clone(),
                    href: status_update_item.href,
                });
            }
        }

        Ok(Some(status_update_serial))
    }

    /// Inserts a status update item into `msgs_status_updates` table.
    ///
    /// Returns serial ID of the status update if a new item is inserted.
    pub(crate) async fn write_status_update_inner(
        &self,
        instance_id: &MsgId,
        status_update_item: &StatusUpdateItem,
        timestamp: i64,
    ) -> Result<Option<StatusUpdateSerial>> {
        let uid = status_update_item.uid.as_deref();
        let status_update_item = serde_json::to_string(&status_update_item)?;
        let trans_fn = |t: &mut rusqlite::Transaction| {
            t.execute(
                "UPDATE msgs SET timestamp_rcvd=? WHERE id=?",
                (timestamp, instance_id),
            )?;
            let rowid = t
                .query_row(
                    "INSERT INTO msgs_status_updates (msg_id, update_item, uid) VALUES(?, ?, ?)
                     ON CONFLICT (uid) DO NOTHING
                     RETURNING id",
                    (instance_id, status_update_item, uid),
                    |row| {
                        let id: u32 = row.get(0)?;
                        Ok(id)
                    },
                )
                .optional()?;
            Ok(rowid)
        };
        let Some(rowid) = self.sql.transaction(trans_fn).await? else {
            let uid = uid.unwrap_or("-");
            info!(self, "Ignoring duplicate status update with uid={uid}");
            return Ok(None);
        };
        let status_update_serial = StatusUpdateSerial(rowid);
        Ok(Some(status_update_serial))
    }

    /// Returns the update_item with `status_update_serial` from the webxdc with message id `msg_id`.
    pub async fn get_status_update(
        &self,
        msg_id: MsgId,
        status_update_serial: StatusUpdateSerial,
    ) -> Result<String> {
        self.sql
            .query_get_value(
                "SELECT update_item FROM msgs_status_updates WHERE id=? AND msg_id=? ",
                (status_update_serial.0, msg_id),
            )
            .await?
            .context("get_status_update: no update item found.")
    }

    /// Sends a status update for an webxdc instance.
    ///
    /// If the instance is a draft,
    /// the status update is sent once the instance is actually sent.
    /// Otherwise, the update is sent as soon as possible.
    pub async fn send_webxdc_status_update(
        &self,
        instance_msg_id: MsgId,
        update_str: &str,
    ) -> Result<()> {
        let status_update_item: StatusUpdateItem = serde_json::from_str(update_str)
            .with_context(|| format!("Failed to parse webxdc update item from {update_str:?}"))?;
        self.send_webxdc_status_update_struct(instance_msg_id, status_update_item)
            .await?;
        Ok(())
    }

    /// Sends a status update for an webxdc instance.
    /// Also see [Self::send_webxdc_status_update]
    pub async fn send_webxdc_status_update_struct(
        &self,
        instance_msg_id: MsgId,
        mut status_update: StatusUpdateItem,
    ) -> Result<()> {
        let instance = Message::load_from_db(self, instance_msg_id)
            .await
            .with_context(|| {
                format!("Failed to load message {instance_msg_id} from the database")
            })?;
        let viewtype = instance.viewtype;
        if viewtype != Viewtype::Webxdc {
            bail!(
                "send_webxdc_status_update: message {instance_msg_id} is not a webxdc message, but a {viewtype} message."
            );
        }

        if instance.param.get_int(Param::WebxdcIntegration).is_some() {
            return self
                .intercept_send_webxdc_status_update(instance, status_update)
                .await;
        }

        let chat_id = instance.chat_id;
        let chat = Chat::load_from_db(self, chat_id)
            .await
            .with_context(|| format!("Failed to load chat {chat_id} from the database"))?;
        if let Some(reason) = chat.why_cant_send(self).await.with_context(|| {
            format!("Failed to check if webxdc update can be sent to chat {chat_id}")
        })? {
            bail!("Cannot send to {chat_id}: {reason}.");
        }

        let send_now = !matches!(
            instance.state,
            MessageState::Undefined | MessageState::OutPreparing | MessageState::OutDraft
        );

        status_update.uid = Some(create_id());
        let status_update_serial: StatusUpdateSerial = self
            .create_status_update_record(
                &instance,
                status_update,
                create_smeared_timestamp(self),
                send_now,
                ContactId::SELF,
            )
            .await
            .context("Failed to create status update")?
            .context("Duplicate status update UID was generated")?;

        if send_now {
            self.sql.insert(
                "INSERT INTO smtp_status_updates (msg_id, first_serial, last_serial, descr) VALUES(?, ?, ?, '')
                 ON CONFLICT(msg_id)
                 DO UPDATE SET last_serial=excluded.last_serial",
                (instance.id, status_update_serial, status_update_serial),
            ).await.context("Failed to insert webxdc update into SMTP queue")?;
            self.scheduler.interrupt_smtp().await;
        }
        Ok(())
    }

    /// Returns one record of the queued webxdc status updates.
    async fn smtp_status_update_get(&self) -> Result<Option<(MsgId, i64, StatusUpdateSerial)>> {
        let res = self
            .sql
            .query_row_optional(
                "SELECT msg_id, first_serial, last_serial \
                 FROM smtp_status_updates LIMIT 1",
                (),
                |row| {
                    let instance_id: MsgId = row.get(0)?;
                    let first_serial: i64 = row.get(1)?;
                    let last_serial: StatusUpdateSerial = row.get(2)?;
                    Ok((instance_id, first_serial, last_serial))
                },
            )
            .await?;
        Ok(res)
    }

    async fn smtp_status_update_pop_serials(
        &self,
        msg_id: MsgId,
        first: i64,
        first_new: StatusUpdateSerial,
    ) -> Result<()> {
        if self
            .sql
            .execute(
                "DELETE FROM smtp_status_updates \
                 WHERE msg_id=? AND first_serial=? AND last_serial<?",
                (msg_id, first, first_new),
            )
            .await?
            > 0
        {
            return Ok(());
        }
        self.sql
            .execute(
                "UPDATE smtp_status_updates SET first_serial=? \
                 WHERE msg_id=? AND first_serial=?",
                (first_new, msg_id, first),
            )
            .await?;
        Ok(())
    }

    /// Attempts to send queued webxdc status updates.
    pub(crate) async fn flush_status_updates(&self) -> Result<()> {
        loop {
            let (instance_id, first, last) = match self.smtp_status_update_get().await? {
                Some(res) => res,
                None => return Ok(()),
            };
            let (json, first_new) = self
                .render_webxdc_status_update_object(
                    instance_id,
                    StatusUpdateSerial(max(first, 1).try_into()?),
                    last,
                    Some(STATUS_UPDATE_SIZE_MAX),
                )
                .await?;
            if let Some(json) = json {
                let instance = Message::load_from_db(self, instance_id).await?;
                let mut status_update = Message {
                    chat_id: instance.chat_id,
                    viewtype: Viewtype::Text,
                    text: BODY_DESCR.to_string(),
                    hidden: true,
                    ..Default::default()
                };
                status_update
                    .param
                    .set_cmd(SystemMessage::WebxdcStatusUpdate);
                status_update.param.set(Param::Arg, json);
                status_update.set_quote(self, Some(&instance)).await?;
                status_update.param.remove(Param::GuaranteeE2ee); // may be set by set_quote(), if #2985 is done, this line can be removed
                chat::send_msg(self, instance.chat_id, &mut status_update).await?;
            }
            self.smtp_status_update_pop_serials(instance_id, first, first_new)
                .await?;
        }
    }

    pub(crate) fn build_status_update_part(&self, json: &str) -> MimePart<'static> {
        MimePart::new("application/json", json.as_bytes().to_vec()).attachment("status-update.json")
    }

    /// Receives status updates from receive_imf to the database
    /// and sends out an event.
    ///
    /// `instance` is a webxdc instance.
    ///
    /// `from_id` is the sender.
    ///
    /// `timestamp` is the timestamp of the update.
    ///
    /// `json` is an array containing one or more update items as created by send_webxdc_status_update(),
    /// the array is parsed using serde, the single payloads are used as is.
    pub(crate) async fn receive_status_update(
        &self,
        from_id: ContactId,
        instance: &Message,
        timestamp: i64,
        can_info_msg: bool,
        json: &str,
    ) -> Result<()> {
        let chat_id = instance.chat_id;

        if from_id != ContactId::SELF && !chat::is_contact_in_chat(self, chat_id, from_id).await? {
            let chat_type: Chattype = self
                .sql
                .query_get_value("SELECT type FROM chats WHERE id=?", (chat_id,))
                .await?
                .with_context(|| format!("Chat type for chat {chat_id} not found"))?;
            if chat_type != Chattype::Mailinglist {
                bail!(
                    "receive_status_update: status sender {from_id} is not a member of chat {chat_id}"
                )
            }
        }

        let updates: StatusUpdates = serde_json::from_str(json)?;
        for update_item in updates.updates {
            self.create_status_update_record(
                instance,
                update_item,
                timestamp,
                can_info_msg,
                from_id,
            )
            .await?;
        }

        Ok(())
    }

    /// Returns status updates as an JSON-array, ready to be consumed by a webxdc.
    ///
    /// Example: `[{"serial":1, "max_serial":3, "payload":"any update data"},
    ///            {"serial":3, "max_serial":3, "payload":"another update data"}]`
    /// Updates with serials larger than `last_known_serial` are returned.
    /// If no last serial is known, set `last_known_serial` to 0.
    /// If no updates are available, an empty JSON-array is returned.
    pub async fn get_webxdc_status_updates(
        &self,
        instance_msg_id: MsgId,
        last_known_serial: StatusUpdateSerial,
    ) -> Result<String> {
        let param = instance_msg_id.get_param(self).await?;
        if param.get_int(Param::WebxdcIntegration).is_some() {
            let instance = Message::load_from_db(self, instance_msg_id).await?;
            return self
                .intercept_get_webxdc_status_updates(instance, last_known_serial)
                .await;
        }

        let json = self
            .sql
            .query_map(
                "SELECT update_item, id FROM msgs_status_updates WHERE msg_id=? AND id>? ORDER BY id",
                (instance_msg_id, last_known_serial),
                |row| {
                    let update_item_str: String = row.get(0)?;
                    let serial: StatusUpdateSerial = row.get(1)?;
                    Ok((update_item_str, serial))
                },
                |rows| {
                    let mut rows_copy : Vec<(String, StatusUpdateSerial)> = Vec::new(); // `rows_copy` needed as `rows` cannot be iterated twice.
                    let mut max_serial = StatusUpdateSerial(0);
                    for row in rows {
                        let row = row?;
                        if row.1 > max_serial {
                            max_serial = row.1;
                        }
                        rows_copy.push(row);
                    }

                    let mut json = String::default();
                    for row in rows_copy {
                        let (update_item_str, serial) = row;
                        let update_item = StatusUpdateItemAndSerial
                        {
                            item: StatusUpdateItem {
                                uid: None, // Erase UIDs, apps, bots and tests don't need to know them.
                                ..serde_json::from_str(&update_item_str)?
                            },
                            serial,
                            max_serial,
                        };

                        if !json.is_empty() {
                            json.push_str(",\n");
                        }
                        json.push_str(&serde_json::to_string(&update_item)?);
                    }
                    Ok(json)
                },
            )
            .await?;
        Ok(format!("[{json}]"))
    }

    /// Renders JSON-object for status updates as used on the wire.
    ///
    /// Returns optional JSON and the first serial of updates not included due to a JSON size
    /// limit. If all requested updates are included, returns the first not requested serial.
    ///
    /// Example JSON: `{"updates": [{"payload":"any update data"},
    ///                             {"payload":"another update data"}]}`
    ///
    /// * `(first, last)`: range of status update serials to send.
    #[expect(clippy::arithmetic_side_effects)]
    pub(crate) async fn render_webxdc_status_update_object(
        &self,
        instance_msg_id: MsgId,
        first: StatusUpdateSerial,
        last: StatusUpdateSerial,
        size_max: Option<usize>,
    ) -> Result<(Option<String>, StatusUpdateSerial)> {
        let (json, first_new) = self
            .sql
            .query_map(
                "SELECT id, update_item FROM msgs_status_updates \
                 WHERE msg_id=? AND id>=? AND id<=? ORDER BY id",
                (instance_msg_id, first, last),
                |row| {
                    let id: StatusUpdateSerial = row.get(0)?;
                    let update_item: String = row.get(1)?;
                    Ok((id, update_item))
                },
                |rows| {
                    let mut json = String::default();
                    for row in rows {
                        let (id, update_item) = row?;
                        if !json.is_empty()
                            && json.len() + update_item.len() >= size_max.unwrap_or(usize::MAX)
                        {
                            return Ok((json, id));
                        }
                        if !json.is_empty() {
                            json.push_str(",\n");
                        }
                        json.push_str(&update_item);
                    }
                    Ok((
                        json,
                        // Too late to fail here if an overflow happens. It's still better to send
                        // the updates.
                        StatusUpdateSerial::new(last.to_u32().saturating_add(1)),
                    ))
                },
            )
            .await?;
        let json = match json.is_empty() {
            true => None,
            false => Some(format!(r#"{{"updates":[{json}]}}"#)),
        };
        Ok((json, first_new))
    }
}

fn parse_webxdc_manifest(bytes: &[u8]) -> Result<WebxdcManifest> {
    let s = std::str::from_utf8(bytes)?;
    let manifest: WebxdcManifest = toml::from_str(s)?;
    Ok(manifest)
}

async fn get_blob(archive: &mut SeekZipFileReader<BufReader<File>>, name: &str) -> Result<Vec<u8>> {
    let (i, _) =
        find_zip_entry(archive.file(), name).ok_or_else(|| anyhow!("no entry found for {name}"))?;
    let mut reader = archive.reader_with_entry(i).await?;
    let mut buf = Vec::new();
    reader.read_to_end_checked(&mut buf).await?;
    Ok(buf)
}

impl Message {
    /// Get handle to a webxdc ZIP-archive.
    /// To check for file existence use archive.by_name(), to read a file, use get_blob(archive).
    async fn get_webxdc_archive(
        &self,
        context: &Context,
    ) -> Result<SeekZipFileReader<BufReader<File>>> {
        let path = self
            .get_file(context)
            .ok_or_else(|| format_err!("No webxdc instance file."))?;
        let path_abs = get_abs_path(context, &path);
        let file = BufReader::new(File::open(path_abs).await?);
        let archive = SeekZipFileReader::with_tokio(file).await?;
        Ok(archive)
    }

    /// Return file from inside an archive.
    /// Currently, this works only if the message is an webxdc instance.
    ///
    /// `name` is the filename within the archive, e.g. `index.html`.
    pub async fn get_webxdc_blob(&self, context: &Context, name: &str) -> Result<Vec<u8>> {
        ensure!(self.viewtype == Viewtype::Webxdc, "No webxdc instance.");

        if name == WEBXDC_DEFAULT_ICON {
            return Ok(include_bytes!("../assets/icon-webxdc.png").to_vec());
        }

        // ignore first slash.
        // this way, files can be accessed absolutely (`/index.html`) as well as relatively (`index.html`)
        let name = if name.starts_with('/') {
            name.split_at(1).1
        } else {
            name
        };

        let mut archive = self.get_webxdc_archive(context).await?;

        if name == "index.html"
            && let Ok(bytes) = get_blob(&mut archive, "manifest.toml").await
            && let Ok(manifest) = parse_webxdc_manifest(&bytes)
            && let Some(min_api) = manifest.min_api
            && min_api > WEBXDC_API_VERSION
        {
            return Ok(Vec::from(
                "<!DOCTYPE html>This Webxdc requires a newer Delta Chat version.",
            ));
        }

        get_blob(&mut archive, name).await
    }

    /// Return info from manifest.toml or from fallbacks.
    pub async fn get_webxdc_info(&self, context: &Context) -> Result<WebxdcInfo> {
        ensure!(self.viewtype == Viewtype::Webxdc, "No webxdc instance.");
        let mut archive = self.get_webxdc_archive(context).await?;

        let mut manifest = get_blob(&mut archive, "manifest.toml")
            .await
            .map(|bytes| parse_webxdc_manifest(&bytes).unwrap_or_default())
            .unwrap_or_default();

        if let Some(ref name) = manifest.name {
            let name = name.trim();
            if name.is_empty() {
                warn!(context, "empty name given in manifest");
                manifest.name = None;
            }
        }

        let request_integration = manifest.request_integration.unwrap_or_default();
        let is_integrated = self.is_set_as_webxdc_integration(context).await?;
        let internet_access = is_integrated;

        let self_addr = self.get_webxdc_self_addr(context).await?;

        Ok(WebxdcInfo {
            name: if let Some(name) = manifest.name {
                name
            } else {
                self.get_filename().unwrap_or_default()
            },
            icon: if find_zip_entry(archive.file(), "icon.png").is_some() {
                "icon.png".to_string()
            } else if find_zip_entry(archive.file(), "icon.jpg").is_some() {
                "icon.jpg".to_string()
            } else {
                WEBXDC_DEFAULT_ICON.to_string()
            },
            document: self
                .param
                .get(Param::WebxdcDocument)
                .unwrap_or_default()
                .to_string(),
            summary: if is_integrated {
                "🌍 Used as map. Delete to use default. Do not enter sensitive data".to_string()
            } else if request_integration == "map" {
                "🌏 To use as map, forward to \"Saved Messages\" again. Do not enter sensitive data"
                    .to_string()
            } else {
                self.param
                    .get(Param::WebxdcSummary)
                    .unwrap_or_default()
                    .to_string()
            },
            source_code_url: if let Some(url) = manifest.source_code_url {
                url
            } else {
                "".to_string()
            },
            request_integration,
            internet_access,
            self_addr,
            send_update_interval: context.ratelimit.read().await.update_interval(),
            send_update_max_size: RECOMMENDED_FILE_SIZE as usize,
        })
    }

    async fn get_webxdc_self_addr(&self, context: &Context) -> Result<String> {
        let fingerprint = self_fingerprint(context).await?;
        let data = format!("{}-{}", fingerprint, self.rfc724_mid);
        let hash = Sha256::digest(data.as_bytes());
        Ok(format!("{hash:x}"))
    }

    /// Get link attached to an info message.
    ///
    /// The info message needs to be of type SystemMessage::WebxdcInfoMessage.
    /// Typically, this is used to start the corresponding webxdc app
    /// with `window.location.href` set in JS land.
    pub fn get_webxdc_href(&self) -> Option<String> {
        self.param.get(Param::Arg).map(|href| href.to_string())
    }
}

#[cfg(test)]
mod webxdc_tests;
