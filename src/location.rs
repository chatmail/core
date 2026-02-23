//! Location handling.
//!
//! Delta Chat handles two kind of locations.
//!
//! There are two kinds of locations:
//! - Independent locations, also known as Points of Interest (POI).
//! - Path locations.
//!
//! Locations are sent as KML attachments.
//! Independent locations are sent in `message.kml` attachments
//! and path locations are sent in `location.kml` attachments.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use async_channel::Receiver;
use quick_xml::events::{BytesEnd, BytesStart, BytesText};
use tokio::time::timeout;

use crate::chat::{self, ChatId};
use crate::constants::DC_CHAT_ID_TRASH;
use crate::contact::ContactId;
use crate::context::Context;
use crate::events::EventType;
use crate::log::warn;
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::tools::{duration_to_str, time};
use crate::{chatlist_events, stock_str};

/// Location record.
#[derive(Debug, Clone, Default)]
pub struct Location {
    /// Row ID of the location.
    pub location_id: u32,

    /// Location latitude.
    pub latitude: f64,

    /// Location longitude.
    pub longitude: f64,

    /// Nonstandard `accuracy` attribute of the `coordinates` tag.
    pub accuracy: f64,

    /// Location timestamp in seconds.
    pub timestamp: i64,

    /// Contact ID.
    pub contact_id: ContactId,

    /// Message ID.
    pub msg_id: u32,

    /// Chat ID.
    pub chat_id: ChatId,

    /// A marker string, such as an emoji, to be displayed on top of the location.
    pub marker: Option<String>,

    /// Whether location is independent, i.e. not part of the path.
    pub independent: u32,
}

impl Location {
    /// Creates a new empty location.
    pub fn new() -> Self {
        Default::default()
    }
}

/// KML document.
///
/// See <https://www.ogc.org/standards/kml/> for the standard and
/// <https://developers.google.com/kml> for documentation.
#[derive(Debug, Clone, Default)]
pub struct Kml {
    /// Nonstandard `addr` attribute of the `Document` tag storing the user email address.
    pub addr: Option<String>,

    /// Placemarks.
    pub locations: Vec<Location>,

    /// Currently parsed XML tag.
    tag: KmlTag,

    /// Currently parsed placemark.
    pub curr: Location,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
enum KmlTag {
    #[default]
    Undefined,
    Placemark,
    PlacemarkTimestamp,
    PlacemarkTimestampWhen,
    PlacemarkPoint,
    PlacemarkPointCoordinates,
}

impl Kml {
    /// Creates a new empty KML document.
    pub fn new() -> Self {
        Default::default()
    }

    /// Parses a KML document.
    pub fn parse(to_parse: &[u8]) -> Result<Self> {
        ensure!(to_parse.len() <= 1024 * 1024, "kml-file is too large");

        let mut reader = quick_xml::Reader::from_reader(to_parse);
        reader.config_mut().trim_text(true);

        let mut kml = Kml::new();
        kml.locations = Vec::with_capacity(100);

        let mut buf = Vec::new();

        loop {
            match reader.read_event_into(&mut buf).with_context(|| {
                format!(
                    "location parsing error at position {}",
                    reader.buffer_position()
                )
            })? {
                quick_xml::events::Event::Start(ref e) => kml.starttag_cb(e, &reader),
                quick_xml::events::Event::End(ref e) => kml.endtag_cb(e),
                quick_xml::events::Event::Text(ref e) => kml.text_cb(e),
                quick_xml::events::Event::Eof => break,
                _ => (),
            }
            buf.clear();
        }

        Ok(kml)
    }

    fn text_cb(&mut self, event: &BytesText) {
        if self.tag == KmlTag::PlacemarkTimestampWhen
            || self.tag == KmlTag::PlacemarkPointCoordinates
        {
            let val = event.xml_content().unwrap_or_default();

            let val = val.replace(['\n', '\r', '\t', ' '], "");

            if self.tag == KmlTag::PlacemarkTimestampWhen && val.len() >= 19 {
                // YYYY-MM-DDTHH:MM:SSZ
                // 0   4  7  10 13 16 19
                match chrono::NaiveDateTime::parse_from_str(&val, "%Y-%m-%dT%H:%M:%SZ") {
                    Ok(res) => {
                        self.curr.timestamp = res.and_utc().timestamp();
                        let now = time();
                        if self.curr.timestamp > now {
                            self.curr.timestamp = now;
                        }
                    }
                    Err(_err) => {
                        self.curr.timestamp = time();
                    }
                }
            } else if self.tag == KmlTag::PlacemarkPointCoordinates {
                let parts = val.splitn(2, ',').collect::<Vec<_>>();
                if let [longitude, latitude] = &parts[..] {
                    self.curr.longitude = longitude.parse().unwrap_or_default();
                    self.curr.latitude = latitude.parse().unwrap_or_default();
                }
            }
        }
    }

    fn endtag_cb(&mut self, event: &BytesEnd) {
        let tag = String::from_utf8_lossy(event.name().as_ref())
            .trim()
            .to_lowercase();

        match self.tag {
            KmlTag::PlacemarkTimestampWhen => {
                if tag == "when" {
                    self.tag = KmlTag::PlacemarkTimestamp
                }
            }
            KmlTag::PlacemarkTimestamp => {
                if tag == "timestamp" {
                    self.tag = KmlTag::Placemark
                }
            }
            KmlTag::PlacemarkPointCoordinates => {
                if tag == "coordinates" {
                    self.tag = KmlTag::PlacemarkPoint
                }
            }
            KmlTag::PlacemarkPoint => {
                if tag == "point" {
                    self.tag = KmlTag::Placemark
                }
            }
            KmlTag::Placemark => {
                if tag == "placemark" {
                    if 0 != self.curr.timestamp
                        && 0. != self.curr.latitude
                        && 0. != self.curr.longitude
                    {
                        self.locations
                            .push(std::mem::replace(&mut self.curr, Location::new()));
                    }
                    self.tag = KmlTag::Undefined;
                }
            }
            KmlTag::Undefined => {}
        }
    }

    fn starttag_cb<B: std::io::BufRead>(
        &mut self,
        event: &BytesStart,
        reader: &quick_xml::Reader<B>,
    ) {
        let tag = String::from_utf8_lossy(event.name().as_ref())
            .trim()
            .to_lowercase();
        if tag == "document" {
            if let Some(addr) = event.attributes().filter_map(|a| a.ok()).find(|attr| {
                String::from_utf8_lossy(attr.key.as_ref())
                    .trim()
                    .to_lowercase()
                    == "addr"
            }) {
                self.addr = addr
                    .decode_and_unescape_value(reader.decoder())
                    .ok()
                    .map(|a| a.into_owned());
            }
        } else if tag == "placemark" {
            self.tag = KmlTag::Placemark;
            self.curr.timestamp = 0;
            self.curr.latitude = 0.0;
            self.curr.longitude = 0.0;
            self.curr.accuracy = 0.0
        } else if tag == "timestamp" && self.tag == KmlTag::Placemark {
            self.tag = KmlTag::PlacemarkTimestamp;
        } else if tag == "when" && self.tag == KmlTag::PlacemarkTimestamp {
            self.tag = KmlTag::PlacemarkTimestampWhen;
        } else if tag == "point" && self.tag == KmlTag::Placemark {
            self.tag = KmlTag::PlacemarkPoint;
        } else if tag == "coordinates" && self.tag == KmlTag::PlacemarkPoint {
            self.tag = KmlTag::PlacemarkPointCoordinates;
            if let Some(acc) = event.attributes().find_map(|attr| {
                attr.ok().filter(|a| {
                    String::from_utf8_lossy(a.key.as_ref())
                        .trim()
                        .eq_ignore_ascii_case("accuracy")
                })
            }) {
                let v = acc
                    .decode_and_unescape_value(reader.decoder())
                    .unwrap_or_default();

                self.curr.accuracy = v.trim().parse().unwrap_or_default();
            }
        }
    }
}

/// Enables location streaming in chat identified by `chat_id` for `seconds` seconds.
#[expect(clippy::arithmetic_side_effects)]
pub async fn send_locations_to_chat(
    context: &Context,
    chat_id: ChatId,
    seconds: i64,
) -> Result<()> {
    ensure!(seconds >= 0);
    ensure!(!chat_id.is_special());
    let now = time();
    let is_sending_locations_before = is_sending_locations_to_chat(context, Some(chat_id)).await?;
    context
        .sql
        .execute(
            "UPDATE chats    \
         SET locations_send_begin=?,        \
         locations_send_until=?  \
         WHERE id=?",
            (
                if 0 != seconds { now } else { 0 },
                if 0 != seconds { now + seconds } else { 0 },
                chat_id,
            ),
        )
        .await?;
    if 0 != seconds && !is_sending_locations_before {
        let mut msg = Message::new_text(stock_str::msg_location_enabled(context).await);
        msg.param.set_cmd(SystemMessage::LocationStreamingEnabled);
        chat::send_msg(context, chat_id, &mut msg)
            .await
            .unwrap_or_default();
    } else if 0 == seconds && is_sending_locations_before {
        let stock_str = stock_str::msg_location_disabled(context).await;
        chat::add_info_msg(context, chat_id, &stock_str).await?;
    }
    context.emit_event(EventType::ChatModified(chat_id));
    chatlist_events::emit_chatlist_item_changed(context, chat_id);
    if 0 != seconds {
        context.scheduler.interrupt_location().await;
    }
    Ok(())
}

/// Returns whether `chat_id` or any chat is sending locations.
///
/// If `chat_id` is `Some` only that chat is checked, otherwise returns `true` if any chat
/// is sending locations.
pub async fn is_sending_locations_to_chat(
    context: &Context,
    chat_id: Option<ChatId>,
) -> Result<bool> {
    let exists = match chat_id {
        Some(chat_id) => {
            context
                .sql
                .exists(
                    "SELECT COUNT(id) FROM chats  WHERE id=?  AND locations_send_until>?;",
                    (chat_id, time()),
                )
                .await?
        }
        None => {
            context
                .sql
                .exists(
                    "SELECT COUNT(id) FROM chats  WHERE locations_send_until>?;",
                    (time(),),
                )
                .await?
        }
    };
    Ok(exists)
}

/// Sets current location of the user device.
pub async fn set(context: &Context, latitude: f64, longitude: f64, accuracy: f64) -> Result<bool> {
    if latitude == 0.0 && longitude == 0.0 {
        return Ok(true);
    }
    let mut continue_streaming = false;
    let now = time();

    let chats = context
        .sql
        .query_map_vec(
            "SELECT id FROM chats WHERE locations_send_until>?;",
            (now,),
            |row| {
                let id: i32 = row.get(0)?;
                Ok(id)
            },
        )
        .await?;

    let mut stored_location = false;
    for chat_id in chats {
        context.sql.execute(
                "INSERT INTO locations  \
                 (latitude, longitude, accuracy, timestamp, chat_id, from_id) VALUES (?,?,?,?,?,?);",
                 (
                    latitude,
                    longitude,
                    accuracy,
                    now,
                    chat_id,
                    ContactId::SELF,
                )).await.context("Failed to store location")?;
        stored_location = true;

        info!(context, "Stored location for chat {chat_id}.");
        continue_streaming = true;
    }
    if continue_streaming {
        context.emit_location_changed(Some(ContactId::SELF)).await?;
    };
    if stored_location {
        // Interrupt location loop so it may send a location-only message.
        context.scheduler.interrupt_location().await;
    }

    Ok(continue_streaming)
}

/// Searches for locations in the given time range, optionally filtering by chat and contact IDs.
#[expect(clippy::arithmetic_side_effects)]
pub async fn get_range(
    context: &Context,
    chat_id: Option<ChatId>,
    contact_id: Option<u32>,
    timestamp_from: i64,
    mut timestamp_to: i64,
) -> Result<Vec<Location>> {
    if timestamp_to == 0 {
        timestamp_to = time() + 10;
    }

    let (disable_chat_id, chat_id) = match chat_id {
        Some(chat_id) => (0, chat_id),
        None => (1, ChatId::new(0)), // this ChatId is unused
    };
    let (disable_contact_id, contact_id) = match contact_id {
        Some(contact_id) => (0, contact_id),
        None => (1, 0), // this contact_id is unused
    };
    let list = context
        .sql
        .query_map_vec(
            "SELECT l.id, l.latitude, l.longitude, l.accuracy, l.timestamp, l.independent, \
             COALESCE(m.id, 0) AS msg_id, l.from_id, l.chat_id, COALESCE(m.txt, '') AS txt \
             FROM locations l  LEFT JOIN msgs m ON l.id=m.location_id  WHERE (? OR l.chat_id=?) \
             AND (? OR l.from_id=?) \
             AND (l.independent=1 OR (l.timestamp>=? AND l.timestamp<=?)) \
             ORDER BY l.timestamp DESC, l.id DESC, msg_id DESC;",
            (
                disable_chat_id,
                chat_id,
                disable_contact_id,
                contact_id as i32,
                timestamp_from,
                timestamp_to,
            ),
            |row| {
                let msg_id = row.get(6)?;
                let txt: String = row.get(9)?;
                let marker = if msg_id != 0 && is_marker(&txt) {
                    Some(txt)
                } else {
                    None
                };
                let loc = Location {
                    location_id: row.get(0)?,
                    latitude: row.get(1)?,
                    longitude: row.get(2)?,
                    accuracy: row.get(3)?,
                    timestamp: row.get(4)?,
                    independent: row.get(5)?,
                    msg_id,
                    contact_id: row.get(7)?,
                    chat_id: row.get(8)?,
                    marker,
                };
                Ok(loc)
            },
        )
        .await?;
    Ok(list)
}

fn is_marker(txt: &str) -> bool {
    let mut chars = txt.chars();
    if let Some(c) = chars.next() {
        !c.is_whitespace() && chars.next().is_none()
    } else {
        false
    }
}

/// Deletes all locations from the database.
pub async fn delete_all(context: &Context) -> Result<()> {
    context.sql.execute("DELETE FROM locations;", ()).await?;
    context.emit_location_changed(None).await?;
    Ok(())
}

/// Deletes expired locations.
///
/// Only path locations are deleted.
/// POIs should be deleted when corresponding message is deleted.
pub(crate) async fn delete_expired(context: &Context, now: i64) -> Result<()> {
    let Some(delete_device_after) = context.get_config_delete_device_after().await? else {
        return Ok(());
    };

    let threshold_timestamp = now.saturating_sub(delete_device_after);
    let deleted = context
        .sql
        .execute(
            "DELETE FROM locations WHERE independent=0 AND timestamp < ?",
            (threshold_timestamp,),
        )
        .await?
        > 0;
    if deleted {
        info!(context, "Deleted {deleted} expired locations.");
        context.emit_location_changed(None).await?;
    }
    Ok(())
}

/// Deletes location if it is an independent location.
///
/// This function is used when a message is deleted
/// that has a corresponding `location_id`.
pub(crate) async fn delete_poi_location(context: &Context, location_id: u32) -> Result<()> {
    context
        .sql
        .execute(
            "DELETE FROM locations WHERE independent = 1 AND id=?",
            (location_id as i32,),
        )
        .await?;
    Ok(())
}

/// Deletes POI locations that don't have corresponding message anymore.
pub(crate) async fn delete_orphaned_poi_locations(context: &Context) -> Result<()> {
    context.sql.execute("
    DELETE FROM locations
    WHERE independent=1 AND id NOT IN
    (SELECT location_id from MSGS LEFT JOIN locations
     ON locations.id=location_id
     WHERE location_id>0 -- This check makes the query faster by not looking for locations with ID 0 that don't exist.
     AND msgs.chat_id != ?)", (DC_CHAT_ID_TRASH,)).await?;
    Ok(())
}

/// Returns `location.kml` contents.
#[expect(clippy::arithmetic_side_effects)]
pub async fn get_kml(context: &Context, chat_id: ChatId) -> Result<Option<(String, u32)>> {
    let mut last_added_location_id = 0;

    let self_addr = context.get_primary_self_addr().await?;

    let (locations_send_begin, locations_send_until, locations_last_sent) = context.sql.query_row(
        "SELECT locations_send_begin, locations_send_until, locations_last_sent  FROM chats  WHERE id=?;",
        (chat_id,), |row| {
            let send_begin: i64 = row.get(0)?;
            let send_until: i64 = row.get(1)?;
            let last_sent: i64 = row.get(2)?;

            Ok((send_begin, send_until, last_sent))
        })
        .await?;

    let now = time();
    let mut location_count = 0;
    let mut ret = String::new();
    if locations_send_begin != 0 && now <= locations_send_until {
        ret += &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
            <kml xmlns=\"http://www.opengis.net/kml/2.2\">\n<Document addr=\"{self_addr}\">\n",
        );

        context
            .sql
            .query_map(
                "SELECT id, latitude, longitude, accuracy, timestamp \
             FROM locations  WHERE from_id=? \
             AND timestamp>=? \
             AND (timestamp>=? OR \
                  timestamp=(SELECT MAX(timestamp) FROM locations WHERE from_id=?)) \
             AND independent=0 \
             GROUP BY timestamp \
             ORDER BY timestamp;",
             (
                    ContactId::SELF,
                    locations_send_begin,
                    locations_last_sent,
                    ContactId::SELF
                ),
                |row| {
                    let location_id: i32 = row.get(0)?;
                    let latitude: f64 = row.get(1)?;
                    let longitude: f64 = row.get(2)?;
                    let accuracy: f64 = row.get(3)?;
                    let timestamp = get_kml_timestamp(row.get(4)?);

                    Ok((location_id, latitude, longitude, accuracy, timestamp))
                },
                |rows| {
                    for row in rows {
                        let (location_id, latitude, longitude, accuracy, timestamp) = row?;
                        ret += &format!(
                            "<Placemark>\
                <Timestamp><when>{timestamp}</when></Timestamp>\
                <Point><coordinates accuracy=\"{accuracy}\">{longitude},{latitude}</coordinates></Point>\
                </Placemark>\n"
                        );
                        location_count += 1;
                        last_added_location_id = location_id as u32;
                    }
                    Ok(())
                },
            )
            .await?;
        ret += "</Document>\n</kml>";
    }

    if location_count > 0 {
        Ok(Some((ret, last_added_location_id)))
    } else {
        Ok(None)
    }
}

fn get_kml_timestamp(utc: i64) -> String {
    // Returns a string formatted as YYYY-MM-DDTHH:MM:SSZ. The trailing `Z` indicates UTC.
    chrono::DateTime::<chrono::Utc>::from_timestamp(utc, 0)
        .unwrap()
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Returns a KML document containing a single location with the given timestamp and coordinates.
pub fn get_message_kml(timestamp: i64, latitude: f64, longitude: f64) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <kml xmlns=\"http://www.opengis.net/kml/2.2\">\n\
         <Document>\n\
         <Placemark>\
         <Timestamp><when>{}</when></Timestamp>\
         <Point><coordinates>{},{}</coordinates></Point>\
         </Placemark>\n\
         </Document>\n\
         </kml>",
        get_kml_timestamp(timestamp),
        longitude,
        latitude,
    )
}

/// Sets the timestamp of the last time location was sent in the chat.
pub async fn set_kml_sent_timestamp(
    context: &Context,
    chat_id: ChatId,
    timestamp: i64,
) -> Result<()> {
    context
        .sql
        .execute(
            "UPDATE chats SET locations_last_sent=? WHERE id=?;",
            (timestamp, chat_id),
        )
        .await?;
    Ok(())
}

/// Sets the location of the message.
pub async fn set_msg_location_id(context: &Context, msg_id: MsgId, location_id: u32) -> Result<()> {
    context
        .sql
        .execute(
            "UPDATE msgs SET location_id=? WHERE id=?;",
            (location_id, msg_id),
        )
        .await?;

    Ok(())
}

/// Saves given locations to the database.
///
/// Returns the database row ID of the location with the highest timestamp.
pub(crate) async fn save(
    context: &Context,
    chat_id: ChatId,
    contact_id: ContactId,
    locations: &[Location],
    independent: bool,
) -> Result<Option<u32>> {
    ensure!(!chat_id.is_special(), "Invalid chat id");

    let mut newest_timestamp = 0;
    let mut newest_location_id = None;

    let stmt_insert = "INSERT INTO locations\
             (timestamp, from_id, chat_id, latitude, longitude, accuracy, independent) \
             VALUES (?,?,?,?,?,?,?);";

    for location in locations {
        let &Location {
            timestamp,
            latitude,
            longitude,
            accuracy,
            ..
        } = location;

        context
            .sql
            .call_write(|conn| {
                let mut stmt_test = conn
                    .prepare_cached("SELECT id FROM locations WHERE timestamp=? AND from_id=?")?;
                let mut stmt_insert = conn.prepare_cached(stmt_insert)?;

                let exists = stmt_test.exists((timestamp, contact_id))?;

                if independent || !exists {
                    stmt_insert.execute((
                        timestamp,
                        contact_id,
                        chat_id,
                        latitude,
                        longitude,
                        accuracy,
                        independent,
                    ))?;

                    if timestamp > newest_timestamp {
                        newest_timestamp = timestamp;
                        newest_location_id = Some(u32::try_from(conn.last_insert_rowid())?);
                    }
                }

                Ok(())
            })
            .await?;
    }

    Ok(newest_location_id)
}

pub(crate) async fn location_loop(context: &Context, interrupt_receiver: Receiver<()>) {
    loop {
        let next_event = match maybe_send_locations(context).await {
            Err(err) => {
                warn!(context, "maybe_send_locations failed: {:#}", err);
                Some(60) // Retry one minute later.
            }
            Ok(next_event) => next_event,
        };

        let duration = if let Some(next_event) = next_event {
            Duration::from_secs(next_event)
        } else {
            Duration::from_secs(86400)
        };

        info!(
            context,
            "Location loop is waiting for {} or interrupt",
            duration_to_str(duration)
        );
        match timeout(duration, interrupt_receiver.recv()).await {
            Err(_err) => {
                info!(context, "Location loop timeout.");
            }
            Ok(Err(err)) => {
                warn!(
                    context,
                    "Interrupt channel closed, location loop exits now: {err:#}."
                );
                return;
            }
            Ok(Ok(())) => {
                info!(context, "Location loop received interrupt.");
            }
        }
    }
}

/// Returns number of seconds until the next time location streaming for some chat ends
/// automatically.
#[expect(clippy::arithmetic_side_effects)]
async fn maybe_send_locations(context: &Context) -> Result<Option<u64>> {
    let mut next_event: Option<u64> = None;

    let now = time();
    let rows = context
        .sql
        .query_map_vec(
            "SELECT id, locations_send_begin, locations_send_until, locations_last_sent
             FROM chats
             WHERE locations_send_until>0",
            [],
            |row| {
                let chat_id: ChatId = row.get(0)?;
                let locations_send_begin: i64 = row.get(1)?;
                let locations_send_until: i64 = row.get(2)?;
                let locations_last_sent: i64 = row.get(3)?;
                Ok((
                    chat_id,
                    locations_send_begin,
                    locations_send_until,
                    locations_last_sent,
                ))
            },
        )
        .await
        .context("failed to query location streaming chats")?;

    for (chat_id, locations_send_begin, locations_send_until, locations_last_sent) in rows {
        if locations_send_begin > 0 && locations_send_until > now {
            let can_send = now > locations_last_sent + 60;
            let has_locations = context
                .sql
                .exists(
                    "SELECT COUNT(id) \
     FROM locations \
     WHERE from_id=? \
     AND timestamp>=? \
     AND timestamp>? \
     AND independent=0",
                    (ContactId::SELF, locations_send_begin, locations_last_sent),
                )
                .await?;

            next_event = next_event
                .into_iter()
                .chain(u64::try_from(locations_send_until - now))
                .min();

            if has_locations {
                if can_send {
                    // Send location-only message.
                    // Pending locations are attached automatically to every message,
                    // so also to this empty text message.
                    info!(
                        context,
                        "Chat {} has pending locations, sending them.", chat_id
                    );
                    let mut msg = Message::new(Viewtype::Text);
                    msg.hidden = true;
                    msg.param.set_cmd(SystemMessage::LocationOnly);
                    chat::send_msg(context, chat_id, &mut msg).await?;
                } else {
                    // Wait until pending locations can be sent.
                    info!(
                        context,
                        "Chat {} has pending locations, but they can't be sent yet.", chat_id
                    );
                    next_event = next_event
                        .into_iter()
                        .chain(u64::try_from(locations_last_sent + 61 - now))
                        .min();
                }
            } else {
                info!(
                    context,
                    "Chat {} has location streaming enabled, but no pending locations.", chat_id
                );
            }
        } else {
            // Location streaming was either explicitly disabled (locations_send_begin = 0) or
            // locations_send_until is in the past.
            info!(
                context,
                "Disabling location streaming for chat {}.", chat_id
            );
            context
                .sql
                .execute(
                    "UPDATE chats \
                         SET locations_send_begin=0, locations_send_until=0 \
                         WHERE id=?",
                    (chat_id,),
                )
                .await
                .context("failed to disable location streaming")?;

            let stock_str = stock_str::msg_location_disabled(context).await;
            chat::add_info_msg(context, chat_id, &stock_str).await?;
            context.emit_event(EventType::ChatModified(chat_id));
            chatlist_events::emit_chatlist_item_changed(context, chat_id);
        }
    }

    Ok(next_event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::message::MessageState;
    use crate::receive_imf::receive_imf;
    use crate::test_utils::{TestContext, TestContextManager};
    use crate::tools::SystemTime;

    #[test]
    fn test_kml_parse() {
        let xml =
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n<Document addr=\"user@example.org\">\n<Placemark><Timestamp><when>2019-03-06T21:09:57Z</when></Timestamp><Point><coordinates accuracy=\"32.000000\">9.423110,53.790302</coordinates></Point></Placemark>\n<PlaceMARK>\n<Timestamp><WHEN > \n\t2018-12-13T22:11:12Z\t</WHEN></Timestamp><Point><coordinates aCCuracy=\"2.500000\"> 19.423110 \t , \n 63.790302\n </coordinates></Point></PlaceMARK>\n</Document>\n</kml>";

        let kml = Kml::parse(xml).expect("parsing failed");

        assert!(kml.addr.is_some());
        assert_eq!(kml.addr.as_ref().unwrap(), "user@example.org",);

        let locations_ref = &kml.locations;
        assert_eq!(locations_ref.len(), 2);

        assert!(locations_ref[0].latitude > 53.6f64);
        assert!(locations_ref[0].latitude < 53.8f64);
        assert!(locations_ref[0].longitude > 9.3f64);
        assert!(locations_ref[0].longitude < 9.5f64);
        assert!(locations_ref[0].accuracy > 31.9f64);
        assert!(locations_ref[0].accuracy < 32.1f64);
        assert_eq!(locations_ref[0].timestamp, 1551906597);

        assert!(locations_ref[1].latitude > 63.6f64);
        assert!(locations_ref[1].latitude < 63.8f64);
        assert!(locations_ref[1].longitude > 19.3f64);
        assert!(locations_ref[1].longitude < 19.5f64);
        assert!(locations_ref[1].accuracy > 2.4f64);
        assert!(locations_ref[1].accuracy < 2.6f64);
        assert_eq!(locations_ref[1].timestamp, 1544739072);
    }

    #[test]
    fn test_kml_parse_error() {
        let xml = b"<?><xmlversi\"\"\">?</document>";
        assert!(Kml::parse(xml).is_err());
    }

    #[test]
    fn test_get_message_kml() {
        let timestamp = 1598490000;

        let xml = get_message_kml(timestamp, 51.423723f64, 8.552556f64);
        let kml = Kml::parse(xml.as_bytes()).expect("parsing failed");
        let locations_ref = &kml.locations;
        assert_eq!(locations_ref.len(), 1);

        assert!(locations_ref[0].latitude >= 51.423723f64);
        assert!(locations_ref[0].latitude < 51.423724f64);
        assert!(locations_ref[0].longitude >= 8.552556f64);
        assert!(locations_ref[0].longitude < 8.552557f64);
        assert!(locations_ref[0].accuracy.abs() < f64::EPSILON);
        assert_eq!(locations_ref[0].timestamp, timestamp);
    }

    #[test]
    fn test_is_marker() {
        assert!(is_marker("f"));
        assert!(!is_marker("foo"));
        assert!(is_marker("🏠"));
        assert!(!is_marker(" "));
        assert!(!is_marker("\t"));
    }

    /// Tests that location.kml is hidden.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receive_location_kml() -> Result<()> {
        let alice = TestContext::new_alice().await;

        receive_imf(
            &alice,
            br#"Subject: Hello
Message-ID: hello@example.net
To: Alice <alice@example.org>
From: Bob <bob@example.net>
Date: Mon, 20 Dec 2021 00:00:00 +0000
Chat-Version: 1.0
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

Text message."#,
            false,
        )
        .await?;
        let received_msg = alice.get_last_msg().await;
        assert_eq!(received_msg.text, "Text message.");

        receive_imf(
            &alice,
            br#"Subject: locations
MIME-Version: 1.0
To: <alice@example.org>
From: <bob@example.net>
Date: Tue, 21 Dec 2021 00:00:00 +0000
Chat-Version: 1.0
Message-ID: <foobar@example.net>
Content-Type: multipart/mixed; boundary="U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF"


--U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no



--U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF
Content-Type: application/vnd.google-earth.kml+xml
Content-Disposition: attachment; filename="location.kml"

<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document addr="bob@example.net">
<Placemark><Timestamp><when>2021-11-21T00:00:00Z</when></Timestamp><Point><coordinates accuracy="1.0000000000000000">10.00000000000000,20.00000000000000</coordinates></Point></Placemark>
</Document>
</kml>

--U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF--"#,
            false,
        )
        .await?;

        // Received location message is not visible, last message stays the same.
        let received_msg2 = alice.get_last_msg().await;
        assert_eq!(received_msg2.id, received_msg.id);

        let locations = get_range(&alice, None, None, 0, 0).await?;
        assert_eq!(locations.len(), 1);
        Ok(())
    }

    /// Tests that `location.kml` is not hidden and not seen if it contains a message.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn receive_visible_location_kml() -> Result<()> {
        let alice = TestContext::new_alice().await;

        receive_imf(
            &alice,
            br#"Subject: locations
MIME-Version: 1.0
To: <alice@example.org>
From: <bob@example.net>
Date: Tue, 21 Dec 2021 00:00:00 +0000
Chat-Version: 1.0
Message-ID: <foobar@localhost>
Content-Type: multipart/mixed; boundary="U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF"


--U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

Text message.


--U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF
Content-Type: application/vnd.google-earth.kml+xml
Content-Disposition: attachment; filename="location.kml"

<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document addr="bob@example.net">
<Placemark><Timestamp><when>2021-11-21T00:00:00Z</when></Timestamp><Point><coordinates accuracy="1.0000000000000000">10.00000000000000,20.00000000000000</coordinates></Point></Placemark>
</Document>
</kml>

--U8BOG8qNXfB0GgLiQ3PKUjlvdIuLRF--"#,
            false,
        )
        .await?;

        let received_msg = alice.get_last_msg().await;
        assert_eq!(received_msg.text, "Text message.");
        assert_eq!(received_msg.state, MessageState::InFresh);

        let locations = get_range(&alice, None, None, 0, 0).await?;
        assert_eq!(locations.len(), 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_send_locations_to_chat() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let bob = TestContext::new_bob().await;

        let alice_chat = alice.create_chat(&bob).await;
        send_locations_to_chat(&alice, alice_chat.id, 1000).await?;
        let sent = alice.pop_sent_msg().await;
        let msg = bob.recv_msg(&sent).await;
        assert_eq!(msg.text, "Location streaming enabled by alice@example.org.");
        let bob_chat_id = msg.chat_id;

        assert_eq!(set(&alice, 10.0, 20.0, 1.0).await?, true);

        // Send image without text.
        let file_name = "image.png";
        let bytes = include_bytes!("../test-data/image/logo.png");
        let file = alice.get_blobdir().join(file_name);
        tokio::fs::write(&file, bytes).await?;
        let mut msg = Message::new(Viewtype::Image);
        msg.set_file_and_deduplicate(&alice, &file, Some("logo.png"), None)?;
        let sent = alice.send_msg(alice_chat.id, &mut msg).await;
        let alice_msg = Message::load_from_db(&alice, sent.sender_msg_id).await?;
        assert_eq!(alice_msg.has_location(), false);

        let msg = bob.recv_msg_opt(&sent).await.unwrap();
        assert!(msg.chat_id == bob_chat_id);
        assert_eq!(msg.msg_ids.len(), 1);

        let bob_msg = Message::load_from_db(&bob, *msg.msg_ids.first().unwrap()).await?;
        assert_eq!(bob_msg.chat_id, bob_chat_id);
        assert_eq!(bob_msg.viewtype, Viewtype::Image);
        assert_eq!(bob_msg.has_location(), false);

        let bob_locations = get_range(&bob, None, None, 0, 0).await?;
        assert_eq!(bob_locations.len(), 1);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_delete_expired_locations() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        // Alice enables deletion of messages from device after 1 week.
        alice
            .set_config(Config::DeleteDeviceAfter, Some("604800"))
            .await?;
        // Bob enables deletion of messages from device after 1 day.
        bob.set_config(Config::DeleteDeviceAfter, Some("86400"))
            .await?;

        let alice_chat = alice.create_chat(bob).await;

        // Alice enables location streaming.
        // Bob receives a message saying that Alice enabled location streaming.
        send_locations_to_chat(alice, alice_chat.id, 60).await?;
        bob.recv_msg(&alice.pop_sent_msg().await).await;

        // Alice gets new location from GPS.
        assert_eq!(set(alice, 10.0, 20.0, 1.0).await?, true);
        assert_eq!(get_range(alice, None, None, 0, 0).await?.len(), 1);

        // 10 seconds later location sending stream manages to send location.
        SystemTime::shift(Duration::from_secs(10));
        delete_expired(alice, time()).await?;
        maybe_send_locations(alice).await?;
        bob.recv_msg_opt(&alice.pop_sent_msg().await).await;
        assert_eq!(get_range(alice, None, None, 0, 0).await?.len(), 1);
        assert_eq!(get_range(bob, None, None, 0, 0).await?.len(), 1);

        // Location-only messages are "auto-generated", but they mustn't make the contact a bot.
        let contact = bob.add_or_lookup_contact(alice).await;
        assert!(!contact.is_bot());

        // Day later Bob removes location.
        SystemTime::shift(Duration::from_secs(86400));
        delete_expired(alice, time()).await?;
        delete_expired(bob, time()).await?;
        assert_eq!(get_range(alice, None, None, 0, 0).await?.len(), 1);
        assert_eq!(get_range(bob, None, None, 0, 0).await?.len(), 0);

        // Week late Alice removes location.
        SystemTime::shift(Duration::from_secs(604800));
        delete_expired(alice, time()).await?;
        delete_expired(bob, time()).await?;
        assert_eq!(get_range(alice, None, None, 0, 0).await?.len(), 0);
        assert_eq!(get_range(bob, None, None, 0, 0).await?.len(), 0);

        Ok(())
    }
}
