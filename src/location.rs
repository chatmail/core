//! Location handling
use std::convert::TryFrom;

use anyhow::{ensure, Error};
use async_std::prelude::*;
use bitflags::bitflags;
use quick_xml::events::{BytesEnd, BytesStart, BytesText};
use sqlx::Row;

use crate::chat::{self, ChatId};
use crate::config::Config;
use crate::constants::{Viewtype, DC_CONTACT_ID_SELF};
use crate::context::Context;
use crate::dc_tools::time;
use crate::events::EventType;
use crate::job::{self, Job};
use crate::message::{Message, MsgId};
use crate::mimeparser::SystemMessage;
use crate::param::Params;
use crate::stock_str;

/// Location record
#[derive(Debug, Clone, Default)]
pub struct Location {
    pub location_id: u32,
    pub latitude: f64,
    pub longitude: f64,
    pub accuracy: f64,
    pub timestamp: i64,
    pub contact_id: u32,
    pub msg_id: u32,
    pub chat_id: ChatId,
    pub marker: Option<String>,
    pub independent: u32,
}

impl Location {
    pub fn new() -> Self {
        Default::default()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Kml {
    pub addr: Option<String>,
    pub locations: Vec<Location>,
    tag: KmlTag,
    pub curr: Location,
}

bitflags! {
    #[derive(Default)]
    struct KmlTag: i32 {
        const UNDEFINED = 0x00;
        const PLACEMARK = 0x01;
        const TIMESTAMP = 0x02;
        const WHEN = 0x04;
        const POINT = 0x08;
        const COORDINATES = 0x10;
    }
}

impl Kml {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn parse(context: &Context, to_parse: &[u8]) -> Result<Self, Error> {
        ensure!(to_parse.len() <= 1024 * 1024, "kml-file is too large");

        let mut reader = quick_xml::Reader::from_reader(to_parse);
        reader.trim_text(true);

        let mut kml = Kml::new();
        kml.locations = Vec::with_capacity(100);

        let mut buf = Vec::new();

        loop {
            match reader.read_event(&mut buf) {
                Ok(quick_xml::events::Event::Start(ref e)) => kml.starttag_cb(e, &reader),
                Ok(quick_xml::events::Event::End(ref e)) => kml.endtag_cb(e),
                Ok(quick_xml::events::Event::Text(ref e)) => kml.text_cb(e, &reader),
                Err(e) => {
                    error!(
                        context,
                        "Location parsing: Error at position {}: {:?}",
                        reader.buffer_position(),
                        e
                    );
                }
                Ok(quick_xml::events::Event::Eof) => break,
                _ => (),
            }
            buf.clear();
        }

        Ok(kml)
    }

    fn text_cb<B: std::io::BufRead>(&mut self, event: &BytesText, reader: &quick_xml::Reader<B>) {
        if self.tag.contains(KmlTag::WHEN) || self.tag.contains(KmlTag::COORDINATES) {
            let val = event.unescape_and_decode(reader).unwrap_or_default();

            let val = val
                .replace("\n", "")
                .replace("\r", "")
                .replace("\t", "")
                .replace(" ", "");

            if self.tag.contains(KmlTag::WHEN) && val.len() >= 19 {
                // YYYY-MM-DDTHH:MM:SSZ
                // 0   4  7  10 13 16 19
                match chrono::NaiveDateTime::parse_from_str(&val, "%Y-%m-%dT%H:%M:%SZ") {
                    Ok(res) => {
                        self.curr.timestamp = res.timestamp();
                        if self.curr.timestamp > time() {
                            self.curr.timestamp = time();
                        }
                    }
                    Err(_err) => {
                        self.curr.timestamp = time();
                    }
                }
            } else if self.tag.contains(KmlTag::COORDINATES) {
                let parts = val.splitn(2, ',').collect::<Vec<_>>();
                if let [longitude, latitude] = &parts[..] {
                    self.curr.longitude = longitude.parse().unwrap_or_default();
                    self.curr.latitude = latitude.parse().unwrap_or_default();
                }
            }
        }
    }

    fn endtag_cb(&mut self, event: &BytesEnd) {
        let tag = String::from_utf8_lossy(event.name()).trim().to_lowercase();

        if tag == "placemark" {
            if self.tag.contains(KmlTag::PLACEMARK)
                && 0 != self.curr.timestamp
                && 0. != self.curr.latitude
                && 0. != self.curr.longitude
            {
                self.locations
                    .push(std::mem::replace(&mut self.curr, Location::new()));
            }
            self.tag = KmlTag::UNDEFINED;
        };
    }

    fn starttag_cb<B: std::io::BufRead>(
        &mut self,
        event: &BytesStart,
        reader: &quick_xml::Reader<B>,
    ) {
        let tag = String::from_utf8_lossy(event.name()).trim().to_lowercase();
        if tag == "document" {
            if let Some(addr) = event.attributes().find(|attr| {
                attr.as_ref()
                    .map(|a| String::from_utf8_lossy(a.key).trim().to_lowercase() == "addr")
                    .unwrap_or_default()
            }) {
                self.addr = addr.unwrap().unescape_and_decode_value(reader).ok();
            }
        } else if tag == "placemark" {
            self.tag = KmlTag::PLACEMARK;
            self.curr.timestamp = 0;
            self.curr.latitude = 0.0;
            self.curr.longitude = 0.0;
            self.curr.accuracy = 0.0
        } else if tag == "timestamp" && self.tag.contains(KmlTag::PLACEMARK) {
            self.tag = KmlTag::PLACEMARK | KmlTag::TIMESTAMP
        } else if tag == "when" && self.tag.contains(KmlTag::TIMESTAMP) {
            self.tag = KmlTag::PLACEMARK | KmlTag::TIMESTAMP | KmlTag::WHEN
        } else if tag == "point" && self.tag.contains(KmlTag::PLACEMARK) {
            self.tag = KmlTag::PLACEMARK | KmlTag::POINT
        } else if tag == "coordinates" && self.tag.contains(KmlTag::POINT) {
            self.tag = KmlTag::PLACEMARK | KmlTag::POINT | KmlTag::COORDINATES;
            if let Some(acc) = event.attributes().find(|attr| {
                attr.as_ref()
                    .map(|a| String::from_utf8_lossy(a.key).trim().to_lowercase() == "accuracy")
                    .unwrap_or_default()
            }) {
                let v = acc
                    .unwrap()
                    .unescape_and_decode_value(reader)
                    .unwrap_or_default();

                self.curr.accuracy = v.trim().parse().unwrap_or_default();
            }
        }
    }
}

// location streaming
pub async fn send_locations_to_chat(context: &Context, chat_id: ChatId, seconds: i64) {
    let now = time();
    if !(seconds < 0 || chat_id.is_special()) {
        let is_sending_locations_before =
            is_sending_locations_to_chat(context, Some(chat_id)).await;
        if context
            .sql
            .execute(
                sqlx::query(
                    "UPDATE chats    \
             SET locations_send_begin=?,        \
             locations_send_until=?  \
             WHERE id=?",
                )
                .bind(if 0 != seconds { now } else { 0 })
                .bind(if 0 != seconds { now + seconds } else { 0 })
                .bind(chat_id),
            )
            .await
            .is_ok()
        {
            if 0 != seconds && !is_sending_locations_before {
                let mut msg = Message::new(Viewtype::Text);
                msg.text = Some(stock_str::msg_location_enabled(context).await);
                msg.param.set_cmd(SystemMessage::LocationStreamingEnabled);
                chat::send_msg(context, chat_id, &mut msg)
                    .await
                    .unwrap_or_default();
            } else if 0 == seconds && is_sending_locations_before {
                let stock_str = stock_str::msg_location_disabled(context).await;
                chat::add_info_msg(context, chat_id, stock_str).await;
            }
            context.emit_event(EventType::ChatModified(chat_id));
            if 0 != seconds {
                schedule_maybe_send_locations(context, false).await;
                job::add(
                    context,
                    job::Job::new(
                        job::Action::MaybeSendLocationsEnded,
                        chat_id.to_u32(),
                        Params::new(),
                        seconds + 1,
                    ),
                )
                .await;
            }
        }
    }
}

async fn schedule_maybe_send_locations(context: &Context, force_schedule: bool) {
    if force_schedule || !job::action_exists(context, job::Action::MaybeSendLocations).await {
        job::add(
            context,
            job::Job::new(job::Action::MaybeSendLocations, 0, Params::new(), 60),
        )
        .await;
    };
}

/// Returns whether `chat_id` or any chat is sending locations.
///
/// If `chat_id` is `Some` only that chat is checked, otherwise returns `true` if any chat
/// is sending locations.
pub async fn is_sending_locations_to_chat(context: &Context, chat_id: Option<ChatId>) -> bool {
    match chat_id {
        Some(chat_id) => context
            .sql
            .exists(
                sqlx::query("SELECT COUNT(id) FROM chats  WHERE id=?  AND locations_send_until>?;")
                    .bind(chat_id)
                    .bind(time()),
            )
            .await
            .unwrap_or_default(),
        None => context
            .sql
            .exists(
                sqlx::query("SELECT COUNT(id) FROM chats  WHERE locations_send_until>?;")
                    .bind(time()),
            )
            .await
            .unwrap_or_default(),
    }
}

pub async fn set(context: &Context, latitude: f64, longitude: f64, accuracy: f64) -> bool {
    if latitude == 0.0 && longitude == 0.0 {
        return true;
    }
    let mut continue_streaming = false;

    if let Ok(mut chats) = context
        .sql
        .fetch(sqlx::query("SELECT id FROM chats WHERE locations_send_until>?;").bind(time()))
        .await
        .map(|rows| rows.map(|row| row?.try_get::<i32, _>(0)))
    {
        while let Some(chat_id) = chats.next().await {
            let chat_id = match chat_id {
                Ok(id) => id,
                Err(_) => break,
            };
            if let Err(err) = context.sql.execute(
                sqlx::query(
                    "INSERT INTO locations  \
                     (latitude, longitude, accuracy, timestamp, chat_id, from_id) VALUES (?,?,?,?,?,?);"
                )
                    .bind(latitude)
                    .bind(longitude)
                    .bind(accuracy)
                    .bind(time())
                    .bind(chat_id)
                    .bind(DC_CONTACT_ID_SELF)

            ).await {
                warn!(context, "failed to store location {:?}", err);
            } else {
                continue_streaming = true;
            }
        }
        if continue_streaming {
            context.emit_event(EventType::LocationChanged(Some(DC_CONTACT_ID_SELF)));
        };
        schedule_maybe_send_locations(context, false).await;
    }

    continue_streaming
}

pub async fn get_range(
    context: &Context,
    chat_id: Option<ChatId>,
    contact_id: Option<u32>,
    timestamp_from: i64,
    mut timestamp_to: i64,
) -> Result<Vec<Location>, Error> {
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
        .fetch(
            sqlx::query(
                "SELECT l.id, l.latitude, l.longitude, l.accuracy, l.timestamp, l.independent, \
             COALESCE(m.id, 0) AS msg_id, l.from_id, l.chat_id, COALESCE(m.txt, '') AS txt \
             FROM locations l  LEFT JOIN msgs m ON l.id=m.location_id  WHERE (? OR l.chat_id=?) \
             AND (? OR l.from_id=?) \
             AND (l.independent=1 OR (l.timestamp>=? AND l.timestamp<=?)) \
             ORDER BY l.timestamp DESC, l.id DESC, msg_id DESC;",
            )
            .bind(disable_chat_id)
            .bind(chat_id)
            .bind(disable_contact_id)
            .bind(contact_id as i64)
            .bind(timestamp_from)
            .bind(timestamp_to),
        )
        .await?
        .map(|row| {
            let row = row?;
            let msg_id = row.try_get(6)?;
            let txt: String = row.try_get(9)?;
            let marker = if msg_id != 0 && is_marker(&txt) {
                Some(txt)
            } else {
                None
            };
            let loc = Location {
                location_id: row.try_get(0)?,
                latitude: row.try_get(1)?,
                longitude: row.try_get(2)?,
                accuracy: row.try_get(3)?,
                timestamp: row.try_get(4)?,
                independent: row.try_get(5)?,
                msg_id,
                contact_id: row.try_get(7)?,
                chat_id: row.try_get(8)?,
                marker,
            };
            Ok(loc)
        })
        .collect::<sqlx::Result<_>>()
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
pub async fn delete_all(context: &Context) -> Result<(), Error> {
    context
        .sql
        .execute(sqlx::query("DELETE FROM locations;"))
        .await?;
    context.emit_event(EventType::LocationChanged(None));
    Ok(())
}

pub async fn get_kml(context: &Context, chat_id: ChatId) -> Result<(String, u32), Error> {
    let mut last_added_location_id = 0;

    let self_addr = context
        .get_config(Config::ConfiguredAddr)
        .await?
        .unwrap_or_default();

    let (locations_send_begin, locations_send_until, locations_last_sent) = {
        let row = context.sql.fetch_one(
            sqlx::query(
                "SELECT locations_send_begin, locations_send_until, locations_last_sent  FROM chats  WHERE id=?;"
            )
                .bind(chat_id)
        ).await?;

        let send_begin: i64 = row.try_get(0)?;
        let send_until: i64 = row.try_get(1)?;
        let last_sent: i64 = row.try_get(2)?;

        (send_begin, send_until, last_sent)
    };

    let now = time();
    let mut location_count = 0;
    let mut ret = String::new();
    if locations_send_begin != 0 && now <= locations_send_until {
        ret += &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n<Document addr=\"{}\">\n",
            self_addr,
        );

        let mut rows = context.sql.fetch(
            sqlx::query(
                "SELECT id, latitude, longitude, accuracy, timestamp \
             FROM locations  WHERE from_id=? \
             AND timestamp>=? \
             AND (timestamp>=? OR timestamp=(SELECT MAX(timestamp) FROM locations WHERE from_id=?)) \
             AND independent=0 \
             GROUP BY timestamp \
             ORDER BY timestamp;"
            )
                .bind(DC_CONTACT_ID_SELF)
                .bind(locations_send_begin)
                .bind(locations_last_sent)
                .bind(DC_CONTACT_ID_SELF)
        ).await?;

        while let Some(row) = rows.next().await {
            let row = row?;
            let location_id: u32 = row.try_get(0)?;
            let latitude: f64 = row.try_get(1)?;
            let longitude: f64 = row.try_get(2)?;
            let accuracy: f64 = row.try_get(3)?;
            let timestamp = get_kml_timestamp(row.try_get(4)?);

            ret += &format!(
                "<Placemark><Timestamp><when>{}</when></Timestamp><Point><coordinates accuracy=\"{}\">{},{}</coordinates></Point></Placemark>\n",
                timestamp,
                accuracy,
                longitude,
                latitude
            );
            location_count += 1;
            last_added_location_id = location_id;
        }

        ret += "</Document>\n</kml>";
    }

    ensure!(location_count > 0, "No locations processed");

    Ok((ret, last_added_location_id))
}

fn get_kml_timestamp(utc: i64) -> String {
    // Returns a string formatted as YYYY-MM-DDTHH:MM:SSZ. The trailing `Z` indicates UTC.
    chrono::NaiveDateTime::from_timestamp(utc, 0)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

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

pub async fn set_kml_sent_timestamp(
    context: &Context,
    chat_id: ChatId,
    timestamp: i64,
) -> Result<(), Error> {
    context
        .sql
        .execute(
            sqlx::query("UPDATE chats SET locations_last_sent=? WHERE id=?;")
                .bind(timestamp)
                .bind(chat_id),
        )
        .await?;
    Ok(())
}

pub async fn set_msg_location_id(
    context: &Context,
    msg_id: MsgId,
    location_id: u32,
) -> Result<(), Error> {
    context
        .sql
        .execute(
            sqlx::query("UPDATE msgs SET location_id=? WHERE id=?;")
                .bind(location_id)
                .bind(msg_id),
        )
        .await?;

    Ok(())
}

pub async fn save(
    context: &Context,
    chat_id: ChatId,
    contact_id: u32,
    locations: &[Location],
    independent: bool,
) -> Result<u32, Error> {
    ensure!(!chat_id.is_special(), "Invalid chat id");

    let mut newest_timestamp = 0;
    let mut newest_location_id = 0;

    let stmt_test = "SELECT COUNT(*) FROM locations WHERE timestamp=? AND from_id=?";
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
        let exists = context
            .sql
            .exists(sqlx::query(stmt_test).bind(timestamp).bind(contact_id))
            .await?;
        if independent || !exists {
            context
                .sql
                .execute(
                    sqlx::query(stmt_insert)
                        .bind(timestamp)
                        .bind(contact_id)
                        .bind(chat_id)
                        .bind(latitude)
                        .bind(longitude)
                        .bind(accuracy)
                        .bind(independent),
                )
                .await?;

            if timestamp > newest_timestamp {
                newest_timestamp = timestamp;
                newest_location_id = context
                    .sql
                    .get_rowid2(
                        "locations",
                        "timestamp",
                        timestamp,
                        "from_id",
                        contact_id as i64,
                    )
                    .await?;
            }
        }
    }

    Ok(u32::try_from(newest_location_id)?)
}

pub(crate) async fn job_maybe_send_locations(context: &Context, _job: &Job) -> job::Status {
    let now = time();
    let mut continue_streaming = false;
    info!(
        context,
        " ----------------- MAYBE_SEND_LOCATIONS -------------- ",
    );

    let rows = context
        .sql
        .fetch(
            sqlx::query(
                "SELECT id, locations_send_begin, locations_last_sent \
         FROM chats \
         WHERE locations_send_until>?;",
            )
            .bind(now),
        )
        .await
        .map(|rows| {
            rows.map(|row| -> sqlx::Result<Option<_>> {
                let row = row?;
                let chat_id: ChatId = row.try_get(0)?;
                let locations_send_begin: i64 = row.try_get(1)?;
                let locations_last_sent: i64 = row.try_get(2)?;
                continue_streaming = true;

                // be a bit tolerant as the timer may not align exactly with time(NULL)
                if now - locations_last_sent < (60 - 3) {
                    Ok(None)
                } else {
                    Ok(Some((chat_id, locations_send_begin, locations_last_sent)))
                }
            })
            .filter_map(|v| v.transpose())
        });

    let stmt = "SELECT COUNT(*) \
         FROM locations \
         WHERE from_id=? \
         AND timestamp>=? \
         AND timestamp>? \
         AND independent=0 \
         ORDER BY timestamp;";

    if let Ok(mut rows) = rows {
        let mut msgs = Vec::new();
        while let Some(row) = rows.next().await {
            let (chat_id, locations_send_begin, locations_last_sent) = match row {
                Ok(row) => row,
                Err(_) => break,
            };
            let exists = context
                .sql
                .exists(
                    sqlx::query(stmt)
                        .bind(DC_CONTACT_ID_SELF)
                        .bind(locations_send_begin)
                        .bind(locations_last_sent),
                )
                .await
                .unwrap_or_default(); // TODO: better error handling

            if !exists {
                // if there is no new location, there's nothing to send.
                // however, maybe we want to bypass this test eg. 15 minutes
            } else {
                // pending locations are attached automatically to every message,
                // so also to this empty text message.
                // DC_CMD_LOCATION is only needed to create a nicer subject.
                //
                // for optimisation and to avoid flooding the sending queue,
                // we could sending these messages only if we're really online.
                // the easiest way to determine this, is to check for an empty message queue.
                // (might not be 100%, however, as positions are sent combined later
                // and dc_set_location() is typically called periodically, this is ok)
                let mut msg = Message::new(Viewtype::Text);
                msg.hidden = true;
                msg.param.set_cmd(SystemMessage::LocationOnly);
                msgs.push((chat_id, msg));
            }
        }

        for (chat_id, mut msg) in msgs.into_iter() {
            // TODO: better error handling
            chat::send_msg(context, chat_id, &mut msg)
                .await
                .unwrap_or_default();
        }
    }

    if continue_streaming {
        schedule_maybe_send_locations(context, true).await;
    }
    job::Status::Finished(Ok(()))
}

pub(crate) async fn job_maybe_send_locations_ended(
    context: &Context,
    job: &mut Job,
) -> job::Status {
    // this function is called when location-streaming _might_ have ended for a chat.
    // the function checks, if location-streaming is really ended;
    // if so, a device-message is added if not yet done.

    let chat_id = ChatId::new(job.foreign_id);

    let (send_begin, send_until) = job_try!(context
        .sql
        .fetch_one(
            sqlx::query(
                "SELECT locations_send_begin, locations_send_until  FROM chats  WHERE id=?",
            )
            .bind(chat_id)
        )
        .await
        .and_then(|row| { Ok((row.try_get::<i64, _>(0)?, row.try_get::<i64, _>(1)?)) }));

    if !(send_begin != 0 && time() <= send_until) {
        // still streaming -
        // may happen as several calls to dc_send_locations_to_chat()
        // do not un-schedule pending DC_MAYBE_SEND_LOC_ENDED jobs
        if !(send_begin == 0 && send_until == 0) {
            // not streaming, device-message already sent
            job_try!(
                context
                    .sql
                    .execute(
                        sqlx::query(
                            "UPDATE chats \
                             SET locations_send_begin=0, locations_send_until=0 \
                             WHERE id=?"
                        )
                        .bind(chat_id)
                    )
                    .await
            );

            let stock_str = stock_str::msg_location_disabled(context).await;
            chat::add_info_msg(context, chat_id, stock_str).await;
            context.emit_event(EventType::ChatModified(chat_id));
        }
    }
    job::Status::Finished(Ok(()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]

    use super::*;
    use crate::test_utils::TestContext;

    #[async_std::test]
    async fn test_kml_parse() {
        let context = TestContext::new().await;

        let xml =
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n<Document addr=\"user@example.org\">\n<Placemark><Timestamp><when>2019-03-06T21:09:57Z</when></Timestamp><Point><coordinates accuracy=\"32.000000\">9.423110,53.790302</coordinates></Point></Placemark>\n<PlaceMARK>\n<Timestamp><WHEN > \n\t2018-12-13T22:11:12Z\t</WHEN></Timestamp><Point><coordinates aCCuracy=\"2.500000\"> 19.423110 \t , \n 63.790302\n </coordinates></Point></PlaceMARK>\n</Document>\n</kml>";

        let kml = Kml::parse(&context.ctx, xml).expect("parsing failed");

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

    #[async_std::test]
    async fn test_get_message_kml() {
        let context = TestContext::new().await;
        let timestamp = 1598490000;

        let xml = get_message_kml(timestamp, 51.423723f64, 8.552556f64);
        let kml = Kml::parse(&context.ctx, xml.as_bytes()).expect("parsing failed");
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
}
