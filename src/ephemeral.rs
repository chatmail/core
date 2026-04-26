//! # Ephemeral messages.
//!
//! Ephemeral messages are messages that have an Ephemeral-Timer
//! header attached to them, which specifies time in seconds after
//! which the message should be deleted both from the device and from
//! the server. The timer is started when the message is marked as
//! seen, which usually happens when its contents is displayed on
//! device screen.
//!
//! Each chat, including 1:1, group chats and "saved messages" chat,
//! has its own ephemeral timer setting, which is applied to all
//! messages sent to the chat. The setting is synchronized to all the
//! devices participating in the chat by applying the timer value from
//! all received messages, including BCC-self ones, to the chat. This
//! way the setting is eventually synchronized among all participants.
//!
//! When user changes ephemeral timer setting for the chat, a system
//! message is automatically sent to update the setting for all
//! participants. This allows changing the setting for a chat like any
//! group chat setting, e.g. name and avatar, without the need to
//! write an actual message.
//!
//! ## Device settings
//!
//! In addition to per-chat ephemeral message setting, each device has
//! two global user-configured settings that complement per-chat
//! settings: `delete_device_after` and `delete_server_after`. These
//! settings are not synchronized among devices and apply to all
//! messages known to the device, including messages sent or received
//! before configuring the setting.
//!
//! `delete_device_after` configures the maximum time device is
//! storing the messages locally. `delete_server_after` configures the
//! time after which device will delete the messages it knows about
//! from the server.
//!
//! ## How messages are deleted
//!
//! When Delta Chat deletes the message locally, it moves the message
//! to the trash chat and removes actual message contents. Messages in
//! the trash chat are called "tombstones" and track the Message-ID to
//! prevent accidental redownloading of the message from the server,
//! e.g. in case of UID validity change.
//!
//! Vice versa, when Delta Chat deletes the message from the server,
//! it removes IMAP folder and UID row from the `imap` table, but
//! keeps the message in the `msgs` table.
//!
//! Delta Chat eventually removes tombstones from the `msgs` table,
//! leaving no trace of the message, when it thinks there are no more
//! copies of the message stored on the server, i.e. when there is no
//! corresponding `imap` table entry. This is done in the
//! `prune_tombstones()` procedure during housekeeping.
//!
//! ## When messages are deleted
//!
//! The `ephemeral_loop` task schedules the next due running of
//! `delete_expired_messages` which in turn emits `MsgsChanged` events
//! when deleting local messages to make UIs reload displayed messages.
//!
//! Server deletion happens by updating the `imap` table based on
//! the database entries which are expired either according to their
//! ephemeral message timers or global `delete_server_after` setting.

use std::cmp::max;
use std::collections::BTreeSet;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context as _, Result, ensure};
use async_channel::Receiver;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

use crate::chat::{ChatId, ChatIdBlocked, send_msg};
use crate::constants::{DC_CHAT_ID_LAST_SPECIAL, DC_CHAT_ID_TRASH};
use crate::contact::ContactId;
use crate::context::Context;
use crate::download::MIN_DELETE_SERVER_AFTER;
use crate::events::EventType;
use crate::log::{LogExt, warn};
use crate::message::{Message, MessageState, MsgId, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::stock_str;
use crate::tools::{SystemTime, duration_to_str, time};
use crate::{location, stats};

/// Ephemeral timer value.
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize, Default)]
pub enum Timer {
    /// Timer is disabled.
    #[default]
    Disabled,

    /// Timer is enabled.
    Enabled {
        /// Timer duration in seconds.
        ///
        /// The value cannot be 0.
        duration: u32,
    },
}

impl Timer {
    /// Converts epehmeral timer value to integer.
    ///
    /// If the timer is disabled, return 0.
    pub fn to_u32(self) -> u32 {
        match self {
            Self::Disabled => 0,
            Self::Enabled { duration } => duration,
        }
    }

    /// Converts integer to ephemeral timer value.
    ///
    /// 0 value is treated as disabled timer.
    pub fn from_u32(duration: u32) -> Self {
        if duration == 0 {
            Self::Disabled
        } else {
            Self::Enabled { duration }
        }
    }
}

impl fmt::Display for Timer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_u32())
    }
}

impl FromStr for Timer {
    type Err = ParseIntError;

    fn from_str(input: &str) -> Result<Timer, ParseIntError> {
        input.parse::<u32>().map(Self::from_u32)
    }
}

impl rusqlite::types::ToSql for Timer {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        let val = rusqlite::types::Value::Integer(match self {
            Self::Disabled => 0,
            Self::Enabled { duration } => i64::from(*duration),
        });
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

impl rusqlite::types::FromSql for Timer {
    fn column_result(value: rusqlite::types::ValueRef) -> rusqlite::types::FromSqlResult<Self> {
        i64::column_result(value).and_then(|value| {
            if value == 0 {
                Ok(Self::Disabled)
            } else if let Ok(duration) = u32::try_from(value) {
                Ok(Self::Enabled { duration })
            } else {
                Err(rusqlite::types::FromSqlError::OutOfRange(value))
            }
        })
    }
}

impl ChatId {
    /// Get ephemeral message timer value in seconds.
    pub async fn get_ephemeral_timer(self, context: &Context) -> Result<Timer> {
        let timer = context
            .sql
            .query_get_value(
                "SELECT IFNULL(ephemeral_timer, 0) FROM chats WHERE id=?",
                (self,),
            )
            .await?
            .with_context(|| format!("Chat {self} not found"))?;
        Ok(timer)
    }

    /// Set ephemeral timer value without sending a message.
    ///
    /// Used when a message arrives indicating that someone else has
    /// changed the timer value for a chat.
    pub(crate) async fn inner_set_ephemeral_timer(
        self,
        context: &Context,
        timer: Timer,
    ) -> Result<()> {
        ensure!(!self.is_special(), "Invalid chat ID");

        context
            .sql
            .execute(
                "UPDATE chats
             SET ephemeral_timer=?
             WHERE id=?;",
                (timer, self),
            )
            .await?;

        context.emit_event(EventType::ChatEphemeralTimerModified {
            chat_id: self,
            timer,
        });
        Ok(())
    }

    /// Set ephemeral message timer value in seconds.
    ///
    /// If timer value is 0, disable ephemeral message timer.
    pub async fn set_ephemeral_timer(self, context: &Context, timer: Timer) -> Result<()> {
        if timer == self.get_ephemeral_timer(context).await? {
            return Ok(());
        }
        self.inner_set_ephemeral_timer(context, timer).await?;

        if self.is_promoted(context).await? {
            let mut msg = Message::new_text(
                stock_ephemeral_timer_changed(context, timer, ContactId::SELF).await,
            );
            msg.param.set_cmd(SystemMessage::EphemeralTimerChanged);
            if let Err(err) = send_msg(context, self, &mut msg).await {
                error!(
                    context,
                    "Failed to send a message about ephemeral message timer change: {:?}", err
                );
            }
        }
        Ok(())
    }
}

/// Returns a stock message saying that ephemeral timer is changed to `timer` by `from_id`.
pub(crate) async fn stock_ephemeral_timer_changed(
    context: &Context,
    timer: Timer,
    from_id: ContactId,
) -> String {
    match timer {
        Timer::Disabled => stock_str::msg_ephemeral_timer_disabled(context, from_id).await,
        Timer::Enabled { duration } => match duration {
            0..=60 => {
                stock_str::msg_ephemeral_timer_enabled(context, &timer.to_string(), from_id).await
            }
            61..=3599 => {
                stock_str::msg_ephemeral_timer_minutes(
                    context,
                    &format!("{}", (f64::from(duration) / 6.0).round() / 10.0),
                    from_id,
                )
                .await
            }
            3600 => stock_str::msg_ephemeral_timer_hour(context, from_id).await,
            3601..=86399 => {
                stock_str::msg_ephemeral_timer_hours(
                    context,
                    &format!("{}", (f64::from(duration) / 360.0).round() / 10.0),
                    from_id,
                )
                .await
            }
            86400 => stock_str::msg_ephemeral_timer_day(context, from_id).await,
            86401..=604_799 => {
                stock_str::msg_ephemeral_timer_days(
                    context,
                    &format!("{}", (f64::from(duration) / 8640.0).round() / 10.0),
                    from_id,
                )
                .await
            }
            604_800 => stock_str::msg_ephemeral_timer_week(context, from_id).await,
            31_536_000..=31_708_800 => stock_str::msg_ephemeral_timer_year(context, from_id).await,
            _ => {
                stock_str::msg_ephemeral_timer_weeks(
                    context,
                    &format!("{}", (f64::from(duration) / 60480.0).round() / 10.0),
                    from_id,
                )
                .await
            }
        },
    }
}

impl MsgId {
    /// Returns ephemeral message timer value for the message.
    pub(crate) async fn ephemeral_timer(self, context: &Context) -> Result<Timer> {
        let res = match context
            .sql
            .query_get_value("SELECT ephemeral_timer FROM msgs WHERE id=?", (self,))
            .await?
        {
            None | Some(0) => Timer::Disabled,
            Some(duration) => Timer::Enabled { duration },
        };
        Ok(res)
    }

    /// Starts ephemeral message timer for the message if it is not started yet.
    pub(crate) async fn start_ephemeral_timer(self, context: &Context) -> Result<()> {
        if let Timer::Enabled { duration } = self.ephemeral_timer(context).await? {
            let ephemeral_timestamp = time().saturating_add(duration.into());

            context
                .sql
                .execute(
                    "UPDATE msgs SET ephemeral_timestamp = ? \
                WHERE (ephemeral_timestamp == 0 OR ephemeral_timestamp > ?) \
                AND id = ?",
                    (ephemeral_timestamp, ephemeral_timestamp, self),
                )
                .await?;
            context.scheduler.interrupt_ephemeral_task().await;
        }
        Ok(())
    }
}

pub(crate) async fn start_ephemeral_timers_msgids(
    context: &Context,
    msg_ids: &[MsgId],
) -> Result<()> {
    let now = time();
    let should_interrupt =
    context
        .sql
        .transaction(move |transaction| {
            let mut should_interrupt = false;
            let mut stmt =
                transaction.prepare(
                    "UPDATE msgs SET ephemeral_timestamp = ?1 + ephemeral_timer
                     WHERE (ephemeral_timestamp == 0 OR ephemeral_timestamp > ?1 + ephemeral_timer) AND ephemeral_timer > 0
                     AND id=?2")?;
            for msg_id in msg_ids {
                should_interrupt |= stmt.execute((now, msg_id))? > 0;
            }
            Ok(should_interrupt)
        }).await?;
    if should_interrupt {
        context.scheduler.interrupt_ephemeral_task().await;
    }
    Ok(())
}

/// Starts ephemeral timer for all messages in the chat.
///
/// This should be called when chat is marked as noticed.
pub(crate) async fn start_chat_ephemeral_timers(context: &Context, chat_id: ChatId) -> Result<()> {
    let now = time();
    let should_interrupt = context
        .sql
        .execute(
            "UPDATE msgs SET ephemeral_timestamp = ?1 + ephemeral_timer
             WHERE chat_id = ?2
             AND ephemeral_timer > 0
             AND (ephemeral_timestamp == 0 OR ephemeral_timestamp > ?1 + ephemeral_timer)",
            (now, chat_id),
        )
        .await?
        > 0;
    if should_interrupt {
        context.scheduler.interrupt_ephemeral_task().await;
    }
    Ok(())
}

/// Selects messages which are expired according to
/// `delete_device_after` setting or `ephemeral_timestamp` column.
///
/// For each message a row ID, chat id, viewtype and location ID is returned.
///
/// Unknown viewtypes are returned as `Viewtype::Unknown`
/// and not as errors bubbled up, easily resulting in infinite loop or leaving messages undeleted.
/// (Happens when viewtypes are removed or added on another device which was backup/add-second-device source)
async fn select_expired_messages(
    context: &Context,
    now: i64,
) -> Result<Vec<(MsgId, ChatId, Viewtype, u32)>> {
    let mut rows = context
        .sql
        .query_map_vec(
            r#"
SELECT id, chat_id, type, location_id
FROM msgs
WHERE
  ephemeral_timestamp != 0
  AND ephemeral_timestamp <= ?
  AND chat_id != ?
"#,
            (now, DC_CHAT_ID_TRASH),
            |row| {
                let id: MsgId = row.get("id")?;
                let chat_id: ChatId = row.get("chat_id")?;
                let viewtype: Viewtype = row
                    .get("type")
                    .context("Using default viewtype for ephemeral handling.")
                    .log_err(context)
                    .unwrap_or_default();
                let location_id: u32 = row.get("location_id")?;
                Ok((id, chat_id, viewtype, location_id))
            },
        )
        .await?;

    if let Some(delete_device_after) = context.get_config_delete_device_after().await? {
        let self_chat_id = ChatIdBlocked::lookup_by_contact(context, ContactId::SELF)
            .await?
            .map(|c| c.id)
            .unwrap_or_default();
        let device_chat_id = ChatIdBlocked::lookup_by_contact(context, ContactId::DEVICE)
            .await?
            .map(|c| c.id)
            .unwrap_or_default();

        let threshold_timestamp = now.saturating_sub(delete_device_after);

        let rows_expired = context
            .sql
            .query_map_vec(
                r#"
SELECT id, chat_id, type, location_id
FROM msgs
WHERE
  timestamp < ?1
  AND timestamp_rcvd < ?1
  AND chat_id > ?
  AND chat_id != ?
  AND chat_id != ?
"#,
                (
                    threshold_timestamp,
                    DC_CHAT_ID_LAST_SPECIAL,
                    self_chat_id,
                    device_chat_id,
                ),
                |row| {
                    let id: MsgId = row.get("id")?;
                    let chat_id: ChatId = row.get("chat_id")?;
                    let viewtype: Viewtype = row
                        .get("type")
                        .context("Using default viewtype for delete-old handling.")
                        .log_err(context)
                        .unwrap_or_default();
                    let location_id: u32 = row.get("location_id")?;
                    Ok((id, chat_id, viewtype, location_id))
                },
            )
            .await?;

        rows.extend(rows_expired);
    }

    Ok(rows)
}

/// Deletes messages which are expired according to
/// `delete_device_after` setting or `ephemeral_timestamp` column.
///
/// Emits relevant `MsgsChanged` and `WebxdcInstanceDeleted` events
/// if messages are deleted.
pub(crate) async fn delete_expired_messages(context: &Context, now: i64) -> Result<()> {
    let rows = select_expired_messages(context, now).await?;

    if !rows.is_empty() {
        info!(context, "Attempting to delete {} messages.", rows.len());

        let (msgs_changed, webxdc_deleted) = context
            .sql
            .transaction(|transaction| {
                let mut msgs_changed = Vec::with_capacity(rows.len());
                let mut webxdc_deleted = Vec::new();
                // If you change which information is preserved here, also change `MsgId::trash()`
                // and other places it references.
                let mut del_msg_stmt = transaction.prepare(
                    "
INSERT OR REPLACE INTO msgs (id, rfc724_mid, pre_rfc724_mid, timestamp, chat_id)
SELECT ?1, rfc724_mid, pre_rfc724_mid, timestamp, ? FROM msgs WHERE id=?1
                    ",
                )?;
                let mut del_location_stmt =
                    transaction.prepare("DELETE FROM locations WHERE independent=1 AND id=?")?;
                for (msg_id, chat_id, viewtype, location_id) in rows {
                    del_msg_stmt.execute((msg_id, DC_CHAT_ID_TRASH))?;
                    if location_id > 0 {
                        del_location_stmt.execute((location_id,))?;
                    }

                    msgs_changed.push((chat_id, msg_id));
                    if viewtype == Viewtype::Webxdc {
                        webxdc_deleted.push(msg_id)
                    }
                }
                Ok((msgs_changed, webxdc_deleted))
            })
            .await?;

        let mut modified_chat_ids = BTreeSet::new();

        for (chat_id, msg_id) in msgs_changed {
            context.emit_event(EventType::MsgDeleted { chat_id, msg_id });
            modified_chat_ids.insert(chat_id);
        }

        for modified_chat_id in modified_chat_ids {
            context.emit_msgs_changed_without_msg_id(modified_chat_id);
        }

        for msg_id in webxdc_deleted {
            context.emit_event(EventType::WebxdcInstanceDeleted { msg_id });
        }
    }

    Ok(())
}

/// Calculates the next timestamp when a message will be deleted due to
/// `delete_device_after` setting being set.
async fn next_delete_device_after_timestamp(context: &Context) -> Result<Option<i64>> {
    if let Some(delete_device_after) = context.get_config_delete_device_after().await? {
        let self_chat_id = ChatIdBlocked::lookup_by_contact(context, ContactId::SELF)
            .await?
            .map(|c| c.id)
            .unwrap_or_default();
        let device_chat_id = ChatIdBlocked::lookup_by_contact(context, ContactId::DEVICE)
            .await?
            .map(|c| c.id)
            .unwrap_or_default();

        let oldest_message_timestamp: Option<i64> = context
            .sql
            .query_get_value(
                r#"
                SELECT min(max(timestamp, timestamp_rcvd))
                FROM msgs
                WHERE chat_id > ?
                  AND chat_id != ?
                  AND chat_id != ?
                HAVING count(*) > 0
                "#,
                (DC_CHAT_ID_TRASH, self_chat_id, device_chat_id),
            )
            .await?;

        Ok(oldest_message_timestamp.map(|x| x.saturating_add(delete_device_after)))
    } else {
        Ok(None)
    }
}

/// Calculates next timestamp when expiration of some message will happen.
///
/// Expiration can happen either because user has set `delete_device_after` setting or because the
/// message itself has an ephemeral timer.
async fn next_expiration_timestamp(context: &Context) -> Option<i64> {
    let ephemeral_timestamp: Option<i64> = match context
        .sql
        .query_get_value(
            r#"
            SELECT min(ephemeral_timestamp)
            FROM msgs
            WHERE ephemeral_timestamp != 0
              AND chat_id != ?
            HAVING count(*) > 0
            "#,
            (DC_CHAT_ID_TRASH,), // Trash contains already deleted messages, skip them
        )
        .await
    {
        Err(err) => {
            warn!(context, "Can't calculate next ephemeral timeout: {}", err);
            None
        }
        Ok(ephemeral_timestamp) => ephemeral_timestamp,
    };

    let delete_device_after_timestamp: Option<i64> =
        match next_delete_device_after_timestamp(context).await {
            Err(err) => {
                warn!(
                    context,
                    "Can't calculate timestamp of the next message expiration: {}", err
                );
                None
            }
            Ok(timestamp) => timestamp,
        };

    ephemeral_timestamp
        .into_iter()
        .chain(delete_device_after_timestamp)
        .min()
}

#[expect(clippy::arithmetic_side_effects)]
pub(crate) async fn ephemeral_loop(context: &Context, interrupt_receiver: Receiver<()>) {
    loop {
        let ephemeral_timestamp = next_expiration_timestamp(context).await;

        let now = SystemTime::now();
        let until = if let Some(ephemeral_timestamp) = ephemeral_timestamp {
            UNIX_EPOCH
                + Duration::from_secs(ephemeral_timestamp.try_into().unwrap_or(u64::MAX))
                + Duration::from_secs(1)
        } else {
            // no messages to be deleted for now, wait long for one to occur
            now + Duration::from_secs(86400) // 1 day
        };

        if let Ok(duration) = until.duration_since(now) {
            info!(
                context,
                "Ephemeral loop waiting for deletion in {} or interrupt",
                duration_to_str(duration)
            );
            match timeout(duration, interrupt_receiver.recv()).await {
                Ok(Ok(())) => {
                    // received an interruption signal, recompute waiting time (if any)
                    continue;
                }
                Ok(Err(err)) => {
                    warn!(
                        context,
                        "Interrupt channel closed, ephemeral loop exits now: {err:#}."
                    );
                    return;
                }
                Err(_err) => {
                    // Timeout.
                }
            }
        }

        // Make sure that the statistics stay correct by updating them _before_ deleting messages:
        stats::maybe_update_message_stats(context)
            .await
            .log_err(context)
            .ok();

        delete_expired_messages(context, time())
            .await
            .log_err(context)
            .ok();

        location::delete_expired(context, time())
            .await
            .log_err(context)
            .ok();
    }
}

/// Schedules expired IMAP messages for deletion.
#[expect(clippy::arithmetic_side_effects)]
pub(crate) async fn delete_expired_imap_messages(context: &Context) -> Result<()> {
    let now = time();

    let (threshold_timestamp, threshold_timestamp_extended) =
        match context.get_config_delete_server_after().await? {
            None => (0, 0),
            Some(delete_server_after) => (
                match delete_server_after {
                    // Guarantee immediate deletion.
                    0 => i64::MAX,
                    _ => now - delete_server_after,
                },
                now - max(delete_server_after, MIN_DELETE_SERVER_AFTER),
            ),
        };

    context
        .sql
        .execute(
            "UPDATE imap
             SET target=''
             WHERE rfc724_mid IN (
               SELECT rfc724_mid FROM msgs
               WHERE ((download_state = 0 AND timestamp < ?) OR
                      (download_state != 0 AND timestamp < ?) OR
                      (ephemeral_timestamp != 0 AND ephemeral_timestamp <= ?))
             )",
            (threshold_timestamp, threshold_timestamp_extended, now),
        )
        .await?;

    Ok(())
}

/// Start ephemeral timers for seen messages if they are not started
/// yet.
///
/// It is possible that timers are not started due to a missing or
/// failed `MsgId.start_ephemeral_timer()` call, either in the current
/// or previous version of Delta Chat.
///
/// This function is supposed to be called in the background,
/// e.g. from housekeeping task.
pub(crate) async fn start_ephemeral_timers(context: &Context) -> Result<()> {
    context
        .sql
        .execute(
            "UPDATE msgs \
    SET ephemeral_timestamp = ? + ephemeral_timer \
    WHERE ephemeral_timer > 0 \
    AND ephemeral_timestamp = 0 \
    AND state NOT IN (?, ?, ?)",
            (
                time(),
                MessageState::InFresh,
                MessageState::InNoticed,
                MessageState::OutDraft,
            ),
        )
        .await?;

    Ok(())
}

#[cfg(test)]
mod ephemeral_tests;
