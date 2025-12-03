//! # Download large messages manually.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail, ensure};
use deltachat_derive::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::imap::session::Session;
use crate::log::{info, warn};
use crate::message::{self, Message, MsgId, rfc724_mid_exists};
use crate::{EventType, chatlist_events};

pub(crate) mod pre_msg_metadata;

/// If a message is downloaded only partially
/// and `delete_server_after` is set to small timeouts (eg. "at once"),
/// the user might have no chance to actually download that message.
/// `MIN_DELETE_SERVER_AFTER` increases the timeout in this case.
pub(crate) const MIN_DELETE_SERVER_AFTER: i64 = 48 * 60 * 60;

/// From this point onward outgoing messages are considered large
/// and get a Pre-Message, which announces the Post-Message.
// this is only about sending so we can modify it any time.
// current value is a bit less than the minimum auto download setting from the UIs (which is 160 KiB)
pub(crate) const PRE_MSG_ATTACHMENT_SIZE_THRESHOLD: u64 = 140_000;

/// Max message size to be fetched in the background.
/// This limit defines what messages are fully fetched in the background.
/// This is for all messages that don't have the Post-Message header.
pub(crate) const MAX_FETCH_MSG_SIZE: u32 = 1_000_000;

/// Max size for pre messages. A warning is emitted when this is exceeded.
/// Should be well below `MAX_FETCH_MSG_SIZE`
pub(crate) const PRE_MSG_SIZE_WARNING_THRESHOLD: usize = 150_000;

/// Download state of the message.
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
pub enum DownloadState {
    /// Message is fully downloaded.
    #[default]
    Done = 0,

    /// Message is partially downloaded and can be fully downloaded at request.
    Available = 10,

    /// Failed to fully download the message.
    Failure = 20,

    /// Undecipherable message.
    Undecipherable = 30,

    /// Full download of the message is in progress.
    InProgress = 1000,
}

impl MsgId {
    /// Schedules Post-Message download for partially downloaded message.
    pub async fn download_full(self, context: &Context) -> Result<()> {
        let msg = Message::load_from_db(context, self).await?;
        match msg.download_state() {
            DownloadState::Done | DownloadState::Undecipherable => {
                return Err(anyhow!("Nothing to download."));
            }
            DownloadState::InProgress => return Err(anyhow!("Download already in progress.")),
            DownloadState::Available | DownloadState::Failure => {
                if msg.rfc724_mid().is_empty() {
                    return Err(anyhow!("Download not possible, message has no rfc724_mid"));
                }
                self.update_download_state(context, DownloadState::InProgress)
                    .await?;
                context
                    .sql
                    .execute(
                        "INSERT INTO download (rfc724_mid) VALUES (?)",
                        (msg.rfc724_mid(),),
                    )
                    .await?;
                context.scheduler.interrupt_inbox().await;
            }
        }
        Ok(())
    }

    /// Updates the message download state. Returns `Ok` if the message doesn't exist anymore.
    pub(crate) async fn update_download_state(
        self,
        context: &Context,
        download_state: DownloadState,
    ) -> Result<()> {
        if context
            .sql
            .execute(
                "UPDATE msgs SET download_state=? WHERE id=?;",
                (download_state, self),
            )
            .await?
            == 0
        {
            return Ok(());
        }
        let Some(msg) = Message::load_from_db_optional(context, self).await? else {
            return Ok(());
        };
        context.emit_event(EventType::MsgsChanged {
            chat_id: msg.chat_id,
            msg_id: self,
        });
        chatlist_events::emit_chatlist_item_changed(context, msg.chat_id);
        Ok(())
    }
}

impl Message {
    /// Returns the download state of the message.
    pub fn download_state(&self) -> DownloadState {
        self.download_state
    }
}

/// Actually download a message partially downloaded before.
///
/// Most messages are downloaded automatically on fetch instead.
pub(crate) async fn download_msg(
    context: &Context,
    rfc724_mid: String,
    session: &mut Session,
) -> Result<()> {
    let row = context
        .sql
        .query_row_optional(
            "SELECT uid, folder FROM imap WHERE rfc724_mid=? AND target!=''",
            (&rfc724_mid,),
            |row| {
                let server_uid: u32 = row.get(0)?;
                let server_folder: String = row.get(1)?;
                Ok((server_uid, server_folder))
            },
        )
        .await?;

    let Some((server_uid, server_folder)) = row else {
        // No IMAP record found, we don't know the UID and folder.
        return Err(anyhow!("Call download_full() again to try over."));
    };

    session
        .fetch_single_msg(context, &server_folder, server_uid, rfc724_mid)
        .await?;
    Ok(())
}

impl Session {
    /// Download a single message and pipe it to receive_imf().
    ///
    /// receive_imf() is not directly aware that this is a result of a call to download_msg(),
    /// however, implicitly knows that as the existing message is flagged as being partly.
    async fn fetch_single_msg(
        &mut self,
        context: &Context,
        folder: &str,
        uid: u32,
        rfc724_mid: String,
    ) -> Result<()> {
        if uid == 0 {
            bail!("Attempt to fetch UID 0");
        }

        let create = false;
        let folder_exists = self
            .select_with_uidvalidity(context, folder, create)
            .await?;
        ensure!(folder_exists, "No folder {folder}");

        // we are connected, and the folder is selected
        info!(context, "Downloading message {}/{} fully...", folder, uid);

        let mut uid_message_ids: BTreeMap<u32, String> = BTreeMap::new();
        uid_message_ids.insert(uid, rfc724_mid);
        let (sender, receiver) = async_channel::unbounded();
        self.fetch_many_msgs(context, folder, vec![uid], &uid_message_ids, sender)
            .await?;
        if receiver.recv().await.is_err() {
            bail!("Failed to fetch UID {uid}");
        }
        Ok(())
    }
}

async fn set_msg_state_to_failed(context: &Context, rfc724_mid: &str) -> Result<()> {
    if let Some(msg_id) = rfc724_mid_exists(context, rfc724_mid).await? {
        // Update download state to failure
        // so it can be retried.
        //
        // On success update_download_state() is not needed
        // as receive_imf() already
        // set the state and emitted the event.
        msg_id
            .update_download_state(context, DownloadState::Failure)
            .await?;
    }
    Ok(())
}

async fn available_post_msgs_contains_rfc724_mid(
    context: &Context,
    rfc724_mid: &str,
) -> Result<bool> {
    Ok(context
        .sql
        .query_get_value::<MsgId>(
            "SELECT rfc724_mid FROM available_post_msgs WHERE rfc724_mid=?",
            (&rfc724_mid,),
        )
        .await?
        .is_some())
}

async fn remove_from_available_post_msgs_table(context: &Context, rfc724_mid: &str) -> Result<()> {
    context
        .sql
        .execute(
            "DELETE FROM available_post_msgs WHERE rfc724_mid=?",
            (&rfc724_mid,),
        )
        .await?;
    Ok(())
}

async fn remove_from_download_table(context: &Context, rfc724_mid: &str) -> Result<()> {
    context
        .sql
        .execute("DELETE FROM download WHERE rfc724_mid=?", (&rfc724_mid,))
        .await?;
    Ok(())
}

// this is a dedicated method because it is used in multiple places.
pub(crate) async fn premessage_is_downloaded_for(
    context: &Context,
    rfc724_mid: &str,
) -> Result<bool> {
    Ok(message::rfc724_mid_exists(context, rfc724_mid)
        .await?
        .is_some())
}

pub(crate) async fn download_msgs(context: &Context, session: &mut Session) -> Result<()> {
    let rfc724_mids = context
        .sql
        .query_map_vec("SELECT rfc724_mid FROM download", (), |row| {
            let rfc724_mid: String = row.get(0)?;
            Ok(rfc724_mid)
        })
        .await?;

    for rfc724_mid in &rfc724_mids {
        let res = download_msg(context, rfc724_mid.clone(), session).await;
        if res.is_ok() {
            remove_from_download_table(context, rfc724_mid).await?;
            remove_from_available_post_msgs_table(context, rfc724_mid).await?;
        }
        if let Err(err) = res {
            warn!(
                context,
                "Failed to download message rfc724_mid={rfc724_mid}: {:#}.", err
            );
            if !premessage_is_downloaded_for(context, rfc724_mid).await? {
                // This is probably a classical email that vanished before we could download it
                warn!(
                    context,
                    "{rfc724_mid} is probably a classical email that vanished before we could download it"
                );
                remove_from_download_table(context, rfc724_mid).await?;
            } else if available_post_msgs_contains_rfc724_mid(context, rfc724_mid).await? {
                // set the message to DownloadState::Failure - probably it was deleted on the server in the meantime
                set_msg_state_to_failed(context, rfc724_mid).await?;
                remove_from_download_table(context, rfc724_mid).await?;
                remove_from_available_post_msgs_table(context, rfc724_mid).await?;
            } else {
                // leave the message in DownloadState::InProgress;
                // it will be downloaded once it arrives.
            }
        }
    }

    Ok(())
}

/// Download known post messages without pre_message
/// in order to guard against lost pre-messages:
pub(crate) async fn download_known_post_messages_without_pre_message(
    context: &Context,
    session: &mut Session,
) -> Result<()> {
    let rfc724_mids = context
        .sql
        .query_map_vec("SELECT rfc724_mid FROM available_post_msgs", (), |row| {
            let rfc724_mid: String = row.get(0)?;
            Ok(rfc724_mid)
        })
        .await?;
    for rfc724_mid in &rfc724_mids {
        if !premessage_is_downloaded_for(context, rfc724_mid).await? {
            // Download the Post-Message unconditionally,
            // because the Pre-Message got lost.
            // The message may be in the wrong order,
            // but at least we have it at all.
            let res = download_msg(context, rfc724_mid.clone(), session).await;
            if res.is_ok() {
                remove_from_available_post_msgs_table(context, rfc724_mid).await?;
            }
            if let Err(err) = res {
                warn!(
                    context,
                    "download_known_post_messages_without_pre_message: Failed to download message rfc724_mid={rfc724_mid}: {:#}.",
                    err
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;
    use crate::chat::send_msg;
    use crate::test_utils::TestContext;

    #[test]
    fn test_downloadstate_values() {
        // values may be written to disk and must not change
        assert_eq!(DownloadState::Done, DownloadState::default());
        assert_eq!(DownloadState::Done, DownloadState::from_i32(0).unwrap());
        assert_eq!(
            DownloadState::Available,
            DownloadState::from_i32(10).unwrap()
        );
        assert_eq!(DownloadState::Failure, DownloadState::from_i32(20).unwrap());
        assert_eq!(
            DownloadState::InProgress,
            DownloadState::from_i32(1000).unwrap()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_update_download_state() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat = t.create_chat_with_contact("Bob", "bob@example.org").await;

        let mut msg = Message::new_text("Hi Bob".to_owned());
        let msg_id = send_msg(&t, chat.id, &mut msg).await?;
        let msg = Message::load_from_db(&t, msg_id).await?;
        assert_eq!(msg.download_state(), DownloadState::Done);

        for s in &[
            DownloadState::Available,
            DownloadState::InProgress,
            DownloadState::Failure,
            DownloadState::Done,
            DownloadState::Done,
        ] {
            msg_id.update_download_state(&t, *s).await?;
            let msg = Message::load_from_db(&t, msg_id).await?;
            assert_eq!(msg.download_state(), *s);
        }
        t.sql
            .execute("DELETE FROM msgs WHERE id=?", (msg_id,))
            .await?;
        // Nothing to do is ok.
        msg_id
            .update_download_state(&t, DownloadState::Done)
            .await?;

        Ok(())
    }

    // NOTE: The download tests for pre-messages are in src/tests/pre_messages.rs
}
