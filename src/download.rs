//! # Download large messages manually.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail, ensure};
use deltachat_derive::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::imap::session::Session;
use crate::log::{info, warn};
use crate::message::{Message, MsgId};
use crate::{EventType, chatlist_events};

/// If a message is downloaded only partially
/// and `delete_server_after` is set to small timeouts (eg. "at once"),
/// the user might have no chance to actually download that message.
/// `MIN_DELETE_SERVER_AFTER` increases the timeout in this case.
pub(crate) const MIN_DELETE_SERVER_AFTER: i64 = 48 * 60 * 60;

/// From this point onward outgoing messages are considered large
/// and get a pre-message, which announces the full message.
// this is only about sending so we can modify it any time.
// current value is a bit less than the minimum auto download setting from the UIs (which is 160 KiB)
pub(crate) const PRE_MSG_ATTACHMENT_SIZE_THRESHOLD: u64 = 140_000;

/// Max message size to be fetched in the background.
/// This limit defines what messages are fully fetched in the background.
/// This is for all messages that don't have the full message header.
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
    /// Schedules full message download for partially downloaded message.
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
                        "INSERT INTO download (msg_id) VALUES (?)",
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
    if let Some(msg_id) = MsgId::get_by_rfc724_mid(context, rfc724_mid).await? {
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

async fn available_full_msgs_contains_rfc724_mid(
    context: &Context,
    rfc724_mid: &str,
) -> Result<bool> {
    Ok(context
        .sql
        .query_get_value::<MsgId>(
            "SELECT rfc724_mid FROM available_full_msgs WHERE rfc724_mid=?",
            (&rfc724_mid,),
        )
        .await?
        .is_some())
}

async fn remove_from_available_full_msgs_table(context: &Context, rfc724_mid: &str) -> Result<()> {
    context
        .sql
        .execute(
            "DELETE FROM available_full_msgs WHERE rfc724_mid=?",
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
    Ok(MsgId::get_by_rfc724_mid(context, rfc724_mid)
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
            remove_from_available_full_msgs_table(context, rfc724_mid).await?;
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
            } else if available_full_msgs_contains_rfc724_mid(context, rfc724_mid).await? {
                // set the message to DownloadState::Failure - probably it was deleted on the server in the meantime
                set_msg_state_to_failed(context, rfc724_mid).await?;
                remove_from_download_table(context, rfc724_mid).await?;
                remove_from_available_full_msgs_table(context, rfc724_mid).await?;
            } else {
                // leave the message in DownloadState::InProgress;
                // it will be downloaded once it arrives.
            }
        }
    }

    Ok(())
}

/// Download known full messages without pre_message
/// in order to guard against lost pre-messages:
// TODO better fn name
pub(crate) async fn download_known_full_messages_without_pre_message(
    context: &Context,
    session: &mut Session,
) -> Result<()> {
    let rfc724_mids = context
        .sql
        .query_map_vec("SELECT rfc724_mid FROM available_full_msgs", (), |row| {
            let rfc724_mid: String = row.get(0)?;
            Ok(rfc724_mid)
        })
        .await?;
    for rfc724_mid in &rfc724_mids {
        if !premessage_is_downloaded_for(context, rfc724_mid).await? {
            // Download the full-message unconditionally,
            // because the pre-message got lost.
            // The message may be in the wrong order,
            // but at least we have it at all.
            let res = download_msg(context, rfc724_mid.clone(), session).await;
            if res.is_ok() {
                remove_from_available_full_msgs_table(context, rfc724_mid).await?;
            }
            if let Err(err) = res {
                warn!(
                    context,
                    "download_known_full_messages_without_pre_message: Failed to download message rfc724_mid={rfc724_mid}: {:#}.",
                    err
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use mailparse::MailHeaderMap;
    use num_traits::FromPrimitive;
    use tokio::fs;

    use super::*;
    use crate::chat::{self, create_group, send_msg};
    use crate::config::Config;
    use crate::headerdef::{HeaderDef, HeaderDefMap};
    use crate::message::Viewtype;
    use crate::receive_imf::receive_imf_from_inbox;
    use crate::test_utils::{self, TestContext, TestContextManager};

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_download_stub_message() -> Result<()> {
        let t = TestContext::new_alice().await;

        let header = "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
             From: bob@example.com\n\
             To: alice@example.org\n\
             Subject: foo\n\
             Message-ID: <Mr.12345678901@example.com>\n\
             Chat-Version: 1.0\n\
             Date: Sun, 22 Mar 2020 22:37:57 +0000\
             Content-Type: text/plain";

        t.sql
            .execute(
                r#"INSERT INTO chats VALUES(
                    11001,100,'bob@example.com',0,'',2,'',
                    replace('C=1763151754\nt=foo','\n',char(10)),0,0,0,0,0,1763151754,0,NULL,0);
                "#,
                (),
            )
            .await?;
        t.sql.execute(r#"INSERT INTO msgs VALUES(
                11001,'Mr.12345678901@example.com','',0,
                11001,11001,1,1763151754,10,10,1,0,
                '[97.66 KiB message]','','',0,1763151754,1763151754,0,X'',
                '','',1,0,'',0,0,0,'foo',10,replace('Hop: From: userid; Date: Mon, 4 Dec 2006 13:51:39 +0000\n\nDKIM Results: Passed=true','\n',char(10)),1,NULL,0);
        "#, ()).await?;
        let msg = t.get_last_msg().await;
        assert_eq!(msg.download_state(), DownloadState::Available);
        assert_eq!(msg.get_subject(), "foo");
        assert!(msg.get_text().contains("[97.66 KiB message]"));

        receive_imf_from_inbox(
            &t,
            "Mr.12345678901@example.com",
            format!("{header}\n\n100k text...").as_bytes(),
            false,
        )
        .await?;
        let msg = t.get_last_msg().await;
        assert_eq!(msg.download_state(), DownloadState::Done);
        assert_eq!(msg.get_subject(), "foo");
        assert_eq!(msg.get_text(), "100k text...");

        Ok(())
    }
    /// Tests that pre message is sent for attachment larger than `PRE_MSG_ATTACHMENT_SIZE_THRESHOLD`
    /// Also test that pre message is sent first, before the full message
    /// And that Autocrypt-gossip and selfavatar never go into full-messages
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_sending_pre_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let fiona = &tcm.fiona().await;
        let group_id = alice
            .create_group_with_members("test group", &[bob, fiona])
            .await;

        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "test.bin", &[0u8; 300_000], None)?;
        msg.set_text("test".to_owned());

        // assert that test attachment is bigger than limit
        assert!(msg.get_filebytes(alice).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

        let msg_id = chat::send_msg(alice, group_id, &mut msg).await?;
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

        //   pre-message and full message should be present
        //   and test that correct headers are present on both messages
        assert_eq!(smtp_rows.len(), 2);
        let pre_message = smtp_rows.first().expect("first element exists");
        let pre_message_parsed = mailparse::parse_mail(pre_message.payload.as_bytes())?;
        let full_message = smtp_rows.get(1).expect("second element exists");
        let full_message_parsed = mailparse::parse_mail(full_message.payload.as_bytes())?;

        assert!(
            pre_message_parsed
                .headers
                .get_first_header(HeaderDef::ChatIsFullMessage.get_headername())
                .is_none()
        );
        assert!(
            full_message_parsed
                .headers
                .get_first_header(HeaderDef::ChatIsFullMessage.get_headername())
                .is_some()
        );

        assert_eq!(
            full_message_parsed
                .headers
                .get_header_value(HeaderDef::MessageId),
            Some(format!("<{}>", msg.rfc724_mid)),
            "full message should have the rfc message id of the database message"
        );

        assert_ne!(
            pre_message_parsed
                .headers
                .get_header_value(HeaderDef::MessageId),
            full_message_parsed
                .headers
                .get_header_value(HeaderDef::MessageId),
            "message ids of pre message and full message should be different"
        );

        let decrypted_full_message = bob.parse_msg(full_message).await;
        assert_eq!(decrypted_full_message.decrypting_failed, false);
        assert_eq!(
            decrypted_full_message.header_exists(HeaderDef::ChatFullMessageId),
            false
        );

        let decrypted_pre_message = bob.parse_msg(pre_message).await;
        assert_eq!(
            decrypted_pre_message
                .get_header(HeaderDef::ChatFullMessageId)
                .map(String::from),
            full_message_parsed
                .headers
                .get_header_value(HeaderDef::MessageId)
        );
        assert!(
            pre_message_parsed
                .headers
                .get_header_value(HeaderDef::ChatFullMessageId)
                .is_none(),
            "no Chat-Full-Message-ID header in unprotected headers of Pre-Message"
        );

        Ok(())
    }

    /// Tests that pre message has autocrypt gossip headers and self avatar
    /// and full message doesn't have these headers
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_selfavatar_and_autocrypt_gossip_goto_pre_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let fiona = &tcm.fiona().await;
        let group_id = alice
            .create_group_with_members("test group", &[bob, fiona])
            .await;

        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "test.bin", &[0u8; 300_000], None)?;
        msg.set_text("test".to_owned());

        // assert that test attachment is bigger than limit
        assert!(msg.get_filebytes(alice).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

        // simulate conditions for sending self avatar
        let avatar_src = alice.get_blobdir().join("avatar.png");
        fs::write(&avatar_src, test_utils::AVATAR_900x900_BYTES).await?;
        alice
            .set_config(Config::Selfavatar, Some(avatar_src.to_str().unwrap()))
            .await?;

        let msg_id = chat::send_msg(alice, group_id, &mut msg).await?;
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

        assert_eq!(smtp_rows.len(), 2);
        let pre_message = smtp_rows.first().expect("first element exists");
        let full_message = smtp_rows.get(1).expect("second element exists");
        let full_message_parsed = mailparse::parse_mail(full_message.payload.as_bytes())?;

        let decrypted_pre_message = bob.parse_msg(pre_message).await;
        assert!(
            decrypted_pre_message
                .get_header(HeaderDef::ChatFullMessageId)
                .is_some(),
            "tested message is not a pre-message, sending order may be broken"
        );
        assert_ne!(decrypted_pre_message.gossiped_keys.len(), 0);
        assert_ne!(decrypted_pre_message.user_avatar, None);

        let decrypted_full_message = bob.parse_msg(full_message).await;
        assert!(
            full_message_parsed
                .headers
                .get_first_header(HeaderDef::ChatIsFullMessage.get_headername())
                .is_some(),
            "tested message is not a full-message, sending order may be broken"
        );
        assert_eq!(decrypted_full_message.gossiped_keys.len(), 0);
        assert_eq!(decrypted_full_message.user_avatar, None);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unecrypted_gets_no_pre_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;

        let chat = alice
            .create_chat_with_contact("example", "email@example.org")
            .await;

        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "test.bin", &[0u8; 300_000], None)?;
        msg.set_text("test".to_owned());

        let msg_id = chat::send_msg(alice, chat.id, &mut msg).await?;
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

        assert_eq!(smtp_rows.len(), 1);
        let message_bytes = smtp_rows
            .first()
            .expect("first element exists")
            .payload
            .as_bytes();
        let message = mailparse::parse_mail(message_bytes)?;
        assert!(
            message
                .headers
                .get_first_header(HeaderDef::ChatIsFullMessage.get_headername())
                .is_none(),
        );
        Ok(())
    }

    /// Tests that no pre message is sent for normal message
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_not_sending_pre_message_no_attachment() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let chat = alice.create_chat(bob).await;

        // send normal text message
        let mut msg = Message::new(Viewtype::Text);
        msg.set_text("test".to_owned());
        let msg_id = chat::send_msg(alice, chat.id, &mut msg).await.unwrap();
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

        assert_eq!(smtp_rows.len(), 1, "only one message should be sent");

        let msg = smtp_rows.first().expect("first element exists");
        let mail = mailparse::parse_mail(msg.payload.as_bytes())?;

        assert!(
            mail.headers
                .get_first_header(HeaderDef::ChatIsFullMessage.get_headername())
                .is_none(),
            "no 'Chat-Is-Full-Message'-header should be present"
        );
        assert!(
            mail.headers
                .get_first_header(HeaderDef::ChatFullMessageId.get_headername())
                .is_none(),
            "no 'Chat-Full-Message-ID'-header should be present in clear text headers"
        );
        let decrypted_message = bob.parse_msg(msg).await;
        assert!(
            !decrypted_message.header_exists(HeaderDef::ChatFullMessageId),
            "no 'Chat-Full-Message-ID'-header should be present"
        );

        // test that pre message is not send for large large text
        let mut msg = Message::new(Viewtype::Text);
        let long_text = String::from_utf8(vec![b'a'; 300_000])?;
        assert!(long_text.len() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD.try_into().unwrap());
        msg.set_text(long_text);
        let msg_id = chat::send_msg(alice, chat.id, &mut msg).await.unwrap();
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

        assert_eq!(smtp_rows.len(), 1, "only one message should be sent");

        let msg = smtp_rows.first().expect("first element exists");
        let mail = mailparse::parse_mail(msg.payload.as_bytes())?;

        assert!(
            mail.headers
                .get_first_header(HeaderDef::ChatIsFullMessage.get_headername())
                .is_none()
        );
        assert!(
            mail.headers
                .get_first_header(HeaderDef::ChatFullMessageId.get_headername())
                .is_none(),
            "no 'Chat-Full-Message-ID'-header should be present in clear text headers"
        );
        let decrypted_message = bob.parse_msg(msg).await;
        assert!(
            !decrypted_message.header_exists(HeaderDef::ChatFullMessageId),
            "no 'Chat-Full-Message-ID'-header should be present"
        );
        Ok(())
    }

    /// Tests that no pre message is sent for attachment smaller than `PRE_MSG_ATTACHMENT_SIZE_THRESHOLD`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_not_sending_pre_message_for_small_attachment() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let chat = alice.create_chat(bob).await;

        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(alice, "test.bin", &[0u8; 100_000], None)?;
        msg.set_text("test".to_owned());

        // assert that test attachment is smaller than limit
        assert!(msg.get_filebytes(alice).await?.unwrap() < PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

        let msg_id = chat::send_msg(alice, chat.id, &mut msg).await.unwrap();
        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;

        //   only one message and no "is full message" header should be present
        assert_eq!(smtp_rows.len(), 1);

        let msg = smtp_rows.first().expect("first element exists");
        let mail = mailparse::parse_mail(msg.payload.as_bytes())?;

        assert!(
            mail.headers
                .get_first_header(HeaderDef::ChatIsFullMessage.get_headername())
                .is_none()
        );
        assert!(
            mail.headers
                .get_first_header(HeaderDef::ChatFullMessageId.get_headername())
                .is_none(),
            "no 'Chat-Full-Message-ID'-header should be present in clear text headers"
        );
        let decrypted_message = bob.parse_msg(msg).await;
        assert!(
            !decrypted_message.header_exists(HeaderDef::ChatFullMessageId),
            "no 'Chat-Full-Message-ID'-header should be present"
        );

        Ok(())
    }

    /// Tests that pre message is not send for large webxdc updates
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_render_webxdc_status_update_object_range() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat_id = create_group(&t, "a chat").await?;

        let instance = {
            let mut instance = Message::new(Viewtype::File);
            instance.set_file_from_bytes(
                &t,
                "minimal.xdc",
                include_bytes!("../test-data/webxdc/minimal.xdc"),
                None,
            )?;
            let instance_msg_id = send_msg(&t, chat_id, &mut instance).await?;
            assert_eq!(instance.viewtype, Viewtype::Webxdc);
            Message::load_from_db(&t, instance_msg_id).await
        }
        .unwrap();

        t.pop_sent_msg().await;
        assert_eq!(t.sql.count("SELECT COUNT(*) FROM smtp", ()).await?, 0);

        let long_text = String::from_utf8(vec![b'a'; 300_000])?;
        assert!(long_text.len() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD.try_into().unwrap());
        t.send_webxdc_status_update(instance.id, &format!("{{\"payload\": \"{long_text}\"}}"))
            .await?;
        t.flush_status_updates().await?;

        assert_eq!(t.sql.count("SELECT COUNT(*) FROM smtp", ()).await?, 1);
        Ok(())
    }
}
