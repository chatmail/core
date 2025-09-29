//! # Download large messages manually.

use std::cmp::max;
use std::collections::BTreeMap;

use anyhow::{Result, anyhow, bail, ensure};
use deltachat_derive::{FromSql, ToSql};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::context::Context;
use crate::imap::session::Session;
use crate::log::info;
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::{MimeMessage, Part};
use crate::tools::time;
use crate::{EventType, chatlist_events, stock_str};

/// Download limits should not be used below `MIN_DOWNLOAD_LIMIT`.
///
/// For better UX, some messages as add-member, non-delivery-reports (NDN) or read-receipts (MDN)
/// should always be downloaded completely to handle them correctly,
/// also in larger groups and if group and contact avatar are attached.
/// Most of these cases are caught by `MIN_DOWNLOAD_LIMIT`.
pub(crate) const MIN_DOWNLOAD_LIMIT: u32 = 163840;

/// If a message is downloaded only partially
/// and `delete_server_after` is set to small timeouts (eg. "at once"),
/// the user might have no chance to actually download that message.
/// `MIN_DELETE_SERVER_AFTER` increases the timeout in this case.
pub(crate) const MIN_DELETE_SERVER_AFTER: i64 = 48 * 60 * 60;

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

impl Context {
    // Returns validated download limit or `None` for "no limit".
    pub(crate) async fn download_limit(&self) -> Result<Option<u32>> {
        let download_limit = self.get_config_int(Config::DownloadLimit).await?;
        if download_limit <= 0 {
            Ok(None)
        } else {
            Ok(Some(max(MIN_DOWNLOAD_LIMIT, download_limit as u32)))
        }
    }
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
                self.update_download_state(context, DownloadState::InProgress)
                    .await?;
                context
                    .sql
                    .execute("INSERT INTO download (msg_id) VALUES (?)", (self,))
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
    msg_id: MsgId,
    session: &mut Session,
) -> Result<()> {
    let Some(msg) = Message::load_from_db_optional(context, msg_id).await? else {
        // If partially downloaded message was already deleted
        // we do not know its Message-ID anymore
        // so cannot download it.
        //
        // Probably the message expired due to `delete_device_after`
        // setting or was otherwise removed from the device,
        // so we don't want it to reappear anyway.
        return Ok(());
    };

    let row = context
        .sql
        .query_row_optional(
            "SELECT uid, folder, uidvalidity FROM imap WHERE rfc724_mid=? AND target!=''",
            (&msg.rfc724_mid,),
            |row| {
                let server_uid: u32 = row.get(0)?;
                let server_folder: String = row.get(1)?;
                let uidvalidity: u32 = row.get(2)?;
                Ok((server_uid, server_folder, uidvalidity))
            },
        )
        .await?;

    let Some((server_uid, server_folder, uidvalidity)) = row else {
        // No IMAP record found, we don't know the UID and folder.
        return Err(anyhow!("Call download_full() again to try over."));
    };

    session
        .fetch_single_msg(
            context,
            &server_folder,
            uidvalidity,
            server_uid,
            msg.rfc724_mid.clone(),
        )
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
        uidvalidity: u32,
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
        self.fetch_many_msgs(
            context,
            folder,
            uidvalidity,
            vec![uid],
            &uid_message_ids,
            false,
            sender,
        )
        .await?;
        if receiver.recv().await.is_err() {
            bail!("Failed to fetch UID {uid}");
        }
        Ok(())
    }
}

impl MimeMessage {
    /// Creates a placeholder part and add that to `parts`.
    ///
    /// To create the placeholder, only the outermost header can be used,
    /// the mime-structure itself is not available.
    ///
    /// The placeholder part currently contains a text with size and availability of the message;
    /// `error` is set as the part error;
    /// in the future, we may do more advanced things as previews here.
    pub(crate) async fn create_stub_from_partial_download(
        &mut self,
        context: &Context,
        org_bytes: u32,
        error: Option<String>,
    ) -> Result<()> {
        let prefix = match error {
            None => "",
            Some(_) => "[❗] ",
        };
        let mut text = format!(
            "{prefix}[{}]",
            stock_str::partial_download_msg_body(context, org_bytes).await
        );
        if let Some(delete_server_after) = context.get_config_delete_server_after().await? {
            let until = stock_str::download_availability(
                context,
                time() + max(delete_server_after, MIN_DELETE_SERVER_AFTER),
            )
            .await;
            text += format!(" [{until}]").as_str();
        };

        info!(context, "Partial download: {}", text);

        self.do_add_single_part(Part {
            typ: Viewtype::Text,
            msg: text,
            error,
            ..Default::default()
        });

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use num_traits::FromPrimitive;

    use super::*;
    use crate::chat::{get_chat_msgs, send_msg};
    use crate::ephemeral::Timer;
    use crate::receive_imf::receive_imf_from_inbox;
    use crate::test_utils::{E2EE_INFO_MSGS, TestContext};

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
    async fn test_download_limit() -> Result<()> {
        let t = TestContext::new_alice().await;

        assert_eq!(t.download_limit().await?, None);

        t.set_config(Config::DownloadLimit, Some("200000")).await?;
        assert_eq!(t.download_limit().await?, Some(200000));

        t.set_config(Config::DownloadLimit, Some("20000")).await?;
        assert_eq!(t.download_limit().await?, Some(MIN_DOWNLOAD_LIMIT));

        t.set_config(Config::DownloadLimit, None).await?;
        assert_eq!(t.download_limit().await?, None);

        for val in &["0", "-1", "-100", "", "foo"] {
            t.set_config(Config::DownloadLimit, Some(val)).await?;
            assert_eq!(t.download_limit().await?, None);
        }

        Ok(())
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
    async fn test_partial_receive_imf() -> Result<()> {
        let t = TestContext::new_alice().await;

        let header = "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
             From: bob@example.com\n\
             To: alice@example.org\n\
             Subject: foo\n\
             Message-ID: <Mr.12345678901@example.com>\n\
             Chat-Version: 1.0\n\
             Date: Sun, 22 Mar 2020 22:37:57 +0000\
             Content-Type: text/plain";

        receive_imf_from_inbox(
            &t,
            "Mr.12345678901@example.com",
            header.as_bytes(),
            false,
            Some(100000),
        )
        .await?;
        let msg = t.get_last_msg().await;
        assert_eq!(msg.download_state(), DownloadState::Available);
        assert_eq!(msg.get_subject(), "foo");
        assert!(
            msg.get_text()
                .contains(&stock_str::partial_download_msg_body(&t, 100000).await)
        );

        receive_imf_from_inbox(
            &t,
            "Mr.12345678901@example.com",
            format!("{header}\n\n100k text...").as_bytes(),
            false,
            None,
        )
        .await?;
        let msg = t.get_last_msg().await;
        assert_eq!(msg.download_state(), DownloadState::Done);
        assert_eq!(msg.get_subject(), "foo");
        assert_eq!(msg.get_text(), "100k text...");

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_partial_download_and_ephemeral() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat_id = t
            .create_chat_with_contact("bob", "bob@example.org")
            .await
            .id;
        chat_id
            .set_ephemeral_timer(&t, Timer::Enabled { duration: 60 })
            .await?;

        // download message from bob partially, this must not change the ephemeral timer
        receive_imf_from_inbox(
            &t,
            "first@example.org",
            b"From: Bob <bob@example.org>\n\
                    To: Alice <alice@example.org>\n\
                    Chat-Version: 1.0\n\
                    Subject: subject\n\
                    Message-ID: <first@example.org>\n\
                    Date: Sun, 14 Nov 2021 00:10:00 +0000\
                    Content-Type: text/plain",
            false,
            Some(100000),
        )
        .await?;
        assert_eq!(
            chat_id.get_ephemeral_timer(&t).await?,
            Timer::Enabled { duration: 60 }
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_status_update_expands_to_nothing() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let bob = TestContext::new_bob().await;
        let chat_id = alice.create_chat(&bob).await.id;

        let file = alice.get_blobdir().join("minimal.xdc");
        tokio::fs::write(&file, include_bytes!("../test-data/webxdc/minimal.xdc")).await?;
        let mut instance = Message::new(Viewtype::File);
        instance.set_file_and_deduplicate(&alice, &file, None, None)?;
        let _sent1 = alice.send_msg(chat_id, &mut instance).await;

        alice
            .send_webxdc_status_update(instance.id, r#"{"payload":7}"#)
            .await?;
        alice.flush_status_updates().await?;
        let sent2 = alice.pop_sent_msg().await;
        let sent2_rfc724_mid = sent2.load_from_db().await.rfc724_mid;

        // not downloading the status update results in an placeholder
        receive_imf_from_inbox(
            &bob,
            &sent2_rfc724_mid,
            sent2.payload().as_bytes(),
            false,
            Some(sent2.payload().len() as u32),
        )
        .await?;
        let msg = bob.get_last_msg().await;
        let chat_id = msg.chat_id;
        assert_eq!(
            get_chat_msgs(&bob, chat_id).await?.len(),
            E2EE_INFO_MSGS + 1
        );
        assert_eq!(msg.download_state(), DownloadState::Available);

        // downloading the status update afterwards expands to nothing and moves the placeholder to trash-chat
        // (usually status updates are too small for not being downloaded directly)
        receive_imf_from_inbox(
            &bob,
            &sent2_rfc724_mid,
            sent2.payload().as_bytes(),
            false,
            None,
        )
        .await?;
        assert_eq!(get_chat_msgs(&bob, chat_id).await?.len(), E2EE_INFO_MSGS);
        assert!(
            Message::load_from_db_optional(&bob, msg.id)
                .await?
                .is_none()
        );

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mdn_expands_to_nothing() -> Result<()> {
        let bob = TestContext::new_bob().await;
        let raw = b"Subject: Message opened\n\
            Date: Mon, 10 Jan 2020 00:00:00 +0000\n\
            Chat-Version: 1.0\n\
            Message-ID: <bar@example.org>\n\
            To: Alice <alice@example.org>\n\
            From: Bob <bob@example.org>\n\
            Content-Type: multipart/report; report-type=disposition-notification;\n\t\
            boundary=\"kJBbU58X1xeWNHgBtTbMk80M5qnV4N\"\n\
            \n\
            \n\
            --kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
            Content-Type: text/plain; charset=utf-8\n\
            \n\
            bla\n\
            \n\
            \n\
            --kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
            Content-Type: message/disposition-notification\n\
            \n\
            Reporting-UA: Delta Chat 1.88.0\n\
            Original-Recipient: rfc822;bob@example.org\n\
            Final-Recipient: rfc822;bob@example.org\n\
            Original-Message-ID: <foo@example.org>\n\
            Disposition: manual-action/MDN-sent-automatically; displayed\n\
            \n\
            \n\
            --kJBbU58X1xeWNHgBtTbMk80M5qnV4N--\n\
            ";

        // not downloading the mdn results in an placeholder
        receive_imf_from_inbox(&bob, "bar@example.org", raw, false, Some(raw.len() as u32)).await?;
        let msg = bob.get_last_msg().await;
        let chat_id = msg.chat_id;
        assert_eq!(get_chat_msgs(&bob, chat_id).await?.len(), 1);
        assert_eq!(msg.download_state(), DownloadState::Available);

        // downloading the mdn afterwards expands to nothing and deletes the placeholder directly
        // (usually mdn are too small for not being downloaded directly)
        receive_imf_from_inbox(&bob, "bar@example.org", raw, false, None).await?;
        assert_eq!(get_chat_msgs(&bob, chat_id).await?.len(), 0);
        assert!(
            Message::load_from_db_optional(&bob, msg.id)
                .await?
                .is_none()
        );

        Ok(())
    }
}
