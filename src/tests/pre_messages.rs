use crate::download::DownloadState;
use crate::test_utils::{self, TestContext, TestContextManager};
use anyhow::Result;

/// Test that downloading old stub messages still works
mod legacy {
    use super::*;
    use crate::receive_imf::receive_imf_from_inbox;

    // The code for downloading stub messages stays
    // during the transition perios to pre-messages
    // so people can still download their files shortly after they updated.
    // After there are a few release with pre-message rolled out,
    // we will remove the ability to download stub messages and replace the following test
    // so it checks that it doesn't crash or that the messages are replaced by sth.
    // like "download failed/expired, please ask sender to send it again"
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
}

/// Tests about sending pre-messages
/// - When to send a pre-message and full-message instead of a normal message
/// - Test that sent pre- and full-message contain the right Headers
///   and that they are send in the correct order (pre-message is sent first.)
mod sending {
    use super::*;
    use mailparse::MailHeaderMap;
    use tokio::fs;

    use crate::chat::{self, create_group, send_msg};
    use crate::config::Config;
    use crate::download::PRE_MSG_ATTACHMENT_SIZE_THRESHOLD;
    use crate::headerdef::{HeaderDef, HeaderDefMap};
    use crate::message::{Message, Viewtype};
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
        msg.set_file_from_bytes(alice, "test.bin", &vec![0u8; 300_000], None)?;
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
        msg.set_file_from_bytes(alice, "test.bin", &vec![0u8; 100_000], None)?;
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
                include_bytes!("../../test-data/webxdc/minimal.xdc"),
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

/// Tests about receiving pre-messages and full messages
mod receiving {
    use super::*;
    use async_zip::tokio::write::ZipFileWriter;
    use async_zip::{Compression, ZipEntryBuilder};
    use futures::io::Cursor as FuturesCursor;
    use pretty_assertions::assert_eq;
    use tokio_util::compat::FuturesAsyncWriteCompatExt;

    use crate::EventType;
    use crate::chat::{self, ChatId};
    use crate::contact::{self};
    use crate::download::PRE_MSG_ATTACHMENT_SIZE_THRESHOLD;
    use crate::download::pre_msg_metadata::PreMsgMetadata;
    use crate::message::{Message, MessageState, MsgId, Viewtype, delete_msgs, markseen_msgs};
    use crate::mimeparser::MimeMessage;
    use crate::param::Param;
    use crate::reaction::{get_msg_reactions, send_reaction};
    use crate::test_utils::{SentMessage, create_test_image};
    use crate::webxdc::StatusUpdateSerial;

    async fn send_large_file_message<'a>(
        sender: &'a TestContext,
        target_chat: ChatId,
        view_type: Viewtype,
        content: &[u8],
    ) -> Result<(SentMessage<'a>, SentMessage<'a>, MsgId)> {
        let mut msg = Message::new(view_type);
        let file_name = if view_type == Viewtype::Webxdc {
            "test.xdc"
        } else {
            "test.bin"
        };
        msg.set_file_from_bytes(sender, file_name, content, None)?;
        msg.set_text("test".to_owned());

        // assert that test attachment is bigger than limit
        assert!(msg.get_filebytes(sender).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

        let msg_id = chat::send_msg(sender, target_chat, &mut msg).await?;
        let smtp_rows = sender.get_smtp_rows_for_msg(msg_id).await;

        assert_eq!(smtp_rows.len(), 2);
        let pre_message = smtp_rows.first().expect("pre-message exists");
        let full_message = smtp_rows.get(1).expect("full message exists");
        Ok((pre_message.to_owned(), full_message.to_owned(), msg_id))
    }

    /// Test that mimeparser can correctly detect and parse pre-messages and full-messages
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mimeparser_pre_message_and_full_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (pre_message, full_message, _alice_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        let parsed_pre_message =
            MimeMessage::from_bytes(bob, pre_message.payload.as_bytes()).await?;
        let parsed_full_message =
            MimeMessage::from_bytes(bob, full_message.payload.as_bytes()).await?;

        assert_eq!(
            parsed_full_message.pre_message,
            Some(crate::mimeparser::PreMessageMode::FullMessage)
        );

        assert_eq!(
            parsed_pre_message.pre_message,
            Some(crate::mimeparser::PreMessageMode::PreMessage {
                full_msg_rfc724_mid: parsed_full_message.get_rfc724_mid().unwrap(),
                metadata: Some(PreMsgMetadata {
                    size: 1_000_000,
                    viewtype: Viewtype::File,
                    filename: "test.bin".to_string(),
                    dimensions: None,
                    duration: None
                })
            })
        );

        Ok(())
    }

    /// Test receiving pre-messages and creation of the placeholder message with the metadata
    /// for file attachment
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_pre_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (pre_message, _full_message, _alice_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        let msg = bob.recv_msg(&pre_message).await;

        assert_eq!(msg.download_state(), DownloadState::Available);
        assert_eq!(msg.viewtype, Viewtype::Text);
        assert_eq!(msg.text, "test".to_owned());

        // test that metadata is correctly returned by methods
        assert_eq!(msg.get_filebytes(bob).await?, Some(1_000_000));
        assert_eq!(msg.get_full_message_viewtype(), Some(Viewtype::File));
        assert_eq!(msg.get_filename(), Some("test.bin".to_owned()));

        Ok(())
    }

    /// Test receiving the full message after receiving the pre-message
    /// for file attachment
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_pre_message_and_dl_full_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (pre_message, full_message, _alice_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        let msg = bob.recv_msg(&pre_message).await;
        assert_eq!(msg.download_state(), DownloadState::Available);
        assert_eq!(msg.viewtype, Viewtype::Text);
        assert!(msg.param.exists(Param::FullMessageViewtype));
        assert!(msg.param.exists(Param::FullMessageFileBytes));
        assert_eq!(msg.text, "test".to_owned());
        let _ = bob.recv_msg_trash(&full_message).await;
        let msg = Message::load_from_db(bob, msg.id).await?;
        assert_eq!(msg.download_state(), DownloadState::Done);
        assert_eq!(msg.viewtype, Viewtype::File);
        assert_eq!(msg.param.exists(Param::FullMessageViewtype), false);
        assert_eq!(msg.param.exists(Param::FullMessageFileBytes), false);
        assert_eq!(msg.text, "test".to_owned());
        Ok(())
    }

    /// Test out of order receiving. Full message is received & downloaded before pre-message.
    /// In that case pre-message shall be trashed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_out_of_order_receiving() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (pre_message, full_message, _alice_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        let msg = bob.recv_msg(&full_message).await;
        assert_eq!(msg.download_state(), DownloadState::Done);
        assert_eq!(msg.viewtype, Viewtype::File);
        let _ = bob.recv_msg_trash(&pre_message).await;
        Ok(())
    }

    /// Test receiving the full message after receiving an edit after receiving the pre-message
    /// for file attachment
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_pre_message_then_edit_and_then_dl_full_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (pre_message, full_message, alice_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        chat::send_edit_request(alice, alice_msg_id, "new_text".to_owned()).await?;
        let edit_request = alice.pop_sent_msg().await;

        let msg = bob.recv_msg(&pre_message).await;
        assert_eq!(msg.download_state(), DownloadState::Available);
        assert_eq!(msg.text, "test".to_owned());
        let _ = bob.recv_msg_trash(&edit_request).await;
        let msg = Message::load_from_db(bob, msg.id).await?;
        assert_eq!(msg.download_state(), DownloadState::Available);
        assert_eq!(msg.text, "new_text".to_owned());
        let _ = bob.recv_msg_trash(&full_message).await;
        let msg = Message::load_from_db(bob, msg.id).await?;
        assert_eq!(msg.download_state(), DownloadState::Done);
        assert_eq!(msg.viewtype, Viewtype::File);
        assert_eq!(msg.text, "new_text".to_owned());
        Ok(())
    }

    /// Process normal message with file attachment (neither full nor pre message)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_normal_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(
            alice,
            "test.bin",
            &vec![0u8; (PRE_MSG_ATTACHMENT_SIZE_THRESHOLD - 10_000) as usize],
            None,
        )?;
        msg.set_text("test".to_owned());
        let msg_id = chat::send_msg(alice, alice_group_id, &mut msg).await?;

        let smtp_rows = alice.get_smtp_rows_for_msg(msg_id).await;
        assert_eq!(smtp_rows.len(), 1);
        let message = smtp_rows.first().expect("message exists");

        let msg = bob.recv_msg(message).await;
        assert_eq!(msg.download_state(), DownloadState::Done);
        assert_eq!(msg.viewtype, Viewtype::File);
        assert_eq!(msg.text, "test".to_owned());
        Ok(())
    }

    /// Test receiving pre-messages and creation of the placeholder message with the metadata
    /// for image attachment
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_receive_pre_message_image() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (width, height) = (1080, 1920);
        let test_img = create_test_image(width, height)?;

        let (pre_message, _full_message, _alice_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::Image, &test_img).await?;

        let msg = bob.recv_msg(&pre_message).await;

        assert_eq!(msg.download_state(), DownloadState::Available);
        assert_eq!(msg.viewtype, Viewtype::Text);
        assert_eq!(msg.text, "test".to_owned());

        // test that metadata is correctly returned by methods
        assert_eq!(msg.get_full_message_viewtype(), Some(Viewtype::Image));
        // recoded image dimensions
        assert_eq!(msg.get_filebytes(bob).await?, Some(149632));
        assert_eq!(msg.get_height(), 1280);
        assert_eq!(msg.get_width(), 720);

        Ok(())
    }

    /// Test receiving reaction on pre-message
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_reaction_on_pre_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (pre_message, full_message, alice_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        // Bob receives pre-message
        let bob_msg = bob.recv_msg(&pre_message).await;
        assert_eq!(bob_msg.download_state(), DownloadState::Available);

        // Alice sends reaction to her own message
        send_reaction(alice, alice_msg_id, "👍").await?;

        // Bob receives the reaction
        bob.recv_msg_hidden(&alice.pop_sent_msg().await).await;

        // Test if Bob sees reaction
        let reactions = get_msg_reactions(bob, bob_msg.id).await?;
        assert_eq!(reactions.to_string(), "👍1");

        // Bob downloads full message
        bob.recv_msg_trash(&full_message).await;
        let msg = Message::load_from_db(bob, bob_msg.id).await?;
        assert_eq!(msg.download_state(), DownloadState::Done);

        // Test if Bob still sees reaction
        let reactions = get_msg_reactions(bob, bob_msg.id).await?;
        assert_eq!(reactions.to_string(), "👍1");

        Ok(())
    }

    /// Tests that fully downloading the message
    /// works but does not reappear when it was already deleted
    /// (as in the Message-ID already exists in the database
    /// and is assigned to the trash chat).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_full_download_after_trashed() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let bob_group_id = bob.create_group_with_members("test group", &[alice]).await;

        let (pre_message, full_message, _bob_msg_id) =
            send_large_file_message(bob, bob_group_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        // Download message from Bob partially.
        let alice_msg = alice.recv_msg(&pre_message).await;

        // Delete the received message.
        // Note that it remains in the database in the trash chat.
        delete_msgs(alice, &[alice_msg.id]).await?;

        // Fully download message after deletion.
        alice.recv_msg_trash(&full_message).await;

        // The message does not reappear.
        let msg = Message::load_from_db_optional(bob, alice_msg.id).await?;
        assert!(msg.is_none());

        Ok(())
    }

    /// Test that webxdc updates are received for pre-messages
    /// and available when the full-message is downloaded
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_webxdc_update_for_not_downloaded_instance() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let futures_cursor = FuturesCursor::new(Vec::new());
        let mut buffer = futures_cursor.compat_write();
        let mut writer = ZipFileWriter::with_tokio(&mut buffer);
        writer
            .write_entry_whole(
                ZipEntryBuilder::new("index.html".into(), Compression::Stored),
                &[0u8; 1_000_000],
            )
            .await?;
        writer.close().await?;
        let big_webxdc_app = buffer.into_inner().into_inner();

        // Alice sends a larger instance and an update
        let (pre_message, full_message, alice_sent_instance_msg_id) =
            send_large_file_message(alice, alice_group_id, Viewtype::Webxdc, &big_webxdc_app)
                .await?;
        alice
            .send_webxdc_status_update(
                alice_sent_instance_msg_id,
                r#"{"payload": 7, "summary":"sum", "document":"doc"}"#,
            )
            .await?;
        alice.flush_status_updates().await?;
        let webxdc_update = alice.pop_sent_msg().await;

        // Bob does not download instance but already receives update
        let bob_instance = bob.recv_msg(&pre_message).await;
        assert_eq!(bob_instance.download_state, DownloadState::Available);
        bob.recv_msg_trash(&webxdc_update).await;

        // Bob downloads instance, updates should be assigned correctly
        bob.recv_msg_trash(&full_message).await;

        let bob_instance = bob.get_last_msg().await;
        assert_eq!(bob_instance.viewtype, Viewtype::Webxdc);
        assert_eq!(bob_instance.download_state, DownloadState::Done);
        assert_eq!(
            bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial::new(0))
                .await?,
            r#"[{"payload":7,"document":"doc","summary":"sum","serial":1,"max_serial":1}]"#
        );
        let info = bob_instance.get_webxdc_info(bob).await?;
        assert_eq!(info.document, "doc");
        assert_eq!(info.summary, "sum");

        Ok(())
    }

    /// Test mark seen pre-message
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_markseen_pre_msg() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let bob_chat_id = bob.create_chat(alice).await.id;
        alice.create_chat(bob).await; // Make sure the chat is accepted.

        tcm.section("Bob sends a large message to Alice");
        let (pre_message, full_message, _bob_msg_id) =
            send_large_file_message(bob, bob_chat_id, Viewtype::File, &vec![0u8; 1_000_000])
                .await?;

        tcm.section("Alice receives a pre-message message from Bob");
        let msg = alice.recv_msg(&pre_message).await;
        assert_eq!(msg.download_state, DownloadState::Available);
        assert!(msg.param.get_bool(Param::WantsMdn).unwrap_or_default());
        assert_eq!(msg.state, MessageState::InFresh);

        tcm.section("Alice marks the pre-message as read and sends a MDN");
        markseen_msgs(alice, vec![msg.id]).await?;
        assert_eq!(msg.id.get_state(alice).await?, MessageState::InSeen);
        assert_eq!(
            alice
                .sql
                .count("SELECT COUNT(*) FROM smtp_mdns", ())
                .await?,
            1
        );

        tcm.section("Alice downloads message");
        alice.recv_msg_trash(&full_message).await;
        let msg = Message::load_from_db(alice, msg.id).await?;
        assert_eq!(msg.download_state, DownloadState::Done);
        assert!(msg.param.get_bool(Param::WantsMdn).unwrap_or_default());
        assert_eq!(
            msg.state,
            MessageState::InSeen,
            "The message state mustn't be downgraded to `InFresh`"
        );

        Ok(())
    }

    /// Test that pre-message can start a chat
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_pre_msg_can_start_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        tcm.section("establishing a DM chat between alice and bob");
        let bob_alice_dm_chat_id = bob.create_chat(alice).await.id;
        alice.create_chat(bob).await; // Make sure the chat is accepted.

        tcm.section("Alice prepares chat");
        let chat_id = chat::create_group(alice, "my group").await?;
        let contacts = contact::Contact::get_all(alice, 0, None).await?;
        let alice_bob_id = contacts.first().expect("contact exists");
        chat::add_contact_to_chat(alice, chat_id, *alice_bob_id).await?;

        tcm.section("Alice sends large message to promote/start chat");
        let (pre_message, _full_message, _alice_msg_id) =
            send_large_file_message(alice, chat_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;

        tcm.section("Bob receives the pre-message message from Alice");
        let msg = bob.recv_msg(&pre_message).await;
        assert_eq!(msg.download_state, DownloadState::Available);
        assert_ne!(msg.chat_id, bob_alice_dm_chat_id);
        let chat = chat::Chat::load_from_db(bob, msg.chat_id).await?;
        assert_eq!(chat.name, "my group");

        Ok(())
    }

    /// Test that full-message can start a chat
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_full_msg_can_start_chat() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        tcm.section("establishing a DM chat between alice and bob");
        let bob_alice_dm_chat_id = bob.create_chat(alice).await.id;
        alice.create_chat(bob).await; // Make sure the chat is accepted.

        tcm.section("Alice prepares chat");
        let chat_id = chat::create_group(alice, "my group").await?;
        let contacts = contact::Contact::get_all(alice, 0, None).await?;
        let alice_bob_id = contacts.first().expect("contact exists");
        chat::add_contact_to_chat(alice, chat_id, *alice_bob_id).await?;

        tcm.section("Alice sends large message to promote/start chat");
        let (_pre_message, full_message, _bob_msg_id) =
            send_large_file_message(alice, chat_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;

        tcm.section("Bob receives the pre-message message from Alice");
        let msg = bob.recv_msg(&full_message).await;
        assert_eq!(msg.download_state, DownloadState::Done);
        assert_ne!(msg.chat_id, bob_alice_dm_chat_id);
        let chat = chat::Chat::load_from_db(bob, msg.chat_id).await?;
        assert_eq!(chat.name, "my group");

        Ok(())
    }

    /// Test that message ordering is still correct after downloading
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_download_later_keeps_message_order() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        tcm.section(
            "establishing a DM chat between alice and bob and bob sends large message to alice",
        );
        let bob_alice_dm_chat = bob.create_chat(alice).await.id;
        alice.create_chat(bob).await; // Make sure the chat is accepted.
        let (pre_message, full_message, _bob_msg_id) = send_large_file_message(
            bob,
            bob_alice_dm_chat,
            Viewtype::File,
            &vec![0u8; 1_000_000],
        )
        .await?;

        tcm.section("Alice downloads pre-message");
        let msg = alice.recv_msg(&pre_message).await;
        assert_eq!(msg.download_state, DownloadState::Available);
        assert_eq!(msg.state, MessageState::InFresh);
        assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, msg.id);

        tcm.section("Bob sends hi to Alice");
        let hi_msg = tcm.send_recv(bob, alice, "hi").await;
        assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, hi_msg.id);

        tcm.section("Alice downloads full-message");
        alice.recv_msg_trash(&full_message).await;
        let msg = Message::load_from_db(alice, msg.id).await?;
        assert_eq!(msg.download_state, DownloadState::Done);
        assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, hi_msg.id);
        assert!(msg.timestamp_sort <= hi_msg.timestamp_sort);

        Ok(())
    }

    /// Test that ChatlistItemChanged event is emitted when downloading full-message
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_chatlist_event_on_full_msg_download() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        tcm.section(
            "establishing a DM chat between alice and bob and bob sends large message to alice",
        );
        let bob_alice_dm_chat = bob.create_chat(alice).await.id;
        alice.create_chat(bob).await; // Make sure the chat is accepted.
        let (pre_message, full_message, _bob_msg_id) = send_large_file_message(
            bob,
            bob_alice_dm_chat,
            Viewtype::File,
            &vec![0u8; 1_000_000],
        )
        .await?;

        tcm.section("Alice downloads pre-message");
        let msg = alice.recv_msg(&pre_message).await;
        assert_eq!(msg.download_state, DownloadState::Available);
        assert_eq!(msg.state, MessageState::InFresh);
        assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, msg.id);

        tcm.section("Alice downloads full-message and waits for ChatlistItemChanged event ");
        alice.evtracker.clear_events();
        alice.recv_msg_trash(&full_message).await;
        let msg = Message::load_from_db(alice, msg.id).await?;
        assert_eq!(msg.download_state, DownloadState::Done);
        alice
            .evtracker
            .get_matching(|e| {
                e == &EventType::ChatlistItemChanged {
                    chat_id: Some(msg.chat_id),
                }
            })
            .await;

        Ok(())
    }
}
