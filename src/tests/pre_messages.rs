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
    use pretty_assertions::assert_eq;

    use crate::chat::{self, ChatId};
    use crate::download::PRE_MSG_ATTACHMENT_SIZE_THRESHOLD;
    use crate::download::pre_msg_metadata::PreMsgMetadata;
    use crate::message::{Message, Viewtype};
    use crate::mimeparser::MimeMessage;
    use crate::param::Param;
    use crate::test_utils::SentMessage;

    async fn send_large_file_message<'a>(
        sender: &'a TestContext,
        target_chat: ChatId,
        attachment_size: u64,
    ) -> Result<(SentMessage<'a>, SentMessage<'a>)> {
        let mut msg = Message::new(Viewtype::File);
        msg.set_file_from_bytes(
            sender,
            "test.bin",
            &vec![0u8; attachment_size as usize],
            None,
        )?;
        msg.set_text("test".to_owned());

        // assert that test attachment is bigger than limit
        assert!(msg.get_filebytes(sender).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

        let msg_id = chat::send_msg(sender, target_chat, &mut msg).await?;
        let smtp_rows = sender.get_smtp_rows_for_msg(msg_id).await;

        assert_eq!(smtp_rows.len(), 2);
        let pre_message = smtp_rows.first().expect("pre-message exists");
        let full_message = smtp_rows.get(1).expect("full message exists");
        Ok((pre_message.to_owned(), full_message.to_owned()))
    }

    /// Test that mimeparser can correctly detect and parse pre-messages and full-messages
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mimeparser_pre_message_and_full_message() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        let alice_group_id = alice.create_group_with_members("test group", &[bob]).await;

        let (pre_message, full_message) =
            send_large_file_message(alice, alice_group_id, 1_000_000).await?;

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

        let (pre_message, _full_message) =
            send_large_file_message(alice, alice_group_id, 1_000_000).await?;

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

        let (pre_message, full_message) =
            send_large_file_message(alice, alice_group_id, 1_000_000).await?;

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

        let (pre_message, full_message) =
            send_large_file_message(alice, alice_group_id, 1_000_000).await?;

        let msg = bob.recv_msg(&full_message).await;
        assert_eq!(msg.download_state(), DownloadState::Done);
        assert_eq!(msg.viewtype, Viewtype::File);
        let _ = bob.recv_msg_trash(&pre_message).await;
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
}
