use rand::Rng;
use std::time::Duration;

use tokio::fs;

use super::*;
use crate::chat::{
    ChatItem, ChatVisibility, add_contact_to_chat, add_to_chat_contacts_table, create_group_chat,
    get_chat_contacts, get_chat_msgs, is_contact_in_chat, remove_contact_from_chat, send_text_msg,
};
use crate::chatlist::Chatlist;
use crate::constants::DC_GCL_FOR_FORWARDING;
use crate::contact;
use crate::download::MIN_DOWNLOAD_LIMIT;
use crate::imap::prefetch_should_download;
use crate::imex::{ImexMode, imex};
use crate::securejoin::get_securejoin_qr;
use crate::test_utils::{
    E2EE_INFO_MSGS, TestContext, TestContextManager, get_chat_msg, mark_as_verified,
};
use crate::tools::{SystemTime, time};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing() -> Result<()> {
    let context = TestContext::new_alice().await;
    let raw = b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                From: alice@example.org\n\
                \n\
                hello";
    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None).await?;
    assert_eq!(mimeparser.incoming, false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_bad_from() {
    let context = TestContext::new_alice().await;
    let raw = b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                    From: hello\n\
                    Subject: outer-subject\n\
                    In-Reply-To: <lqkjwelq123@123123>\n\
                    References: <Gr.HcxyMARjyJy.9-uvzWPTLtV@nauta.cu>\n\
                    \n\
                    hello\x00";
    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None).await;
    assert!(mimeparser.is_err());
}

static MSGRMSG: &[u8] =
    b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                    From: Bob <bob@example.com>\n\
                    To: alice@example.org\n\
                    Chat-Version: 1.0\n\
                    Subject: Chat: hello\n\
                    Message-ID: <Mr.1111@example.com>\n\
                    Date: Sun, 22 Mar 2020 22:37:55 +0000\n\
                    \n\
                    hello\n";

static ONETOONE_NOREPLY_MAIL: &[u8] =
    b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                    From: Bob <bob@example.com>\n\
                    To: alice@example.org\n\
                    Subject: Chat: hello\n\
                    Message-ID: <2222@example.com>\n\
                    Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
                    \n\
                    hello\n";

static GRP_MAIL: &[u8] =
    b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                    From: bob@example.com\n\
                    To: alice@example.org, claire@example.com\n\
                    Subject: group with Alice, Bob and Claire\n\
                    Message-ID: <3333@example.com>\n\
                    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                    \n\
                    hello\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_group_show_chats_only() {
    let t = TestContext::new_alice().await;
    t.set_config(Config::ShowEmails, Some("0")).await.unwrap();

    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);

    receive_imf(&t, MSGRMSG, false).await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);

    receive_imf(&t, ONETOONE_NOREPLY_MAIL, false).await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);

    receive_imf(&t, GRP_MAIL, false).await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_group_show_accepted_contact_unknown() {
    let t = TestContext::new_alice().await;
    t.set_config(Config::ShowEmails, Some("1")).await.unwrap();
    receive_imf(&t, GRP_MAIL, false).await.unwrap();

    // adhoc-group with unknown contacts with show_emails=accepted is ignored for unknown contacts
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_group_outgoing_show_accepted_contact_unaccepted() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    bob.set_config(
        Config::ShowEmails,
        Some(&ShowEmails::AcceptedContacts.to_string()),
    )
    .await?;
    tcm.send_recv(alice, bob, "hi").await;
    receive_imf(
        bob,
        b"From: bob@example.net\n\
        To: alice@example.org, claire@example.com\n\
        Message-ID: <3333@example.net>\n\
        Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
        \n\
        hello\n",
        false,
    )
    .await?;
    let chats = Chatlist::try_load(bob, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0)?;
    assert_eq!(chat_id.get_msg_cnt(bob).await?, E2EE_INFO_MSGS + 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_group_show_accepted_contact_known() {
    let t = TestContext::new_alice().await;
    t.set_config(Config::ShowEmails, Some("1")).await.unwrap();
    Contact::create(&t, "Bob", "bob@example.com").await.unwrap();
    receive_imf(&t, GRP_MAIL, false).await.unwrap();

    // adhoc-group with known contacts with show_emails=accepted is still ignored for known contacts
    // (and existent chat is required)
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_group_show_accepted_contact_accepted() {
    let t = TestContext::new_alice().await;
    t.set_config(Config::ShowEmails, Some("1")).await.unwrap();

    // accept Bob by accepting a delta-message from Bob
    receive_imf(&t, MSGRMSG, false).await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0).unwrap();
    assert!(!chat_id.is_special());
    let chat = chat::Chat::load_from_db(&t, chat_id).await.unwrap();
    assert!(chat.is_contact_request());
    chat_id.accept(&t).await.unwrap();
    let chat = chat::Chat::load_from_db(&t, chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Single);
    assert_eq!(chat.name, "Bob");
    assert_eq!(chat::get_chat_contacts(&t, chat_id).await.unwrap().len(), 1);
    assert_eq!(chat::get_chat_msgs(&t, chat_id).await.unwrap().len(), 1);

    // receive a non-delta-message from Bob, shows up because of the show_emails setting
    receive_imf(&t, ONETOONE_NOREPLY_MAIL, false).await.unwrap();

    assert_eq!(chat::get_chat_msgs(&t, chat_id).await.unwrap().len(), 2);

    // let Bob create an adhoc-group by a non-delta-message, shows up because of the show_emails setting
    receive_imf(&t, GRP_MAIL, false).await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 2);
    let chat_id = chats.get_chat_id(0).unwrap();
    let chat = chat::Chat::load_from_db(&t, chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Group);
    assert_eq!(chat.name, "group with Alice, Bob and Claire");
    assert_eq!(chat::get_chat_contacts(&t, chat_id).await.unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_group_show_all() {
    let t = TestContext::new_alice().await;
    assert_eq!(t.get_config_int(Config::ShowEmails).await.unwrap(), 2);
    receive_imf(&t, GRP_MAIL, false).await.unwrap();

    // adhoc-group with unknown contacts with show_emails=all will show up in a single chat
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0).unwrap();
    let chat = chat::Chat::load_from_db(&t, chat_id).await.unwrap();
    assert!(chat.is_contact_request());
    chat_id.accept(&t).await.unwrap();
    let chat = chat::Chat::load_from_db(&t, chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Group);
    assert_eq!(chat.name, "group with Alice, Bob and Claire");
    assert_eq!(chat::get_chat_contacts(&t, chat_id).await.unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_groups_merge() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    receive_imf(
        alice,
        b"From: bob@example.net\n\
        To: alice@example.org, claire@example.com\n\
        Message-ID: <1111@example.net>\n\
        Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
        Subject: New thread\n\
        \n\
        The first of us should create a thread as discussed\n",
        false,
    )
    .await?;
    receive_imf(
        alice,
        b"From: alice@example.org\n\
        To: bob@example.net, claire@example.com\n\
        Message-ID: <2222@example.org>\n\
        Date: Sun, 22 Mar 2020 22:37:58 +0000\n\
        Subject: New thread\n\
        \n\
        The first of us should create a thread as discussed\n",
        false,
    )
    .await?;
    let chats = Chatlist::try_load(alice, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0)?;
    assert_eq!(chat_id.get_msg_cnt(alice).await?, 2);

    // If member list doesn't match, threads aren't merged.
    receive_imf(
        alice,
        b"From: bob@example.net\n\
        To: alice@example.org, claire@example.com, fiona@example.net\n\
        Message-ID: <3333@example.net>\n\
        Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
        Subject: New thread\n\
        \n\
        This is another thread, with Fiona\n",
        false,
    )
    .await?;
    let chats = Chatlist::try_load(alice, 0, None, None).await?;
    assert_eq!(chats.len(), 2);
    receive_imf(
        alice,
        b"From: bob@example.net\n\
        To: alice@example.org, fiona@example.net\n\
        Message-ID: <4444@example.net>\n\
        Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
        Subject: New thread\n\
        \n\
        This is yet another thread, with Fiona and 0 Claires\n",
        false,
    )
    .await?;
    let chats = Chatlist::try_load(alice, 0, None, None).await?;
    assert_eq!(chats.len(), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mdn_and_alias() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let sent = alice.send_text(alice_chat.id, "alice -> bob").await;
    let msg_id = sent.sender_msg_id;
    receive_imf(
        &alice,
        format!(
            "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
             From: bob@example.net\n\
             To: alicechat@example.org\n\
             Subject: message opened\n\
             Date: Sun, 22 Mar 2020 23:37:57 +0000\n\
             Chat-Version: 1.0\n\
             Message-ID: <aranudiaerudiaduiaertd@example.com>\n\
             Content-Type: multipart/report; report-type=disposition-notification; boundary=\"SNIPP\"\n\
             \n\
             \n\
             --SNIPP\n\
             Content-Type: text/plain; charset=utf-8\n\
             \n\
             Read receipts do not guarantee sth. was read.\n\
             \n\
             \n\
             --SNIPP\n\
             Content-Type: message/disposition-notification\n\
             \n\
             Reporting-UA: Delta Chat 1.28.0\n\
             Original-Recipient: rfc822;bob@example.com\n\
             Final-Recipient: rfc822;bob@example.com\n\
             Original-Message-ID: <{msg_id}>\n\
             Disposition: manual-action/MDN-sent-automatically; displayed\n\
             \n\
             \n\
             --SNIPP--",
        )
        .as_bytes(),
        false,
    )
    .await?;

    let chats = Chatlist::try_load(&alice, 0, None, None).await?;
    assert_eq!(chats.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_from() {
    // if there is no from given, from_id stays 0 which is just fine. These messages
    // are very rare, however, we have to add them to the database
    // to avoid a re-download from the server.

    let t = TestContext::new_alice().await;
    let context = &t;

    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert!(chats.get_msg_id(0).is_err());

    let received = receive_imf(
        context,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 To: bob@example.com\n\
                 Subject: foo\n\
                 Message-ID: <3924@example.com>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await
    .unwrap()
    .unwrap();

    // Check that tombstone MsgId is returned.
    assert_eq!(received.msg_ids.len(), 1);
    assert!(!received.msg_ids[0].is_special());

    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    // Check that the message is not shown to the user:
    assert!(chats.is_empty());

    // Check that the message was added to the db:
    assert!(
        message::rfc724_mid_exists(context, "3924@example.com")
            .await
            .unwrap()
            .is_some()
    );
}

/// If there is no Message-Id header, we generate a random id.
/// But there is no point in adding a trash entry in the database
/// if the email is malformed (e.g. because `From` is missing)
/// with this random id we just generated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_message_id_header() {
    let t = TestContext::new_alice().await;

    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert!(chats.get_msg_id(0).is_err());

    let received = receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
              To: bob@example.com\n\
              Subject: foo\n\
              Chat-Version: 1.0\n\
              Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
              \n\
              hello\n",
        false,
    )
    .await
    .unwrap();
    assert!(received.is_none());

    assert!(
        !t.sql
            .exists(
                "SELECT COUNT(*) FROM msgs WHERE chat_id=?;",
                (DC_CHAT_ID_TRASH,),
            )
            .await
            .unwrap()
    );

    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    // Check that the message is not shown to the user:
    assert!(chats.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_escaped_from() {
    let t = TestContext::new_alice().await;
    let contact_id = Contact::create(&t, "foobar", "foobar@example.com")
        .await
        .unwrap();
    let chat_id = ChatId::create_for_contact(&t, contact_id).await.unwrap();
    receive_imf(
            &t,
            b"From: =?UTF-8?B?0JjQvNGPLCDQpNCw0LzQuNC70LjRjw==?= <foobar@example.com>\n\
                 To: alice@example.org\n\
                 Subject: foo\n\
                 Message-ID: <asdklfjjaweofi@example.com>\n\
                 Chat-Version: 1.0\n\
                 Chat-Disposition-Notification-To: =?UTF-8?B?0JjQvNGPLCDQpNCw0LzQuNC70LjRjw==?= <foobar@example.com>\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello\n",
            false,
        ).await.unwrap();
    assert_eq!(
        Contact::get_by_id(&t, contact_id)
            .await
            .unwrap()
            .get_authname(),
        "Имя, Фамилия",
    );
    let msg = get_chat_msg(&t, chat_id, 0, 1).await;
    assert_eq!(msg.is_dc_message, MessengerMessage::Yes);
    assert_eq!(msg.text, "hello");
    assert_eq!(msg.param.get_int(Param::WantsMdn).unwrap(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_escaped_recipients() {
    let t = TestContext::new_alice().await;
    Contact::create(&t, "foobar", "foobar@example.com")
        .await
        .unwrap();

    let carl_contact_id = Contact::add_or_lookup(
        &t,
        "Carl",
        &ContactAddress::new("carl@host.tld").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap()
    .0;

    // We test with non-chat message here
    // because chat messages are not expected to have `Cc` header.
    receive_imf(
        &t,
        b"From: Foobar <foobar@example.com>\n\
                 To: =?UTF-8?B?0JjQvNGPLCDQpNCw0LzQuNC70LjRjw==?= alice@example.org\n\
                 Cc: =?utf-8?q?=3Ch2=3E?= <carl@host.tld>\n\
                 Subject: foo\n\
                 Message-ID: <asdklfjjaweofi@example.com>\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await
    .unwrap();
    let contact = Contact::get_by_id(&t, carl_contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "h2");

    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    let msg = Message::load_from_db(&t, chats.get_msg_id(0).unwrap().unwrap())
        .await
        .unwrap();
    assert_eq!(msg.is_dc_message, MessengerMessage::No);
    assert_eq!(msg.text, "foo – hello");
}

/// Tests that `Cc` header updates display name
/// if existing contact has low enough origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cc_to_contact() {
    let t = TestContext::new_alice().await;
    Contact::create(&t, "foobar", "foobar@example.com")
        .await
        .unwrap();

    let carl_contact_id = Contact::add_or_lookup(
        &t,
        "garabage",
        &ContactAddress::new("carl@host.tld").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await
    .unwrap()
    .0;

    // We use non-chat message here
    // because chat messages are not expected to have `Cc` header.
    receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: Foobar <foobar@example.com>\n\
                 To: alice@example.org\n\
                 Cc: Carl <carl@host.tld>\n\
                 Subject: foo\n\
                 Message-ID: <asdklfjjaweofi@example.com>\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await
    .unwrap();
    let contact = Contact::get_by_id(&t, carl_contact_id).await.unwrap();
    assert_eq!(contact.get_name(), "");
    assert_eq!(contact.get_display_name(), "Carl");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_tiscali() {
    test_parse_ndn(
            "alice@tiscali.it",
            "shenauithz@testrun.org",
            "Mr.un2NYERi1RM.lbQ5F9q-QyJ@tiscali.it",
            include_bytes!("../../test-data/message/tiscali_ndn.eml"),
            Some("Delivery status notification –       This is an automatically generated Delivery Status Notification.      \n\nDelivery to the following recipients was aborted after 2 second(s):\n\n  * shenauithz@testrun.org"),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_testrun() {
    test_parse_ndn(
            "alice@testrun.org",
            "hcksocnsofoejx@five.chat",
            "Mr.A7pTA5IgrUA.q4bP41vAJOp@testrun.org",
            include_bytes!("../../test-data/message/testrun_ndn.eml"),
            Some("Undelivered Mail Returned to Sender – This is the mail system at host hq5.merlinux.eu.\n\nI\'m sorry to have to inform you that your message could not\nbe delivered to one or more recipients. It\'s attached below.\n\nFor further assistance, please send mail to postmaster.\n\nIf you do so, please include this problem report. You can\ndelete your own text from the attached returned message.\n\n                   The mail system\n\n<hcksocnsofoejx@five.chat>: host mail.five.chat[195.62.125.103] said: 550 5.1.1\n    <hcksocnsofoejx@five.chat>: Recipient address rejected: User unknown in\n    virtual mailbox table (in reply to RCPT TO command)"),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_yahoo() {
    test_parse_ndn(
            "alice@yahoo.com",
            "haeclirth.sinoenrat@yahoo.com",
            "1680295672.3657931.1591783872936@mail.yahoo.com",
            include_bytes!("../../test-data/message/yahoo_ndn.eml"),
            Some("Failure Notice – Sorry, we were unable to deliver your message to the following address.\n\n<haeclirth.sinoenrat@yahoo.com>:\n554: delivery error: dd Not a valid recipient - atlas117.free.mail.ne1.yahoo.com [...]"),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_gmail() {
    test_parse_ndn(
            "alice@gmail.com",
            "assidhfaaspocwaeofi@gmail.com",
            "CABXKi8zruXJc_6e4Dr087H5wE7sLp+u250o0N2q5DdjF_r-8wg@mail.gmail.com",
            include_bytes!("../../test-data/message/gmail_ndn.eml"),
            Some("Delivery Status Notification (Failure) – ** Die Adresse wurde nicht gefunden **\n\nIhre Nachricht wurde nicht an assidhfaaspocwaeofi@gmail.com zugestellt, weil die Adresse nicht gefunden wurde oder keine E-Mails empfangen kann.\n\nHier erfahren Sie mehr: https://support.google.com/mail/?p=NoSuchUser\n\nAntwort:\n\n550 5.1.1 The email account that you tried to reach does not exist. Please try double-checking the recipient\'s email address for typos or unnecessary spaces. Learn more at https://support.google.com/mail/?p=NoSuchUser i18sor6261697wrs.38 - gsmtp"),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_gmx() {
    test_parse_ndn(
            "alice@gmx.com",
            "snaerituhaeirns@gmail.com",
            "9c9c2a32-056b-3592-c372-d7e8f0bd4bc2@gmx.de",
            include_bytes!("../../test-data/message/gmx_ndn.eml"),
            Some("Mail delivery failed: returning message to sender – This message was created automatically by mail delivery software.\n\nA message that you sent could not be delivered to one or more of\nits recipients. This is a permanent error. The following address(es)\nfailed:\n\nsnaerituhaeirns@gmail.com:\nSMTP error from remote server for RCPT TO command, host: gmail-smtp-in.l.google.com (66.102.1.27) reason: 550-5.1.1 The email account that you tried to reach does not exist. Please\n try\n550-5.1.1 double-checking the recipient\'s email address for typos or\n550-5.1.1 unnecessary spaces. Learn more at\n550 5.1.1  https://support.google.com/mail/?p=NoSuchUser f6si2517766wmc.21\n9 - gsmtp [...]"),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_posteo() {
    test_parse_ndn(
            "alice@posteo.org",
            "hanerthaertidiuea@gmx.de",
            "04422840-f884-3e37-5778-8192fe22d8e1@posteo.de",
            include_bytes!("../../test-data/message/posteo_ndn.eml"),
            Some("Undelivered Mail Returned to Sender – This is the mail system at host mout01.posteo.de.\n\nI\'m sorry to have to inform you that your message could not\nbe delivered to one or more recipients. It\'s attached below.\n\nFor further assistance, please send mail to postmaster.\n\nIf you do so, please include this problem report. You can\ndelete your own text from the attached returned message.\n\n                   The mail system\n\n<hanerthaertidiuea@gmx.de>: host mx01.emig.gmx.net[212.227.17.5] said: 550\n    Requested action not taken: mailbox unavailable (in reply to RCPT TO\n    command)"),
        )
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_testrun_2() {
    test_parse_ndn(
            "alice@example.org",
            "bob@example.org",
            "Mr.5xqflwt0YFv.IXDFfHauvWx@testrun.org",
            include_bytes!("../../test-data/message/testrun_ndn_2.eml"),
            Some("Undelivered Mail Returned to Sender – This is the mail system at host hq5.merlinux.eu.\n\nI'm sorry to have to inform you that your message could not\nbe delivered to one or more recipients. It's attached below.\n\nFor further assistance, please send mail to postmaster.\n\nIf you do so, please include this problem report. You can\ndelete your own text from the attached returned message.\n\n                   The mail system\n\n<bob@example.org>: Host or domain name not found. Name service error for\n    name=echedelyr.tk type=AAAA: Host not found"),
        )
        .await;
}

/// Tests that text part is not squashed into OpenPGP attachment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_with_attachment() {
    test_parse_ndn(
            "alice@example.org",
            "bob@example.net",
            "Mr.I6Da6dXcTel.TroC5J3uSDH@example.org",
            include_bytes!("../../test-data/message/ndn_with_attachment.eml"),
            Some("Undelivered Mail Returned to Sender – This is the mail system at host relay01.example.org.\n\nI'm sorry to have to inform you that your message could not\nbe delivered to one or more recipients. It's attached below.\n\nFor further assistance, please send mail to postmaster.\n\nIf you do so, please include this problem report. You can\ndelete your own text from the attached returned message.\n\n                   The mail system\n\n<bob@example.net>: host mx2.example.net[80.241.60.215] said: 552 5.2.2\n    <bob@example.net>: Recipient address rejected: Mailbox quota exceeded (in\n    reply to RCPT TO command)\n\n<bob2@example.net>: host mx1.example.net[80.241.60.212] said: 552 5.2.2\n    <bob2@example.net>: Recipient address rejected: Mailbox quota\n    exceeded (in reply to RCPT TO command)")
        )
        .await;
}

/// Test that DSN is not treated as NDN if Action: is not "failed"
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_dsn_relayed() {
    test_parse_ndn(
        "anon_1@posteo.de",
        "anon_2@gmx.at",
        "8b7b1a9d0c8cc588c7bcac47f5687634@posteo.de",
        include_bytes!("../../test-data/message/dsn_relayed.eml"),
        None,
    )
    .await;
}

// ndn = Non Delivery Notification
async fn test_parse_ndn(
    self_addr: &str,
    foreign_addr: &str,
    rfc724_mid_outgoing: &str,
    raw_ndn: &[u8],
    error_msg: Option<&str>,
) -> (TestContext, MsgId) {
    let t = TestContext::new().await;
    t.configure_addr(self_addr).await;

    receive_imf(
        &t,
        format!(
            "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                From: {self_addr}\n\
                To: {foreign_addr}\n\
                Subject: foo\n\
                Message-ID: <{rfc724_mid_outgoing}>\n\
                Chat-Version: 1.0\n\
                Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                \n\
                hello\n"
        )
        .as_bytes(),
        false,
    )
    .await
    .unwrap();

    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    let msg_id = chats.get_msg_id(0).unwrap().unwrap();

    // Check that the ndn would be downloaded:
    let headers = mailparse::parse_mail(raw_ndn).unwrap().headers;
    assert!(
        prefetch_should_download(&t, &headers, "some-other-message-id", std::iter::empty(),)
            .await
            .unwrap()
    );

    receive_imf(&t, raw_ndn, false).await.unwrap();
    let msg = Message::load_from_db(&t, msg_id).await.unwrap();

    assert_eq!(
        msg.state,
        if error_msg.is_some() {
            MessageState::OutFailed
        } else {
            MessageState::OutDelivered
        }
    );

    assert_eq!(msg.error(), error_msg.map(|error| error.to_string()));
    (t, msg_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_after_ndn() -> Result<()> {
    let (t, msg_id) = test_parse_ndn(
            "alice@testrun.org",
            "hcksocnsofoejx@five.chat",
            "Mr.A7pTA5IgrUA.q4bP41vAJOp@testrun.org",
            include_bytes!("../../test-data/message/testrun_ndn.eml"),
            Some("Undelivered Mail Returned to Sender – This is the mail system at host hq5.merlinux.eu.\n\nI\'m sorry to have to inform you that your message could not\nbe delivered to one or more recipients. It\'s attached below.\n\nFor further assistance, please send mail to postmaster.\n\nIf you do so, please include this problem report. You can\ndelete your own text from the attached returned message.\n\n                   The mail system\n\n<hcksocnsofoejx@five.chat>: host mail.five.chat[195.62.125.103] said: 550 5.1.1\n    <hcksocnsofoejx@five.chat>: Recipient address rejected: User unknown in\n    virtual mailbox table (in reply to RCPT TO command)"),
        )
        .await;
    chat::resend_msgs(&t, &[msg_id]).await?;
    let msg = Message::load_from_db(&t, msg_id).await?;
    assert_eq!(msg.state, MessageState::OutPending);
    assert_eq!(msg.error(), None);
    // Alice receives a BCC-self copy of their message.
    receive_imf(
        &t,
        "To: hcksocnsofoejx@five.chat\n\
        From: alice@testrun.org\n\
        Date: Today, 2 January 2024 00:00:00 -300\n\
        Message-ID: Mr.A7pTA5IgrUA.q4bP41vAJOp@testrun.org\n\
        \n\
        hi"
        .as_bytes(),
        false,
    )
    .await?;
    let msg = t.get_last_msg().await;
    assert_eq!(msg.state, MessageState::OutDelivered);
    assert_eq!(msg.error(), None);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_ndn_group_msg() -> Result<()> {
    let t = TestContext::new().await;
    t.configure_addr("alice@gmail.com").await;

    receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: alice@gmail.com\n\
                 To: bob@example.com, assidhfaaspocwaeofi@gmail.com\n\
                 Subject: foo\n\
                 Message-ID: <CADWx9Cs32Wa7Gy-gM0bvbq54P_FEHe7UcsAV=yW7sVVW=fiMYQ@mail.gmail.com>\n\
                 Chat-Version: 1.0\n\
                 Chat-Group-ID: abcde\n\
                 Chat-Group-Name: foo\n\
                 Chat-Disposition-Notification-To: alice@example.org\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await?;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    let msg_id = chats.get_msg_id(0)?.unwrap();

    let raw = include_bytes!("../../test-data/message/gmail_ndn_group.eml");
    receive_imf(&t, raw, false).await?;

    let msg = Message::load_from_db(&t, msg_id).await?;

    assert_eq!(msg.state, MessageState::OutFailed);

    let msgs = chat::get_chat_msgs(&t, msg.chat_id).await?;
    let ChatItem::Message { msg_id } = *msgs.last().unwrap() else {
        panic!("Wrong item type");
    };
    assert_eq!(msg_id, msg.id);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concat_multiple_ndns() -> Result<()> {
    let t = TestContext::new().await;
    t.configure_addr("alice@posteo.org").await;
    let mid = "1234@mail.gmail.com";
    receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: alice@posteo.org\n\
                 To: hanerthaertidiuea@gmx.de\n\
                 Subject: foo\n\
                 Message-ID: <1234@mail.gmail.com>\n\
                 Chat-Version: 1.0\n\
                 Chat-Disposition-Notification-To: alice@example.org\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await?;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    let msg_id = chats.get_msg_id(0)?.unwrap();

    let raw = include_str!("../../test-data/message/posteo_ndn.eml");
    let raw = raw.replace(
        "Message-ID: <04422840-f884-3e37-5778-8192fe22d8e1@posteo.de>",
        &format!("Message-ID: <{mid}>"),
    );
    receive_imf(&t, raw.as_bytes(), false).await?;

    let msg = Message::load_from_db(&t, msg_id).await?;

    let err = "Undelivered Mail Returned to Sender – This is the mail system at host mout01.posteo.de.\n\nI'm sorry to have to inform you that your message could not\nbe delivered to one or more recipients. It's attached below.\n\nFor further assistance, please send mail to postmaster.\n\nIf you do so, please include this problem report. You can\ndelete your own text from the attached returned message.\n\n                   The mail system\n\n<hanerthaertidiuea@gmx.de>: host mx01.emig.gmx.net[212.227.17.5] said: 550\n    Requested action not taken: mailbox unavailable (in reply to RCPT TO\n    command)".to_string();
    assert_eq!(msg.error(), Some(err.clone()));
    assert_eq!(msg.state, MessageState::OutFailed);

    let raw = raw.replace(
        "Message-Id: <20200609184422.DCB6B1200DD@mout01.posteo.de>",
        "Message-Id: <next@mout01.posteo.de>",
    );
    receive_imf(&t, raw.as_bytes(), false).await?;
    let msg = Message::load_from_db(&t, msg_id).await?;

    assert_eq!(msg.error(), Some([err.clone(), err].join("\n\n")));
    Ok(())
}

async fn load_imf_email(context: &Context, imf_raw: &[u8]) -> Message {
    context
        .set_config(Config::ShowEmails, Some("2"))
        .await
        .unwrap();
    receive_imf(context, imf_raw, false).await.unwrap();
    let chats = Chatlist::try_load(context, 0, None, None).await.unwrap();
    let msg_id = chats.get_msg_id(0).unwrap().unwrap();
    Message::load_from_db(context, msg_id).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_html_only_mail() {
    let t = TestContext::new_alice().await;
    let msg = load_imf_email(&t, include_bytes!("../../test-data/message/wrong-html.eml")).await;
    assert_eq!(
        msg.text,
        "Guten Abend,\n\nLots of text\n\ntext with Umlaut ä...\n\nMfG\n\n--------------------------------------\n\n[Camping ](https://example.com/)\n\nsomeaddress\n\nsometown"
    );
}

static GH_MAILINGLIST: &[u8] =
    b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
    From: Max Mustermann <notifications@github.com>\n\
    To: deltachat/deltachat-core-rust <deltachat-core-rust@noreply.github.com>\n\
    Subject: Let's put some [brackets here that] have nothing to do with the topic\n\
    Message-ID: <3333@example.org>\n\
    List-ID: deltachat/deltachat-core-rust <deltachat-core-rust.deltachat.github.com>\n\
    List-Post: <mailto:reply+ELERNSHSETUSHOYSESHETIHSEUSAFERUHSEDTISNEU@reply.github.com>\n\
    Precedence: list\n\
    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
    \n\
    hello\n";

static GH_MAILINGLIST2: &str = "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
    From: Github <notifications@github.com>\n\
    To: deltachat/deltachat-core-rust <deltachat-core-rust@noreply.github.com>\n\
    Subject: [deltachat/deltachat-core-rust] PR run failed\n\
    Message-ID: <3334@example.org>\n\
    List-ID: deltachat/deltachat-core-rust <deltachat-core-rust.deltachat.github.com>\n\
    List-Post: <mailto:reply+EGELITBABIHXSITUZIEPAKYONASITEPUANERGRUSHE@reply.github.com>\n\
    Precedence: list\n\
    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
    \n\
    hello back\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_github_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(&t.ctx, GH_MAILINGLIST, false).await?;

    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await?;
    assert_eq!(chats.len(), 1);

    let chat_id = chats.get_chat_id(0).unwrap();
    chat_id.accept(&t).await.unwrap();
    let chat = chat::Chat::load_from_db(&t.ctx, chat_id).await?;

    assert!(chat.is_mailing_list());
    assert!(chat.can_send(&t.ctx).await?);
    assert_eq!(
        chat.get_mailinglist_addr(),
        Some("reply+elernshsetushoyseshetihseusaferuhsedtisneu@reply.github.com")
    );
    assert_eq!(chat.name, "deltachat/deltachat-core-rust");
    assert_eq!(chat::get_chat_contacts(&t.ctx, chat_id).await?.len(), 1);

    receive_imf(&t.ctx, GH_MAILINGLIST2.as_bytes(), false).await?;

    let chat = chat::Chat::load_from_db(&t.ctx, chat_id).await?;
    assert!(!chat.can_send(&t.ctx).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let chats = Chatlist::try_load(&t.ctx, DC_GCL_FOR_FORWARDING, None, None).await?;
    assert_eq!(chats.len(), 0);
    let contacts = Contact::get_all(&t.ctx, 0, None).await?;
    assert_eq!(contacts.len(), 0); // mailing list recipients and senders do not count as "known contacts"

    let msg1 = get_chat_msg(&t, chat_id, 0, 2).await;
    let contact1 = Contact::get_by_id(&t.ctx, msg1.from_id).await?;
    assert_eq!(contact1.get_addr(), "notifications@github.com");
    assert_eq!(contact1.get_display_name(), "notifications@github.com"); // Make sure this is not "Max Mustermann" or somethinng

    let msg2 = get_chat_msg(&t, chat_id, 1, 2).await;
    let contact2 = Contact::get_by_id(&t.ctx, msg2.from_id).await?;
    assert_eq!(contact2.get_addr(), "notifications@github.com");

    assert_eq!(msg1.get_override_sender_name().unwrap(), "Max Mustermann");
    assert_eq!(msg2.get_override_sender_name().unwrap(), "Github");
    Ok(())
}

static DC_MAILINGLIST: &[u8] = b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
    From: Bob <bob@posteo.org>\n\
    To: delta@codespeak.net\n\
    Subject: Re: [delta-dev] What's up?\n\
    Message-ID: <38942@posteo.org>\n\
    List-ID: \"discussions about and around https://delta.chat developments\" <delta.codespeak.net>\n\
    List-Post: <mailto:delta@codespeak.net>\n\
    Precedence: list\n\
    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
    \n\
    body\n";

static DC_MAILINGLIST2: &[u8] = b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
    From: Charlie <charlie@posteo.org>\n\
    To: delta@codespeak.net\n\
    Subject: Re: [delta-dev] DC is nice!\n\
    Message-ID: <38943@posteo.org>\n\
    List-ID: \"discussions about and around https://delta.chat developments\" <delta.codespeak.net>\n\
    List-Post: <mailto:delta@codespeak.net>\n\
    Precedence: list\n\
    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
    \n\
    body 4\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_classic_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;
    receive_imf(&t.ctx, DC_MAILINGLIST, false).await.unwrap();
    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    let chat_id = chats.get_chat_id(0).unwrap();
    chat_id.accept(&t).await.unwrap();
    let chat = Chat::load_from_db(&t.ctx, chat_id).await.unwrap();
    assert_eq!(chat.name, "delta-dev");
    assert!(chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), Some("delta@codespeak.net"));

    let msg = get_chat_msg(&t, chat_id, 0, 1).await;
    let contact1 = Contact::get_by_id(&t.ctx, msg.from_id).await.unwrap();
    assert_eq!(contact1.get_addr(), "bob@posteo.org");

    let sent = t.send_text(chat.id, "Hello mailinglist!").await;
    let mime = sent.payload();

    println!("Sent mime message is:\n\n{mime}\n\n");
    assert!(mime.contains("Content-Type: text/plain; charset=\"utf-8\"\r\n"));
    assert!(mime.contains("Subject: Re: [delta-dev] What's up?\r\n"));
    assert!(mime.contains("MIME-Version: 1.0\r\n"));
    assert!(mime.contains("In-Reply-To: <38942@posteo.org>\r\n"));
    assert!(mime.contains("Chat-Version: 1.0\r\n"));
    assert!(mime.contains("To: <delta@codespeak.net>\r\n"));
    assert!(mime.contains("From: <alice@example.org>\r\n"));
    assert!(mime.contains(
        "\r\n\
\r\n\
Hello mailinglist!\r\n"
    ));

    receive_imf(&t.ctx, DC_MAILINGLIST2, false).await?;

    let chat = chat::Chat::load_from_db(&t.ctx, chat_id).await?;
    assert!(chat.can_send(&t.ctx).await?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_other_device_writes_to_mailinglist() -> Result<()> {
    let t = TestContext::new_alice().await;
    receive_imf(&t, DC_MAILINGLIST, false).await.unwrap();
    let first_msg = t.get_last_msg().await;
    let first_chat = Chat::load_from_db(&t, first_msg.chat_id).await?;
    assert_eq!(
        first_chat.param.get(Param::ListPost).unwrap(),
        "delta@codespeak.net"
    );

    let list_post_contact_id =
        Contact::lookup_id_by_addr(&t, "delta@codespeak.net", Origin::Unknown)
            .await?
            .unwrap();
    let list_post_contact = Contact::get_by_id(&t, list_post_contact_id).await?;
    assert_eq!(list_post_contact.is_key_contact(), false);
    assert_eq!(
        list_post_contact.param.get(Param::ListId).unwrap(),
        "delta.codespeak.net"
    );
    assert_eq!(
        chat::get_chat_id_by_grpid(&t, "delta.codespeak.net")
            .await?
            .unwrap(),
        (first_chat.id, false, Blocked::Request)
    );

    receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
            From: Alice <alice@example.org>\n\
            To: delta@codespeak.net\n\
            Subject: [delta-dev] Subject\n\
            Message-ID: <0476@example.org>\n\
            Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
            \n\
            body 4\n",
        false,
    )
    .await
    .unwrap();

    let second_msg = t.get_last_msg().await;

    assert_eq!(first_msg.chat_id, second_msg.chat_id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_block_mailing_list() {
    let t = TestContext::new_alice().await;

    receive_imf(&t.ctx, DC_MAILINGLIST, false).await.unwrap();
    t.evtracker.wait_next_incoming_message().await;
    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0).unwrap();
    let chat = Chat::load_from_db(&t.ctx, chat_id).await.unwrap();
    assert!(chat.is_contact_request());

    // Block the contact request.
    chat_id.block(&t).await.unwrap();

    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0); // Test that the message disappeared

    receive_imf(&t.ctx, DC_MAILINGLIST2, false).await.unwrap();

    // Check that no notification is displayed for blocked mailing list message.
    while let Ok(event) = t.evtracker.try_recv() {
        assert!(!matches!(event.typ, EventType::IncomingMsg { .. }));
    }

    // Test that the mailing list stays disappeared
    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0); // Test that the message is not shown

    // Both messages are in the same blocked chat.
    let msgs = chat::get_chat_msgs(&t.ctx, chat_id).await.unwrap();
    assert_eq!(msgs.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_decide_block_then_unblock() {
    let t = TestContext::new_alice().await;

    receive_imf(&t, DC_MAILINGLIST, false).await.unwrap();
    let blocked = Contact::get_all_blocked(&t).await.unwrap();
    assert_eq!(blocked.len(), 0);

    // Block the contact request, this should add one blocked contact.
    let msg = t.get_last_msg().await;
    msg.chat_id.block(&t).await.unwrap();

    let blocked = Contact::get_all_blocked(&t).await.unwrap();
    assert_eq!(blocked.len(), 1);
    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0); // Test that the message is not shown

    // Unblock contact and check if the next message arrives in a chat
    Contact::unblock(&t, *blocked.first().unwrap())
        .await
        .unwrap();
    let blocked = Contact::get_all_blocked(&t).await.unwrap();
    assert_eq!(blocked.len(), 0);

    receive_imf(&t.ctx, DC_MAILINGLIST2, false).await.unwrap();
    let msg = t.get_last_msg().await;
    let msgs = chat::get_chat_msgs(&t, msg.chat_id).await.unwrap();
    assert_eq!(msgs.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_decide_not_now() {
    let t = TestContext::new_alice().await;

    receive_imf(&t.ctx, DC_MAILINGLIST, false).await.unwrap();

    let msg = t.get_last_msg().await;
    let chat_id = msg.get_chat_id();

    // Open the chat and go back
    chat::marknoticed_chat(&t.ctx, chat_id).await.unwrap();

    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1); // Test that chat is still in the chatlist
    let msgs = chat::get_chat_msgs(&t.ctx, chat_id).await.unwrap();
    assert_eq!(msgs.len(), 1); // ...and contains 1 message

    receive_imf(&t.ctx, DC_MAILINGLIST2, false).await.unwrap();

    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1); // Test that the new mailing list message got into the same chat
    let msgs = chat::get_chat_msgs(&t.ctx, chat_id).await.unwrap();
    assert_eq!(msgs.len(), 2);
    let chat = Chat::load_from_db(&t.ctx, chat_id).await.unwrap();
    assert!(chat.is_contact_request());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_decide_accept() {
    let t = TestContext::new_alice().await;

    receive_imf(&t.ctx, DC_MAILINGLIST, false).await.unwrap();

    let msg = t.get_last_msg().await;
    let chat_id = msg.get_chat_id();
    chat_id.accept(&t).await.unwrap();

    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1); // Test that the message is shown
    assert!(!chat_id.is_special());

    receive_imf(&t.ctx, DC_MAILINGLIST2, false).await.unwrap();

    let msgs = chat::get_chat_msgs(&t.ctx, chat_id).await.unwrap();
    assert_eq!(msgs.len(), 2);
    let chat = chat::Chat::load_from_db(&t.ctx, chat_id).await.unwrap();
    assert!(chat.can_send(&t.ctx).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_multiple_names_in_subject() -> Result<()> {
    let t = TestContext::new_alice().await;
    receive_imf(
        &t,
        b"From: Foo Bar <foo@bar.org>\n\
    To: deltachat/deltachat-core-rust <deltachat-core-rust@noreply.github.com>\n\
    Subject: [ola list] [foo][bar]  just a subject\n\
    Message-ID: <3333@example.org>\n\
    List-ID: \"looong description of 'ola list', with foo, bar\" <delta.codespeak.net>\n\
    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
    \n\
    hello\n",
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    let chat_id = msg.get_chat_id();
    let chat = Chat::load_from_db(&t, chat_id).await?;
    assert_eq!(chat.name, "ola list [foo][bar]");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_majordomo_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    // test mailing lists not having a `ListId:`-header
    receive_imf(
        &t,
        b"From: Foo Bar <foo@bar.org>\n\
    To: deltachat/deltachat-core-rust <deltachat-core-rust@noreply.github.com>\n\
    Subject: [ola] just a subject\n\
    Message-ID: <3333@example.org>\n\
    Sender: My list <mylist@bar.org>\n\
    Precedence: list\n\
    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
    \n\
    hello\n",
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    let chat_id = msg.get_chat_id();
    let chat = Chat::load_from_db(&t, chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.grpid, "mylist@bar.org");
    assert_eq!(chat.name, "ola");
    assert_eq!(chat::get_chat_msgs(&t, chat.id).await.unwrap().len(), 1);
    assert!(!chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    // receive another message with no sender name but the same address,
    // make sure this lands in the same chat
    receive_imf(
        &t,
        b"From: Nu Bar <nu@bar.org>\n\
    To: deltachat/deltachat-core-rust <deltachat-core-rust@noreply.github.com>\n\
    Subject: [ola] Re: just a subject\n\
    Message-ID: <4444@example.org>\n\
    Sender: mylist@bar.org\n\
    Precedence: list\n\
    Date: Sun, 22 Mar 2020 23:37:57 +0000\n\
    \n\
    hello\n",
        false,
    )
    .await
    .unwrap();
    assert_eq!(chat::get_chat_msgs(&t, chat.id).await.unwrap().len(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailchimp_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
            &t,
            b"To: alice <alice@example.org>\n\
            Subject: =?utf-8?Q?How=20early=20megacities=20emerged=20from=20Cambodia=E2=80=99s=20jungles?=\n\
            From: =?utf-8?Q?Atlas=20Obscura?= <info@atlasobscura.com>\n\
            List-ID: 399fc0402f1b154b67965632emc list <399fc0402f1b154b67965632e.100761.list-id.mcsv.net>\n\
            Message-ID: <555@example.org>\n\
            Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
            \n\
            hello\n",
            false,
        )
        .await
        .unwrap();
    let msg = t.get_last_msg().await;
    let chat = Chat::load_from_db(&t, msg.chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.blocked, Blocked::Request);
    assert_eq!(
        chat.grpid,
        "399fc0402f1b154b67965632e.100761.list-id.mcsv.net"
    );
    assert_eq!(chat.name, "Atlas Obscura");
    assert!(!chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dhl_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_dhl.eml"),
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    assert_eq!(msg.text, "Ihr Paket ist in der Packstation 123 – bla bla");
    assert!(msg.has_html());
    let chat = Chat::load_from_db(&t, msg.chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.blocked, Blocked::Request);
    assert_eq!(chat.grpid, "1234ABCD-123LMNO.mailing.dhl.de");
    assert_eq!(chat.name, "DHL Paket");
    assert!(!chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dpd_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_dpd.eml"),
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    assert_eq!(msg.text, "Bald ist Ihr DPD Paket da – bla bla");
    assert!(msg.has_html());
    let chat = Chat::load_from_db(&t, msg.chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.blocked, Blocked::Request);
    assert_eq!(chat.grpid, "dpdde.mxmail.service.dpd.de");
    assert_eq!(chat.name, "DPD");
    assert!(!chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_xt_local_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_xt_local_microsoft.eml"),
        false,
    )
    .await?;
    let chat = Chat::load_from_db(&t, t.get_last_msg().await.chat_id).await?;
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.grpid, "96540.xt.local");
    assert_eq!(chat.name, "Microsoft Store");
    assert!(!chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_xt_local_spiegel.eml"),
        false,
    )
    .await?;
    let chat = Chat::load_from_db(&t, t.get_last_msg().await.chat_id).await?;
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.grpid, "121231234.xt.local");
    assert_eq!(chat.name, "DER SPIEGEL Kundenservice");
    assert!(!chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_xing_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_xing.eml"),
        false,
    )
    .await?;
    let msg = t.get_last_msg().await;
    assert_eq!(msg.subject, "Kennst Du Dr. Mabuse?");
    let chat = Chat::load_from_db(&t, msg.chat_id).await?;
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.grpid, "51231231231231231231231232869f58.xing.com");
    assert_eq!(chat.name, "xing.com");
    assert!(!chat.can_send(&t).await?);
    assert_eq!(chat.get_mailinglist_addr(), None);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ttline_mailing_list() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_ttline.eml"),
        false,
    )
    .await?;
    let msg = t.get_last_msg().await;
    assert_eq!(msg.subject, "Unsere Sommerangebote an Bord ⚓");
    let chat = Chat::load_from_db(&t, msg.chat_id).await?;
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.grpid, "39123123-1BBQXPY.t.ttline.com");
    assert_eq!(chat.name, "TT-Line - Die Schwedenfähren");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_with_mimepart_footer() {
    let t = TestContext::new_alice().await;

    // the mailing list message contains two top-level texts.
    // the second text is a footer that is added by some mailing list software
    // if the user-edited text contains html.
    // this footer should not become a text-message in delta chat
    // (otherwise every second mail might be the same footer)
    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_with_mimepart_footer.eml"),
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    assert_eq!(msg.text, "[Intern] important stuff – Hi mr ... [text part]");
    assert!(msg.has_html());
    let chat = Chat::load_from_db(&t, msg.chat_id).await.unwrap();
    assert_eq!(get_chat_msgs(&t, msg.chat_id).await.unwrap().len(), 1);
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.blocked, Blocked::Request);
    assert_eq!(chat.grpid, "intern.lists.abc.de");
    assert_eq!(chat.name, "Intern");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_with_mimepart_footer_signed() {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_with_mimepart_footer_signed.eml"),
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    assert_eq!(get_chat_msgs(&t, msg.chat_id).await.unwrap().len(), 1);
    let text = msg.text.clone();
    assert!(text.contains("content text"));
    assert!(!text.contains("footer text"));
    assert!(msg.has_html());
    let html = msg.get_id().get_html(&t).await.unwrap().unwrap();
    assert!(html.contains("content text"));
    assert!(!html.contains("footer text"));
}

/// Test that the changes from apply_mailinglist_changes() are also applied
/// if the message is a reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_apply_mailinglist_changes_assigned_by_reply() {
    let t = TestContext::new_alice().await;

    receive_imf(&t, GH_MAILINGLIST, false).await.unwrap();

    let chat_id = t.get_last_msg().await.chat_id;
    chat_id.accept(&t).await.unwrap();
    let chat = Chat::load_from_db(&t, chat_id).await.unwrap();
    assert!(chat.can_send(&t).await.unwrap());

    let imf_raw = format!("In-Reply-To: 3333@example.org\n{GH_MAILINGLIST2}");
    receive_imf(&t, imf_raw.as_bytes(), false).await.unwrap();

    assert_eq!(
        t.get_last_msg().await.in_reply_to.unwrap(),
        "3333@example.org"
    );

    let chat = Chat::load_from_db(&t, chat_id).await.unwrap();
    assert!(!chat.can_send(&t).await.unwrap());

    let contact_id = Contact::lookup_id_by_addr(
        &t,
        "reply+EGELITBABIHXSITUZIEPAKYONASITEPUANERGRUSHE@reply.github.com",
        Origin::Hidden,
    )
    .await
    .unwrap()
    .unwrap();
    let contact = Contact::get_by_id(&t, contact_id).await.unwrap();
    assert_eq!(contact.is_key_contact(), false);
    assert_eq!(
        contact.param.get(Param::ListId).unwrap(),
        "deltachat-core-rust.deltachat.github.com"
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_chat_message() {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_chat_message.eml"),
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    assert_eq!(msg.text, "hello, this is a test 👋\n\n_______________________________________________\nTest1 mailing list -- test1@example.net\nTo unsubscribe send an email to test1-leave@example.net".to_string());
    assert!(!msg.has_html());
    let chat = Chat::load_from_db(&t, msg.chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Mailinglist);
    assert_eq!(chat.blocked, Blocked::Request);
    assert_eq!(chat.grpid, "test1.example.net");
    assert_eq!(chat.name, "Test1");
}

/// Tests that bots automatically accept mailing lists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailing_list_bot() {
    let t = TestContext::new_alice().await;
    t.set_config(Config::Bot, Some("1")).await.unwrap();

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/mailinglist_chat_message.eml"),
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    let chat = Chat::load_from_db(&t, msg.chat_id).await.unwrap();
    assert_eq!(chat.blocked, Blocked::Not);

    // Bot should see the message as fresh and process it.
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_show_tokens_in_contacts_list() {
    check_dont_show_in_contacts_list(
        "reply+OGHVYCLVBEGATYBICAXBIRQATABUOTUCERABERAHNO@reply.github.com",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_show_noreply_in_contacts_list() {
    check_dont_show_in_contacts_list("noreply@github.com").await;
}

async fn check_dont_show_in_contacts_list(addr: &str) {
    let t = TestContext::new_alice().await;
    receive_imf(
        &t,
        format!(
            "Subject: Re: [deltachat/deltachat-core-rust] DC is the best repo on GitHub!
To: {addr}
References: <deltachat/deltachat-core-rust/pull/1625@github.com>
 <deltachat/deltachat-core-rust/pull/1625/c644661857@github.com>
From: alice@example.org
Message-ID: <d2717387-0ba7-7b60-9b09-fd89a76ea8a0@gmx.de>
Date: Tue, 16 Jun 2020 12:04:20 +0200
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

YEAAAAAA!.
"
        )
        .as_bytes(),
        false,
    )
    .await
    .unwrap();
    let contacts = Contact::get_all(&t, 0, None as Option<&str>).await.unwrap();
    assert!(contacts.is_empty()); // The contact should not have been added to the db
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pdf_filename_simple() {
    let t = TestContext::new_alice().await;
    let msg = load_imf_email(
        &t,
        include_bytes!("../../test-data/message/pdf_filename_simple.eml"),
    )
    .await;
    assert_eq!(msg.viewtype, Viewtype::File);
    assert_eq!(msg.text, "mail body");
    let file_path = msg.param.get(Param::File).unwrap();
    assert_eq!(
        file_path,
        // That's the blake3 hash of the file content:
        "$BLOBDIR/24a6af459cec5d733374aeaa19a6133.pdf"
    );
    assert_eq!(msg.param.get(Param::Filename).unwrap(), "simple.pdf");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pdf_filename_continuation() {
    // test filenames split across multiple header lines, see rfc 2231
    let t = TestContext::new_alice().await;
    let msg = load_imf_email(
        &t,
        include_bytes!("../../test-data/message/pdf_filename_continuation.eml"),
    )
    .await;
    assert_eq!(msg.viewtype, Viewtype::File);
    assert_eq!(msg.text, "mail body");
    let file_path = msg.param.get(Param::File).unwrap();
    assert!(file_path.starts_with("$BLOBDIR/"));
    assert_eq!(msg.get_filename().unwrap(), "test pdf äöüß.pdf");
}

/// HTML-images may come with many embedded images, eg. tiny icons, corners for formatting,
/// twitter/facebook/whatever logos and so on.
/// that may easily be 50 and more images, one would not have these images in a chat.
///
/// fortunately, if we remove them, they are accessible by get_msg_html() now.
///
/// unfortunately, these images are not that easy to detect as they may also be on purpose,
/// or mua may use multipart/related not correctly -
/// so this test is in competition with parse_thunderbird_html_embedded_image()
/// that wants the image to be kept in the chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_many_images() {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/many_images_amazon_via_apple_mail.eml"),
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    assert_eq!(msg.viewtype, Viewtype::Image);
    assert!(msg.has_html());
    let chat = Chat::load_from_db(&t, msg.chat_id).await.unwrap();
    assert_eq!(get_chat_msgs(&t, chat.id).await.unwrap().len(), 1);
}

/// Test that classical MUA messages are assigned to group chats based on the `In-Reply-To`
/// header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_in_reply_to() {
    let t = TestContext::new().await;
    t.configure_addr("bob@example.com").await;

    // Receive message from Alice about group "foo".
    receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: alice@example.org\n\
                 To: bob@example.com, charlie@example.net\n\
                 Subject: foo\n\
                 Message-ID: <message@example.org>\n\
                 Chat-Version: 1.0\n\
                 Chat-Group-ID: foo\n\
                 Chat-Group-Name: foo\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello foo\n",
        false,
    )
    .await
    .unwrap();

    // Receive reply from Charlie without group ID but with In-Reply-To header.
    receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: charlie@example.net\n\
                 To: alice@example.org, bob@example.com\n\
                 Subject: Re: foo\n\
                 Message-ID: <message@example.net>\n\
                 In-Reply-To: <message@example.org>\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 reply foo\n",
        false,
    )
    .await
    .unwrap();

    let msg = t.get_last_msg().await;
    assert_eq!(msg.get_text(), "reply foo");

    // Load the first message from the same chat.
    let msgs = chat::get_chat_msgs(&t, msg.chat_id).await.unwrap();
    let msg_id = if let ChatItem::Message { msg_id } = msgs.first().unwrap() {
        msg_id
    } else {
        panic!("Wrong item type");
    };

    let reply_msg = Message::load_from_db(&t, *msg_id).await.unwrap();
    assert_eq!(reply_msg.get_text(), "hello foo");

    // Check that reply got into the same chat as the original message.
    assert_eq!(msg.chat_id, reply_msg.chat_id);

    // Make sure we looked at real chat ID and do not just
    // test that both messages got into the same virtual chat.
    assert!(!msg.chat_id.is_special());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_save_mime_headers_off() -> anyhow::Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let chat_alice = alice.create_chat(&bob).await;
    chat::send_text_msg(&alice, chat_alice.id, "hi!".to_string()).await?;

    let msg = bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert_eq!(msg.get_text(), "hi!");
    let mime = message::get_mime_headers(&bob, msg.id).await?;
    assert!(mime.is_empty());
    Ok(())
}

async fn check_alias_reply(from_dc: bool, chat_request: bool, group_request: bool) {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;

    // Claire, a customer, sends a support request
    // to the alias address <support@example.org>.
    // If `chat_request` is true, Claire is using Delta Chat,
    // otherwise Claire sends the request from a classic MUA.
    // The alias expands to the supporters Alice and Bob.
    let claire_request = if group_request {
        format!(
            "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
             To: support@example.org, ceo@example.org\n\
             From: claire@example.org\n\
             Subject: i have a question\n\
             Message-ID: <non-dc-1@example.org>\n\
             {}\
             Date: Sun, 14 Mar 2021 17:04:36 +0100\n\
             Content-Type: text/plain\n\
             \n\
             hi support! what is the current version?",
            if chat_request {
                "Chat-Version: 1.0\n\
                 Chat-Group-ID: 8ud29aridt29arid\n\
                 Chat-Group-Name: =?utf-8?q?i_have_a_question?=\n"
            } else {
                ""
            }
        )
    } else {
        format!(
            "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
             To: support@example.org\n\
             From: claire@example.org\n\
             Subject: i have a question\n\
             Message-ID: <non-dc-1@example.org>\n\
             {}\
             Date: Sun, 14 Mar 2021 17:04:36 +0100\n\
             Content-Type: text/plain\n\
             \n\
             hi support! what is the current version?",
            if chat_request {
                "Chat-Version: 1.0\n"
            } else {
                ""
            }
        )
    };

    receive_imf(&alice, claire_request.as_bytes(), false)
        .await
        .unwrap();

    // Check that Alice receives the message in a group chat.
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.get_subject(), "i have a question");
    assert!(msg.get_text().contains("hi support!"));
    let chat = Chat::load_from_db(&alice, msg.chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Group);
    assert_eq!(get_chat_msgs(&alice, chat.id).await.unwrap().len(), 1);
    if group_request {
        assert_eq!(get_chat_contacts(&alice, chat.id).await.unwrap().len(), 4);
    } else {
        assert_eq!(get_chat_contacts(&alice, chat.id).await.unwrap().len(), 3);
    }
    assert_eq!(msg.get_override_sender_name(), None);

    let claire = tcm.unconfigured().await;
    claire.configure_addr("claire@example.org").await;
    receive_imf(&claire, claire_request.as_bytes(), false)
        .await
        .unwrap();

    let (msg_id, _) = rfc724_mid_exists(&claire, "non-dc-1@example.org")
        .await
        .unwrap()
        .unwrap();

    let msg = Message::load_from_db(&claire, msg_id).await.unwrap();
    msg.chat_id.accept(&claire).await.unwrap();
    assert_eq!(msg.get_subject(), "i have a question");
    assert!(msg.get_text().contains("hi support!"));
    let chat = Chat::load_from_db(&claire, msg.chat_id).await.unwrap();
    if group_request {
        assert_eq!(chat.typ, Chattype::Group);
    } else {
        assert_eq!(chat.typ, Chattype::Single);
    }
    assert_eq!(get_chat_msgs(&claire, chat.id).await.unwrap().len(), 1);
    assert_eq!(msg.get_override_sender_name(), None);

    let reply = if from_dc {
        // Bob, the other supporter, answers with Delta Chat.
        format!(
            "To: support@example.org, claire@example.org\n\
          From: bob@example.net\n\
          Subject: =?utf-8?q?Re=3A_i_have_a_question?=\n\
          References: <bobreply@localhost>\n\
          In-Reply-To: <non-dc-1@example.org>\n\
          Message-ID: <bobreply@localhost>\n\
          Date: Sun, 14 Mar 2021 16:04:57 +0000\n\
          Chat-Version: 1.0\n\
          {}\
          Chat-Group-Name: =?utf-8?q?i_have_a_question?=\n\
          Chat-Disposition-Notification-To: bob@example.net\n\
          Content-Type: text/plain\n\
          \n\
          hi claire, the version is 1.0, cheers bob",
            if group_request && chat_request {
                "Chat-Group-ID: 8ud29aridt29arid\n"
            } else {
                // Ad-hoc group has no ID.
                ""
            }
        )
    } else {
        // Bob, the other supporter, answers with a classic MUA.
        "To: support@example.org, claire@example.org\n\
         From: bob@example.net\n\
         Subject: =?utf-8?q?Re=3A_i_have_a_question?=\n\
         References: <non-dc-1@example.org>\n\
         In-Reply-To: <non-dc-1@example.org>\n\
         Message-ID: <non-dc-2@example.net>\n\
         Date: Sun, 14 Mar 2021 16:04:57 +0000\n\
         Content-Type: text/plain\n\
         \n\
         hi claire, the version is 1.0, cheers bob"
            .to_string()
    };

    // Check that Alice gets the message in the same chat.
    let request = alice.get_last_msg().await;
    receive_imf(&alice, reply.as_bytes(), false).await.unwrap();
    let answer = alice.get_last_msg().await;
    assert_eq!(answer.get_subject(), "Re: i have a question");
    assert!(answer.get_text().contains("the version is 1.0"));
    assert_eq!(answer.chat_id, request.chat_id);
    let chat_contacts = get_chat_contacts(&alice, answer.chat_id)
        .await
        .unwrap()
        .len();
    if group_request {
        // Claire, Support, CEO and Alice (Bob is not added)
        assert_eq!(chat_contacts, 4);
    } else {
        // Claire, Support and Alice
        assert_eq!(chat_contacts, 3);
    }
    assert_eq!(
        answer.get_override_sender_name().unwrap(),
        "bob@example.net"
    ); // Bob is not part of the group, so override-sender-name should be set

    // Claire gets the reply as ad hoc group.
    let request = claire.get_last_msg().await;
    receive_imf(&claire, reply.as_bytes(), false).await.unwrap();
    let answer = claire.get_last_msg().await;
    assert_eq!(answer.get_subject(), "Re: i have a question");
    assert!(answer.get_text().contains("the version is 1.0"));
    if group_request {
        assert_eq!(answer.chat_id, request.chat_id);
        assert_eq!(
            answer.get_override_sender_name().unwrap(),
            "bob@example.net"
        );
    } else {
        assert_ne!(answer.chat_id, request.chat_id);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_nondc_nonchat_nongroup() {
    check_alias_reply(false, false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_nondc_nonchat_group() {
    check_alias_reply(false, false, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_nondc_chat_nongroup() {
    check_alias_reply(false, true, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_nondc_chat_group() {
    check_alias_reply(false, true, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_dc_nonchat_nongroup() {
    check_alias_reply(true, false, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_dc_nonchat_group() {
    check_alias_reply(true, false, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_dc_chat_nongroup() {
    check_alias_reply(true, true, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_alias_support_answer_from_dc_chat_group() {
    check_alias_reply(true, true, true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_assign_to_trash_by_parent() {
    let t = TestContext::new_alice().await;
    println!("\n========= Receive a message ==========");
    receive_imf(
        &t,
        b"From: Nu Bar <nu@bar.org>\n\
            To: alice@example.org, bob@example.org\n\
            Subject: Hi\n\
            Message-ID: <4444@example.org>\n\
            \n\
            hello\n",
        false,
    )
    .await
    .unwrap();
    let chat_id = t.get_last_msg().await.chat_id;
    chat_id.accept(&t).await.unwrap();
    let msg = get_chat_msg(&t, chat_id, 0, 1).await; // Make sure that the message is actually in the chat
    assert!(!msg.chat_id.is_special());
    assert_eq!(msg.text, "Hi – hello");

    println!("\n========= Delete the message ==========");
    msg.id.trash(&t, false).await.unwrap();

    let msgs = chat::get_chat_msgs(&t.ctx, chat_id).await.unwrap();
    assert_eq!(msgs.len(), 0);

    println!("\n========= Receive a message that is a reply to the deleted message ==========");
    receive_imf(
        &t,
        b"From: Nu Bar <nu@bar.org>\n\
            To: alice@example.org, bob@example.org\n\
            Subject: Re: Hi\n\
            Message-ID: <5555@example.org>\n\
            In-Reply-To: <4444@example.org\n\
            \n\
            Reply\n",
        false,
    )
    .await
    .unwrap();
    let msg = t.get_last_msg().await;
    assert!(!msg.chat_id.is_special()); // Esp. check that the chat_id is not TRASH
    assert_eq!(msg.text, "Reply");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_show_all_outgoing_msgs_in_self_chat() {
    // Regression test for <https://github.com/deltachat/deltachat-android/issues/1940>:
    // Some servers add a `Bcc: <Self>` header, which caused all outgoing messages to
    // be shown in the self-chat.
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        b"Bcc: alice@example.org
Received: from [127.0.0.1]
Subject: s
Chat-Version: 1.0
Message-ID: <abcd@gmail.com>
To: <me@other.maildomain.com>
From: <alice@example.org>

Message content",
        false,
    )
    .await
    .unwrap();

    let msg = t.get_last_msg().await;
    assert_ne!(msg.chat_id, t.get_self_chat().await.id);
}

/// Tests that message with hidden recipients is assigned to Saved Messages chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_hidden_recipients_self_chat() {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        b"Subject: s
Chat-Version: 1.0
Message-ID: <foobar@localhost>
To: hidden-recipients:;
From: <alice@example.org>

Message content",
        false,
    )
    .await
    .unwrap();

    let msg = t.get_last_msg().await;
    assert_eq!(msg.chat_id, t.get_self_chat().await.id);
    assert_eq!(msg.to_id, ContactId::SELF);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_unencrypted_name_in_self_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let bob = &tcm.bob().await;
    bob.set_config(Config::Displayname, Some("Bob Smith"))
        .await?;
    let chat_id = bob.get_self_chat().await.id;
    let msg = bob.send_text(chat_id, "Happy birthday to me").await;
    assert_eq!(msg.payload.contains("Bob Smith"), false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_smtp_job_for_self_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let bob = &tcm.bob().await;
    bob.set_config_bool(Config::BccSelf, false).await?;
    let chat_id = bob.get_self_chat().await.id;
    let mut msg = Message::new_text("Happy birthday to me".to_string());
    chat::send_msg(bob, chat_id, &mut msg).await?;
    assert!(bob.pop_sent_msg_opt(Duration::ZERO).await.is_none());

    bob.set_config_bool(Config::BccSelf, true).await?;
    bob.set_config(Config::DeleteServerAfter, Some("1")).await?;
    let mut msg = Message::new_text("Happy birthday to me".to_string());
    chat::send_msg(bob, chat_id, &mut msg).await?;
    assert!(bob.pop_sent_msg_opt(Duration::ZERO).await.is_none());

    bob.set_config(Config::DeleteServerAfter, None).await?;
    let mut msg = Message::new_text("Happy birthday to me".to_string());
    chat::send_msg(bob, chat_id, &mut msg).await?;
    assert!(bob.pop_sent_msg_opt(Duration::ZERO).await.is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_classic_mail_creates_chat() {
    let alice = TestContext::new_alice().await;

    // Alice downloads outgoing classic email.
    receive_imf(
        &alice,
        b"Received: from [127.0.0.1]
Subject: Subj
Message-ID: <abcd@example.com>
To: <bob@example.org>
From: <alice@example.org>

Message content",
        false,
    )
    .await
    .unwrap();

    // Outgoing email should create a chat.
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.get_text(), "Subj – Message content");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_duplicate_message() -> Result<()> {
    // Test that duplicate messages are ignored based on the Message-ID
    let alice = TestContext::new_alice().await;

    let bob_contact_id = Contact::add_or_lookup(
        &alice,
        "Bob",
        &ContactAddress::new("bob@example.org").unwrap(),
        Origin::IncomingUnknownFrom,
    )
    .await?
    .0;

    let first_message = b"Received: from [127.0.0.1]
Subject: First message
Message-ID: <first@example.org>
To: Alice <alice@example.org>
From: Bob1 <bob@example.org>
Chat-Version: 1.0

Message content

-- 
First signature";

    let second_message = b"Received: from [127.0.0.1]
Subject: Second message
Message-ID: <second@example.org>
To: Alice <alice@example.org>
From: Bob2 <bob@example.org>
Chat-Version: 1.0

Message content

-- 
Second signature";

    receive_imf(&alice, first_message, false).await?;
    let contact = Contact::get_by_id(&alice, bob_contact_id).await?;
    assert_eq!(contact.get_status(), "First signature");
    assert_eq!(contact.get_display_name(), "Bob1");

    receive_imf(&alice, second_message, false).await?;
    let contact = Contact::get_by_id(&alice, bob_contact_id).await?;
    assert_eq!(contact.get_status(), "Second signature");
    assert_eq!(contact.get_display_name(), "Bob2");

    // Duplicate message, should be ignored
    receive_imf(&alice, first_message, false).await?;

    // No change because last message is duplicate of the first.
    let contact = Contact::get_by_id(&alice, bob_contact_id).await?;
    assert_eq!(contact.get_status(), "Second signature");
    assert_eq!(contact.get_display_name(), "Bob2");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ignore_footer_status_from_mailinglist() -> Result<()> {
    let t = TestContext::new_alice().await;
    let bob_id = Contact::add_or_lookup(
        &t,
        "",
        &ContactAddress::new("bob@example.net").unwrap(),
        Origin::IncomingUnknownCc,
    )
    .await?
    .0;
    let bob = Contact::get_by_id(&t, bob_id).await?;
    assert_eq!(bob.get_status(), "");
    assert_eq!(Chatlist::try_load(&t, 0, None, None).await?.len(), 0);

    receive_imf(
        &t,
        b"From: Bob <bob@example.net>
To: Alice <alice@example.org>
Message-ID: <1@example.org>
Subject: first message

body 1

--
Original signature",
        false,
    )
    .await?;
    let msg = t.get_last_msg().await;
    let one2one_chat_id = msg.chat_id;
    let bob = Contact::get_by_id(&t, bob_id).await?;
    assert_eq!(bob.get_status(), "Original signature");
    assert!(!msg.has_html());

    receive_imf(
        &t,
        b"From: Bob <bob@example.net>
Sender: ml@example.net
To: Alice <alice@example.org>
Message-ID: <2@example.net>
Precedence: list
Subject: second message

body 2

--
The modified signature
--
Tap here to unsubscribe ...",
        false,
    )
    .await?;
    let ml_chat_id = t.get_last_msg().await.chat_id;
    let bob = Contact::get_by_id(&t, bob_id).await?;
    assert_eq!(bob.get_status(), "Original signature");

    receive_imf(
        &t,
        b"From: Bob <bob@example.net>
To: Alice <alice@example.org>
Message-ID: <3@example.org>
Subject: third message

body 3

--
Original signature updated",
        false,
    )
    .await?;
    let bob = Contact::get_by_id(&t, bob_id).await?;
    assert_eq!(bob.get_status(), "Original signature updated");
    assert_eq!(get_chat_msgs(&t, one2one_chat_id).await?.len(), 2);
    assert_eq!(get_chat_msgs(&t, ml_chat_id).await?.len(), 1);
    assert_eq!(Chatlist::try_load(&t, 0, None, None).await?.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ignore_old_status_updates() -> Result<()> {
    let t = TestContext::new_alice().await;
    let bob_id = Contact::add_or_lookup(
        &t,
        "",
        &ContactAddress::new("bob@example.net")?,
        Origin::AddressBook,
    )
    .await?
    .0;

    receive_imf(
        &t,
        b"From: Bob <bob@example.net>
To: Alice <alice@example.org>
Message-ID: <2@example.org>
Date: Wed, 22 Feb 2023 20:00:00 +0000

body

--
sig wednesday",
        false,
    )
    .await?;
    let chat_id = t.get_last_msg().await.chat_id;
    let bob = Contact::get_by_id(&t, bob_id).await?;
    assert_eq!(bob.get_status(), "sig wednesday");
    assert_eq!(get_chat_msgs(&t, chat_id).await?.len(), 1);

    receive_imf(
        &t,
        b"From: Bob <bob@example.net>
To: Alice <alice@example.org>
Message-ID: <1@example.org>
Date: Tue, 21 Feb 2023 20:00:00 +0000

body

--
sig tuesday",
        false,
    )
    .await?;
    let bob = Contact::get_by_id(&t, bob_id).await?;
    assert_eq!(bob.get_status(), "sig wednesday");
    assert_eq!(get_chat_msgs(&t, chat_id).await?.len(), 2);

    receive_imf(
        &t,
        b"From: Bob <bob@example.net>
To: Alice <alice@example.org>
Message-ID: <3@example.org>
Date: Thu, 23 Feb 2023 20:00:00 +0000

body

--
sig thursday",
        false,
    )
    .await?;
    let bob = Contact::get_by_id(&t, bob_id).await?;
    assert_eq!(bob.get_status(), "sig thursday");
    assert_eq!(get_chat_msgs(&t, chat_id).await?.len(), 3);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_assignment_private_classical_reply() {
    for outgoing_is_classical in &[true, false] {
        let t = TestContext::new_alice().await;

        receive_imf(
            &t,
            format!(
                r#"Received: from mout.gmx.net (mout.gmx.net [212.227.17.22])
Subject: =?utf-8?q?single_reply-to?=
{}
Date: Fri, 28 May 2021 10:15:05 +0000
To: Bob <bob@example.com>, <claire@example.com>
From: Alice <alice@example.org>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Content-Transfer-Encoding: quoted-printable

Hello, I've just created the group "single reply-to" for us."#,
                if *outgoing_is_classical {
                    r"Message-ID: abcd@gmx.de"
                } else {
                    r"Chat-Group-ID: eJ_llQIXf0K
Chat-Group-Name: =?utf-8?q?single_reply-to?=
References: <Gr.eJ_llQIXf0K.buxmrnMmG0Y@gmx.de>
Chat-Version: 1.0
Message-ID: <Gr.eJ_llQIXf0K.buxmrnMmG0Y@gmx.de>"
                }
            )
            .as_bytes(),
            false,
        )
        .await
        .unwrap();

        let group_msg = t.get_last_msg().await;
        assert_eq!(
            group_msg.text,
            if *outgoing_is_classical {
                "single reply-to – Hello, I\'ve just created the group \"single reply-to\" for us."
            } else {
                "Hello, I've just created the group \"single reply-to\" for us."
            }
        );
        let group_chat = Chat::load_from_db(&t, group_msg.chat_id).await.unwrap();
        assert_eq!(group_chat.typ, Chattype::Group);
        assert_eq!(group_chat.name, "single reply-to");

        receive_imf(
            &t,
            format!(
                r#"Subject: Re: single reply-to
To: "Alice" <alice@example.org>
References: <{0}>
 <{0}>
From: Bob <bob@example.com>
Message-ID: <028674eb-77f9-4ad1-1c30-e93e18b891c8@testrun.org>
Date: Fri, 28 May 2021 12:17:03 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.2
MIME-Version: 1.0
In-Reply-To: <{0}>

Private reply"#,
                if *outgoing_is_classical {
                    "abcd@gmx.de"
                } else {
                    "Gr.eJ_llQIXf0K.buxmrnMmG0Y@gmx.de"
                }
            )
            .as_bytes(),
            false,
        )
        .await
        .unwrap();

        let private_msg = t.get_last_msg().await;
        assert_eq!(private_msg.text, "Private reply");
        let private_chat = Chat::load_from_db(&t, private_msg.chat_id).await.unwrap();
        assert_eq!(private_chat.typ, Chattype::Single);
        assert_ne!(private_msg.chat_id, group_msg.chat_id);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_assignment_private_chat_reply() {
    for (outgoing_is_classical, outgoing_has_multiple_recipients) in
        &[(true, true), (false, true), (false, false)]
    {
        let t = TestContext::new_alice().await;

        receive_imf(
            &t,
            format!(
                r#"Received: from mout.gmx.net (mout.gmx.net [212.227.17.22])
Subject: =?utf-8?q?single_reply-to?=
{}
Date: Fri, 28 May 2021 10:15:05 +0000
To: Bob <bob@example.com>, Charlie <charlie@example.net>{}
From: Alice <alice@example.org>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Content-Transfer-Encoding: quoted-printable

Hello, I've just created the group "single reply-to" for us."#,
                if *outgoing_is_classical {
                    r"Message-ID: abcd@gmx.de"
                } else {
                    r"Chat-Group-ID: eJ_llQIXf0K
Chat-Group-Name: =?utf-8?q?single_reply-to?=
References: <Gr.iy1KCE2y65_.mH2TM52miv9@testrun.org>
Chat-Version: 1.0
Message-ID: <Gr.iy1KCE2y65_.mH2TM52miv9@testrun.org>"
                },
                if *outgoing_has_multiple_recipients {
                    ", <claire@example.com>"
                } else {
                    ""
                }
            )
            .as_bytes(),
            false,
        )
        .await
        .unwrap();
        let group_msg = t.get_last_msg().await;
        assert_eq!(
            group_msg.text,
            if *outgoing_is_classical {
                "single reply-to – Hello, I\'ve just created the group \"single reply-to\" for us."
            } else {
                "Hello, I've just created the group \"single reply-to\" for us."
            }
        );
        let group_chat = Chat::load_from_db(&t, group_msg.chat_id).await.unwrap();
        assert_eq!(group_chat.typ, Chattype::Group);
        assert_eq!(group_chat.name, "single reply-to");

        receive_imf(
            &t,
            format!(
                r#"Subject: =?utf-8?q?Re=3A_single_reply-to?=
MIME-Version: 1.0
In-Reply-To: <{0}>
Date: Sat, 03 Jul 2021 20:00:26 +0000
Chat-Version: 1.0
Message-ID: <Mr.CJFwF5hwn8W.Pd-GGH5m32k@gmx.de>
To: <alice@example.org>
From: <bob@example.com>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Content-Transfer-Encoding: quoted-printable

> Hello, I've just created the group "single reply-to" for us.

Private reply

=2D-
Sent with my Delta Chat Messenger: https://delta.chat

"#,
                if *outgoing_is_classical {
                    "abcd@gmx.de"
                } else {
                    "Gr.iy1KCE2y65_.mH2TM52miv9@testrun.org"
                }
            )
            .as_bytes(),
            false,
        )
        .await
        .unwrap();

        let private_msg = t.get_last_msg().await;
        assert_eq!(private_msg.text, "Private reply");
        let private_chat = Chat::load_from_db(&t, private_msg.chat_id).await.unwrap();
        assert_eq!(private_chat.typ, Chattype::Single);
        assert_ne!(private_msg.chat_id, group_msg.chat_id);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_assignment_nonprivate_classical_reply() {
    for outgoing_is_classical in &[true, false] {
        let t = TestContext::new_alice().await;

        receive_imf(
            &t,
            format!(
                r#"Received: from mout.gmx.net (mout.gmx.net [212.227.17.22])
Subject: =?utf-8?q?single_reply-to?=
{}
To: Bob <bob@example.com>, <claire@example.com>
From: Alice <alice@example.org>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Content-Transfer-Encoding: quoted-printable

Hello, I've just created the group "single reply-to" for us."#,
                if *outgoing_is_classical {
                    r"Message-ID: abcd@gmx.de"
                } else {
                    r"Chat-Group-ID: eJ_llQIXf0K
Chat-Group-Name: =?utf-8?q?single_reply-to?=
References: <Gr.eJ_llQIXf0K.buxmrnMmG0Y@gmx.de>
Chat-Version: 1.0
Message-ID: <Gr.eJ_llQIXf0K.buxmrnMmG0Y@gmx.de>"
                }
            )
            .as_bytes(),
            false,
        )
        .await
        .unwrap();

        let group_msg = t.get_last_msg().await;
        assert_eq!(
            group_msg.text,
            if *outgoing_is_classical {
                "single reply-to – Hello, I\'ve just created the group \"single reply-to\" for us."
            } else {
                "Hello, I've just created the group \"single reply-to\" for us."
            }
        );
        let group_chat = Chat::load_from_db(&t, group_msg.chat_id).await.unwrap();
        assert_eq!(group_chat.typ, Chattype::Group);
        assert_eq!(group_chat.name, "single reply-to");

        // =============== Receive another outgoing message and check that it is put into the same chat ===============
        receive_imf(
            &t,
            format!(
                r#"Received: from mout.gmx.net (mout.gmx.net [212.227.17.22])
Subject: Out subj
To: "Bob" <bob@example.com>, "Claire" <claire@example.com>
From: Alice <alice@example.org>
Message-ID: <outgoing@testrun.org>
MIME-Version: 1.0
In-Reply-To: <{0}>

Outgoing reply to all"#,
                if *outgoing_is_classical {
                    "abcd@gmx.de"
                } else {
                    "Gr.eJ_llQIXf0K.buxmrnMmG0Y@gmx.de"
                }
            )
            .as_bytes(),
            false,
        )
        .await
        .unwrap();

        let reply = t.get_last_msg().await;
        assert_eq!(reply.text, "Out subj – Outgoing reply to all");
        let reply_chat = Chat::load_from_db(&t, reply.chat_id).await.unwrap();
        assert_eq!(reply_chat.typ, Chattype::Group);
        assert_eq!(reply.chat_id, group_msg.chat_id);

        // =============== Receive an incoming message and check that it is put into the same chat ===============
        receive_imf(
            &t,
            br#"Received: from mout.gmx.net (mout.gmx.net [212.227.17.22])
Subject: In subj
To: "Bob" <bob@example.com>, "Claire" <claire@example.com>
From: alice <alice@example.org>
Message-ID: <xyz@testrun.org>
MIME-Version: 1.0
In-Reply-To: <outgoing@testrun.org>

Reply to all"#,
            false,
        )
        .await
        .unwrap();

        let reply = t.get_last_msg().await;
        assert_eq!(reply.text, "In subj – Reply to all");
        let reply_chat = Chat::load_from_db(&t, reply.chat_id).await.unwrap();
        assert_eq!(reply_chat.typ, Chattype::Group);
        assert_eq!(reply.chat_id, group_msg.chat_id);
    }
}

/// Tests that replies to similar ad hoc groups are correctly assigned to chats.
///
/// The difficulty here is that ad hoc groups don't have unique group IDs, because both
/// messages have the same recipient lists and only differ in the subject and message contents.
/// The messages can be properly assigned to chats only using the In-Reply-To or References
/// headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_assignment_adhoc() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    let first_thread_mime = br#"Subject: First thread
Message-ID: first@example.org
To: Alice <alice@example.org>, Bob <bob@example.net>
From: Claire <claire@example.org>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

First thread."#;
    let second_thread_mime = br#"Subject: Second thread
Message-ID: second@example.org
To: Alice <alice@example.org>, Bob <bob@example.net>
From: Claire <claire@example.org>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

Second thread."#;

    // Alice receives two classic emails from Claire.
    receive_imf(&alice, first_thread_mime, false).await?;
    let alice_first_msg = alice.get_last_msg().await;
    receive_imf(&alice, second_thread_mime, false).await?;
    let alice_second_msg = alice.get_last_msg().await;

    // Bob receives the same two emails.
    receive_imf(&bob, first_thread_mime, false).await?;
    let bob_first_msg = bob.get_last_msg().await;
    receive_imf(&bob, second_thread_mime, false).await?;
    let bob_second_msg = bob.get_last_msg().await;

    // Messages go to separate chats both for Alice and Bob.
    assert_ne!(alice_first_msg.chat_id, alice_second_msg.chat_id);
    assert_ne!(bob_first_msg.chat_id, bob_second_msg.chat_id);

    // Alice replies to both chats. Bob receives two messages and assigns them to corresponding
    // chats.
    alice_first_msg.chat_id.accept(&alice).await?;
    let alice_first_reply = alice
        .send_text(alice_first_msg.chat_id, "First reply")
        .await;
    let bob_first_reply = bob.recv_msg(&alice_first_reply).await;
    assert_eq!(bob_first_reply.chat_id, bob_first_msg.chat_id);

    alice_second_msg.chat_id.accept(&alice).await?;
    let alice_second_reply = alice
        .send_text(alice_second_msg.chat_id, "Second reply")
        .await;
    let bob_second_reply = bob.recv_msg(&alice_second_reply).await;
    assert_eq!(bob_second_reply.chat_id, bob_second_msg.chat_id);

    // Alice adds Fiona to both ad hoc groups.
    let alice_fiona_contact = alice.add_or_lookup_address_contact(&fiona).await;
    let alice_fiona_contact_id = alice_fiona_contact.id;

    chat::add_contact_to_chat(&alice, alice_first_msg.chat_id, alice_fiona_contact_id).await?;
    let alice_first_invite = alice.pop_sent_msg().await;
    let fiona_first_invite = fiona.recv_msg(&alice_first_invite).await;

    chat::add_contact_to_chat(&alice, alice_second_msg.chat_id, alice_fiona_contact_id).await?;
    let alice_second_invite = alice.pop_sent_msg().await;
    let fiona_second_invite = fiona.recv_msg(&alice_second_invite).await;

    // Fiona was added to two separate chats and should see two separate chats, even though they
    // don't have different group IDs to distinguish them.
    assert_ne!(fiona_first_invite.chat_id, fiona_second_invite.chat_id);

    Ok(())
}

/// Test that read receipts don't create chats.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_receipts_dont_create_chats() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;

    // Alice sends a message to Bob.
    assert_eq!(Chatlist::try_load(&bob, 0, None, None).await?.len(), 0);
    bob.recv_msg(&alice.send_text(alice_chat.id, "Message").await)
        .await;
    let received_msg = bob.get_last_msg().await;

    // Alice deletes the chat.
    alice_chat.id.delete(&alice).await?;
    let chats = Chatlist::try_load(&alice, 0, None, None).await?;
    assert_eq!(chats.len(), 0);

    // Bob sends a read receipt.
    let mdn_mimefactory = crate::mimefactory::MimeFactory::from_mdn(
        &bob,
        received_msg.from_id,
        received_msg.rfc724_mid,
        vec![],
    )
    .await?;
    let rendered_mdn = mdn_mimefactory.render(&bob).await?;
    let mdn_body = rendered_mdn.message;

    // Alice receives the read receipt.
    receive_imf(&alice, mdn_body.as_bytes(), false).await?;

    // Chat should not pop up in the chatlist.
    let chats = Chatlist::try_load(&alice, 0, None, None).await?;
    assert_eq!(chats.len(), 0);

    Ok(())
}

/// Test that read receipts don't unmark contacts as bots.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_read_receipts_dont_unmark_bots() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    let bob = &TestContext::new_bob().await;
    let ab_contact = alice.add_or_lookup_contact(bob).await;
    ab_contact.id.mark_bot(alice, true).await?;
    let alice_chat = alice.create_chat(bob).await;

    // Alice sends and Bob receives a message.
    bob.recv_msg(&alice.send_text(alice_chat.id, "Message").await)
        .await;
    let received_msg = bob.get_last_msg().await;

    // Bob sends a read receipt.
    let mdn_mimefactory = crate::mimefactory::MimeFactory::from_mdn(
        bob,
        received_msg.from_id,
        received_msg.rfc724_mid,
        vec![],
    )
    .await?;
    let rendered_mdn = mdn_mimefactory.render(bob).await?;
    let mdn_body = rendered_mdn.message;

    // Alice receives the read receipt.
    receive_imf(alice, mdn_body.as_bytes(), false).await?;
    let msg = alice.get_last_msg_in(alice_chat.id).await;
    assert_eq!(msg.state, MessageState::OutMdnRcvd);
    let ab_contact = alice.add_or_lookup_contact(bob).await;
    assert!(ab_contact.is_bot());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_gmx_forwarded_msg() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/gmx-forward.eml"),
        false,
    )
    .await?;

    let msg = t.get_last_msg().await;
    assert!(msg.has_html());
    assert_eq!(
        msg.id.get_html(&t).await?.unwrap().replace("\r\n", "\n"),
        "<html><head></head><body><div style=\"font-family: Verdana;font-size: 12.0px;\"><div>&nbsp;</div>\n\n<div>&nbsp;\n<div>&nbsp;\n<div data-darkreader-inline-border-left=\"\" name=\"quote\" style=\"margin: 10px 5px 5px 10px; padding: 10px 0px 10px 10px; border-left: 2px solid rgb(195, 217, 229); overflow-wrap: break-word; --darkreader-inline-border-left:#274759;\">\n<div style=\"margin:0 0 10px 0;\"><b>Gesendet:</b>&nbsp;Donnerstag, 12. August 2021 um 15:52 Uhr<br/>\n<b>Von:</b>&nbsp;&quot;Claire&quot; &lt;claire@example.org&gt;<br/>\n<b>An:</b>&nbsp;alice@example.org<br/>\n<b>Betreff:</b>&nbsp;subject</div>\n\n<div name=\"quoted-content\">bodytext</div>\n</div>\n</div>\n</div></div></body></html>\n\n"
    );

    Ok(())
}

/// Tests that user is notified about new incoming contact requests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_incoming_contact_request() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(&t, MSGRMSG, false).await?;
    let msg = t.get_last_msg().await;
    let chat = chat::Chat::load_from_db(&t, msg.chat_id).await?;
    assert!(chat.is_contact_request());

    let event = t
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::IncomingMsg { .. }))
        .await;
    match event {
        EventType::IncomingMsg { chat_id, msg_id } => {
            assert_eq!(msg.chat_id, chat_id);
            assert_eq!(msg.id, msg_id);
            Ok(())
        }
        _ => unreachable!(),
    }
}

async fn get_parent_message(
    context: &Context,
    mime_parser: &MimeMessage,
) -> Result<Option<Message>> {
    super::get_parent_message(
        context,
        mime_parser.get_header(HeaderDef::References),
        mime_parser.get_header(HeaderDef::InReplyTo),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_parent_message() -> Result<()> {
    let t = TestContext::new_alice().await;

    let mime = br#"Subject: First
Message-ID: first@example.net
To: Alice <alice@example.org>
From: Bob <bob@example.net>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

First."#;
    receive_imf(&t, mime, false).await?;
    let first = t.get_last_msg().await;
    let mime = br#"Subject: Second
Message-ID: second@example.net
To: Alice <alice@example.org>
From: Bob <bob@example.net>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

First."#;
    receive_imf(&t, mime, false).await?;
    let second = t.get_last_msg().await;
    let mime = br#"Subject: Third
Message-ID: third@example.net
To: Alice <alice@example.org>
From: Bob <bob@example.net>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

First."#;
    receive_imf(&t, mime, false).await?;
    let third = t.get_last_msg().await;

    let mime = br#"Subject: Message with references.
Message-ID: second@example.net
To: Alice <alice@example.org>
From: Bob <bob@example.net>
In-Reply-To: <third@example.net>
References: <second@example.net> <nonexistent@example.net> <first@example.net>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

Message with references."#;
    let mime_parser = MimeMessage::from_bytes(&t, &mime[..], None).await?;

    let parent = get_parent_message(&t, &mime_parser).await?.unwrap();
    assert_eq!(parent.id, first.id);

    message::delete_msgs(&t, &[first.id]).await?;
    let parent = get_parent_message(&t, &mime_parser).await?.unwrap();
    assert_eq!(parent.id, second.id);

    message::delete_msgs(&t, &[second.id]).await?;
    let parent = get_parent_message(&t, &mime_parser).await?.unwrap();
    assert_eq!(parent.id, third.id);

    message::delete_msgs(&t, &[third.id]).await?;
    let parent = get_parent_message(&t, &mime_parser).await?;
    assert!(parent.is_none());

    Ok(())
}

/// Test a message with RFC 1847 encapsulation as created by Thunderbird.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rfc1847_encapsulation() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // Bob gets Alice's key via vCard.
    bob.add_or_lookup_contact_id(alice).await;

    // Alice sends a message to Bob using Thunderbird.
    let raw = include_bytes!("../../test-data/message/rfc1847_encapsulation.eml");
    receive_imf(bob, raw, false).await?;

    let msg = bob.get_last_msg().await;
    assert!(msg.get_showpadlock());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_invalid_to_address() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let mime = include_bytes!("../../test-data/message/invalid_email_to.eml");

    // receive_imf should not fail on this mail with invalid To: field
    receive_imf(&alice, mime, false).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_weird_and_duplicated_filenames() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    for filename_sent in &[
        "foo.bar very long file name test baz.tar.gz",
        "foo.barabababababababbababababverylongfilenametestbaz.tar.gz",
        "fooo...tar.gz",
        "foo. .tar.gz",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.tar.gz",
        "a.tar.gz",
        "a.tar.gz",
        "a.a..a.a.a.a.tar.gz",
        "a. tar.tar.gz",
    ] {
        let attachment = alice.blobdir.join(filename_sent);
        let content = "File content of tar.gz archive".to_string();
        tokio::fs::write(&attachment, content.as_bytes()).await?;

        let mut msg_alice = Message::new(Viewtype::File);
        msg_alice.set_file_and_deduplicate(&alice, &attachment, None, None)?;
        let alice_chat = alice.create_chat(&bob).await;
        let sent = alice.send_msg(alice_chat.id, &mut msg_alice).await;
        println!("{}", sent.payload());

        let msg_bob = bob.recv_msg(&sent).await;

        async fn check_message(msg: &Message, t: &TestContext, filename: &str, content: &str) {
            assert_eq!(msg.get_viewtype(), Viewtype::File);
            let resulting_filename = msg.get_filename().unwrap();
            assert_eq!(resulting_filename, filename);
            let path = msg.get_file(t).unwrap();
            let path2 = path.with_file_name("saved.txt");
            msg.save_file(t, &path2).await.unwrap();
            assert_eq!(
                path.file_name().unwrap().to_str().unwrap(),
                "79402cb76f44c5761888f9036992a76.gz",
                "The hash of the content should always be the same"
            );
            assert_eq!(fs::read_to_string(&path).await.unwrap(), content);
            assert_eq!(fs::read_to_string(&path2).await.unwrap(), content);
            fs::remove_file(path2).await.unwrap();
        }
        check_message(&msg_alice, &alice, filename_sent, &content).await;
        check_message(&msg_bob, &bob, filename_sent, &content).await;
    }

    Ok(())
}

/// Tests that contact request is accepted automatically on outgoing message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_accept_outgoing() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = tcm.alice().await;
    let alice2 = tcm.alice().await;
    let bob1 = tcm.bob().await;
    let bob2 = tcm.bob().await;

    let bob1_chat = bob1.create_chat(&alice1).await;
    let sent = bob1.send_text(bob1_chat.id, "Hello!").await;

    alice1.recv_msg(&sent).await;
    alice2.recv_msg(&sent).await;
    let alice1_msg = bob2.recv_msg(&sent).await;
    assert_eq!(alice1_msg.text, "Hello!");
    let alice1_chat = chat::Chat::load_from_db(&alice1, alice1_msg.chat_id).await?;
    assert!(alice1_chat.is_contact_request());

    let alice2_msg = alice2.get_last_msg().await;
    assert_eq!(alice2_msg.text, "Hello!");
    let alice2_chat = chat::Chat::load_from_db(&alice2, alice2_msg.chat_id).await?;
    assert!(alice2_chat.is_contact_request());

    let bob1_msg = bob1.get_last_msg().await;
    assert_eq!(bob1_msg.text, "Hello!");
    let bob1_chat = chat::Chat::load_from_db(&bob1, bob1_msg.chat_id).await?;
    assert!(!bob1_chat.is_contact_request());

    let bob2_msg = bob2.get_last_msg().await;
    assert_eq!(bob2_msg.text, "Hello!");
    let bob2_chat = chat::Chat::load_from_db(&bob2, bob2_msg.chat_id).await?;
    assert!(!bob2_chat.is_contact_request());

    // Alice sends reply.
    alice1_msg.chat_id.accept(&alice1).await.unwrap();
    let sent = alice1.send_text(alice1_chat.id, "Hi!").await;
    alice2.recv_msg(&sent).await;

    // Second device automatically accepts the contact request.
    let alice2_chat = chat::Chat::load_from_db(&alice2, alice2_msg.chat_id).await?;
    assert!(!alice2_chat.is_contact_request());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_private_reply_multidevice() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = tcm.alice().await;
    let alice2 = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await;

    // =============== Bob creates a group ===============
    let group_id = chat::create_group_chat(&bob, ProtectionStatus::Unprotected, "Group").await?;
    chat::add_to_chat_contacts_table(
        &bob,
        time(),
        group_id,
        &[
            bob.add_or_lookup_contact_id(&alice1).await,
            bob.add_or_lookup_contact_id(&charlie).await,
        ],
    )
    .await?;

    // =============== Bob sends the first message to the group ===============
    let sent = bob.send_text(group_id, "Hello all!").await;
    alice1.recv_msg(&sent).await;
    alice2.recv_msg(&sent).await;

    // =============== Alice answers privately with device 1 ===============
    let received = alice1.get_last_msg().await;
    let alice1_bob_contact = alice1.add_or_lookup_contact(&bob).await;
    assert_eq!(received.from_id, alice1_bob_contact.id);
    assert_eq!(received.to_id, ContactId::SELF);
    assert!(!received.hidden);
    assert_eq!(received.text, "Hello all!");
    assert_eq!(received.in_reply_to, None);
    assert_eq!(received.chat_blocked, Blocked::Request);

    let received_group = Chat::load_from_db(&alice1, received.chat_id).await?;
    assert_eq!(received_group.typ, Chattype::Group);
    assert_eq!(received_group.name, "Group");
    assert_eq!(received_group.can_send(&alice1).await?, false); // Can't send because it's Blocked::Request

    let mut msg_out = Message::new_text("Private reply".to_string());

    assert_eq!(received_group.blocked, Blocked::Request);
    msg_out.set_quote(&alice1, Some(&received)).await?;
    let alice1_bob_chat = alice1.create_chat(&bob).await;
    let sent2 = alice1.send_msg(alice1_bob_chat.id, &mut msg_out).await;
    alice2.recv_msg(&sent2).await;

    // =============== Alice's second device receives the message ===============
    let received = alice2.get_last_msg().await;

    // That's a regression test for https://github.com/chatmail/core/issues/2949:
    assert_eq!(received.chat_id, alice2.get_chat(&bob).await.id);

    let alice2_bob_contact = alice2.add_or_lookup_contact(&bob).await;
    assert_eq!(received.from_id, ContactId::SELF);
    assert_eq!(received.to_id, alice2_bob_contact.id);
    assert!(!received.hidden);
    assert_eq!(received.text, "Private reply");
    assert_eq!(
        received.parent(&alice2).await?.unwrap().text,
        "Hello all!".to_string()
    );
    assert_eq!(received.chat_blocked, Blocked::Not);

    let received_chat = Chat::load_from_db(&alice2, received.chat_id).await?;
    assert_eq!(received_chat.typ, Chattype::Single);
    assert_eq!(received_chat.name, "bob@example.net");
    assert_eq!(received_chat.can_send(&alice2).await?, true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_auto_accept_for_bots() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config(Config::Bot, Some("1")).await.unwrap();
    let msg = tcm.send_recv(bob, alice, "Hello!").await;
    let chat = chat::Chat::load_from_db(alice, msg.chat_id).await?;
    assert!(!chat.is_contact_request());

    assert_eq!(Contact::get_all(alice, 0, None).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_auto_accept_group_for_bots() -> Result<()> {
    let t = TestContext::new_alice().await;
    t.set_config(Config::Bot, Some("1")).await.unwrap();
    receive_imf(&t, GRP_MAIL, false).await?;
    let msg = t.get_last_msg().await;
    let chat = chat::Chat::load_from_db(&t, msg.chat_id).await?;
    assert!(!chat.is_contact_request());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_auto_accept_protected_group_for_bots() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    bob.set_config(Config::Bot, Some("1")).await.unwrap();
    mark_as_verified(alice, bob).await;
    mark_as_verified(bob, alice).await;
    let group_id = alice
        .create_group_with_members(ProtectionStatus::Protected, "Group", &[bob])
        .await;
    let sent = alice.send_text(group_id, "Hello!").await;
    let msg = bob.recv_msg(&sent).await;
    let chat = chat::Chat::load_from_db(bob, msg.chat_id).await?;
    assert!(!chat.is_contact_request());
    Ok(())
}

/// Regression test for a bug where receive_imf() failed
/// if the sender of a verification-gossiping message
/// also put itself into the To header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verification_gossip() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    mark_as_verified(alice, bob).await;
    mark_as_verified(bob, alice).await;

    // This is message sent by Alice with verified encryption
    // that gossips Fiona's verification,
    // and for some reason, Alice also put herself into the To: header.
    let imf_raw =
        include_bytes!("../../test-data/message/verification-gossip-also-sent-to-from.eml");

    // The regression test is that receive_imf() doesn't panic:
    let msg = receive_imf(bob, imf_raw, false).await?.unwrap();
    let msg = Message::load_from_db(bob, msg.msg_ids[0]).await?;
    assert_eq!(msg.text, "Hello!");
    assert!(
        bob.add_or_lookup_contact(fiona)
            .await
            .is_verified(bob)
            .await?
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_bot_accepts_another_group_after_qr_scan() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    bob.set_config(Config::Bot, Some("1")).await?;

    let group_id = chat::create_group_chat(alice, ProtectionStatus::Protected, "Group").await?;
    let qr = get_securejoin_qr(alice, Some(group_id)).await?;
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    let group_id = alice
        .create_group_with_members(ProtectionStatus::Protected, "Group", &[bob])
        .await;
    let sent = alice.send_text(group_id, "Hello!").await;
    let msg = bob.recv_msg(&sent).await;
    let chat = chat::Chat::load_from_db(bob, msg.chat_id).await?;
    assert!(!chat.is_contact_request());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_as_bot() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    alice.set_config(Config::Bot, Some("1")).await.unwrap();
    let bob = &tcm.bob().await;
    let alice_bob_id = alice.add_or_lookup_contact_id(bob).await;
    let bob_chat_id = tcm.send_recv_accept(alice, bob, "hi").await.chat_id;
    let alice_chat_id = ChatId::lookup_by_contact(alice, alice_bob_id)
        .await?
        .unwrap();
    let msg = alice.get_last_msg_in(alice_chat_id).await;
    assert!(msg.is_bot());
    let msg = bob.get_last_msg_in(bob_chat_id).await;
    assert!(msg.is_bot());
    chat::forward_msgs(bob, &[msg.id], bob_chat_id).await?;
    let msg = bob.get_last_msg_in(bob_chat_id).await;
    assert!(msg.is_forwarded());
    assert!(!msg.is_bot());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wrong_date_in_imf_section() {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat_id = tcm.send_recv_accept(bob, alice, "hi").await.chat_id;
    let time_before_sending = time();
    let mut sent_msg = alice.send_text(alice_chat_id, "hi").await;
    sent_msg.payload = sent_msg.payload.replace(
        "Date:",
        "Date: Tue, 29 Feb 1972 22:37:57 +0000\nX-Microsoft-Original-Date:",
    );
    let msg = bob.recv_msg(&sent_msg).await;
    assert!(msg.timestamp_sent >= time_before_sending);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_private_reply_to_blocked_account() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    tcm.section("Bob creates a group");
    let group_id = chat::create_group_chat(&bob, ProtectionStatus::Unprotected, "Group").await?;
    chat::add_to_chat_contacts_table(
        &bob,
        time(),
        group_id,
        &[bob.add_or_lookup_contact(&alice).await.id],
    )
    .await?;

    tcm.section("Bob sends the first message to the group");
    let sent = bob.send_text(group_id, "Hello all!").await;
    alice.recv_msg(&sent).await;

    let chats = Chatlist::try_load(&bob, 0, None, None).await?;
    assert_eq!(chats.len(), 1);

    tcm.section("Bob blocks Alice");
    Contact::block(&bob, bob.add_or_lookup_contact(&alice).await.id).await?;

    tcm.section("Alice replies private to Bob");
    let received = alice.get_last_msg().await;
    assert_eq!(received.text, "Hello all!");

    let received_group = Chat::load_from_db(&alice, received.chat_id).await?;
    assert_eq!(received_group.typ, Chattype::Group);

    let mut msg_out = Message::new_text("Private reply".to_string());
    msg_out.set_quote(&alice, Some(&received)).await?;

    let alice_bob_chat = alice.create_chat(&bob).await;
    let sent2 = alice.send_msg(alice_bob_chat.id, &mut msg_out).await;
    bob.recv_msg(&sent2).await;

    // check that no contact request was created
    let chats = Chatlist::try_load(&bob, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0).unwrap();
    let chat = Chat::load_from_db(&bob, chat_id).await.unwrap();

    // since only chat is a group, no new open chat has been created
    assert_eq!(chat.typ, Chattype::Group);
    let received = bob.get_last_msg().await;
    assert_eq!(received.text, "Hello all!");

    tcm.section("Bob unblocks Alice");
    // test if the blocked chat is restored correctly
    Contact::unblock(&bob, bob.add_or_lookup_contact(&alice).await.id).await?;
    let chats = Chatlist::try_load(&bob, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 2);
    let chat_id = chats.get_chat_id(0).unwrap();
    let chat = Chat::load_from_db(&bob, chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Single);
    let received = bob.get_last_msg().await;
    assert_eq!(received.text, "Private reply");

    Ok(())
}

/// Regression test for two bugs:
///
/// 1. If you blocked some spammer using DC, the 1:1 messages with that contact
///    are not received, but they could easily bypass this restriction creating
///    a new group with only you two as member.
/// 2. A blocked group was sometimes not unblocked when when an unblocked
///    contact sent a message into it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_blocked_contact_creates_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    let chat = alice.create_chat(&bob).await;
    chat.id.block(&alice).await?;

    let group_id = bob
        .create_group_with_members(
            ProtectionStatus::Unprotected,
            "group name",
            &[&alice, &fiona],
        )
        .await;

    let sent = bob.send_text(group_id, "Heyho, I'm a spammer!").await;
    let rcvd = alice.recv_msg(&sent).await;
    // Alice blocked Bob, so she shouldn't get the message
    assert_eq!(rcvd.chat_blocked, Blocked::Yes);

    // Fiona didn't block Bob, though, so she gets the message
    let rcvd = fiona.recv_msg(&sent).await;
    assert_eq!(rcvd.chat_blocked, Blocked::Request);

    // Fiona writes to the group
    rcvd.chat_id.accept(&fiona).await?;
    let sent = fiona.send_text(rcvd.chat_id, "Hello from Fiona").await;

    // The group is unblocked now that Fiona sent a message to it
    let rcvd = alice.recv_msg(&sent).await;
    assert_eq!(rcvd.chat_blocked, Blocked::Request);
    // In order not to lose context, Bob's message should also be shown in the group
    let msgs = chat::get_chat_msgs(&alice, rcvd.chat_id).await?;
    assert_eq!(msgs.len(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_undecryptable() -> Result<()> {
    let alice = &TestContext::new().await;
    alice.configure_addr("alice@example.org").await;

    let raw = include_bytes!("../../test-data/message/thunderbird_with_autocrypt.eml");
    receive_imf(alice, raw, false).await?;

    // Undecryptable message does not even create a contact.
    let bob_contact_id =
        Contact::lookup_id_by_addr(alice, "bob@example.net", Origin::OutgoingTo).await?;
    assert!(bob_contact_id.is_none());

    let dev_chat_id = ChatId::lookup_by_contact(alice, ContactId::DEVICE)
        .await?
        .unwrap();
    let dev_msg = alice.get_last_msg_in(dev_chat_id).await;
    assert!(dev_msg.error().is_none());
    assert!(
        dev_msg
            .text
            .contains(&stock_str::cant_decrypt_outgoing_msgs(alice).await)
    );

    let raw = include_bytes!("../../test-data/message/thunderbird_encrypted_signed.eml");
    receive_imf(alice, raw, false).await?;

    let bob_contact_id =
        Contact::lookup_id_by_addr(alice, "bob@example.net", Origin::OutgoingTo).await?;
    assert!(bob_contact_id.is_none());
    // The device message mustn't be added too frequently.
    assert_eq!(alice.get_last_msg_in(dev_chat_id).await.id, dev_msg.id);

    Ok(())
}

/// Tests that a message from Thunderbird with an Autocrypt header is assigned to the key-contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_thunderbird_autocrypt() -> Result<()> {
    let t = TestContext::new_bob().await;

    let raw = include_bytes!("../../test-data/message/thunderbird_with_autocrypt.eml");
    let received_msg = receive_imf(&t, raw, false).await?.unwrap();

    assert_eq!(received_msg.msg_ids.len(), 1);
    let msg_id = received_msg.msg_ids[0];

    let message = Message::load_from_db(&t, msg_id).await?;
    assert!(message.get_showpadlock());

    let from_id = message.from_id;

    let from_contact = Contact::get_by_id(&t, from_id).await?;
    assert!(from_contact.is_key_contact());

    Ok(())
}

/// Tests that a message without an Autocrypt header is assigned to the key-contact
/// by using the signature Issuer Fingerprint.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_issuer_fingerprint() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_contact_id = bob.add_or_lookup_contact_id(alice).await;

    let raw = include_bytes!("../../test-data/message/encrypted-signed.eml");
    let received_msg = receive_imf(bob, raw, false).await?.unwrap();

    assert_eq!(received_msg.msg_ids.len(), 1);
    let msg_id = received_msg.msg_ids[0];

    let message = Message::load_from_db(bob, msg_id).await?;
    assert!(message.get_showpadlock());

    let from_id = message.from_id;
    assert_eq!(from_id, alice_contact_id);

    Ok(())
}

/// Tests reception of a message from Thunderbird with attached key.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_prefer_encrypt_mutual_if_encrypted() -> Result<()> {
    let t = TestContext::new_bob().await;

    // The message has public key attached *and* Autocrypt header.
    //
    // Autocrypt header is used to check the signature.
    //
    // At the time of the writing (2025-04-30, introduction of key-contacts)
    // signature checking does not work without the Autocrypt header.
    let raw =
        include_bytes!("../../test-data/message/thunderbird_encrypted_signed_with_pubkey.eml");
    let received_msg = receive_imf(&t, raw, false).await?.unwrap();

    // Attached key does not appear as an attachment,
    // there is only one part.
    assert_eq!(received_msg.msg_ids.len(), 1);
    let msg_id = received_msg.msg_ids[0];

    let message = Message::load_from_db(&t, msg_id).await?;
    assert!(message.get_showpadlock());

    let alice_id = message.from_id;
    let alice_contact = Contact::get_by_id(&t, alice_id).await?;
    assert!(alice_contact.is_key_contact());

    // The message without the Autocrypt header
    // cannot be assigned to the contact even if it
    // is encrypted and signed.
    //
    // This could be fixed by looking up
    // the key by the issuer fingerprint
    // which is present in the detached signature,
    // but this is not done yet.
    let raw = include_bytes!("../../test-data/message/thunderbird_encrypted_signed.eml");
    let received_msg = receive_imf(&t, raw, false).await?.unwrap();

    assert_eq!(received_msg.msg_ids.len(), 1);
    let msg_id = received_msg.msg_ids[0];

    let message = Message::load_from_db(&t, msg_id).await?;
    assert!(!message.get_showpadlock());

    let alice_email_id = message.from_id;
    assert_ne!(alice_email_id, alice_id);
    let alice_address_contact = Contact::get_by_id(&t, alice_email_id).await?;
    assert!(!alice_address_contact.is_key_contact());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forged_from_and_no_valid_signatures() -> Result<()> {
    let t = &TestContext::new_bob().await;
    let raw = include_bytes!("../../test-data/message/thunderbird_encrypted_signed.eml");
    let received_msg = receive_imf(t, raw, false).await?.unwrap();

    assert_eq!(received_msg.msg_ids.len(), 1);
    let msg_id = received_msg.msg_ids[0];
    let msg = Message::load_from_db(t, msg_id).await?;
    assert!(!msg.chat_id.is_trash());
    assert!(!msg.get_showpadlock());

    let t = &TestContext::new_bob().await;
    let raw = String::from_utf8(raw.to_vec())?.replace("alice@example.org", "clarice@example.org");
    let received_msg = receive_imf(t, raw.as_bytes(), false).await?.unwrap();
    assert!(received_msg.chat_id.is_trash());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wrong_from_name_and_no_valid_signatures() -> Result<()> {
    let t = &TestContext::new_bob().await;
    let raw = include_bytes!("../../test-data/message/thunderbird_encrypted_signed.eml");
    let raw = String::from_utf8(raw.to_vec())?.replace("From: Alice", "From: A");
    receive_imf(t, raw.as_bytes(), false).await?.unwrap();
    let msg = t.get_last_msg().await;
    assert!(!msg.chat_id.is_trash());
    assert!(!msg.get_showpadlock());
    let contact = Contact::get_by_id(t, msg.from_id).await?;
    assert_eq!(contact.get_authname(), "Alice");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_thunderbird_autocrypt_unencrypted() -> Result<()> {
    let bob = &TestContext::new_bob().await;

    // Thunderbird message with Autocrypt header and a signature,
    // but not encrypted.
    let raw = include_bytes!("../../test-data/message/thunderbird_with_autocrypt_unencrypted.eml");
    let received_msg = receive_imf(bob, raw, false).await?.unwrap();

    assert_eq!(received_msg.msg_ids.len(), 1);
    let msg_id = received_msg.msg_ids[0];
    let msg = Message::load_from_db(bob, msg_id).await?;
    assert!(!msg.get_showpadlock());

    // The message should arrive as address-contact
    let alice_id = msg.from_id;
    let alice_contact = Contact::get_by_id(bob, alice_id).await?;
    assert!(!alice_contact.is_key_contact());

    let raw = include_bytes!("../../test-data/message/thunderbird_signed_unencrypted.eml");
    let received_msg = receive_imf(bob, raw, false).await?.unwrap();

    assert_eq!(received_msg.msg_ids.len(), 1);
    let msg_id = received_msg.msg_ids[0];
    let msg = Message::load_from_db(bob, msg_id).await?;
    assert!(!msg.get_showpadlock());

    let alice_id = msg.from_id;
    let alice_contact = Contact::get_by_id(bob, alice_id).await?;
    assert!(!alice_contact.is_key_contact());

    Ok(())
}

/// Alice receives an encrypted, but unsigned message.
///
/// Test that the message is displayed without any errors,
/// but also without a padlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_thunderbird_unsigned() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Alice receives an unsigned message from Bob.
    let raw = include_bytes!("../../test-data/message/thunderbird_encrypted_unsigned.eml");
    receive_imf(&alice, raw, false).await?.unwrap();

    let msg = alice.get_last_msg().await;
    assert!(!msg.get_showpadlock());
    assert!(msg.error().is_none());

    Ok(())
}

/// Bob receives an encrypted unsigned message with only an unencrypted Subject.
///
/// Test that the message is displayed without any errors,
/// but also without a padlock, but with the Subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_thunderbird_unsigned_with_unencrypted_subject() -> Result<()> {
    let bob = TestContext::new_bob().await;

    let raw = include_bytes!(
        "../../test-data/message/thunderbird_encrypted_unsigned_with_unencrypted_subject.eml"
    );
    receive_imf(&bob, raw, false).await?;

    let msg = bob.get_last_msg().await;
    assert!(!msg.get_showpadlock());
    assert!(msg.error().is_none());
    assert_eq!(msg.get_subject(), "Hello!");

    Ok(())
}

/// Tests that DC takes the correct Message-ID from the encrypted message part, not the unencrypted
/// one messed up by the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_messed_up_message_id() -> Result<()> {
    let t = TestContext::new_bob().await;

    let raw = include_bytes!("../../test-data/message/messed_up_message_id.eml");
    receive_imf(&t, raw, false).await?;
    assert_eq!(
        t.get_last_msg().await.rfc724_mid,
        "0bb9ffe1-2596-d997-95b4-1fef8cc4808e@example.org"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_big_forwarded_with_big_attachment() -> Result<()> {
    let t = &TestContext::new_bob().await;

    let raw = include_bytes!("../../test-data/message/big_forwarded_with_big_attachment.eml");
    let rcvd = receive_imf(t, raw, false).await?.unwrap();
    assert_eq!(rcvd.msg_ids.len(), 3);

    let msg = Message::load_from_db(t, rcvd.msg_ids[0]).await?;
    assert_eq!(msg.get_viewtype(), Viewtype::Text);
    assert_eq!(msg.get_text(), "Hello!");
    assert!(!msg.has_html());

    let msg = Message::load_from_db(t, rcvd.msg_ids[1]).await?;
    assert_eq!(msg.get_viewtype(), Viewtype::Text);
    assert!(
        msg.get_text()
            .starts_with("this text with 42 chars is just repeated.")
    );
    assert!(msg.get_text().ends_with("[...]"));
    assert!(!msg.has_html());

    let msg = Message::load_from_db(t, rcvd.msg_ids[2]).await?;
    assert_eq!(msg.get_viewtype(), Viewtype::File);
    assert!(msg.has_html());
    let html = msg.id.get_html(t).await?.unwrap();
    let tail = html
        .split_once("Hello!")
        .unwrap()
        .1
        .split_once("From: AAA")
        .unwrap()
        .1
        .split_once("aaa@example.org")
        .unwrap()
        .1
        .split_once("To: Alice")
        .unwrap()
        .1
        .split_once("alice@example.org")
        .unwrap()
        .1
        .split_once("Subject: Some subject")
        .unwrap()
        .1
        .split_once("Date: Fri, 2 Jun 2023 12:29:17 +0000")
        .unwrap()
        .1;
    assert_eq!(
        tail.matches("this text with 42 chars is just repeated.")
            .count(),
        128
    );
    Ok(())
}

/// Tests that MUA user can add members to ad-hoc group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mua_user_adds_member() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        b"From: alice@example.org\n\
          To: bob@example.com, charlie@example.net\n\
          Subject: foo\n\
          Message-ID: <Gr.gggroupiddd.12345678901@example.com>\n\
          Chat-Version: 1.0\n\
          Chat-Group-ID: gggroupiddd\n\
          Chat-Group-Name: foo\n\
          Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
          \n\
          hello\n",
        false,
    )
    .await?
    .unwrap();

    let msg = receive_imf(
        &t,
        b"From: bob@example.com\n\
          To: alice@example.org, charlie@example.net, fiona@example.net\n\
          Subject: foo\n\
          Message-ID: <raaaaandoooooooooommmm@example.com>\n\
          In-Reply-To: Gr.gggroupiddd.12345678901@example.com\n\
          Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
          \n\
          hello\n",
        false,
    )
    .await?
    .unwrap();

    let chat_id = msg.chat_id;
    let mut actual_chat_contacts = chat::get_chat_contacts(&t, chat_id).await?;
    actual_chat_contacts.sort();
    let mut expected_chat_contacts = vec![
        Contact::create(&t, "", "bob@example.com").await?,
        Contact::create(&t, "", "charlie@example.net").await?,
        Contact::create(&t, "", "fiona@example.net").await?,
        ContactId::SELF,
    ];
    expected_chat_contacts.sort();
    assert_eq!(actual_chat_contacts, expected_chat_contacts);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mua_user_adds_recipient_to_single_chat() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Alice sends a 1:1 message to Bob, creating a 1:1 chat.
    let msg = receive_imf(
        &alice,
        b"Subject: =?utf-8?q?Message_from_alice=40example=2Eorg?=\r\n\
            From: alice@example.org\r\n\
            To: <bob@example.net>\r\n\
            Date: Mon, 12 Dec 2022 14:30:39 +0000\r\n\
            Message-ID: <Mr.alices_original_mail@example.org>\r\n\
            Chat-Version: 1.0\r\n\
            \r\n\
            tst\r\n",
        false,
    )
    .await?
    .unwrap();
    let single_chat = Chat::load_from_db(&alice, msg.chat_id).await?;
    assert_eq!(single_chat.typ, Chattype::Single);

    // Bob uses a classical MUA to answer in the 1:1 chat.
    let msg2 = receive_imf(
        &alice,
        b"Subject: Re: Message from alice\r\n\
            From: <bob@example.net>\r\n\
            To: <alice@example.org>\r\n\
            Date: Mon, 12 Dec 2022 14:31:39 +0000\r\n\
            Message-ID: <bobs_private_answer@example.net>\r\n\
            In-Reply-To: <Mr.alices_original_mail@example.org>\r\n\
            \r\n\
            Hi back!\r\n",
        false,
    )
    .await?
    .unwrap();
    assert_eq!(msg2.chat_id, single_chat.id);

    // Bob uses a classical MUA to answer again, this time adding a recipient.
    // This message should go to a newly created ad-hoc group.
    let msg3 = receive_imf(
        &alice,
        b"Subject: Re: Message from alice\r\n\
            From: <bob@example.net>\r\n\
            To: <alice@example.org>, <claire@example.org>\r\n\
            Date: Mon, 12 Dec 2022 14:32:39 +0000\r\n\
            Message-ID: <bobs_answer_to_two_recipients@example.net>\r\n\
            In-Reply-To: <Mr.alices_original_mail@example.org>\r\n\
            \r\n\
            Hi back!\r\n",
        false,
    )
    .await?
    .unwrap();
    assert_ne!(msg3.chat_id, single_chat.id);
    let group_chat = Chat::load_from_db(&alice, msg3.chat_id).await?;
    assert_eq!(group_chat.typ, Chattype::Group);
    assert_eq!(
        chat::get_chat_contacts(&alice, group_chat.id).await?.len(),
        3
    );

    // Bob uses a classical MUA to answer once more, adding another recipient.
    // This new recipient should also be added to the group.
    let msg4 = receive_imf(
        &alice,
        b"Subject: Re: Message from alice\r\n\
            From: <bob@example.net>\r\n\
            To: <alice@example.org>, <claire@example.org>, <fiona@example.net>\r\n\
            Date: Mon, 12 Dec 2022 14:33:39 +0000\r\n\
            Message-ID: <69573857-542f-0fx3-55da-1289be5e0efe@example.net>\r\n\
            In-Reply-To: <bobs_answer_to_two_recipients@example.net>\r\n\
            \r\n\
            Hi back!\r\n",
        false,
    )
    .await?
    .unwrap();
    assert_eq!(msg4.chat_id, group_chat.id);
    assert_eq!(
        chat::get_chat_contacts(&alice, group_chat.id).await?.len(),
        4
    );
    let fiona_contact_id =
        Contact::lookup_id_by_addr(&alice, "fiona@example.net", Origin::IncomingTo)
            .await?
            .unwrap();
    assert!(chat::is_contact_in_chat(&alice, group_chat.id, fiona_contact_id).await?);
    let fiona_contact = Contact::get_by_id(&alice, fiona_contact_id).await?;
    assert_eq!(fiona_contact.is_key_contact(), false);

    Ok(())
}

/// If a message is Autocrypt-encrypted, unsigned Chat-Group-* headers have no effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unsigned_chat_group_hdr() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let bob_addr = bob.get_config(Config::Addr).await?.unwrap();
    let bob_id = alice.add_or_lookup_contact_id(bob).await;
    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "foos").await?;
    add_contact_to_chat(alice, alice_chat_id, bob_id).await?;
    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    let sent_msg = alice.pop_sent_msg().await;
    let bob_chat_id = bob.recv_msg(&sent_msg).await.chat_id;
    bob_chat_id.accept(bob).await?;
    send_text_msg(bob, bob_chat_id, "hi all!".to_string()).await?;
    let mut sent_msg = bob.pop_sent_msg().await;
    sent_msg.payload = sent_msg.payload.replace(
        "Chat-Version:",
        &format!("Chat-Group-Member-Removed: {bob_addr}\r\nChat-Version:"),
    );
    let chat_id = alice.recv_msg(&sent_msg).await.chat_id;
    assert_eq!(chat_id, alice_chat_id);
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ignore_protected_headers_in_outer_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let bob_chat_id = tcm.send_recv_accept(alice, bob, "hi").await.chat_id;
    send_text_msg(bob, bob_chat_id, "hi all!".to_string()).await?;
    let mut sent_msg = bob.pop_sent_msg().await;
    sent_msg.payload = sent_msg.payload.replace(
        "Chat-Version:",
        "Auto-Submitted: auto-generated\r\nChat-Version:",
    );
    alice.recv_msg(&sent_msg).await;
    let ab_contact = alice.add_or_lookup_contact(bob).await;
    assert!(!ab_contact.is_bot());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_member_list_on_rejoin() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let bob_id = alice.add_or_lookup_contact_id(bob).await;
    let fiona_id = alice.add_or_lookup_contact_id(fiona).await;

    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "foos").await?;
    add_contact_to_chat(alice, alice_chat_id, bob_id).await?;
    add_contact_to_chat(alice, alice_chat_id, fiona_id).await?;

    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    let add = alice.pop_sent_msg().await;
    bob.recv_msg(&add).await;
    let bob_chat_id = bob.get_last_msg().await.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 3);

    // remove bob from chat
    remove_contact_from_chat(alice, alice_chat_id, bob_id).await?;
    let remove_bob = alice.pop_sent_msg().await;
    bob.recv_msg(&remove_bob).await;

    // remove any other member
    remove_contact_from_chat(alice, alice_chat_id, fiona_id).await?;
    alice.pop_sent_msg().await;

    // re-add bob
    add_contact_to_chat(alice, alice_chat_id, bob_id).await?;
    let add2 = alice.pop_sent_msg().await;
    bob.recv_msg(&add2).await;

    // number of members in chat should have updated
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    Ok(())
}

/// Test for the bug when remote group membership changes from outdated messages overrode local
/// ones. Especially that was a problem when a message is sent offline so that it doesn't
/// incorporate recent group membership changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ignore_outdated_membership_changes() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_bob_id = alice.add_or_lookup_contact_id(bob).await;
    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "grp").await?;

    // Alice creates a group chat. Bob accepts it.
    add_contact_to_chat(alice, alice_chat_id, alice_bob_id).await?;
    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    let msg = &alice.pop_sent_msg().await;
    bob.recv_msg(msg).await;
    let bob_chat_id = bob.get_last_msg().await.chat_id;
    bob_chat_id.accept(bob).await?;

    // Bob replies.
    send_text_msg(bob, bob_chat_id, "i'm bob".to_string()).await?;
    let msg = &bob.pop_sent_msg().await;

    SystemTime::shift(Duration::from_secs(3600));

    // Alice leaves.
    remove_contact_from_chat(alice, alice_chat_id, ContactId::SELF).await?;
    alice.pop_sent_msg().await;
    assert!(!is_contact_in_chat(alice, alice_chat_id, ContactId::SELF).await?);

    // Alice receives Bob's message, but it's outdated to add Alice back.
    alice.recv_msg(msg).await;
    assert!(!is_contact_in_chat(alice, alice_chat_id, ContactId::SELF).await?);

    SystemTime::shift(Duration::from_secs(3600));

    // Bob replies again, even after some time this does not add Alice back.
    //
    // Bob cannot learn from Alice that Alice has left the group
    // because Alice is not going to send more messages to the group.
    send_text_msg(bob, bob_chat_id, "i'm bob".to_string()).await?;
    let msg = &bob.pop_sent_msg().await;
    alice.recv_msg(msg).await;

    assert!(!is_contact_in_chat(alice, alice_chat_id, ContactId::SELF).await?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_recreate_contacts_on_add_remove() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let charlie = &tcm.charlie().await;

    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;

    add_contact_to_chat(
        alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(bob).await,
    )
    .await?;

    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    let bob_chat_id = bob.recv_msg(&alice.pop_sent_msg().await).await.chat_id;
    bob_chat_id.accept(bob).await?;

    // alice adds a member
    add_contact_to_chat(
        alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(fiona).await,
    )
    .await?;

    // Bob adds a member.
    let bob_charlie = bob.add_or_lookup_contact_id(charlie).await;
    add_contact_to_chat(bob, bob_chat_id, bob_charlie).await?;

    alice.recv_msg(&bob.pop_sent_msg().await).await;

    // Bob didn't receive the addition of Fiona, but Alice mustn't remove Fiona from the members
    // list back. Instead, Bob must add Fiona from the next Alice's message to make their group
    // members view consistent.
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 4);

    // Just a dumb check for remove_contact_from_chat(). Let's have it in this only place.
    remove_contact_from_chat(bob, bob_chat_id, bob_charlie).await?;
    alice.recv_msg(&bob.pop_sent_msg().await).await;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 3);

    SystemTime::shift(Duration::from_secs(3600));
    send_text_msg(alice, alice_chat_id, "Finally add Fiona please".to_string()).await?;
    bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 3);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delayed_removal_is_ignored() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;
    let alice_bob = alice.add_or_lookup_contact_id(bob).await;
    let alice_fiona = alice.add_or_lookup_contact_id(fiona).await;
    // create chat with three members
    add_to_chat_contacts_table(alice, time(), chat_id, &[alice_bob, alice_fiona]).await?;

    send_text_msg(alice, chat_id, "populate".to_string()).await?;
    let bob_chat_id = bob.recv_msg(&alice.pop_sent_msg().await).await.chat_id;
    bob_chat_id.accept(bob).await?;

    // Bob removes Fiona.
    let bob_contact_fiona = bob.add_or_lookup_contact_id(fiona).await;
    remove_contact_from_chat(bob, bob_chat_id, bob_contact_fiona).await?;
    let remove_msg = bob.pop_sent_msg().await;

    // Bob adds new members Dom and Elena, but first addition message is lost.
    let dom = &tcm.dom().await;
    let elena = &tcm.elena().await;
    let bob_dom = bob.add_or_lookup_contact_id(dom).await;
    add_contact_to_chat(bob, bob_chat_id, bob_dom).await?;
    bob.pop_sent_msg().await;
    let bob_elena = bob.add_or_lookup_contact_id(elena).await;
    add_contact_to_chat(bob, bob_chat_id, bob_elena).await?;
    let add_msg = bob.pop_sent_msg().await;

    // Alice only receives the second member addition,
    // but this results in addition of both members
    // and removal of Fiona.
    alice.recv_msg(&add_msg).await;
    assert_eq!(get_chat_contacts(alice, chat_id).await?.len(), 4);

    // Alice re-adds Fiona.
    add_contact_to_chat(alice, chat_id, alice_fiona).await?;
    assert_eq!(get_chat_contacts(alice, chat_id).await?.len(), 5);

    // Delayed removal of Fiona by Bob shouldn't remove her.
    alice.recv_msg(&remove_msg).await;
    assert_eq!(get_chat_contacts(alice, chat_id).await?.len(), 5);

    alice
        .golden_test_chat(chat_id, "receive_imf_delayed_removal_is_ignored")
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_readd_with_normal_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;

    add_contact_to_chat(
        alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(bob).await,
    )
    .await?;

    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    let bob_chat_id = bob.recv_msg(&alice.pop_sent_msg().await).await.chat_id;
    bob_chat_id.accept(bob).await?;

    // Bob leaves, but Alice didn't receive Bob's leave message.
    remove_contact_from_chat(bob, bob_chat_id, ContactId::SELF).await?;
    bob.pop_sent_msg().await;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 1);

    SystemTime::shift(Duration::from_secs(3600));
    add_contact_to_chat(
        alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(fiona).await,
    )
    .await?;
    bob.recv_msg(&alice.pop_sent_msg().await).await;

    // Bob received a message from Alice, but this should not re-add him to the group.
    assert!(!is_contact_in_chat(bob, bob_chat_id, ContactId::SELF).await?);

    // Bob got an update that Fiona is added nevertheless.
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mua_cant_remove() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let now = time();

    // Alice creates chat with 3 contacts
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(now - 2000, 0)
        .unwrap()
        .to_rfc2822();
    let msg = receive_imf(
        &alice,
        format!(
            "Subject: =?utf-8?q?Message_from_alice=40example=2Eorg?=\r\n\
             From: alice@example.org\r\n\
             To: <bob@example.net>, <claire@example.org>, <fiona@example.org> \r\n\
            Date: {date}\r\n\
             Message-ID: <Mr.alices_original_mail@example.org>\r\n\
             Chat-Version: 1.0\r\n\
             \r\n\
            tst\r\n"
        )
        .as_bytes(),
        false,
    )
    .await?
    .unwrap();
    let alice_chat = Chat::load_from_db(&alice, msg.chat_id).await?;
    assert_eq!(alice_chat.typ, Chattype::Group);
    assert_eq!(alice_chat.member_list_is_stale(&alice).await?, false);

    // Bob uses a classical MUA to answer, removing a recipient.
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(now - 1000, 0)
        .unwrap()
        .to_rfc2822();
    let bob_removes = receive_imf(
        &alice,
        format!(
            "Subject: Re: Message from alice\r\n\
             From: <bob@example.net>\r\n\
             To: <alice@example.org>, <claire@example.org>\r\n\
            Date: {date}\r\n\
             Message-ID: <bobs_answer_to_two_recipients@example.net>\r\n\
             In-Reply-To: <Mr.alices_original_mail@example.org>\r\n\
             \r\n\
            Hi back!\r\n"
        )
        .as_bytes(),
        false,
    )
    .await?
    .unwrap();
    assert_eq!(bob_removes.chat_id, alice_chat.id);
    let group_chat = Chat::load_from_db(&alice, bob_removes.chat_id).await?;
    assert_eq!(group_chat.typ, Chattype::Group);
    assert_eq!(group_chat.member_list_is_stale(&alice).await?, false);
    assert_eq!(
        chat::get_chat_contacts(&alice, group_chat.id).await?.len(),
        4
    );

    // But if the parent message is missing, the message must goto a new ad-hoc group.
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(now, 0)
        .unwrap()
        .to_rfc2822();
    let bob_removes = receive_imf(
        &alice,
        format!(
            "Subject: Re: Message from alice\r\n\
             From: <bob@example.net>\r\n\
             To: <alice@example.org>, <claire@example.org>\r\n\
            Date: {date}\r\n\
             Message-ID: <bobs_answer_to_two_recipients_1@example.net>\r\n\
             In-Reply-To: <Mr.missing@example.org>\r\n\
             \r\n\
            Hi back!\r\n"
        )
        .as_bytes(),
        false,
    )
    .await?
    .unwrap();
    assert_ne!(bob_removes.chat_id, alice_chat.id);
    let group_chat = Chat::load_from_db(&alice, bob_removes.chat_id).await?;
    assert_eq!(group_chat.typ, Chattype::Group);
    assert_eq!(
        chat::get_chat_contacts(&alice, group_chat.id).await?.len(),
        3,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mua_can_add() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let now = time();

    // Alice creates chat with 3 contacts
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(now - 2000, 0)
        .unwrap()
        .to_rfc2822();
    let msg = receive_imf(
        &alice,
        format!(
            "Subject: =?utf-8?q?Message_from_alice=40example=2Eorg?=\r\n\
             From: alice@example.org\r\n\
             To: <bob@example.net>, <claire@example.org>, <fiona@example.org> \r\n\
            Date: {date}\r\n\
             Message-ID: <Mr.alices_original_mail@example.org>\r\n\
             Chat-Version: 1.0\r\n\
             \r\n\
            Hi!\r\n"
        )
        .as_bytes(),
        false,
    )
    .await?
    .unwrap();
    let alice_chat = Chat::load_from_db(&alice, msg.chat_id).await?;
    assert_eq!(alice_chat.typ, Chattype::Group);
    assert_eq!(alice_chat.member_list_is_stale(&alice).await?, false);

    // Bob uses a classical MUA to answer, adding a recipient.
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(now - 1000, 0)
        .unwrap()
        .to_rfc2822();
    let bob_adds = receive_imf(
         &alice,
        format!("Subject: Re: Message from alice\r\n\
             From: <bob@example.net>\r\n\
             To: <alice@example.org>, <claire@example.org>, <fiona@example.org>, <greg@example.host>\r\n\
            Date: {date}\r\n\
             Message-ID: <bobs_answer_to_two_recipients@example.net>\r\n\
             In-Reply-To: <Mr.alices_original_mail@example.org>\r\n\
             \r\n\
            Hi back!\r\n").as_bytes(),
         false,
     )
     .await?
     .unwrap();

    let group_chat = Chat::load_from_db(&alice, bob_adds.chat_id).await?;
    assert_eq!(group_chat.typ, Chattype::Group);
    assert_eq!(
        chat::get_chat_contacts(&alice, group_chat.id).await?.len(),
        5
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mua_can_readd() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Alice creates chat with 3 contacts.
    let msg = receive_imf(
        &alice,
        b"Subject: =?utf-8?q?Message_from_alice=40example=2Eorg?=\r\n\
            From: alice@example.org\r\n\
            To: <bob@example.net>, <claire@example.org>, <fiona@example.org> \r\n\
            Date: Mon, 12 Dec 2022 14:30:39 +0000\r\n\
            Message-ID: <Mr.alices_original_mail@example.org>\r\n\
            Chat-Version: 1.0\r\n\
            \r\n\
            Hi!\r\n",
        false,
    )
    .await?
    .unwrap();
    let alice_chat = Chat::load_from_db(&alice, msg.chat_id).await?;
    assert_eq!(alice_chat.typ, Chattype::Group);
    assert!(is_contact_in_chat(&alice, alice_chat.id, ContactId::SELF).await?);

    // And leaves it.
    remove_contact_from_chat(&alice, alice_chat.id, ContactId::SELF).await?;
    alice.pop_sent_msg().await;
    assert!(!is_contact_in_chat(&alice, alice_chat.id, ContactId::SELF).await?);

    // Bob uses a classical MUA to answer, adding Alice back.
    receive_imf(
        &alice,
        b"Subject: Re: Message from alice\r\n\
            From: <bob@example.net>\r\n\
            To: <alice@example.org>, <claire@example.org>, <fiona@example.org>\r\n\
            Date: Mon, 12 Dec 3000 14:32:39 +0000\r\n\
            Message-ID: <bobs_answer_to_two_recipients@example.net>\r\n\
            In-Reply-To: <Mr.alices_original_mail@example.org>\r\n\
            \r\n\
            Hi back!\r\n",
        false,
    )
    .await?
    .unwrap();
    assert!(is_contact_in_chat(&alice, alice_chat.id, ContactId::SELF).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_member_left_does_not_create_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;
    add_contact_to_chat(
        alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(bob).await,
    )
    .await?;
    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    alice.pop_sent_msg().await;

    // Bob only received a message of Alice leaving the group.
    // This should not create the group.
    //
    // The reason is to avoid recreating deleted chats,
    // especially the chats that were created due to "split group" bugs
    // which some members simply deleted and some members left,
    // recreating the chat for others.
    remove_contact_from_chat(alice, alice_chat_id, ContactId::SELF).await?;
    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_recreate_member_list_on_missing_add_of_self() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;
    add_contact_to_chat(
        alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(bob).await,
    )
    .await?;
    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    alice.pop_sent_msg().await;

    send_text_msg(alice, alice_chat_id, "second message".to_string()).await?;

    let bob_chat_id = bob.recv_msg(&alice.pop_sent_msg().await).await.chat_id;
    assert!(!bob_chat_id.is_special());

    // Bob missed the message adding them, but must recreate the member list.
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    assert!(is_contact_in_chat(bob, bob_chat_id, ContactId::SELF).await?);

    // But if Bob just left, they mustn't recreate the member list even after missing a message.
    bob_chat_id.accept(bob).await?;
    remove_contact_from_chat(bob, bob_chat_id, ContactId::SELF).await?;
    bob.pop_sent_msg().await;
    send_text_msg(alice, alice_chat_id, "3rd message".to_string()).await?;
    alice.pop_sent_msg().await;
    send_text_msg(alice, alice_chat_id, "4th message".to_string()).await?;
    bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert!(!is_contact_in_chat(bob, bob_chat_id, ContactId::SELF).await?);

    // Even if some time passed, Bob must not be re-added back.
    SystemTime::shift(Duration::from_secs(3600));
    send_text_msg(alice, alice_chat_id, "5th message".to_string()).await?;
    alice.pop_sent_msg().await;
    send_text_msg(alice, alice_chat_id, "6th message".to_string()).await?;
    bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert!(!is_contact_in_chat(bob, bob_chat_id, ContactId::SELF).await?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keep_member_list_if_possibly_nomember() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "Group").await?;
    add_contact_to_chat(
        &alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(&bob).await,
    )
    .await?;
    send_text_msg(&alice, alice_chat_id, "populate".to_string()).await?;
    let bob_chat_id = bob.recv_msg(&alice.pop_sent_msg().await).await.chat_id;

    let fiona = TestContext::new_fiona().await;
    add_contact_to_chat(
        &alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(&fiona).await,
    )
    .await?;
    let fiona_chat_id = fiona.recv_msg(&alice.pop_sent_msg().await).await.chat_id;
    fiona_chat_id.accept(&fiona).await?;

    SystemTime::shift(Duration::from_secs(60));
    chat::set_chat_name(&fiona, fiona_chat_id, "Renamed").await?;
    bob.recv_msg(&fiona.pop_sent_msg().await).await;

    // Bob missed the message adding fiona, but mustn't recreate the member list or apply the group
    // name change.
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 2);
    assert!(is_contact_in_chat(&bob, bob_chat_id, ContactId::SELF).await?);
    let bob_alice_contact = bob.add_or_lookup_contact_id(&alice).await;
    assert!(is_contact_in_chat(&bob, bob_chat_id, bob_alice_contact).await?);
    let chat = Chat::load_from_db(&bob, bob_chat_id).await?;
    assert_eq!(chat.get_name(), "Group");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_grp_name_no_prefix() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let chat_id = receive_imf(
        alice,
        b"Subject: Re: Once upon a time this was with the only Re: here\n\
          From: <bob@example.net>\n\
          To: <claire@example.org>, <alice@example.org>\n\
          Date: Mon, 12 Dec 3000 14:32:39 +0000\n\
          Message-ID: <thisone@example.net>\n\
          In-Reply-To: <previous@example.net>\n\
          \n\
          Adding Alice the Delta Chat lover",
        false,
    )
    .await?
    .unwrap()
    .chat_id;
    let chat = Chat::load_from_db(alice, chat_id).await.unwrap();
    assert_eq!(
        chat.get_name(),
        "Once upon a time this was with the only Re: here"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_download_later() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    alice.set_config(Config::DownloadLimit, Some("1")).await?;
    assert_eq!(alice.download_limit().await?, Some(MIN_DOWNLOAD_LIMIT));

    let bob = tcm.bob().await;
    let bob_chat = bob.create_chat(&alice).await;

    // Generate a random string so OpenPGP does not compress it.
    let text: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(MIN_DOWNLOAD_LIMIT as usize)
        .map(char::from)
        .collect();

    let sent_msg = bob.send_text(bob_chat.id, &text).await;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_eq!(msg.state, MessageState::InFresh);

    let hi_msg = tcm.send_recv(&bob, &alice, "hi").await;

    alice.set_config(Config::DownloadLimit, None).await?;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_eq!(msg.state, MessageState::InFresh);
    assert_eq!(alice.get_last_msg_in(msg.chat_id).await.id, hi_msg.id);
    assert!(msg.timestamp_sort <= hi_msg.timestamp_sort);

    Ok(())
}

/// Malice can pretend they have the same address as Alice and sends a message encrypted to Alice's
/// key but signed with another one. Alice must detect that this message is wrongly signed and not
/// treat it as Autocrypt-encrypted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_msg_forgery() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let export_dir = tempfile::tempdir().unwrap();
    let alice = &tcm.alice().await;
    let alice_addr = &alice.get_config(Config::Addr).await?.unwrap();
    imex(alice, ImexMode::ExportSelfKeys, export_dir.path(), None).await?;
    // We need Bob only to encrypt the forged message to Alice's key, actually Bob doesn't
    // participate in the scenario.
    let bob = &TestContext::new().await;
    assert_eq!(crate::key::load_self_secret_keyring(bob).await?.len(), 0);
    bob.configure_addr("bob@example.net").await;
    imex(bob, ImexMode::ImportSelfKeys, export_dir.path(), None).await?;
    assert_eq!(crate::key::load_self_secret_keyring(bob).await?.len(), 1);
    let malice = &TestContext::new().await;
    malice.configure_addr(alice_addr).await;

    let malice_chat_id = tcm
        .send_recv_accept(bob, malice, "hi from bob")
        .await
        .chat_id;
    assert_eq!(crate::key::load_self_secret_keyring(bob).await?.len(), 1);

    let sent_msg = malice.send_text(malice_chat_id, "hi from malice").await;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.state, MessageState::OutDelivered);
    assert!(!msg.get_showpadlock());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_group_with_big_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let ba_contact = bob.add_or_lookup_contact_id(&alice).await;
    let ab_chat_id = alice.create_chat(&bob).await.id;

    let file_bytes = include_bytes!("../../test-data/image/screenshot.png");

    let bob_grp_id = create_group_chat(&bob, ProtectionStatus::Unprotected, "Group").await?;
    add_contact_to_chat(&bob, bob_grp_id, ba_contact).await?;
    let mut msg = Message::new(Viewtype::Image);
    msg.set_file_from_bytes(&bob, "a.jpg", file_bytes, None)?;
    let sent_msg = bob.send_msg(bob_grp_id, &mut msg).await;
    assert!(msg.get_showpadlock());

    alice.set_config(Config::DownloadLimit, Some("1")).await?;
    assert_eq!(alice.download_limit().await?, Some(MIN_DOWNLOAD_LIMIT));
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    let alice_chat = Chat::load_from_db(&alice, msg.chat_id).await?;
    // Incomplete message is assigned to 1:1 chat.
    assert_eq!(alice_chat.typ, Chattype::Single);

    alice.set_config(Config::DownloadLimit, None).await?;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_eq!(msg.state, MessageState::InFresh);
    assert_eq!(msg.viewtype, Viewtype::Image);
    assert_ne!(msg.chat_id, alice_chat.id);
    let alice_grp = Chat::load_from_db(&alice, msg.chat_id).await?;
    assert_eq!(alice_grp.typ, Chattype::Group);
    assert_eq!(alice_grp.name, "Group");
    assert_eq!(
        chat::get_chat_contacts(&alice, alice_grp.id).await?.len(),
        2
    );

    // Now Bob can send encrypted messages to Alice.

    let bob_grp_id = create_group_chat(&bob, ProtectionStatus::Unprotected, "Group1").await?;
    add_contact_to_chat(&bob, bob_grp_id, ba_contact).await?;
    let mut msg = Message::new(Viewtype::Image);
    msg.set_file_from_bytes(&bob, "a.jpg", file_bytes, None)?;
    let sent_msg = bob.send_msg(bob_grp_id, &mut msg).await;
    assert!(msg.get_showpadlock());

    alice.set_config(Config::DownloadLimit, Some("1")).await?;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Available);
    // Until fully downloaded, an encrypted message must sit in the 1:1 chat.
    assert_eq!(msg.chat_id, ab_chat_id);

    alice.set_config(Config::DownloadLimit, None).await?;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_eq!(msg.state, MessageState::InFresh);
    assert_eq!(msg.viewtype, Viewtype::Image);
    assert_ne!(msg.chat_id, ab_chat_id);
    let alice_grp = Chat::load_from_db(&alice, msg.chat_id).await?;
    assert_eq!(alice_grp.typ, Chattype::Group);
    assert_eq!(alice_grp.name, "Group1");
    assert_eq!(
        chat::get_chat_contacts(&alice, alice_grp.id).await?.len(),
        2
    );

    // The big message must go away from the 1:1 chat.
    let msgs = chat::get_chat_msgs(&alice, ab_chat_id).await?;
    assert_eq!(msgs.len(), E2EE_INFO_MSGS);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_partial_group_consistency() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;
    let bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let alice_chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "foos").await?;
    add_contact_to_chat(&alice, alice_chat_id, bob_id).await?;

    send_text_msg(&alice, alice_chat_id, "populate".to_string()).await?;
    let add = alice.pop_sent_msg().await;
    bob.recv_msg(&add).await;
    let bob_chat_id = bob.get_last_msg().await.chat_id;
    let contacts = get_chat_contacts(&bob, bob_chat_id).await?;
    assert_eq!(contacts.len(), 2);

    // Bob receives partial message.
    let msg_id = receive_imf_from_inbox(
        &bob,
        "first@example.org",
        b"From: Alice <alice@example.org>\n\
To: <bob@example.net>, <charlie@example.com>\n\
Chat-Version: 1.0\n\
Subject: subject\n\
Message-ID: <first@example.org>\n\
Date: Sun, 14 Nov 2021 00:10:00 +0000\
Content-Type: text/plain
Chat-Group-Member-Added: charlie@example.com",
        false,
        Some(100000),
    )
    .await?
    .context("no received message")?;

    let msg = Message::load_from_db(&bob, msg_id.msg_ids[0]).await?;

    // Partial download does not change the member list.
    assert_eq!(msg.download_state, DownloadState::Available);
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?, contacts);

    // Alice sends normal message to bob, adding fiona.
    add_contact_to_chat(
        &alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(&fiona).await,
    )
    .await?;

    bob.recv_msg(&alice.pop_sent_msg().await).await;

    let contacts = get_chat_contacts(&bob, bob_chat_id).await?;
    assert_eq!(contacts.len(), 3);

    // Bob fully receives the partial message.
    let msg_id = receive_imf_from_inbox(
        &bob,
        "first@example.org",
        b"From: Alice <alice@example.org>\n\
To: Bob <bob@example.net>\n\
Chat-Version: 1.0\n\
Subject: subject\n\
Message-ID: <first@example.org>\n\
Date: Sun, 14 Nov 2021 00:10:00 +0000\
Content-Type: text/plain
Chat-Group-Member-Added: charlie@example.com",
        false,
        None,
    )
    .await?
    .context("no received message")?;

    let msg = Message::load_from_db(&bob, msg_id.msg_ids[0]).await?;

    // After full download, the old message should not change group state.
    assert_eq!(msg.download_state, DownloadState::Done);
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?, contacts);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_protected_group_add_remove_member_missing_key() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    mark_as_verified(alice, bob).await;
    let group_id = create_group_chat(alice, ProtectionStatus::Protected, "Group").await?;
    let alice_bob_id = alice.add_or_lookup_contact(bob).await.id;
    add_contact_to_chat(alice, group_id, alice_bob_id).await?;
    alice.send_text(group_id, "Hello!").await;
    alice.sql.execute("DELETE FROM public_keys", ()).await?;

    let fiona = &tcm.fiona().await;
    mark_as_verified(alice, fiona).await;
    let alice_fiona_id = alice.add_or_lookup_contact(fiona).await.id;
    add_contact_to_chat(alice, group_id, alice_fiona_id).await?;

    // The message is not sent to Bob,
    // but member is added to the chat locally anyway.
    assert!(is_contact_in_chat(alice, group_id, alice_fiona_id).await?);
    let msg = alice.get_last_msg_in(group_id).await;
    assert!(msg.is_info());
    assert_eq!(
        msg.get_text(),
        stock_str::msg_add_member_local(alice, alice_fiona_id, ContactId::SELF).await
    );

    remove_contact_from_chat(alice, group_id, alice_bob_id).await?;
    assert!(!is_contact_in_chat(alice, group_id, alice_bob_id).await?);
    let msg = alice.get_last_msg_in(group_id).await;
    assert!(msg.is_info());
    assert_eq!(
        msg.get_text(),
        stock_str::msg_del_member_local(alice, alice_bob_id, ContactId::SELF).await
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_older_message_from_2nd_device() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let chat_id = alice
        .create_chat_with_contact("", "bob@example.net")
        .await
        .id;
    alice.send_text(chat_id, "We share this account").await;
    let received = receive_imf(
        alice,
        b"From: alice@example.org\n\
          To: bob@example.net\n\
          Message-ID: <1234-2-4@example.org>\n\
          Date: Sat, 07 Dec 1970 19:00:26 +0000\n\
          \n\
          I'm Alice too\n",
        true,
    )
    .await?
    .unwrap();
    alice
        .golden_test_chat(
            received.chat_id,
            "receive_imf_older_message_from_2nd_device",
        )
        .await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_create_adhoc_group_on_member_removal() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let bob = &tcm.bob().await;
    async fn get_chat_cnt(ctx: &Context) -> Result<usize> {
        ctx.sql
            .count("SELECT COUNT(*) FROM chats WHERE id>9", ())
            .await
    }
    let chat_cnt = get_chat_cnt(bob).await?;
    receive_imf(
        bob,
        b"From: Alice <alice@example.org>\n\
To: <bob@example.net>, <charlie@example.com>\n\
Chat-Version: 1.0\n\
Subject: subject\n\
Message-ID: <first@example.org>\n\
Date: Sun, 14 Nov 2021 00:10:00 +0000\
Content-Type: text/plain
Chat-Group-Member-Removed: charlie@example.com",
        false,
    )
    .await?;
    assert_eq!(get_chat_cnt(bob).await?, chat_cnt);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unarchive_on_member_removal() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let bob_id = alice.add_or_lookup_contact_id(bob).await;
    let fiona_id = alice.add_or_lookup_contact_id(fiona).await;
    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "foos").await?;
    add_contact_to_chat(alice, alice_chat_id, bob_id).await?;
    add_contact_to_chat(alice, alice_chat_id, fiona_id).await?;

    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    let msg = alice.pop_sent_msg().await;
    bob.recv_msg(&msg).await;
    let bob_chat_id = bob.get_last_msg().await.chat_id;
    bob_chat_id
        .set_visibility(bob, ChatVisibility::Archived)
        .await?;

    remove_contact_from_chat(alice, alice_chat_id, fiona_id).await?;
    let msg = alice.pop_sent_msg().await;
    bob.recv_msg(&msg).await;
    let bob_chat = Chat::load_from_db(bob, bob_chat_id).await?;
    assert_eq!(bob_chat.get_visibility(), ChatVisibility::Archived);

    remove_contact_from_chat(alice, alice_chat_id, bob_id).await?;
    let msg = alice.pop_sent_msg().await;
    bob.recv_msg(&msg).await;
    let bob_chat = Chat::load_from_db(bob, bob_chat_id).await?;
    assert_eq!(bob_chat.get_visibility(), ChatVisibility::Normal);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_op_member_added_is_trash() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    let alice_chat_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "foos", &[bob])
        .await;
    send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
    let msg = alice.pop_sent_msg().await;
    bob.recv_msg(&msg).await;
    let bob_chat_id = bob.get_last_msg().await.chat_id;
    bob_chat_id.accept(bob).await?;

    let fiona_id = alice.add_or_lookup_contact_id(fiona).await;
    add_contact_to_chat(alice, alice_chat_id, fiona_id).await?;
    let msg = alice.pop_sent_msg().await;

    let fiona_id = bob.add_or_lookup_contact_id(fiona).await;
    add_contact_to_chat(bob, bob_chat_id, fiona_id).await?;
    bob.recv_msg_trash(&msg).await;
    let contacts = get_chat_contacts(bob, bob_chat_id).await?;
    assert_eq!(contacts.len(), 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forged_from() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let bob_chat_id = tcm.send_recv_accept(&alice, &bob, "hi").await.chat_id;
    chat::send_text_msg(&bob, bob_chat_id, "hi!".to_string()).await?;

    let mut sent_msg = bob.pop_sent_msg().await;
    sent_msg.payload = sent_msg
        .payload
        .replace("bob@example.net", "notbob@example.net");

    let msg = alice.recv_msg_opt(&sent_msg).await;
    assert!(msg.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_multiline_iso_8859_1_subject() -> Result<()> {
    let t = &TestContext::new_alice().await;
    let mail = b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
        From: bob@example.com\n\
        To: alice@example.org, claire@example.com\n\
        Subject:\n \
        =?iso-8859-1?Q?Weihnachten_&_Silvester:_Feiern,_genie=DFen_&_entspannen_i?=\n \
        =?iso-8859-1?Q?nmitten_der_Weing=E4rten?=\n\
        Message-ID: <3333@example.com>\n\
        Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
        \n\
        hello\n";
    receive_imf(t, mail, false).await?;
    let msg = t.get_last_msg().await;
    assert_eq!(
        msg.get_subject(),
        "Weihnachten & Silvester: Feiern, genießen & entspannen inmitten der Weingärten"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_references() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.set_config_bool(Config::BccSelf, true).await?;

    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;
    alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    let sent = alice.pop_sent_msg().await;
    let bob_received_msg = bob.recv_msg(&sent).await;
    let bob_chat_id = bob_received_msg.chat_id;

    // Alice sends another three messages, but two of them are lost.
    let _sent = alice.send_text(alice_chat_id, "Second message").await;
    let _sent = alice.send_text(alice_chat_id, "Third message").await;

    // Message can still be assigned based on the `References` header.
    let sent = alice.send_text(alice_chat_id, "Fourth message").await;
    let bob_parsed_message = bob.parse_msg(&sent).await;
    let bob_parent_message = get_parent_message(bob, &bob_parsed_message).await?.unwrap();
    assert_eq!(bob_chat_id, bob_parent_message.chat_id);

    // If more messages are lost, message cannot be assigned to the correct chat
    // without `Chat-Group-ID` header, e.g. if the message is partially downloaded.
    let sent = alice.send_text(alice_chat_id, "Fifth message").await;
    let bob_parsed_message = bob.parse_msg(&sent).await;
    let bob_parent_message = get_parent_message(bob, &bob_parsed_message).await?;
    assert!(bob_parent_message.is_none());

    // When the message is received, it is assigned correctly because of `Chat-Group-ID` header.
    let bob_received_msg = bob.recv_msg(&sent).await;
    assert_eq!(bob_chat_id, bob_received_msg.chat_id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_prefer_references_to_downloaded_msgs() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    bob.set_config(Config::DownloadLimit, Some("1")).await?;
    let fiona = &tcm.fiona().await;
    let alice_bob_id = tcm.send_recv(bob, alice, "hi").await.from_id;
    let alice_fiona_id = tcm.send_recv(fiona, alice, "hi").await.from_id;
    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_id).await?;
    // W/o fiona the test doesn't work -- the last message is assigned to the 1:1 chat due to
    // `is_probably_private_reply()`.
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_id).await?;
    let sent = alice.send_text(alice_chat_id, "Hi").await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.download_state, DownloadState::Done);
    let bob_chat_id = received.chat_id;

    let file_bytes = include_bytes!("../../test-data/image/screenshot.gif");
    let mut msg = Message::new(Viewtype::File);
    msg.set_file_from_bytes(alice, "file", file_bytes, None)?;
    let mut sent = alice.send_msg(alice_chat_id, &mut msg).await;
    sent.payload = sent
        .payload
        .replace("References:", "X-Microsoft-Original-References:")
        .replace("In-Reply-To:", "X-Microsoft-Original-In-Reply-To:");
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.download_state, DownloadState::Available);
    assert_ne!(received.chat_id, bob_chat_id);
    assert_eq!(received.chat_id, bob.get_chat(alice).await.id);

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_from_bytes(alice, "file", file_bytes, None)?;
    let sent = alice.send_msg(alice_chat_id, &mut msg).await;
    let received = bob.recv_msg(&sent).await;
    assert_eq!(received.download_state, DownloadState::Available);
    assert_eq!(received.chat_id, bob_chat_id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_list_from() -> Result<()> {
    let t = &TestContext::new_alice().await;

    let raw = include_bytes!("../../test-data/message/list-from.eml");
    let received = receive_imf(t, raw, false).await?.unwrap();
    let msg = Message::load_from_db(t, *received.msg_ids.last().unwrap()).await?;
    assert_eq!(msg.get_override_sender_name().unwrap(), "ÖAMTC");
    let sender_contact = Contact::get_by_id(t, msg.from_id).await?;
    assert_eq!(
        sender_contact.get_display_name(),
        "clubinfo@donotreply.oeamtc.at"
    );
    let info = msg.id.get_info(t).await?;
    assert!(info.contains(" by ~ÖAMTC (clubinfo@donotreply.oeamtc.at)"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_vcard() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    async fn test(
        alice: &TestContext,
        bob: &TestContext,
        vcard_contains_address: bool,
        viewtype: Viewtype,
    ) -> Result<()> {
        let mut msg = Message::new(viewtype);
        msg.set_file_from_bytes(
            alice,
            "claire.vcf",
            format!(
                "BEGIN:VCARD\n\
                VERSION:4.0\n\
                FN:Claire\n\
                {}\
                END:VCARD",
                if vcard_contains_address {
                    "EMAIL;TYPE=work:claire@example.org\n"
                } else {
                    ""
                }
            )
            .as_bytes(),
            None,
        )
        .unwrap();

        let alice_bob_chat = alice.create_chat(bob).await;
        let sent = alice.send_msg(alice_bob_chat.id, &mut msg).await;
        let rcvd = bob.recv_msg(&sent).await;
        let sent = Message::load_from_db(alice, sent.sender_msg_id).await?;

        if vcard_contains_address {
            assert_eq!(sent.viewtype, Viewtype::Vcard);
            assert_eq!(sent.get_summary_text(alice).await, "👤 Claire");
            assert_eq!(rcvd.viewtype, Viewtype::Vcard);
            assert_eq!(rcvd.get_summary_text(bob).await, "👤 Claire");
        } else {
            // VCards without an email address are not "deltachat contacts",
            // so they are shown as files
            assert_eq!(sent.viewtype, Viewtype::File);
            assert_eq!(rcvd.viewtype, Viewtype::File);
        }

        let vcard = tokio::fs::read(rcvd.get_file(bob).unwrap()).await?;
        let vcard = std::str::from_utf8(&vcard)?;
        let parsed = deltachat_contact_tools::parse_vcard(vcard);
        assert_eq!(parsed.len(), 1);
        if vcard_contains_address {
            assert_eq!(&parsed[0].addr, "claire@example.org");
        } else {
            assert_eq!(&parsed[0].addr, "");
        }
        Ok(())
    }

    for vcard_contains_address in [true, false] {
        for viewtype in [Viewtype::File, Viewtype::Vcard] {
            test(&alice, &bob, vcard_contains_address, viewtype).await?;
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_make_n_send_vcard() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let vcard = "BEGIN:VCARD\n\
         VERSION:4.0\n\
         FN:Claire\n\
         EMAIL;TYPE=work:claire@example.org\n\
         END:VCARD";
    let contact_ids = contact::import_vcard(alice, vcard).await?;
    assert_eq!(contact_ids.len(), 1);

    let mut msg = Message::new(Viewtype::File);
    msg.make_vcard(alice, &contact_ids).await?;

    let alice_bob_chat = alice.create_chat(bob).await;
    let sent = alice.send_msg(alice_bob_chat.id, &mut msg).await;
    let rcvd = bob.recv_msg(&sent).await;
    let sent = Message::load_from_db(alice, sent.sender_msg_id).await?;

    assert_eq!(sent.viewtype, Viewtype::Vcard);
    assert_eq!(sent.get_summary_text(alice).await, "👤 Claire");
    assert_eq!(rcvd.viewtype, Viewtype::Vcard);
    assert_eq!(rcvd.get_summary_text(bob).await, "👤 Claire");

    let vcard = tokio::fs::read(rcvd.get_file(bob).unwrap()).await?;
    let vcard = std::str::from_utf8(&vcard)?;
    let parsed = deltachat_contact_tools::parse_vcard(vcard);
    assert_eq!(parsed.len(), 1);
    assert_eq!(&parsed[0].addr, "claire@example.org");

    Ok(())
}

/// Tests that group is not created if the message
/// has no recipients even if it has unencrypted Chat-Group-ID.
///
/// Chat-Group-ID in unencrypted messages should be ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unencrypted_group_id_no_recipients() -> Result<()> {
    let t = &TestContext::new_alice().await;
    let raw = "From: alice@example.org
Subject: Group
Chat-Version: 1.0
Chat-Group-Name: Group
 name\u{202B}
Chat-Group-ID: GePFDkwEj2K
Message-ID: <foobar@localhost>

Hello!"
        .as_bytes();
    let received = receive_imf(t, raw, false).await?.unwrap();
    let msg = Message::load_from_db(t, *received.msg_ids.last().unwrap()).await?;
    let chat = Chat::load_from_db(t, msg.chat_id).await?;
    assert_eq!(chat.typ, Chattype::Single);

    // Check that the weird group name is sanitzied correctly:
    let mail = mailparse::parse_mail(raw).unwrap();
    assert_eq!(
        mail.headers
            .get_header(HeaderDef::ChatGroupName)
            .unwrap()
            .get_value_raw(),
        "Group\n name\u{202B}".as_bytes()
    );
    assert_eq!(chat.name, "Saved messages");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_group_name_with_newline() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat_id = create_group_chat(
        alice,
        ProtectionStatus::Unprotected,
        "Group\r\nwith\nnewlines",
    )
    .await?;
    add_contact_to_chat(alice, chat_id, alice.add_or_lookup_contact_id(bob).await).await?;
    send_text_msg(alice, chat_id, "populate".to_string()).await?;
    let bob_chat_id = bob.recv_msg(&alice.pop_sent_msg().await).await.chat_id;

    let chat = Chat::load_from_db(bob, bob_chat_id).await?;
    assert_eq!(chat.typ, Chattype::Group);
    assert_eq!(chat.name, "Group  with newlines");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rename_chat_on_missing_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await;
    let chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "Group").await?;
    add_to_chat_contacts_table(
        &alice,
        time(),
        chat_id,
        &[alice.add_or_lookup_contact_id(&bob).await],
    )
    .await?;
    send_text_msg(&alice, chat_id, "populate".to_string()).await?;
    let bob_chat_id = bob.recv_msg(&alice.pop_sent_msg().await).await.chat_id;
    bob_chat_id.accept(&bob).await?;

    // Bob changes the group name. NB: If Bob does this too fast, it's not guaranteed that his group
    // name wins because "Group-Name-Timestamp" may not increase.
    SystemTime::shift(Duration::from_secs(3600));
    chat::set_chat_name(&bob, bob_chat_id, "Renamed").await?;
    bob.pop_sent_msg().await;

    // Bob adds a new member.
    let bob_charlie = bob.add_or_lookup_contact_id(&charlie).await;
    add_contact_to_chat(&bob, bob_chat_id, bob_charlie).await?;
    let add_msg = bob.pop_sent_msg().await;

    // Alice only receives the member addition.
    alice.recv_msg(&add_msg).await;
    let chat = Chat::load_from_db(&alice, chat_id).await?;
    assert_eq!(chat.get_name(), "Renamed");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rename_chat_after_creating_invite() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    for populate_before_securejoin in [false, true] {
        let alice_chat_id = create_group_chat(alice, ProtectionStatus::Protected, "Group").await?;
        let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await?;

        SystemTime::shift(Duration::from_secs(60));
        chat::set_chat_name(alice, alice_chat_id, "Renamed").await?;
        if populate_before_securejoin {
            send_text_msg(alice, alice_chat_id, "populate".to_string()).await?;
            alice.pop_sent_msg().await;
        }

        let bob_chat_id = tcm.exec_securejoin_qr(bob, alice, &qr).await;
        let bob_chat = Chat::load_from_db(bob, bob_chat_id).await?;
        assert_eq!(bob_chat.get_name(), "Renamed");
    }
    Ok(())
}

/// Regression test for the bug
/// that resulted in an info message
/// about Bob addition to the group on Fiona's device.
///
/// There should be no info messages about implicit
/// member changes when we are added to the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_two_group_securejoins() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let group_id = chat::create_group_chat(alice, ProtectionStatus::Protected, "Group").await?;

    let qr = get_securejoin_qr(alice, Some(group_id)).await?;

    // Bob joins using QR code.
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    // Fiona joins using QR code.
    tcm.exec_securejoin_qr(fiona, alice, &qr).await;

    let fiona_chat_id = fiona.get_last_msg().await.chat_id;
    fiona
        .golden_test_chat(fiona_chat_id, "two_group_securejoins")
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unverified_member_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let alice_chat_id =
        chat::create_group_chat(alice, ProtectionStatus::Protected, "Group").await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await?;

    tcm.exec_securejoin_qr(bob, alice, &qr).await;
    tcm.exec_securejoin_qr(fiona, alice, &qr).await;

    let fiona_chat_id = fiona.get_last_msg().await.chat_id;
    let fiona_sent_msg = fiona.send_text(fiona_chat_id, "Hi").await;

    // The message is by non-verified member,
    // but the checks have been removed
    // and the message should be downloaded as usual.
    let bob_msg = bob.recv_msg(&fiona_sent_msg).await;
    assert_eq!(bob_msg.download_state, DownloadState::Done);
    assert_eq!(bob_msg.text, "Hi");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_reverify_by_self_on_outgoing_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let a0 = &tcm.alice().await;
    let a1 = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let bob_chat_id = chat::create_group_chat(bob, ProtectionStatus::Protected, "Group").await?;
    let qr = get_securejoin_qr(bob, Some(bob_chat_id)).await?;
    tcm.exec_securejoin_qr(fiona, bob, &qr).await;
    tcm.exec_securejoin_qr(a0, bob, &qr).await;
    tcm.exec_securejoin_qr(a1, bob, &qr).await;

    let a0_chat_id = a0.get_last_msg().await.chat_id;
    let a0_sent_msg = a0.send_text(a0_chat_id, "Hi").await;
    a1.recv_msg(&a0_sent_msg).await;
    let a1_bob_id = a1.add_or_lookup_contact_id(bob).await;
    let a1_fiona = a1.add_or_lookup_contact(fiona).await;
    assert_eq!(
        a1_fiona.get_verifier_id(a1).await?.unwrap().unwrap(),
        a1_bob_id
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sanitize_filename_in_received() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    let raw = b"Message-ID: Mr.XA6y3og8-az.WGbH9_dNcQx@testr
To: <tmp_5890965001269692@testrun.org>
From: \"=?utf-8?q??=\" <tmp_6272287793210918@testrun.org>
Content-Type: multipart/mixed; boundary=\"mwkNRwaJw1M5n2xcr2ODfAqvTjcj9Z\"


--mwkNRwaJw1M5n2xcr2ODfAqvTjcj9Z
Content-Type: text/plain; charset=utf-8

-- 
Sent with my Delta Chat Messenger: https://delta.chat

--mwkNRwaJw1M5n2xcr2ODfAqvTjcj9Z
Content-Type: text/html
Content-Disposition: attachment; filename=\"te\xE2\x80\xACst/../../test.H|TML\xE2\x80\xAC \"
Content-Transfer-Encoding: base64

PGh0bWw+PGJvZHk+dGV4dDwvYm9keT5kYXRh

--mwkNRwaJw1M5n2xcr2ODfAqvTjcj9Z--";

    let msg = receive_imf(alice, raw, false).await?.unwrap();
    let msg = Message::load_from_db(alice, msg.msg_ids[0]).await?;

    assert_eq!(msg.get_filename().unwrap(), "test.HTML");

    let blob = msg.param.get_file_blob(alice)?.unwrap();
    assert_eq!(blob.suffix().unwrap(), "html");

    Ok(())
}

/// Tests that address-contacts are not added into a group
/// with key-contacts by a plaintext reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_address_contact_added_into_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "Group", &[bob])
        .await;
    let bob_received_msg = bob
        .recv_msg(&alice.send_text(alice_chat_id, "Message").await)
        .await;
    let rfc724_mid = bob_received_msg.rfc724_mid;

    // Alice leaves the group so message from email address contact bob@example.com
    // does not fail the test for being non-member and is allowed to
    // modify the chat.
    remove_contact_from_chat(alice, alice_chat_id, ContactId::SELF).await?;

    // Wait 60 days so chatlist is stale.
    SystemTime::shift(Duration::from_secs(60 * 24 * 60 * 60 + 1));

    // Only Bob is the chat member.
    assert_eq!(
        chat::get_chat_contacts(alice, alice_chat_id).await?.len(),
        1
    );

    let msg = receive_imf(
        alice,
        format!(
            "From: bob@example.com\n\
          To: alice@example.net, charlie@example.net, fiona@example.net\n\
          Subject: foo\n\
          Message-ID: <something@example.com>\n\
          Chat-Version: 1.0\n\
          In-Reply-To: {rfc724_mid}\n\
          Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
          \n\
          Hello\n"
        )
        .as_bytes(),
        false,
    )
    .await?
    .unwrap();

    // Unencrypted message should not modify the chat member list.
    assert_eq!(
        chat::get_chat_contacts(alice, alice_chat_id).await?.len(),
        1
    );

    // Unencrypted message should not even be assigned to encrypted chat.
    assert_ne!(msg.chat_id, alice_chat_id);

    Ok(())
}

/// Tests that message is assigned to an ad hoc group
/// if the message has a `Chat-Group-ID` even
/// if there are only two members in a group.
///
/// Since key-contacts introduction all groups are encrypted,
/// but old versions running on other devices might still
/// create unencrypted groups.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_plaintext_two_member_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;

    let msg = receive_imf(
        alice,
        b"From: alice@example.org\n\
          To: bob@example.net\n\
          Subject: foo\n\
          Message-ID: <something@example.com>\n\
          Chat-Version: 1.0\n\
          Chat-Group-ID: 8ud29aridt29arid\n\
          Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
          \n\
          Hello\n",
        false,
    )
    .await?
    .unwrap();

    let chat = Chat::load_from_db(alice, msg.chat_id).await?;
    assert_eq!(chat.typ, Chattype::Group);

    Ok(())
}

/// Tests that large messages are assigned
/// to non-key-contacts if the type is not `multipart/encrypted`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_partial_download_key_contact_lookup() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // Create two chats with Alice, both with key-contact and email address contact.
    let encrypted_chat = bob.create_chat(alice).await;
    let unencrypted_chat = bob.create_email_chat(alice).await;

    let seen = false;
    let is_partial_download = Some(9999);
    let received = receive_imf_from_inbox(
        bob,
        "3333@example.org",
        b"From: alice@example.org\n\
        To: bob@example.net\n\
        Message-ID: <3333@example.org>\n\
        Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
        \n\
        hello\n",
        seen,
        is_partial_download,
    )
    .await?
    .unwrap();

    assert_ne!(received.chat_id, encrypted_chat.id);
    assert_eq!(received.chat_id, unencrypted_chat.id);

    Ok(())
}

/// Tests that outgoing unencrypted message
/// is assigned to a chat with email-contact.
///
/// Previously such message got assigned to Saved Messages
/// if it had In-Reply-To due to a bug resulting
/// in attempt to lookup key-contacts in the existing
/// chat pointed to by In-Reply-To.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_unencrypted_chat_assignment() {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Alice receives unencrypted message from Bob");
    receive_imf(
        alice,
        b"From: bob@example.net\n\
          To: alice@example.org\n\
          Subject: Message from Bob\n\
          Message-ID: <message@example.net>\n\
          Chat-Version: 1.0\n\
          Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
          \n\
          Hello, Alice!\n",
        false,
    )
    .await
    .unwrap()
    .unwrap();

    tcm.section("Alice sends unencrypted reply to Bob from another device");
    let received = receive_imf(
        alice,
        b"From: alice@example.org\n\
          To: bob@example.net\n\
          Subject: Message from Alice\n\
          Message-ID: <message@example.org>\n\
          Chat-Version: 1.0\n\
          In-Reply-To: <message@example.net>\n\
          Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
          \n\
          Hello, Bob!\n",
        false,
    )
    .await
    .unwrap()
    .unwrap();

    let chat = alice.create_email_chat(bob).await;
    assert_eq!(received.chat_id, chat.id);
}

/// Tests Bob receiving a message from Alice
/// in a new group she just created
/// with only Alice and Bob.
///
/// The message has no Autocrypt-Gossip
/// headers and no Chat-Group-Member-Fpr header.
/// Such messages were created by core 1.159.5
/// when Alice has bcc_self disabled
/// as Chat-Group-Member-Fpr header did not exist
/// yet and Autocrypt-Gossip is not sent
/// as there is only one recipient
/// (Bob, and no additional Alice devices).
///
/// Bob should recognize self as being
/// a member of the group by just the e-mail address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_group_introduction_no_gossip() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let bob = &tcm.bob().await;

    let received = receive_imf(
        bob,
        include_bytes!("../../test-data/message/group-introduction-no-gossip.eml"),
        false,
    )
    .await
    .unwrap()
    .unwrap();
    let msg = Message::load_from_db(bob, *received.msg_ids.last().unwrap())
        .await
        .unwrap();
    assert_eq!(msg.text, "I created a group");
    let chat = Chat::load_from_db(bob, msg.chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Group);
    assert_eq!(chat.blocked, Blocked::Request);
    assert_eq!(chat.name, "Group!");
    assert!(chat.is_encrypted(bob).await.unwrap());

    let contacts = get_chat_contacts(bob, chat.id).await?;
    assert_eq!(contacts.len(), 2);
    assert!(chat.is_self_in_chat(bob).await?);

    Ok(())
}

/// Tests reception of an encrypted group message
/// without Chat-Group-ID.
///
/// The message should be displayed as
/// encrypted and have key-contact `from_id`,
/// but all group members should be address-contacts.
///
/// Due to a bug in v2.10.0 this resulted
/// in creation of an ad hoc group with a key-contact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_encrypted_adhoc_group_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // Bob receives encrypted message from Alice
    // sent to multiple recipients,
    // but without a group ID.
    let received = receive_imf(
        bob,
        include_bytes!("../../test-data/message/encrypted-group-without-id.eml"),
        false,
    )
    .await?
    .unwrap();
    let msg = Message::load_from_db(bob, *received.msg_ids.last().unwrap())
        .await
        .unwrap();

    let chat = Chat::load_from_db(bob, msg.chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Group);
    assert_eq!(chat.is_encrypted(bob).await?, false);

    let contact_ids = get_chat_contacts(bob, chat.id).await?;
    assert_eq!(contact_ids.len(), 3);
    assert!(chat.is_self_in_chat(bob).await?);

    // Since the group is unencrypted, all contacts have
    // to be address-contacts.
    for contact_id in contact_ids {
        let contact = Contact::get_by_id(bob, contact_id).await?;
        if contact_id != ContactId::SELF {
            assert_eq!(contact.is_key_contact(), false);
        }
    }

    // `from_id` of the message corresponds to key-contact of Alice
    // even though the message is assigned to unencrypted chat.
    let alice_contact_id = bob.add_or_lookup_contact_id(alice).await;
    assert_eq!(msg.from_id, alice_contact_id);

    Ok(())
}

/// Tests that messages sent to unencrypted group
/// with only two members arrive in a group
/// and not in 1:1 chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_small_unencrypted_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat_id = chat::create_group_ex(alice, None, "Unencrypted group").await?;
    let alice_bob_id = alice.add_or_lookup_address_contact_id(bob).await;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_id).await?;
    send_text_msg(alice, alice_chat_id, "Hello!".to_string()).await?;

    let sent_msg = alice.pop_sent_msg().await;
    let bob_chat_id = bob.recv_msg(&sent_msg).await.chat_id;
    let bob_chat = Chat::load_from_db(bob, bob_chat_id).await?;

    assert_eq!(bob_chat.typ, Chattype::Group);
    assert_eq!(bob_chat.is_encrypted(bob).await?, false);

    bob_chat_id.accept(bob).await?;
    send_text_msg(bob, bob_chat_id, "Hello back!".to_string()).await?;
    let sent_msg = bob.pop_sent_msg().await;
    let alice_rcvd_msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(alice_rcvd_msg.chat_id, alice_chat_id);

    Ok(())
}

/// Tests that if the sender includes self
/// in the `To` field, we do not count
/// it as a third recipient in addition to ourselves
/// and the sender and do not create a group chat.
///
/// This is a regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_bcc_not_a_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;

    let received = receive_imf(
        alice,
        b"From: \"\"<foobar@example.org>\n\
          To: <foobar@example.org>\n\
          Subject: Hello, this is not a group\n\
          Message-ID: <abcdef@example.org>\n\
          Chat-Version: 1.0\n\
          Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
          \n\
          hello\n",
        false,
    )
    .await?
    .unwrap();

    let received_chat = Chat::load_from_db(alice, received.chat_id).await?;
    assert_eq!(received_chat.typ, Chattype::Single);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lookup_key_contact_by_address_self() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.alice().await;
    let addr = &t.get_config(Config::Addr).await?.unwrap();
    assert_eq!(
        lookup_key_contact_by_address(t, addr, None).await?,
        Some(ContactId::SELF)
    );
    Ok(())
}

/// Tests reception of multipart/alternative
/// with three parts, one of which is a calendar.
///
/// MS Exchange produces multipart/alternative
/// messages with three parts:
/// `text/plain`, `text/html` and `text/calendar`.
///
/// We display `text/plain` part in this case,
/// but .ics file is available as an attachment.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_calendar_alternative() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.alice().await;
    let raw = include_bytes!("../../test-data/message/calendar-alternative.eml");
    let msg = receive_imf(t, raw, false).await?.unwrap();
    assert_eq!(msg.msg_ids.len(), 1);

    let calendar_msg = Message::load_from_db(t, msg.msg_ids[0]).await?;
    assert_eq!(calendar_msg.text, "Subject was here – Hello!");
    assert_eq!(calendar_msg.viewtype, Viewtype::File);
    assert_eq!(calendar_msg.get_filename().unwrap(), "calendar.ics");

    assert!(calendar_msg.has_html());
    let html = calendar_msg.get_id().get_html(t).await.unwrap().unwrap();
    assert_eq!(html, "<b>Hello!</b>");

    Ok(())
}
