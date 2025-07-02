use deltachat_contact_tools::ContactAddress;
use mail_builder::headers::Header;
use mailparse::{MailHeaderMap, addrparse_header};
use std::str;

use super::*;
use crate::chat::{
    self, ChatId, ProtectionStatus, add_contact_to_chat, create_group_chat,
    remove_contact_from_chat, send_text_msg,
};
use crate::chatlist::Chatlist;
use crate::constants;
use crate::contact::Origin;
use crate::headerdef::HeaderDef;
use crate::message;
use crate::mimeparser::MimeMessage;
use crate::receive_imf::receive_imf;
use crate::test_utils::{TestContext, TestContextManager, get_chat_msg};

fn render_email_address(display_name: &str, addr: &str) -> String {
    let mut output = Vec::<u8>::new();
    new_address_with_name(display_name, addr.to_string())
        .unwrap_address()
        .write_header(&mut output, 0)
        .unwrap();

    String::from_utf8(output).unwrap()
}

#[test]
fn test_render_email_address() {
    let display_name = "ä space";
    let addr = "x@y.org";

    assert!(!display_name.is_ascii());
    assert!(
        !display_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ')
    );

    let s = render_email_address(display_name, addr);

    println!("{s}");

    assert_eq!(s, r#""=?utf-8?B?w6Qgc3BhY2U=?=" <x@y.org>"#);
}

#[test]
fn test_render_email_address_noescape() {
    let display_name = "a space";
    let addr = "x@y.org";

    assert!(display_name.is_ascii());
    assert!(
        display_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == ' ')
    );

    let s = render_email_address(display_name, addr);

    // Addresses should not be unnecessarily be encoded, see <https://github.com/deltachat/deltachat-core-rust/issues/1575>:
    assert_eq!(s, r#""a space" <x@y.org>"#);
}

#[test]
fn test_render_email_address_duplicated_as_name() {
    let addr = "x@y.org";
    let s = render_email_address(addr, addr);
    assert_eq!(s, "<x@y.org>");
}

#[test]
fn test_render_rfc724_mid() {
    assert_eq!(
        render_rfc724_mid("kqjwle123@qlwe"),
        "<kqjwle123@qlwe>".to_string()
    );
    assert_eq!(
        render_rfc724_mid("  kqjwle123@qlwe "),
        "<kqjwle123@qlwe>".to_string()
    );
    assert_eq!(
        render_rfc724_mid("<kqjwle123@qlwe>"),
        "<kqjwle123@qlwe>".to_string()
    );
}

fn render_header_text(text: &str) -> String {
    let mut output = Vec::<u8>::new();
    mail_builder::headers::text::Text::new(text.to_string())
        .write_header(&mut output, 0)
        .unwrap();

    String::from_utf8(output).unwrap()
}

#[test]
fn test_header_encoding() {
    assert_eq!(render_header_text("foobar"), "foobar\r\n");
    assert_eq!(render_header_text("-_.~%"), "-_.~%\r\n");
    assert_eq!(render_header_text("äöü"), "=?utf-8?B?w6TDtsO8?=\r\n");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_manually_set_subject() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat = t.create_chat_with_contact("bob", "bob@example.org").await;

    let mut msg = Message::new(Viewtype::Text);
    msg.set_subject("Subjeeeeect".to_string());

    let sent_msg = t.send_msg(chat.id, &mut msg).await;
    let payload = sent_msg.payload();

    assert_eq!(payload.match_indices("Subject: Subjeeeeect").count(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_subject_from_mua() {
    // 1.: Receive a mail from an MUA
    assert_eq!(
        msg_to_subject_str(
            b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                From: Bob <bob@example.com>\n\
                To: alice@example.org\n\
                Subject: Antw: Chat: hello\n\
                Message-ID: <2222@example.com>\n\
                Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
                \n\
                hello\n"
        )
        .await,
        "Re: Chat: hello"
    );

    assert_eq!(
        msg_to_subject_str(
            b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                From: Bob <bob@example.com>\n\
                To: alice@example.org\n\
                Subject: Infos: 42\n\
                Message-ID: <2222@example.com>\n\
                Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
                \n\
                hello\n"
        )
        .await,
        "Re: Infos: 42"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_subject_from_dc() {
    // 2. Receive a message from Delta Chat
    assert_eq!(
        msg_to_subject_str(
            b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                From: bob@example.com\n\
                To: alice@example.org\n\
                Subject: Chat: hello\n\
                Chat-Version: 1.0\n\
                Message-ID: <2223@example.com>\n\
                Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
                \n\
                hello\n"
        )
        .await,
        "Re: Chat: hello"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_subject_outgoing() {
    // 3. Send the first message to a new contact
    let t = TestContext::new_alice().await;

    assert_eq!(first_subject_str(t).await, "Message from alice@example.org");

    let t = TestContext::new_alice().await;
    t.set_config(Config::Displayname, Some("Alice"))
        .await
        .unwrap();
    assert_eq!(first_subject_str(t).await, "Message from Alice");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_subject_unicode() {
    // 4. Receive messages with unicode characters and make sure that we do not panic (we do not care about the result)
    msg_to_subject_str(
        "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
            From: bob@example.com\n\
            To: alice@example.org\n\
            Subject: äääää\n\
            Chat-Version: 1.0\n\
            Message-ID: <2893@example.com>\n\
            Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
            \n\
            hello\n"
            .as_bytes(),
    )
    .await;

    msg_to_subject_str(
        "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
            From: bob@example.com\n\
            To: alice@example.org\n\
            Subject: aäääää\n\
            Chat-Version: 1.0\n\
            Message-ID: <2893@example.com>\n\
            Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
            \n\
            hello\n"
            .as_bytes(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_subject_mdn() {
    // 5. Receive an mdn (read receipt) and make sure the mdn's subject is not used
    let t = TestContext::new_alice().await;
    receive_imf(
        &t,
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
            From: alice@example.org\n\
            To: bob@example.com\n\
            Subject: Hello, Bob\n\
            Chat-Version: 1.0\n\
            Message-ID: <2893@example.com>\n\
            Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
            \n\
            hello\n",
        false,
    )
    .await
    .unwrap();
    let mut new_msg = incoming_msg_to_reply_msg(
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: bob@example.com\n\
                 To: alice@example.org\n\
                 Subject: message opened\n\
                 Date: Sun, 22 Mar 2020 23:37:57 +0000\n\
                 Chat-Version: 1.0\n\
                 Message-ID: <Mr.12345678902@example.com>\n\
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
                 Original-Message-ID: <2893@example.com>\n\
                 Disposition: manual-action/MDN-sent-automatically; displayed\n\
                 \n", &t).await;
    chat::send_msg(&t, new_msg.chat_id, &mut new_msg)
        .await
        .unwrap();
    let mf = MimeFactory::from_msg(&t, new_msg).await.unwrap();
    // The subject string should not be "Re: message opened"
    assert_eq!("Re: Hello, Bob", mf.subject_str(&t).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mdn_create_encrypted() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    alice
        .set_config(Config::Displayname, Some("Alice Exampleorg"))
        .await?;
    let bob = tcm.bob().await;
    bob.set_config(Config::Displayname, Some("Bob Examplenet"))
        .await?;
    bob.set_config(Config::Selfstatus, Some("Bob Examplenet"))
        .await?;
    bob.set_config_bool(Config::MdnsEnabled, true).await?;

    let mut msg = Message::new(Viewtype::Text);
    msg.param.set_int(Param::SkipAutocrypt, 1);
    let chat_alice = alice.create_chat(&bob).await.id;
    let sent = alice.send_msg(chat_alice, &mut msg).await;

    let rcvd = bob.recv_msg(&sent).await;
    message::markseen_msgs(&bob, vec![rcvd.id]).await?;
    let mimefactory =
        MimeFactory::from_mdn(&bob, rcvd.from_id, rcvd.rfc724_mid.clone(), vec![]).await?;
    let rendered_msg = mimefactory.render(&bob).await?;

    assert!(!rendered_msg.is_encrypted);
    assert!(!rendered_msg.message.contains("Bob Examplenet"));
    assert!(!rendered_msg.message.contains("Alice Exampleorg"));
    let bob_alice_contact = bob.add_or_lookup_contact(&alice).await;
    assert_eq!(bob_alice_contact.get_authname(), "Alice Exampleorg");

    let rcvd = tcm.send_recv(&alice, &bob, "Heyho").await;
    message::markseen_msgs(&bob, vec![rcvd.id]).await?;

    let mimefactory = MimeFactory::from_mdn(&bob, rcvd.from_id, rcvd.rfc724_mid, vec![]).await?;
    let rendered_msg = mimefactory.render(&bob).await?;

    // When encrypted, the MDN should be encrypted as well
    assert!(rendered_msg.is_encrypted);
    assert!(!rendered_msg.message.contains("Bob Examplenet"));
    assert!(!rendered_msg.message.contains("Alice Exampleorg"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_subject_in_group() -> Result<()> {
    async fn send_msg_get_subject(
        t: &TestContext,
        group_id: ChatId,
        quote: Option<&Message>,
    ) -> Result<String> {
        let mut new_msg = Message::new_text("Hi".to_string());
        if let Some(q) = quote {
            new_msg.set_quote(t, Some(q)).await?;
        }
        let sent = t.send_msg(group_id, &mut new_msg).await;
        get_subject(t, sent).await
    }
    async fn get_subject(
        t: &TestContext,
        sent: crate::test_utils::SentMessage<'_>,
    ) -> Result<String> {
        let parsed_subject = t.parse_msg(&sent).await.get_subject().unwrap();

        let sent_msg = sent.load_from_db().await;
        assert_eq!(parsed_subject, sent_msg.subject);

        Ok(parsed_subject)
    }

    // 6. Test that in a group, replies also take the quoted message's subject, while non-replies use the group title as subject
    let mut tcm = TestContextManager::new();
    let t = tcm.alice().await;
    let bob = tcm.bob().await;
    let group_id = chat::create_group_chat(&t, chat::ProtectionStatus::Unprotected, "groupname")
        .await
        .unwrap();
    let bob_contact_id = t.add_or_lookup_contact_id(&bob).await;
    chat::add_contact_to_chat(&t, group_id, bob_contact_id).await?;

    let sent_message = t.send_text(group_id, "Hello!").await;
    let bob_received_message = bob.recv_msg(&sent_message).await;
    let bob_group_id = bob_received_message.chat_id;
    bob_group_id.accept(&bob).await.unwrap();
    assert_eq!(get_subject(&t, sent_message).await?, "groupname");

    let subject = send_msg_get_subject(&t, group_id, None).await?;
    assert_eq!(subject, "Re: groupname");

    let subject = send_msg_get_subject(&t, group_id, None).await?;
    assert_eq!(subject, "Re: groupname");

    let mut msg = Message::new(Viewtype::Text);
    msg.set_subject("Different subject".to_string());
    let bob_sent_msg = bob.send_msg(bob_group_id, &mut msg).await;
    let message_from_bob = t.recv_msg(&bob_sent_msg).await;

    let subject = send_msg_get_subject(&t, group_id, None).await?;
    assert_eq!(subject, "Re: groupname");

    let subject = send_msg_get_subject(&t, group_id, Some(&message_from_bob)).await?;
    let outgoing_quoting_msg = t.get_last_msg().await;
    assert_eq!(subject, "Re: Different subject");

    let subject = send_msg_get_subject(&t, group_id, None).await?;
    assert_eq!(subject, "Re: groupname");

    let subject = send_msg_get_subject(&t, group_id, Some(&outgoing_quoting_msg)).await?;
    assert_eq!(subject, "Re: Different subject");

    chat::forward_msgs(&t, &[message_from_bob.id], group_id).await?;
    let subject = get_subject(&t, t.pop_sent_msg().await).await?;
    assert_eq!(subject, "Re: groupname");
    Ok(())
}

async fn first_subject_str(t: TestContext) -> String {
    let contact_id = Contact::add_or_lookup(
        &t,
        "Dave",
        &ContactAddress::new("dave@example.com").unwrap(),
        Origin::ManuallyCreated,
    )
    .await
    .unwrap()
    .0;

    let chat_id = ChatId::create_for_contact(&t, contact_id).await.unwrap();

    let mut new_msg = Message::new_text("Hi".to_string());
    new_msg.chat_id = chat_id;
    chat::send_msg(&t, chat_id, &mut new_msg).await.unwrap();

    let mf = MimeFactory::from_msg(&t, new_msg).await.unwrap();

    mf.subject_str(&t).await.unwrap()
}

// In `imf_raw`, From has to be bob@example.com, To has to be alice@example.org
async fn msg_to_subject_str(imf_raw: &[u8]) -> String {
    let subject_str = msg_to_subject_str_inner(imf_raw, false, false, false).await;

    // Check that combinations of true and false reproduce the same subject_str:
    assert_eq!(
        subject_str,
        msg_to_subject_str_inner(imf_raw, true, false, false).await
    );
    assert_eq!(
        subject_str,
        msg_to_subject_str_inner(imf_raw, false, true, false).await
    );
    assert_eq!(
        subject_str,
        msg_to_subject_str_inner(imf_raw, false, true, true).await
    );
    assert_eq!(
        subject_str,
        msg_to_subject_str_inner(imf_raw, true, true, false).await
    );

    // These two combinations are different: If `message_arrives_inbetween` is true, but
    // `reply` is false, the core is actually expected to use the subject of the message
    // that arrived in between.
    assert_eq!(
        "Re: Some other, completely unrelated subject",
        msg_to_subject_str_inner(imf_raw, false, false, true).await
    );
    assert_eq!(
        "Re: Some other, completely unrelated subject",
        msg_to_subject_str_inner(imf_raw, true, false, true).await
    );

    // We leave away the combination (true, true, true) here:
    // It would mean that the original message is quoted without sending the quoting message
    // out yet, then the original message is deleted, then another unrelated message arrives
    // and then the message with the quote is sent out. Not very realistic.

    subject_str
}

async fn msg_to_subject_str_inner(
    imf_raw: &[u8],
    delete_original_msg: bool,
    reply: bool,
    message_arrives_inbetween: bool,
) -> String {
    let t = TestContext::new_alice().await;
    let mut new_msg = incoming_msg_to_reply_msg(imf_raw, &t).await;
    let incoming_msg = get_chat_msg(&t, new_msg.chat_id, 0, 1).await;

    if delete_original_msg {
        incoming_msg.id.trash(&t, false).await.unwrap();
    }

    if message_arrives_inbetween {
        receive_imf(
            &t,
            b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                    From: Bob <bob@example.com>\n\
                    To: alice@example.org\n\
                    Subject: Some other, completely unrelated subject\n\
                    Message-ID: <3cl4@example.com>\n\
                    Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
                    \n\
                    Some other, completely unrelated content\n",
            false,
        )
        .await
        .unwrap();

        let arrived_msg = t.get_last_msg().await;
        assert_eq!(arrived_msg.chat_id, incoming_msg.chat_id);
    }

    if reply {
        new_msg.set_quote(&t, Some(&incoming_msg)).await.unwrap();
    }

    chat::send_msg(&t, new_msg.chat_id, &mut new_msg)
        .await
        .unwrap();
    let mf = MimeFactory::from_msg(&t, new_msg).await.unwrap();
    mf.subject_str(&t).await.unwrap()
}

// Creates a `Message` that replies "Hi" to the incoming email in `imf_raw`.
async fn incoming_msg_to_reply_msg(imf_raw: &[u8], context: &Context) -> Message {
    context
        .set_config(Config::ShowEmails, Some("2"))
        .await
        .unwrap();

    receive_imf(context, imf_raw, false).await.unwrap();

    let chats = Chatlist::try_load(context, 0, None, None).await.unwrap();

    let chat_id = chats.get_chat_id(0).unwrap();
    chat_id.accept(context).await.unwrap();

    let mut new_msg = Message::new_text("Hi".to_string());
    new_msg.chat_id = chat_id;

    new_msg
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// This test could still be extended
async fn test_render_reply() {
    let t = TestContext::new_alice().await;
    let context = &t;

    let mut msg = incoming_msg_to_reply_msg(
        b"Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                From: Charlie <charlie@example.com>\n\
                To: alice@example.org\n\
                Subject: Chat: hello\n\
                Chat-Version: 1.0\n\
                Message-ID: <2223@example.com>\n\
                Date: Sun, 22 Mar 2020 22:37:56 +0000\n\
                \n\
                hello\n",
        context,
    )
    .await;
    chat::send_msg(&t, msg.chat_id, &mut msg).await.unwrap();

    let mimefactory = MimeFactory::from_msg(&t, msg).await.unwrap();

    let recipients = mimefactory.recipients();
    assert_eq!(recipients, vec!["charlie@example.com"]);

    let rendered_msg = mimefactory.render(context).await.unwrap();

    let mail = mailparse::parse_mail(rendered_msg.message.as_bytes()).unwrap();
    assert_eq!(
        mail.headers
            .iter()
            .find(|h| h.get_key() == "MIME-Version")
            .unwrap()
            .get_value(),
        "1.0"
    );

    let _mime_msg = MimeMessage::from_bytes(context, rendered_msg.message.as_bytes(), None)
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_selfavatar_unencrypted() -> anyhow::Result<()> {
    // create chat with bob, set selfavatar
    let t = TestContext::new_alice().await;
    let chat = t.create_chat_with_contact("bob", "bob@example.org").await;

    let file = t.dir.path().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await?;
    t.set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
        .await?;

    // send message to bob: that should get multipart/mixed because of the avatar moved to inner header;
    // make sure, `Subject:` stays in the outer header (imf header)
    let mut msg = Message::new_text("this is the text!".to_string());

    let sent_msg = t.send_msg(chat.id, &mut msg).await;
    let mut payload = sent_msg.payload().splitn(3, "\r\n\r\n");

    let outer = payload.next().unwrap();
    let inner = payload.next().unwrap();
    let body = payload.next().unwrap();

    assert_eq!(outer.match_indices("multipart/mixed").count(), 1);
    assert_eq!(outer.match_indices("Message-ID:").count(), 1);
    assert_eq!(outer.match_indices("Subject:").count(), 1);
    assert_eq!(outer.match_indices("Autocrypt:").count(), 1);
    assert_eq!(outer.match_indices("Chat-User-Avatar:").count(), 0);

    assert_eq!(inner.match_indices("text/plain").count(), 1);
    assert_eq!(inner.match_indices("Message-ID:").count(), 1);
    assert_eq!(inner.match_indices("Chat-User-Avatar:").count(), 1);
    assert_eq!(inner.match_indices("Subject:").count(), 0);

    assert_eq!(body.match_indices("this is the text!").count(), 1);

    // if another message is sent, that one must not contain the avatar
    let sent_msg = t.send_msg(chat.id, &mut msg).await;
    let mut payload = sent_msg.payload().splitn(3, "\r\n\r\n");
    let outer = payload.next().unwrap();
    let inner = payload.next().unwrap();
    let body = payload.next().unwrap();

    assert_eq!(outer.match_indices("multipart/mixed").count(), 1);
    assert_eq!(outer.match_indices("Message-ID:").count(), 1);
    assert_eq!(outer.match_indices("Subject:").count(), 1);
    assert_eq!(outer.match_indices("Autocrypt:").count(), 1);
    assert_eq!(outer.match_indices("Chat-User-Avatar:").count(), 0);

    assert_eq!(inner.match_indices("text/plain").count(), 1);
    assert_eq!(inner.match_indices("Message-ID:").count(), 1);
    assert_eq!(inner.match_indices("Chat-User-Avatar:").count(), 0);
    assert_eq!(inner.match_indices("Subject:").count(), 0);

    assert_eq!(body.match_indices("this is the text!").count(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_selfavatar_unencrypted_signed() {
    // create chat with bob, set selfavatar
    let t = TestContext::new_alice().await;
    t.set_config(Config::SignUnencrypted, Some("1"))
        .await
        .unwrap();
    let chat = t.create_chat_with_contact("bob", "bob@example.org").await;

    let file = t.dir.path().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await.unwrap();
    t.set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
        .await
        .unwrap();

    // send message to bob: that should get multipart/signed.
    // `Subject:` is protected by copying it.
    // make sure, `Subject:` stays in the outer header (imf header)
    let mut msg = Message::new_text("this is the text!".to_string());

    let sent_msg = t.send_msg(chat.id, &mut msg).await;
    let mut payload = sent_msg.payload().splitn(4, "\r\n\r\n");

    let part = payload.next().unwrap();
    assert_eq!(part.match_indices("multipart/signed").count(), 1);
    assert_eq!(part.match_indices("From:").count(), 1);
    assert_eq!(part.match_indices("Message-ID:").count(), 1);
    assert_eq!(part.match_indices("Subject:").count(), 1);
    assert_eq!(part.match_indices("Autocrypt:").count(), 1);
    assert_eq!(part.match_indices("Chat-User-Avatar:").count(), 0);

    let part = payload.next().unwrap();
    assert_eq!(
        part.match_indices("multipart/mixed; protected-headers=\"v1\"")
            .count(),
        1
    );
    assert_eq!(part.match_indices("From:").count(), 1);
    assert_eq!(part.match_indices("Message-ID:").count(), 0);
    assert_eq!(part.match_indices("Subject:").count(), 1);
    assert_eq!(part.match_indices("Autocrypt:").count(), 0);
    assert_eq!(part.match_indices("Chat-User-Avatar:").count(), 0);

    let part = payload.next().unwrap();
    assert_eq!(part.match_indices("text/plain").count(), 1);
    assert_eq!(part.match_indices("From:").count(), 0);
    assert_eq!(part.match_indices("Message-ID:").count(), 1);
    assert_eq!(part.match_indices("Chat-User-Avatar:").count(), 1);
    assert_eq!(part.match_indices("Subject:").count(), 0);

    let body = payload.next().unwrap();
    assert_eq!(body.match_indices("this is the text!").count(), 1);

    let bob = TestContext::new_bob().await;
    bob.recv_msg(&sent_msg).await;
    let alice_id = Contact::lookup_id_by_addr(&bob.ctx, "alice@example.org", Origin::Unknown)
        .await
        .unwrap()
        .unwrap();
    let alice_contact = Contact::get_by_id(&bob.ctx, alice_id).await.unwrap();
    assert!(
        alice_contact
            .get_profile_image(&bob.ctx)
            .await
            .unwrap()
            .is_some()
    );

    // if another message is sent, that one must not contain the avatar
    let mut msg = Message::new_text("this is the text!".to_string());
    let sent_msg = t.send_msg(chat.id, &mut msg).await;
    let mut payload = sent_msg.payload().splitn(4, "\r\n\r\n");

    let part = payload.next().unwrap();
    assert_eq!(part.match_indices("multipart/signed").count(), 1);
    assert_eq!(part.match_indices("From:").count(), 1);
    assert_eq!(part.match_indices("Message-ID:").count(), 1);
    assert_eq!(part.match_indices("Subject:").count(), 1);
    assert_eq!(part.match_indices("Autocrypt:").count(), 1);
    assert_eq!(part.match_indices("Chat-User-Avatar:").count(), 0);

    let part = payload.next().unwrap();
    assert_eq!(
        part.match_indices("multipart/mixed; protected-headers=\"v1\"")
            .count(),
        1
    );
    assert_eq!(part.match_indices("From:").count(), 1);
    assert_eq!(part.match_indices("Message-ID:").count(), 0);
    assert_eq!(part.match_indices("Subject:").count(), 1);
    assert_eq!(part.match_indices("Autocrypt:").count(), 0);
    assert_eq!(part.match_indices("Chat-User-Avatar:").count(), 0);

    let part = payload.next().unwrap();
    assert_eq!(part.match_indices("text/plain").count(), 1);
    assert_eq!(body.match_indices("From:").count(), 0);
    assert_eq!(part.match_indices("Message-ID:").count(), 1);
    assert_eq!(part.match_indices("Chat-User-Avatar:").count(), 0);
    assert_eq!(part.match_indices("Subject:").count(), 0);

    let body = payload.next().unwrap();
    assert_eq!(body.match_indices("this is the text!").count(), 1);

    bob.recv_msg(&sent_msg).await;
    let alice_contact = Contact::get_by_id(&bob.ctx, alice_id).await.unwrap();
    assert!(
        alice_contact
            .get_profile_image(&bob.ctx)
            .await
            .unwrap()
            .is_some()
    );
}

/// Test that removed member address does not go into the `To:` field.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remove_member_bcc() -> Result<()> {
    let mut tcm = TestContextManager::new();

    // Alice creates a group with Bob and Claire and then removes Bob.
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    let bob_id = alice.add_or_lookup_contact_id(bob).await;
    let charlie_id = alice.add_or_lookup_contact_id(charlie).await;
    let charlie_contact = Contact::get_by_id(alice, charlie_id).await?;
    let charlie_addr = charlie_contact.get_addr();

    let alice_chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "foo").await?;
    add_contact_to_chat(alice, alice_chat_id, bob_id).await?;
    add_contact_to_chat(alice, alice_chat_id, charlie_id).await?;
    send_text_msg(alice, alice_chat_id, "Creating a group".to_string()).await?;

    remove_contact_from_chat(alice, alice_chat_id, charlie_id).await?;
    let remove = alice.pop_sent_msg().await;
    let remove_payload = remove.payload();
    let parsed = mailparse::parse_mail(remove_payload.as_bytes())?;
    let to = parsed
        .headers
        .get_first_header("To")
        .context("no To: header parsed")?;
    let to = addrparse_header(to)?;
    for to_addr in to.iter() {
        match to_addr {
            mailparse::MailAddr::Single(info) => {
                // Addresses should be of existing members (Alice and Bob) and not Charlie.
                assert_ne!(info.addr, charlie_addr);
            }
            mailparse::MailAddr::Group(_) => {
                panic!("Group addresses are not expected here");
            }
        }
    }

    Ok(())
}

/// Tests that standard IMF header "From:" comes before non-standard "Autocrypt:" header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_from_before_autocrypt() -> Result<()> {
    // create chat with bob
    let t = TestContext::new_alice().await;
    let chat = t.create_chat_with_contact("bob", "bob@example.org").await;

    // send message to bob: that should get multipart/mixed because of the avatar moved to inner header;
    // make sure, `Subject:` stays in the outer header (imf header)
    let mut msg = Message::new_text("this is the text!".to_string());

    let sent_msg = t.send_msg(chat.id, &mut msg).await;
    let payload = sent_msg.payload();

    assert_eq!(payload.match_indices("Autocrypt:").count(), 1);
    assert_eq!(payload.match_indices("From:").count(), 1);

    assert!(payload.match_indices("From:").next() < payload.match_indices("Autocrypt:").next());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_protected_headers_directive() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let chat = tcm
        .send_recv_accept(&alice, &bob, "alice->bob")
        .await
        .chat_id;

    // Now Bob can send an encrypted message to Alice.
    let mut msg = Message::new(Viewtype::File);
    // Long messages are truncated and MimeMessage::decoded_data is set for them. We need
    // decoded_data to check presence of the necessary headers.
    msg.set_text("a".repeat(constants::DC_DESIRED_TEXT_LEN + 1));
    msg.set_file_from_bytes(&bob, "foo.bar", "content".as_bytes(), None)?;
    let sent = bob.send_msg(chat, &mut msg).await;
    assert!(msg.get_showpadlock());
    assert!(sent.payload.contains("\r\nSubject: [...]\r\n"));

    let mime = MimeMessage::from_bytes(&alice, sent.payload.as_bytes(), None).await?;
    let mut payload = str::from_utf8(&mime.decoded_data)?.splitn(2, "\r\n\r\n");
    let part = payload.next().unwrap();
    assert_eq!(
        part.match_indices("multipart/mixed; protected-headers=\"v1\"")
            .count(),
        1
    );
    assert_eq!(part.match_indices("Subject:").count(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_dont_remove_self() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let first_group = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "First group", &[bob])
        .await;
    alice.send_text(first_group, "Hi! I created a group.").await;
    remove_contact_from_chat(alice, first_group, ContactId::SELF).await?;
    alice.pop_sent_msg().await;

    let second_group = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "First group", &[bob])
        .await;
    let sent = alice
        .send_text(second_group, "Hi! I created another group.")
        .await;

    println!("{}", sent.payload);
    let mime_message = MimeMessage::from_bytes(alice, sent.payload.as_bytes(), None)
        .await
        .unwrap();
    assert!(!mime_message.header_exists(HeaderDef::ChatGroupPastMembers));
    assert_eq!(
        mime_message.chat_group_member_timestamps().unwrap().len(),
        1 // There is a timestamp for Bob, not for Alice
    );

    Ok(())
}

/// Regression test: mimefactory should never create an empty to header,
/// also not if the Selftalk parameter is missing
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_empty_to_header() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    let mut self_chat = alice.get_self_chat().await;
    self_chat.param.remove(Param::Selftalk);
    self_chat.update_param(alice).await?;

    let payload = alice.send_text(self_chat.id, "Hi").await.payload;
    assert!(
        // It would be equally fine if the payload contained `To: alice@example.org` or similar,
        // as long as it's a valid header
        payload.contains("To: \"hidden-recipients\": ;"),
        "Payload doesn't contain correct To: header: {payload}"
    );

    Ok(())
}
