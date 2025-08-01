use mailparse::ParsedMail;
use std::mem;

use super::*;
use crate::{
    chat,
    chatlist::Chatlist,
    constants::{self, Blocked, DC_DESIRED_TEXT_LEN, DC_ELLIPSIS},
    message::{MessageState, MessengerMessage},
    receive_imf::receive_imf,
    test_utils::{TestContext, TestContextManager},
    tools::time,
};

impl AvatarAction {
    pub fn is_change(&self) -> bool {
        match self {
            AvatarAction::Delete => false,
            AvatarAction::Change(_) => true,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_fromheader() {
    let ctx = TestContext::new_alice().await;

    let mimemsg = MimeMessage::from_bytes(&ctx, b"From: g@c.de\n\nhi", None)
        .await
        .unwrap();
    let contact = mimemsg.from;
    assert_eq!(contact.addr, "g@c.de");
    assert_eq!(contact.display_name, None);

    let mimemsg = MimeMessage::from_bytes(&ctx, b"From:   g@c.de  \n\nhi", None)
        .await
        .unwrap();
    let contact = mimemsg.from;
    assert_eq!(contact.addr, "g@c.de");
    assert_eq!(contact.display_name, None);

    let mimemsg = MimeMessage::from_bytes(&ctx, b"From: <g@c.de>\n\nhi", None)
        .await
        .unwrap();
    let contact = mimemsg.from;
    assert_eq!(contact.addr, "g@c.de");
    assert_eq!(contact.display_name, None);

    let mimemsg = MimeMessage::from_bytes(&ctx, b"From: Goetz C <g@c.de>\n\nhi", None)
        .await
        .unwrap();
    let contact = mimemsg.from;
    assert_eq!(contact.addr, "g@c.de");
    assert_eq!(contact.display_name, Some("Goetz C".to_string()));

    let mimemsg = MimeMessage::from_bytes(&ctx, b"From: \"Goetz C\" <g@c.de>\n\nhi", None)
        .await
        .unwrap();
    let contact = mimemsg.from;
    assert_eq!(contact.addr, "g@c.de");
    assert_eq!(contact.display_name, Some("Goetz C".to_string()));

    let mimemsg =
        MimeMessage::from_bytes(&ctx, b"From: =?utf-8?q?G=C3=B6tz?= C <g@c.de>\n\nhi", None)
            .await
            .unwrap();
    let contact = mimemsg.from;
    assert_eq!(contact.addr, "g@c.de");
    assert_eq!(contact.display_name, Some("Götz C".to_string()));

    // although RFC 2047 says, encoded-words shall not appear inside quoted-string,
    // this combination is used in the wild eg. by MailMate
    let mimemsg = MimeMessage::from_bytes(
        &ctx,
        b"From: \"=?utf-8?q?G=C3=B6tz?= C\" <g@c.de>\n\nhi",
        None,
    )
    .await
    .unwrap();
    let contact = mimemsg.from;
    assert_eq!(contact.addr, "g@c.de");
    assert_eq!(contact.display_name, Some("Götz C".to_string()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_crash() {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/issue_523.txt");
    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();

    assert_eq!(mimeparser.get_subject(), None);
    assert_eq!(mimeparser.parts.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_rfc724_mid_exists() {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/mail_with_message_id.txt");
    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();

    assert_eq!(
        mimeparser.get_rfc724_mid(),
        Some("2dfdbde7@example.org".into())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_rfc724_mid_not_exists() {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/issue_523.txt");
    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(mimeparser.get_rfc724_mid(), None);
}

#[test]
fn test_get_recipients() {
    let raw = include_bytes!("../../test-data/message/mail_with_cc.txt");
    let mail = mailparse::parse_mail(&raw[..]).unwrap();
    let recipients = get_recipients(&mail.headers);
    assert!(recipients.iter().any(|info| info.addr == "abc@bcd.com"));
    assert!(recipients.iter().any(|info| info.addr == "def@def.de"));
    assert_eq!(recipients.len(), 2);

    // If some header is present multiple times,
    // only the last one must be used.
    let raw = b"From: alice@example.org\n\
                    TO: mallory@example.com\n\
                    To: mallory@example.net\n\
                    To: bob@example.net\n\
                    Content-Type: text/plain\n\
                    Chat-Version: 1.0\n\
                    \n\
                    Hello\n\
                    ";
    let mail = mailparse::parse_mail(&raw[..]).unwrap();
    let recipients = get_recipients(&mail.headers);
    assert!(recipients.iter().any(|info| info.addr == "bob@example.net"));
    assert_eq!(recipients.len(), 1);
}

#[test]
fn test_is_attachment() {
    let raw = include_bytes!("../../test-data/message/mail_with_cc.txt");
    let mail = mailparse::parse_mail(raw).unwrap();
    assert!(!is_attachment_disposition(&mail));

    let raw = include_bytes!("../../test-data/message/mail_attach_txt.eml");
    let mail = mailparse::parse_mail(raw).unwrap();
    assert!(!is_attachment_disposition(&mail));
    assert!(!is_attachment_disposition(&mail.subparts[0]));
    assert!(is_attachment_disposition(&mail.subparts[1]));
}

fn load_mail_with_attachment<'a>(t: &'a TestContext, raw: &'a [u8]) -> ParsedMail<'a> {
    let mail = mailparse::parse_mail(raw).unwrap();
    assert!(get_attachment_filename(t, &mail).unwrap().is_none());
    assert!(
        get_attachment_filename(t, &mail.subparts[0])
            .unwrap()
            .is_none()
    );
    mail
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_simple.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("test.html".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_encoded_words() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_encoded_words.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("Maßnahmen Okt. 2020.html".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_encoded_words_binary() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_encoded_words_binary.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some(" § 165 Abs".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_encoded_words_windows1251() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_encoded_words_windows1251.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("file Что нового 2020.pdf".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_encoded_words_cont() {
    // test continued encoded-words and also test apostropes work that way
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_encoded_words_cont.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("Maßn'ah'men Okt. 2020.html".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_encoded_words_bad_delimiter() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_encoded_words_bad_delimiter.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    // not decoded as a space is missing after encoded-words part
    assert_eq!(filename, Some("=?utf-8?q?foo?=.bar".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_apostrophed() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_apostrophed.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("Maßnahmen Okt. 2021.html".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_apostrophed_cont() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_apostrophed_cont.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("Maßnahmen März 2022.html".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_apostrophed_windows1251() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_apostrophed_windows1251.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("программирование.HTM".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_apostrophed_cp1252() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_apostrophed_cp1252.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("Auftragsbestätigung.pdf".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_apostrophed_invalid() {
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_apostrophed_invalid.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("somedäüta.html.zip".to_string()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_attachment_filename_combined() {
    // test that if `filename` and `filename*0` are given, the filename is not doubled
    let t = TestContext::new().await;
    let mail = load_mail_with_attachment(
        &t,
        include_bytes!("../../test-data/message/attach_filename_combined.eml"),
    );
    let filename = get_attachment_filename(&t, &mail.subparts[1]).unwrap();
    assert_eq!(filename, Some("Maßnahmen Okt. 2020.html".to_string()))
}

#[test]
fn test_mailparse_content_type() {
    let ctype = mailparse::parse_content_type("text/plain; charset=utf-8; protected-headers=v1;");

    assert_eq!(ctype.mimetype, "text/plain");
    assert_eq!(ctype.charset, "utf-8");
    assert_eq!(
        ctype.params.get("protected-headers"),
        Some(&"v1".to_string())
    );
}

/// Test to reproduce
/// <https://github.com/staktrace/mailparse/issues/130>.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mailparse_0_16_0_panic() {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/mailparse-0.16.0-panic.eml");

    // There should be an error, but no panic.
    assert!(
        MimeMessage::from_bytes(&context.ctx, &raw[..], None)
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_first_addr() {
    let context = TestContext::new().await;
    let raw = b"From: hello@one.org, world@two.org\n\
                    Chat-Disposition-Notification-To: wrong\n\
                    Content-Type: text/plain\n\
                    Chat-Version: 1.0\n\
                    \n\
                    test1\n\
                    ";

    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None).await;

    assert!(mimeparser.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_parent_timestamp() {
    let context = TestContext::new_alice().await;
    let raw = b"From: foo@example.org\n\
                    Content-Type: text/plain\n\
                    Chat-Version: 1.0\n\
                    In-Reply-To: <Gr.beZgAF2Nn0-.oyaJOpeuT70@example.org>\n\
                    \n\
                    Some reply\n\
                    ";
    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        mimeparser.get_parent_timestamp(&context.ctx).await.unwrap(),
        None
    );
    let timestamp = 1570435529;
    context
        .ctx
        .sql
        .execute(
            "INSERT INTO msgs (rfc724_mid, timestamp) VALUES(?,?)",
            ("Gr.beZgAF2Nn0-.oyaJOpeuT70@example.org", timestamp),
        )
        .await
        .expect("Failed to write to the database");
    assert_eq!(
        mimeparser.get_parent_timestamp(&context.ctx).await.unwrap(),
        Some(timestamp)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_with_context() {
    let context = TestContext::new_alice().await;
    let raw = b"From: hello@example.org\n\
                    Content-Type: multipart/mixed; boundary=\"==break==\";\n\
                    Subject: outer-subject\n\
                    Secure-Join-Group: no\n\
                    Secure-Join-Fingerprint: 123456\n\
                    Test-Header: Bar\n\
                    chat-VERSION: 0.0\n\
                    \n\
                    --==break==\n\
                    Content-Type: text/plain; protected-headers=\"v1\";\n\
                    Subject: inner-subject\n\
                    SecureBar-Join-Group: yes\n\
                    Test-Header: Xy\n\
                    chat-VERSION: 1.0\n\
                    \n\
                    test1\n\
                    \n\
                    --==break==--\n\
                    \n";

    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();

    // non-overwritten headers do not bubble up
    let of = mimeparser.get_header(HeaderDef::SecureJoinGroup).unwrap();
    assert_eq!(of, "no");

    // unknown headers do not bubble upwards
    let of = mimeparser.get_header(HeaderDef::TestHeader).unwrap();
    assert_eq!(of, "Bar");

    // the following fields would bubble up
    // if the test would really use encryption for the protected part
    // however, as this is not the case, the outer things stay valid.
    // for Chat-Version, also the case-insensivity is tested.
    assert_eq!(mimeparser.get_subject(), Some("outer-subject".into()));

    let of = mimeparser.get_header(HeaderDef::ChatVersion).unwrap();
    assert_eq!(of, "0.0");
    assert_eq!(mimeparser.parts.len(), 1);

    // make sure, headers that are only allowed in the encrypted part
    // cannot be set from the outer part
    assert!(
        mimeparser
            .get_header(HeaderDef::SecureJoinFingerprint)
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_with_avatars() {
    let t = TestContext::new_alice().await;

    let raw = include_bytes!("../../test-data/message/mail_attach_txt.eml");
    let mimeparser = MimeMessage::from_bytes(&t, &raw[..], None).await.unwrap();
    assert_eq!(mimeparser.user_avatar, None);
    assert_eq!(mimeparser.group_avatar, None);

    let raw = include_bytes!("../../test-data/message/mail_with_user_avatar.eml");
    let mimeparser = MimeMessage::from_bytes(&t, &raw[..], None).await.unwrap();
    assert_eq!(mimeparser.parts.len(), 1);
    assert_eq!(mimeparser.parts[0].typ, Viewtype::Text);
    assert!(mimeparser.user_avatar.unwrap().is_change());
    assert_eq!(mimeparser.group_avatar, None);

    let raw = include_bytes!("../../test-data/message/mail_with_user_avatar_deleted.eml");
    let mimeparser = MimeMessage::from_bytes(&t, &raw[..], None).await.unwrap();
    assert_eq!(mimeparser.parts.len(), 1);
    assert_eq!(mimeparser.parts[0].typ, Viewtype::Text);
    assert_eq!(mimeparser.user_avatar, Some(AvatarAction::Delete));
    assert_eq!(mimeparser.group_avatar, None);

    let raw = include_bytes!("../../test-data/message/mail_with_user_and_group_avatars.eml");
    let mimeparser = MimeMessage::from_bytes(&t, &raw[..], None).await.unwrap();
    assert_eq!(mimeparser.parts.len(), 1);
    assert_eq!(mimeparser.parts[0].typ, Viewtype::Text);
    assert!(mimeparser.user_avatar.unwrap().is_change());
    assert!(mimeparser.group_avatar.unwrap().is_change());

    // if the Chat-User-Avatar header is missing, the avatar become a normal attachment
    let raw = include_bytes!("../../test-data/message/mail_with_user_and_group_avatars.eml");
    let raw = String::from_utf8_lossy(raw).to_string();
    let raw = raw.replace("Chat-User-Avatar:", "Xhat-Xser-Xvatar:");
    let mimeparser = MimeMessage::from_bytes(&t, raw.as_bytes(), None)
        .await
        .unwrap();
    assert_eq!(mimeparser.parts.len(), 1);
    assert_eq!(mimeparser.parts[0].typ, Viewtype::Image);
    assert_eq!(mimeparser.user_avatar, None);
    assert!(mimeparser.group_avatar.unwrap().is_change());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_with_videochat() {
    let t = TestContext::new_alice().await;

    let raw = include_bytes!("../../test-data/message/videochat_invitation.eml");
    let mimeparser = MimeMessage::from_bytes(&t, &raw[..], None).await.unwrap();
    assert_eq!(mimeparser.parts.len(), 1);
    assert_eq!(mimeparser.parts[0].typ, Viewtype::VideochatInvitation);
    assert_eq!(
        mimeparser.parts[0]
            .param
            .get(Param::WebrtcRoom)
            .unwrap_or_default(),
        "https://example.org/p2p/?roomname=6HiduoAn4xN"
    );
    assert!(
        mimeparser.parts[0]
            .msg
            .contains("https://example.org/p2p/?roomname=6HiduoAn4xN")
    );
    assert_eq!(mimeparser.user_avatar, None);
    assert_eq!(mimeparser.group_avatar, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_message_kml() {
    let context = TestContext::new_alice().await;
    let raw = b"Chat-Version: 1.0\n\
From: foo <foo@example.org>\n\
To: bar <bar@example.org>\n\
Subject: Location streaming\n\
Content-Type: multipart/mixed; boundary=\"==break==\"\n\
\n\
\n\
--==break==\n\
Content-Type: text/plain; charset=utf-8\n\
\n\
--\n\
Sent with my Delta Chat Messenger: https://delta.chat\n\
\n\
--==break==\n\
Content-Type: application/vnd.google-earth.kml+xml\n\
Content-Disposition: attachment; filename=\"message.kml\"\n\
\n\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n\
<Document addr=\"foo@example.org\">\n\
<Placemark><Timestamp><when>XXX</when></Timestamp><Point><coordinates accuracy=\"48\">0.0,0.0</coordinates></Point></Placemark>\n\
</Document>\n\
</kml>\n\
\n\
--==break==--\n\
;";

    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        mimeparser.get_subject(),
        Some("Location streaming".to_string())
    );
    assert!(mimeparser.location_kml.is_none());
    assert!(mimeparser.message_kml.is_some());

    // There is only one part because message.kml attachment is special
    // and only goes into message_kml.
    assert_eq!(mimeparser.parts.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_mdn() {
    let context = TestContext::new_alice().await;
    let raw = b"Subject: =?utf-8?q?Chat=3A_Message_opened?=\n\
Date: Mon, 10 Jan 2020 00:00:00 +0000\n\
Chat-Version: 1.0\n\
Message-ID: <bar@example.org>\n\
To: Alice <alice@example.org>\n\
From: Bob <bob@example.org>\n\
Auto-Submitted: auto-replied\n\
Content-Type: multipart/report; report-type=disposition-notification;\n\t\
boundary=\"kJBbU58X1xeWNHgBtTbMk80M5qnV4N\"\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
Content-Type: text/plain; charset=utf-8\n\
\n\
The \"Encrypted message\" message you sent was displayed on the screen of the recipient.\n\
\n\
This is no guarantee the content was read.\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
Content-Type: message/disposition-notification\n\
\n\
Reporting-UA: Delta Chat 1.0.0-beta.22\n\
Original-Recipient: rfc822;bob@example.org\n\
Final-Recipient: rfc822;bob@example.org\n\
Original-Message-ID: <foo@example.org>\n\
Disposition: manual-action/MDN-sent-automatically; displayed\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N--\n\
";

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        message.get_subject(),
        Some("Chat: Message opened".to_string())
    );

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.mdn_reports.len(), 1);
    assert_eq!(message.is_bot, None);
}

/// Test parsing multiple MDNs combined in a single message.
///
/// RFC 6522 specifically allows MDNs to be nested inside
/// multipart MIME messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_multiple_mdns() {
    let context = TestContext::new_alice().await;
    let raw = b"Subject: =?utf-8?q?Chat=3A_Message_opened?=\n\
Date: Mon, 10 Jan 2020 00:00:00 +0000\n\
Chat-Version: 1.0\n\
Message-ID: <foo@example.org>\n\
To: Alice <alice@example.org>\n\
From: Bob <bob@example.org>\n\
Content-Type: multipart/parallel; boundary=outer\n\
\n\
This is a multipart MDN.\n\
\n\
--outer\n\
Content-Type: multipart/report; report-type=disposition-notification;\n\t\
boundary=kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
Content-Type: text/plain; charset=utf-8\n\
\n\
The \"Encrypted message\" message you sent was displayed on the screen of the recipient.\n\
\n\
This is no guarantee the content was read.\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
Content-Type: message/disposition-notification\n\
\n\
Reporting-UA: Delta Chat 1.0.0-beta.22\n\
Original-Recipient: rfc822;bob@example.org\n\
Final-Recipient: rfc822;bob@example.org\n\
Original-Message-ID: <bar@example.org>\n\
Disposition: manual-action/MDN-sent-automatically; displayed\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N--\n\
--outer\n\
Content-Type: multipart/report; report-type=disposition-notification;\n\t\
boundary=zuOJlsTfZAukyawEPVdIgqWjaM9w2W\n\
\n\
\n\
--zuOJlsTfZAukyawEPVdIgqWjaM9w2W\n\
Content-Type: text/plain; charset=utf-8\n\
\n\
The \"Encrypted message\" message you sent was displayed on the screen of the recipient.\n\
\n\
This is no guarantee the content was read.\n\
\n\
\n\
--zuOJlsTfZAukyawEPVdIgqWjaM9w2W\n\
Content-Type: message/disposition-notification\n\
\n\
Reporting-UA: Delta Chat 1.0.0-beta.22\n\
Original-Recipient: rfc822;bob@example.org\n\
Final-Recipient: rfc822;bob@example.org\n\
Original-Message-ID: <baz@example.org>\n\
Disposition: manual-action/MDN-sent-automatically; displayed\n\
\n\
\n\
--zuOJlsTfZAukyawEPVdIgqWjaM9w2W--\n\
--outer--\n\
";

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        message.get_subject(),
        Some("Chat: Message opened".to_string())
    );

    assert_eq!(message.parts.len(), 2);
    assert_eq!(message.mdn_reports.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_mdn_with_additional_message_ids() {
    let context = TestContext::new_alice().await;
    let raw = b"Subject: =?utf-8?q?Chat=3A_Message_opened?=\n\
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
The \"Encrypted message\" message you sent was displayed on the screen of the recipient.\n\
\n\
This is no guarantee the content was read.\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N\n\
Content-Type: message/disposition-notification\n\
\n\
Reporting-UA: Delta Chat 1.0.0-beta.22\n\
Original-Recipient: rfc822;bob@example.org\n\
Final-Recipient: rfc822;bob@example.org\n\
Original-Message-ID: <foo@example.org>\n\
Disposition: manual-action/MDN-sent-automatically; displayed\n\
Additional-Message-IDs: <foo@example.com> <foo@example.net>\n\
\n\
\n\
--kJBbU58X1xeWNHgBtTbMk80M5qnV4N--\n\
";

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        message.get_subject(),
        Some("Chat: Message opened".to_string())
    );

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.mdn_reports.len(), 1);
    assert_eq!(
        message.mdn_reports[0].original_message_id,
        Some("foo@example.org".to_string())
    );
    assert_eq!(
        &message.mdn_reports[0].additional_message_ids,
        &["foo@example.com", "foo@example.net"]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_inline_attachment() {
    let context = TestContext::new_alice().await;
    let raw = br#"Date: Thu, 13 Feb 2020 22:41:20 +0000 (UTC)
From: sender@example.com
To: receiver@example.com
Subject: Mail with inline attachment
MIME-Version: 1.0
Content-Type: multipart/mixed;
	boundary="----=_Part_25_46172632.1581201680436"

------=_Part_25_46172632.1581201680436
Content-Type: text/plain; charset=utf-8

Hello!

------=_Part_25_46172632.1581201680436
Content-Type: application/pdf; name="some_pdf.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename="some_pdf.pdf"

JVBERi0xLjUKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURl
Y29kZT4+CnN0cmVhbQp4nGVOuwoCMRDs8xVbC8aZvC4Hx4Hno7ATAhZi56MTtPH33YtXiLKQ3ZnM
MDYyMDYxNTE1RTlDOEE4Cj4+CnN0YXJ0eHJlZgo4Mjc4CiUlRU9GCg==
------=_Part_25_46172632.1581201680436--
"#;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        message.get_subject(),
        Some("Mail with inline attachment".to_string())
    );

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::File);
    assert_eq!(message.parts[0].msg, "Mail with inline attachment – Hello!");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_hide_html_without_content() {
    let t = TestContext::new_alice().await;
    let raw = br#"Date: Thu, 13 Feb 2020 22:41:20 +0000 (UTC)
From: sender@example.com
To: receiver@example.com
Subject: Mail with inline attachment
MIME-Version: 1.0
Content-Type: multipart/mixed;
	boundary="----=_Part_25_46172632.1581201680436"

------=_Part_25_46172632.1581201680436
Content-Type: text/html; charset=utf-8

<head>
<meta http-equiv="Content-Type" content="text/html; charset=Windows-1252">
<meta name="GENERATOR" content="MSHTML 11.00.10570.1001"></head>
<body><img align="baseline" alt="" src="cid:1712254131-1" border="0" hspace="0">
</body>

------=_Part_25_46172632.1581201680436
Content-Type: application/pdf; name="some_pdf.pdf"
Content-Transfer-Encoding: base64
Content-Disposition: inline; filename="some_pdf.pdf"

JVBERi0xLjUKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURl
Y29kZT4+CnN0cmVhbQp4nGVOuwoCMRDs8xVbC8aZvC4Hx4Hno7ATAhZi56MTtPH33YtXiLKQ3ZnM
MDYyMDYxNTE1RTlDOEE4Cj4+CnN0YXJ0eHJlZgo4Mjc4CiUlRU9GCg==
------=_Part_25_46172632.1581201680436--
"#;

    let message = MimeMessage::from_bytes(&t, &raw[..], None).await.unwrap();

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::File);
    assert_eq!(message.parts[0].msg, "");

    // Make sure the file is there even though the html is wrong:
    let param = &message.parts[0].param;
    let blob: BlobObject = param.get_file_blob(&t).unwrap().unwrap();
    let f = tokio::fs::File::open(blob.to_abs_path()).await.unwrap();
    let size = f.metadata().await.unwrap().len();
    assert_eq!(size, 154);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parse_inline_image() {
    let context = TestContext::new_alice().await;
    let raw = br#"Message-ID: <foobar@example.org>
From: foo <foo@example.org>
Subject: example
To: bar@example.org
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="--11019878869865180"

----11019878869865180
Content-Type: text/plain; charset=utf-8

Test

----11019878869865180
Content-Type: image/jpeg;
 name="JPEG_filename.jpg"
Content-Transfer-Encoding: base64
Content-Disposition: inline;
 filename="JPEG_filename.jpg"

iVBORw0KGgoAAAANSUhEUgAAACAAAAAeCAAAAABoYUP1AAAAAXNSR0IArs4c6QAAAo1JREFUKJFdkdFuG0UUhr/szuxkxtlduzVx00jGUAhcI56CF0DiHXgFHqDiMfoCvAJC4gIJEBdVaZoGOY5dJ45r7zozmRlvzIVDm3Iu//PpP7/+s/OC/0+UREkEGZGr5N6mAX78MwISQEYJ6j6QYqZf7fzsYyRGJDISuQ9g6uMjW00WRCSRCP4DwNSEg496v828fC++B4yBGro7h+PliiiJHtR9B1vrmbtg359cOk+UqA8cDJm+eHu8yDfii6sAxK0u3hlsnPFn1WvT4XxYUqqtKu8cTMNKT8+nz3/aaWft3svKecBD/O9ETu2O//G7fXt5mHX2xwGP32aIEUNNvX/uh3z2pAkcKD+9XOLVNoMESw7YC+aPP8nqqSluyiuVaZRXCKLEQK3PxsP27UHe1lXV9eczCu2V8ippJA2gz+YTNTK9ttZOoYr+aeXwHp+k245cnFRNt1tmMJg3XV0dXQd3F5LcGn5fDnVQgwINRyFvtddnNmwBSW1qXfzNSDwoM+2A+aTbShfDd89Ka9ybiiLvGa33gK8THrWfVNUSSGLTALMRo/xBXnLbACu3QtRXY+sgkWnawKxCcLjPtr29gVZdPTidBUcSaXJeTfUL+mW4631Fmse+772xIGjSza/KTW/MYE/UCXPbEWs//Xxvqf8qZgYhG0jt8cnTnJpEgfDQ6rvE0n9tq66ICafil5OnOYt0hY94FUPoxI136uPpw4VIYNd+M5utrqvGpg0hc50bRl6BvLanX4pb/3347uWi/WgNHtYyyrdwszsX5fjZtwghy7C5sK2WgUoErcjIoEWr4fAHHhoRP+XZ86L/uMAarLFgsMBaAJhM8Ief9Ey7yHSmyXTp0GRoF7KQEdD/ArmtONKkgCleAAAAAElFTkSuQmCC


----11019878869865180--
"#;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(message.get_subject(), Some("example".to_string()));

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::Image);
    assert_eq!(message.parts[0].msg, "example – Test");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parse_thunderbird_html_embedded_image() {
    let context = TestContext::new_alice().await;
    let raw = br#"To: Alice <alice@example.org>
From: Bob <bob@example.org>
Subject: Test subject
Message-ID: <foobarbaz@example.org>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.7.0
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary="------------779C1631600DF3DB8C02E53A"
Content-Language: en-US

This is a multi-part message in MIME format.
--------------779C1631600DF3DB8C02E53A
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

Test


--------------779C1631600DF3DB8C02E53A
Content-Type: multipart/related;
 boundary="------------10CC6C2609EB38DA782C5CA9"


--------------10CC6C2609EB38DA782C5CA9
Content-Type: text/html; charset=utf-8
Content-Transfer-Encoding: 7bit

<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
</head>
<body>
Test<br>
<p><img moz-do-not-send="false" src="cid:part1.9DFA679B.52A88D69@example.org" alt=""></p>
</body>
</html>

--------------10CC6C2609EB38DA782C5CA9
Content-Type: image/png;
 name="1.png"
Content-Transfer-Encoding: base64
Content-ID: <part1.9DFA679B.52A88D69@example.org>
Content-Disposition: inline;
 filename="1.png"

iVBORw0KGgoAAAANSUhEUgAAACAAAAAeCAAAAABoYUP1AAAAAXNSR0IArs4c6QAAAo1JREFUKJFdkdFuG0UUhr/szuxkxtlduzVx00jGUAhcI56CF0DiHXgFHqDiMfoCvAJC4gIJEBdVaZoGOY5dJ45r7zozmRlvzIVDm3Iu//PpP7/+s/OC/0+UREkEGZGr5N6mAX78MwISQEYJ6j6QYqZf7fzsYyRGJDISuQ9g6uMjW00WRCSRCP4DwNSEg496v828fC++B4yBGro7h+PliiiJHtR9B1vrmbtg359cOk+UqA8cDJm+eHu8yDfii6sAxK0u3hlsnPFn1WvT4XxYUqqtKu8cTMNKT8+nz3/aaWft3svKecBD/O9ETu2O//G7fXt5mHX2xwGP32aIEUNNvX/uh3z2pAkcKD+9XOLVNoMESw7YC+aPP8nqqSluyiuVaZRXCKLEQK3PxsP27UHe1lXV9eczCu2V8ippJA2gz+YTNTK9ttZOoYr+aeXwHp+k245cnFRNt1tmMJg3XV0dXQd3F5LcGn5fDnVQgwINRyFvtddnNmwBSW1qXfzNSDwoM+2A+aTbShfDd89Ka9ybiiLvGa33gK8THrWfVNUSSGLTALMRo/xBXnLbACu3QtRXY+sgkWnawKxCcLjPtr29gVZdPTidBUcSaXJeTfUL+mW4631Fmse+772xIGjSza/KTW/MYE/UCXPbEWs//Xxvqf8qZgYhG0jt8cnTnJpEgfDQ6rvE0n9tq66ICafil5OnOYt0hY94FUPoxI136uPpw4VIYNd+M5utrqvGpg0hc50bRl6BvLanX4pb/3347uWi/WgNHtYyyrdwszsX5fjZtwghy7C5sK2WgUoErcjIoEWr4fAHHhoRP+XZ86L/uMAarLFgsMBaAJhM8Ief9Ey7yHSmyXTp0GRoF7KQEdD/ArmtONKkgCleAAAAAElFTkSuQmCC
--------------10CC6C2609EB38DA782C5CA9--

--------------779C1631600DF3DB8C02E53A--"#;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(message.get_subject(), Some("Test subject".to_string()));

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::Image);
    assert_eq!(message.parts[0].msg, "Test subject – Test");
}

// Outlook specifies filename in the "name" attribute of Content-Type
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parse_outlook_html_embedded_image() {
    let context = TestContext::new_alice().await;
    let raw = br#"From: Anonymous <anonymous@example.org>
To: Anonymous <anonymous@example.org>
Subject: Delta Chat is great stuff!
Date: Tue, 5 May 2020 01:23:45 +0000
MIME-Version: 1.0
Content-Type: multipart/related;
	boundary="----=_NextPart_000_0003_01D622B3.CA753E60"
X-Mailer: Microsoft Outlook 15.0

This is a multipart message in MIME format.

------=_NextPart_000_0003_01D622B3.CA753E60
Content-Type: multipart/alternative;
	boundary="----=_NextPart_001_0004_01D622B3.CA753E60"


------=_NextPart_001_0004_01D622B3.CA753E60
Content-Type: text/plain;
	charset="us-ascii"
Content-Transfer-Encoding: 7bit




------=_NextPart_001_0004_01D622B3.CA753E60
Content-Type: text/html;
	charset="us-ascii"
Content-Transfer-Encoding: quoted-printable

<html>
<body>
<p>
Test<img src="cid:image001.jpg@01D622B3.C9D8D750">
</p>
</body>
</html>
------=_NextPart_001_0004_01D622B3.CA753E60--

------=_NextPart_000_0003_01D622B3.CA753E60
Content-Type: image/jpeg;
	name="image001.jpg"
Content-Transfer-Encoding: base64
Content-ID: <image001.jpg@01D622B3.C9D8D750>

iVBORw0KGgoAAAANSUhEUgAAACAAAAAeCAAAAABoYUP1AAAAAXNSR0IArs4c6QAAAo1JREFUKJFdkdFuG0UUhr/szuxkxtlduzVx00jGUAhcI56CF0DiHXgFHqDiMfoCvAJC4gIJEBdVaZoGOY5dJ45r7zozmRlvzIVDm3Iu//PpP7/+s/OC/0+UREkEGZGr5N6mAX78MwISQEYJ6j6QYqZf7fzsYyRGJDISuQ9g6uMjW00WRCSRCP4DwNSEg496v828fC++B4yBGro7h+PliiiJHtR9B1vrmbtg359cOk+UqA8cDJm+eHu8yDfii6sAxK0u3hlsnPFn1WvT4XxYUqqtKu8cTMNKT8+nz3/aaWft3svKecBD/O9ETu2O//G7fXt5mHX2xwGP32aIEUNNvX/uh3z2pAkcKD+9XOLVNoMESw7YC+aPP8nqqSluyiuVaZRXCKLEQK3PxsP27UHe1lXV9eczCu2V8ippJA2gz+YTNTK9ttZOoYr+aeXwHp+k245cnFRNt1tmMJg3XV0dXQd3F5LcGn5fDnVQgwINRyFvtddnNmwBSW1qXfzNSDwoM+2A+aTbShfDd89Ka9ybiiLvGa33gK8THrWfVNUSSGLTALMRo/xBXnLbACu3QtRXY+sgkWnawKxCcLjPtr29gVZdPTidBUcSaXJeTfUL+mW4631Fmse+772xIGjSza/KTW/MYE/UCXPbEWs//Xxvqf8qZgYhG0jt8cnTnJpEgfDQ6rvE0n9tq66ICafil5OnOYt0hY94FUPoxI136uPpw4VIYNd+M5utrqvGpg0hc50bRl6BvLanX4pb/3347uWi/WgNHtYyyrdwszsX5fjZtwghy7C5sK2WgUoErcjIoEWr4fAHHhoRP+XZ86L/uMAarLFgsMBaAJhM8Ief9Ey7yHSmyXTp0GRoF7KQEdD/ArmtONKkgCleAAAAAElFTkSuQmCC

------=_NextPart_000_0003_01D622B3.CA753E60--
"#;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        message.get_subject(),
        Some("Delta Chat is great stuff!".to_string())
    );

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::Image);
    assert_eq!(message.parts[0].msg, "Delta Chat is great stuff! – Test");
}

#[test]
fn test_parse_message_id() {
    let test = parse_message_id("<foobar>");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "foobar");

    let test = parse_message_id("<foo> <bar>");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "foo");

    let test = parse_message_id("  < foo > <bar>");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "foo");

    let test = parse_message_id("foo");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "foo");

    let test = parse_message_id(" foo ");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "foo");

    let test = parse_message_id("foo bar");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "foo");

    let test = parse_message_id("  foo  bar ");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "foo");

    let test = parse_message_id("");
    assert!(test.is_err());

    let test = parse_message_id(" ");
    assert!(test.is_err());

    let test = parse_message_id("<>");
    assert!(test.is_err());

    let test = parse_message_id("<> bar");
    assert!(test.is_ok());
    assert_eq!(test.unwrap(), "bar");
}

#[test]
fn test_parse_message_ids() {
    let test = parse_message_ids("  foo  bar <foobar>");
    assert_eq!(test.len(), 3);
    assert_eq!(test[0], "foo");
    assert_eq!(test[1], "bar");
    assert_eq!(test[2], "foobar");

    let test = parse_message_ids("  < foobar >");
    assert_eq!(test.len(), 1);
    assert_eq!(test[0], "foobar");

    let test = parse_message_ids("");
    assert!(test.is_empty());

    let test = parse_message_ids(" ");
    assert!(test.is_empty());

    let test = parse_message_ids("  < ");
    assert!(test.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parse_format_flowed_quote() {
    let context = TestContext::new_alice().await;
    let raw = br##"Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Subject: Re: swipe-to-reply
MIME-Version: 1.0
In-Reply-To: <bar@example.org>
Date: Tue, 06 Oct 2020 00:00:00 +0000
Chat-Version: 1.0
Message-ID: <foo@example.org>
To: bob <bob@example.org>
From: alice <alice@example.org>

> Long 
> quote.

Reply
"##;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        message.get_subject(),
        Some("Re: swipe-to-reply".to_string())
    );

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::Text);
    assert_eq!(
        message.parts[0].param.get(Param::Quote).unwrap(),
        "Long quote."
    );
    assert_eq!(message.parts[0].msg, "Reply");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parse_quote_without_reply() {
    let context = TestContext::new_alice().await;
    let raw = br##"Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Subject: Re: swipe-to-reply
MIME-Version: 1.0
In-Reply-To: <bar@example.org>
Date: Tue, 06 Oct 2020 00:00:00 +0000
Message-ID: <foo@example.org>
To: bob <bob@example.org>
From: alice <alice@example.org>

> Just a quote.
"##;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        message.get_subject(),
        Some("Re: swipe-to-reply".to_string())
    );

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::Text);
    assert_eq!(
        message.parts[0].param.get(Param::Quote).unwrap(),
        "Just a quote."
    );
    assert_eq!(message.parts[0].msg, "");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn parse_quote_top_posting() {
    let context = TestContext::new_alice().await;
    let raw = br##"Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no
Subject: Re: top posting
MIME-Version: 1.0
In-Reply-To: <bar@example.org>
Message-ID: <foo@example.org>
To: bob <bob@example.org>
From: alice <alice@example.org>

A reply.

On 2020-10-25, Bob wrote:
> A quote.
"##;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(message.get_subject(), Some("Re: top posting".to_string()));

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::Text);
    assert_eq!(
        message.parts[0].param.get(Param::Quote).unwrap(),
        "A quote."
    );
    assert_eq!(message.parts[0].msg, "A reply.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_attachment_quote() {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/quote_attach.eml");
    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();

    assert_eq!(mimeparser.get_subject().unwrap(), "Message from Alice");
    assert_eq!(mimeparser.parts.len(), 1);
    assert_eq!(mimeparser.parts[0].msg, "Reply");
    assert_eq!(
        mimeparser.parts[0].param.get(Param::Quote).unwrap(),
        "Quote"
    );
    assert_eq!(mimeparser.parts[0].typ, Viewtype::File);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_quote_div() {
    let t = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/gmx-quote.eml");
    let mimeparser = MimeMessage::from_bytes(&t, raw, None).await.unwrap();
    assert_eq!(mimeparser.parts[0].msg, "YIPPEEEEEE\n\nMulti-line");
    assert_eq!(mimeparser.parts[0].param.get(Param::Quote).unwrap(), "Now?");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_allinkl_blockquote() {
    // all-inkl.com puts quotes into `<blockquote> </blockquote>`.
    let t = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/allinkl-quote.eml");
    let mimeparser = MimeMessage::from_bytes(&t, raw, None).await.unwrap();
    assert!(mimeparser.parts[0].msg.starts_with("It's 1.0."));
    assert_eq!(
        mimeparser.parts[0].param.get(Param::Quote).unwrap(),
        "What's the version?"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_subj_to_multimedia_msg() {
    let t = TestContext::new_alice().await;
    receive_imf(
        &t.ctx,
        include_bytes!("../../test-data/message/subj_with_multimedia_msg.eml"),
        false,
    )
    .await
    .unwrap();

    let chats = Chatlist::try_load(&t.ctx, 0, None, None).await.unwrap();
    let msg_id = chats.get_msg_id(0).unwrap().unwrap();
    let msg = Message::load_from_db(&t.ctx, msg_id).await.unwrap();

    assert_eq!(msg.text, "subj with important info – body text");
    assert_eq!(msg.viewtype, Viewtype::Image);
    assert_eq!(msg.error(), None);
    assert_eq!(msg.is_dc_message, MessengerMessage::No);
    assert_eq!(msg.chat_blocked, Blocked::Request);
    assert_eq!(msg.state, MessageState::InFresh);
    assert_eq!(msg.get_filebytes(&t).await.unwrap().unwrap(), 2115);
    assert!(msg.get_file(&t).is_some());
    assert_eq!(msg.get_filename().unwrap(), "avatar64x64.png");
    assert_eq!(msg.get_width(), 64);
    assert_eq!(msg.get_height(), 64);
    assert_eq!(msg.get_filemime().unwrap(), "image/png");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mime_modified_plain() {
    let t = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/text_plain_unspecified.eml");
    let mimeparser = MimeMessage::from_bytes(&t.ctx, raw, None).await.unwrap();
    assert!(!mimeparser.is_mime_modified);
    assert_eq!(
        mimeparser.parts[0].msg,
        "This message does not have Content-Type nor Subject."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mime_modified_alt_plain_html() {
    let t = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/text_alt_plain_html.eml");
    let mimeparser = MimeMessage::from_bytes(&t.ctx, raw, None).await.unwrap();
    assert!(mimeparser.is_mime_modified);
    assert_eq!(
        mimeparser.parts[0].msg,
        "mime-modified test – this is plain"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mime_modified_alt_plain() {
    let t = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/text_alt_plain.eml");
    let mimeparser = MimeMessage::from_bytes(&t.ctx, raw, None).await.unwrap();
    assert!(!mimeparser.is_mime_modified);
    assert_eq!(
        mimeparser.parts[0].msg,
        "mime-modified test – \
        mime-modified should not be set set as there is no html and no special stuff;\n\
        although not being a delta-message.\n\
        test some special html-characters as < > and & but also \" and ' :)"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mime_modified_alt_html() {
    let t = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/text_alt_html.eml");
    let mimeparser = MimeMessage::from_bytes(&t.ctx, raw, None).await.unwrap();
    assert!(mimeparser.is_mime_modified);
    assert_eq!(
        mimeparser.parts[0].msg,
        "mime-modified test – mime-modified *set*; simplify is always regarded as lossy."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mime_modified_html() {
    let t = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/text_html.eml");
    let mimeparser = MimeMessage::from_bytes(&t.ctx, raw, None).await.unwrap();
    assert!(mimeparser.is_mime_modified);
    assert_eq!(
        mimeparser.parts[0].msg,
        "mime-modified test – mime-modified *set*; simplify is always regarded as lossy."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mime_modified_large_plain() -> Result<()> {
    let t = TestContext::new_alice().await;
    let t1 = TestContext::new_alice().await;

    static REPEAT_TXT: &str = "this text with 42 chars is just repeated.\n";
    static REPEAT_CNT: usize = DC_DESIRED_TEXT_LEN / REPEAT_TXT.len() + 2;
    let long_txt = format!("From: alice@c.de\n\n{}", REPEAT_TXT.repeat(REPEAT_CNT));
    assert_eq!(long_txt.matches("just repeated").count(), REPEAT_CNT);
    assert!(long_txt.len() > DC_DESIRED_TEXT_LEN);

    {
        let mimemsg = MimeMessage::from_bytes(&t, long_txt.as_ref(), None).await?;
        assert!(mimemsg.is_mime_modified);
        assert!(
            mimemsg.parts[0].msg.matches("just repeated").count()
                <= DC_DESIRED_TEXT_LEN / REPEAT_TXT.len()
        );
        assert!(mimemsg.parts[0].msg.len() <= DC_DESIRED_TEXT_LEN + DC_ELLIPSIS.len());
    }

    for draft in [false, true] {
        let chat = t.get_self_chat().await;
        let mut msg = Message::new_text(long_txt.clone());
        if draft {
            chat.id.set_draft(&t, Some(&mut msg)).await?;
        }
        let sent_msg = t.send_msg(chat.id, &mut msg).await;
        let msg = t.get_last_msg_in(chat.id).await;
        assert!(msg.has_html());
        let html = msg.id.get_html(&t).await?.unwrap();
        assert_eq!(html.matches("<!DOCTYPE html>").count(), 1);
        assert_eq!(html.matches("just repeated.<br/>").count(), REPEAT_CNT);
        assert!(
            msg.text.matches("just repeated.").count() <= DC_DESIRED_TEXT_LEN / REPEAT_TXT.len()
        );
        assert!(msg.text.len() <= DC_DESIRED_TEXT_LEN + DC_ELLIPSIS.len());

        let msg = t1.recv_msg(&sent_msg).await;
        assert!(msg.has_html());
        assert_eq!(msg.id.get_html(&t1).await?.unwrap(), html);
    }

    t.set_config(Config::Bot, Some("1")).await?;
    {
        let mimemsg = MimeMessage::from_bytes(&t, long_txt.as_ref(), None).await?;
        assert!(!mimemsg.is_mime_modified);
        assert_eq!(
            format!("{}\n", mimemsg.parts[0].msg),
            REPEAT_TXT.repeat(REPEAT_CNT)
        );
    }

    Ok(())
}

/// Tests that sender status (signature) does not appear
/// in HTML view of a long message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_large_message_no_signature() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    alice
        .set_config(Config::Selfstatus, Some("Some signature"))
        .await?;
    let chat = alice.create_chat(bob).await;
    let txt = "Hello!\n".repeat(500);
    let sent = alice.send_text(chat.id, &txt).await;
    let msg = bob.recv_msg(&sent).await;

    assert_eq!(msg.has_html(), true);
    let html = msg.id.get_html(bob).await?.unwrap();
    assert_eq!(html.contains("Some signature"), false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_x_microsoft_original_message_id() {
    let t = TestContext::new_alice().await;
    let message = MimeMessage::from_bytes(&t, b"Date: Wed, 17 Feb 2021 15:45:15 +0000\n\
                Chat-Version: 1.0\n\
                Message-ID: <DBAPR03MB1180CE51A1BFE265BD018D4790869@DBAPR03MB6691.eurprd03.prod.outlook.com>\n\
                To: Bob <bob@example.org>\n\
                From: Alice <alice@example.org>\n\
                Subject: Message from Alice\n\
                Content-Type: text/plain\n\
                X-Microsoft-Original-Message-ID: <Mr.6Dx7ITn4w38.n9j7epIcuQI@outlook.com>\n\
                MIME-Version: 1.0\n\
                \n\
                Does it work with outlook now?\n\
                ", None)
            .await
            .unwrap();
    assert_eq!(
        message.get_rfc724_mid(),
        Some("Mr.6Dx7ITn4w38.n9j7epIcuQI@outlook.com".to_string())
    );
}

/// Tests that X-Microsoft-Original-Message-ID does not overwrite encrypted Message-ID.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_x_microsoft_original_message_id_precedence() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let bob_chat_id = tcm.send_recv_accept(&alice, &bob, "hi").await.chat_id;
    chat::send_text_msg(&bob, bob_chat_id, "hi!".to_string()).await?;
    let mut sent_msg = bob.pop_sent_msg().await;

    // Insert X-Microsoft-Original-Message-ID.
    // It should be ignored because there is a Message-ID in the encrypted part.
    sent_msg.payload = sent_msg.payload.replace(
        "Message-ID:",
        "X-Microsoft-Original-Message-ID: <fake-message-id@example.net>\r\nMessage-ID:",
    );

    let msg = alice.recv_msg(&sent_msg).await;
    assert!(!msg.rfc724_mid.contains("fake-message-id"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_extra_imf_chat_header() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.alice().await;
    let chat_id = t.get_self_chat().await.id;

    chat::send_text_msg(t, chat_id, "hi!".to_string()).await?;
    let sent_msg = t.pop_sent_msg().await;
    // Check removal of some nonexistent "Chat-*" header to protect the code from future breakages.
    let payload = sent_msg
        .payload
        .replace("Message-ID:", "Chat-Forty-Two: 42\r\nMessage-ID:");
    let msg = MimeMessage::from_bytes(t, payload.as_bytes(), None)
        .await
        .unwrap();
    assert!(msg.headers.contains_key("chat-version"));
    assert!(!msg.headers.contains_key("chat-forty-two"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_long_in_reply_to() -> Result<()> {
    let t = TestContext::new_alice().await;

    // A message with a long Message-ID.
    // Long message-IDs are generated by Mailjet.
    let raw = br"Date: Thu, 28 Jan 2021 00:26:57 +0000
Chat-Version: 1.0\n\
Message-ID: <ABCDEFGH.1234567_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@mailjet.com>
To: Bob <bob@example.org>
From: Alice <alice@example.org>
Subject: ...

Some quote.
";
    receive_imf(&t, raw, false).await?;

    // Delta Chat generates In-Reply-To with a starting tab when Message-ID is too long.
    let raw = br"In-Reply-To:
	<ABCDEFGH.1234567_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@mailjet.com>
Date: Thu, 28 Jan 2021 00:26:57 +0000
Chat-Version: 1.0\n\
Message-ID: <foobar@example.org>
To: Alice <alice@example.org>
From: Bob <bob@example.org>
Subject: ...

> Some quote.

Some reply
";

    receive_imf(&t, raw, false).await?;

    let msg = t.get_last_msg().await;
    assert_eq!(msg.get_text(), "Some reply");
    let quoted_message = msg.quoted_message(&t).await?.unwrap();
    assert_eq!(quoted_message.get_text(), "Some quote.");

    Ok(())
}

// Test that WantsMdn parameter is not set on outgoing messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_wants_mdn() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let raw = br"Date: Thu, 28 Jan 2021 00:26:57 +0000
Chat-Version: 1.0\n\
Message-ID: <foobarbaz@example.org>
To: Bob <bob@example.org>
From: Alice <alice@example.org>
Subject: subject
Chat-Disposition-Notification-To: alice@example.org

Message.
";

    // Bob receives message.
    receive_imf(&bob, raw, false).await?;
    let msg = bob.get_last_msg().await;
    // Message is incoming.
    assert!(msg.param.get_bool(Param::WantsMdn).unwrap());

    // Alice receives copy-to-self.
    receive_imf(&alice, raw, false).await?;
    let msg = alice.get_last_msg().await;
    // Message is outgoing, don't send read receipt to self.
    assert!(msg.param.get_bool(Param::WantsMdn).is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ignore_read_receipt_to_self() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Alice receives BCC-self copy of a message sent to Bob.
    receive_imf(
        &alice,
        "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: alice@example.org\n\
                 To: bob@example.net\n\
                 Subject: foo\n\
                 Message-ID: first@example.com\n\
                 Chat-Version: 1.0\n\
                 Chat-Disposition-Notification-To: alice@example.org\n\
                 Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                 \n\
                 hello\n"
            .as_bytes(),
        false,
    )
    .await?;
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.state, MessageState::OutDelivered);

    // Due to a bug in the old version running on the other device, Alice receives a read
    // receipt from self.
    receive_imf(
            &alice,
                "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                 From: alice@example.org\n\
                 To: alice@example.org\n\
                 Subject: message opened\n\
                 Date: Sun, 22 Mar 2020 23:37:57 +0000\n\
                 Chat-Version: 1.0\n\
                 Message-ID: second@example.com\n\
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
                 Original-Recipient: rfc822;bob@example.com\n\
                 Final-Recipient: rfc822;bob@example.com\n\
                 Original-Message-ID: <first@example.com>\n\
                 Disposition: manual-action/MDN-sent-automatically; displayed\n\
                 \n\
                 \n\
                 --SNIPP--"
            .as_bytes(),
            false,
        )
        .await?;

    // Check that the state has not changed to `MessageState::OutMdnRcvd`.
    let msg = Message::load_from_db(&alice, msg.id).await?;
    assert_eq!(msg.state, MessageState::OutDelivered);

    Ok(())
}

/// Test parsing of MDN sent by MS Exchange.
///
/// It does not have required Original-Message-ID field, so it is useless, but we want to
/// recognize it as MDN nevertheless to avoid displaying it in the chat as normal message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ms_exchange_mdn() -> Result<()> {
    let t = TestContext::new_alice().await;

    let original =
        include_bytes!("../../test-data/message/ms_exchange_report_original_message.eml");
    receive_imf(&t, original, false).await?;
    let original_msg_id = t.get_last_msg().await.id;

    // 1. Test mimeparser directly
    let mdn =
        include_bytes!("../../test-data/message/ms_exchange_report_disposition_notification.eml");
    let mimeparser = MimeMessage::from_bytes(&t.ctx, mdn, None).await?;
    assert_eq!(mimeparser.mdn_reports.len(), 1);
    assert_eq!(
        mimeparser.mdn_reports[0].original_message_id.as_deref(),
        Some("d5904dc344eeb5deaf9bb44603f0c716@posteo.de")
    );
    assert!(mimeparser.mdn_reports[0].additional_message_ids.is_empty());

    // 2. Test that marking the original msg as read works
    receive_imf(&t, mdn, false).await?;

    assert_eq!(
        original_msg_id.get_state(&t).await?,
        MessageState::OutMdnRcvd
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_eml() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let mime_message = MimeMessage::from_bytes(
        &alice,
        include_bytes!("../../test-data/message/attached-eml.eml"),
        None,
    )
    .await?;

    assert_eq!(mime_message.parts.len(), 1);
    assert_eq!(mime_message.parts[0].typ, Viewtype::File);
    assert_eq!(
        mime_message.parts[0].mimetype,
        Some("message/rfc822".parse().unwrap(),)
    );
    assert_eq!(
        mime_message.parts[0].msg,
        "this is a classic email – I attached the .EML file".to_string()
    );
    assert_eq!(
        mime_message.parts[0].param.get(Param::Filename),
        Some(".eml")
    );

    assert_eq!(mime_message.parts[0].org_filename, Some(".eml".to_string()));

    Ok(())
}

/// Tests parsing of MIME message containing RFC 9078 reaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_reaction() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let mime_message = MimeMessage::from_bytes(
        &alice,
        "To: alice@example.org\n\
From: bob@example.net\n\
Date: Today, 29 February 2021 00:00:10 -800\n\
Message-ID: 56789@example.net\n\
In-Reply-To: 12345@example.org\n\
Subject: Meeting\n\
Mime-Version: 1.0 (1.0)\n\
Content-Type: text/plain; charset=utf-8\n\
Content-Disposition: reaction\n\
\n\
\u{1F44D}"
            .as_bytes(),
        None,
    )
    .await?;

    assert_eq!(mime_message.parts.len(), 1);
    assert_eq!(mime_message.parts[0].is_reaction, true);
    assert_eq!(
        mime_message
            .get_header(HeaderDef::InReplyTo)
            .and_then(|msgid| parse_message_id(msgid).ok())
            .unwrap(),
        "12345@example.org"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_jpeg_as_application_octet_stream() -> Result<()> {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/jpeg-as-application-octet-stream.eml");

    let msg = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(msg.parts.len(), 1);
    assert_eq!(msg.parts[0].typ, Viewtype::Image);

    receive_imf(&context, &raw[..], false).await?;
    let msg = context.get_last_msg().await;
    assert_eq!(msg.get_viewtype(), Viewtype::Image);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_schleuder() -> Result<()> {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/schleuder.eml");

    let msg = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(msg.parts.len(), 2);

    // Header part.
    assert_eq!(msg.parts[0].typ, Viewtype::Text);

    // Actual contents part.
    assert_eq!(msg.parts[1].typ, Viewtype::Text);
    assert_eq!(msg.parts[1].msg, "hello,\nbye");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_tlsrpt() -> Result<()> {
    let context = TestContext::new_alice().await;
    let raw = include_bytes!("../../test-data/message/tlsrpt.eml");

    let msg = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(msg.parts.len(), 1);

    assert_eq!(msg.parts[0].typ, Viewtype::File);
    assert_eq!(
        msg.parts[0].msg,
        "Report Domain: nine.testrun.org Submitter: google.com Report-ID: <2024.01.20T00.00.00Z+nine.testrun.org@google.com> – This is an aggregate TLS report from google.com"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_time_in_future() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let beginning_time = time();

    // Receive a message with a date far in the future (year 3004)
    // I'm just going to assume that no one uses this code after the year 3000
    let mime_message = MimeMessage::from_bytes(
        &alice,
        b"To: alice@example.org\n\
              From: bob@example.net\n\
              Date: Today, 29 February 3004 00:00:10 -800\n\
              Message-ID: 56789@example.net\n\
              Subject: Meeting\n\
              Mime-Version: 1.0 (1.0)\n\
              Content-Type: text/plain; charset=utf-8\n\
              \n\
              Hi",
        None,
    )
    .await?;

    // We do allow the time to be in the future a bit (because of unsynchronized clocks),
    // but only 60 seconds:
    assert!(mime_message.timestamp_sent <= time() + 60);
    assert!(mime_message.timestamp_sent >= beginning_time + 60);
    assert!(mime_message.timestamp_rcvd <= time());

    Ok(())
}

/// Tests that subject is not prepended to the message
/// when bot receives it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_bot_no_subject() {
    let context = TestContext::new().await;
    context.set_config(Config::Bot, Some("1")).await.unwrap();
    let raw = br#"Message-ID: <foobar@example.org>
From: foo <foo@example.org>
Subject: Some subject
To: bar@example.org
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

/help
"#;

    let message = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(message.get_subject(), Some("Some subject".to_string()));

    assert_eq!(message.parts.len(), 1);
    assert_eq!(message.parts[0].typ, Viewtype::Text);
    // Not "Some subject – /help"
    assert_eq!(message.parts[0].msg, "/help");
}

/// Tests that Delta Chat takes the last header value
/// rather than the first one if multiple headers
/// are present.
///
/// DKIM signature applies to the last N headers
/// if header name is included N times in
/// DKIM-Signature.
///
/// If the client takes the first header
/// rather than the last, it can be fooled
/// into using unsigned header
/// when signed one is present
/// but not protected by oversigning.
///
/// See
/// <https://www.zone.eu/blog/2024/05/17/bimi-and-dmarc-cant-save-you/>
/// for reference.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_take_last_header() {
    let context = TestContext::new().await;

    // Mallory added second From: header.
    let raw = b"From: mallory@example.org\n\
                    From: alice@example.org\n\
                    Content-Type: text/plain\n\
                    Chat-Version: 1.0\n\
                    \n\
                    Hello\n\
                    ";

    let mimeparser = MimeMessage::from_bytes(&context.ctx, &raw[..], None)
        .await
        .unwrap();
    assert_eq!(
        mimeparser.get_header(HeaderDef::From_).unwrap(),
        "alice@example.org"
    );
}

async fn test_protect_autocrypt(enabled: bool) -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat = alice.create_chat(bob).await;
    alice
        .set_config_bool(Config::ProtectAutocrypt, enabled)
        .await?;
    let sent = alice.send_text(chat.id, "Hello!").await;
    assert_eq!(sent.payload().contains("Autocrypt: "), !enabled);
    let msg = bob.recv_msg(&sent).await;
    assert_eq!(msg.get_showpadlock(), true);

    Ok(())
}

/// Tests that if `protect_autocrypt` is enabled,
/// `Autocrypt` header does not appear in the outer headers
/// of encrypted messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_protect_autocrypt_enabled() -> Result<()> {
    test_protect_autocrypt(true).await
}

/// Tests that if `protect_autocrypt` is disabled,
/// `Autocrypt` header appears in the outer headers
/// of encrypted messages.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_protect_autocrypt_false() -> Result<()> {
    test_protect_autocrypt(false).await
}

/// Tests that CRLF before MIME boundary
/// is not treated as the part body.
///
/// RFC 2046 explicitly says that
/// "The CRLF preceding the boundary delimiter line is conceptually attached
/// to the boundary so that it is possible to have a part that does not end
/// with a CRLF (line break). Body parts that must be considered to end with
/// line breaks, therefore, must have two CRLFs preceding the boundary delimiter
/// line, the first of which is part of the preceding body part,
/// and the second of which is part of the encapsulation boundary."
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mimeparser_trailing_newlines() {
    let context = TestContext::new_alice().await;

    // Example from <https://www.rfc-editor.org/rfc/rfc2046#section-5.1.1>
    // with a `Content-Disposition` headers added to turn files
    // into attachments.
    let raw = b"From: Nathaniel Borenstein <nsb@bellcore.com>\r
To: Ned Freed <ned@innosoft.com>\r
Date: Sun, 21 Mar 1993 23:56:48 -0800 (PST)\r
Subject: Sample message\r
MIME-Version: 1.0\r
Content-type: multipart/mixed; boundary=\"simple boundary\"\r
\r
This is the preamble.  It is to be ignored, though it\r
is a handy place for composition agents to include an\r
explanatory note to non-MIME conformant readers.\r
\r
--simple boundary\r
Content-Disposition: attachment; filename=\"file1.txt\"\r
\r
This is implicitly typed plain US-ASCII text.\r
It does NOT end with a linebreak.\r
--simple boundary\r
Content-type: text/plain; charset=us-ascii\r
Content-Disposition: attachment; filename=\"file2.txt\"\r
\r
This is explicitly typed plain US-ASCII text.\r
It DOES end with a linebreak.\r
\r
--simple boundary--\r
\r
This is the epilogue.  It is also to be ignored.";

    let mimeparser = MimeMessage::from_bytes(&context, &raw[..], None)
        .await
        .unwrap();

    assert_eq!(mimeparser.parts.len(), 2);

    assert_eq!(mimeparser.parts[0].typ, Viewtype::File);
    let blob: BlobObject = mimeparser.parts[0]
        .param
        .get_file_blob(&context)
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::fs::read_to_string(blob.to_abs_path()).await.unwrap(),
        "This is implicitly typed plain US-ASCII text.\r\nIt does NOT end with a linebreak."
    );

    assert_eq!(mimeparser.parts[1].typ, Viewtype::File);
    let blob: BlobObject = mimeparser.parts[1]
        .param
        .get_file_blob(&context)
        .unwrap()
        .unwrap();
    assert_eq!(
        tokio::fs::read_to_string(blob.to_abs_path()).await.unwrap(),
        "This is explicitly typed plain US-ASCII text.\r\nIt DOES end with a linebreak.\r\n"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_hidden_message_id() {
    let t = &TestContext::new().await;
    let raw = br#"Message-ID: bar@example.org
Date: Sun, 08 Dec 2019 23:12:55 +0000
To: <alice@example.org>
From: <tunis4@example.org>
Content-Type: multipart/mixed; boundary="luTiGu6GBoVLCvTkzVtmZmwsmhkNMw"


--luTiGu6GBoVLCvTkzVtmZmwsmhkNMw
Message-ID: foo@example.org
Content-Type: text/plain; charset=utf-8

Message with a correct Message-ID hidden header

--luTiGu6GBoVLCvTkzVtmZmwsmhkNMw--
"#;

    let message = MimeMessage::from_bytes(t, &raw[..], None).await.unwrap();
    assert_eq!(message.get_rfc724_mid().unwrap(), "foo@example.org");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_edit_imf_header() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat = alice.create_email_chat(bob).await;

    // Alice sends a message, then sends an invalid edit request.
    let sent1 = alice.send_text(alice_chat.id, "foo").await;
    let alice_msg = sent1.load_from_db().await;
    assert_eq!(alice_chat.id.get_msg_cnt(alice).await?, 1);

    chat::send_edit_request(alice, alice_msg.id, "bar".to_string()).await?;
    let mut sent2 = alice.pop_sent_msg().await;
    let mut s0 = String::new();
    let mut s1 = String::new();
    for l in sent2.payload.lines() {
        if l.starts_with("Chat-Edit:") {
            s1 += l;
            s1 += "\n";
            continue;
        }
        s0 += l;
        s0 += "\n";
        if l.starts_with("Message-ID:") && s1.is_empty() {
            s1 = mem::take(&mut s0);
        }
    }
    sent2.payload = s1 + &s0;

    // Bob receives both messages, the edit request with "Chat-Edit" in IMF headers is
    // received as text message.
    let bob_msg = bob.recv_msg(&sent1).await;
    assert_eq!(bob_msg.text, "foo");
    assert_eq!(bob_msg.chat_id.get_msg_cnt(bob).await?, 1);
    let bob_msg = bob.recv_msg(&sent2).await;
    assert_eq!(bob_msg.text, constants::EDITED_PREFIX.to_string() + "bar");
    assert_eq!(bob_msg.chat_id.get_msg_cnt(bob).await?, 2);

    Ok(())
}

/// Tests that timestamp of signed but not encrypted message is protected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_protected_date() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    alice.set_config(Config::SignUnencrypted, Some("1")).await?;

    let alice_chat = alice.create_email_chat(bob).await;
    let alice_msg_id = chat::send_text_msg(alice, alice_chat.id, "Hello!".to_string()).await?;
    let alice_msg = Message::load_from_db(alice, alice_msg_id).await?;
    assert_eq!(alice_msg.get_showpadlock(), false);

    let mut sent_msg = alice.pop_sent_msg().await;
    sent_msg.payload = sent_msg.payload.replacen(
        "Date:",
        "Date: Wed, 17 Mar 2021 14:30:53 +0100 (CET)\r\nX-Not-Date:",
        1,
    );
    let bob_msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(alice_msg.get_text(), bob_msg.get_text());

    // Timestamp that the sender has put into the message
    // should always be displayed as is on the receiver.
    assert_eq!(alice_msg.get_timestamp(), bob_msg.get_timestamp());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_huge_image_becomes_file() -> Result<()> {
    let t = TestContext::new_alice().await;
    let msg_id = receive_imf(
        &t,
        include_bytes!("../../test-data/message/image_huge_64M.eml"),
        false,
    )
    .await?
    .unwrap()
    .msg_ids[0];
    let msg = Message::load_from_db(&t.ctx, msg_id).await.unwrap();
    // Huge image should be treated as file:
    assert_eq!(msg.viewtype, Viewtype::File);
    assert!(msg.get_file(&t).is_some());
    assert_eq!(msg.get_filename().unwrap(), "huge_image.png");
    assert_eq!(msg.get_filemime().unwrap(), "image/png");
    // File has no width or height
    assert!(msg.param.get_int(Param::Width).is_none());
    assert!(msg.param.get_int(Param::Height).is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_4k_image_stays_image() -> Result<()> {
    let t = TestContext::new_alice().await;
    let msg_id = receive_imf(
        &t,
        include_bytes!("../../test-data/message/image_4k.eml"),
        false,
    )
    .await?
    .unwrap()
    .msg_ids[0];
    let msg = Message::load_from_db(&t.ctx, msg_id).await.unwrap();
    // 4K image should be treated as image:
    assert_eq!(msg.viewtype, Viewtype::Image);
    assert!(msg.get_file(&t).is_some());
    assert_eq!(msg.get_filename().unwrap(), "4k_image.png");
    assert_eq!(msg.get_filemime().unwrap(), "image/png");
    assert_eq!(msg.param.get_int(Param::Width).unwrap_or_default(), 3840);
    assert_eq!(msg.param.get_int(Param::Height).unwrap_or_default(), 2160);
    Ok(())
}
