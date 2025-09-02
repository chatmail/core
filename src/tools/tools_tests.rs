use chrono::NaiveDate;
use proptest::prelude::*;

use super::*;
use crate::chatlist::Chatlist;
use crate::test_utils::TimeShiftFalsePositiveNote;
use crate::{chat, test_utils};
use crate::{receive_imf::receive_imf, test_utils::TestContext};

#[test]
fn test_parse_receive_headers() {
    // Test `parse_receive_headers()` with some more-or-less random emails from the test-data
    let raw = include_bytes!("../../test-data/message/mail_with_cc.txt");
    let expected = "Hop: From: localhost; By: hq5.merlinux.eu; Date: Sat, 14 Sep 2019 17:00:22 +0000\n\
             Hop: From: hq5.merlinux.eu; By: hq5.merlinux.eu; Date: Sat, 14 Sep 2019 17:00:25 +0000";
    check_parse_receive_headers(raw, expected);

    let raw = include_bytes!("../../test-data/message/wrong-html.eml");
    let expected = "Hop: From: oxbsltgw18.schlund.de; By: mrelayeu.kundenserver.de; Date: Thu, 6 Aug 2020 16:40:31 +0000\n\
             Hop: From: mout.kundenserver.de; By: dd37930.kasserver.com; Date: Thu, 6 Aug 2020 16:40:32 +0000";
    check_parse_receive_headers(raw, expected);

    let raw = include_bytes!("../../test-data/message/posteo_ndn.eml");
    let expected = "Hop: By: mout01.posteo.de; Date: Tue, 9 Jun 2020 18:44:22 +0000\n\
             Hop: From: mout01.posteo.de; By: mx04.posteo.de; Date: Tue, 9 Jun 2020 18:44:22 +0000\n\
             Hop: From: mx04.posteo.de; By: mailin06.posteo.de; Date: Tue, 9 Jun 2020 18:44:23 +0000\n\
             Hop: From: mailin06.posteo.de; By: proxy02.posteo.de; Date: Tue, 9 Jun 2020 18:44:23 +0000\n\
             Hop: From: proxy02.posteo.de; By: proxy02.posteo.name; Date: Tue, 9 Jun 2020 18:44:23 +0000\n\
             Hop: From: proxy02.posteo.name; By: dovecot03.posteo.local; Date: Tue, 9 Jun 2020 18:44:24 +0000";
    check_parse_receive_headers(raw, expected);
}

fn check_parse_receive_headers(raw: &[u8], expected: &str) {
    let mail = mailparse::parse_mail(raw).unwrap();
    let hop_info = parse_receive_headers(&mail.get_headers());
    assert_eq!(hop_info, expected)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_receive_headers_integration() {
    let raw = include_bytes!("../../test-data/message/mail_with_cc.txt");
    let expected = r"State: Fresh

Message-ID: 2dfdbde7@example.org

Hop: From: localhost; By: hq5.merlinux.eu; Date: Sat, 14 Sep 2019 17:00:22 +0000
Hop: From: hq5.merlinux.eu; By: hq5.merlinux.eu; Date: Sat, 14 Sep 2019 17:00:25 +0000

DKIM Results: Passed=true";
    check_parse_receive_headers_integration(raw, expected).await;

    let raw = include_bytes!("../../test-data/message/encrypted_with_received_headers.eml");
    let expected = "State: Fresh, Encrypted

Message-ID: Mr.adQpEwndXLH.LPDdlFVJ7wG@example.net

Hop: From: [127.0.0.1]; By: mail.example.org; Date: Mon, 27 Dec 2021 11:21:21 +0000
Hop: From: mout.example.org; By: hq5.example.org; Date: Mon, 27 Dec 2021 11:21:22 +0000
Hop: From: hq5.example.org; By: hq5.example.org; Date: Mon, 27 Dec 2021 11:21:22 +0000

DKIM Results: Passed=true";
    check_parse_receive_headers_integration(raw, expected).await;
}

async fn check_parse_receive_headers_integration(raw: &[u8], expected: &str) {
    let t = TestContext::new_alice().await;
    receive_imf(&t, raw, false).await.unwrap();
    let msg = t.get_last_msg().await;
    let msg_info = msg.id.get_info(&t).await.unwrap();

    // Ignore the first rows of the msg_info because they contain a
    // received time that depends on the test time which makes it impossible to
    // compare with a static string
    let capped_result = &msg_info[msg_info.find("State").unwrap()..];
    assert_eq!(expected, capped_result);
}

#[test]
fn test_rust_ftoa() {
    assert_eq!("1.22", format!("{}", 1.22));
}

#[test]
fn test_truncate_1() {
    let s = "this is a little test string";
    assert_eq!(truncate(s, 16), "this is a [...]");
}

#[test]
fn test_truncate_2() {
    assert_eq!(truncate("1234", 2), "1234");
}

#[test]
fn test_truncate_3() {
    assert_eq!(truncate("1234567", 1), "1[...]");
}

#[test]
fn test_truncate_4() {
    assert_eq!(truncate("123456", 4), "123456");
}

#[test]
fn test_truncate_edge() {
    assert_eq!(truncate("", 4), "");

    assert_eq!(truncate("\n  hello \n world", 4), "\n  [...]");

    assert_eq!(truncate("𐠈0Aᝮa𫝀®!ꫛa¡0A𐢧00𐹠®A  丽ⷐએ", 1), "𐠈[...]");
    assert_eq!(truncate("𐠈0Aᝮa𫝀®!ꫛa¡0A𐢧00𐹠®A  丽ⷐએ", 0), "[...]");

    // 9 characters, so no truncation
    assert_eq!(truncate("𑒀ὐ￠🜀\u{1e01b}A a🟠", 6), "𑒀ὐ￠🜀\u{1e01b}A a🟠",);

    // 12 characters, truncation
    assert_eq!(
        truncate("𑒀ὐ￠🜀\u{1e01b}A a🟠bcd", 6),
        "𑒀ὐ￠🜀\u{1e01b}A[...]",
    );
}

mod truncate_by_lines {
    use super::*;

    #[test]
    fn test_just_text() {
        let s = "this is a little test string".to_string();
        assert_eq!(
            truncate_by_lines(s, 4, 6),
            ("this is a little test [...]".to_string(), true)
        );
    }

    #[test]
    fn test_with_linebreaks() {
        let s = "this\n is\n a little test string".to_string();
        assert_eq!(
            truncate_by_lines(s, 4, 6),
            ("this\n is\n a little [...]".to_string(), true)
        );
    }

    #[test]
    fn test_only_linebreaks() {
        let s = "\n\n\n\n\n\n\n".to_string();
        assert_eq!(
            truncate_by_lines(s, 4, 5),
            ("\n\n\n[...]".to_string(), true)
        );
    }

    #[test]
    fn limit_hits_end() {
        let s = "hello\n world !".to_string();
        assert_eq!(
            truncate_by_lines(s, 2, 8),
            ("hello\n world !".to_string(), false)
        );
    }

    #[test]
    fn test_edge() {
        assert_eq!(
            truncate_by_lines("".to_string(), 2, 4),
            ("".to_string(), false)
        );

        assert_eq!(
            truncate_by_lines("\n  hello \n world".to_string(), 2, 4),
            ("\n  [...]".to_string(), true)
        );
        assert_eq!(
            truncate_by_lines("𐠈0Aᝮa𫝀®!ꫛa¡0A𐢧00𐹠®A  丽ⷐએ".to_string(), 1, 2),
            ("𐠈0[...]".to_string(), true)
        );
        assert_eq!(
            truncate_by_lines("𐠈0Aᝮa𫝀®!ꫛa¡0A𐢧00𐹠®A  丽ⷐએ".to_string(), 1, 0),
            ("[...]".to_string(), true)
        );

        // 9 characters, so no truncation
        assert_eq!(
            truncate_by_lines("𑒀ὐ￠🜀\u{1e01b}A a🟠".to_string(), 1, 12),
            ("𑒀ὐ￠🜀\u{1e01b}A a🟠".to_string(), false),
        );

        // 12 characters, truncation
        assert_eq!(
            truncate_by_lines("𑒀ὐ￠🜀\u{1e01b}A a🟠bcd".to_string(), 1, 7),
            ("𑒀ὐ￠🜀\u{1e01b}A [...]".to_string(), true),
        );
    }
}

#[test]
fn test_create_id() {
    let buf = create_id();
    assert_eq!(buf.len(), 24);
}

#[test]
fn test_validate_id() {
    for _ in 0..10 {
        assert!(validate_id(&create_id()));
    }

    assert_eq!(validate_id("aaaaaaaaaaaa"), true);
    assert_eq!(validate_id("aa-aa_aaaXaa"), true);

    // ID cannot contain whitespace.
    assert_eq!(validate_id("aaaaa aaaaaa"), false);
    assert_eq!(validate_id("aaaaa\naaaaaa"), false);

    // ID cannot contain "/", "+".
    assert_eq!(validate_id("aaaaa/aaaaaa"), false);
    assert_eq!(validate_id("aaaaaaaa+aaa"), false);

    // Too long ID.
    assert_eq!(validate_id("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), false);
}

#[test]
fn test_create_id_invalid_chars() {
    for _ in 1..1000 {
        let buf = create_id();
        assert!(!buf.contains('/')); // `/` must not be used to be URL-safe
        assert!(!buf.contains('.')); // `.` is used as a delimiter when extracting grpid from Message-ID
    }
}

#[test]
fn test_create_outgoing_rfc724_mid() {
    let mid = create_outgoing_rfc724_mid();
    assert_eq!(mid.len(), 46);
    assert!(mid.contains("-")); // It has an UUID inside.
    assert!(mid.ends_with("@localhost"));
}

proptest! {
    #[test]
    fn test_truncate(
        buf: String,
        approx_chars in 0..100usize
    ) {
        let res = truncate(&buf, approx_chars);
        let el_len = 5;
        let l = res.chars().count();
        assert!(
            l <= approx_chars + el_len,
            "buf: '{}' - res: '{}' - len {}, approx {}",
            &buf, &res, res.len(), approx_chars
        );

        if buf.chars().count() > approx_chars + el_len {
            let l = res.len();
            assert_eq!(&res[l-5..l], "[...]", "missing ellipsis in {}", &res);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_file_handling() {
    let t = TestContext::new().await;
    let context = &t;
    macro_rules! file_exist {
        ($ctx:expr, $fname:expr) => {
            $ctx.get_blobdir()
                .join(Path::new($fname).file_name().unwrap())
                .exists()
        };
    }

    assert!(
        delete_file(context, Path::new("$BLOBDIR/lkqwjelqkwlje"))
            .await
            .is_err()
    );
    assert!(
        write_file(context, Path::new("$BLOBDIR/foobar"), b"content")
            .await
            .is_ok()
    );
    assert!(file_exist!(context, "$BLOBDIR/foobar"));
    assert!(!file_exist!(context, "$BLOBDIR/foobarx"));
    assert_eq!(
        get_filebytes(context, Path::new("$BLOBDIR/foobar"))
            .await
            .unwrap(),
        7
    );

    let abs_path = context
        .get_blobdir()
        .join("foobar")
        .to_string_lossy()
        .to_string();

    assert!(file_exist!(context, &abs_path));

    assert!(
        delete_file(context, Path::new("$BLOBDIR/foobar"))
            .await
            .is_ok()
    );
    assert!(
        create_folder(context, Path::new("$BLOBDIR/foobar-folder"))
            .await
            .is_ok()
    );
    assert!(file_exist!(context, "$BLOBDIR/foobar-folder"));
    assert!(
        delete_file(context, Path::new("$BLOBDIR/foobar-folder"))
            .await
            .is_err()
    );

    let fn0 = "$BLOBDIR/data.data";
    assert!(
        write_file(context, Path::new(fn0), b"content")
            .await
            .is_ok()
    );

    assert!(delete_file(context, Path::new(fn0)).await.is_ok());
    assert!(!file_exist!(context, &fn0));
}

#[test]
fn test_duration_to_str() {
    assert_eq!(duration_to_str(Duration::from_secs(0)), "0h 0m 0s");
    assert_eq!(duration_to_str(Duration::from_secs(59)), "0h 0m 59s");
    assert_eq!(duration_to_str(Duration::from_secs(60)), "0h 1m 0s");
    assert_eq!(duration_to_str(Duration::from_secs(61)), "0h 1m 1s");
    assert_eq!(duration_to_str(Duration::from_secs(59 * 60)), "0h 59m 0s");
    assert_eq!(
        duration_to_str(Duration::from_secs(59 * 60 + 59)),
        "0h 59m 59s"
    );
    assert_eq!(
        duration_to_str(Duration::from_secs(59 * 60 + 60)),
        "1h 0m 0s"
    );
    assert_eq!(
        duration_to_str(Duration::from_secs(2 * 60 * 60 + 59 * 60 + 59)),
        "2h 59m 59s"
    );
    assert_eq!(
        duration_to_str(Duration::from_secs(2 * 60 * 60 + 59 * 60 + 60)),
        "3h 0m 0s"
    );
    assert_eq!(
        duration_to_str(Duration::from_secs(3 * 60 * 60 + 59)),
        "3h 0m 59s"
    );
    assert_eq!(
        duration_to_str(Duration::from_secs(3 * 60 * 60 + 60)),
        "3h 1m 0s"
    );
}

#[test]
fn test_get_filemeta() {
    let (w, h) = get_filemeta(test_utils::AVATAR_900x900_BYTES).unwrap();
    assert_eq!(w, 900);
    assert_eq!(h, 900);

    let data = include_bytes!("../../test-data/image/avatar1000x1000.jpg");
    let (w, h) = get_filemeta(data).unwrap();
    assert_eq!(w, 1000);
    assert_eq!(h, 1000);

    let data = include_bytes!("../../test-data/image/image100x50.gif");
    let (w, h) = get_filemeta(data).unwrap();
    assert_eq!(w, 100);
    assert_eq!(h, 50);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_warn_on_bad_time() {
    let t = TestContext::new().await;
    let timestamp_now = time();
    let timestamp_future = timestamp_now + 60 * 60 * 24 * 7;
    let timestamp_past = NaiveDateTime::new(
        NaiveDate::from_ymd_opt(2020, 9, 1).unwrap(),
        NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
    )
    .and_utc()
    .timestamp_millis()
        / 1_000;

    // a correct time must not add a device message
    maybe_warn_on_bad_time(&t, timestamp_now, get_release_timestamp()).await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);

    // we cannot find out if a date in the future is wrong - a device message is not added
    maybe_warn_on_bad_time(&t, timestamp_future, get_release_timestamp()).await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);

    // a date in the past must add a device message
    maybe_warn_on_bad_time(&t, timestamp_past, get_release_timestamp()).await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let device_chat_id = chats.get_chat_id(0).unwrap();
    let msgs = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    assert_eq!(msgs.len(), 1);

    // the message should be added only once a day - test that an hour later and nearly a day later
    maybe_warn_on_bad_time(&t, timestamp_past + 60 * 60, get_release_timestamp()).await;
    let msgs = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    assert_eq!(msgs.len(), 1);

    maybe_warn_on_bad_time(
        &t,
        timestamp_past + 60 * 60 * 24 - 1,
        get_release_timestamp(),
    )
    .await;
    let msgs = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    assert_eq!(msgs.len(), 1);

    // next day, there should be another device message
    maybe_warn_on_bad_time(&t, timestamp_past + 60 * 60 * 24, get_release_timestamp()).await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    assert_eq!(device_chat_id, chats.get_chat_id(0).unwrap());
    let msgs = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    assert_eq!(msgs.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_maybe_warn_on_outdated() {
    let _n = TimeShiftFalsePositiveNote;

    let t = TestContext::new().await;
    let timestamp_now: i64 = time();

    // in about 3 months, the app should not be outdated.
    // "90 days" has proven to be too short at some point - user were informed but there was no update
    maybe_warn_on_outdated(
        &t,
        timestamp_now + 90 * 24 * 60 * 60,
        get_release_timestamp(),
    )
    .await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);

    // in 1 year, the app should be considered as outdated
    maybe_warn_on_outdated(
        &t,
        timestamp_now + 365 * 24 * 60 * 60,
        get_release_timestamp(),
    )
    .await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let device_chat_id = chats.get_chat_id(0).unwrap();
    let msgs = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    assert_eq!(msgs.len(), 1);

    // do not repeat the warning every day ...
    // (we test that for the 2 subsequent days, this may be the next month, so the result should be 1 or 2 device message)
    maybe_warn_on_outdated(
        &t,
        timestamp_now + (365 + 1) * 24 * 60 * 60,
        get_release_timestamp(),
    )
    .await;
    maybe_warn_on_outdated(
        &t,
        timestamp_now + (365 + 2) * 24 * 60 * 60,
        get_release_timestamp(),
    )
    .await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let device_chat_id = chats.get_chat_id(0).unwrap();
    let msgs = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    let test_len = msgs.len();
    assert!(test_len == 1 || test_len == 2);

    // ... but every month
    // (forward generous 33 days to avoid being in the same month as in the previous check)
    maybe_warn_on_outdated(
        &t,
        timestamp_now + (365 + 33) * 24 * 60 * 60,
        get_release_timestamp(),
    )
    .await;
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);
    let device_chat_id = chats.get_chat_id(0).unwrap();
    let msgs = chat::get_chat_msgs(&t, device_chat_id).await.unwrap();
    assert_eq!(msgs.len(), test_len + 1);
}

#[test]
fn test_get_release_timestamp() {
    let timestamp_past = NaiveDateTime::new(
        NaiveDate::from_ymd_opt(2020, 9, 9).unwrap(),
        NaiveTime::from_hms_opt(0, 0, 0).unwrap(),
    )
    .and_utc()
    .timestamp_millis()
        / 1_000;
    assert!(get_release_timestamp() <= time());
    assert!(get_release_timestamp() > timestamp_past);
}

#[test]
fn test_remove_subject_prefix() {
    assert_eq!(remove_subject_prefix("Subject"), "Subject");
    assert_eq!(
        remove_subject_prefix("Chat: Re: Subject"),
        "Chat: Re: Subject"
    );
    assert_eq!(remove_subject_prefix("Re: Subject"), "Subject");
    assert_eq!(remove_subject_prefix("Fwd: Subject"), "Subject");
    assert_eq!(remove_subject_prefix("Fw: Subject"), "Subject");
}

#[test]
fn test_parse_mailto() {
    let mailto_url = "mailto:someone@example.com";
    let reps = parse_mailto(mailto_url);
    assert_eq!(
        Some(MailTo {
            to: vec![EmailAddress {
                local: "someone".to_string(),
                domain: "example.com".to_string()
            }],
            subject: None,
            body: None
        }),
        reps
    );

    let mailto_url = "mailto:someone@example.com?subject=Hello%20World";
    let reps = parse_mailto(mailto_url);
    assert_eq!(
        Some(MailTo {
            to: vec![EmailAddress {
                local: "someone".to_string(),
                domain: "example.com".to_string()
            }],
            subject: Some("Hello World".to_string()),
            body: None
        }),
        reps
    );

    let mailto_url = "mailto:someone@example.com,someoneelse@example.com?subject=Hello%20World&body=This%20is%20a%20test";
    let reps = parse_mailto(mailto_url);
    assert_eq!(
        Some(MailTo {
            to: vec![
                EmailAddress {
                    local: "someone".to_string(),
                    domain: "example.com".to_string()
                },
                EmailAddress {
                    local: "someoneelse".to_string(),
                    domain: "example.com".to_string()
                }
            ],
            subject: Some("Hello World".to_string()),
            body: Some("This is a test".to_string())
        }),
        reps
    );
}

#[test]
fn test_sanitize_filename() {
    let name = sanitize_filename("Я ЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯЯ.txt");
    assert!(!name.is_empty());

    let name = sanitize_filename("wot.tar.gz");
    assert_eq!(name, "wot.tar.gz");

    let name = sanitize_filename(".foo.bar");
    assert_eq!(name, "file.foo.bar");

    let name = sanitize_filename("foo?.bar");
    assert_eq!(name, "foo.bar");
    assert!(!name.contains('?'));

    let name = sanitize_filename("no-extension");
    assert_eq!(name, "no-extension");

    let name = sanitize_filename("path/ignored\\this: is* forbidden?.c");
    assert_eq!(name, "this is forbidden.c");

    let name =
        sanitize_filename("file.with_lots_of_characters_behind_point_and_double_ending.tar.gz");
    assert_eq!(
        name,
        "file.with_lots_of_characters_behind_point_and_double_ending.tar.gz"
    );

    let name = sanitize_filename("a. tar.tar.gz");
    assert_eq!(name, "a. tar.tar.gz");

    let name = sanitize_filename("Guia_uso_GNB (v0.8).pdf");
    assert_eq!(name, "Guia_uso_GNB (v0.8).pdf");
}
