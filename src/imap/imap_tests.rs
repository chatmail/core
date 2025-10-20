use super::*;
use crate::test_utils::TestContext;

#[test]
fn test_get_folder_meaning_by_name() {
    assert_eq!(get_folder_meaning_by_name("xxx"), FolderMeaning::Unknown);
    assert_eq!(get_folder_meaning_by_name("SPAM"), FolderMeaning::Spam);
    assert_eq!(get_folder_meaning_by_name("Trash"), FolderMeaning::Trash);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_uid_next_validity() {
    let t = TestContext::new_alice().await;
    assert_eq!(get_uid_next(&t.ctx, "Inbox").await.unwrap(), 0);
    assert_eq!(get_uidvalidity(&t.ctx, "Inbox").await.unwrap(), 0);

    set_uidvalidity(&t.ctx, "Inbox", 7).await.unwrap();
    assert_eq!(get_uidvalidity(&t.ctx, "Inbox").await.unwrap(), 7);
    assert_eq!(get_uid_next(&t.ctx, "Inbox").await.unwrap(), 0);

    set_uid_next(&t.ctx, "Inbox", 5).await.unwrap();
    set_uidvalidity(&t.ctx, "Inbox", 6).await.unwrap();
    assert_eq!(get_uid_next(&t.ctx, "Inbox").await.unwrap(), 5);
    assert_eq!(get_uidvalidity(&t.ctx, "Inbox").await.unwrap(), 6);
}

#[test]
fn test_build_sequence_sets() {
    assert_eq!(build_sequence_sets(&[]).unwrap(), vec![]);

    let cases = vec![
        (vec![1], "1"),
        (vec![3291], "3291"),
        (vec![1, 3, 5, 7, 9, 11], "1,3,5,7,9,11"),
        (vec![1, 2, 3], "1:3"),
        (vec![1, 4, 5, 6], "1,4:6"),
        ((1..=500).collect(), "1:500"),
        (vec![3, 4, 8, 9, 10, 11, 39, 50, 2], "3:4,8:11,39,50,2"),
    ];
    for (input, s) in cases {
        assert_eq!(
            build_sequence_sets(&input).unwrap(),
            vec![(input, s.into())]
        );
    }

    let has_number = |(uids, s): &(Vec<u32>, String), number| {
        uids.contains(&number) && s.split(',').any(|n| n.parse::<u32>().unwrap() == number)
    };

    let numbers: Vec<_> = (2..=500).step_by(2).collect();
    let result = build_sequence_sets(&numbers).unwrap();
    for (_, set) in &result {
        assert!(set.len() < 1010);
        assert!(!set.ends_with(','));
        assert!(!set.starts_with(','));
    }
    assert!(result.len() == 1); // these UIDs fit in one set
    for &number in &numbers {
        assert!(result.iter().any(|r| has_number(r, number)));
    }

    let numbers: Vec<_> = (1..=1000).step_by(3).collect();
    let result = build_sequence_sets(&numbers).unwrap();
    for (_, set) in &result {
        assert!(set.len() < 1010);
        assert!(!set.ends_with(','));
        assert!(!set.starts_with(','));
    }
    let (last_uids, last_str) = result.last().unwrap();
    assert_eq!(
        last_uids.get((last_uids.len() - 2)..).unwrap(),
        &[997, 1000]
    );
    assert!(last_str.ends_with("997,1000"));
    assert!(result.len() == 2); // This time we need 2 sets
    for &number in &numbers {
        assert!(result.iter().any(|r| has_number(r, number)));
    }

    let numbers: Vec<_> = (30000000..=30002500).step_by(4).collect();
    let result = build_sequence_sets(&numbers).unwrap();
    for (_, set) in &result {
        assert!(set.len() < 1010);
        assert!(!set.ends_with(','));
        assert!(!set.starts_with(','));
    }
    assert_eq!(result.len(), 6);
    for &number in &numbers {
        assert!(result.iter().any(|r| has_number(r, number)));
    }
}

async fn check_target_folder_combination(
    folder: &str,
    mvbox_move: bool,
    chat_msg: bool,
    expected_destination: &str,
    accepted_chat: bool,
    outgoing: bool,
    setupmessage: bool,
) -> Result<()> {
    println!(
        "Testing: For folder {folder}, mvbox_move {mvbox_move}, chat_msg {chat_msg}, accepted {accepted_chat}, outgoing {outgoing}, setupmessage {setupmessage}"
    );

    let t = TestContext::new_alice().await;
    t.ctx
        .set_config(Config::ConfiguredMvboxFolder, Some("DeltaChat"))
        .await?;
    t.ctx
        .set_config(Config::MvboxMove, Some(if mvbox_move { "1" } else { "0" }))
        .await?;

    if accepted_chat {
        let contact_id = Contact::create(&t.ctx, "", "bob@example.net").await?;
        ChatId::create_for_contact(&t.ctx, contact_id).await?;
    }
    let temp;

    let bytes = if setupmessage {
        include_bytes!("../../test-data/message/AutocryptSetupMessage.eml")
    } else {
        temp = format!(
            "Received: (Postfix, from userid 1000); Mon, 4 Dec 2006 14:51:39 +0100 (CET)\n\
                    {}\
                    Subject: foo\n\
                    Message-ID: <abc@example.com>\n\
                    {}\
                    Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
                    \n\
                    hello\n",
            if outgoing {
                "From: alice@example.org\nTo: bob@example.net\n"
            } else {
                "From: bob@example.net\nTo: alice@example.org\n"
            },
            if chat_msg { "Chat-Version: 1.0\n" } else { "" },
        );
        temp.as_bytes()
    };

    let (headers, _) = mailparse::parse_headers(bytes)?;
    let actual = if let Some(config) =
        target_folder_cfg(&t, folder, get_folder_meaning_by_name(folder), &headers).await?
    {
        t.get_config(config).await?
    } else {
        None
    };

    let expected = if expected_destination == folder {
        None
    } else {
        Some(expected_destination)
    };
    assert_eq!(
        expected,
        actual.as_deref(),
        "For folder {folder}, mvbox_move {mvbox_move}, chat_msg {chat_msg}, accepted {accepted_chat}, outgoing {outgoing}, setupmessage {setupmessage}: expected {expected:?}, got {actual:?}"
    );
    Ok(())
}

// chat_msg means that the message was sent by Delta Chat
// The tuples are (folder, mvbox_move, chat_msg, expected_destination)
const COMBINATIONS_ACCEPTED_CHAT: &[(&str, bool, bool, &str)] = &[
    ("INBOX", false, false, "INBOX"),
    ("INBOX", false, true, "INBOX"),
    ("INBOX", true, false, "INBOX"),
    ("INBOX", true, true, "DeltaChat"),
    ("Spam", false, false, "INBOX"), // Move classical emails in accepted chats from Spam to Inbox, not 100% sure on this, we could also just never move non-chat-msgs
    ("Spam", false, true, "INBOX"),
    ("Spam", true, false, "INBOX"), // Move classical emails in accepted chats from Spam to Inbox, not 100% sure on this, we could also just never move non-chat-msgs
    ("Spam", true, true, "DeltaChat"),
];

// These are the same as above, but non-chat messages in Spam stay in Spam
const COMBINATIONS_REQUEST: &[(&str, bool, bool, &str)] = &[
    ("INBOX", false, false, "INBOX"),
    ("INBOX", false, true, "INBOX"),
    ("INBOX", true, false, "INBOX"),
    ("INBOX", true, true, "DeltaChat"),
    ("Spam", false, false, "Spam"),
    ("Spam", false, true, "INBOX"),
    ("Spam", true, false, "Spam"),
    ("Spam", true, true, "DeltaChat"),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_target_folder_incoming_accepted() -> Result<()> {
    for (folder, mvbox_move, chat_msg, expected_destination) in COMBINATIONS_ACCEPTED_CHAT {
        check_target_folder_combination(
            folder,
            *mvbox_move,
            *chat_msg,
            expected_destination,
            true,
            false,
            false,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_target_folder_incoming_request() -> Result<()> {
    for (folder, mvbox_move, chat_msg, expected_destination) in COMBINATIONS_REQUEST {
        check_target_folder_combination(
            folder,
            *mvbox_move,
            *chat_msg,
            expected_destination,
            false,
            false,
            false,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_target_folder_outgoing() -> Result<()> {
    // Test outgoing emails
    for (folder, mvbox_move, chat_msg, expected_destination) in COMBINATIONS_ACCEPTED_CHAT {
        check_target_folder_combination(
            folder,
            *mvbox_move,
            *chat_msg,
            expected_destination,
            true,
            true,
            false,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_target_folder_setupmsg() -> Result<()> {
    // Test setupmessages
    for (folder, mvbox_move, chat_msg, _expected_destination) in COMBINATIONS_ACCEPTED_CHAT {
        check_target_folder_combination(
            folder,
            *mvbox_move,
            *chat_msg,
            if folder == &"Spam" { "INBOX" } else { folder }, // Never move setup messages, except if they are in "Spam"
            false,
            true,
            true,
        )
        .await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_imap_search_command() -> Result<()> {
    let t = TestContext::new_alice().await;
    assert_eq!(
        get_imap_self_sent_search_command(&t.ctx).await?,
        r#"FROM "alice@example.org""#
    );

    t.ctx.set_primary_self_addr("alice@another.com").await?;
    assert_eq!(
        get_imap_self_sent_search_command(&t.ctx).await?,
        r#"OR (FROM "alice@another.com") (FROM "alice@example.org")"#
    );

    t.ctx.set_primary_self_addr("alice@third.com").await?;
    assert_eq!(
        get_imap_self_sent_search_command(&t.ctx).await?,
        r#"OR (OR (FROM "alice@third.com") (FROM "alice@another.com")) (FROM "alice@example.org")"#
    );

    Ok(())
}

#[test]
fn test_uid_grouper() {
    // Input: sequence of (rowid: i64, uid: u32, target: String)
    // Output: sequence of (target: String, rowid_set: Vec<i64>, uid_set: String)
    let grouper = UidGrouper::from([(1, 2, "INBOX".to_string())]);
    let res: Vec<(String, Vec<i64>, String)> = grouper.into_iter().collect();
    assert_eq!(res, vec![("INBOX".to_string(), vec![1], "2".to_string())]);

    let grouper = UidGrouper::from([(1, 2, "INBOX".to_string()), (2, 3, "INBOX".to_string())]);
    let res: Vec<(String, Vec<i64>, String)> = grouper.into_iter().collect();
    assert_eq!(
        res,
        vec![("INBOX".to_string(), vec![1, 2], "2:3".to_string())]
    );

    let grouper = UidGrouper::from([
        (1, 2, "INBOX".to_string()),
        (2, 2, "INBOX".to_string()),
        (3, 3, "INBOX".to_string()),
    ]);
    let res: Vec<(String, Vec<i64>, String)> = grouper.into_iter().collect();
    assert_eq!(
        res,
        vec![("INBOX".to_string(), vec![1, 2, 3], "2:3".to_string())]
    );
}

#[test]
fn test_setmetadata_device_token() {
    assert_eq!(
        format_setmetadata("INBOX", "foobarbaz"),
        "SETMETADATA \"INBOX\" (/private/devicetoken {9+}\r\nfoobarbaz)"
    );
    assert_eq!(
        format_setmetadata("INBOX", "foo\r\nbar\r\nbaz\r\n"),
        "SETMETADATA \"INBOX\" (/private/devicetoken {15+}\r\nfoo\r\nbar\r\nbaz\r\n)"
    );
}
