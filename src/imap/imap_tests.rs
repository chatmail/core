use super::*;
use crate::test_utils::{TestContext, TestContextManager};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_uid_next_validity() {
    let t = TestContext::new_alice().await;
    assert_eq!(get_uid_next(&t.ctx, 1, "Inbox").await.unwrap(), 0);
    assert_eq!(get_uidvalidity(&t.ctx, 1, "Inbox").await.unwrap(), 0);

    set_uidvalidity(&t.ctx, 1, "Inbox", 7).await.unwrap();
    assert_eq!(get_uidvalidity(&t.ctx, 1, "Inbox").await.unwrap(), 7);
    assert_eq!(get_uid_next(&t.ctx, 1, "Inbox").await.unwrap(), 0);

    // For another transport there is still no UIDVALIDITY set.
    assert_eq!(get_uidvalidity(&t.ctx, 2, "Inbox").await.unwrap(), 0);

    set_uid_next(&t.ctx, 1, "Inbox", 5).await.unwrap();
    set_uidvalidity(&t.ctx, 1, "Inbox", 6).await.unwrap();
    assert_eq!(get_uid_next(&t.ctx, 1, "Inbox").await.unwrap(), 5);
    assert_eq!(get_uidvalidity(&t.ctx, 1, "Inbox").await.unwrap(), 6);

    assert_eq!(get_uid_next(&t.ctx, 2, "Inbox").await.unwrap(), 0);
    assert_eq!(get_uidvalidity(&t.ctx, 2, "Inbox").await.unwrap(), 0);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_loop_queries_do_not_scan_imap() -> Result<()> {
    let t = TestContext::new_alice().await;
    let mut scans = Vec::new();
    for (name, query) in [
        ("PENDING_DELETIONS", PENDING_DELETIONS),
        ("PENDING_SEEN_FLAGS", PENDING_SEEN_FLAGS),
    ] {
        for step in t.query_plan(query).await? {
            // A step on the `imap` table (not `imap_markseen`) may only look up single rows
            // by rowid or read the partial index of rows pending deletion. With any other index
            // SQLite walks at least every `imap` row of the transport.
            let reads_imap = step.contains(" imap ") || step.ends_with(" imap");
            if reads_imap
                && !step.contains("USING INTEGER PRIMARY KEY (rowid=?)")
                && !step.contains("USING INDEX imap_pending_deletions ")
            {
                scans.push(format!("{name}: {step}"));
            }
        }
    }
    assert!(scans.is_empty(), "{scans:#?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_is_encrypted_copy_of_downloaded_msg() -> Result<()> {
    let t = TestContext::new_alice().await;

    for (rfc724_mid, pre_rfc724_mid, download_state) in [
        ("done@localhost", "", DownloadState::Done),
        (
            "available_post@localhost",
            "pre@localhost",
            DownloadState::Available,
        ),
    ] {
        t.sql
            .execute(
                "INSERT INTO msgs (rfc724_mid, pre_rfc724_mid, download_state) VALUES (?,?,?)",
                (rfc724_mid, pre_rfc724_mid, download_state),
            )
            .await?;
    }

    let encrypted: &[u8] = b"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"x\"\r\n\r\n";
    let unencrypted: &[u8] = b"Content-Type: text/plain\r\n\r\n";
    for (headers, message_id, expected) in [
        (encrypted, "done@localhost", true),
        (unencrypted, "done@localhost", false),
        (encrypted, "pre@localhost", true),
        (encrypted, "available_post@localhost", false),
        (encrypted, "unknown@localhost", false),
    ] {
        let (headers, _) = mailparse::parse_headers(headers)?;
        assert_eq!(
            is_encrypted_copy_of_downloaded_msg(&t, &headers, message_id).await?,
            expected,
            "{message_id}"
        );
    }
    Ok(())
}

/// Adds an `imap` row for `payload` on each of `transport_ids`, like prefetching does,
/// then receives the message like `fetch_many_msgs()` does.
/// Returns the Message-ID used for the `imap` rows.
async fn recv_with_imap_rows(
    t: &TestContext,
    payload: &[u8],
    transport_ids: &[u32],
) -> Result<(String, Option<crate::receive_imf::ReceivedMsg>)> {
    let rfc724_mid = add_imap_rows(t, payload, transport_ids).await?;
    let received = crate::receive_imf::receive_imf_inner(t, &rfc724_mid, payload, false).await?;
    Ok((rfc724_mid, received))
}

async fn add_imap_rows(t: &TestContext, payload: &[u8], transport_ids: &[u32]) -> Result<String> {
    let mail = mailparse::parse_mail(payload)?;
    let rfc724_mid = prefetch_get_message_id(&mail.headers).unwrap();
    for transport_id in transport_ids {
        t.sql
            .execute(
                "INSERT INTO imap (transport_id, rfc724_mid, folder, uid, target, uidvalidity)
                 VALUES (?1, ?2, 'INBOX',
                         (SELECT IFNULL(MAX(uid), 0) + 1 FROM imap WHERE transport_id=?1),
                         'INBOX', 1)",
                (transport_id, &rfc724_mid),
            )
            .await?;
    }
    Ok(rfc724_mid)
}

/// Returns for each `imap` row of `rfc724_mid`, ordered by transport, whether it is marked for deletion.
async fn deleted_on_server(t: &TestContext, rfc724_mid: &str) -> Result<Vec<bool>> {
    t.sql
        .query_map_vec(
            "SELECT target='' FROM imap WHERE rfc724_mid=? ORDER BY transport_id",
            (rfc724_mid,),
            |row| Ok(row.get::<_, bool>(0)?),
        )
        .await
}

/// With `bcc_self` off, processed messages are deleted on all relays.
/// This includes keyupdates, which are trashed early in `receive_imf`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_deletion() -> Result<()> {
    for bcc_self in [false, true] {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        bob.set_config_bool(Config::BccSelf, bcc_self).await?;

        let chat_msg = alice.send_text(alice.create_chat_id(bob).await, "hi").await;
        alice.add_transport("alice@relay.example.net").await;
        crate::keyupdate::maybe_send_keyupdate_message(alice).await?;
        let keyupdate = alice.pop_sent_msg().await;

        for (sent, is_trash) in [(&chat_msg, false), (&keyupdate, true)] {
            let (rfc724_mid, received) =
                recv_with_imap_rows(bob, sent.payload.as_bytes(), &[1, 2]).await?;
            assert_eq!(received.unwrap().chat_id.is_trash(), is_trash);
            assert_eq!(
                deleted_on_server(bob, &rfc724_mid).await?,
                [!bcc_self, !bcc_self]
            );
        }
    }
    Ok(())
}

/// With `bcc_self` off, the pre-message is deleted from all relays when it is received,
/// and the post-message when it is downloaded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_deletion_pre_and_post_msg() -> Result<()> {
    for bcc_self in [false, true] {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        bob.set_config_bool(Config::BccSelf, bcc_self).await?;

        let chat_id = alice.create_chat_id(bob).await;
        let (pre_msg, post_msg, _) = crate::tests::pre_messages::util::send_large_file_message(
            alice,
            chat_id,
            crate::message::Viewtype::File,
            &vec![0u8; 1_000_000],
        )
        .await?;
        let post_rfc724_mid = add_imap_rows(bob, post_msg.payload.as_bytes(), &[1, 2]).await?;

        let (pre_rfc724_mid, received) =
            recv_with_imap_rows(bob, pre_msg.payload.as_bytes(), &[1, 2]).await?;
        let msg = crate::message::Message::load_from_db(bob, received.unwrap().msg_ids[0]).await?;
        assert_eq!(msg.download_state, DownloadState::Available);
        assert_eq!(
            deleted_on_server(bob, &pre_rfc724_mid).await?,
            [!bcc_self, !bcc_self]
        );
        assert_eq!(
            deleted_on_server(bob, &post_rfc724_mid).await?,
            [false, false]
        );

        let received = crate::receive_imf::receive_imf_inner(
            bob,
            &post_rfc724_mid,
            post_msg.payload.as_bytes(),
            false,
        )
        .await?;
        assert_eq!(received.unwrap().chat_id.is_trash(), true);
        let msg = crate::message::Message::load_from_db(bob, msg.id).await?;
        assert_eq!(msg.download_state, DownloadState::Done);
        assert_eq!(
            deleted_on_server(bob, &post_rfc724_mid).await?,
            [!bcc_self, !bcc_self]
        );
    }
    Ok(())
}

/// Messages that Delta Chat can't use are trashed, but kept on the server even with `bcc_self` off,
/// so that the user can read them with a different email client.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_server_keeps_unusable_msgs() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    for t in [alice, bob] {
        t.set_config_bool(Config::BccSelf, false).await?;
    }

    // Unencrypted.
    let unencrypted = b"From: Fiona <fiona@example.net>\r\n\
        To: bob@example.net\r\n\
        Subject: Hello\r\n\
        Message-ID: <unencrypted@example.net>\r\n\
        Date: Sun, 22 Mar 2020 22:37:57 +0000\r\n\
        \r\n\
        Hello from another email app\r\n";
    // Encrypted to a key that Bob doesn't have.
    let undecryptable = alice
        .send_text(alice.create_chat_id(fiona).await, "for fiona")
        .await;
    for (payload, expected_warnings) in [
        (&unencrypted[..], &[][..]),
        (
            undecryptable.payload.as_bytes(),
            &["decryption failed: decrypt_the_ring: missing key"][..],
        ),
    ] {
        let (rfc724_mid, received) = recv_with_imap_rows(bob, payload, &[1]).await?;
        for warning in expected_warnings {
            bob.assert_warn(warning).await;
        }
        bob.assert_warn("Fetched unencrypted message, ignoring")
            .await;
        assert_eq!(received.unwrap().chat_id.is_trash(), true);
        assert_eq!(deleted_on_server(bob, &rfc724_mid).await?, [false]);
    }

    // Encrypted, but unsigned.
    let unsigned = include_bytes!("../../test-data/message/thunderbird_encrypted_unsigned.eml");
    let (rfc724_mid, received) = recv_with_imap_rows(alice, unsigned, &[1]).await?;
    alice
        .assert_warn("Fetched unencrypted message, ignoring")
        .await;
    assert_eq!(received.unwrap().chat_id.is_trash(), true);
    assert_eq!(deleted_on_server(alice, &rfc724_mid).await?, [false]);

    Ok(())
}
