use anyhow::Context as _;
use strum::IntoEnumIterator;
use tempfile::tempdir;

use super::*;
use crate::chat::{Chat, MuteDuration, get_chat_contacts, get_chat_msgs, send_msg, set_muted};
use crate::chatlist::Chatlist;
use crate::constants::Chattype;
use crate::message::Message;
use crate::receive_imf::receive_imf;
use crate::test_utils::{E2EE_INFO_MSGS, TestContext};
use crate::tools::{SystemTime, create_outgoing_rfc724_mid};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wrong_db() -> Result<()> {
    let tmp = tempfile::tempdir()?;
    let dbfile = tmp.path().join("db.sqlite");
    tokio::fs::write(&dbfile, b"123").await?;
    let res = Context::new(&dbfile, 1, Events::new(), StockStrings::new()).await?;

    // Broken database is indistinguishable from encrypted one.
    assert_eq!(res.is_open().await, false);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_fresh_msgs() {
    let t = TestContext::new().await;
    let fresh = t.get_fresh_msgs().await.unwrap();
    assert!(fresh.is_empty())
}

async fn receive_msg(t: &TestContext, chat: &Chat) {
    let members = get_chat_contacts(t, chat.id).await.unwrap();
    let contact = Contact::get_by_id(t, *members.first().unwrap())
        .await
        .unwrap();
    let msg = format!(
        "From: {}\n\
             To: alice@example.org\n\
             Message-ID: <{}>\n\
             Chat-Version: 1.0\n\
             Date: Sun, 22 Mar 2020 22:37:57 +0000\n\
             \n\
             hello\n",
        contact.get_addr(),
        create_outgoing_rfc724_mid()
    );
    println!("{msg}");
    receive_imf(t, msg.as_bytes(), false).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_fresh_msgs_and_muted_chats() {
    // receive various mails in 3 chats
    let t = TestContext::new_alice().await;
    let bob = t.create_chat_with_contact("", "bob@g.it").await;
    let claire = t.create_chat_with_contact("", "claire@g.it").await;
    let dave = t.create_chat_with_contact("", "dave@g.it").await;
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 0);

    receive_msg(&t, &bob).await;
    assert_eq!(get_chat_msgs(&t, bob.id).await.unwrap().len(), 1);
    assert_eq!(bob.id.get_fresh_msg_cnt(&t).await.unwrap(), 1);
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 1);

    receive_msg(&t, &claire).await;
    receive_msg(&t, &claire).await;
    assert_eq!(get_chat_msgs(&t, claire.id).await.unwrap().len(), 2);
    assert_eq!(claire.id.get_fresh_msg_cnt(&t).await.unwrap(), 2);
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 3);

    receive_msg(&t, &dave).await;
    receive_msg(&t, &dave).await;
    receive_msg(&t, &dave).await;
    assert_eq!(get_chat_msgs(&t, dave.id).await.unwrap().len(), 3);
    assert_eq!(dave.id.get_fresh_msg_cnt(&t).await.unwrap(), 3);
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 6);

    // mute one of the chats
    set_muted(&t, claire.id, MuteDuration::Forever)
        .await
        .unwrap();
    assert_eq!(claire.id.get_fresh_msg_cnt(&t).await.unwrap(), 2);
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 4); // muted claires messages are no longer counted

    // receive more messages
    receive_msg(&t, &bob).await;
    receive_msg(&t, &claire).await;
    receive_msg(&t, &dave).await;
    assert_eq!(get_chat_msgs(&t, claire.id).await.unwrap().len(), 3);
    assert_eq!(claire.id.get_fresh_msg_cnt(&t).await.unwrap(), 3);
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 6); // muted claire is not counted

    // unmute claire again
    set_muted(&t, claire.id, MuteDuration::NotMuted)
        .await
        .unwrap();
    assert_eq!(claire.id.get_fresh_msg_cnt(&t).await.unwrap(), 3);
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 9); // claire is counted again
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_fresh_msgs_and_muted_until() {
    let t = TestContext::new_alice().await;
    let bob = t.create_chat_with_contact("", "bob@g.it").await;
    receive_msg(&t, &bob).await;
    assert_eq!(get_chat_msgs(&t, bob.id).await.unwrap().len(), 1);

    // chat is unmuted by default, here and in the following assert(),
    // we check mainly that the SQL-statements in is_muted() and get_fresh_msgs()
    // have the same view to the database.
    assert!(!bob.is_muted());
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 1);

    // test get_fresh_msgs() with mute_until in the future
    set_muted(
        &t,
        bob.id,
        MuteDuration::Until(SystemTime::now() + Duration::from_secs(3600)),
    )
    .await
    .unwrap();
    let bob = Chat::load_from_db(&t, bob.id).await.unwrap();
    assert!(bob.is_muted());
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 0);

    // to test get_fresh_msgs() with mute_until in the past,
    // we need to modify the database directly
    t.sql
        .execute(
            "UPDATE chats SET muted_until=? WHERE id=?;",
            (time() - 3600, bob.id),
        )
        .await
        .unwrap();
    let bob = Chat::load_from_db(&t, bob.id).await.unwrap();
    assert!(!bob.is_muted());
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 1);

    // test get_fresh_msgs() with "forever" mute_until
    set_muted(&t, bob.id, MuteDuration::Forever).await.unwrap();
    let bob = Chat::load_from_db(&t, bob.id).await.unwrap();
    assert!(bob.is_muted());
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 0);

    // to test get_fresh_msgs() with invalid mute_until (everything < -1),
    // that results in "muted forever" by definition.
    t.sql
        .execute("UPDATE chats SET muted_until=-2 WHERE id=?;", (bob.id,))
        .await
        .unwrap();
    let bob = Chat::load_from_db(&t, bob.id).await.unwrap();
    assert!(!bob.is_muted());
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_muted_context() -> Result<()> {
    let t = TestContext::new_alice().await;
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 0);
    t.set_config(Config::IsMuted, Some("1")).await?;
    let chat = t.create_chat_with_contact("", "bob@g.it").await;
    receive_msg(&t, &chat).await;

    // muted contexts should still show dimmed badge counters eg. in the sidebars,
    // (same as muted chats show dimmed badge counters in the chatlist)
    // therefore the fresh messages count should not be affected.
    assert_eq!(t.get_fresh_msgs().await.unwrap().len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_blobdir_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let dbfile = tmp.path().join("db.sqlite");
    Context::new(&dbfile, 1, Events::new(), StockStrings::new())
        .await
        .unwrap();
    let blobdir = tmp.path().join("db.sqlite-blobs");
    assert!(blobdir.is_dir());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wrong_blogdir() {
    let tmp = tempfile::tempdir().unwrap();
    let dbfile = tmp.path().join("db.sqlite");
    let blobdir = tmp.path().join("db.sqlite-blobs");
    tokio::fs::write(&blobdir, b"123").await.unwrap();
    let res = Context::new(&dbfile, 1, Events::new(), StockStrings::new()).await;
    assert!(res.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sqlite_parent_not_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let subdir = tmp.path().join("subdir");
    let dbfile = subdir.join("db.sqlite");
    let dbfile2 = dbfile.clone();
    Context::new(&dbfile, 1, Events::new(), StockStrings::new())
        .await
        .unwrap();
    assert!(subdir.is_dir());
    assert!(dbfile2.is_file());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_with_empty_blobdir() {
    let tmp = tempfile::tempdir().unwrap();
    let dbfile = tmp.path().join("db.sqlite");
    let blobdir = PathBuf::new();
    let res = Context::with_blobdir(
        dbfile,
        blobdir,
        1,
        Events::new(),
        StockStrings::new(),
        Default::default(),
    );
    assert!(res.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_with_blobdir_not_exists() {
    let tmp = tempfile::tempdir().unwrap();
    let dbfile = tmp.path().join("db.sqlite");
    let blobdir = tmp.path().join("blobs");
    let res = Context::with_blobdir(
        dbfile,
        blobdir,
        1,
        Events::new(),
        StockStrings::new(),
        Default::default(),
    );
    assert!(res.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_crashes_on_context_deref() {
    let t = TestContext::new().await;
    std::mem::drop(t);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_info() {
    let t = TestContext::new().await;

    let info = t.get_info().await.unwrap();
    assert!(info.contains_key("database_dir"));
}

#[test]
fn test_get_info_no_context() {
    let info = get_info();
    assert!(info.contains_key("deltachat_core_version"));
    assert!(!info.contains_key("database_dir"));
    assert_eq!(info.get("level").unwrap(), "awesome");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_info_completeness() {
    // For easier debugging,
    // get_info() shall return all important information configurable by the Config-values.
    //
    // There are exceptions for Config-values considered to be unimportant,
    // too sensitive or summarized in another item.
    let skip_from_get_info = vec![
        "addr",
        "displayname",
        "imap_certificate_checks",
        "mail_server",
        "mail_user",
        "mail_pw",
        "mail_port",
        "mail_security",
        "notify_about_wrong_pw",
        "selfstatus",
        "send_server",
        "send_user",
        "send_pw",
        "send_port",
        "send_security",
        "server_flags",
        "skip_start_messages",
        "smtp_certificate_checks",
        "proxy_url",      // May contain passwords, don't leak it to the logs.
        "socks5_enabled", // SOCKS5 options are deprecated.
        "socks5_host",
        "socks5_port",
        "socks5_user",
        "socks5_password",
        "key_id",
        "webxdc_integration",
        "device_token",
        "encrypted_device_token",
        "stats_last_update",
        "stats_last_old_contact_id",
    ];
    let t = TestContext::new().await;
    let info = t.get_info().await.unwrap();
    for key in Config::iter() {
        let key: String = key.to_string();
        if !skip_from_get_info.contains(&&*key)
            && !key.starts_with("configured")
            && !key.starts_with("sys.")
        {
            assert!(
                info.contains_key(&*key),
                "'{key}' missing in get_info() output"
            );
        }

        if skip_from_get_info.contains(&&*key) {
            assert!(
                !info.contains_key(&*key),
                "'{key}' should not be in get_info() output"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_search_msgs() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let self_talk = ChatId::create_for_contact(&alice, ContactId::SELF).await?;
    let chat = alice
        .create_chat_with_contact("Bob", "bob@example.org")
        .await;

    // Global search finds nothing.
    let res = alice.search_msgs(None, "foo").await?;
    assert!(res.is_empty());

    // Search in chat with Bob finds nothing.
    let res = alice.search_msgs(Some(chat.id), "foo").await?;
    assert!(res.is_empty());

    // Add messages to chat with Bob.
    let mut msg1 = Message::new_text("foobar".to_string());
    send_msg(&alice, chat.id, &mut msg1).await?;

    let mut msg2 = Message::new_text("barbaz".to_string());
    send_msg(&alice, chat.id, &mut msg2).await?;

    alice.send_text(chat.id, "Δ-Chat").await;

    // Global search with a part of text finds the message.
    let res = alice.search_msgs(None, "ob").await?;
    assert_eq!(res.len(), 1);

    // Global search for "bar" matches both "foobar" and "barbaz".
    let res = alice.search_msgs(None, "bar").await?;
    assert_eq!(res.len(), 2);

    // Message added later is returned first.
    assert_eq!(res.first(), Some(&msg2.id));
    assert_eq!(res.get(1), Some(&msg1.id));

    // Search is case-insensitive.
    for chat_id in [None, Some(chat.id)] {
        let res = alice.search_msgs(chat_id, "δ-chat").await?;
        assert_eq!(res.len(), 1);
    }

    // Global search with longer text does not find any message.
    let res = alice.search_msgs(None, "foobarbaz").await?;
    assert!(res.is_empty());

    // Search for random string finds nothing.
    let res = alice.search_msgs(None, "abc").await?;
    assert!(res.is_empty());

    // Search in chat with Bob finds the message.
    let res = alice.search_msgs(Some(chat.id), "foo").await?;
    assert_eq!(res.len(), 1);

    // Search in Saved Messages does not find the message.
    let res = alice.search_msgs(Some(self_talk), "foo").await?;
    assert!(res.is_empty());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_search_unaccepted_requests() -> Result<()> {
    let t = TestContext::new_alice().await;
    receive_imf(
        &t,
        b"From: BobBar <bob@example.org>\n\
                 To: alice@example.org\n\
                 Subject: foo\n\
                 Message-ID: <msg1234@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Tue, 25 Oct 2022 13:37:00 +0000\n\
                 \n\
                 hello bob, foobar test!\n",
        false,
    )
    .await?;
    let chat_id = t.get_last_msg().await.get_chat_id();
    let chat = Chat::load_from_db(&t, chat_id).await?;
    assert_eq!(chat.get_type(), Chattype::Single);
    assert!(chat.is_contact_request());

    assert_eq!(Chatlist::try_load(&t, 0, None, None).await?.len(), 1);
    assert_eq!(
        Chatlist::try_load(&t, 0, Some("BobBar"), None).await?.len(),
        1
    );
    assert_eq!(t.search_msgs(None, "foobar").await?.len(), 1);
    assert_eq!(t.search_msgs(Some(chat_id), "foobar").await?.len(), 1);

    chat_id.block(&t).await?;

    assert_eq!(Chatlist::try_load(&t, 0, None, None).await?.len(), 0);
    assert_eq!(
        Chatlist::try_load(&t, 0, Some("BobBar"), None).await?.len(),
        0
    );
    assert_eq!(t.search_msgs(None, "foobar").await?.len(), 0);
    assert_eq!(t.search_msgs(Some(chat_id), "foobar").await?.len(), 0);

    let contact_ids = get_chat_contacts(&t, chat_id).await?;
    Contact::unblock(&t, *contact_ids.first().unwrap()).await?;

    assert_eq!(Chatlist::try_load(&t, 0, None, None).await?.len(), 1);
    assert_eq!(
        Chatlist::try_load(&t, 0, Some("BobBar"), None).await?.len(),
        1
    );
    assert_eq!(t.search_msgs(None, "foobar").await?.len(), 1);
    assert_eq!(t.search_msgs(Some(chat_id), "foobar").await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_limit_search_msgs() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let chat = alice
        .create_chat_with_contact("Bob", "bob@example.org")
        .await;

    // Add 999 messages
    let mut msg = Message::new_text("foobar".to_string());
    for _ in 0..999 {
        send_msg(&alice, chat.id, &mut msg).await?;
    }
    let res = alice.search_msgs(None, "foo").await?;
    assert_eq!(res.len(), 999);

    // Add one more message, no limit yet
    send_msg(&alice, chat.id, &mut msg).await?;
    let res = alice.search_msgs(None, "foo").await?;
    assert_eq!(res.len(), 1000);

    // Add one more message, that one is truncated then
    send_msg(&alice, chat.id, &mut msg).await?;
    let res = alice.search_msgs(None, "foo").await?;
    assert_eq!(res.len(), 1000);

    // In-chat should not be not limited
    let res = alice.search_msgs(Some(chat.id), "foo").await?;
    assert_eq!(res.len(), 1001);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_check_passphrase() -> Result<()> {
    let dir = tempdir()?;
    let dbfile = dir.path().join("db.sqlite");

    let context = ContextBuilder::new(dbfile.clone())
        .with_id(1)
        .build()
        .await
        .context("failed to create context")?;
    assert_eq!(context.open("foo".to_string()).await?, true);
    assert_eq!(context.is_open().await, true);
    drop(context);

    let context = ContextBuilder::new(dbfile)
        .with_id(2)
        .build()
        .await
        .context("failed to create context")?;
    assert_eq!(context.is_open().await, false);
    assert_eq!(context.check_passphrase("bar".to_string()).await?, false);
    assert_eq!(context.open("false".to_string()).await?, false);
    assert_eq!(context.open("foo".to_string()).await?, true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_context_change_passphrase() -> Result<()> {
    let dir = tempdir()?;
    let dbfile = dir.path().join("db.sqlite");

    let context = ContextBuilder::new(dbfile)
        .with_id(1)
        .build()
        .await
        .context("failed to create context")?;
    assert_eq!(context.open("foo".to_string()).await?, true);
    assert_eq!(context.is_open().await, true);

    context
        .set_config(Config::Addr, Some("alice@example.org"))
        .await?;

    context
        .change_passphrase("bar".to_string())
        .await
        .context("Failed to change passphrase")?;

    assert_eq!(
        context.get_config(Config::Addr).await?.unwrap(),
        "alice@example.org"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_ongoing() -> Result<()> {
    let context = TestContext::new().await;

    // No ongoing process allocated.
    assert!(context.shall_stop_ongoing().await);

    let receiver = context.alloc_ongoing().await?;

    // Cannot allocate another ongoing process while the first one is running.
    assert!(context.alloc_ongoing().await.is_err());

    // Stop signal is not sent yet.
    assert!(receiver.try_recv().is_err());

    assert!(!context.shall_stop_ongoing().await);

    // Send the stop signal.
    context.stop_ongoing().await;

    // Receive stop signal.
    receiver.recv().await?;

    assert!(context.shall_stop_ongoing().await);

    // Ongoing process is still running even though stop signal was received,
    // so another one cannot be allocated.
    assert!(context.alloc_ongoing().await.is_err());

    context.free_ongoing().await;

    // No ongoing process allocated, should have been stopped already.
    assert!(context.shall_stop_ongoing().await);

    // Another ongoing process can be allocated now.
    let _receiver = context.alloc_ongoing().await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_next_msgs() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let alice_chat = alice.create_chat(&bob).await;

    assert_eq!(alice.get_next_msgs().await?.len(), E2EE_INFO_MSGS);
    assert!(bob.get_next_msgs().await?.is_empty());

    let sent_msg = alice.send_text(alice_chat.id, "Hi Bob").await;
    let received_msg = bob.recv_msg(&sent_msg).await;

    let bob_next_msg_ids = bob.get_next_msgs().await?;
    assert_eq!(bob_next_msg_ids.len(), 1);
    assert_eq!(bob_next_msg_ids.first(), Some(&received_msg.id));

    bob.set_config_u32(Config::LastMsgId, received_msg.id.to_u32())
        .await?;
    assert!(bob.get_next_msgs().await?.is_empty());

    // Next messages include self-sent messages.
    let alice_next_msg_ids = alice.get_next_msgs().await?;
    assert_eq!(alice_next_msg_ids.len(), 1);
    assert_eq!(alice_next_msg_ids.first(), Some(&sent_msg.sender_msg_id));

    alice
        .set_config_u32(Config::LastMsgId, sent_msg.sender_msg_id.to_u32())
        .await?;
    assert!(alice.get_next_msgs().await?.is_empty());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cache_is_cleared_when_io_is_started() -> Result<()> {
    let alice = TestContext::new_alice().await;
    assert_eq!(
        alice.get_config(Config::ShowEmails).await?,
        Some("2".to_string())
    );

    // Change the config circumventing the cache
    // This simulates what the notification plugin on iOS might do
    // because it runs in a different process
    alice
        .sql
        .execute(
            "INSERT OR REPLACE INTO config (keyname, value) VALUES ('show_emails', '0')",
            (),
        )
        .await?;

    // Alice's Delta Chat doesn't know about it yet:
    assert_eq!(
        alice.get_config(Config::ShowEmails).await?,
        Some("2".to_string())
    );

    // Starting IO will fail of course because no server settings are configured,
    // but it should invalidate the caches:
    alice.start_io().await;

    assert_eq!(
        alice.get_config(Config::ShowEmails).await?,
        Some("0".to_string())
    );

    Ok(())
}
