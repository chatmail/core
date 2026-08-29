use std::collections::BTreeSet;
use std::num::NonZero;
use std::time::Duration;

use deltachat_contact_tools::EmailAddress;
use pgp::composed::{Esk, Message};
use pgp::packet::PublicKeyEncryptedSessionKey;

use super::*;
use crate::chat::{
    ChatId, add_to_chat_contacts_table, create_broadcast, create_group,
    remove_from_chat_contacts_table,
};
use crate::constants::Blocked;
use crate::contact::{Contact, Origin, import_public_key, update_last_seen};
use crate::decrypt::{decrypt, get_encrypted_pgp_message_boxed};
use crate::ephemeral::{Timer, delete_expired_messages};
use crate::pgp::{addresses_from_public_key, create_keypair};
use crate::securejoin::get_securejoin_qr;
use crate::test_utils::{TestContext, TestContextManager};
use crate::tools::SystemTime;
use crate::transport::send_sync_transports;

/// Asserts that no session key packet names the recipient it is meant for.
fn assert_anonymous_recipients(payload: &str, expected: usize) {
    let mail = mailparse::parse_mail(payload.as_bytes()).unwrap();
    let msg = get_encrypted_pgp_message_boxed(&mail).unwrap().unwrap();
    let Message::Encrypted { esk, .. } = &*msg else {
        panic!("Expected encrypted message");
    };
    assert_eq!(esk.len(), expected);
    for encrypted_session_key in esk {
        let Esk::PublicKeyEncryptedSessionKey(pkesk) = encrypted_session_key else {
            panic!("Expected asymmetric encryption");
        };
        match pkesk {
            PublicKeyEncryptedSessionKey::V3 { id, .. } => assert!(id.is_wildcard()),
            PublicKeyEncryptedSessionKey::V6 { fingerprint, .. } => assert!(fingerprint.is_none()),
            PublicKeyEncryptedSessionKey::Other { .. } => unreachable!(),
        }
    }
}

/// Creates a single chat with `other` and writes to it.
async fn send_text_message(context: &TestContext, other: &TestContext) {
    let chat_id = context.create_chat_id(other).await;
    context.send_text(chat_id, "hi").await;
}

/// Adds a key-contact for `addr`, with a fresh key of its own,
/// or with a fingerprint whose certificate is not stored.
async fn add_key_contact(context: &Context, addr: &str, with_key: bool) -> Result<ContactId> {
    let public_key = create_keypair(EmailAddress::new(addr)?)?.to_public_key();
    if with_key {
        import_public_key(context, &public_key).await?;
    }
    let fingerprint = public_key.dc_fingerprint().hex();
    let (contact_id, _modifier) =
        Contact::add_or_lookup_ext(context, "", addr, &fingerprint, Origin::ManuallyCreated)
            .await?;
    Ok(contact_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_recipients() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob_1to1 = &tcm.bob().await;
    let charlie_in_group = &tcm.charlie().await;
    let dom_subscriber = &tcm.dom().await;
    let elena_blocked = &tcm.elena().await;
    let fiona_unaccepted = &tcm.fiona().await;
    let pqc_broadcaster = &tcm.pqc().await;

    send_text_message(alice, bob_1to1).await;
    let group = alice
        .create_group_with_members("Group", &[charlie_in_group, elena_blocked])
        .await;

    // The group chat stays accepted, so only the contact-level block excludes elena.
    Contact::block(alice, alice.add_or_lookup_contact_id(elena_blocked).await).await?;

    // Dom joins our channel the way a subscriber does.
    // This leaves no single chat on our side,
    // because only a setup-contact QR creates one,
    // so subscribing alone does not make someone a keyupdate recipient.
    let own_channel = create_broadcast(alice, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(own_channel)).await?;
    tcm.exec_securejoin_qr(dom_subscriber, alice, &qr).await;

    // A channel we follow contains exactly its owner (`InBroadcast`).
    let followed_channel = ChatId::create_multiuser_record(
        alice,
        Chattype::InBroadcast,
        "grpid",
        "Followed channel",
        Blocked::Not,
        None,
        time(),
    )
    .await?;
    let pqc_id = alice.add_or_lookup_contact_id(pqc_broadcaster).await;
    add_to_chat_contacts_table(alice, time(), followed_channel, &[pqc_id]).await?;

    // Add to, and remove fiona from, the group, keeping her unaccepted.
    tcm.send_recv(fiona_unaccepted, alice, "hi").await;
    let fiona_id = alice.add_or_lookup_contact_id(fiona_unaccepted).await;
    add_to_chat_contacts_table(alice, time(), group, &[fiona_id]).await?;
    remove_from_chat_contacts_table(alice, group, fiona_id).await?;

    // A key-contact whose certificate we do not store cannot be encrypted to.
    let with_key = false;
    let keyless = add_key_contact(alice, "keyless@example.net", with_key).await?;
    ChatId::create_for_contact(alice, keyless).await?;

    let no_msgs_contact = add_key_contact(alice, "no_msgs@example.net", true).await?;
    ChatId::create_for_contact(alice, no_msgs_contact).await?;

    // Blocked, unaccepted, keyless or message-less contacts are left out.
    let mut recipients: Vec<String> = keyupdate_recipients(alice, KEYUPDATE_MAX_RECIPIENTS)
        .await?
        .into_iter()
        .flat_map(|recipient| recipient.relays)
        .collect();
    recipients.sort();
    assert_eq!(
        recipients,
        ["bob@example.net", "charlie@example.net", "pqc@example.org"]
    );

    Ok(())
}

/// Tests that contacts falling silent drop out of the recipient set,
/// that any sign of life brings them back, and that the cap keeps the freshest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_recipients_freshness() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob_written_to = &tcm.bob().await;
    let charlie_heard_from = &tcm.charlie().await;

    send_text_message(alice, bob_written_to).await;
    alice
        .create_group_with_members("Group", &[charlie_heard_from])
        .await;
    let charlie_id = alice.add_or_lookup_contact_id(charlie_heard_from).await;
    let max = KEYUPDATE_MAX_RECIPIENTS;
    assert_eq!(keyupdate_recipients(alice, max).await?.len(), 2);

    // Contacts that showed no sign of life for years are left out.
    SystemTime::shift(Duration::from_secs(KEYUPDATE_MAX_SILENCE as u64 + 1));
    assert!(keyupdate_recipients(alice, max).await?.is_empty());

    send_text_message(alice, bob_written_to).await;
    update_last_seen(alice, charlie_id, time().saturating_sub(1000)).await?;
    assert_eq!(keyupdate_recipients(alice, max).await?.len(), 2);

    // Beyond the cap the freshest contacts are kept.
    let capped = keyupdate_recipients(alice, 1).await?;
    assert_eq!(capped.len(), 1);
    assert_eq!(capped[0].relays, ["bob@example.net"]);

    Ok(())
}

/// Tests that a contact in an ephemeral single chat
/// stays a recipient once the written messages expired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_recipients_ephemeral() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat_id = alice.create_chat_id(bob).await;
    let duration = NonZero::new(60).unwrap();
    chat_id
        .set_ephemeral_timer(alice, Timer::Enabled { duration })
        .await?;
    alice.send_text(chat_id, "hi").await;

    let max = KEYUPDATE_MAX_RECIPIENTS;
    assert_eq!(keyupdate_recipients(alice, max).await?.len(), 1);

    let msg_cnt = chat_id.get_msg_cnt(alice).await?;
    SystemTime::shift(Duration::from_secs(61));
    delete_expired_messages(alice, time()).await?;
    assert_eq!(chat_id.get_msg_cnt(alice).await?, msg_cnt - 1);
    assert_eq!(keyupdate_recipients(alice, max).await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_and_receive_keyupdate() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    send_text_message(alice, bob).await;
    let alice_contact = bob.add_or_lookup_contact(alice).await;
    assert_eq!(alice_contact.last_seen(), 0);
    // Create Bob's chat before the transport change: creating it later
    // would re-import Alice's current key and hide a failing keyupdate.
    let bob_chat_id = bob.create_chat_id(alice).await;

    // Merely created chats without any message cause no keyupdate recipient.
    let no_msgs_contact = add_key_contact(alice, "no_msgs@example.net", true).await?;
    ChatId::create_for_contact(alice, no_msgs_contact).await?;

    alice.add_transport("alice@relay.example.net").await;
    maybe_send_keyupdate_message(alice).await?;
    let keyupdate = alice.pop_sent_msg().await;
    assert_eq!(keyupdate.recipients, "bob@example.net");
    assert!(keyupdate.payload.contains("Subject: [...]"));

    // A keyupdate is trashed on old cores because it's unsigned MDN
    // without a message reference. See also cross-core Python tests.
    let mail = mailparse::parse_mail(keyupdate.payload.as_bytes())?;
    let (mut decrypted, _fingerprint) = decrypt(bob, &mail).await?.unwrap();
    // The next line is important: A key update message must NOT be signed,
    // as the signature might contain intended recipient fingerprints,
    // leaking all of the sender's contacts to all the other contacts.
    assert!(!decrypted.is_signed());
    let plain = String::from_utf8(decrypted.as_data_vec()?)?;
    assert!(plain.contains("multipart/report; report-type=disposition-notification"));
    assert!(!plain.contains("Original-Message-ID"));

    bob.recv_msg_trash(&keyupdate).await;
    // No green "online" dot, unlike for a regular message, see `test_last_seen()`.
    let alice_contact = Contact::get_by_id(bob, alice_contact.id).await?;
    assert_eq!(alice_contact.last_seen(), 0);

    let bob_message = bob.send_text(bob_chat_id, "hi").await;
    assert!(bob_message.recipients.contains("alice@relay.example.net"));

    // The removal direction: unpublishing the relay sends a keyupdate
    // whose list no longer contains it, so Bob stops sending there.
    // The time shift gives the re-signed key a later signature timestamp,
    // so that certificate merging prefers the removal.
    SystemTime::shift(Duration::from_secs(2));
    alice
        .set_transport_unpublished("alice@relay.example.net", true)
        .await?;
    maybe_send_keyupdate_message(alice).await?;
    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;
    let bob_message = bob.send_text(bob_chat_id, "hi again").await;
    assert!(!bob_message.recipients.contains("alice@relay.example.net"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_trigger_dedup() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // No contacts yet, so this only records the baseline.
    maybe_send_keyupdate_message(alice).await?;
    assert!(alice.pop_sent_msg_opt().await.is_none());

    send_text_message(alice, bob).await;
    maybe_send_keyupdate_message(alice).await?;
    assert!(alice.pop_sent_msg_opt().await.is_none());

    let debounce = 60;
    alice
        .set_config(Config::KeyupdateDebounce, Some(&debounce.to_string()))
        .await?;
    let before = time();
    alice.add_transport("alice@relay.example.net").await;
    send_sync_transports(alice).await?;
    let next_check = alice.next_keyupdate_check.load(Ordering::Relaxed);
    assert!(next_check >= before.saturating_add(debounce));
    assert!(next_check <= time().saturating_add(debounce));

    // Sending is driven by the changed relay list, not by the scheduled check.
    maybe_send_keyupdate_message(alice).await?;
    assert!(alice.pop_sent_msg_opt().await.is_some());
    assert!(alice.pop_sent_msg_opt().await.is_none());
    maybe_send_keyupdate_message(alice).await?;
    assert!(alice.pop_sent_msg_opt().await.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_not_sent_by_synced_device() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;
    for a in [alice, alice2] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
        a.set_config_bool(Config::BccSelf, true).await?;
        // Both devices need a recipient, otherwise silence proves nothing.
        send_text_message(a, bob).await;
    }

    alice.add_transport("alice@relay.example.net").await;
    send_sync_transports(alice).await?;
    alice.send_sync_msg().await?;
    alice2.recv_msg_trash(&alice.pop_sent_msg().await).await;
    // The sync was applied, so silence below is meaningful.
    let published = alice2.get_published_self_addrs().await?;
    assert!(published.contains(&"alice@relay.example.net".to_string()));

    maybe_send_keyupdate_message(alice2).await?;
    assert!(alice2.pop_sent_msg_opt().await.is_none());
    maybe_send_keyupdate_message(alice).await?;
    assert_eq!(alice.pop_sent_msg().await.recipients, "bob@example.net");

    Ok(())
}

/// Tests that more contacts than fit into one message are sent in chunks,
/// each chunk being a message of its own with its own recipients.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_chunks() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;

    let chat_id = create_group(alice, "Group").await?;
    let with_key = true;
    let mut contact_ids = Vec::new();
    for i in 0..=KEYUPDATE_CHUNK_CONTACTS {
        let addr = format!("member{i}@example.net");
        contact_ids.push(add_key_contact(alice, &addr, with_key).await?);
    }
    add_to_chat_contacts_table(alice, time(), chat_id, &contact_ids).await?;
    assert_eq!(
        keyupdate_recipients(alice, KEYUPDATE_MAX_RECIPIENTS)
            .await?
            .len(),
        KEYUPDATE_CHUNK_CONTACTS + 1
    );

    alice.add_transport("alice@relay.example.net").await;
    maybe_send_keyupdate_message(alice).await?;

    let sent = [alice.pop_sent_msg().await, alice.pop_sent_msg().await];
    assert!(alice.pop_sent_msg_opt().await.is_none());

    let recipients: Vec<BTreeSet<&str>> = sent
        .iter()
        .map(|msg| msg.recipients.split(' ').collect())
        .collect();
    let mut sizes: Vec<usize> = recipients.iter().map(BTreeSet::len).collect();
    sizes.sort();
    assert_eq!(sizes, [1, KEYUPDATE_CHUNK_CONTACTS]);
    assert!(recipients[0].is_disjoint(&recipients[1]));

    // Each recipient only ever sees the size of its own chunk;
    // the extra session key packet is the sender's own key.
    for (msg, recipients) in sent.iter().zip(&recipients) {
        assert_anonymous_recipients(&msg.payload, recipients.len() + 1);
    }

    Ok(())
}

/// Tests that a receiver who does not know the sender yet
/// still stores the key, and still gets nothing to see.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_from_unknown_sender() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    send_text_message(alice, bob).await;
    let contacts = Contact::get_real_cnt(bob).await?;

    alice.add_transport("alice@relay.example.net").await;
    maybe_send_keyupdate_message(alice).await?;
    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;

    assert_eq!(Contact::get_real_cnt(bob).await?, contacts);

    // Look the contact up by fingerprint alone, so the key can only come
    // from the keyupdate and not from importing Alice's current vCard.
    let alice_contact_id = bob.add_or_lookup_contact_id_no_key(alice).await;
    let alice_contact = Contact::get_by_id(bob, alice_contact_id).await?;
    let alice_key = alice_contact.public_key(bob).await?.unwrap();
    let addrs = addresses_from_public_key(&alice_key).unwrap();
    assert!(addrs.contains(&"alice@relay.example.net".to_string()));

    Ok(())
}
