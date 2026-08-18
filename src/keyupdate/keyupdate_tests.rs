use super::*;
use crate::contact::Contact;
use crate::decrypt::get_encrypted_pgp_message_boxed;
use crate::pgp::addresses_from_public_key;
use crate::test_utils::TestContextManager;
use crate::transport::send_sync_transports;
use pgp::composed::{Esk, Message};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_keyupdate_recipients() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;
    let dom = &tcm.dom().await;
    let elena = &tcm.elena().await;
    let fiona = &tcm.fiona().await;

    alice.create_chat(bob).await;
    alice
        .create_group_with_members("Group", &[charlie, elena])
        .await;
    // The group chat stays accepted, so only the contact-level block excludes elena.
    Contact::block(alice, alice.add_or_lookup_contact_id(elena).await).await?;

    alice
        .create_broadcast_with_subscribers("Channel", &[dom])
        .await;

    // Unaccepted contact request.
    tcm.send_recv(fiona, alice, "hi").await;

    let mut recipients = keyupdate_recipients(alice).await?;
    recipients.sort();
    assert_eq!(recipients, ["bob@example.net", "charlie@example.net"]);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_and_receive_keyupdate() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    alice.create_chat(bob).await;
    let alice_contact = bob.add_or_lookup_contact(alice).await;
    assert_eq!(alice_contact.last_seen(), 0);
    // Create Bob's chat before the transport change: creating it later
    // would re-import Alice's current key and hide a failing keyupdate.
    let bob_chat_id = bob.create_chat_id(alice).await;

    alice.add_transport("alice@relay.example.net").await;
    maybe_send_keyupdate_message(alice).await?;
    let keyupdate = alice.pop_sent_msg().await;
    assert_eq!(keyupdate.recipients, "bob@example.net");
    assert!(keyupdate.payload.contains("Subject: [...]"));

    // One SKESK and no PKESK: nothing leaks about the recipients.
    let mail = mailparse::parse_mail(keyupdate.payload.as_bytes())?;
    let msg = get_encrypted_pgp_message_boxed(&mail)?.unwrap();
    let Message::Encrypted { esk, .. } = &*msg else {
        panic!("Expected encrypted message");
    };
    assert!(matches!(esk[..], [Esk::SymKeyEncryptedSessionKey(_)]));

    bob.recv_msg_trash(&keyupdate).await;
    let alice_key_at_bob = alice_contact.public_key(bob).await?.unwrap();
    let addrs = addresses_from_public_key(&alice_key_at_bob).unwrap();
    assert!(addrs.contains(&"alice@relay.example.net".to_string()));
    // No green "online" dot, unlike for a regular message, see `test_last_seen()`.
    let alice_contact = Contact::get_by_id(bob, alice_contact.id).await?;
    assert_eq!(alice_contact.last_seen(), 0);

    let bob_message = bob.send_text(bob_chat_id, "hi").await;
    assert!(bob_message.recipients.contains("alice@relay.example.net"));

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

    alice.create_chat(bob).await;
    maybe_send_keyupdate_message(alice).await?;
    assert!(alice.pop_sent_msg_opt().await.is_none());

    alice.add_transport("alice@relay.example.net").await;
    send_sync_transports(alice).await?;
    let deadline = alice.keyupdate_check_deadline.load(Ordering::Relaxed);
    assert!(deadline > time());

    // Sending is driven by the changed relay list, not by the deadline.
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
        a.create_chat(bob).await;
    }

    alice.add_transport("alice@relay.example.net").await;
    send_sync_transports(alice).await?;
    alice.send_sync_msg().await?;
    alice2.recv_msg_trash(&alice.pop_sent_msg().await).await;

    maybe_send_keyupdate_message(alice2).await?;
    assert!(alice2.pop_sent_msg_opt().await.is_none());
    maybe_send_keyupdate_message(alice).await?;
    assert_eq!(alice.pop_sent_msg().await.recipients, "bob@example.net");

    Ok(())
}
