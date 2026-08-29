use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::chat::resend_msgs;
use crate::chat::{self, Chat, add_contact_to_chat, remove_contact_from_chat, send_msg};
use crate::config::Config;
use crate::constants::Chattype;
use crate::contact::{Contact, ContactId};
use crate::key::self_fingerprint;
use crate::message::{Message, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::receive_imf::receive_imf;
use crate::securejoin::{get_securejoin_qr, join_securejoin};
use crate::test_utils::{TestContextManager, get_chat_msg};
use crate::tools::SystemTime;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_missing_key_reexecute_securejoin() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let chat_id = tcm.execute_securejoin(bob, alice).await;
    let chat = Chat::load_from_db(bob, chat_id).await?;
    assert!(chat.can_send(bob).await?);
    bob.sql
        .execute(
            "DELETE FROM public_keys WHERE fingerprint=?",
            (&self_fingerprint(alice).await.unwrap(),),
        )
        .await?;
    let chat = Chat::load_from_db(bob, chat_id).await?;
    assert!(!chat.can_send(bob).await?);

    let chat_id = tcm.execute_securejoin(bob, alice).await;
    let chat = Chat::load_from_db(bob, chat_id).await?;
    assert!(chat.can_send(bob).await?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_mua_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    alice.allow_unencrypted().await?;

    tcm.send_recv_accept(bob, alice, "Heyho from DC").await;

    let sent = receive_imf(
        alice,
        b"From: alice@example.org\n\
          To: bob@example.net\n\
          \n\
          One classical MUA message",
        false,
    )
    .await?
    .unwrap();
    tcm.send_recv(alice, bob, "Sending with DC again").await;

    // Unencrypted message from MUA gets into a separate chat.
    // PGP chat gets all encrypted messages.
    alice
        .golden_test_chat(sent.chat_id, "test_outgoing_mua_msg")
        .await;
    alice
        .golden_test_chat(alice.get_chat(bob).await.id, "test_outgoing_mua_msg_pgp")
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_encrypted_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat_id = alice.create_chat(bob).await.id;
    let raw = include_bytes!("../../test-data/message/thunderbird_with_autocrypt.eml");
    receive_imf(alice, raw, false).await?;
    alice
        .golden_test_chat(chat_id, "test_outgoing_encrypted_msg")
        .await;
    Ok(())
}

/// If Bob answers unencrypted from another address with a classical MUA,
/// the message is under some circumstances still assigned to the original
/// chat (see lookup_chat_by_reply()); this is meant to make aliases
/// work nicely.
/// However, the unencrypted message must NOT be assigned to an encrypted chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reply() -> Result<()> {
    {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        alice.allow_unencrypted().await?;

        tcm.send_recv_accept(&bob, &alice, "Heyho from DC").await;
        let encrypted_msg = tcm.send_recv(&alice, &bob, "Heyho back").await;

        let unencrypted_msg = receive_imf(
            &alice,
            format!(
                "From: bob@someotherdomain.org\n\
                 To: some-alias-forwarding-to-alice@example.org\n\
                 In-Reply-To: {}\n\
                 \n\
                 Weird reply",
                encrypted_msg.rfc724_mid
            )
            .as_bytes(),
            false,
        )
        .await?
        .unwrap();

        let unencrypted_msg = Message::load_from_db(&alice, unencrypted_msg.msg_ids[0]).await?;
        assert_eq!(unencrypted_msg.text, "Weird reply");

        assert_ne!(unencrypted_msg.chat_id, encrypted_msg.chat_id);
    }

    Ok(())
}

/// Tests that a message from an old DC setup does not break the new chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_message_from_old_dc_setup() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob_old = &tcm.unconfigured().await;

    bob_old.configure_addr("bob@example.net").await;
    let chat = bob_old.create_chat(alice).await;
    let sent_old = bob_old
        .send_text(chat.id, "Soon i'll have a new device")
        .await;
    SystemTime::shift(std::time::Duration::from_secs(3600));

    tcm.section("Bob reinstalls DC");
    let bob = &tcm.bob().await;

    tcm.send_recv(bob, alice, "Now i have it!").await;

    let msg = alice.recv_msg(&sent_old).await;
    assert!(msg.get_showpadlock());
    let contact = alice.add_or_lookup_contact(bob).await;

    // The outdated Bob's Autocrypt header isn't applied,
    // so the message goes to another chat.
    assert_ne!(contact.id, msg.from_id);
    Ok(())
}

/// Tests that on a second device the e2ee info message
/// sorts before the older message that created the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_grp_multidev() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice1 = &tcm.alice().await;

    let group_id = alice.create_group_with_members("Group", &[]).await;
    assert_eq!(
        get_chat_msg(alice, group_id, 0, 1).await.get_info_type(),
        SystemMessage::ChatE2ee
    );

    let sent = alice.send_text(group_id, "Hey").await;
    // This time shift is necessary to reproduce the bug when the original message is sorted over
    // the "Messages are end-to-end encrypted" message so that these messages have different timestamps.
    SystemTime::shift(std::time::Duration::from_secs(3600));
    let msg = alice1.recv_msg(&sent).await;
    let group1 = Chat::load_from_db(alice1, msg.chat_id).await?;
    assert_eq!(group1.get_type(), Chattype::Group);
    assert_eq!(
        chat::get_chat_contacts(alice1, group1.id).await?,
        vec![ContactId::SELF]
    );
    assert_eq!(
        get_chat_msg(alice1, group1.id, 0, 2).await.get_info_type(),
        SystemMessage::ChatE2ee
    );
    assert_eq!(get_chat_msg(alice1, group1.id, 1, 2).await.id, msg.id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_member_added_reordering() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(fiona).await;

    // Bob and Fiona scan Alice's QR code.
    tcm.execute_securejoin(bob, alice).await;
    tcm.execute_securejoin(fiona, alice).await;

    // Alice creates a group with Bob.
    let alice_chat_id = alice.create_group_with_members("Group", &[bob]).await;
    let alice_sent_group_promotion = alice.send_text(alice_chat_id, "I created a group").await;
    let msg = bob.recv_msg(&alice_sent_group_promotion).await;
    let bob_chat_id = msg.chat_id;

    // Alice adds Fiona.
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    let alice_sent_member_added = alice.pop_sent_msg().await;

    // Bob receives "Alice added Fiona" message.
    bob.recv_msg(&alice_sent_member_added).await;

    // Bob sends a message to the group.
    let bob_sent_message = bob.send_text(bob_chat_id, "Hi").await;

    // Fiona receives message from Bob before receiving
    // the "Member added" message, so she cannot send yet.
    let fiona_received_message = fiona.recv_msg(&bob_sent_message).await;
    let fiona_chat = Chat::load_from_db(fiona, fiona_received_message.chat_id).await?;
    assert!(!fiona_chat.can_send(fiona).await?);

    assert_eq!(fiona_received_message.get_text(), "Hi");

    // Fiona receives late "Member added" message.
    fiona.recv_msg_trash(&alice_sent_member_added).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_unencrypted_name_if_encrypted() -> Result<()> {
    let mut tcm = TestContextManager::new();
    {
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        bob.set_config(Config::Displayname, Some("Bob Smith"))
            .await?;
        tcm.send_recv_accept(&alice, &bob, "hi").await;

        let chat_id = bob.create_chat(&alice).await.id;
        let msg = &bob.send_text(chat_id, "hi").await;

        assert_eq!(msg.payload.contains("Bob Smith"), false);
        assert!(msg.payload.contains("BEGIN PGP MESSAGE"));

        let msg = alice.recv_msg(msg).await;
        let contact = Contact::get_by_id(&alice, msg.from_id).await?;

        assert_eq!(Contact::get_display_name(&contact), "Bob Smith");
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lost_member_added() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    tcm.execute_securejoin(bob, alice).await;
    tcm.execute_securejoin(fiona, alice).await;

    let alice_chat_id = alice.create_group_with_members("Group", &[bob]).await;
    let alice_sent = alice.send_text(alice_chat_id, "Hi!").await;
    let bob_chat_id = bob.recv_msg(&alice_sent).await.chat_id;
    assert_eq!(chat::get_chat_contacts(bob, bob_chat_id).await?.len(), 2);

    // Attempt to add member, but message is lost.
    let fiona_id = alice.add_or_lookup_contact(fiona).await.id;
    add_contact_to_chat(alice, alice_chat_id, fiona_id).await?;
    alice.pop_sent_msg().await;

    let alice_sent = alice.send_text(alice_chat_id, "Hi again!").await;
    bob.recv_msg(&alice_sent).await;
    assert_eq!(chat::get_chat_contacts(bob, bob_chat_id).await?.len(), 3);

    bob_chat_id.accept(bob).await?;
    let sent = bob.send_text(bob_chat_id, "Hello!").await;
    let sent_msg = Message::load_from_db(bob, sent.sender_msg_id).await?;
    assert_eq!(sent_msg.get_showpadlock(), true);

    // The message will not be sent to Fiona.
    // Test that Fiona will not be able to decrypt it
    // and the message is trashed because
    // we don't create groups from undecipherable messages.
    fiona.recv_msg_trash(&sent).await;

    // Advance the time so Alice does not leave at the same second
    // as the group was created.
    SystemTime::shift(std::time::Duration::from_secs(100));

    // Alice leaves the chat.
    remove_contact_from_chat(alice, alice_chat_id, ContactId::SELF).await?;
    assert_eq!(
        chat::get_chat_contacts(alice, alice_chat_id).await?.len(),
        2
    );
    bob.recv_msg(&alice.pop_sent_msg().await).await;

    // Now only Bob and Fiona are in the chat.
    assert_eq!(chat::get_chat_contacts(bob, bob_chat_id).await?.len(), 2);

    // Bob cannot send messages anymore because there are no recipients
    // other than self for which Bob has the key.
    let mut msg = Message::new_text("No key for Fiona".to_string());
    let result = send_msg(bob, bob_chat_id, &mut msg).await;
    assert!(result.is_err());

    bob.assert_warn("Missing key for fiona@example.net").await;
    fiona.assert_warn("missing key").await;
    fiona.assert_warn("unencrypted message").await;
    bob.assert_warn("Missing key for fiona@example.net").await;
    bob.assert_warn(r#"No recipient keys are available, cannot encrypt to ["fiona@example.net"]"#)
        .await;

    Ok(())
}

/// Tests handling of resent .xdc arriving before "Member added".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_editor_reordering() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    tcm.execute_securejoin(alice, bob).await;

    tcm.section("Alice creates a group with Bob");
    let alice_chat_id = alice.create_group_with_members("Group", &[bob]).await;
    let alice_sent = alice.send_text(alice_chat_id, "Hi!").await;
    let bob_chat_id = bob.recv_msg(&alice_sent).await.chat_id;

    tcm.section("Bob sends an .xdc to the chat");

    let mut webxdc_instance = Message::new(Viewtype::File);
    webxdc_instance.set_file_from_bytes(
        bob,
        "editor.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
        None,
    )?;
    let bob_instance_msg_id = send_msg(bob, bob_chat_id, &mut webxdc_instance).await?;
    let bob_sent_instance_msg = bob.pop_sent_msg().await;

    tcm.section("Alice receives .xdc");
    alice.recv_msg(&bob_sent_instance_msg).await;

    tcm.section("Alice creates a group QR code");
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();

    tcm.section("Charlie scans SecureJoin QR code");
    join_securejoin(charlie, &qr).await?;

    // vg-request
    alice.recv_msg_trash(&charlie.pop_sent_msg().await).await;

    // vg-auth-required
    charlie.recv_msg_trash(&alice.pop_sent_msg().await).await;

    // vg-request-with-auth
    alice.recv_msg_trash(&charlie.pop_sent_msg().await).await;

    // vg-member-added
    let sent_member_added_msg = alice.pop_sent_msg().await;

    tcm.section("Bob receives member added message");
    bob.recv_msg(&sent_member_added_msg).await;

    tcm.section("Bob resends webxdc");
    resend_msgs(bob, &[bob_instance_msg_id]).await?;

    tcm.section("Charlie receives resent webxdc before member added");
    let charlie_received_xdc = charlie.recv_msg(&bob.pop_sent_msg().await).await;

    assert_eq!(charlie_received_xdc.viewtype, Viewtype::Webxdc);

    tcm.section("Charlie receives member added message");
    charlie.recv_msg(&sent_member_added_msg).await;
    charlie
        .golden_test_chat(
            charlie_received_xdc.chat_id,
            "encrypted_chats_editor_reordering",
        )
        .await;
    Ok(())
}
