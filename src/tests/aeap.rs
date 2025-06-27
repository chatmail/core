//! "AEAP" means "Automatic Email Address Porting"
//! and was the predecessor of key-contacts
//! (i.e. identifying contacts via the fingerprint,
//! while allowing the email address to change).
//!
//! These tests still pass because key-contacts
//! allows messaging to continue after an email address change,
//! just as AEAP did. Some other tests had to be removed.

use anyhow::Result;

use crate::chat::{self, Chat, ChatId, ProtectionStatus};
use crate::contact::{Contact, ContactId};
use crate::message::Message;
use crate::receive_imf::receive_imf;
use crate::securejoin::get_securejoin_qr;
use crate::test_utils::TestContext;
use crate::test_utils::TestContextManager;
use crate::test_utils::mark_as_verified;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_change_primary_self_addr() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    tcm.send_recv_accept(&alice, &bob, "Hi").await;
    let bob_alice_chat = bob.create_chat(&alice).await;

    tcm.change_addr(&alice, "alice@someotherdomain.xyz").await;

    tcm.section("Bob sends a message to Alice, encrypting to her previous key");
    let sent = bob.send_text(bob_alice_chat.id, "hi back").await;

    // Alice set up message forwarding so that she still receives
    // the message with her new address
    let alice_msg = alice.recv_msg(&sent).await;
    assert_eq!(alice_msg.text, "hi back".to_string());
    assert_eq!(alice_msg.get_showpadlock(), true);
    let alice_bob_chat = alice.create_chat(&bob).await;
    assert_eq!(alice_msg.chat_id, alice_bob_chat.id);

    Ok(())
}

enum ChatForTransition {
    OneToOne,
    GroupChat,
    VerifiedGroup,
}
use ChatForTransition::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_aeap_transition_0() {
    check_aeap_transition(OneToOne, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_aeap_transition_1() {
    check_aeap_transition(GroupChat, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_aeap_transition_0_verified() {
    check_aeap_transition(OneToOne, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_aeap_transition_1_verified() {
    check_aeap_transition(GroupChat, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_aeap_transition_2_verified() {
    check_aeap_transition(VerifiedGroup, true).await;
}

/// Happy path test for AEAP.
/// - `chat_for_transition`: Which chat the transition message should be sent in
/// - `verified`: Whether Alice and Bob verified each other
async fn check_aeap_transition(chat_for_transition: ChatForTransition, verified: bool) {
    const ALICE_NEW_ADDR: &str = "alice2@example.net";

    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.send_recv_accept(alice, bob, "Hi").await;
    tcm.send_recv(bob, alice, "Hi back").await;

    if verified {
        mark_as_verified(alice, bob).await;
        mark_as_verified(bob, alice).await;
    }

    let mut groups = vec![
        chat::create_group_chat(bob, chat::ProtectionStatus::Unprotected, "Group 0")
            .await
            .unwrap(),
        chat::create_group_chat(bob, chat::ProtectionStatus::Unprotected, "Group 1")
            .await
            .unwrap(),
    ];
    if verified {
        groups.push(
            chat::create_group_chat(bob, chat::ProtectionStatus::Protected, "Group 2")
                .await
                .unwrap(),
        );
        groups.push(
            chat::create_group_chat(bob, chat::ProtectionStatus::Protected, "Group 3")
                .await
                .unwrap(),
        );
    }

    let alice_contact = bob.add_or_lookup_contact_id(alice).await;
    for group in &groups {
        chat::add_contact_to_chat(bob, *group, alice_contact)
            .await
            .unwrap();
    }

    // groups 0 and 2 stay unpromoted (i.e. local
    // on Bob's device, Alice doesn't know about them)
    tcm.section("Promoting group 1");
    let sent = bob.send_text(groups[1], "group created").await;
    let group1_alice = alice.recv_msg(&sent).await.chat_id;

    let mut group3_alice = None;
    if verified {
        tcm.section("Promoting group 3");
        let sent = bob.send_text(groups[3], "group created").await;
        group3_alice = Some(alice.recv_msg(&sent).await.chat_id);
    }

    tcm.change_addr(alice, ALICE_NEW_ADDR).await;

    tcm.section("Alice sends another message to Bob, this time from her new addr");
    // No matter which chat Alice sends to, the transition should be done in all groups
    let chat_to_send = match chat_for_transition {
        OneToOne => alice.create_chat(bob).await.id,
        GroupChat => group1_alice,
        VerifiedGroup => group3_alice.expect("No verified group"),
    };
    let sent = alice
        .send_text(chat_to_send, "Hello from my new addr!")
        .await;
    let recvd = bob.recv_msg(&sent).await;
    assert_eq!(recvd.text, "Hello from my new addr!");

    tcm.section("Check that the AEAP transition worked");
    check_that_transition_worked(bob, &groups, alice_contact, ALICE_NEW_ADDR).await;

    tcm.section("Test switching back");
    tcm.change_addr(alice, "alice@example.org").await;
    let sent = alice
        .send_text(chat_to_send, "Hello from my old addr!")
        .await;
    let recvd = bob.recv_msg(&sent).await;
    assert_eq!(recvd.text, "Hello from my old addr!");

    check_that_transition_worked(bob, &groups, alice_contact, "alice@example.org").await;
}

async fn check_that_transition_worked(
    bob: &TestContext,
    groups: &[ChatId],
    alice_contact_id: ContactId,
    alice_addr: &str,
) {
    for group in groups {
        let members = chat::get_chat_contacts(bob, *group).await.unwrap();
        // In all the groups, exactly Bob and Alice are members.
        assert_eq!(
            members.len(),
            2,
            "Group {} has members {:?}, but should have members {:?} and {:?}",
            group,
            &members,
            alice_contact_id,
            ContactId::SELF
        );
        assert!(
            members.contains(&alice_contact_id),
            "Group {group} lacks {alice_contact_id}"
        );
        assert!(members.contains(&ContactId::SELF));
    }

    // Test that the email address of Alice is updated.
    let alice_contact = Contact::get_by_id(bob, alice_contact_id).await.unwrap();
    assert_eq!(alice_contact.get_addr(), alice_addr);
}

/// Test that an attacker - here Fiona - can't replay a message sent by Alice
/// to make Bob think that there was a transition to Fiona's address.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_aeap_replay_attack() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    tcm.send_recv_accept(&alice, &bob, "Hi").await;
    tcm.send_recv(&bob, &alice, "Hi back").await;

    let group =
        chat::create_group_chat(&bob, chat::ProtectionStatus::Unprotected, "Group 0").await?;

    let bob_alice_contact = bob.add_or_lookup_contact_id(&alice).await;
    let bob_fiona_contact = bob.add_or_lookup_contact_id(&fiona).await;
    chat::add_contact_to_chat(&bob, group, bob_alice_contact).await?;

    // Alice sends a message which Bob doesn't receive or something
    // A real attack would rather reuse a message that was sent to a group
    // and replace the Message-Id or so.
    let chat = alice.create_chat(&bob).await;
    let sent = alice.send_text(chat.id, "whoop whoop").await;

    // Fiona gets the message, replaces the From addr...
    let sent = sent
        .payload()
        .replace("From: <alice@example.org>", "From: <fiona@example.net>")
        .replace("addr=alice@example.org;", "addr=fiona@example.net;");
    sent.find("From: <fiona@example.net>").unwrap(); // Assert that it worked
    sent.find("addr=fiona@example.net;").unwrap(); // Assert that it worked

    tcm.section("Fiona replaced the From addr and forwards the message to Bob");
    receive_imf(&bob, sent.as_bytes(), false).await?.unwrap();

    // Check that no transition was done
    assert!(chat::is_contact_in_chat(&bob, group, bob_alice_contact).await?);
    assert!(!chat::is_contact_in_chat(&bob, group, bob_fiona_contact).await?);

    Ok(())
}

/// Tests that writing to a contact is possible
/// after address change.
///
/// This test is redundant after introduction
/// of key-contacts, but is kept to avoid deleting the tests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_write_to_alice_after_aeap() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_grp_id = chat::create_group_chat(alice, ProtectionStatus::Protected, "Group").await?;
    let qr = get_securejoin_qr(alice, Some(alice_grp_id)).await?;
    tcm.exec_securejoin_qr(bob, alice, &qr).await;
    let bob_alice_contact = bob.add_or_lookup_contact(alice).await;
    assert!(bob_alice_contact.is_verified(bob).await?);
    let bob_alice_chat = bob.create_chat(alice).await;
    assert!(bob_alice_chat.is_protected());
    let bob_unprotected_grp_id = bob
        .create_group_with_members(ProtectionStatus::Unprotected, "Group", &[alice])
        .await;

    tcm.change_addr(alice, "alice@someotherdomain.xyz").await;
    let sent = alice.send_text(alice_grp_id, "Hello!").await;
    bob.recv_msg(&sent).await;

    assert!(bob_alice_contact.is_verified(bob).await?);
    let bob_alice_chat = Chat::load_from_db(bob, bob_alice_chat.id).await?;
    assert!(bob_alice_chat.is_protected());
    let mut msg = Message::new_text("hi".to_string());
    chat::send_msg(bob, bob_alice_chat.id, &mut msg).await?;

    // Encrypted communication is also possible in unprotected groups with Alice.
    let sent = bob
        .send_text(bob_unprotected_grp_id, "Alice, how is your address change?")
        .await;
    let msg = Message::load_from_db(bob, sent.sender_msg_id).await?;
    assert!(msg.get_showpadlock());
    Ok(())
}
