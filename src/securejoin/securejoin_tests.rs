use std::time::Duration;

use deltachat_contact_tools::EmailAddress;

use super::*;
use crate::chat::{CantSendReason, remove_contact_from_chat};
use crate::chatlist::Chatlist;
use crate::constants::Chattype;
use crate::key::self_fingerprint;
use crate::mimeparser::{GossipedKey, SystemMessage};
use crate::receive_imf::receive_imf;
use crate::stock_str::{self, messages_e2e_encrypted};
use crate::test_utils::{
    AVATAR_64x64_BYTES, AVATAR_64x64_DEDUPLICATED, TestContext, TestContextManager,
    TimeShiftFalsePositiveNote, get_chat_msg,
};
use crate::tools::SystemTime;

#[derive(PartialEq)]
enum SetupContactCase {
    Normal,
    WrongAliceGossip,
    AliceIsBot,
    AliceHasName,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setup_contact() {
    test_setup_contact_ex(SetupContactCase::Normal).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setup_contact_wrong_alice_gossip() {
    test_setup_contact_ex(SetupContactCase::WrongAliceGossip).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setup_contact_alice_is_bot() {
    test_setup_contact_ex(SetupContactCase::AliceIsBot).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setup_contact_alice_has_name() {
    test_setup_contact_ex(SetupContactCase::AliceHasName).await
}

async fn test_setup_contact_ex(case: SetupContactCase) {
    let _n = TimeShiftFalsePositiveNote;

    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let alice_addr = &alice.get_config(Config::Addr).await.unwrap().unwrap();
    if case == SetupContactCase::AliceHasName {
        alice
            .set_config(Config::Displayname, Some("Alice"))
            .await
            .unwrap();
    }
    let bob = tcm.bob().await;
    bob.set_config(Config::Displayname, Some("Bob Examplenet"))
        .await
        .unwrap();
    let alice_auto_submitted_hdr;
    match case {
        SetupContactCase::AliceIsBot => {
            alice.set_config_bool(Config::Bot, true).await.unwrap();
            alice_auto_submitted_hdr = "Auto-Submitted: auto-generated";
        }
        _ => alice_auto_submitted_hdr = "Auto-Submitted: auto-replied",
    };

    assert_eq!(
        Chatlist::try_load(&alice, 0, None, None)
            .await
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        Chatlist::try_load(&bob, 0, None, None).await.unwrap().len(),
        0
    );

    tcm.section("Step 1: Generate QR-code, ChatId(0) indicates setup-contact");
    let qr = get_securejoin_qr(&alice, None).await.unwrap();
    // We want Bob to learn Alice's name from their messages, not from the QR code.
    alice
        .set_config(Config::Displayname, Some("Alice Exampleorg"))
        .await
        .unwrap();

    tcm.section("Step 2: Bob scans QR-code, sends vc-request");
    let bob_chat_id = join_securejoin(&bob.ctx, &qr).await.unwrap();
    assert_eq!(
        Chatlist::try_load(&bob, 0, None, None).await.unwrap().len(),
        1
    );
    let bob_chat = Chat::load_from_db(&bob, bob_chat_id).await.unwrap();
    assert_eq!(
        bob_chat.why_cant_send(&bob).await.unwrap(),
        Some(CantSendReason::MissingKey)
    );
    let contact_alice_id = bob.add_or_lookup_contact_no_key(&alice).await.id;
    let sent = bob.pop_sent_msg().await;
    assert!(!sent.payload.contains("Bob Examplenet"));
    assert_eq!(sent.recipient(), EmailAddress::new(alice_addr).unwrap());
    let msg = alice.parse_msg(&sent).await;
    assert!(!msg.was_encrypted());
    assert_eq!(msg.get_header(HeaderDef::SecureJoin).unwrap(), "vc-request");
    assert!(msg.get_header(HeaderDef::SecureJoinInvitenumber).is_some());
    assert!(!msg.header_exists(HeaderDef::AutoSubmitted));

    tcm.section("Step 3: Alice receives vc-request, sends vc-auth-required");
    alice.recv_msg_trash(&sent).await;
    assert_eq!(
        Chatlist::try_load(&alice, 0, None, None)
            .await
            .unwrap()
            .len(),
        0
    );

    let sent = alice.pop_sent_msg().await;
    assert!(sent.payload.contains(alice_auto_submitted_hdr));
    assert!(!sent.payload.contains("Alice Exampleorg"));
    let msg = bob.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vc-auth-required"
    );

    let bob_chat = bob.get_chat(&alice).await;
    assert_eq!(bob_chat.can_send(&bob).await.unwrap(), true);

    tcm.section("Step 4: Bob receives vc-auth-required, sends vc-request-with-auth");
    bob.recv_msg_trash(&sent).await;
    let bob_chat = bob.get_chat(&alice).await;
    assert_eq!(bob_chat.why_cant_send(&bob).await.unwrap(), None);
    assert_eq!(bob_chat.can_send(&bob).await.unwrap(), true);

    // Check Bob emitted the JoinerProgress event.
    let event = bob
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::SecurejoinJoinerProgress { .. }))
        .await;
    match event {
        EventType::SecurejoinJoinerProgress {
            contact_id,
            progress,
        } => {
            assert_eq!(contact_id, contact_alice_id);
            assert_eq!(progress, 400);
        }
        _ => unreachable!(),
    }

    // Check Bob sent the right message.
    let sent = bob.pop_sent_msg().await;
    assert!(sent.payload.contains("Auto-Submitted: auto-replied"));
    assert!(!sent.payload.contains("Bob Examplenet"));
    let mut msg = alice.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vc-request-with-auth"
    );
    assert!(msg.get_header(HeaderDef::SecureJoinAuth).is_some());
    let bob_fp = self_fingerprint(&bob).await.unwrap();
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoinFingerprint).unwrap(),
        bob_fp
    );

    if case == SetupContactCase::WrongAliceGossip {
        let wrong_pubkey = GossipedKey {
            public_key: load_self_public_key(&bob).await.unwrap(),
            verified: false,
        };
        let alice_pubkey = msg
            .gossiped_keys
            .insert(alice_addr.to_string(), wrong_pubkey)
            .unwrap();
        let contact_bob = alice.add_or_lookup_contact_no_key(&bob).await;
        let handshake_msg = handle_securejoin_handshake(&alice, &mut msg, contact_bob.id)
            .await
            .unwrap();
        assert_eq!(handshake_msg, HandshakeMessage::Ignore);
        assert_eq!(contact_bob.is_verified(&alice).await.unwrap(), false);

        msg.gossiped_keys
            .insert(alice_addr.to_string(), alice_pubkey)
            .unwrap();
        let handshake_msg = handle_securejoin_handshake(&alice, &mut msg, contact_bob.id)
            .await
            .unwrap();
        assert_eq!(handshake_msg, HandshakeMessage::Ignore);
        assert!(contact_bob.is_verified(&alice).await.unwrap());
        return;
    }

    // Alice should not yet have Bob verified
    let contact_bob = alice.add_or_lookup_contact_no_key(&bob).await;
    let contact_bob_id = contact_bob.id;
    assert_eq!(contact_bob.is_key_contact(), true);
    assert_eq!(contact_bob.is_verified(&alice).await.unwrap(), false);
    assert_eq!(contact_bob.get_authname(), "");

    tcm.section("Step 5+6: Alice receives vc-request-with-auth, sends vc-contact-confirm");
    alice.recv_msg_trash(&sent).await;
    assert_eq!(contact_bob.is_verified(&alice).await.unwrap(), true);
    let contact_bob = Contact::get_by_id(&alice, contact_bob_id).await.unwrap();
    assert_eq!(contact_bob.get_authname(), "Bob Examplenet");
    assert!(contact_bob.get_name().is_empty());
    assert_eq!(contact_bob.is_bot(), false);

    // exactly one one-to-one chat should be visible for both now
    // (check this before calling alice.get_chat() explicitly below)
    assert_eq!(
        Chatlist::try_load(&alice, 0, None, None)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        Chatlist::try_load(&bob, 0, None, None).await.unwrap().len(),
        1
    );

    // Check Alice got the verified message in her 1:1 chat.
    {
        let chat = alice.get_chat(&bob).await;
        let msg = get_chat_msg(&alice, chat.get_id(), 0, 1).await;
        assert!(msg.is_info());
        let expected_text = messages_e2e_encrypted(&alice).await;
        assert_eq!(msg.get_text(), expected_text);
    }

    // Make sure Alice hasn't yet sent their name to Bob.
    let contact_alice = Contact::get_by_id(&bob.ctx, contact_alice_id)
        .await
        .unwrap();
    match case {
        SetupContactCase::AliceHasName => assert_eq!(contact_alice.get_authname(), "Alice"),
        _ => assert_eq!(contact_alice.get_authname(), "Alice Exampleorg"),
    };

    // Check Alice sent the right message to Bob.
    let sent = alice.pop_sent_msg().await;
    assert!(sent.payload.contains(alice_auto_submitted_hdr));
    assert!(!sent.payload.contains("Alice Exampleorg"));
    let msg = bob.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vc-contact-confirm"
    );

    // Bob has verified Alice already.
    //
    // Alice may not have verified Bob yet.
    assert_eq!(contact_alice.is_verified(&bob.ctx).await.unwrap(), true);

    // Step 7: Bob receives vc-contact-confirm
    bob.recv_msg_trash(&sent).await;
    assert_eq!(contact_alice.is_verified(&bob.ctx).await.unwrap(), true);
    let contact_alice = Contact::get_by_id(&bob.ctx, contact_alice_id)
        .await
        .unwrap();
    assert_eq!(contact_alice.get_authname(), "Alice Exampleorg");
    assert!(contact_alice.get_name().is_empty());
    assert_eq!(contact_alice.is_bot(), case == SetupContactCase::AliceIsBot);

    // Check Bob got expected info messages in his 1:1 chat.
    let msg_cnt = 2;
    let mut i = 0..msg_cnt;
    let msg = get_chat_msg(&bob, bob_chat.get_id(), i.next().unwrap(), msg_cnt).await;
    assert!(msg.is_info());
    assert_eq!(msg.get_text(), messages_e2e_encrypted(&bob).await);
    let msg = get_chat_msg(&bob, bob_chat.get_id(), i.next().unwrap(), msg_cnt).await;
    assert!(msg.is_info());
    assert_eq!(msg.get_text(), stock_str::securejoin_wait(&bob).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setup_contact_bad_qr() {
    let bob = TestContext::new_bob().await;
    let ret = join_securejoin(&bob.ctx, "not a qr code").await;
    assert!(ret.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setup_contact_bob_knows_alice() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // Ensure Bob knows Alice_FP
    let alice_contact_id = bob.add_or_lookup_contact_id(alice).await;

    tcm.section("Step 1: Generate QR-code");
    // `None` indicates setup-contact.
    let qr = get_securejoin_qr(alice, None).await?;

    tcm.section("Step 2+4: Bob scans QR-code, sends vc-request-with-auth, skipping vc-request");
    join_securejoin(bob, &qr).await.unwrap();

    // Check Bob emitted the JoinerProgress event.
    let event = bob
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::SecurejoinJoinerProgress { .. }))
        .await;
    match event {
        EventType::SecurejoinJoinerProgress {
            contact_id,
            progress,
        } => {
            assert_eq!(contact_id, alice_contact_id);
            assert_eq!(progress, 400);
        }
        _ => unreachable!(),
    }

    // Check Bob sent the right handshake message.
    let sent = bob.pop_sent_msg().await;
    let msg = alice.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vc-request-with-auth"
    );
    assert!(msg.get_header(HeaderDef::SecureJoinAuth).is_some());
    let bob_fp = load_self_public_key(bob).await?.dc_fingerprint();
    assert_eq!(
        *msg.get_header(HeaderDef::SecureJoinFingerprint).unwrap(),
        bob_fp.hex()
    );

    // Alice should not yet have Bob verified
    let contact_bob = alice.add_or_lookup_contact_no_key(bob).await;
    assert_eq!(contact_bob.is_verified(alice).await?, false);

    tcm.section("Step 5+6: Alice receives vc-request-with-auth, sends vc-contact-confirm");
    alice.recv_msg_trash(&sent).await;
    assert_eq!(contact_bob.is_verified(alice).await?, true);

    // Check Alice signalled success via the SecurejoinInviterProgress event.
    let event = alice
        .evtracker
        .get_matching(|evt| {
            matches!(
                evt,
                EventType::SecurejoinInviterProgress { progress: 1000, .. }
            )
        })
        .await;
    match event {
        EventType::SecurejoinInviterProgress {
            contact_id,
            chat_type,
            progress,
            ..
        } => {
            assert_eq!(contact_id, contact_bob.id);
            assert_eq!(chat_type, Chattype::Single);
            assert_eq!(progress, 1000);
        }
        _ => unreachable!(),
    }

    let sent = alice.pop_sent_msg().await;
    let msg = bob.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vc-contact-confirm"
    );

    // Bob has verified Alice already.
    let contact_alice = bob.add_or_lookup_contact_no_key(alice).await;
    assert_eq!(contact_alice.is_verified(bob).await?, true);

    // Alice confirms that Bob is now verified.
    //
    // This does not change anything for Bob.
    tcm.section("Step 7: Bob receives vc-contact-confirm");
    bob.recv_msg_trash(&sent).await;
    assert_eq!(contact_alice.is_verified(bob).await?, true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setup_contact_concurrent_calls() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    // do a scan that is not working as claire is never responding
    let qr_stale = "OPENPGP4FPR:1234567890123456789012345678901234567890#a=claire%40foo.de&n=&i=12345678901&s=23456789012";
    let claire_id = join_securejoin(&bob, qr_stale).await?;
    let chat = Chat::load_from_db(&bob, claire_id).await?;
    assert!(!claire_id.is_special());
    assert_eq!(chat.typ, Chattype::Single);
    assert!(bob.pop_sent_msg().await.payload().contains("claire@foo.de"));

    // subsequent scans shall abort existing ones or run concurrently -
    // but they must not fail as otherwise the whole qr scanning becomes unusable until restart.
    let qr = get_securejoin_qr(&alice, None).await?;
    let alice_id = join_securejoin(&bob, &qr).await?;
    let chat = Chat::load_from_db(&bob, alice_id).await?;
    assert!(!alice_id.is_special());
    assert_eq!(chat.typ, Chattype::Single);
    assert_ne!(claire_id, alice_id);
    assert!(
        bob.pop_sent_msg()
            .await
            .payload()
            .contains("alice@example.org")
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_secure_join() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    // We start with empty chatlists.
    assert_eq!(Chatlist::try_load(&alice, 0, None, None).await?.len(), 0);
    assert_eq!(Chatlist::try_load(&bob, 0, None, None).await?.len(), 0);

    let alice_chatid = chat::create_group(&alice, "the chat").await?;

    tcm.section("Step 1: Generate QR-code, secure-join implied by chatid");
    let qr = get_securejoin_qr(&alice, Some(alice_chatid)).await.unwrap();

    tcm.section("Step 2: Bob scans QR-code, sends vg-request");
    let bob_chatid = join_securejoin(&bob, &qr).await?;
    assert_eq!(Chatlist::try_load(&bob, 0, None, None).await?.len(), 1);

    let sent = bob.pop_sent_msg().await;
    assert_eq!(
        sent.recipient(),
        EmailAddress::new("alice@example.org").unwrap()
    );
    let msg = alice.parse_msg(&sent).await;
    assert!(!msg.was_encrypted());
    assert_eq!(msg.get_header(HeaderDef::SecureJoin).unwrap(), "vg-request");
    assert!(msg.get_header(HeaderDef::SecureJoinInvitenumber).is_some());
    assert!(!msg.header_exists(HeaderDef::AutoSubmitted));

    // Old Delta Chat core sent `Secure-Join-Group` header in `vg-request`,
    // but it was only used by Alice in `vg-request-with-auth`.
    // New Delta Chat versions do not use `Secure-Join-Group` header at all
    // and it is deprecated.
    // Now `Secure-Join-Group` header
    // is only sent in `vg-request-with-auth` for compatibility.
    assert!(!msg.header_exists(HeaderDef::SecureJoinGroup));

    tcm.section("Step 3: Alice receives vg-request, sends vg-auth-required");
    alice.recv_msg_trash(&sent).await;

    let sent = alice.pop_sent_msg().await;
    assert!(sent.payload.contains("Auto-Submitted: auto-replied"));
    let msg = bob.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vg-auth-required"
    );

    tcm.section("Step 4: Bob receives vg-auth-required, sends vg-request-with-auth");
    bob.recv_msg_trash(&sent).await;
    let sent = bob.pop_sent_msg().await;

    let contact_alice_id = bob.add_or_lookup_contact_no_key(&alice).await.id;

    // Check Bob emitted the JoinerProgress event.
    let event = bob
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::SecurejoinJoinerProgress { .. }))
        .await;
    match event {
        EventType::SecurejoinJoinerProgress {
            contact_id,
            progress,
        } => {
            assert_eq!(contact_id, contact_alice_id);
            assert_eq!(progress, 400);
        }
        _ => unreachable!(),
    }

    // Check Bob sent the right handshake message.
    assert!(sent.payload.contains("Auto-Submitted: auto-replied"));
    let msg = alice.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vg-request-with-auth"
    );
    assert!(msg.get_header(HeaderDef::SecureJoinAuth).is_some());
    let bob_fp = self_fingerprint(&bob).await?;
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoinFingerprint).unwrap(),
        bob_fp
    );

    // Alice should not yet have Bob verified
    let contact_bob = alice.add_or_lookup_contact_no_key(&bob).await;
    assert_eq!(contact_bob.is_verified(&alice).await?, false);

    tcm.section("Step 5+6: Alice receives vg-request-with-auth, sends vg-member-added");
    alice.recv_msg_trash(&sent).await;
    assert_eq!(contact_bob.is_verified(&alice).await?, true);

    // Check Alice signalled success via the SecurejoinInviterProgress event.
    let event = alice
        .evtracker
        .get_matching(|evt| {
            matches!(
                evt,
                EventType::SecurejoinInviterProgress { progress: 1000, .. }
            )
        })
        .await;
    match event {
        EventType::SecurejoinInviterProgress {
            contact_id,
            chat_type,
            chat_id,
            progress,
        } => {
            assert_eq!(contact_id, contact_bob.id);
            assert_eq!(chat_type, Chattype::Group);
            assert_eq!(chat_id, alice_chatid);
            assert_eq!(progress, 1000);
        }
        _ => unreachable!(),
    }

    let sent = alice.pop_sent_msg().await;
    let msg = bob.parse_msg(&sent).await;
    assert!(msg.was_encrypted());
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vg-member-added"
    );
    // Formally this message is auto-submitted, but as the member addition is a result of an
    // explicit user action, the Auto-Submitted header shouldn't be present. Otherwise it would
    // be strange to have it in "member-added" messages of verified groups only.
    assert!(!msg.header_exists(HeaderDef::AutoSubmitted));
    // This is a two-member group, but Alice must Autocrypt-gossip to her other devices.
    assert!(msg.get_header(HeaderDef::AutocryptGossip).is_some());

    {
        // Now Alice's chat with Bob should still be hidden, the verified message should
        // appear in the group chat.

        let chat = alice.get_chat(&bob).await;
        assert_eq!(
            chat.blocked,
            Blocked::Yes,
            "Alice's 1:1 chat with Bob is not hidden"
        );
        // There should be 2 messages in the chat:
        // - The ChatProtectionEnabled message
        // - You added member bob@example.net
        let msg = get_chat_msg(&alice, alice_chatid, 0, 2).await;
        assert!(msg.is_info());
        let expected_text = messages_e2e_encrypted(&alice).await;
        assert_eq!(msg.get_text(), expected_text);
    }

    // Bob has verified Alice already.
    //
    // Alice may not have verified Bob yet.
    let contact_alice = bob.add_or_lookup_contact_no_key(&alice).await;
    assert_eq!(contact_alice.is_verified(&bob).await?, true);

    tcm.section("Step 7: Bob receives vg-member-added");
    bob.recv_msg(&sent).await;
    {
        // Bob has Alice verified, message shows up in the group chat.
        assert_eq!(contact_alice.is_verified(&bob).await?, true);
        let chat = bob.get_chat(&alice).await;
        assert_eq!(
            chat.blocked,
            Blocked::Yes,
            "Bob's 1:1 chat with Alice is not hidden"
        );
        for item in chat::get_chat_msgs(&bob.ctx, bob_chatid).await.unwrap() {
            if let chat::ChatItem::Message { msg_id } = item {
                let msg = Message::load_from_db(&bob.ctx, msg_id).await.unwrap();
                let text = msg.get_text();
                println!("msg {msg_id} text: {text}");
            }
        }
    }

    let bob_chat = Chat::load_from_db(&bob.ctx, bob_chatid).await?;
    assert!(bob_chat.typ == Chattype::Group);

    // On this "happy path", Alice and Bob get only a group-chat where all information are added to.
    // The one-to-one chats are used internally for the hidden handshake messages,
    // however, should not be visible in the UIs.
    assert_eq!(Chatlist::try_load(&alice, 0, None, None).await?.len(), 1);
    assert_eq!(Chatlist::try_load(&bob, 0, None, None).await?.len(), 1);

    // If Bob then sends a direct message to alice, however, the one-to-one with Alice should appear.
    let bobs_chat_with_alice = bob.create_chat(&alice).await;
    let sent = bob.send_text(bobs_chat_with_alice.id, "Hello").await;
    alice.recv_msg(&sent).await;
    assert_eq!(Chatlist::try_load(&alice, 0, None, None).await?.len(), 2);
    assert_eq!(Chatlist::try_load(&bob, 0, None, None).await?.len(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adhoc_group_no_qr() -> Result<()> {
    let alice = TestContext::new_alice().await;

    let mime = br#"Subject: First thread
Message-ID: first@example.org
To: Alice <alice@example.org>, Bob <bob@example.net>
From: Claire <claire@example.org>
Content-Type: text/plain; charset=utf-8; format=flowed; delsp=no

First thread."#;

    receive_imf(&alice, mime, false).await?;
    let msg = alice.get_last_msg().await;
    let chat_id = msg.chat_id;

    assert!(get_securejoin_qr(&alice, Some(chat_id)).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unknown_sender() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    tcm.execute_securejoin(&alice, &bob).await;

    let alice_chat_id = alice
        .create_group_with_members("Group with Bob", &[&bob])
        .await;

    let sent = alice.send_text(alice_chat_id, "Hi!").await;
    let bob_chat_id = bob.recv_msg(&sent).await.chat_id;

    let sent = bob.send_text(bob_chat_id, "Hi hi!").await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(&bob).await;
    remove_contact_from_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    alice.pop_sent_msg().await;

    // The message from Bob is delivered late, Bob is already removed.
    let msg = alice.recv_msg(&sent).await;
    assert_eq!(msg.text, "Hi hi!");
    assert_eq!(msg.get_override_sender_name().unwrap(), "bob@example.net");

    Ok(())
}

/// Tests that Bob gets Alice as verified
/// if `vc-contact-confirm` is lost.
/// Previously `vc-contact-confirm` was used
/// to confirm backward verification,
/// but backward verification is not tracked anymore.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lost_contact_confirm() {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let qr = get_securejoin_qr(&alice, None).await.unwrap();
    join_securejoin(&bob.ctx, &qr).await.unwrap();

    // vc-request
    let sent = bob.pop_sent_msg().await;
    alice.recv_msg_trash(&sent).await;

    // vc-auth-required
    let sent = alice.pop_sent_msg().await;
    bob.recv_msg_trash(&sent).await;

    // vc-request-with-auth
    let sent = bob.pop_sent_msg().await;
    alice.recv_msg_trash(&sent).await;

    // Alice has Bob verified now.
    let contact_bob = alice.add_or_lookup_contact_no_key(&bob).await;
    assert_eq!(contact_bob.is_verified(&alice).await.unwrap(), true);

    // Alice sends vc-contact-confirm, but it gets lost.
    let _sent_vc_contact_confirm = alice.pop_sent_msg().await;

    // Bob has alice as verified too, even though vc-contact-confirm is lost.
    let contact_alice = bob.add_or_lookup_contact_no_key(&alice).await;
    assert_eq!(contact_alice.is_verified(&bob).await.unwrap(), true);
}

/// Tests Bob joining two groups by scanning two QR codes
/// from the same Alice at the same time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel_securejoin() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat1_id = chat::create_group(alice, "First chat").await?;
    let alice_chat2_id = chat::create_group(alice, "Second chat").await?;

    let qr1 = get_securejoin_qr(alice, Some(alice_chat1_id)).await?;
    let qr2 = get_securejoin_qr(alice, Some(alice_chat2_id)).await?;

    // Bob scans both QR codes.
    let bob_chat1_id = join_securejoin(bob, &qr1).await?;
    let sent_vg_request1 = bob.pop_sent_msg().await;

    let bob_chat2_id = join_securejoin(bob, &qr2).await?;
    let sent_vg_request2 = bob.pop_sent_msg().await;

    // Alice receives two `vg-request` messages
    // and sends back two `vg-auth-required` messages.
    alice.recv_msg_trash(&sent_vg_request1).await;
    let sent_vg_auth_required1 = alice.pop_sent_msg().await;

    alice.recv_msg_trash(&sent_vg_request2).await;
    let _sent_vg_auth_required2 = alice.pop_sent_msg().await;

    // Bob receives first `vg-auth-required` message.
    // Bob has two securejoin processes started,
    // so he should send two `vg-request-with-auth` messages.
    bob.recv_msg_trash(&sent_vg_auth_required1).await;

    // Bob sends `vg-request-with-auth` messages.
    let sent_vg_request_with_auth2 = bob.pop_sent_msg().await;
    let sent_vg_request_with_auth1 = bob.pop_sent_msg().await;

    // Alice receives both `vg-request-with-auth` messages.
    alice.recv_msg_trash(&sent_vg_request_with_auth1).await;
    let sent_vg_member_added1 = alice.pop_sent_msg().await;
    let joined_chat_id1 = bob.recv_msg(&sent_vg_member_added1).await.chat_id;
    assert_eq!(joined_chat_id1, bob_chat1_id);

    alice.recv_msg_trash(&sent_vg_request_with_auth2).await;
    let sent_vg_member_added2 = alice.pop_sent_msg().await;
    let joined_chat_id2 = bob.recv_msg(&sent_vg_member_added2).await.chat_id;
    assert_eq!(joined_chat_id2, bob_chat2_id);

    Ok(())
}

/// Tests Bob scanning setup contact QR codes of Alice and Fiona
/// concurrently.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel_setup_contact() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    // Bob scans Alice's QR code,
    // but Alice is offline and takes a while to respond.
    let alice_qr = get_securejoin_qr(alice, None).await?;
    join_securejoin(bob, &alice_qr).await?;
    let sent_alice_vc_request = bob.pop_sent_msg().await;

    // Bob scans Fiona's QR code while SecureJoin
    // process with Alice is not finished.
    let fiona_qr = get_securejoin_qr(fiona, None).await?;
    join_securejoin(bob, &fiona_qr).await?;
    let sent_fiona_vc_request = bob.pop_sent_msg().await;

    fiona.recv_msg_trash(&sent_fiona_vc_request).await;
    let sent_fiona_vc_auth_required = fiona.pop_sent_msg().await;

    bob.recv_msg_trash(&sent_fiona_vc_auth_required).await;
    let sent_fiona_vc_request_with_auth = bob.pop_sent_msg().await;

    fiona.recv_msg_trash(&sent_fiona_vc_request_with_auth).await;
    let sent_fiona_vc_contact_confirm = fiona.pop_sent_msg().await;

    bob.recv_msg_trash(&sent_fiona_vc_contact_confirm).await;
    let bob_fiona_contact_id = bob.add_or_lookup_contact_id(fiona).await;
    let bob_fiona_contact = Contact::get_by_id(bob, bob_fiona_contact_id).await.unwrap();
    assert_eq!(bob_fiona_contact.is_verified(bob).await.unwrap(), true);

    // Alice gets online and previously started SecureJoin process finishes.
    alice.recv_msg_trash(&sent_alice_vc_request).await;
    let sent_alice_vc_auth_required = alice.pop_sent_msg().await;

    bob.recv_msg_trash(&sent_alice_vc_auth_required).await;
    let sent_alice_vc_request_with_auth = bob.pop_sent_msg().await;

    alice.recv_msg_trash(&sent_alice_vc_request_with_auth).await;
    let sent_alice_vc_contact_confirm = alice.pop_sent_msg().await;

    bob.recv_msg_trash(&sent_alice_vc_contact_confirm).await;
    let bob_alice_contact_id = bob.add_or_lookup_contact_id(alice).await;
    let bob_alice_contact = Contact::get_by_id(bob, bob_alice_contact_id).await.unwrap();
    assert_eq!(bob_alice_contact.is_verified(bob).await.unwrap(), true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_wrong_auth_token() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // Bob should already have Alice's key
    // so that he can directly send vc-request-with-auth
    tcm.send_recv(alice, bob, "hi").await;

    let alice_qr = get_securejoin_qr(alice, None).await?;
    println!("{}", &alice_qr);
    let invalid_alice_qr = alice_qr.replace("&s=", "&s=INVALIDAUTHTOKEN&someotherkey=");

    join_securejoin(bob, &invalid_alice_qr).await?;
    let sent = bob.pop_sent_msg().await;

    let msg = alice.parse_msg(&sent).await;
    assert_eq!(
        msg.get_header(HeaderDef::SecureJoin).unwrap(),
        "vc-request-with-auth"
    );

    alice.recv_msg_trash(&sent).await;

    let alice_bob_contact = alice.add_or_lookup_contact(bob).await;
    assert!(!alice_bob_contact.is_verified(alice).await?);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_avatar_in_securejoin() -> Result<()> {
    async fn exec_securejoin_group(
        tcm: &TestContextManager,
        scanner: &TestContext,
        scanned: &TestContext,
    ) {
        let chat_id = chat::create_group(scanned, "group").await.unwrap();
        let qr = get_securejoin_qr(scanned, Some(chat_id)).await.unwrap();
        tcm.exec_securejoin_qr(scanner, scanned, &qr).await;
    }
    async fn exec_securejoin_broadcast(
        tcm: &TestContextManager,
        scanner: &TestContext,
        scanned: &TestContext,
    ) {
        let chat_id = chat::create_broadcast(scanned, "group".to_string())
            .await
            .unwrap();
        let qr = get_securejoin_qr(scanned, Some(chat_id)).await.unwrap();
        tcm.exec_securejoin_qr(scanner, scanned, &qr).await;
    }

    for round in 0..6 {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;

        let file = alice.dir.path().join("avatar.png");
        tokio::fs::write(&file, AVATAR_64x64_BYTES).await?;
        alice
            .set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
            .await?;

        match round {
            0 => {
                tcm.execute_securejoin(alice, bob).await;
            }
            1 => {
                tcm.execute_securejoin(bob, alice).await;
            }
            2 => {
                exec_securejoin_group(&tcm, alice, bob).await;
            }
            3 => {
                exec_securejoin_group(&tcm, bob, alice).await;
            }
            4 => {
                exec_securejoin_broadcast(&tcm, alice, bob).await;
            }
            5 => {
                exec_securejoin_broadcast(&tcm, bob, alice).await;
            }
            _ => panic!(),
        }

        let alice_on_bob = bob.add_or_lookup_contact_no_key(alice).await;
        let avatar = alice_on_bob.get_profile_image(bob).await?.unwrap();
        assert_eq!(
            avatar.file_name().unwrap().to_str().unwrap(),
            AVATAR_64x64_DEDUPLICATED
        );
    }

    Ok(())
}

/// Tests that scanning a QR code week later
/// allows Bob to establish a contact with Alice,
/// but does not mark Bob as verified for Alice.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_expired_contact_auth_token() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // Alice creates a QR code.
    let qr = get_securejoin_qr(alice, None).await?;

    // One week passes, QR code expires.
    SystemTime::shift(Duration::from_secs(7 * 24 * 3600));

    // Bob scans the QR code.
    join_securejoin(bob, &qr).await?;

    // vc-request
    alice.recv_msg_trash(&bob.pop_sent_msg().await).await;

    // vc-auth-requried
    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;

    // vc-request-with-auth
    alice.recv_msg_trash(&bob.pop_sent_msg().await).await;

    // Bob should not be verified for Alice.
    let contact_bob = alice.add_or_lookup_contact_no_key(bob).await;
    assert_eq!(contact_bob.is_verified(alice).await.unwrap(), false);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_expired_group_auth_token() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat_id = chat::create_group(alice, "Group").await?;

    // Alice creates a group QR code.
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();

    // One week passes, QR code expires.
    SystemTime::shift(Duration::from_secs(7 * 24 * 3600));

    // Bob scans the QR code.
    join_securejoin(bob, &qr).await?;

    // vg-request
    alice.recv_msg_trash(&bob.pop_sent_msg().await).await;

    // vg-auth-requried
    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;

    // vg-request-with-auth
    alice.recv_msg_trash(&bob.pop_sent_msg().await).await;

    // vg-member-added
    let bob_member_added_msg = bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert!(bob_member_added_msg.is_info());
    assert_eq!(
        bob_member_added_msg.get_info_type(),
        SystemMessage::MemberAddedToGroup
    );

    // Bob should not be verified for Alice.
    let contact_bob = alice.add_or_lookup_contact_no_key(bob).await;
    assert_eq!(contact_bob.is_verified(alice).await.unwrap(), false);

    Ok(())
}

/// Tests that old token is considered expired
/// even if sync message just arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_expired_synced_auth_token() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;

    alice.set_config_bool(Config::SyncMsgs, true).await?;
    alice2.set_config_bool(Config::SyncMsgs, true).await?;

    // Alice creates a QR code on the second device.
    let qr = get_securejoin_qr(alice2, None).await?;

    alice2.send_sync_msg().await.unwrap();
    let sync_msg = alice2.pop_sent_sync_msg().await;

    // One week passes, QR code expires.
    SystemTime::shift(Duration::from_secs(7 * 24 * 3600));

    alice.recv_msg_trash(&sync_msg).await;

    // Bob scans the QR code.
    join_securejoin(bob, &qr).await?;

    // vc-request
    alice.recv_msg_trash(&bob.pop_sent_msg().await).await;

    // vc-auth-requried
    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;

    // vc-request-with-auth
    alice.recv_msg_trash(&bob.pop_sent_msg().await).await;

    // Bob should not be verified for Alice.
    let contact_bob = alice.add_or_lookup_contact_no_key(bob).await;
    assert_eq!(contact_bob.is_verified(alice).await.unwrap(), false);

    Ok(())
}

/// Tests that attempting to join already joined group does nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_rejoin_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat_id = chat::create_group(alice, "the chat").await?;

    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await?;
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    // Bob gets two progress events.
    for expected_progress in [400, 1000] {
        let EventType::SecurejoinJoinerProgress { progress, .. } = bob
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::SecurejoinJoinerProgress { .. }))
            .await
        else {
            unreachable!();
        };
        assert_eq!(progress, expected_progress);
    }

    // Bob scans the QR code again.
    join_securejoin(bob, &qr).await?;

    // Bob immediately receives progress 1000 event.
    let EventType::SecurejoinJoinerProgress { progress, .. } = bob
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::SecurejoinJoinerProgress { .. }))
        .await
    else {
        unreachable!();
    };
    assert_eq!(progress, 1000);

    // Bob does not send any more messages by scanning the QR code.
    assert!(bob.pop_sent_msg_opt(Duration::ZERO).await.is_none());

    Ok(())
}
