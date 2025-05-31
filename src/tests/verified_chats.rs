use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::chat::resend_msgs;
use crate::chat::{
    self, add_contact_to_chat, remove_contact_from_chat, send_msg, Chat, ProtectionStatus,
};
use crate::chatlist::Chatlist;
use crate::config::Config;
use crate::constants::{Chattype, DC_GCL_FOR_FORWARDING};
use crate::contact::{Contact, ContactId, Origin};
use crate::message::{Message, Viewtype};
use crate::mimefactory::MimeFactory;
use crate::mimeparser::SystemMessage;
use crate::receive_imf::receive_imf;
use crate::securejoin::{get_securejoin_qr, join_securejoin};
use crate::stock_str;
use crate::test_utils::{get_chat_msg, mark_as_verified, TestContext, TestContextManager};
use crate::tools::SystemTime;
use crate::{e2ee, message};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verified_oneonone_chat_broken_by_classical() {
    check_verified_oneonone_chat(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verified_oneonone_chat_broken_by_device_change() {
    check_verified_oneonone_chat(false).await;
}

async fn check_verified_oneonone_chat(broken_by_classical_email: bool) {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    tcm.execute_securejoin(&alice, &bob).await;

    assert_verified(&alice, &bob, ProtectionStatus::Protected).await;
    assert_verified(&bob, &alice, ProtectionStatus::Protected).await;

    if broken_by_classical_email {
        tcm.section("Bob uses a classical MUA to send a message to Alice");
        receive_imf(
            &alice,
            b"Subject: Re: Message from alice\r\n\
          From: <bob@example.net>\r\n\
          To: <alice@example.org>\r\n\
          Date: Mon, 12 Dec 3000 14:33:39 +0000\r\n\
          Message-ID: <abcd@example.net>\r\n\
          \r\n\
          Heyho!\r\n",
            false,
        )
        .await
        .unwrap()
        .unwrap();
        // Bob's contact is still verified, but the chat isn't marked as protected anymore
        let contact = alice.add_or_lookup_contact(&bob).await;
        assert_eq!(contact.is_verified(&alice).await.unwrap(), true);
        assert_verified(&alice, &bob, ProtectionStatus::ProtectionBroken).await;
    } else {
        tcm.section("Bob sets up another Delta Chat device");
        let bob2 = TestContext::new().await;
        bob2.set_name("bob2");
        bob2.configure_addr("bob@example.net").await;

        SystemTime::shift(std::time::Duration::from_secs(3600));
        tcm.send_recv(&bob2, &alice, "Using another device now")
            .await;
        let contact = alice.add_or_lookup_contact(&bob).await;
        assert_eq!(contact.is_verified(&alice).await.unwrap(), false);
        assert_verified(&alice, &bob, ProtectionStatus::ProtectionBroken).await;
    }

    tcm.section("Bob sends another message from DC");
    SystemTime::shift(std::time::Duration::from_secs(3600));
    tcm.send_recv(&bob, &alice, "Using DC again").await;

    // Bob's chat is marked as verified again
    assert_verified(&alice, &bob, ProtectionStatus::Protected).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_verified_oneonone_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;
    enable_verified_oneonone_chats(&[&alice, &bob, &fiona]).await;

    tcm.execute_securejoin(&alice, &bob).await;
    tcm.execute_securejoin(&bob, &fiona).await;
    assert_verified(&alice, &bob, ProtectionStatus::Protected).await;
    assert_verified(&bob, &alice, ProtectionStatus::Protected).await;
    assert_verified(&bob, &fiona, ProtectionStatus::Protected).await;
    assert_verified(&fiona, &bob, ProtectionStatus::Protected).await;

    let group_id = bob
        .create_group_with_members(
            ProtectionStatus::Protected,
            "Group with everyone",
            &[&alice, &fiona],
        )
        .await;
    assert_eq!(
        get_chat_msg(&bob, group_id, 0, 1).await.get_info_type(),
        SystemMessage::ChatProtectionEnabled
    );

    {
        let sent = bob.send_text(group_id, "Heyho").await;
        alice.recv_msg(&sent).await;

        let msg = fiona.recv_msg(&sent).await;
        assert_eq!(
            get_chat_msg(&fiona, msg.chat_id, 0, 2)
                .await
                .get_info_type(),
            SystemMessage::ChatProtectionEnabled
        );
    }

    // Alice and Fiona should now be verified because of gossip
    let alice_fiona_contact = alice.add_or_lookup_contact(&fiona).await;
    assert!(alice_fiona_contact.is_verified(&alice).await.unwrap(),);

    // Alice should have a hidden protected chat with Fiona
    {
        let chat = alice.get_chat(&fiona).await;
        assert!(chat.is_protected());

        let msg = get_chat_msg(&alice, chat.id, 0, 1).await;
        let expected_text = stock_str::chat_protection_enabled(&alice).await;
        assert_eq!(msg.text, expected_text);
    }

    // Fiona should have a hidden protected chat with Alice
    {
        let chat = fiona.get_chat(&alice).await;
        assert!(chat.is_protected());

        let msg0 = get_chat_msg(&fiona, chat.id, 0, 1).await;
        let expected_text = stock_str::chat_protection_enabled(&fiona).await;
        assert_eq!(msg0.text, expected_text);
    }

    tcm.section("Fiona reinstalls DC");
    drop(fiona);

    let fiona_new = tcm.unconfigured().await;
    enable_verified_oneonone_chats(&[&fiona_new]).await;
    fiona_new.configure_addr("fiona@example.net").await;
    e2ee::ensure_secret_key_exists(&fiona_new).await?;

    tcm.send_recv(&fiona_new, &alice, "I have a new device")
        .await;

    // The chat should be and stay unprotected
    {
        let chat = alice.get_chat(&fiona_new).await;
        assert!(!chat.is_protected());
        assert!(chat.is_protection_broken());

        let msg1 = get_chat_msg(&alice, chat.id, 0, 3).await;
        assert_eq!(msg1.get_info_type(), SystemMessage::ChatProtectionEnabled);

        let msg2 = get_chat_msg(&alice, chat.id, 1, 3).await;
        assert_eq!(msg2.get_info_type(), SystemMessage::ChatProtectionDisabled);

        let msg2 = get_chat_msg(&alice, chat.id, 2, 3).await;
        assert_eq!(msg2.text, "I have a new device");

        // After recreating the chat, it should still be unprotected
        chat.id.delete(&alice).await?;

        let chat = alice.create_chat(&fiona_new).await;
        assert!(!chat.is_protected());
        assert!(!chat.is_protection_broken());
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_missing_peerstate_reexecute_securejoin() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice_addr = alice.get_config(Config::Addr).await?.unwrap();
    let bob = &tcm.bob().await;
    enable_verified_oneonone_chats(&[alice, bob]).await;
    let chat_id = tcm.execute_securejoin(bob, alice).await;
    let chat = Chat::load_from_db(bob, chat_id).await?;
    assert!(chat.is_protected());
    bob.sql
        .execute("DELETE FROM acpeerstates WHERE addr=?", (&alice_addr,))
        .await?;
    let chat_id = tcm.execute_securejoin(bob, alice).await;
    let chat = Chat::load_from_db(bob, chat_id).await?;
    assert!(chat.is_protected());
    assert!(!chat.is_protection_broken());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_unverified_oneonone_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    // A chat with an unknown contact should be created unprotected
    let chat = alice.create_chat(&bob).await;
    assert!(!chat.is_protected());
    assert!(!chat.is_protection_broken());

    receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <1234-2@example.org>\n\
          \n\
          hello\n",
        false,
    )
    .await?;

    chat.id.delete(&alice).await.unwrap();
    // Now Bob is a known contact, new chats should still be created unprotected
    let chat = alice.create_chat(&bob).await;
    assert!(!chat.is_protected());
    assert!(!chat.is_protection_broken());

    tcm.send_recv(&bob, &alice, "hi").await;
    chat.id.delete(&alice).await.unwrap();
    // Now we have a public key, new chats should still be created unprotected
    let chat = alice.create_chat(&bob).await;
    assert!(!chat.is_protected());
    assert!(!chat.is_protection_broken());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_degrade_verified_oneonone_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    mark_as_verified(&alice, &bob).await;

    let alice_chat = alice.create_chat(&bob).await;
    assert!(alice_chat.is_protected());

    receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <1234-2@example.org>\n\
          \n\
          hello\n",
        false,
    )
    .await?;

    let contact_id = Contact::lookup_id_by_addr(&alice, "bob@example.net", Origin::Hidden)
        .await?
        .unwrap();

    let msg0 = get_chat_msg(&alice, alice_chat.id, 0, 3).await;
    let enabled = stock_str::chat_protection_enabled(&alice).await;
    assert_eq!(msg0.text, enabled);
    assert_eq!(msg0.param.get_cmd(), SystemMessage::ChatProtectionEnabled);

    let msg1 = get_chat_msg(&alice, alice_chat.id, 1, 3).await;
    let disabled = stock_str::chat_protection_disabled(&alice, contact_id).await;
    assert_eq!(msg1.text, disabled);
    assert_eq!(msg1.param.get_cmd(), SystemMessage::ChatProtectionDisabled);

    let msg2 = get_chat_msg(&alice, alice_chat.id, 2, 3).await;
    assert_eq!(msg2.text, "hello".to_string());
    assert!(!msg2.is_system_message());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verified_oneonone_chat_enable_disable() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    // Alice & Bob verify each other
    mark_as_verified(&alice, &bob).await;
    mark_as_verified(&bob, &alice).await;

    let chat = alice.create_chat(&bob).await;
    assert!(chat.is_protected());

    for alice_accepts_breakage in [true, false] {
        SystemTime::shift(std::time::Duration::from_secs(300));
        // Bob uses Thunderbird to send a message
        receive_imf(
            &alice,
            format!(
                "From: Bob <bob@example.net>\n\
              To: alice@example.org\n\
              Message-ID: <1234-2{alice_accepts_breakage}@example.org>\n\
              \n\
              Message from Thunderbird\n"
            )
            .as_bytes(),
            false,
        )
        .await?;

        let chat = alice.get_chat(&bob).await;
        assert!(!chat.is_protected());
        assert!(chat.is_protection_broken());

        if alice_accepts_breakage {
            tcm.section("Alice clicks 'Accept' on the input-bar-dialog");
            chat.id.accept(&alice).await?;
            let chat = alice.get_chat(&bob).await;
            assert!(!chat.is_protected());
            assert!(!chat.is_protection_broken());
        }

        // Bob sends a message from DC again
        tcm.send_recv(&bob, &alice, "Hello from DC").await;
        let chat = alice.get_chat(&bob).await;
        assert!(chat.is_protected());
        assert!(!chat.is_protection_broken());
    }

    alice
        .golden_test_chat(chat.id, "test_verified_oneonone_chat_enable_disable")
        .await;

    Ok(())
}

/// Messages with old timestamps are difficult for verified chats:
/// - They must not be sorted over a protection-changed info message.
///   That's what `test_old_message_2` tests
/// - If they change the protection, then they must not be sorted over existing other messages,
///   because then the protection-changed info message would also be above these existing messages.
///   That's what `test_old_message_3` tests.
///
/// `test_old_message_1` tests the case where both the old and the new message
/// change verification
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_old_message_1() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    mark_as_verified(&alice, &bob).await;

    let chat = alice.create_chat(&bob).await; // This creates a protection-changed info message
    assert!(chat.is_protected());

    // This creates protection-changed info message #2;
    // even though the date is old, info message and email must be sorted below the original info message.
    receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <1234-2-3@example.org>\n\
          Date: Sat, 07 Dec 2019 19:00:27 +0000\n\
          \n\
          Message from Thunderbird\n",
        true,
    )
    .await?;

    alice.golden_test_chat(chat.id, "test_old_message_1").await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_old_message_2() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    mark_as_verified(&alice, &bob).await;

    // This creates protection-changed info message #1:
    let chat = alice.create_chat(&bob).await;
    assert!(chat.is_protected());
    let protection_msg = alice.get_last_msg().await;
    assert_eq!(
        protection_msg.param.get_cmd(),
        SystemMessage::ChatProtectionEnabled
    );

    // This creates protection-changed info message #2 with `timestamp_sort` greater by 1.
    let first_email = receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <1234-2-3@example.org>\n\
          Date: Sun, 08 Dec 2019 19:00:27 +0000\n\
          \n\
          Somewhat old message\n",
        false,
    )
    .await?
    .unwrap();

    // Both messages will get the same timestamp, so this one will be sorted under the previous one
    // even though it has an older timestamp.
    let second_email = receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <2319-2-3@example.org>\n\
          Date: Sat, 07 Dec 2019 19:00:27 +0000\n\
          \n\
          Even older message, that must NOT be shown before the info message\n",
        true,
    )
    .await?
    .unwrap();

    assert_eq!(first_email.sort_timestamp, second_email.sort_timestamp);
    assert_eq!(
        first_email.sort_timestamp,
        protection_msg.timestamp_sort + 1
    );

    alice.golden_test_chat(chat.id, "test_old_message_2").await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_old_message_3() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    mark_as_verified(&alice, &bob).await;
    mark_as_verified(&bob, &alice).await;

    tcm.send_recv_accept(&bob, &alice, "Heyho from my verified device!")
        .await;

    // This unverified message must not be sorted over the message sent in the previous line:
    receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <1234-2-3@example.org>\n\
          Date: Sat, 07 Dec 2019 19:00:27 +0000\n\
          \n\
          Old, unverified message\n",
        true,
    )
    .await?;

    alice
        .golden_test_chat(alice.get_chat(&bob).await.id, "test_old_message_3")
        .await;

    Ok(())
}

/// Alice is offline for some time.
/// When she comes online, first her inbox is synced and then her sentbox.
/// This test tests that the messages are still in the right order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_old_message_4() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let msg_incoming = receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <1234-2-3@example.org>\n\
          Date: Sun, 08 Dec 2019 19:00:27 +0000\n\
          \n\
          Thanks, Alice!\n",
        true,
    )
    .await?
    .unwrap();

    let msg_sent = receive_imf(
        &alice,
        b"From: alice@example.org\n\
          To: Bob <bob@example.net>\n\
          Message-ID: <1234-2-4@example.org>\n\
          Date: Sat, 07 Dec 2019 19:00:27 +0000\n\
          \n\
          Happy birthday, Bob!\n",
        true,
    )
    .await?
    .unwrap();

    // The "Happy birthday" message should be shown first, and then the "Thanks" message
    assert!(msg_sent.sort_timestamp < msg_incoming.sort_timestamp);

    Ok(())
}

/// Alice is offline for some time.
/// When they come online, first their sentbox is synced and then their inbox.
/// This test tests that the messages are still in the right order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_old_message_5() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let msg_sent = receive_imf(
        &alice,
        b"From: alice@example.org\n\
          To: Bob <bob@example.net>\n\
          Message-ID: <1234-2-4@example.org>\n\
          Date: Sat, 07 Dec 2019 19:00:27 +0000\n\
          \n\
          Happy birthday, Bob!\n",
        true,
    )
    .await?
    .unwrap();

    let msg_incoming = receive_imf(
        &alice,
        b"From: Bob <bob@example.net>\n\
          To: alice@example.org\n\
          Message-ID: <1234-2-3@example.org>\n\
          Date: Sun, 07 Dec 2019 19:00:26 +0000\n\
          \n\
          Happy birthday to me, Alice!\n",
        false,
    )
    .await?
    .unwrap();

    assert!(msg_sent.sort_timestamp == msg_incoming.sort_timestamp);
    alice
        .golden_test_chat(msg_sent.chat_id, "test_old_message_5")
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_mdn_doesnt_disable_verification() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;
    bob.set_config_bool(Config::MdnsEnabled, true).await?;

    // Alice & Bob verify each other
    mark_as_verified(&alice, &bob).await;
    mark_as_verified(&bob, &alice).await;

    let rcvd = tcm.send_recv_accept(&alice, &bob, "Heyho").await;
    message::markseen_msgs(&bob, vec![rcvd.id]).await?;

    let mimefactory = MimeFactory::from_mdn(&bob, rcvd.from_id, rcvd.rfc724_mid, vec![]).await?;
    let rendered_msg = mimefactory.render(&bob).await?;
    let body = rendered_msg.message;
    receive_imf(&alice, body.as_bytes(), false).await.unwrap();

    assert_verified(&alice, &bob, ProtectionStatus::Protected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_outgoing_mua_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    mark_as_verified(&alice, &bob).await;
    mark_as_verified(&bob, &alice).await;

    tcm.send_recv_accept(&bob, &alice, "Heyho from DC").await;
    assert_verified(&alice, &bob, ProtectionStatus::Protected).await;

    let sent = receive_imf(
        &alice,
        b"From: alice@example.org\n\
          To: bob@example.net\n\
          \n\
          One classical MUA message",
        false,
    )
    .await?
    .unwrap();
    tcm.send_recv(&alice, &bob, "Sending with DC again").await;

    alice
        .golden_test_chat(sent.chat_id, "test_outgoing_mua_msg")
        .await;

    Ok(())
}

/// If Bob answers unencrypted from another address with a classical MUA,
/// the message is under some circumstances still assigned to the original
/// chat (see lookup_chat_by_reply()); this is meant to make aliases
/// work nicely.
/// However, if the original chat is verified, the unencrypted message
/// must NOT be assigned to it (it would be replaced by an error
/// message in the verified chat, so, this would just be a usability issue,
/// not a security issue).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_reply() -> Result<()> {
    for verified in [false, true] {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        enable_verified_oneonone_chats(&[&alice, &bob]).await;

        if verified {
            mark_as_verified(&alice, &bob).await;
            mark_as_verified(&bob, &alice).await;
        }

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

        if verified {
            assert_ne!(unencrypted_msg.chat_id, encrypted_msg.chat_id);
        } else {
            assert_eq!(unencrypted_msg.chat_id, encrypted_msg.chat_id);
        }
    }

    Ok(())
}

/// Regression test for the following bug:
///
/// - Scan your chat partner's QR Code
/// - They change devices
/// - They send you a message
/// - Without accepting the encryption downgrade, scan your chat partner's QR Code again
///
/// -> The re-verification fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_break_protection_then_verify_again() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    // Cave: Bob can't write a message to Alice here.
    // If he did, alice would increase his peerstate's last_seen timestamp.
    // Then, after Bob reinstalls DC, alice's `if message_time > last_seen*`
    // checks would return false (there are many checks of this form in peerstate.rs).
    // Therefore, during the securejoin, Alice wouldn't accept the new key
    // and reject the securejoin.

    mark_as_verified(&alice, &bob).await;
    mark_as_verified(&bob, &alice).await;

    alice.create_chat(&bob).await;
    assert_verified(&alice, &bob, ProtectionStatus::Protected).await;
    let chats = Chatlist::try_load(&alice, DC_GCL_FOR_FORWARDING, None, None).await?;
    assert_eq!(chats.len(), 1);

    tcm.section("Bob reinstalls DC");
    drop(bob);
    let bob_new = tcm.unconfigured().await;
    enable_verified_oneonone_chats(&[&bob_new]).await;
    bob_new.configure_addr("bob@example.net").await;
    e2ee::ensure_secret_key_exists(&bob_new).await?;

    tcm.send_recv(&bob_new, &alice, "I have a new device").await;

    let contact = alice.add_or_lookup_contact(&bob_new).await;
    assert_eq!(
        contact.is_verified(&alice).await.unwrap(),
        // Bob sent a message with a new key, so he most likely doesn't have
        // the old key anymore. This means that Alice's device should show
        // him as unverified:
        false
    );
    let chat = alice.get_chat(&bob_new).await;
    assert_eq!(chat.is_protected(), false);
    assert_eq!(chat.is_protection_broken(), true);
    let chats = Chatlist::try_load(&alice, DC_GCL_FOR_FORWARDING, None, None).await?;
    assert_eq!(chats.len(), 1);

    {
        let alice_bob_chat = alice.get_chat(&bob_new).await;
        assert!(!alice_bob_chat.can_send(&alice).await?);

        // Alice's UI should still be able to save a draft, which Alice started to type right when she got Bob's message:
        let mut msg = Message::new_text("Draftttt".to_string());
        alice_bob_chat.id.set_draft(&alice, Some(&mut msg)).await?;
        assert_eq!(
            alice_bob_chat.id.get_draft(&alice).await?.unwrap().text,
            "Draftttt"
        );
    }

    tcm.execute_securejoin(&alice, &bob_new).await;
    assert_verified(&alice, &bob_new, ProtectionStatus::Protected).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_message_from_old_dc_setup() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob_old = &tcm.unconfigured().await;
    enable_verified_oneonone_chats(&[alice, bob_old]).await;
    mark_as_verified(bob_old, alice).await;
    bob_old.configure_addr("bob@example.net").await;
    let chat = bob_old.create_chat(alice).await;
    let sent_old = bob_old
        .send_text(chat.id, "Soon i'll have a new device")
        .await;
    SystemTime::shift(std::time::Duration::from_secs(3600));

    tcm.section("Bob reinstalls DC");
    let bob = &tcm.bob().await;
    enable_verified_oneonone_chats(&[bob]).await;

    mark_as_verified(alice, bob).await;
    mark_as_verified(bob, alice).await;

    tcm.send_recv(bob, alice, "Now i have it!").await;
    assert_verified(alice, bob, ProtectionStatus::Protected).await;

    let msg = alice.recv_msg(&sent_old).await;
    assert!(!msg.get_showpadlock());
    let contact = alice.add_or_lookup_contact(bob).await;
    // The outdated Bob's Autocrypt header isn't applied, so the verification preserves.
    assert!(contact.is_verified(alice).await.unwrap());
    let chat = alice.get_chat(bob).await;
    assert!(chat.is_protected());
    assert_eq!(chat.is_protection_broken(), false);
    let protection_msg = alice.get_last_msg().await;
    assert_eq!(
        protection_msg.param.get_cmd(),
        SystemMessage::ChatProtectionEnabled
    );
    assert!(protection_msg.timestamp_sort >= msg.timestamp_rcvd);
    alice
        .golden_test_chat(msg.chat_id, "verified_chats_message_from_old_dc_setup")
        .await;
    Ok(())
}

/// Regression test for the following bug:
///
/// - Scan your chat partner's QR Code
/// - They change devices
/// - Scan their QR code again
///
/// -> The re-verification fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verify_then_verify_again() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice, &bob]).await;

    mark_as_verified(&alice, &bob).await;
    mark_as_verified(&bob, &alice).await;

    alice.create_chat(&bob).await;
    assert_verified(&alice, &bob, ProtectionStatus::Protected).await;

    tcm.section("Bob reinstalls DC");
    drop(bob);
    let bob_new = tcm.unconfigured().await;
    enable_verified_oneonone_chats(&[&bob_new]).await;
    bob_new.configure_addr("bob@example.net").await;
    e2ee::ensure_secret_key_exists(&bob_new).await?;

    tcm.execute_securejoin(&bob_new, &alice).await;
    assert_verified(&alice, &bob_new, ProtectionStatus::Protected).await;

    Ok(())
}

/// Regression test:
/// - Verify a contact
/// - The contact stops using DC and sends a message from a classical MUA instead
/// - Delete the 1:1 chat
/// - Create a 1:1 chat
/// - Check that the created chat is not marked as protected
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_oneonone_chat_with_former_verified_contact() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    enable_verified_oneonone_chats(&[&alice]).await;

    mark_as_verified(&alice, &bob).await;

    receive_imf(
        &alice,
        b"Subject: Message from bob\r\n\
          From: <bob@example.net>\r\n\
          To: <alice@example.org>\r\n\
          Date: Mon, 12 Dec 2022 14:33:39 +0000\r\n\
          Message-ID: <abcd@example.net>\r\n\
          \r\n\
          Heyho!\r\n",
        false,
    )
    .await
    .unwrap()
    .unwrap();

    alice.create_chat(&bob).await;

    assert_verified(&alice, &bob, ProtectionStatus::Unprotected).await;

    Ok(())
}

/// Tests that on the second device of a protected group creator the first message is
/// `SystemMessage::ChatProtectionEnabled` and the second one is the message populating the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_protected_grp_multidev() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice1 = &tcm.alice().await;

    let group_id = alice
        .create_group_with_members(ProtectionStatus::Protected, "Group", &[])
        .await;
    assert_eq!(
        get_chat_msg(alice, group_id, 0, 1).await.get_info_type(),
        SystemMessage::ChatProtectionEnabled
    );

    let sent = alice.send_text(group_id, "Hey").await;
    // This time shift is necessary to reproduce the bug when the original message is sorted over
    // the "protection enabled" message so that these messages have different timestamps.
    SystemTime::shift(std::time::Duration::from_secs(3600));
    let msg = alice1.recv_msg(&sent).await;
    let group1 = Chat::load_from_db(alice1, msg.chat_id).await?;
    assert_eq!(group1.get_type(), Chattype::Group);
    assert!(group1.is_protected());
    assert_eq!(
        chat::get_chat_contacts(alice1, group1.id).await?,
        vec![ContactId::SELF]
    );
    assert_eq!(
        get_chat_msg(alice1, group1.id, 0, 2).await.get_info_type(),
        SystemMessage::ChatProtectionEnabled
    );
    assert_eq!(get_chat_msg(alice1, group1.id, 1, 2).await.id, msg.id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verified_member_added_reordering() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;
    enable_verified_oneonone_chats(&[alice, bob, fiona]).await;

    let alice_fiona_contact_id = Contact::create(alice, "Fiona", "fiona@example.net").await?;

    // Bob and Fiona scan Alice's QR code.
    tcm.execute_securejoin(bob, alice).await;
    tcm.execute_securejoin(fiona, alice).await;

    // Alice creates protected group with Bob.
    let alice_chat_id = alice
        .create_group_with_members(ProtectionStatus::Protected, "Group", &[bob])
        .await;
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
    // "Member added" message, so unverified group is created.
    let fiona_received_message = fiona.recv_msg(&bob_sent_message).await;
    let fiona_chat = Chat::load_from_db(fiona, fiona_received_message.chat_id).await?;

    assert_eq!(fiona_received_message.get_text(), "Hi");
    assert_eq!(fiona_chat.is_protected(), false);

    // Fiona receives late "Member added" message
    // and the chat becomes protected.
    fiona.recv_msg(&alice_sent_member_added).await;
    let fiona_chat = Chat::load_from_db(fiona, fiona_received_message.chat_id).await?;
    assert_eq!(fiona_chat.is_protected(), true);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_unencrypted_name_if_encrypted() -> Result<()> {
    let mut tcm = TestContextManager::new();
    for verified in [false, true] {
        let alice = tcm.alice().await;
        let bob = tcm.bob().await;
        bob.set_config(Config::Displayname, Some("Bob Smith"))
            .await?;
        if verified {
            enable_verified_oneonone_chats(&[&bob]).await;
            mark_as_verified(&bob, &alice).await;
        } else {
            tcm.send_recv_accept(&alice, &bob, "hi").await;
        }

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
async fn test_verified_lost_member_added() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    tcm.execute_securejoin(bob, alice).await;
    tcm.execute_securejoin(fiona, alice).await;

    let alice_chat_id = alice
        .create_group_with_members(ProtectionStatus::Protected, "Group", &[bob])
        .await;
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

    Ok(())
}

/// Tests handling of resent .xdc arriving before "Member added"
/// in a verified group
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_verified_chat_editor_reordering() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    tcm.execute_securejoin(alice, bob).await;

    tcm.section("Alice creates a protected group with Bob");
    let alice_chat_id = alice
        .create_group_with_members(ProtectionStatus::Protected, "Group", &[bob])
        .await;
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

    // The message should not be replaced with
    // "The message was sent with non-verified encryption." text
    // just because it was reordered.
    assert_eq!(charlie_received_xdc.viewtype, Viewtype::Webxdc);

    tcm.section("Charlie receives member added message");
    charlie.recv_msg(&sent_member_added_msg).await;

    Ok(())
}

// ============== Helper Functions ==============

async fn assert_verified(this: &TestContext, other: &TestContext, protected: ProtectionStatus) {
    if protected != ProtectionStatus::ProtectionBroken {
        let contact = this.add_or_lookup_contact(other).await;
        assert_eq!(contact.is_verified(this).await.unwrap(), true);
    }

    let chat = this.get_chat(other).await;
    let (expect_protected, expect_broken) = match protected {
        ProtectionStatus::Unprotected => (false, false),
        ProtectionStatus::Protected => (true, false),
        ProtectionStatus::ProtectionBroken => (false, true),
    };
    assert_eq!(chat.is_protected(), expect_protected);
    assert_eq!(chat.is_protection_broken(), expect_broken);
}

async fn enable_verified_oneonone_chats(test_contexts: &[&TestContext]) {
    for t in test_contexts {
        t.set_config_bool(Config::VerifiedOneOnOneChats, true)
            .await
            .unwrap()
    }
}
