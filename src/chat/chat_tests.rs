use std::sync::Arc;

use super::*;
use crate::Event;
use crate::chatlist::get_archived_cnt;
use crate::constants::{DC_GCL_ARCHIVED_ONLY, DC_GCL_NO_SPECIALS};
use crate::ephemeral::Timer;
use crate::headerdef::HeaderDef;
use crate::imex::{ImexMode, has_backup, imex};
use crate::message::{MessengerMessage, delete_msgs};
use crate::mimeparser::{self, MimeMessage};
use crate::receive_imf::receive_imf;
use crate::securejoin::{get_securejoin_qr, join_securejoin};
use crate::test_utils::{
    AVATAR_64x64_BYTES, AVATAR_64x64_DEDUPLICATED, E2EE_INFO_MSGS, TestContext, TestContextManager,
    TimeShiftFalsePositiveNote, sync,
};
use crate::tools::SystemTime;
use pretty_assertions::assert_eq;
use std::time::Duration;
use strum::IntoEnumIterator;
use tokio::fs;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_info() {
    let t = TestContext::new().await;
    let chat = t.create_chat_with_contact("bob", "bob@example.com").await;
    let info = chat.get_info(&t).await.unwrap();

    // Ensure we can serialize this.
    println!("{}", serde_json::to_string_pretty(&info).unwrap());

    let expected = format!(
        r#"{{
  "id": 10,
  "type": 100,
  "name": "bob",
  "archived": false,
  "param": "",
  "is_sending_locations": false,
  "color": 29381,
  "profile_image": {},
  "draft": "",
  "is_muted": false,
  "ephemeral_timer": "Disabled"
}}"#,
        // We need to do it like this so that the test passes on Windows:
        serde_json::to_string(
            t.get_blobdir()
                .join("4138c52e5bc1c576cda7dd44d088c07.png")
                .to_str()
                .unwrap()
        )
        .unwrap()
    );

    // Ensure we can deserialize this.
    serde_json::from_str::<ChatInfo>(&expected).unwrap();

    assert_eq!(serde_json::to_string_pretty(&info).unwrap(), expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_draft_no_draft() {
    let t = TestContext::new_alice().await;
    let chat = t.get_self_chat().await;
    let draft = chat.id.get_draft(&t).await.unwrap();
    assert!(draft.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_draft_special_chat_id() {
    let t = TestContext::new().await;
    let draft = DC_CHAT_ID_LAST_SPECIAL.get_draft(&t).await.unwrap();
    assert!(draft.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_draft_no_chat() {
    // This is a weird case, maybe this should be an error but we
    // do not get this info from the database currently.
    let t = TestContext::new_alice().await;
    let draft = ChatId::new(42).get_draft(&t).await.unwrap();
    assert!(draft.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_draft() {
    let t = TestContext::new_alice().await;
    let chat_id = &t.get_self_chat().await.id;
    let mut msg = Message::new_text("hello".to_string());

    chat_id.set_draft(&t, Some(&mut msg)).await.unwrap();
    let draft = chat_id.get_draft(&t).await.unwrap().unwrap();
    let msg_text = msg.get_text();
    let draft_text = draft.get_text();
    assert_eq!(msg_text, draft_text);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_draft() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group(&t, "abc").await?;

    let mut msg = Message::new_text("hi!".to_string());
    chat_id.set_draft(&t, Some(&mut msg)).await?;
    assert!(chat_id.get_draft(&t).await?.is_some());

    let mut msg = Message::new_text("another".to_string());
    chat_id.set_draft(&t, Some(&mut msg)).await?;
    assert!(chat_id.get_draft(&t).await?.is_some());

    chat_id.set_draft(&t, None).await?;
    assert!(chat_id.get_draft(&t).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forwarding_draft_failing() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = &t.get_self_chat().await.id;
    let mut msg = Message::new_text("hello".to_string());
    chat_id.set_draft(&t, Some(&mut msg)).await?;
    assert_eq!(msg.id, chat_id.get_draft(&t).await?.unwrap().id);

    let chat_id2 = create_group(&t, "foo").await?;
    assert!(forward_msgs(&t, &[msg.id], chat_id2).await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_draft_stable_ids() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = &t.get_self_chat().await.id;
    let mut msg = Message::new_text("hello".to_string());
    assert_eq!(msg.id, MsgId::new_unset());
    assert!(chat_id.get_draft_msg_id(&t).await?.is_none());

    chat_id.set_draft(&t, Some(&mut msg)).await?;
    let id_after_1st_set = msg.id;
    assert_ne!(id_after_1st_set, MsgId::new_unset());
    assert_eq!(
        id_after_1st_set,
        chat_id.get_draft_msg_id(&t).await?.unwrap()
    );
    assert_eq!(id_after_1st_set, chat_id.get_draft(&t).await?.unwrap().id);

    msg.set_text("hello2".to_string());
    chat_id.set_draft(&t, Some(&mut msg)).await?;
    let id_after_2nd_set = msg.id;

    assert_eq!(id_after_2nd_set, id_after_1st_set);
    assert_eq!(
        id_after_2nd_set,
        chat_id.get_draft_msg_id(&t).await?.unwrap()
    );
    let test = chat_id.get_draft(&t).await?.unwrap();
    assert_eq!(id_after_2nd_set, test.id);
    assert_eq!(id_after_2nd_set, msg.id);
    assert_eq!(test.text, "hello2".to_string());
    assert_eq!(test.state, MessageState::OutDraft);

    let id_after_send = send_msg(&t, *chat_id, &mut msg).await?;
    assert_eq!(id_after_send, id_after_1st_set);

    let test = Message::load_from_db(&t, id_after_send).await?;
    assert!(!test.hidden); // sent draft must no longer be hidden

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_only_one_draft_per_chat() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group(&t, "abc").await?;

    let msgs: Vec<message::Message> = (1..=1000)
        .map(|i| Message::new_text(i.to_string()))
        .collect();
    let mut tasks = Vec::new();
    for mut msg in msgs {
        let ctx = t.clone();
        let task = tokio::spawn(async move {
            let ctx = ctx;
            chat_id.set_draft(&ctx, Some(&mut msg)).await
        });
        tasks.push(task);
    }
    futures::future::join_all(tasks.into_iter()).await;

    assert!(chat_id.get_draft(&t).await?.is_some());

    chat_id.set_draft(&t, None).await?;
    assert!(chat_id.get_draft(&t).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_change_quotes_on_reused_message_object() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group(&t, "chat").await?;
    let quote1 =
        Message::load_from_db(&t, send_text_msg(&t, chat_id, "quote1".to_string()).await?).await?;
    let quote2 =
        Message::load_from_db(&t, send_text_msg(&t, chat_id, "quote2".to_string()).await?).await?;

    // save a draft
    let mut draft = Message::new_text("draft text".to_string());
    chat_id.set_draft(&t, Some(&mut draft)).await?;

    let test = Message::load_from_db(&t, draft.id).await?;
    assert_eq!(test.text, "draft text".to_string());
    assert!(test.quoted_text().is_none());
    assert!(test.quoted_message(&t).await?.is_none());

    // add quote to same message object
    draft.set_quote(&t, Some(&quote1)).await?;
    chat_id.set_draft(&t, Some(&mut draft)).await?;

    let test = Message::load_from_db(&t, draft.id).await?;
    assert_eq!(test.text, "draft text".to_string());
    assert_eq!(test.quoted_text(), Some("quote1".to_string()));
    assert_eq!(test.quoted_message(&t).await?.unwrap().id, quote1.id);

    // change quote on same message object
    draft.set_text("another draft text".to_string());
    draft.set_quote(&t, Some(&quote2)).await?;
    chat_id.set_draft(&t, Some(&mut draft)).await?;

    let test = Message::load_from_db(&t, draft.id).await?;
    assert_eq!(test.text, "another draft text".to_string());
    assert_eq!(test.quoted_text(), Some("quote2".to_string()));
    assert_eq!(test.quoted_message(&t).await?.unwrap().id, quote2.id);

    // remove quote on same message object
    draft.set_quote(&t, None).await?;
    chat_id.set_draft(&t, Some(&mut draft)).await?;

    let test = Message::load_from_db(&t, draft.id).await?;
    assert_eq!(test.text, "another draft text".to_string());
    assert!(test.quoted_text().is_none());
    assert!(test.quoted_message(&t).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_quote_replies() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let grp_chat_id = create_group(&alice, "grp").await?;
    let grp_msg_id = send_text_msg(&alice, grp_chat_id, "bar".to_string()).await?;
    let grp_msg = Message::load_from_db(&alice, grp_msg_id).await?;

    let one2one_chat_id = alice.create_chat(&bob).await.id;
    let one2one_msg_id = send_text_msg(&alice, one2one_chat_id, "foo".to_string()).await?;
    let one2one_msg = Message::load_from_db(&alice, one2one_msg_id).await?;

    // quoting messages in same chat is okay
    let mut msg = Message::new_text("baz".to_string());
    msg.set_quote(&alice, Some(&grp_msg)).await?;
    let result = send_msg(&alice, grp_chat_id, &mut msg).await;
    assert!(result.is_ok());

    let mut msg = Message::new_text("baz".to_string());
    msg.set_quote(&alice, Some(&one2one_msg)).await?;
    let result = send_msg(&alice, one2one_chat_id, &mut msg).await;
    assert!(result.is_ok());
    let one2one_quote_reply_msg_id = result.unwrap();

    // quoting messages from groups to one-to-ones is okay ("reply privately")
    let mut msg = Message::new_text("baz".to_string());
    msg.set_quote(&alice, Some(&grp_msg)).await?;
    let result = send_msg(&alice, one2one_chat_id, &mut msg).await;
    assert!(result.is_ok());

    // quoting messages from one-to-one chats in groups is an error; usually this is also not allowed by UI at all ...
    let mut msg = Message::new_text("baz".to_string());
    msg.set_quote(&alice, Some(&one2one_msg)).await?;
    let result = send_msg(&alice, grp_chat_id, &mut msg).await;
    assert!(result.is_err());

    // ... but forwarding messages with quotes is allowed
    let result = forward_msgs(&alice, &[one2one_quote_reply_msg_id], grp_chat_id).await;
    assert!(result.is_ok());

    // ... and bots are not restricted
    alice.set_config(Config::Bot, Some("1")).await?;
    let result = send_msg(&alice, grp_chat_id, &mut msg).await;
    assert!(result.is_ok());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_contact_to_chat_ex_add_self() {
    // Adding self to a contact should succeed, even though it's pointless.
    let t = TestContext::new_alice().await;
    let chat_id = create_group(&t, "foo").await.unwrap();
    let added = add_contact_to_chat_ex(&t, Nosync, chat_id, ContactId::SELF, false)
        .await
        .unwrap();
    assert_eq!(added, false);
}

/// Test adding and removing members in a group chat.
///
/// Make sure messages sent outside contain authname
/// and displayed messages contain locally set name.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_member_add_remove() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    // Create contact for Bob on the Alice side with name "robert".
    let alice_bob_contact_id = alice.add_or_lookup_contact_id(&bob).await;
    alice_bob_contact_id.set_name(&alice, "robert").await?;

    // Set Bob authname to "Bob" and send it to Alice.
    bob.set_config(Config::Displayname, Some("Bob")).await?;
    tcm.send_recv(&bob, &alice, "Hello!").await;

    // Check that Alice has Bob's name set to "robert" and authname set to "Bob".
    {
        let alice_bob_contact = Contact::get_by_id(&alice, alice_bob_contact_id).await?;
        assert_eq!(alice_bob_contact.get_name(), "robert");

        // This is the name that will be sent outside.
        assert_eq!(alice_bob_contact.get_authname(), "Bob");

        assert_eq!(alice_bob_contact.get_display_name(), "robert");
    }

    tcm.section("Create and promote a group.");
    let alice_chat_id = create_group(&alice, "Group chat").await?;
    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(&fiona).await;
    add_contact_to_chat(&alice, alice_chat_id, alice_fiona_contact_id).await?;
    let sent = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let fiona_chat_id = fiona.recv_msg(&sent).await.chat_id;

    tcm.section("Alice adds Bob to the chat.");
    add_contact_to_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    let sent = alice.pop_sent_msg().await;
    fiona.recv_msg(&sent).await;

    // Locally set name "robert" should not leak.
    assert!(!sent.payload.contains("robert"));
    assert_eq!(
        sent.load_from_db().await.get_text(),
        "You added member robert."
    );
    let fiona_contact_ids = get_chat_contacts(&fiona, fiona_chat_id).await?;
    assert_eq!(fiona_contact_ids.len(), 3);
    for contact_id in fiona_contact_ids {
        let contact = Contact::get_by_id(&fiona, contact_id).await?;
        assert_ne!(contact.get_name(), "robert");
        assert!(contact.is_key_contact());
    }

    tcm.section("Alice removes Bob from the chat.");
    remove_contact_from_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    let sent = alice.pop_sent_msg().await;
    assert!(!sent.payload.contains("robert"));
    assert_eq!(
        sent.load_from_db().await.get_text(),
        "You removed member robert."
    );

    // Alice leaves the chat.
    remove_contact_from_chat(&alice, alice_chat_id, ContactId::SELF).await?;
    let sent = alice.pop_sent_msg().await;
    assert_eq!(
        sent.load_from_db().await.get_text(),
        stock_str::msg_group_left_local(&alice, ContactId::SELF).await
    );

    Ok(())
}

/// Test parallel removal of user from the chat and leaving the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel_member_remove() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await;
    let fiona = tcm.fiona().await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(&bob).await;
    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(&fiona).await;
    let alice_charlie_contact_id = alice.add_or_lookup_contact_id(&charlie).await;

    tcm.section("Alice creates and promotes a group");
    let alice_chat_id = create_group(&alice, "Group chat").await?;
    add_contact_to_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(&alice, alice_chat_id, alice_fiona_contact_id).await?;
    let alice_sent_msg = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let bob_received_msg = bob.recv_msg(&alice_sent_msg).await;

    let bob_chat_id = bob_received_msg.get_chat_id();
    bob_chat_id.accept(&bob).await?;

    tcm.section("Alice adds Charlie to the chat");
    add_contact_to_chat(&alice, alice_chat_id, alice_charlie_contact_id).await?;
    let alice_sent_add_msg = alice.pop_sent_msg().await;

    tcm.section("Bob leaves the chat");
    remove_contact_from_chat(&bob, bob_chat_id, ContactId::SELF).await?;
    bob.pop_sent_msg().await;

    tcm.section("Bob receives a message about Alice adding Charlie to the group");
    bob.recv_msg(&alice_sent_add_msg).await;

    SystemTime::shift(Duration::from_secs(3600));

    tcm.section("Alice sends a message to Bob because the message about leaving is lost");
    let alice_sent_msg = alice.send_text(alice_chat_id, "What a silence!").await;
    bob.recv_msg(&alice_sent_msg).await;

    bob.golden_test_chat(bob_chat_id, "chat_test_parallel_member_remove")
        .await;

    tcm.section("Alice removes Bob from the chat");
    remove_contact_from_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    let alice_sent_remove_msg = alice.pop_sent_msg().await;

    tcm.section("Bob receives a msg about Alice removing him from the group");
    let bob_received_remove_msg = bob.recv_msg(&alice_sent_remove_msg).await;

    // Test that remove message is rewritten.
    assert_eq!(
        bob_received_remove_msg.get_text(),
        "Member Me removed by alice@example.org."
    );

    Ok(())
}

/// Test that member removal is synchronized eventually even if the message is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_with_implicit_member_removed() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;
    let alice_bob_contact_id = alice.add_or_lookup_contact_id(&bob).await;
    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(&fiona).await;
    let bob_fiona_contact_id = bob.add_or_lookup_contact_id(&fiona).await;
    let alice_chat_id = create_group(&alice, "Group chat").await?;
    add_contact_to_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    let sent_msg = alice.send_text(alice_chat_id, "I created a group").await;
    let bob_received_msg = bob.recv_msg(&sent_msg).await;
    let bob_chat_id = bob_received_msg.get_chat_id();
    bob_chat_id.accept(&bob).await?;
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 2);

    add_contact_to_chat(&alice, alice_chat_id, alice_fiona_contact_id).await?;
    let sent_msg = alice.pop_sent_msg().await;
    bob.recv_msg(&sent_msg).await;

    // Bob removed Fiona, but the message is lost.
    remove_contact_from_chat(&bob, bob_chat_id, bob_fiona_contact_id).await?;
    bob.pop_sent_msg().await;

    // This doesn't add Fiona back because Bob just removed them.
    let sent_msg = alice.send_text(alice_chat_id, "Welcome, Fiona!").await;
    bob.recv_msg(&sent_msg).await;
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 2);

    // Even after some time Fiona is not added back.
    SystemTime::shift(Duration::from_secs(3600));
    let sent_msg = alice.send_text(alice_chat_id, "Welcome back, Fiona!").await;
    bob.recv_msg(&sent_msg).await;
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 2);

    // If Bob sends a message to Alice now, Fiona is removed.
    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 3);
    let sent_msg = bob
        .send_text(bob_chat_id, "I have removed Fiona some time ago.")
        .await;
    alice.recv_msg(&sent_msg).await;
    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_modify_chat_multi_device() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let a1 = tcm.alice().await;
    let a2 = tcm.alice().await;
    a1.set_config_bool(Config::BccSelf, true).await?;

    // create group and sync it to the second device
    let a1_chat_id = create_group(&a1, "foo").await?;
    let sent = a1.send_text(a1_chat_id, "ho!").await;
    let a1_msg = a1.get_last_msg().await;
    let a1_chat = Chat::load_from_db(&a1, a1_chat_id).await?;

    let a2_msg = a2.recv_msg(&sent).await;
    let a2_chat_id = a2_msg.chat_id;
    let a2_chat = Chat::load_from_db(&a2, a2_chat_id).await?;

    assert!(!a1_msg.is_system_message());
    assert!(!a2_msg.is_system_message());
    assert_eq!(a1_chat.grpid, a2_chat.grpid);
    assert_eq!(a1_chat.name, "foo");
    assert_eq!(a2_chat.name, "foo");
    assert_eq!(a1_chat.get_profile_image(&a1).await?, None);
    assert_eq!(a2_chat.get_profile_image(&a2).await?, None);
    assert_eq!(get_chat_contacts(&a1, a1_chat_id).await?.len(), 1);
    assert_eq!(get_chat_contacts(&a2, a2_chat_id).await?.len(), 1);

    // add a member to the group
    let bob = tcm.bob().await;
    let bob_id = a1.add_or_lookup_contact_id(&bob).await;
    add_contact_to_chat(&a1, a1_chat_id, bob_id).await?;
    let a1_msg = a1.get_last_msg().await;

    let a2_msg = a2.recv_msg(&a1.pop_sent_msg().await).await;

    assert!(a1_msg.is_system_message());
    assert!(a2_msg.is_system_message());
    assert_eq!(a1_msg.get_info_type(), SystemMessage::MemberAddedToGroup);
    assert_eq!(a2_msg.get_info_type(), SystemMessage::MemberAddedToGroup);
    assert_eq!(get_chat_contacts(&a1, a1_chat_id).await?.len(), 2);
    assert_eq!(get_chat_contacts(&a2, a2_chat_id).await?.len(), 2);
    assert_eq!(get_past_chat_contacts(&a1, a1_chat_id).await?.len(), 0);
    assert_eq!(get_past_chat_contacts(&a2, a2_chat_id).await?.len(), 0);

    // rename the group
    set_chat_name(&a1, a1_chat_id, "bar").await?;
    let a1_msg = a1.get_last_msg().await;

    let a2_msg = a2.recv_msg(&a1.pop_sent_msg().await).await;

    assert!(a1_msg.is_system_message());
    assert!(a2_msg.is_system_message());
    assert_eq!(a1_msg.get_info_type(), SystemMessage::GroupNameChanged);
    assert_eq!(a2_msg.get_info_type(), SystemMessage::GroupNameChanged);
    assert_eq!(
        a1_msg.get_info_contact_id(&a1).await?,
        Some(ContactId::SELF)
    );
    assert_eq!(
        a2_msg.get_info_contact_id(&a2).await?,
        Some(ContactId::SELF)
    );
    assert_eq!(Chat::load_from_db(&a1, a1_chat_id).await?.name, "bar");
    assert_eq!(Chat::load_from_db(&a2, a2_chat_id).await?.name, "bar");

    // remove member from group
    remove_contact_from_chat(&a1, a1_chat_id, bob_id).await?;
    let a1_msg = a1.get_last_msg().await;

    let a2_msg = a2.recv_msg(&a1.pop_sent_msg().await).await;

    assert!(a1_msg.is_system_message());
    assert!(a2_msg.is_system_message());
    assert_eq!(
        a1_msg.get_info_type(),
        SystemMessage::MemberRemovedFromGroup
    );
    assert_eq!(
        a2_msg.get_info_type(),
        SystemMessage::MemberRemovedFromGroup
    );
    assert_eq!(get_chat_contacts(&a1, a1_chat_id).await?.len(), 1);
    assert_eq!(get_chat_contacts(&a2, a2_chat_id).await?.len(), 1);
    assert_eq!(get_past_chat_contacts(&a1, a1_chat_id).await?.len(), 1);
    assert_eq!(get_past_chat_contacts(&a2, a2_chat_id).await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_modify_chat_disordered() -> Result<()> {
    let _n = TimeShiftFalsePositiveNote;

    let mut tcm = TestContextManager::new();

    // Alice creates a group with Bob, Charlie and Fiona and then removes Charlie and Fiona
    // (time shift is needed as otherwise smeared time from Alice looks to Bob like messages from the future which are all set to "now" then)
    let alice = tcm.alice().await;

    let bob = tcm.bob().await;
    let bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let charlie = tcm.charlie().await;
    let charlie_id = alice.add_or_lookup_contact_id(&charlie).await;
    let fiona = tcm.fiona().await;
    let fiona_id = alice.add_or_lookup_contact_id(&fiona).await;

    let alice_chat_id = create_group(&alice, "foo").await?;
    send_text_msg(&alice, alice_chat_id, "populate".to_string()).await?;

    add_contact_to_chat(&alice, alice_chat_id, bob_id).await?;
    let add1 = alice.pop_sent_msg().await;

    add_contact_to_chat(&alice, alice_chat_id, charlie_id).await?;
    let add2 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    add_contact_to_chat(&alice, alice_chat_id, fiona_id).await?;
    let add3 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 4);

    remove_contact_from_chat(&alice, alice_chat_id, charlie_id).await?;
    let remove1 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    remove_contact_from_chat(&alice, alice_chat_id, fiona_id).await?;
    let remove2 = alice.pop_sent_msg().await;

    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 2);

    // Bob receives the add and deletion messages out of order
    let bob = TestContext::new_bob().await;
    bob.recv_msg(&add1).await;
    let bob_chat_id = bob.recv_msg(&add3).await.chat_id;
    bob.recv_msg_trash(&add2).await; // No-op addition message is trashed.
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 4);

    bob.recv_msg(&remove2).await;
    bob.recv_msg(&remove1).await;
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 2);

    Ok(())
}

/// Tests that if member added message is completely lost,
/// member is eventually added.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lost_member_added() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;
    let alice_chat_id = alice.create_group_with_members("Group", &[bob]).await;
    let alice_sent = alice.send_text(alice_chat_id, "Hi!").await;
    let bob_chat_id = bob.recv_msg(&alice_sent).await.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);

    // Attempt to add member, but message is lost.
    let charlie_id = alice.add_or_lookup_contact_id(charlie).await;
    add_contact_to_chat(alice, alice_chat_id, charlie_id).await?;
    alice.pop_sent_msg().await;

    let alice_sent = alice.send_text(alice_chat_id, "Hi again!").await;
    bob.recv_msg(&alice_sent).await;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 3);

    Ok(())
}

/// Test that group updates are robust to lost messages and eventual out of order arrival.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_modify_chat_lost() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;

    let bob = tcm.bob().await;
    let bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let charlie = tcm.charlie().await;
    let charlie_id = alice.add_or_lookup_contact_id(&charlie).await;
    let fiona = tcm.fiona().await;
    let fiona_id = alice.add_or_lookup_contact_id(&fiona).await;

    let alice_chat_id = create_group(&alice, "foo").await?;
    add_contact_to_chat(&alice, alice_chat_id, bob_id).await?;
    add_contact_to_chat(&alice, alice_chat_id, charlie_id).await?;
    add_contact_to_chat(&alice, alice_chat_id, fiona_id).await?;

    send_text_msg(&alice, alice_chat_id, "populate".to_string()).await?;
    let add = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    remove_contact_from_chat(&alice, alice_chat_id, charlie_id).await?;
    let remove1 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    remove_contact_from_chat(&alice, alice_chat_id, fiona_id).await?;
    let remove2 = alice.pop_sent_msg().await;

    let bob = tcm.bob().await;

    bob.recv_msg(&add).await;
    let bob_chat_id = bob.get_last_msg().await.chat_id;
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 4);

    // First removal message is lost.
    // Nevertheless, two members are removed.
    bob.recv_msg(&remove2).await;
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 2);

    // Eventually, first removal message arrives.
    // This has no effect.
    bob.recv_msg(&remove1).await;
    assert_eq!(get_chat_contacts(&bob, bob_chat_id).await?.len(), 2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_leave_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    tcm.section("Alice creates group chat with Bob.");
    let alice_chat_id = create_group(&alice, "foo").await?;
    let bob_contact = alice.add_or_lookup_contact(&bob).await.id;
    add_contact_to_chat(&alice, alice_chat_id, bob_contact).await?;

    tcm.section("Alice sends first message to group.");
    let sent_msg = alice.send_text(alice_chat_id, "Hello!").await;
    let bob_msg = bob.recv_msg(&sent_msg).await;

    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 2);

    // Clear events so that we can later check
    // that the 'Group left' message didn't trigger IncomingMsg:
    alice.evtracker.clear_events();

    // Shift the time so that we can later check the 'Group left' message's timestamp:
    SystemTime::shift(Duration::from_secs(60));

    tcm.section("Bob leaves the group.");
    let bob_chat_id = bob_msg.chat_id;
    bob_chat_id.accept(&bob).await?;
    remove_contact_from_chat(&bob, bob_chat_id, ContactId::SELF).await?;

    let leave_msg = bob.pop_sent_msg().await;
    let rcvd_leave_msg = alice.recv_msg(&leave_msg).await;

    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 1);

    assert_eq!(rcvd_leave_msg.state, MessageState::InSeen);

    alice.emit_event(EventType::Test);
    alice
        .evtracker
        .get_matching(|ev| match ev {
            EventType::Test => true,
            EventType::IncomingMsg { .. } => panic!("'Group left' message should be silent"),
            EventType::MsgsNoticed(..) => {
                panic!("'Group left' message shouldn't clear notifications")
            }
            _ => false,
        })
        .await;

    // The 'Group left' message timestamp should be the same as the previous message in the chat
    // so that the chat is not popped up in the chatlist:
    assert_eq!(
        sent_msg.load_from_db().await.timestamp_sort,
        rcvd_leave_msg.timestamp_sort
    );

    Ok(())
}

/// Test that adding or removing contacts in 1:1 chat is not allowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_remove_contact_for_single() {
    let ctx = TestContext::new_alice().await;
    let bob = Contact::create(&ctx, "", "bob@f.br").await.unwrap();
    let chat_id = ChatId::create_for_contact(&ctx, bob).await.unwrap();
    let chat = Chat::load_from_db(&ctx, chat_id).await.unwrap();
    assert_eq!(chat.typ, Chattype::Single);
    assert_eq!(get_chat_contacts(&ctx, chat.id).await.unwrap().len(), 1);

    // adding or removing contacts from one-to-one-chats result in an error
    let claire = Contact::create(&ctx, "", "claire@foo.de").await.unwrap();
    let added = add_contact_to_chat_ex(&ctx, Nosync, chat.id, claire, false).await;
    assert!(added.is_err());
    assert_eq!(get_chat_contacts(&ctx, chat.id).await.unwrap().len(), 1);

    let removed = remove_contact_from_chat(&ctx, chat.id, claire).await;
    assert!(removed.is_err());
    assert_eq!(get_chat_contacts(&ctx, chat.id).await.unwrap().len(), 1);

    let removed = remove_contact_from_chat(&ctx, chat.id, ContactId::SELF).await;
    assert!(removed.is_err());
    assert_eq!(get_chat_contacts(&ctx, chat.id).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_self_talk() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat = &t.get_self_chat().await;
    assert!(!chat.id.is_special());
    assert!(chat.is_self_talk());
    assert!(chat.is_encrypted(&t).await?);
    assert!(chat.visibility == ChatVisibility::Normal);
    assert!(!chat.is_device_talk());
    assert!(chat.can_send(&t).await?);
    assert_eq!(chat.name, stock_str::saved_messages(&t).await);
    assert!(chat.get_profile_image(&t).await?.is_some());

    let msg_id = send_text_msg(&t, chat.id, "foo self".to_string()).await?;
    let msg = Message::load_from_db(&t, msg_id).await?;
    assert_eq!(msg.from_id, ContactId::SELF);
    assert_eq!(msg.to_id, ContactId::SELF);
    assert!(msg.get_showpadlock());

    let sent_msg = t.pop_sent_msg().await;

    let t2 = TestContext::new_alice().await;
    t2.recv_msg(&sent_msg).await;
    let chat = &t2.get_self_chat().await;
    let msg = t2.get_last_msg_in(chat.id).await;
    assert_eq!(msg.text, "foo self".to_string());
    assert_eq!(msg.from_id, ContactId::SELF);
    assert_eq!(msg.to_id, ContactId::SELF);
    assert!(msg.get_showpadlock());

    Ok(())
}

/// Tests that when BCC-self is disabled
/// and no messages are actually sent
/// in a self-chat, they have a padlock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_self_talk_no_bcc_padlock() -> Result<()> {
    let t = &TestContext::new_alice().await;
    t.set_config_bool(Config::BccSelf, false).await?;
    let chat = &t.get_self_chat().await;

    let msg_id = send_text_msg(t, chat.id, "Foobar".to_string()).await?;
    let msg = Message::load_from_db(t, msg_id).await?;
    assert!(msg.get_showpadlock());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_device_msg_unlabelled() {
    let t = TestContext::new().await;

    // add two device-messages
    let mut msg1 = Message::new_text("first message".to_string());
    let msg1_id = add_device_msg(&t, None, Some(&mut msg1)).await;
    assert!(msg1_id.is_ok());

    let mut msg2 = Message::new_text("second message".to_string());
    let msg2_id = add_device_msg(&t, None, Some(&mut msg2)).await;
    assert!(msg2_id.is_ok());
    assert_ne!(msg1_id.as_ref().unwrap(), msg2_id.as_ref().unwrap());

    // check added messages
    let msg1 = message::Message::load_from_db(&t, msg1_id.unwrap()).await;
    assert!(msg1.is_ok());
    let msg1 = msg1.unwrap();
    assert_eq!(msg1.text, "first message");
    assert_eq!(msg1.from_id, ContactId::DEVICE);
    assert_eq!(msg1.to_id, ContactId::SELF);
    assert!(!msg1.is_info());
    assert!(!msg1.is_setupmessage());

    let msg2 = message::Message::load_from_db(&t, msg2_id.unwrap()).await;
    assert!(msg2.is_ok());
    let msg2 = msg2.unwrap();
    assert_eq!(msg2.text, "second message");

    // check device chat
    assert_eq!(msg2.chat_id.get_msg_cnt(&t).await.unwrap(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_device_msg_labelled() -> Result<()> {
    let t = TestContext::new().await;

    // add two device-messages with the same label (second attempt is not added)
    let mut msg1 = Message::new_text("first message".to_string());
    let msg1_id = add_device_msg(&t, Some("any-label"), Some(&mut msg1)).await;
    assert!(msg1_id.is_ok());
    assert!(!msg1_id.as_ref().unwrap().is_unset());

    let mut msg2 = Message::new_text("second message".to_string());
    let msg2_id = add_device_msg(&t, Some("any-label"), Some(&mut msg2)).await;
    assert!(msg2_id.is_ok());
    assert!(msg2_id.as_ref().unwrap().is_unset());

    // check added message
    let msg1 = message::Message::load_from_db(&t, *msg1_id.as_ref().unwrap()).await?;
    assert_eq!(msg1_id.as_ref().unwrap(), &msg1.id);
    assert_eq!(msg1.text, "first message");
    assert_eq!(msg1.from_id, ContactId::DEVICE);
    assert_eq!(msg1.to_id, ContactId::SELF);
    assert!(!msg1.is_info());
    assert!(!msg1.is_setupmessage());

    // check device chat
    let chat_id = msg1.chat_id;

    assert_eq!(chat_id.get_msg_cnt(&t).await?, 1);
    assert!(!chat_id.is_special());
    let chat = Chat::load_from_db(&t, chat_id).await?;
    assert_eq!(chat.get_type(), Chattype::Single);
    assert!(chat.is_device_talk());
    assert!(!chat.is_self_talk());
    assert!(!chat.can_send(&t).await?);
    assert!(chat.why_cant_send(&t).await? == Some(CantSendReason::DeviceChat));

    assert_eq!(chat.name, stock_str::device_messages(&t).await);
    let device_msg_icon = chat.get_profile_image(&t).await?.unwrap();
    assert_eq!(
        device_msg_icon.metadata()?.len(),
        include_bytes!("../../assets/icon-device.png").len() as u64
    );

    // delete device message, make sure it is not added again
    message::delete_msgs(&t, &[*msg1_id.as_ref().unwrap()]).await?;
    let msg1 = message::Message::load_from_db(&t, *msg1_id.as_ref().unwrap()).await;
    assert!(msg1.is_err() || msg1.unwrap().chat_id.is_trash());
    let msg3_id = add_device_msg(&t, Some("any-label"), Some(&mut msg2)).await;
    assert!(msg3_id.is_ok());
    assert!(msg2_id.as_ref().unwrap().is_unset());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_device_msg_label_only() {
    let t = TestContext::new().await;
    let res = add_device_msg(&t, Some(""), None).await;
    assert!(res.is_err());
    let res = add_device_msg(&t, Some("some-label"), None).await;
    assert!(res.is_ok());

    let mut msg = Message::new_text("message text".to_string());

    let msg_id = add_device_msg(&t, Some("some-label"), Some(&mut msg)).await;
    assert!(msg_id.is_ok());
    assert!(msg_id.as_ref().unwrap().is_unset());

    let msg_id = add_device_msg(&t, Some("unused-label"), Some(&mut msg)).await;
    assert!(msg_id.is_ok());
    assert!(!msg_id.as_ref().unwrap().is_unset());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_was_device_msg_ever_added() {
    let t = TestContext::new().await;
    add_device_msg(&t, Some("some-label"), None).await.ok();
    assert!(was_device_msg_ever_added(&t, "some-label").await.unwrap());

    let mut msg = Message::new_text("message text".to_string());
    add_device_msg(&t, Some("another-label"), Some(&mut msg))
        .await
        .ok();
    assert!(
        was_device_msg_ever_added(&t, "another-label")
            .await
            .unwrap()
    );

    assert!(!was_device_msg_ever_added(&t, "unused-label").await.unwrap());

    assert!(was_device_msg_ever_added(&t, "").await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_device_chat() {
    let t = TestContext::new().await;

    let mut msg = Message::new_text("message text".to_string());
    add_device_msg(&t, Some("some-label"), Some(&mut msg))
        .await
        .ok();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 1);

    // after the device-chat and all messages are deleted, a re-adding should do nothing
    chats.get_chat_id(0).unwrap().delete(&t).await.ok();
    add_device_msg(&t, Some("some-label"), Some(&mut msg))
        .await
        .ok();
    assert_eq!(chatlist_len(&t, 0).await, 0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_device_chat_cannot_sent() {
    let t = TestContext::new_alice().await;
    t.update_device_chats().await.unwrap();
    let device_chat_id = ChatId::get_for_contact(&t, ContactId::DEVICE)
        .await
        .unwrap();

    let mut msg = Message::new_text("message text".to_string());
    assert!(send_msg(&t, device_chat_id, &mut msg).await.is_err());

    let msg_id = add_device_msg(&t, None, Some(&mut msg)).await.unwrap();
    assert!(forward_msgs(&t, &[msg_id], device_chat_id).await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_device_chat_is_encrypted() {
    let t = TestContext::new_alice().await;
    t.update_device_chats().await.unwrap();
    let device_chat_id = ChatId::get_for_contact(&t, ContactId::DEVICE)
        .await
        .unwrap();

    let device_chat = Chat::load_from_db(&t, device_chat_id).await.unwrap();
    assert!(device_chat.is_encrypted(&t).await.unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_and_reset_all_device_msgs() {
    let t = TestContext::new().await;
    let mut msg = Message::new_text("message text".to_string());
    let msg_id1 = add_device_msg(&t, Some("some-label"), Some(&mut msg))
        .await
        .unwrap();

    // adding a device message with the same label won't be executed again ...
    assert!(was_device_msg_ever_added(&t, "some-label").await.unwrap());
    let msg_id2 = add_device_msg(&t, Some("some-label"), Some(&mut msg))
        .await
        .unwrap();
    assert!(msg_id2.is_unset());

    // ... unless everything is deleted and reset - as needed eg. on device switch
    delete_and_reset_all_device_msgs(&t).await.unwrap();
    assert!(!was_device_msg_ever_added(&t, "some-label").await.unwrap());
    let msg_id3 = add_device_msg(&t, Some("some-label"), Some(&mut msg))
        .await
        .unwrap();
    assert_ne!(msg_id1, msg_id3);
}

async fn chatlist_len(ctx: &Context, listflags: usize) -> usize {
    Chatlist::try_load(ctx, listflags, None, None)
        .await
        .unwrap()
        .len()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_archive() {
    // create two chats
    let t = TestContext::new_alice().await;
    let mut msg = Message::new_text("foo".to_string());
    let msg_id = add_device_msg(&t, None, Some(&mut msg)).await.unwrap();
    let chat_id1 = message::Message::load_from_db(&t, msg_id)
        .await
        .unwrap()
        .chat_id;
    let chat_id2 = t.get_self_chat().await.id;
    assert!(!chat_id1.is_special());
    assert!(!chat_id2.is_special());

    assert_eq!(get_chat_cnt(&t).await.unwrap(), 2);
    assert_eq!(chatlist_len(&t, 0).await, 2);
    assert_eq!(chatlist_len(&t, DC_GCL_NO_SPECIALS).await, 2);
    assert_eq!(chatlist_len(&t, DC_GCL_ARCHIVED_ONLY).await, 0);
    assert_eq!(DC_GCL_ARCHIVED_ONLY, 0x01);
    assert_eq!(DC_GCL_NO_SPECIALS, 0x02);

    // archive first chat
    assert!(
        chat_id1
            .set_visibility(&t, ChatVisibility::Archived)
            .await
            .is_ok()
    );
    assert!(
        Chat::load_from_db(&t, chat_id1)
            .await
            .unwrap()
            .get_visibility()
            == ChatVisibility::Archived
    );
    assert!(
        Chat::load_from_db(&t, chat_id2)
            .await
            .unwrap()
            .get_visibility()
            == ChatVisibility::Normal
    );
    assert_eq!(get_chat_cnt(&t).await.unwrap(), 2);
    assert_eq!(chatlist_len(&t, 0).await, 2); // including DC_CHAT_ID_ARCHIVED_LINK now
    assert_eq!(chatlist_len(&t, DC_GCL_NO_SPECIALS).await, 1);
    assert_eq!(chatlist_len(&t, DC_GCL_ARCHIVED_ONLY).await, 1);

    // archive second chat
    assert!(
        chat_id2
            .set_visibility(&t, ChatVisibility::Archived)
            .await
            .is_ok()
    );
    assert!(
        Chat::load_from_db(&t, chat_id1)
            .await
            .unwrap()
            .get_visibility()
            == ChatVisibility::Archived
    );
    assert!(
        Chat::load_from_db(&t, chat_id2)
            .await
            .unwrap()
            .get_visibility()
            == ChatVisibility::Archived
    );
    assert_eq!(get_chat_cnt(&t).await.unwrap(), 2);
    assert_eq!(chatlist_len(&t, 0).await, 1); // only DC_CHAT_ID_ARCHIVED_LINK now
    assert_eq!(chatlist_len(&t, DC_GCL_NO_SPECIALS).await, 0);
    assert_eq!(chatlist_len(&t, DC_GCL_ARCHIVED_ONLY).await, 2);

    // archive already archived first chat, unarchive second chat two times
    assert!(
        chat_id1
            .set_visibility(&t, ChatVisibility::Archived)
            .await
            .is_ok()
    );
    assert!(
        chat_id2
            .set_visibility(&t, ChatVisibility::Normal)
            .await
            .is_ok()
    );
    assert!(
        chat_id2
            .set_visibility(&t, ChatVisibility::Normal)
            .await
            .is_ok()
    );
    assert!(
        Chat::load_from_db(&t, chat_id1)
            .await
            .unwrap()
            .get_visibility()
            == ChatVisibility::Archived
    );
    assert!(
        Chat::load_from_db(&t, chat_id2)
            .await
            .unwrap()
            .get_visibility()
            == ChatVisibility::Normal
    );
    assert_eq!(get_chat_cnt(&t).await.unwrap(), 2);
    assert_eq!(chatlist_len(&t, 0).await, 2);
    assert_eq!(chatlist_len(&t, DC_GCL_NO_SPECIALS).await, 1);
    assert_eq!(chatlist_len(&t, DC_GCL_ARCHIVED_ONLY).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_unarchive_if_muted() -> Result<()> {
    let t = TestContext::new_alice().await;

    async fn msg_from_bob(t: &TestContext, num: u32) -> Result<()> {
        receive_imf(
            t,
            format!(
                "From: bob@example.net\n\
                     To: alice@example.org\n\
                     Message-ID: <{num}@example.org>\n\
                     Chat-Version: 1.0\n\
                     Date: Sun, 22 Mar 2022 19:37:57 +0000\n\
                     \n\
                     hello\n"
            )
            .as_bytes(),
            false,
        )
        .await?;
        Ok(())
    }

    msg_from_bob(&t, 1).await?;
    let chat_id = t.get_last_msg().await.get_chat_id();
    chat_id.accept(&t).await?;
    chat_id.set_visibility(&t, ChatVisibility::Archived).await?;
    assert_eq!(get_archived_cnt(&t).await?, 1);

    // not muted chat is unarchived on receiving a message
    msg_from_bob(&t, 2).await?;
    assert_eq!(get_archived_cnt(&t).await?, 0);

    // forever muted chat is not unarchived on receiving a message
    chat_id.set_visibility(&t, ChatVisibility::Archived).await?;
    set_muted(&t, chat_id, MuteDuration::Forever).await?;
    msg_from_bob(&t, 3).await?;
    assert_eq!(get_archived_cnt(&t).await?, 1);

    // otherwise muted chat is not unarchived on receiving a message
    set_muted(
        &t,
        chat_id,
        MuteDuration::Until(
            SystemTime::now()
                .checked_add(Duration::from_secs(1000))
                .unwrap(),
        ),
    )
    .await?;
    msg_from_bob(&t, 4).await?;
    assert_eq!(get_archived_cnt(&t).await?, 1);

    // expired mute will unarchive the chat
    set_muted(
        &t,
        chat_id,
        MuteDuration::Until(
            SystemTime::now()
                .checked_sub(Duration::from_secs(1000))
                .unwrap(),
        ),
    )
    .await?;
    msg_from_bob(&t, 5).await?;
    assert_eq!(get_archived_cnt(&t).await?, 0);

    // no unarchiving on sending to muted chat or on adding info messages to muted chat
    chat_id.set_visibility(&t, ChatVisibility::Archived).await?;
    set_muted(&t, chat_id, MuteDuration::Forever).await?;
    send_text_msg(&t, chat_id, "out".to_string()).await?;
    add_info_msg(&t, chat_id, "info").await?;
    assert_eq!(get_archived_cnt(&t).await?, 1);

    // finally, unarchive on sending to not muted chat
    set_muted(&t, chat_id, MuteDuration::NotMuted).await?;
    send_text_msg(&t, chat_id, "out2".to_string()).await?;
    assert_eq!(get_archived_cnt(&t).await?, 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_marknoticed_all_chats() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("alice: create chats & promote them by sending a message");

    let alice_chat_normal = alice
        .create_group_with_members("Chat (normal)", &[alice, bob])
        .await;
    send_text_msg(alice, alice_chat_normal, "Hi".to_string()).await?;

    let alice_chat_muted = alice
        .create_group_with_members("Chat (muted)", &[alice, bob])
        .await;
    send_text_msg(alice, alice_chat_muted, "Hi".to_string()).await?;
    set_muted(&alice.ctx, alice_chat_muted, MuteDuration::Forever).await?;

    let alice_chat_archived_and_muted = alice
        .create_group_with_members("Chat (archived and muted)", &[alice, bob])
        .await;
    send_text_msg(alice, alice_chat_archived_and_muted, "Hi".to_string()).await?;
    set_muted(
        &alice.ctx,
        alice_chat_archived_and_muted,
        MuteDuration::Forever,
    )
    .await?;
    alice_chat_archived_and_muted
        .set_visibility(&alice.ctx, ChatVisibility::Archived)
        .await?;

    tcm.section("bob: receive messages, accept all chats and send a reply to each messsage");

    while let Some(sent_msg) = alice.pop_sent_msg_opt(Duration::default()).await {
        let bob_message = bob.recv_msg(&sent_msg).await;
        let bob_chat_id = bob_message.chat_id;
        bob_chat_id.accept(bob).await?;
        send_text_msg(bob, bob_chat_id, "reply".to_string()).await?;
    }

    tcm.section("alice: receive replies from bob");
    while let Some(sent_msg) = bob.pop_sent_msg_opt(Duration::default()).await {
        alice.recv_msg(&sent_msg).await;
    }
    // ensure chats have unread messages
    assert_eq!(alice_chat_normal.get_fresh_msg_cnt(alice).await?, 1);
    assert_eq!(alice_chat_muted.get_fresh_msg_cnt(alice).await?, 1);
    assert_eq!(
        alice_chat_archived_and_muted
            .get_fresh_msg_cnt(alice)
            .await?,
        1
    );

    tcm.section("alice: mark as read");
    alice.evtracker.clear_events();
    marknoticed_all_chats(alice).await?;
    tcm.section("alice: check that chats are no longer unread and that chatlist update events were received");
    assert_eq!(alice_chat_normal.get_fresh_msg_cnt(alice).await?, 0);
    assert_eq!(alice_chat_muted.get_fresh_msg_cnt(alice).await?, 0);
    assert_eq!(
        alice_chat_archived_and_muted
            .get_fresh_msg_cnt(alice)
            .await?,
        0
    );

    let emitted_events = alice.evtracker.take_events();
    for event in &[
        EventType::ChatlistItemChanged {
            chat_id: Some(alice_chat_normal),
        },
        EventType::ChatlistItemChanged {
            chat_id: Some(alice_chat_muted),
        },
        EventType::ChatlistItemChanged {
            chat_id: Some(alice_chat_archived_and_muted),
        },
        EventType::ChatlistItemChanged {
            chat_id: Some(DC_CHAT_ID_ARCHIVED_LINK),
        },
    ] {
        assert!(emitted_events.iter().any(|Event { typ, .. }| typ == event));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_archive_fresh_msgs() -> Result<()> {
    let t = TestContext::new_alice().await;

    async fn msg_from(t: &TestContext, name: &str, num: u32) -> Result<()> {
        receive_imf(
            t,
            format!(
                "From: {name}@example.net\n\
                     To: alice@example.org\n\
                     Message-ID: <{num}@example.org>\n\
                     Chat-Version: 1.0\n\
                     Date: Sun, 22 Mar 2022 19:37:57 +0000\n\
                     \n\
                     hello\n"
            )
            .as_bytes(),
            false,
        )
        .await?;
        Ok(())
    }

    // receive some messages in archived+muted chats
    msg_from(&t, "bob", 1).await?;
    let bob_chat_id = t.get_last_msg().await.get_chat_id();
    bob_chat_id.accept(&t).await?;
    set_muted(&t, bob_chat_id, MuteDuration::Forever).await?;
    bob_chat_id
        .set_visibility(&t, ChatVisibility::Archived)
        .await?;
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 0);

    msg_from(&t, "bob", 2).await?;
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 1);

    msg_from(&t, "bob", 3).await?;
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 1);

    msg_from(&t, "claire", 4).await?;
    let claire_chat_id = t.get_last_msg().await.get_chat_id();
    claire_chat_id.accept(&t).await?;
    set_muted(&t, claire_chat_id, MuteDuration::Forever).await?;
    claire_chat_id
        .set_visibility(&t, ChatVisibility::Archived)
        .await?;
    msg_from(&t, "claire", 5).await?;
    msg_from(&t, "claire", 6).await?;
    msg_from(&t, "claire", 7).await?;
    assert_eq!(bob_chat_id.get_fresh_msg_cnt(&t).await?, 2);
    assert_eq!(claire_chat_id.get_fresh_msg_cnt(&t).await?, 3);
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 2);

    // mark one of the archived+muted chats as noticed: check that the archive-link counter is changed as well
    t.evtracker.clear_events();
    marknoticed_chat(&t, claire_chat_id).await?;
    let ev = t
        .evtracker
        .get_matching(|ev| {
            matches!(
                ev,
                EventType::MsgsChanged {
                    chat_id: DC_CHAT_ID_ARCHIVED_LINK,
                    ..
                }
            )
        })
        .await;
    assert_eq!(
        ev,
        EventType::MsgsChanged {
            chat_id: DC_CHAT_ID_ARCHIVED_LINK,
            msg_id: MsgId::new(0),
        }
    );
    assert_eq!(bob_chat_id.get_fresh_msg_cnt(&t).await?, 2);
    assert_eq!(claire_chat_id.get_fresh_msg_cnt(&t).await?, 0);
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 1);

    // receive some more messages
    msg_from(&t, "claire", 8).await?;
    assert_eq!(bob_chat_id.get_fresh_msg_cnt(&t).await?, 2);
    assert_eq!(claire_chat_id.get_fresh_msg_cnt(&t).await?, 1);
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 2);
    assert_eq!(t.get_fresh_msgs().await?.len(), 0);

    msg_from(&t, "dave", 9).await?;
    let dave_chat_id = t.get_last_msg().await.get_chat_id();
    dave_chat_id.accept(&t).await?;
    assert_eq!(dave_chat_id.get_fresh_msg_cnt(&t).await?, 1);
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 2);
    assert_eq!(t.get_fresh_msgs().await?.len(), 1);

    // mark the archived-link as noticed: check that the real chats are noticed as well
    marknoticed_chat(&t, DC_CHAT_ID_ARCHIVED_LINK).await?;
    assert_eq!(bob_chat_id.get_fresh_msg_cnt(&t).await?, 0);
    assert_eq!(claire_chat_id.get_fresh_msg_cnt(&t).await?, 0);
    assert_eq!(dave_chat_id.get_fresh_msg_cnt(&t).await?, 1);
    assert_eq!(DC_CHAT_ID_ARCHIVED_LINK.get_fresh_msg_cnt(&t).await?, 0);
    assert_eq!(t.get_fresh_msgs().await?.len(), 1);

    Ok(())
}

async fn get_chats_from_chat_list(ctx: &Context, listflags: usize) -> Vec<ChatId> {
    let chatlist = Chatlist::try_load(ctx, listflags, None, None)
        .await
        .unwrap();
    let mut result = Vec::new();
    for chatlist_index in 0..chatlist.len() {
        result.push(chatlist.get_chat_id(chatlist_index).unwrap())
    }
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pinned() {
    let t = TestContext::new_alice().await;

    // create 3 chats, wait 1 second in between to get a reliable order (we order by time)
    let mut msg = Message::new_text("foo".to_string());
    let msg_id = add_device_msg(&t, None, Some(&mut msg)).await.unwrap();
    let chat_id1 = message::Message::load_from_db(&t, msg_id)
        .await
        .unwrap()
        .chat_id;
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let chat_id2 = t.get_self_chat().await.id;
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    let chat_id3 = create_group(&t, "foo").await.unwrap();

    let chatlist = get_chats_from_chat_list(&t, DC_GCL_NO_SPECIALS).await;
    assert_eq!(chatlist, vec![chat_id3, chat_id2, chat_id1]);

    // pin
    assert!(
        chat_id1
            .set_visibility(&t, ChatVisibility::Pinned)
            .await
            .is_ok()
    );
    assert_eq!(
        Chat::load_from_db(&t, chat_id1)
            .await
            .unwrap()
            .get_visibility(),
        ChatVisibility::Pinned
    );

    // check if chat order changed
    let chatlist = get_chats_from_chat_list(&t, DC_GCL_NO_SPECIALS).await;
    assert_eq!(chatlist, vec![chat_id1, chat_id3, chat_id2]);

    // unpin
    assert!(
        chat_id1
            .set_visibility(&t, ChatVisibility::Normal)
            .await
            .is_ok()
    );
    assert_eq!(
        Chat::load_from_db(&t, chat_id1)
            .await
            .unwrap()
            .get_visibility(),
        ChatVisibility::Normal
    );

    // check if chat order changed back
    let chatlist = get_chats_from_chat_list(&t, DC_GCL_NO_SPECIALS).await;
    assert_eq!(chatlist, vec![chat_id3, chat_id2, chat_id1]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pinned_after_new_msgs() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat_id = alice.create_chat(&bob).await.id;
    let bob_chat_id = bob.create_chat(&alice).await.id;

    assert!(
        alice_chat_id
            .set_visibility(&alice, ChatVisibility::Pinned)
            .await
            .is_ok()
    );
    assert_eq!(
        Chat::load_from_db(&alice, alice_chat_id)
            .await?
            .get_visibility(),
        ChatVisibility::Pinned,
    );

    send_text_msg(&alice, alice_chat_id, "hi!".into()).await?;
    assert_eq!(
        Chat::load_from_db(&alice, alice_chat_id)
            .await?
            .get_visibility(),
        ChatVisibility::Pinned,
    );

    let mut msg = Message::new_text("hi!".into());
    let sent_msg = bob.send_msg(bob_chat_id, &mut msg).await;
    let msg = alice.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, alice_chat_id);
    assert_eq!(
        Chat::load_from_db(&alice, alice_chat_id)
            .await?
            .get_visibility(),
        ChatVisibility::Pinned,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_chat_name() {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;

    let chat_id = create_group(alice, "foo").await.unwrap();
    assert_eq!(
        Chat::load_from_db(alice, chat_id).await.unwrap().get_name(),
        "foo"
    );

    set_chat_name(alice, chat_id, "bar").await.unwrap();
    assert_eq!(
        Chat::load_from_db(alice, chat_id).await.unwrap().get_name(),
        "bar"
    );

    let bob = &tcm.bob().await;
    let bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(alice, chat_id, bob_contact_id)
        .await
        .unwrap();

    let sent_msg = alice.send_text(chat_id, "Hi").await;
    let received_msg = bob.recv_msg(&sent_msg).await;
    let bob_chat_id = received_msg.chat_id;

    for new_name in [
        "Baz",
        "xyzzy",
        "Quux",
        "another name",
        "something different",
    ] {
        set_chat_name(alice, chat_id, new_name).await.unwrap();
        let sent_msg = alice.pop_sent_msg().await;
        let received_msg = bob.recv_msg(&sent_msg).await;
        assert_eq!(received_msg.chat_id, bob_chat_id);
        assert_eq!(
            Chat::load_from_db(bob, bob_chat_id)
                .await
                .unwrap()
                .get_name(),
            new_name
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_same_chat_twice() {
    let context = TestContext::new().await;
    let contact1 = Contact::create(&context.ctx, "bob", "bob@mail.de")
        .await
        .unwrap();
    assert_ne!(contact1, ContactId::UNDEFINED);

    let chat_id = ChatId::create_for_contact(&context.ctx, contact1)
        .await
        .unwrap();
    assert!(!chat_id.is_special(), "chat_id too small {chat_id}");
    let chat = Chat::load_from_db(&context.ctx, chat_id).await.unwrap();

    let chat2_id = ChatId::create_for_contact(&context.ctx, contact1)
        .await
        .unwrap();
    assert_eq!(chat2_id, chat_id);
    let chat2 = Chat::load_from_db(&context.ctx, chat2_id).await.unwrap();

    assert_eq!(chat2.name, chat.name);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_shall_attach_selfavatar() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat_id = create_group(alice, "foo").await?;
    assert!(!shall_attach_selfavatar(alice, chat_id).await?);

    let contact_id = alice.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(alice, chat_id, contact_id).await?;
    assert!(shall_attach_selfavatar(alice, chat_id).await?);

    chat_id.set_selfavatar_timestamp(alice, time()).await?;
    assert!(!shall_attach_selfavatar(alice, chat_id).await?);

    alice.set_config(Config::Selfavatar, None).await?; // setting to None also forces re-sending
    assert!(shall_attach_selfavatar(alice, chat_id).await?);
    Ok(())
}

/// Tests that profile data is attached to group leave messages. There are some pros and cons of
/// doing this, but at least we don't want to complicate the code with this special case.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_profile_data_on_group_leave() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let chat_id = create_group(t, "foo").await?;

    let contact_id = t.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(t, chat_id, contact_id).await?;

    send_text_msg(t, chat_id, "populate".to_string()).await?;
    t.pop_sent_msg().await;

    let file = t.dir.path().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await?;
    t.set_config(Config::Selfavatar, Some(file.to_str().unwrap()))
        .await?;
    assert!(shall_attach_selfavatar(t, chat_id).await?);

    remove_contact_from_chat(t, chat_id, ContactId::SELF).await?;
    let sent_msg = t.pop_sent_msg().await;
    let msg = bob.parse_msg(&sent_msg).await;
    assert!(msg.header_exists(HeaderDef::ChatUserAvatar));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_mute_duration() {
    let t = TestContext::new().await;
    let chat_id = create_group(&t, "foo").await.unwrap();
    // Initial
    assert_eq!(
        Chat::load_from_db(&t, chat_id).await.unwrap().is_muted(),
        false
    );
    // Forever
    set_muted(&t, chat_id, MuteDuration::Forever).await.unwrap();
    assert_eq!(
        Chat::load_from_db(&t, chat_id).await.unwrap().is_muted(),
        true
    );
    // unMute
    set_muted(&t, chat_id, MuteDuration::NotMuted)
        .await
        .unwrap();
    assert_eq!(
        Chat::load_from_db(&t, chat_id).await.unwrap().is_muted(),
        false
    );
    // Timed in the future
    set_muted(
        &t,
        chat_id,
        MuteDuration::Until(SystemTime::now() + Duration::from_secs(3600)),
    )
    .await
    .unwrap();
    assert_eq!(
        Chat::load_from_db(&t, chat_id).await.unwrap().is_muted(),
        true
    );
    // Time in the past
    set_muted(
        &t,
        chat_id,
        MuteDuration::Until(SystemTime::now() - Duration::from_secs(3600)),
    )
    .await
    .unwrap();
    assert_eq!(
        Chat::load_from_db(&t, chat_id).await.unwrap().is_muted(),
        false
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_info_msg() -> Result<()> {
    let t = TestContext::new().await;
    let chat_id = create_group(&t, "foo").await?;
    add_info_msg(&t, chat_id, "foo info").await?;

    let msg = t.get_last_msg_in(chat_id).await;
    assert_eq!(msg.get_chat_id(), chat_id);
    assert_eq!(msg.get_viewtype(), Viewtype::Text);
    assert_eq!(msg.get_text(), "foo info");
    assert!(msg.is_info());
    assert_eq!(msg.get_info_type(), SystemMessage::Unknown);
    assert!(msg.parent(&t).await?.is_none());
    assert!(msg.quoted_message(&t).await?.is_none());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_info_msg_with_cmd() -> Result<()> {
    let t = TestContext::new().await;
    let chat_id = create_group(&t, "foo").await?;
    let msg_id = add_info_msg_with_cmd(
        &t,
        chat_id,
        "foo bar info",
        SystemMessage::EphemeralTimerChanged,
        None,
        time(),
        None,
        None,
        None,
    )
    .await?;

    let msg = Message::load_from_db(&t, msg_id).await?;
    assert_eq!(msg.get_chat_id(), chat_id);
    assert_eq!(msg.get_viewtype(), Viewtype::Text);
    assert_eq!(msg.get_text(), "foo bar info");
    assert!(msg.is_info());
    assert_eq!(msg.get_info_type(), SystemMessage::EphemeralTimerChanged);
    assert!(msg.parent(&t).await?.is_none());
    assert!(msg.quoted_message(&t).await?.is_none());

    let msg2 = t.get_last_msg_in(chat_id).await;
    assert_eq!(msg.get_id(), msg2.get_id());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lookup_by_contact_id() {
    let ctx = TestContext::new_alice().await;

    // create contact, then unblocked chat
    let contact_id = Contact::create(&ctx, "", "bob@foo.de").await.unwrap();
    assert_ne!(contact_id, ContactId::UNDEFINED);
    let found = ChatId::lookup_by_contact(&ctx, contact_id).await.unwrap();
    assert!(found.is_none());

    let chat_id = ChatId::create_for_contact(&ctx, contact_id).await.unwrap();
    let chat2 = ChatIdBlocked::lookup_by_contact(&ctx, contact_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(chat_id, chat2.id);
    assert_eq!(chat2.blocked, Blocked::Not);

    // create contact, then blocked chat
    let contact_id = Contact::create(&ctx, "", "claire@foo.de").await.unwrap();
    let chat_id = ChatIdBlocked::get_for_contact(&ctx, contact_id, Blocked::Yes)
        .await
        .unwrap()
        .id;
    let chat2 = ChatIdBlocked::lookup_by_contact(&ctx, contact_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(chat_id, chat2.id);
    assert_eq!(chat2.blocked, Blocked::Yes);

    // test nonexistent contact
    let found = ChatId::lookup_by_contact(&ctx, ContactId::new(1234))
        .await
        .unwrap();
    assert!(found.is_none());

    let found = ChatIdBlocked::lookup_by_contact(&ctx, ContactId::new(1234))
        .await
        .unwrap();
    assert!(found.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_lookup_self_by_contact_id() {
    let ctx = TestContext::new_alice().await;

    let chat = ChatId::lookup_by_contact(&ctx, ContactId::SELF)
        .await
        .unwrap();
    assert!(chat.is_none());

    ctx.update_device_chats().await.unwrap();
    let chat = ChatIdBlocked::lookup_by_contact(&ctx, ContactId::SELF)
        .await
        .unwrap()
        .unwrap();
    assert!(!chat.id.is_special());
    assert!(chat.id.is_self_talk(&ctx).await.unwrap());
    assert_eq!(chat.blocked, Blocked::Not);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_marknoticed_chat() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat = t.create_chat_with_contact("bob", "bob@example.org").await;

    receive_imf(
        &t,
        b"From: bob@example.org\n\
                 To: alice@example.org\n\
                 Message-ID: <1@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Fri, 23 Apr 2021 10:00:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await?;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats.get_chat_id(0)?, chat.id);
    assert_eq!(chat.id.get_fresh_msg_cnt(&t).await?, 1);
    assert_eq!(t.get_fresh_msgs().await?.len(), 1);

    let msgs = get_chat_msgs(&t, chat.id).await?;
    assert_eq!(msgs.len(), 1);
    let msg_id = match msgs.first().unwrap() {
        ChatItem::Message { msg_id } => *msg_id,
        _ => MsgId::new_unset(),
    };
    let msg = message::Message::load_from_db(&t, msg_id).await?;
    assert_eq!(msg.state, MessageState::InFresh);

    marknoticed_chat(&t, chat.id).await?;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let msg = message::Message::load_from_db(&t, msg_id).await?;
    assert_eq!(msg.state, MessageState::InNoticed);
    assert_eq!(chat.id.get_fresh_msg_cnt(&t).await?, 0);
    assert_eq!(t.get_fresh_msgs().await?.len(), 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_contact_request_fresh_messages() -> Result<()> {
    let t = TestContext::new_alice().await;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chats.len(), 0);

    receive_imf(
        &t,
        b"From: bob@example.org\n\
                 To: alice@example.org\n\
                 Message-ID: <1@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 22 Mar 2021 19:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await?;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0).unwrap();
    assert!(
        Chat::load_from_db(&t, chat_id)
            .await
            .unwrap()
            .is_contact_request()
    );
    assert_eq!(chat_id.get_msg_cnt(&t).await?, 1);
    assert_eq!(chat_id.get_fresh_msg_cnt(&t).await?, 1);
    let msgs = get_chat_msgs(&t, chat_id).await?;
    assert_eq!(msgs.len(), 1);
    let msg_id = match msgs.first().unwrap() {
        ChatItem::Message { msg_id } => *msg_id,
        _ => MsgId::new_unset(),
    };
    let msg = message::Message::load_from_db(&t, msg_id).await?;
    assert_eq!(msg.state, MessageState::InFresh);

    // Contact requests are excluded from global badge.
    assert_eq!(t.get_fresh_msgs().await?.len(), 0);

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let msg = message::Message::load_from_db(&t, msg_id).await?;
    assert_eq!(msg.state, MessageState::InFresh);
    assert_eq!(t.get_fresh_msgs().await?.len(), 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_contact_request_archive() -> Result<()> {
    let t = TestContext::new_alice().await;

    receive_imf(
        &t,
        b"From: bob@example.org\n\
                 To: alice@example.org\n\
                 Message-ID: <2@example.org>\n\
                 Chat-Version: 1.0\n\
                 Date: Sun, 22 Mar 2021 19:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await?;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0)?;
    assert!(Chat::load_from_db(&t, chat_id).await?.is_contact_request());
    assert_eq!(get_archived_cnt(&t).await?, 0);

    // archive request without accepting or blocking
    chat_id.set_visibility(&t, ChatVisibility::Archived).await?;

    let chats = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0)?;
    assert!(chat_id.is_archived_link());
    assert_eq!(get_archived_cnt(&t).await?, 1);

    let chats = Chatlist::try_load(&t, DC_GCL_ARCHIVED_ONLY, None, None).await?;
    assert_eq!(chats.len(), 1);
    let chat_id = chats.get_chat_id(0)?;
    assert!(Chat::load_from_db(&t, chat_id).await?.is_contact_request());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_classic_email_chat() -> Result<()> {
    let alice = TestContext::new_alice().await;

    // Alice receives a classic (non-chat) message from Bob.
    receive_imf(
        &alice,
        b"From: bob@example.org\n\
                 To: alice@example.org\n\
                 Message-ID: <1@example.org>\n\
                 Date: Sun, 22 Mar 2021 19:37:57 +0000\n\
                 \n\
                 hello\n",
        false,
    )
    .await?;

    let msg = alice.get_last_msg().await;
    let chat_id = msg.chat_id;
    assert_eq!(chat_id.get_fresh_msg_cnt(&alice).await?, 1);

    let msgs = get_chat_msgs(&alice, chat_id).await?;
    assert_eq!(msgs.len(), 1);

    // Alice disables receiving classic emails.
    alice
        .set_config(Config::ShowEmails, Some("0"))
        .await
        .unwrap();

    // Already received classic email should still be in the chat.
    assert_eq!(chat_id.get_fresh_msg_cnt(&alice).await?, 1);

    let msgs = get_chat_msgs(&alice, chat_id).await?;
    assert_eq!(msgs.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_get_color() -> Result<()> {
    let t = TestContext::new().await;
    let chat_id = create_group_unencrypted(&t, "a chat").await?;
    let color1 = Chat::load_from_db(&t, chat_id).await?.get_color(&t).await?;
    assert_eq!(color1, 0x6239dc);

    // upper-/lowercase makes a difference for the colors, these are different groups
    // (in contrast to email addresses, where upper-/lowercase is ignored in practise)
    let t = TestContext::new().await;
    let chat_id = create_group_unencrypted(&t, "A CHAT").await?;
    let color2 = Chat::load_from_db(&t, chat_id).await?.get_color(&t).await?;
    assert_ne!(color2, color1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_get_color_encrypted() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.alice().await;
    let chat_id = create_group(t, "a chat").await?;
    let color1 = Chat::load_from_db(t, chat_id).await?.get_color(t).await?;
    set_chat_name(t, chat_id, "A CHAT").await?;
    let color2 = Chat::load_from_db(t, chat_id).await?.get_color(t).await?;
    assert_eq!(color2, color1);
    Ok(())
}

async fn test_sticker(
    filename: &str,
    bytes: &[u8],
    res_viewtype: Viewtype,
    w: i32,
    h: i32,
) -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    let file = alice.get_blobdir().join(filename);
    tokio::fs::write(&file, bytes).await?;

    let mut msg = Message::new(Viewtype::Sticker);
    msg.set_file_and_deduplicate(&alice, &file, Some(filename), None)?;

    let sent_msg = alice.send_msg(alice_chat.id, &mut msg).await;

    let msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, bob_chat.id);
    assert_eq!(msg.get_viewtype(), res_viewtype);
    assert_eq!(msg.get_filename().unwrap(), filename);
    assert_eq!(msg.get_width(), w);
    assert_eq!(msg.get_height(), h);
    assert!(msg.get_filebytes(&bob).await?.unwrap() > 250);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sticker_png() -> Result<()> {
    test_sticker(
        "sticker.png",
        include_bytes!("../../test-data/image/logo.png"),
        Viewtype::Sticker,
        135,
        135,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sticker_jpeg() -> Result<()> {
    test_sticker(
        "sticker.jpg",
        include_bytes!("../../test-data/image/avatar1000x1000.jpg"),
        Viewtype::Image,
        1000,
        1000,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sticker_jpeg_force() {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;

    let file = alice.get_blobdir().join("sticker.jpg");
    tokio::fs::write(
        &file,
        include_bytes!("../../test-data/image/avatar1000x1000.jpg"),
    )
    .await
    .unwrap();

    // Images without force_sticker should be turned into [Viewtype::Image]
    let mut msg = Message::new(Viewtype::Sticker);
    msg.set_file_and_deduplicate(&alice, &file, Some("sticker.jpg"), None)
        .unwrap();
    let file = msg.get_file(&alice).unwrap();
    let sent_msg = alice.send_msg(alice_chat.id, &mut msg).await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(msg.get_viewtype(), Viewtype::Image);

    // Images with `force_sticker = true` should keep [Viewtype::Sticker]
    let mut msg = Message::new(Viewtype::Sticker);
    msg.set_file_and_deduplicate(&alice, &file, Some("sticker.jpg"), None)
        .unwrap();
    msg.force_sticker();
    let sent_msg = alice.send_msg(alice_chat.id, &mut msg).await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(msg.get_viewtype(), Viewtype::Sticker);

    // Images with `force_sticker = true` should keep [Viewtype::Sticker]
    // even on drafted messages
    let mut msg = Message::new(Viewtype::Sticker);
    msg.set_file_and_deduplicate(&alice, &file, Some("sticker.jpg"), None)
        .unwrap();
    msg.force_sticker();
    alice_chat
        .id
        .set_draft(&alice, Some(&mut msg))
        .await
        .unwrap();
    let mut msg = alice_chat.id.get_draft(&alice).await.unwrap().unwrap();
    let sent_msg = alice.send_msg(alice_chat.id, &mut msg).await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(msg.get_viewtype(), Viewtype::Sticker);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sticker_gif() -> Result<()> {
    test_sticker(
        "sticker.gif",
        include_bytes!("../../test-data/image/logo.gif"),
        Viewtype::Sticker,
        135,
        135,
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sticker_forward() -> Result<()> {
    // create chats
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    // create sticker
    let file_name = "sticker.png";
    let bytes = include_bytes!("../../test-data/image/logo.png");
    let file = alice.get_blobdir().join(file_name);
    tokio::fs::write(&file, bytes).await?;
    let mut msg = Message::new(Viewtype::Sticker);
    msg.set_file_and_deduplicate(&alice, &file, Some("sticker.jpg"), None)?;

    // send sticker to bob
    let sent_msg = alice.send_msg(alice_chat.get_id(), &mut msg).await;
    let msg = bob.recv_msg(&sent_msg).await;

    // forward said sticker to alice
    forward_msgs(&bob, &[msg.id], bob_chat.get_id()).await?;
    let forwarded_msg = bob.pop_sent_msg().await;

    let msg = alice.recv_msg(&forwarded_msg).await;
    // forwarded sticker should not have forwarded-flag
    assert!(!msg.is_forwarded());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_basic() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    let mut alice_msg = Message::new_text("Hi Bob".to_owned());
    let sent_msg = alice.send_msg(alice_chat.get_id(), &mut alice_msg).await;
    let msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(alice_msg.rfc724_mid, msg.rfc724_mid);

    forward_msgs(&bob, &[msg.id], bob_chat.get_id()).await?;

    let forwarded_msg = bob.pop_sent_msg().await;
    assert_eq!(bob_chat.id.get_msg_cnt(&bob).await?, E2EE_INFO_MSGS + 2);
    assert_ne!(
        forwarded_msg.load_from_db().await.rfc724_mid,
        msg.rfc724_mid,
    );
    let msg_bob = Message::load_from_db(&bob, forwarded_msg.sender_msg_id).await?;
    let msg = alice.recv_msg(&forwarded_msg).await;
    assert_eq!(msg.rfc724_mid(), msg_bob.rfc724_mid());
    assert_eq!(msg.get_text(), "Hi Bob");
    assert!(msg.is_forwarded());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_info_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let chat_id1 = create_group(alice, "a").await?;
    send_text_msg(alice, chat_id1, "msg one".to_string()).await?;
    let bob_id = alice.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(alice, chat_id1, bob_id).await?;
    let msg1 = alice.get_last_msg_in(chat_id1).await;
    assert!(msg1.is_info());
    assert!(msg1.get_text().contains("bob@example.net"));

    let chat_id2 = ChatId::create_for_contact(alice, bob_id).await?;
    assert_eq!(get_chat_msgs(alice, chat_id2).await?.len(), E2EE_INFO_MSGS);
    forward_msgs(alice, &[msg1.id], chat_id2).await?;
    let msg2 = alice.get_last_msg_in(chat_id2).await;
    assert!(!msg2.is_info()); // forwarded info-messages lose their info-state
    assert_eq!(msg2.get_info_type(), SystemMessage::Unknown);
    assert_ne!(msg2.from_id, ContactId::INFO);
    assert_ne!(msg2.to_id, ContactId::INFO);
    assert_eq!(msg2.get_text(), msg1.get_text());
    assert!(msg2.is_forwarded());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_quote() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    // Alice sends a message to Bob.
    let sent_msg = alice.send_text(alice_chat.id, "Hi Bob").await;
    let received_msg = bob.recv_msg(&sent_msg).await;

    // Bob quotes received message and sends a reply to Alice.
    let mut reply = Message::new_text("Reply".to_owned());
    reply.set_quote(&bob, Some(&received_msg)).await?;
    let sent_reply = bob.send_msg(bob_chat.id, &mut reply).await;
    let received_reply = alice.recv_msg(&sent_reply).await;

    // Alice forwards a reply.
    forward_msgs(&alice, &[received_reply.id], alice_chat.get_id()).await?;
    let forwarded_msg = alice.pop_sent_msg().await;
    let alice_forwarded_msg = bob.recv_msg(&forwarded_msg).await;
    assert!(alice_forwarded_msg.quoted_message(&alice).await?.is_none());
    assert_eq!(
        alice_forwarded_msg.quoted_text(),
        Some("Hi Bob".to_string())
    );

    let bob_forwarded_msg = bob.get_last_msg().await;
    assert!(bob_forwarded_msg.quoted_message(&bob).await?.is_none());
    assert_eq!(bob_forwarded_msg.quoted_text(), Some("Hi Bob".to_string()));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await;

    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    // Alice creates a group with Bob.
    let alice_group_chat_id = create_group(&alice, "Group").await?;
    let bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let charlie_id = alice.add_or_lookup_contact_id(&charlie).await;
    add_contact_to_chat(&alice, alice_group_chat_id, bob_id).await?;
    add_contact_to_chat(&alice, alice_group_chat_id, charlie_id).await?;
    let sent_group_msg = alice
        .send_text(alice_group_chat_id, "Hi Bob and Charlie")
        .await;
    let bob_group_chat_id = bob.recv_msg(&sent_group_msg).await.chat_id;

    // Alice deletes a message on her device.
    // This is needed to make assignment of further messages received in this group
    // based on `References:` header harder.
    // Previously this exposed a bug, so this is a regression test.
    message::delete_msgs(&alice, &[sent_group_msg.sender_msg_id]).await?;

    // Alice sends a message to Bob.
    let sent_msg = alice.send_text(alice_chat.id, "Hi Bob").await;
    let received_msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(received_msg.get_text(), "Hi Bob");
    assert_eq!(received_msg.chat_id, bob_chat.id);

    // Alice sends another message to Bob, this has first message as a parent.
    let sent_msg = alice.send_text(alice_chat.id, "Hello Bob").await;
    let received_msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(received_msg.get_text(), "Hello Bob");
    assert_eq!(received_msg.chat_id, bob_chat.id);

    // Bob forwards message to a group chat with Alice.
    forward_msgs(&bob, &[received_msg.id], bob_group_chat_id).await?;
    let forwarded_msg = bob.pop_sent_msg().await;
    alice.recv_msg(&forwarded_msg).await;

    let received_forwarded_msg = alice.get_last_msg_in(alice_group_chat_id).await;
    assert!(received_forwarded_msg.is_forwarded());
    assert_eq!(received_forwarded_msg.chat_id, alice_group_chat_id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_only_minimal_data_are_forwarded() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let charlie = tcm.charlie().await;

    // send a message from Alice to a group with Bob
    alice
        .set_config(Config::Displayname, Some("secretname"))
        .await?;
    let bob_id = alice.add_or_lookup_contact_id(&bob).await;
    let group_id = create_group(&alice, "secretgrpname").await?;
    add_contact_to_chat(&alice, group_id, bob_id).await?;
    let mut msg = Message::new_text("bla foo".to_owned());
    let sent_msg = alice.send_msg(group_id, &mut msg).await;
    let parsed_msg = alice.parse_msg(&sent_msg).await;
    let encrypted_payload = String::from_utf8(parsed_msg.decoded_data.clone()).unwrap();
    assert!(encrypted_payload.contains("secretgrpname"));
    assert!(encrypted_payload.contains("secretname"));
    assert!(encrypted_payload.contains("alice"));

    // Bob forwards that message to Claire -
    // Claire should not get information about Alice for the original Group
    let orig_msg = bob.recv_msg(&sent_msg).await;
    let charlie_id = bob.add_or_lookup_contact_id(&charlie).await;
    let single_id = ChatId::create_for_contact(&bob, charlie_id).await?;
    let group_id = create_group(&bob, "group2").await?;
    add_contact_to_chat(&bob, group_id, charlie_id).await?;
    let broadcast_id = create_broadcast(&bob, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(&bob, Some(broadcast_id)).await?;
    tcm.exec_securejoin_qr(&charlie, &bob, &qr).await;
    for chat_id in &[single_id, group_id, broadcast_id] {
        forward_msgs(&bob, &[orig_msg.id], *chat_id).await?;
        let sent_msg = bob.pop_sent_msg().await;
        let parsed_msg = bob.parse_msg(&sent_msg).await;
        let encrypted_payload = String::from_utf8(parsed_msg.decoded_data.clone()).unwrap();

        assert!(encrypted_payload.contains("---------- Forwarded message ----------"));
        assert!(!encrypted_payload.contains("secretgrpname"));
        assert!(!encrypted_payload.contains("secretname"));
        assert!(!encrypted_payload.contains("alice"));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_save_msgs() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let alice_chat = alice.create_chat(&bob).await;

    let sent = alice.send_text(alice_chat.get_id(), "hi, bob").await;
    let sent_msg = Message::load_from_db(&alice, sent.sender_msg_id).await?;
    assert!(sent_msg.get_saved_msg_id(&alice).await?.is_none());
    assert!(sent_msg.get_original_msg_id(&alice).await?.is_none());
    let sent_timestamp = sent_msg.get_timestamp();
    assert!(sent_timestamp > 0);

    SystemTime::shift(Duration::from_secs(60));

    let self_chat = alice.get_self_chat().await;
    save_msgs(&alice, &[sent.sender_msg_id]).await?;

    let saved_msg = alice.get_last_msg_in(self_chat.id).await;
    assert_ne!(saved_msg.get_id(), sent.sender_msg_id);
    assert!(saved_msg.get_saved_msg_id(&alice).await?.is_none());
    assert_eq!(
        saved_msg.get_original_msg_id(&alice).await?.unwrap(),
        sent.sender_msg_id
    );
    assert_eq!(saved_msg.get_text(), "hi, bob");
    assert!(!saved_msg.is_forwarded()); // UI should not flag "saved messages" as "forwarded"
    assert_eq!(saved_msg.is_dc_message, MessengerMessage::Yes);
    assert_eq!(saved_msg.get_from_id(), ContactId::SELF);
    assert_eq!(saved_msg.get_state(), MessageState::OutDelivered);
    assert_ne!(saved_msg.rfc724_mid(), sent_msg.rfc724_mid());
    let saved_timestamp = saved_msg.get_timestamp();
    assert_eq!(saved_timestamp, sent_timestamp);

    let sent_msg = Message::load_from_db(&alice, sent.sender_msg_id).await?;
    assert_eq!(
        sent_msg.get_saved_msg_id(&alice).await?.unwrap(),
        saved_msg.id
    );
    assert!(sent_msg.get_original_msg_id(&alice).await?.is_none());

    let rcvd_msg = bob.recv_msg(&sent).await;
    let self_chat = bob.get_self_chat().await;
    save_msgs(&bob, &[rcvd_msg.id]).await?;
    let saved_msg = bob.get_last_msg_in(self_chat.id).await;
    assert_ne!(saved_msg.get_id(), rcvd_msg.id);
    assert_eq!(
        saved_msg.get_original_msg_id(&bob).await?.unwrap(),
        rcvd_msg.id
    );
    assert_eq!(saved_msg.get_text(), "hi, bob");
    assert!(!saved_msg.is_forwarded());
    assert_eq!(saved_msg.is_dc_message, MessengerMessage::Yes);
    assert_ne!(saved_msg.get_from_id(), ContactId::SELF);
    assert_eq!(saved_msg.get_state(), MessageState::InSeen);
    assert_ne!(saved_msg.rfc724_mid(), rcvd_msg.rfc724_mid());

    // delete original message
    delete_msgs(&bob, &[rcvd_msg.id]).await?;
    let saved_msg = Message::load_from_db(&bob, saved_msg.id).await?;
    assert!(saved_msg.get_original_msg_id(&bob).await?.is_none());

    // delete original chat
    rcvd_msg.chat_id.delete(&bob).await?;
    let msg = Message::load_from_db(&bob, saved_msg.id).await?;
    assert!(msg.get_original_msg_id(&bob).await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_save_msgs_order() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let chat_id = create_group(alice, "grp").await?;
    let sent = [
        alice.send_text(chat_id, "0").await,
        alice.send_text(chat_id, "1").await,
    ];
    // NB: This doesn't work if sync messages are fetched earlier than the referenced ones.
    for msg in &sent {
        alice1.recv_msg(msg).await;
    }
    save_msgs(alice, &[sent[1].sender_msg_id, sent[0].sender_msg_id]).await?;
    sync(alice, alice1).await;

    for a in [alice, alice1] {
        let self_chat = a.get_self_chat().await;
        let msgs = get_chat_msgs(a, self_chat.id).await?;
        for i in [0, 1] {
            let ChatItem::Message { msg_id } = msgs[msgs.len() - 2 + i] else {
                panic!("Wrong item type");
            };
            let msg = Message::load_from_db(a, msg_id).await.unwrap();
            assert_eq!(msg.get_text(), format!("{i}"));
        }
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_saved_msgs_not_added_to_shared_chats() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let msg = tcm.send_recv_accept(&alice, &bob, "hi, bob").await;

    let self_chat = bob.get_self_chat().await;
    save_msgs(&bob, &[msg.id]).await?;
    let msg = bob.get_last_msg_in(self_chat.id).await;
    let contact = Contact::get_by_id(&bob, msg.get_from_id()).await?;
    assert_eq!(contact.get_addr(), "alice@example.org");

    let shared_chats = Chatlist::try_load(&bob, 0, None, Some(contact.id)).await?;
    assert_eq!(shared_chats.len(), 1);
    assert_eq!(
        shared_chats.get_chat_id(0).unwrap(),
        bob.get_chat(&alice).await.id
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_from_saved_to_saved() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let sent = alice.send_text(alice.create_chat(&bob).await.id, "k").await;

    let received_message = bob.recv_msg(&sent).await;
    let orig = bob.get_last_msg().await;
    let self_chat = bob.get_self_chat().await;
    save_msgs(&bob, &[orig.id]).await?;
    let saved1 = bob.get_last_msg().await;
    assert_eq!(
        saved1.get_original_msg_id(&bob).await?.unwrap(),
        received_message.id
    );
    assert_ne!(saved1.from_id, ContactId::SELF);

    forward_msgs(&bob, &[saved1.id], self_chat.id).await?;
    let saved2 = bob.get_last_msg().await;
    assert!(saved2.get_original_msg_id(&bob).await?.is_none(),);
    assert_eq!(saved2.from_id, ContactId::SELF);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_encrypted_to_unencrypted() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    let txt = "This should be encrypted";
    let sent = alice.send_text(alice.create_chat(bob).await.id, txt).await;
    let msg = bob.recv_msg(&sent).await;
    assert_eq!(msg.text, txt);
    assert!(msg.get_showpadlock());

    let unencrypted_chat = bob.create_email_chat(charlie).await;
    forward_msgs(bob, &[msg.id], unencrypted_chat.id).await?;
    let msg2 = bob.get_last_msg().await;
    assert_eq!(msg2.text, txt);
    assert_ne!(msg.id, msg2.id);
    assert!(!msg2.get_showpadlock());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_save_from_saved_to_saved_failing() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let sent = alice.send_text(alice.create_chat(&bob).await.id, "k").await;

    bob.recv_msg(&sent).await;
    let orig = bob.get_last_msg().await;
    save_msgs(&bob, &[orig.id]).await?;
    let saved1 = bob.get_last_msg().await;

    let result = save_msgs(&bob, &[saved1.id]).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_own_message() -> Result<()> {
    // Alice creates group with Bob and sends an initial message
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let fiona = TestContext::new_fiona().await;
    let alice_grp = create_group(&alice, "grp").await?;
    add_contact_to_chat(
        &alice,
        alice_grp,
        alice.add_or_lookup_contact_id(&bob).await,
    )
    .await?;
    let sent1 = alice.send_text(alice_grp, "alice->bob").await;

    // Alice adds Claire to group and resends her own initial message
    add_contact_to_chat(
        &alice,
        alice_grp,
        alice.add_or_lookup_contact_id(&fiona).await,
    )
    .await?;
    let sent2 = alice.pop_sent_msg().await;
    let resent_msg_id = sent1.sender_msg_id;
    resend_msgs(&alice, &[resent_msg_id]).await?;
    assert_eq!(
        resent_msg_id.get_state(&alice).await?,
        MessageState::OutPending
    );
    resend_msgs(&alice, &[resent_msg_id]).await?;
    // Message can be re-sent multiple times.
    assert_eq!(
        resent_msg_id.get_state(&alice).await?,
        MessageState::OutPending
    );
    alice.pop_sent_msg().await;
    // There's still one more pending SMTP job.
    assert_eq!(
        resent_msg_id.get_state(&alice).await?,
        MessageState::OutPending
    );
    let sent3 = alice.pop_sent_msg().await;
    assert_eq!(
        resent_msg_id.get_state(&alice).await?,
        MessageState::OutDelivered
    );

    // Bob receives all messages
    let bob = TestContext::new_bob().await;
    let msg = bob.recv_msg(&sent1).await;
    let sent1_ts_sent = msg.timestamp_sent;
    assert_eq!(msg.get_text(), "alice->bob");
    assert_eq!(get_chat_contacts(&bob, msg.chat_id).await?.len(), 2);
    assert_eq!(
        get_chat_msgs(&bob, msg.chat_id).await?.len(),
        E2EE_INFO_MSGS + 1
    );
    bob.recv_msg(&sent2).await;
    assert_eq!(get_chat_contacts(&bob, msg.chat_id).await?.len(), 3);
    assert_eq!(
        get_chat_msgs(&bob, msg.chat_id).await?.len(),
        E2EE_INFO_MSGS + 2
    );
    let received = bob.recv_msg_opt(&sent3).await;
    // No message should actually be added since we already know this message:
    assert!(received.is_none());
    assert_eq!(get_chat_contacts(&bob, msg.chat_id).await?.len(), 3);
    assert_eq!(
        get_chat_msgs(&bob, msg.chat_id).await?.len(),
        E2EE_INFO_MSGS + 2
    );

    // Fiona does not receive the first message, however, due to resending, she has a similar view as Alice and Bob
    fiona.recv_msg(&sent2).await;
    let msg = fiona.recv_msg(&sent3).await;
    assert_eq!(msg.get_text(), "alice->bob");
    assert_eq!(get_chat_contacts(&fiona, msg.chat_id).await?.len(), 3);
    assert_eq!(
        get_chat_msgs(&fiona, msg.chat_id).await?.len(),
        E2EE_INFO_MSGS + 2
    );
    let msg_from = Contact::get_by_id(&fiona, msg.get_from_id()).await?;
    assert_eq!(msg_from.get_addr(), "alice@example.org");
    assert!(sent1_ts_sent == msg.timestamp_sent);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_foreign_message_fails() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_grp = create_group(alice, "grp").await?;
    add_contact_to_chat(alice, alice_grp, alice.add_or_lookup_contact_id(bob).await).await?;
    let sent1 = alice.send_text(alice_grp, "alice->bob").await;

    let msg = bob.recv_msg(&sent1).await;
    assert!(resend_msgs(bob, &[msg.id]).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_info_message_fails() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    let alice_grp = create_group(alice, "grp").await?;
    add_contact_to_chat(alice, alice_grp, alice.add_or_lookup_contact_id(bob).await).await?;
    alice.send_text(alice_grp, "alice->bob").await;

    add_contact_to_chat(
        alice,
        alice_grp,
        alice.add_or_lookup_contact_id(charlie).await,
    )
    .await?;
    let sent2 = alice.pop_sent_msg().await;
    assert!(resend_msgs(alice, &[sent2.sender_msg_id]).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_can_send_group() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = Contact::create(&alice, "", "bob@f.br").await?;
    let chat_id = ChatId::create_for_contact(&alice, bob).await?;
    let chat = Chat::load_from_db(&alice, chat_id).await?;
    assert!(chat.can_send(&alice).await?);
    let chat_id = create_group(&alice, "foo").await?;
    assert_eq!(
        Chat::load_from_db(&alice, chat_id)
            .await?
            .can_send(&alice)
            .await?,
        true
    );
    remove_contact_from_chat(&alice, chat_id, ContactId::SELF).await?;
    assert_eq!(
        Chat::load_from_db(&alice, chat_id)
            .await?
            .can_send(&alice)
            .await?,
        false
    );
    Ok(())
}

/// Tests that in a broadcast channel,
/// the recipients can't see the identity of their fellow recipients.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_members_cant_see_each_other() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    tcm.section("Alice creates a channel, Bob joins.");
    let alice_broadcast_id = create_broadcast(alice, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_broadcast_id))
        .await
        .unwrap();
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    tcm.section("Charlie scans the QR code and sends request.");
    {
        join_securejoin(charlie, &qr).await.unwrap();

        let request = charlie.pop_sent_msg().await;
        assert_eq!(request.recipients, "alice@example.org charlie@example.net");

        alice.recv_msg_trash(&request).await;
    }

    tcm.section("Alice sends auth-required");
    {
        let auth_required = alice.pop_sent_msg().await;
        assert_eq!(
            auth_required.recipients,
            "charlie@example.net alice@example.org"
        );
        let parsed = charlie.parse_msg(&auth_required).await;
        assert!(parsed.get_header(HeaderDef::AutocryptGossip).is_some());
        assert!(parsed.decoded_data_contains("charlie@example.net"));
        assert_eq!(parsed.decoded_data_contains("bob@example.net"), false);

        let parsed_by_bob = bob.parse_msg(&auth_required).await;
        assert!(parsed_by_bob.decrypting_failed);

        charlie.recv_msg_trash(&auth_required).await;
    }

    tcm.section("Charlie sends request-with-auth");
    {
        let request_with_auth = charlie.pop_sent_msg().await;
        assert_eq!(
            request_with_auth.recipients,
            "alice@example.org charlie@example.net"
        );

        alice.recv_msg_trash(&request_with_auth).await;
    }

    tcm.section("Alice adds member");
    {
        let member_added = alice.pop_sent_msg().await;
        assert_eq!(
            member_added.recipients,
            "charlie@example.net alice@example.org"
        );
        let parsed = charlie.parse_msg(&member_added).await;
        assert!(parsed.get_header(HeaderDef::AutocryptGossip).is_some());
        assert!(parsed.decoded_data_contains("charlie@example.net"));
        assert_eq!(parsed.decoded_data_contains("bob@example.net"), false);

        let parsed_by_bob = bob.parse_msg(&member_added).await;
        assert!(parsed_by_bob.decrypting_failed);

        let rcvd = charlie.recv_msg(&member_added).await;
        assert_eq!(rcvd.param.get_cmd(), SystemMessage::MemberAddedToGroup);
    }

    tcm.section("Alice sends into the channel.");
    {
        let hi_msg = alice.send_text(alice_broadcast_id, "hi").await;
        let parsed = charlie.parse_msg(&hi_msg).await;
        assert_eq!(parsed.header_exists(HeaderDef::AutocryptGossip), false);
        assert_eq!(parsed.decoded_data_contains("charlie@example.net"), false);
        assert_eq!(parsed.decoded_data_contains("bob@example.net"), false);

        let parsed_by_bob = bob.parse_msg(&hi_msg).await;
        assert_eq!(parsed_by_bob.decrypting_failed, false);
    }

    tcm.section("Alice removes Charlie. Bob must not see it.");
    {
        let alice_charlie_contact = alice.add_or_lookup_contact_id(charlie).await;
        remove_contact_from_chat(alice, alice_broadcast_id, alice_charlie_contact).await?;
        let member_removed = alice.pop_sent_msg().await;
        assert_eq!(
            member_removed.recipients,
            "charlie@example.net alice@example.org"
        );
        let parsed = charlie.parse_msg(&member_removed).await;
        assert!(parsed.decoded_data_contains("charlie@example.net"));
        assert_eq!(parsed.decoded_data_contains("bob@example.net"), false);

        let parsed_by_bob = bob.parse_msg(&member_removed).await;
        assert!(parsed_by_bob.decrypting_failed);

        let rcvd = charlie.recv_msg(&member_removed).await;
        assert_eq!(rcvd.param.get_cmd(), SystemMessage::MemberRemovedFromGroup);
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_change_name() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let broadcast_id = create_broadcast(alice, "Channel".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(broadcast_id)).await.unwrap();

    tcm.section("Alice invites Bob to her channel");
    tcm.exec_securejoin_qr(bob, alice, &qr).await;
    tcm.section("Alice invites Fiona to her channel");
    tcm.exec_securejoin_qr(fiona, alice, &qr).await;

    {
        tcm.section("Alice changes the chat name");
        set_chat_name(alice, broadcast_id, "My great broadcast").await?;
        let sent = alice.pop_sent_msg().await;

        tcm.section("Bob receives the name-change system message");
        let msg = bob.recv_msg(&sent).await;
        assert_eq!(msg.subject, "Re: My great broadcast");
        let bob_chat = Chat::load_from_db(bob, msg.chat_id).await?;
        assert_eq!(bob_chat.name, "My great broadcast");

        tcm.section("Fiona receives the name-change system message");
        let msg = fiona.recv_msg(&sent).await;
        assert_eq!(msg.subject, "Re: My great broadcast");
        let fiona_chat = Chat::load_from_db(fiona, msg.chat_id).await?;
        assert_eq!(fiona_chat.name, "My great broadcast");
    }

    {
        tcm.section("Alice changes the chat name again, but the system message is lost somehow");
        set_chat_name(alice, broadcast_id, "Broadcast channel").await?;

        let chat = Chat::load_from_db(alice, broadcast_id).await?;
        assert_eq!(chat.typ, Chattype::OutBroadcast);
        assert_eq!(chat.name, "Broadcast channel");
        assert!(!chat.is_self_talk());

        tcm.section("Alice sends a text message 'ola!'");
        send_text_msg(alice, broadcast_id, "ola!".to_string()).await?;
        let msg = alice.get_last_msg().await;
        assert_eq!(msg.chat_id, chat.id);
    }

    {
        tcm.section("Bob receives the 'ola!' message");
        let sent_msg = alice.pop_sent_msg().await;
        let msg = bob.parse_msg(&sent_msg).await;
        assert!(msg.was_encrypted());
        assert!(!msg.header_exists(HeaderDef::ChatGroupMemberTimestamps));
        assert!(!msg.header_exists(HeaderDef::AutocryptGossip));

        // If we sent a ChatGroupId header,
        // older versions of DC would ignore the message
        assert!(!msg.header_exists(HeaderDef::ChatGroupId));

        let msg = bob.recv_msg(&sent_msg).await;
        assert_eq!(msg.get_text(), "ola!");
        assert_eq!(msg.subject, "Re: Broadcast channel");
        assert!(msg.get_showpadlock());
        assert!(msg.get_override_sender_name().is_none());
        let chat = Chat::load_from_db(bob, msg.chat_id).await?;
        assert_eq!(chat.typ, Chattype::InBroadcast);
        let chat_bob = bob.create_chat(alice).await;
        assert_ne!(chat.id, chat_bob.id);
        assert_eq!(chat.name, "Broadcast channel");
        assert!(!chat.is_self_talk());

        tcm.section("Fiona receives the 'ola!' message");
        let msg = fiona.recv_msg(&sent_msg).await;
        assert_eq!(msg.get_text(), "ola!");
        assert!(msg.get_showpadlock());
        assert!(msg.get_override_sender_name().is_none());
        let chat = Chat::load_from_db(fiona, msg.chat_id).await?;
        assert_eq!(chat.typ, Chattype::InBroadcast);
        assert_eq!(chat.name, "Broadcast channel");
    }

    Ok(())
}

/// - Alice has multiple devices
/// - Alice creates a broadcast and sends a message into it
/// - Alice's second device sees the broadcast
/// - Alice's second device changes the name,
///   Alice's first device sees the name change
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_multidev() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    for a in &[alice1, alice2] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    let a1_broadcast_id = create_broadcast(alice1, "Channel".to_string()).await?;
    sync(alice1, alice2).await;
    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    set_chat_name(alice1, a1_broadcast_id, "Broadcast channel 42").await?;
    let sent_msg = alice1.send_text(a1_broadcast_id, "hi").await;
    let msg = alice2.recv_msg(&sent_msg).await;
    let a2_broadcast_id = get_chat_id_by_grpid(alice2, &a1_broadcast_chat.grpid)
        .await?
        .unwrap()
        .0;
    assert_eq!(msg.chat_id, a2_broadcast_id);
    let a2_broadcast_chat = Chat::load_from_db(alice2, a2_broadcast_id).await?;
    assert_eq!(a2_broadcast_chat.get_type(), Chattype::OutBroadcast);
    assert_eq!(a2_broadcast_chat.get_name(), "Broadcast channel 42");
    assert!(get_chat_contacts(alice2, a2_broadcast_id).await?.is_empty());

    SystemTime::shift(Duration::from_secs(10));

    tcm.section("Alice2 changes the broadcast channel name");
    set_chat_name(alice2, a2_broadcast_id, "Broadcast channel 43").await?;

    tcm.section("Alice2 sends a message");
    let sent_msg = alice2.send_text(a2_broadcast_id, "hi").await;

    tcm.section("Alice1 receives it");
    let msg = alice1.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, a1_broadcast_id);
    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    assert_eq!(a1_broadcast_chat.get_type(), Chattype::OutBroadcast);
    assert_eq!(a1_broadcast_chat.get_name(), "Broadcast channel 43");
    assert!(get_chat_contacts(alice1, a1_broadcast_id).await?.is_empty());

    Ok(())
}

/// Test that, if the broadcast channel owner has multiple devices
/// and they have diverging views on the recipients,
/// it is synced when sending a member-addition message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_recipients_sync1() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;
    for a in &[alice1, alice2] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    // Alice1 creates a broadcast and adds Bob, but for some reason
    // (e.g. because alice2 runs an older version of DC),
    // Alice2 doesn't get to know about it
    let a1_broadcast_id = create_broadcast(alice1, "Channel".to_string()).await?;
    alice1.send_sync_msg().await.unwrap();
    alice1.pop_sent_msg().await;

    let qr = get_securejoin_qr(alice1, Some(a1_broadcast_id))
        .await
        .unwrap();
    tcm.exec_securejoin_qr(bob, alice1, &qr).await;

    // The first sync message got lost, so, alice2 doesn't know about the channel now
    sync(alice1, alice2).await;
    let a2_chatlist = Chatlist::try_load(alice2, 0, Some("Channel"), None).await?;
    assert!(a2_chatlist.is_empty());

    // Alice1 adds Charlie to the broadcast channel,
    // and now, Alice2 receives the messages
    join_securejoin(charlie, &qr).await.unwrap();

    let request = charlie.pop_sent_msg().await;
    alice1.recv_msg_trash(&request).await;
    alice2.recv_msg_trash(&request).await;

    let auth_required = alice1.pop_sent_msg().await;
    charlie.recv_msg_trash(&auth_required).await;
    alice2.recv_msg_trash(&auth_required).await;

    let request_with_auth = charlie.pop_sent_msg().await;
    alice1.recv_msg_trash(&request_with_auth).await;
    alice2.recv_msg_trash(&request_with_auth).await;

    let member_added = alice1.pop_sent_msg().await;
    let a2_member_added = alice2.recv_msg(&member_added).await;
    let _c_member_added = charlie.recv_msg(&member_added).await;

    // Alice1 will now sync the full member list to Alice2:
    sync(alice1, alice2).await;
    let a2_chatlist = Chatlist::try_load(alice2, 0, Some("Channel"), None).await?;
    assert_eq!(a2_chatlist.get_msg_id(0)?.unwrap(), a2_member_added.id);

    let a2_bob_contact = alice2.add_or_lookup_contact_id(bob).await;
    let a2_charlie_contact = alice2.add_or_lookup_contact_id(charlie).await;

    let a2_chat_members = get_chat_contacts(alice2, a2_member_added.chat_id).await?;
    assert!(a2_chat_members.contains(&a2_bob_contact));
    assert!(a2_chat_members.contains(&a2_charlie_contact));
    assert_eq!(a2_chat_members.len(), 2);

    Ok(())
}

/// Test that, if the broadcast channel owner has multiple devices
/// and they have diverging views on the recipients,
/// sync messages only add members but don't remove them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_recipients_sync2() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;
    for a in &[alice1, alice2] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    let a1_broadcast_id = create_broadcast(alice1, "Channel".to_string()).await?;
    sync(alice1, alice2).await;

    tcm.section("Alice1 adds Bob, but Alice2 misses it for some reason");
    let qr = get_securejoin_qr(alice1, Some(a1_broadcast_id))
        .await
        .unwrap();
    tcm.exec_securejoin_qr(bob, alice1, &qr).await;

    tcm.section("Alice2 adds Charlie, but Alice1 misses it for some reason");
    let a2_broadcast_id = Chatlist::try_load(alice2, 0, Some("Channel"), None)
        .await?
        .get_chat_id(0)
        .unwrap();
    let qr = get_securejoin_qr(alice2, Some(a2_broadcast_id))
        .await
        .unwrap();
    tcm.exec_securejoin_qr(charlie, alice2, &qr).await;

    tcm.section("The sync messages should correct the problem");
    sync(alice1, alice2).await;
    sync(alice2, alice1).await;

    for (alice, broadcast_id) in [(alice1, a1_broadcast_id), (alice2, a2_broadcast_id)] {
        let bob_contact = alice.add_or_lookup_contact_id(bob).await;
        let charlie_contact = alice.add_or_lookup_contact_id(charlie).await;

        let chat_members = get_chat_contacts(alice, broadcast_id).await?;
        assert!(chat_members.contains(&bob_contact));
        assert!(chat_members.contains(&charlie_contact));
        assert_eq!(chat_members.len(), 2);
    }

    Ok(())
}

/// - Create a broadcast channel
/// - Send a message into it in order to promote it
/// - Add a contact
/// - Rename it
///   - the change should be visible on the receiver's side immediately
/// - Change the avatar
///   - The change should be visible on the receiver's side immediately
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcasts_name_and_avatar() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    alice.set_config(Config::Displayname, Some("Alice")).await?;
    let bob = &tcm.bob().await;

    tcm.section("Create a broadcast channel");
    let alice_chat_id = create_broadcast(alice, "My Channel".to_string()).await?;
    let alice_chat = Chat::load_from_db(alice, alice_chat_id).await?;
    assert_eq!(alice_chat.typ, Chattype::OutBroadcast);

    let alice_chat = Chat::load_from_db(alice, alice_chat_id).await?;
    assert_eq!(alice_chat.is_promoted(), true); // Broadcast channels are never unpromoted
    let sent = alice.send_text(alice_chat_id, "Hi nobody").await;
    let alice_chat = Chat::load_from_db(alice, alice_chat_id).await?;
    assert_eq!(alice_chat.is_promoted(), true);
    assert_eq!(sent.recipients, "alice@example.org");

    tcm.section("Add a contact to the chat and send a message");
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
    tcm.exec_securejoin_qr(bob, alice, &qr).await;
    let sent = alice.send_text(alice_chat_id, "Hi somebody").await;

    assert_eq!(sent.recipients, "bob@example.net alice@example.org");
    let rcvd = bob.recv_msg(&sent).await;
    assert!(rcvd.get_override_sender_name().is_none());
    assert_eq!(rcvd.text, "Hi somebody");
    let bob_chat = Chat::load_from_db(bob, rcvd.chat_id).await?;
    assert_eq!(bob_chat.typ, Chattype::InBroadcast);
    assert_eq!(bob_chat.name, "My Channel");
    assert_eq!(bob_chat.get_profile_image(bob).await?, None);

    tcm.section("Change broadcast channel name, and check that receivers see it");
    set_chat_name(alice, alice_chat_id, "New Channel name").await?;
    let sent = alice.pop_sent_msg().await;
    let rcvd = bob.recv_msg(&sent).await;
    assert!(rcvd.get_override_sender_name().is_none());
    assert_eq!(rcvd.get_info_type(), SystemMessage::GroupNameChanged);
    assert_eq!(
        rcvd.text,
        r#"Group name changed from "My Channel" to "New Channel name" by Alice."#
    );
    let bob_chat = Chat::load_from_db(bob, bob_chat.id).await?;
    assert_eq!(bob_chat.name, "New Channel name");

    tcm.section("Set a broadcast channel avatar, and check that receivers see it");
    let file = alice.get_blobdir().join("avatar.png");
    tokio::fs::write(&file, AVATAR_64x64_BYTES).await?;
    set_chat_profile_image(alice, alice_chat_id, file.to_str().unwrap()).await?;
    let sent = alice.pop_sent_msg().await;

    let bob_chat = Chat::load_from_db(bob, bob_chat.id).await?;
    assert_eq!(bob_chat.get_profile_image(bob).await?, None);

    let rcvd = bob.recv_msg(&sent).await;
    assert!(rcvd.get_override_sender_name().is_none());
    assert_eq!(rcvd.get_info_type(), SystemMessage::GroupImageChanged);
    assert_eq!(rcvd.text, "Group image changed by Alice.");
    assert_eq!(rcvd.chat_id, bob_chat.id);

    let bob_chat = Chat::load_from_db(bob, bob_chat.id).await?;
    let avatar = bob_chat.get_profile_image(bob).await?.unwrap();
    assert_eq!(
        avatar.file_name().unwrap().to_str().unwrap(),
        AVATAR_64x64_DEDUPLICATED
    );

    tcm.section("Check that Bob can't modify the broadcast channel");
    set_chat_profile_image(bob, bob_chat.id, file.to_str().unwrap())
        .await
        .unwrap_err();
    set_chat_name(bob, bob_chat.id, "Bob Channel name")
        .await
        .unwrap_err();

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_description_basic() {
    test_chat_description("", false).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_description_unpromoted_description() {
    test_chat_description("Unpromoted description in the beginning", false)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_description_qr() {
    test_chat_description("", true).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_description_unpromoted_description_qr() {
    test_chat_description("Unpromoted description in the beginning", true)
        .await
        .unwrap()
}

async fn test_chat_description(initial_description: &str, join_via_qr: bool) -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;

    alice.set_config_bool(Config::SyncMsgs, true).await?;
    alice2.set_config_bool(Config::SyncMsgs, true).await?;

    tcm.section("Create a group chat, and add Bob");
    let alice_chat_id = create_group(alice, "My Group").await?;

    if !initial_description.is_empty() {
        set_chat_description(alice, alice_chat_id, initial_description).await?;
    }
    sync(alice, alice2).await;

    let alice2_chat_id = get_chat_id_by_grpid(
        alice2,
        &Chat::load_from_db(alice, alice_chat_id).await?.grpid,
    )
    .await?
    .unwrap()
    .0;
    assert_eq!(
        get_chat_description(alice2, alice2_chat_id).await?,
        initial_description
    );

    let bob_chat_id = if join_via_qr {
        let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
        tcm.exec_securejoin_qr(bob, alice, &qr).await
    } else {
        let alice_bob_id = alice.add_or_lookup_contact_id(bob).await;
        add_contact_to_chat(alice, alice_chat_id, alice_bob_id).await?;
        let sent = alice.send_text(alice_chat_id, "promoting the group").await;
        bob.recv_msg(&sent).await.chat_id
    };
    assert_eq!(
        get_chat_description(bob, bob_chat_id).await?,
        initial_description
    );

    for description in ["This is a cool group", "", "ä ẟ 😂"] {
        tcm.section(&format!(
            "Alice sets the chat description to '{description}'"
        ));
        set_chat_description(alice, alice_chat_id, description).await?;
        let sent = alice.pop_sent_msg().await;
        assert_eq!(
            sent.load_from_db().await.text,
            "[Chat description changed. To see this and other new features, please update the app]"
        );

        tcm.section("Bob receives the description change");
        let rcvd = bob.recv_msg(&sent).await;
        assert_eq!(rcvd.get_info_type(), SystemMessage::GroupDescriptionChanged);
        assert_eq!(rcvd.text, "Chat description changed by alice@example.org.");

        assert_eq!(get_chat_description(bob, rcvd.chat_id).await?, description);

        tcm.section("Check Alice's second device");
        alice2.recv_msg(&sent).await;
        let alice2_chat_id = get_chat_id_by_grpid(
            alice2,
            &Chat::load_from_db(alice, alice_chat_id).await?.grpid,
        )
        .await?
        .unwrap()
        .0;

        assert_eq!(
            get_chat_description(alice2, alice2_chat_id).await?,
            description
        );
    }

    tcm.section("Alice calls set_chat_description() without actually changing the description");
    set_chat_description(alice, alice_chat_id, "ä ẟ 😂").await?;
    assert!(
        alice
            .pop_sent_msg_opt(Duration::from_secs(0))
            .await
            .is_none()
    );

    Ok(())
}

/// Tests explicitly setting an empty chat description
/// doesn't trigger sending out a message
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_setting_empty_chat_description() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Create a group chat, and add Bob in order to promote it");
    let alice_chat_id = create_group(alice, "My Group").await?;

    add_contact_to_chat(
        alice,
        alice_chat_id,
        alice.add_or_lookup_contact_id(bob).await,
    )
    .await?;
    let _hi = alice.send_text(alice_chat_id, "hi").await;

    set_chat_description(alice, alice_chat_id, "").await?;
    assert!(
        alice
            .pop_sent_msg_opt(Duration::from_secs(0))
            .await
            .is_none()
    );

    Ok(())
}

/// Tests that directly after broadcast-securejoin,
/// the brodacast is shown correctly on both devices.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_joining_golden() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    alice.set_config(Config::Displayname, Some("Alice")).await?;

    tcm.section("Create a broadcast channel with an avatar");
    let alice_chat_id = create_broadcast(alice, "My Channel".to_string()).await?;
    let file = alice.get_blobdir().join("avatar.png");
    tokio::fs::write(&file, AVATAR_64x64_BYTES).await?;
    set_chat_profile_image(alice, alice_chat_id, file.to_str().unwrap()).await?;
    // Because broadcasts are always 'promoted',
    // set_chat_profile_image() sends out a message,
    // which we need to pop:
    alice.pop_sent_msg().await;

    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
    let bob_chat_id = tcm.exec_securejoin_qr(bob, alice, &qr).await;

    alice
        .golden_test_chat(alice_chat_id, "test_broadcast_joining_golden_alice")
        .await;
    bob.golden_test_chat(bob_chat_id, "test_broadcast_joining_golden_bob")
        .await;

    let alice_bob_contact = alice.add_or_lookup_contact_no_key(bob).await;
    let private_chat = ChatIdBlocked::lookup_by_contact(alice, alice_bob_contact.id)
        .await?
        .unwrap();
    // The 1:1 chat with Bob should not be visible to the user:
    assert_eq!(private_chat.blocked, Blocked::Yes);
    alice
        .golden_test_chat(
            private_chat.id,
            "test_broadcast_joining_golden_private_chat",
        )
        .await;

    assert_eq!(
        alice_bob_contact
            .get_verifier_id(alice)
            .await?
            .unwrap()
            .unwrap(),
        ContactId::SELF
    );

    let bob_alice_contact = bob.add_or_lookup_contact_no_key(alice).await;
    assert_eq!(
        bob_alice_contact
            .get_verifier_id(bob)
            .await?
            .unwrap()
            .unwrap(),
        ContactId::SELF
    );

    Ok(())
}

/// - Create a broadcast channel
/// - Block it
/// - Check that the broadcast channel appears in the list of blocked contacts
/// - A message is sent into the broadcast channel, but it is blocked
/// - Unblock it
/// - Receive a message again in the now-unblocked broadcast channel
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_block_broadcast() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Create a broadcast channel with Bob, and send a message");
    let alice_chat_id = create_broadcast(alice, "My Channel".to_string()).await?;

    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    let sent = alice.send_text(alice_chat_id, "Hi somebody").await;
    let rcvd = bob.recv_msg(&sent).await;

    let chats = Chatlist::try_load(bob, DC_GCL_NO_SPECIALS, None, None).await?;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats.get_chat_id(0)?, rcvd.chat_id);

    assert_eq!(rcvd.chat_blocked, Blocked::Not);
    let blocked = Contact::get_all_blocked(bob).await.unwrap();
    assert_eq!(blocked.len(), 0);

    tcm.section("Bob blocks the chat");
    rcvd.chat_id.block(bob).await?;
    let chat = Chat::load_from_db(bob, rcvd.chat_id).await?;
    assert_eq!(chat.blocked, Blocked::Yes);
    let blocked = Contact::get_all_blocked(bob).await.unwrap();
    assert_eq!(blocked.len(), 1);
    let blocked = Contact::get_by_id(bob, blocked[0]).await?;
    assert!(blocked.is_key_contact());
    assert_eq!(blocked.origin, Origin::MailinglistAddress);
    assert_eq!(blocked.get_name(), "My Channel");

    let sent = alice.send_text(alice_chat_id, "Second message").await;
    let rcvd2 = bob.recv_msg(&sent).await;
    assert_eq!(rcvd2.chat_id, rcvd.chat_id);
    assert_eq!(rcvd2.chat_blocked, Blocked::Yes);

    let chats = Chatlist::try_load(bob, DC_GCL_NO_SPECIALS, None, None).await?;
    assert_eq!(chats.len(), 0);

    tcm.section("Bob unblocks the chat");
    Contact::unblock(bob, blocked.id).await?;

    let sent = alice.send_text(alice_chat_id, "Third message").await;
    let rcvd3 = bob.recv_msg(&sent).await;
    assert_eq!(rcvd3.chat_id, rcvd.chat_id);
    assert_eq!(rcvd3.chat_blocked, Blocked::Not);

    let blocked = Contact::get_all_blocked(bob).await.unwrap();
    assert_eq!(blocked.len(), 0);

    let chats = Chatlist::try_load(bob, DC_GCL_NO_SPECIALS, None, None).await?;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats.get_chat_id(0)?, rcvd.chat_id);

    let chat = Chat::load_from_db(bob, rcvd3.chat_id).await?;
    assert_eq!(chat.blocked, Blocked::Not);
    assert_eq!(chat.name, "My Channel");
    assert_eq!(chat.typ, Chattype::InBroadcast);

    Ok(())
}

/// Tests that a List-Id header in the encrypted part
/// overrides a List-Id header in the unencrypted part,
/// and that the List-Id isn't visible in the unencrypted part.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_channel_protected_listid() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Create a broadcast channel with Bob, and send a message");
    let alice_chat_id = create_broadcast(alice, "My Channel".to_string()).await?;

    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    let mut sent = alice.send_text(alice_chat_id, "Hi somebody").await;

    assert!(!sent.payload.contains("List-ID"));
    // Do the counter check that the Message-Id header is present:
    assert!(sent.payload.contains("Message-ID"));

    // Check that Delta Chat ignores an injected List-ID header:
    let new_payload = sent.payload.replace(
        "Date: ",
        "List-ID: some wrong listid that would make things fail\nDate: ",
    );
    assert_ne!(&sent.payload, &new_payload);
    sent.payload = new_payload;

    let alice_list_id = Chat::load_from_db(alice, sent.load_from_db().await.chat_id)
        .await?
        .grpid;

    let parsed = mimeparser::MimeMessage::from_bytes(bob, sent.payload.as_bytes()).await?;
    assert_eq!(
        parsed.get_mailinglist_header().unwrap(),
        format!("My Channel <{}>", alice_list_id)
    );

    let rcvd = bob.recv_msg(&sent).await;
    assert_eq!(
        Chat::load_from_db(bob, rcvd.chat_id).await?.grpid,
        alice_list_id
    );

    Ok(())
}

/// Test that if Bob leaves a broadcast channel,
/// Alice (the channel owner) won't see him as a member anymore,
/// but won't be notified about this in any way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_leave_broadcast() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Alice creates broadcast channel with Bob.");
    let alice_chat_id = create_broadcast(alice, "foo".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    tcm.section("Alice sends first message to broadcast.");
    let sent_msg = alice.send_text(alice_chat_id, "Hello!").await;
    let bob_msg = bob.recv_msg(&sent_msg).await;
    let bob_chat_id = bob_msg.chat_id;

    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 1);

    // Clear events so that we can later check
    // that the 'Broadcast channel left' message didn't trigger IncomingMsg:
    alice.evtracker.clear_events();

    // Shift the time so that we can later check the "Broadcast channel left" message's timestamp:
    SystemTime::shift(Duration::from_secs(60));

    assert_eq!(
        load_broadcast_secret(bob, bob_chat_id).await?,
        load_broadcast_secret(alice, alice_chat_id).await?
    );

    tcm.section("Bob leaves the broadcast channel.");
    bob_chat_id.accept(bob).await?;
    remove_contact_from_chat(bob, bob_chat_id, ContactId::SELF).await?;

    let leave_msg = bob.pop_sent_msg().await;
    alice.recv_msg_trash(&leave_msg).await;

    assert!(get_chat_contacts(alice, alice_chat_id).await?.is_empty());
    assert!(
        get_past_chat_contacts(alice, alice_chat_id)
            .await?
            .is_empty()
    );

    alice.emit_event(EventType::Test);
    alice
        .evtracker
        .get_matching(|ev| match ev {
            EventType::Test => true,
            EventType::IncomingMsg { .. } => {
                panic!("'Broadcast channel left' message should be silent")
            }
            EventType::MsgsNoticed(..) => {
                panic!("'Broadcast channel left' message shouldn't clear notifications")
            }
            EventType::MsgsChanged { .. } => {
                panic!("Broadcast channels should be left silently, without any message");
            }
            _ => false,
        })
        .await;

    assert_eq!(load_broadcast_secret(bob, bob_chat_id).await?, None);

    Ok(())
}

/// Test removing Bob from the channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_remove_member_from_broadcast() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Alice creates broadcast channel with Bob.");
    let alice_chat_id = create_broadcast(alice, "foo".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
    tcm.exec_securejoin_qr(bob, alice, &qr).await;

    tcm.section("Alice sends first message to broadcast.");
    let sent_msg = alice.send_text(alice_chat_id, "Hello!").await;
    let bob_msg = bob.recv_msg(&sent_msg).await;
    let bob_chat_id = bob_msg.chat_id;

    assert_eq!(
        load_broadcast_secret(bob, bob_chat_id).await?,
        load_broadcast_secret(alice, alice_chat_id).await?
    );

    tcm.section("Alice removes Bob from the channel.");
    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    remove_contact_from_chat(alice, alice_chat_id, alice_bob_contact_id).await?;

    // Alice must not remember old members,
    // because we would like to remember the minimum information possible
    let past_contacts = get_past_chat_contacts(alice, alice_chat_id).await?;
    assert_eq!(past_contacts.len(), 0);

    let remove_msg = alice.pop_sent_msg().await;
    let rcvd = bob.recv_msg(&remove_msg).await;
    assert_eq!(rcvd.text, "Member Me removed by alice@example.org.");

    let bob_chat = Chat::load_from_db(bob, bob_chat_id).await?;
    assert_eq!(bob_chat.is_self_in_chat(bob).await?, false);

    assert_eq!(load_broadcast_secret(bob, bob_chat_id).await?, None);

    Ok(())
}

/// Tests that if Bob leaves a broadcast channel with one device,
/// the other device shows a correct info message "You left the channel.".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_leave_broadcast_multidevice() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob0 = &tcm.bob().await;
    let bob1 = &tcm.bob().await;
    for b in [bob0, bob1] {
        b.set_config_bool(Config::SyncMsgs, true).await?;
    }

    tcm.section("Alice creates broadcast channel with Bob.");
    let alice_chat_id = create_broadcast(alice, "foo".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();
    join_securejoin(bob0, &qr).await.unwrap();

    let request = bob0.pop_sent_msg().await;
    assert_eq!(request.recipients, "alice@example.org bob@example.net");

    alice.recv_msg_trash(&request).await;
    let auth_required = alice.pop_sent_msg().await;
    assert_eq!(
        auth_required.recipients,
        "bob@example.net alice@example.org"
    );

    bob0.recv_msg_trash(&auth_required).await;
    let request_with_auth = bob0.pop_sent_msg().await;
    assert_eq!(
        request_with_auth.recipients,
        "alice@example.org bob@example.net"
    );

    alice.recv_msg_trash(&request_with_auth).await;
    let member_added = alice.pop_sent_msg().await;
    assert_eq!(member_added.recipients, "bob@example.net alice@example.org");

    tcm.section("Bob receives the member-added message answer, and processes it");
    let rcvd = bob0.recv_msg(&member_added).await;
    assert_eq!(rcvd.param.get_cmd(), SystemMessage::MemberAddedToGroup);

    tcm.section("Bob's second device also receives these messages");
    bob1.recv_msg_trash(&auth_required).await;
    bob1.recv_msg_trash(&request_with_auth).await;
    bob1.recv_msg(&member_added).await;

    // The 1:1 chat should not be visible to the user on any of the devices.
    // The contact should be marked as verified.
    check_direct_chat_is_hidden_and_contact_is_verified(alice, bob0).await;
    check_direct_chat_is_hidden_and_contact_is_verified(bob0, alice).await;

    // TODO: There is a known bug in `observe_securejoin_on_other_device()`:
    // When Bob joins a group or broadcast with his first device,
    // then a chat with Alice will pop up on his second device.
    // When it's fixed, the 2 following lines can be replaced with
    // `check_direct_chat_is_hidden_and_contact_is_verified(bob1, alice).await;`
    let bob1_alice_contact = bob1.add_or_lookup_contact_no_key(alice).await;
    assert!(bob1_alice_contact.is_verified(bob1).await.unwrap());

    tcm.section("Alice sends first message to broadcast.");
    let sent_msg = alice.send_text(alice_chat_id, "Hello!").await;
    let bob0_hello = bob0.recv_msg(&sent_msg).await;
    assert_eq!(bob0_hello.chat_blocked, Blocked::Not);
    let bob1_hello = bob1.recv_msg(&sent_msg).await;
    assert_eq!(bob1_hello.chat_blocked, Blocked::Not);

    tcm.section("Bob leaves the broadcast channel with his first device.");
    let bob_chat_id = bob0_hello.chat_id;
    remove_contact_from_chat(bob0, bob_chat_id, ContactId::SELF).await?;

    let leave_msg = bob0.pop_sent_msg().await;
    let parsed = MimeMessage::from_bytes(bob1, leave_msg.payload().as_bytes()).await?;
    assert_eq!(parsed.parts[0].msg, "I left the group.");

    let rcvd = bob1.recv_msg(&leave_msg).await;

    assert_eq!(rcvd.chat_id, bob1_hello.chat_id);
    assert!(rcvd.is_info());
    assert_eq!(rcvd.get_info_type(), SystemMessage::MemberRemovedFromGroup);
    assert_eq!(rcvd.text, stock_str::msg_you_left_broadcast(bob1).await);

    Ok(())
}

async fn check_direct_chat_is_hidden_and_contact_is_verified(
    t: &TestContext,
    contact: &TestContext,
) {
    let contact = t.add_or_lookup_contact_no_key(contact).await;
    if let Some(direct_chat) = ChatIdBlocked::lookup_by_contact(t, contact.id)
        .await
        .unwrap()
    {
        assert_eq!(direct_chat.blocked, Blocked::Yes);
    }
    assert!(contact.is_verified(t).await.unwrap());
}

/// Test that only the owner of the broadcast channel
/// can send messages into the chat.
///
/// To do so, we change Alice's public key on Bob's side,
/// so that she is supposed to appear as a new contact when we receive another message,
/// and check that she can't write into the channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_only_broadcast_owner_can_send_1() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Alice creates broadcast channel and creates a QR code.");
    let alice_chat_id = create_broadcast(alice, "foo".to_string()).await?;
    let qr = get_securejoin_qr(alice, Some(alice_chat_id)).await.unwrap();

    tcm.section("Bob now scans the QR code");
    let bob_broadcast_id = join_securejoin(bob, &qr).await.unwrap();
    let request = bob.pop_sent_msg().await;
    alice.recv_msg_trash(&request).await;
    let auth_required = alice.pop_sent_msg().await;
    bob.recv_msg_trash(&auth_required).await;
    let request_with_auth = bob.pop_sent_msg().await;
    alice.recv_msg_trash(&request_with_auth).await;
    let member_added = alice.pop_sent_msg().await;

    tcm.section("Change Alice's fingerprint for Bob, so that she is a different contact from Bob's point of view");
    let bob_alice_id = bob.add_or_lookup_contact_no_key(alice).await.id;
    bob.sql
        .execute(
            "UPDATE contacts
            SET fingerprint='1234567890123456789012345678901234567890'
            WHERE id=?",
            (bob_alice_id,),
        )
        .await?;

    tcm.section(
        "Bob receives an answer, but shows it in 1:1 chat because of a fingerprint mismatch",
    );
    let rcvd = bob.recv_msg(&member_added).await;
    assert_eq!(rcvd.text, "I added member bob@example.net.");

    let bob_alice_chat_id = bob.get_chat(alice).await.id;
    assert_eq!(rcvd.chat_id, bob_alice_chat_id);

    assert!(
        load_broadcast_secret(bob, bob_broadcast_id)
            .await?
            .is_none()
    );

    Ok(())
}

/// Same as the previous test, but Alice's fingerprint is changed later,
/// so that we can check that until the fingerprint change, everything works fine.
///
/// Also, this changes Alice's fingerprint in Alice's database, rather than Bob's database,
/// in order to test for the same thing in different ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_only_broadcast_owner_can_send_2() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Alice creates broadcast channel and creates a QR code.");
    let alice_broadcast_id = create_broadcast(alice, "foo".to_string()).await?;

    let qr = get_securejoin_qr(alice, Some(alice_broadcast_id))
        .await
        .unwrap();

    tcm.section("Bob now scans the QR code");
    let bob_broadcast_id = tcm.exec_securejoin_qr(bob, alice, &qr).await;

    assert!(
        load_broadcast_secret(bob, bob_broadcast_id)
            .await?
            .is_some()
    );

    tcm.section("Alice sends a message, which still arrives fine");
    let sent = alice.send_text(alice_broadcast_id, "Hi").await;
    let rcvd = bob.recv_msg(&sent).await;
    assert_eq!(rcvd.text, "Hi");
    assert_eq!(rcvd.chat_id, bob_broadcast_id);

    tcm.section("Now, Alice's fingerprint changes");

    alice.sql.execute("DELETE FROM keypairs", ()).await?;
    alice
        .sql
        .execute("DELETE FROM config WHERE keyname='key_id'", ())
        .await?;
    // Invalidate cached self fingerprint:
    Arc::get_mut(&mut alice.ctx.inner)
        .unwrap()
        .self_fingerprint
        .take();

    tcm.section(
        "Alice sends a message, which is not put into the broadcast chat but into a 1:1 chat",
    );
    let sent = alice.send_text(alice_broadcast_id, "Hi").await;
    let rcvd = bob.recv_msg(&sent).await;
    assert_eq!(rcvd.text, "Hi");
    let bob_alice_chat_id = bob.get_chat(alice).await.id;
    assert_eq!(rcvd.chat_id, bob_alice_chat_id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_broadcast_avatar_and_name() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = &tcm.alice().await;
    let alice2 = &tcm.alice().await;

    alice1.set_config_bool(Config::SyncMsgs, true).await?;
    alice2.set_config_bool(Config::SyncMsgs, true).await?;

    tcm.section("Alice1 creates broadcast channel.");
    let a1_broadcast_id = create_broadcast(alice1, "foo".to_string()).await?;

    tcm.section("The channel syncs to her second device");
    sync(alice1, alice2).await;

    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    let a2_broadcast_id = get_chat_id_by_grpid(alice2, &a1_broadcast_chat.grpid)
        .await?
        .unwrap()
        .0;
    let a2_broadcast_chat = Chat::load_from_db(alice2, a2_broadcast_id).await?;
    assert_eq!(a2_broadcast_chat.get_name(), "foo".to_string());

    set_chat_name(alice1, a1_broadcast_id, "New name").await?;
    let sent = alice1.pop_sent_msg().await;
    let rcvd = alice2.recv_msg(&sent).await;
    assert_eq!(rcvd.chat_id, a2_broadcast_id);
    assert_eq!(rcvd.param.get_cmd(), SystemMessage::GroupNameChanged);
    assert_eq!(
        rcvd.text,
        r#"You changed group name from "foo" to "New name"."#
    );

    let a2_broadcast_chat = Chat::load_from_db(alice2, a2_broadcast_id).await?;
    assert_eq!(a2_broadcast_chat.get_name(), "New name".to_string());

    let file = alice2.get_blobdir().join("avatar.png");
    tokio::fs::write(&file, AVATAR_64x64_BYTES).await?;
    set_chat_profile_image(alice2, a2_broadcast_id, file.to_str().unwrap()).await?;

    let sent = alice2.pop_sent_msg().await;
    let rcvd = alice1.recv_msg(&sent).await;
    assert_eq!(rcvd.chat_id, a1_broadcast_id);
    assert_eq!(rcvd.param.get_cmd(), SystemMessage::GroupImageChanged);
    assert_eq!(rcvd.text, "You changed the group image.");

    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    let avatar = a1_broadcast_chat.get_profile_image(alice1).await?.unwrap();
    assert_eq!(avatar.file_name().unwrap(), AVATAR_64x64_DEDUPLICATED);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_encrypt_decrypt_broadcast() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let bob_without_secret = &tcm.bob().await;

    let secret = "secret";
    let grpid = "grpid";

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;

    tcm.section("Create a broadcast channel with Bob, and send a message");
    let alice_chat_id = create_out_broadcast_ex(
        alice,
        Sync,
        "My Channel".to_string(),
        grpid.to_string(),
        secret.to_string(),
    )
    .await?;
    add_to_chat_contacts_table(alice, time(), alice_chat_id, &[alice_bob_contact_id]).await?;

    let bob_chat_id = ChatId::create_multiuser_record(
        bob,
        Chattype::InBroadcast,
        grpid,
        "My Channel",
        Blocked::Not,
        None,
        time(),
    )
    .await?;
    save_broadcast_secret(bob, bob_chat_id, secret).await?;

    let sent = alice
        .send_text(alice_chat_id, "Symmetrically encrypted message")
        .await;
    let rcvd = bob.recv_msg(&sent).await;
    assert_eq!(rcvd.text, "Symmetrically encrypted message");

    tcm.section("If Bob doesn't know the secret, he can't decrypt the message");
    bob_without_secret.recv_msg_trash(&sent).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_for_contact_with_blocked() -> Result<()> {
    let t = TestContext::new().await;
    let (contact_id, _) = Contact::add_or_lookup(
        &t,
        "",
        &ContactAddress::new("foo@bar.org")?,
        Origin::ManuallyCreated,
    )
    .await?;

    // create a blocked chat
    let chat_id_orig =
        ChatId::create_for_contact_with_blocked(&t, contact_id, Blocked::Yes).await?;
    assert!(!chat_id_orig.is_special());
    let chat = Chat::load_from_db(&t, chat_id_orig).await?;
    assert_eq!(chat.blocked, Blocked::Yes);

    // repeating the call, the same chat must still be blocked
    let chat_id = ChatId::create_for_contact_with_blocked(&t, contact_id, Blocked::Yes).await?;
    assert_eq!(chat_id, chat_id_orig);
    let chat = Chat::load_from_db(&t, chat_id).await?;
    assert_eq!(chat.blocked, Blocked::Yes);

    // already created chats are unblocked if requested
    let chat_id = ChatId::create_for_contact_with_blocked(&t, contact_id, Blocked::Not).await?;
    assert_eq!(chat_id, chat_id_orig);
    let chat = Chat::load_from_db(&t, chat_id).await?;
    assert_eq!(chat.blocked, Blocked::Not);

    // however, already created chats are not re-blocked
    let chat_id = ChatId::create_for_contact_with_blocked(&t, contact_id, Blocked::Yes).await?;
    assert_eq!(chat_id, chat_id_orig);
    let chat = Chat::load_from_db(&t, chat_id).await?;
    assert_eq!(chat.blocked, Blocked::Not);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_get_encryption_info() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let contact_bob = alice.add_or_lookup_contact_id(bob).await;
    let contact_fiona = alice.add_or_lookup_contact_id(fiona).await;

    let chat_id = create_group(alice, "Group").await?;
    assert_eq!(
        chat_id.get_encryption_info(alice).await?,
        "Messages are end-to-end encrypted."
    );

    add_contact_to_chat(alice, chat_id, contact_bob).await?;
    assert_eq!(
        chat_id.get_encryption_info(alice).await?,
        "Messages are end-to-end encrypted.\n\
         \n\
         bob@example.net\n\
         CCCB 5AA9 F6E1 141C 9431\n\
         65F1 DB18 B18C BCF7 0487"
    );

    add_contact_to_chat(alice, chat_id, contact_fiona).await?;
    assert_eq!(
        chat_id.get_encryption_info(alice).await?,
        "Messages are end-to-end encrypted.\n\
         \n\
         fiona@example.net\n\
         C8BA 50BF 4AC1 2FAF 38D7\n\
         F657 DDFC 8E9F 3C79 9195\n\
         \n\
         bob@example.net\n\
         CCCB 5AA9 F6E1 141C 9431\n\
         65F1 DB18 B18C BCF7 0487"
    );

    let email_chat = alice.create_email_chat(bob).await;
    assert_eq!(
        email_chat.id.get_encryption_info(alice).await?,
        "No encryption."
    );

    alice.sql.execute("DELETE FROM public_keys", ()).await?;
    assert_eq!(
        chat_id.get_encryption_info(alice).await?,
        "Messages are end-to-end encrypted.\n\
         \n\
         fiona@example.net\n\
         (key missing)\n\
         C8BA 50BF 4AC1 2FAF 38D7\n\
         F657 DDFC 8E9F 3C79 9195\n\
         \n\
         bob@example.net\n\
         (key missing)\n\
         CCCB 5AA9 F6E1 141C 9431\n\
         65F1 DB18 B18C BCF7 0487"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_out_failed_on_all_keys_missing() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let bob_chat_id = bob.create_group_with_members("", &[alice, fiona]).await;
    bob.send_text(bob_chat_id, "Gossiping Fiona's key").await;
    alice
        .recv_msg(&bob.send_text(bob_chat_id, "No key gossip").await)
        .await;
    SystemTime::shift(Duration::from_secs(60));
    remove_contact_from_chat(bob, bob_chat_id, ContactId::SELF).await?;
    let alice_chat_id = alice.recv_msg(&bob.pop_sent_msg().await).await.chat_id;
    alice_chat_id.accept(alice).await?;
    let mut msg = Message::new_text("Hi".to_string());
    send_msg(alice, alice_chat_id, &mut msg).await.ok();
    assert_eq!(msg.id.get_state(alice).await?, MessageState::OutFailed);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_chat_media() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id1 = create_group(&t, "foo").await?;
    let chat_id2 = create_group(&t, "bar").await?;

    assert_eq!(
        get_chat_media(
            &t,
            Some(chat_id1),
            Viewtype::Image,
            Viewtype::Sticker,
            Viewtype::Unknown
        )
        .await?
        .len(),
        0
    );

    async fn send_media(
        t: &TestContext,
        chat_id: ChatId,
        msg_type: Viewtype,
        name: &str,
        bytes: &[u8],
    ) -> Result<MsgId> {
        let file = t.get_blobdir().join(name);
        tokio::fs::write(&file, bytes).await?;
        let mut msg = Message::new(msg_type);
        msg.set_file_and_deduplicate(t, &file, Some(name), None)?;
        send_msg(t, chat_id, &mut msg).await
    }

    send_media(
        &t,
        chat_id1,
        Viewtype::Image,
        "a.jpg",
        include_bytes!("../../test-data/image/rectangle200x180-rotated.jpg"),
    )
    .await?;
    send_media(
        &t,
        chat_id1,
        Viewtype::Sticker,
        "b.png",
        include_bytes!("../../test-data/image/logo.png"),
    )
    .await?;
    let second_image_msg_id = send_media(
        &t,
        chat_id2,
        Viewtype::Image,
        "c.jpg",
        include_bytes!("../../test-data/image/avatar64x64.png"),
    )
    .await?;
    send_media(
        &t,
        chat_id2,
        Viewtype::Webxdc,
        "d.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )
    .await?;

    assert_eq!(
        get_chat_media(
            &t,
            Some(chat_id1),
            Viewtype::Image,
            Viewtype::Unknown,
            Viewtype::Unknown,
        )
        .await?
        .len(),
        1
    );
    assert_eq!(
        get_chat_media(
            &t,
            Some(chat_id1),
            Viewtype::Sticker,
            Viewtype::Unknown,
            Viewtype::Unknown,
        )
        .await?
        .len(),
        1
    );
    assert_eq!(
        get_chat_media(
            &t,
            Some(chat_id1),
            Viewtype::Sticker,
            Viewtype::Image,
            Viewtype::Unknown,
        )
        .await?
        .len(),
        2
    );
    assert_eq!(
        get_chat_media(
            &t,
            Some(chat_id2),
            Viewtype::Webxdc,
            Viewtype::Unknown,
            Viewtype::Unknown,
        )
        .await?
        .len(),
        1
    );
    assert_eq!(
        get_chat_media(
            &t,
            None,
            Viewtype::Image,
            Viewtype::Unknown,
            Viewtype::Unknown,
        )
        .await?
        .len(),
        2
    );
    assert_eq!(
        get_chat_media(
            &t,
            None,
            Viewtype::Image,
            Viewtype::Sticker,
            Viewtype::Unknown,
        )
        .await?
        .len(),
        3
    );
    assert_eq!(
        get_chat_media(
            &t,
            None,
            Viewtype::Image,
            Viewtype::Sticker,
            Viewtype::Webxdc,
        )
        .await?
        .len(),
        4
    );

    // Delete an image.
    delete_msgs(&t, &[second_image_msg_id]).await?;
    assert_eq!(
        get_chat_media(
            &t,
            None,
            Viewtype::Image,
            Viewtype::Sticker,
            Viewtype::Webxdc,
        )
        .await?
        .len(),
        3
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_chat_media_webxdc_order() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let chat = alice.create_chat(&bob).await;

    let mut instance1 = Message::new(Viewtype::Webxdc);
    instance1.set_file_from_bytes(
        &alice,
        "test1.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
        None,
    )?;
    let instance1_id = send_msg(&alice, chat.id, &mut instance1).await?;

    let mut instance2 = Message::new(Viewtype::Webxdc);
    instance2.set_file_from_bytes(
        &alice,
        "test2.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
        None,
    )?;
    let instance2_id = send_msg(&alice, chat.id, &mut instance2).await?;

    // list is ordered oldest to newest, check that
    let media = get_chat_media(
        &alice,
        Some(chat.id),
        Viewtype::Webxdc,
        Viewtype::Unknown,
        Viewtype::Unknown,
    )
    .await?;
    assert_eq!(media.first().unwrap(), &instance1_id);
    assert_eq!(media.get(1).unwrap(), &instance2_id);

    // add a status update for the oder instance; that resorts the list
    alice
        .send_webxdc_status_update(instance1_id, r#"{"payload": {"foo": "bar"}}"#)
        .await?;
    let media = get_chat_media(
        &alice,
        Some(chat.id),
        Viewtype::Webxdc,
        Viewtype::Unknown,
        Viewtype::Unknown,
    )
    .await?;
    assert_eq!(media.first().unwrap(), &instance2_id);
    assert_eq!(media.get(1).unwrap(), &instance1_id);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_blob_renaming() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let chat_id = create_group(&alice, "Group").await?;
    add_contact_to_chat(&alice, chat_id, alice.add_or_lookup_contact_id(&bob).await).await?;
    let file = alice.get_blobdir().join("harmless_file.\u{202e}txt.exe");
    fs::write(&file, "aaa").await?;
    let mut msg = Message::new(Viewtype::File);
    msg.set_file_and_deduplicate(&alice, &file, Some("harmless_file.\u{202e}txt.exe"), None)?;
    let msg = bob.recv_msg(&alice.send_msg(chat_id, &mut msg).await).await;

    // the file bob receives should not contain BIDI-control characters
    assert_eq!(
        Some("$BLOBDIR/30c0f9c6a167fc2a91285c85be7ea34.exe"),
        msg.param.get(Param::File),
    );
    assert_eq!(
        Some("harmless_file.txt.exe"),
        msg.param.get(Param::Filename),
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_blocked() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = &tcm.bob().await;

    let ba_chat = bob.create_chat(alice0).await;
    let sent_msg = bob.send_text(ba_chat.id, "hi").await;
    let a0b_chat_id = alice0.recv_msg(&sent_msg).await.chat_id;
    alice1.recv_msg(&sent_msg).await;
    let a0b_contact_id = alice0.add_or_lookup_contact_id(bob).await;

    assert_eq!(alice1.get_chat(bob).await.blocked, Blocked::Request);
    a0b_chat_id.accept(alice0).await?;
    sync(alice0, alice1).await;
    assert_eq!(alice1.get_chat(bob).await.blocked, Blocked::Not);
    a0b_chat_id.block(alice0).await?;
    sync(alice0, alice1).await;
    assert_eq!(alice1.get_chat(bob).await.blocked, Blocked::Yes);
    a0b_chat_id.unblock(alice0).await?;
    sync(alice0, alice1).await;
    assert_eq!(alice1.get_chat(bob).await.blocked, Blocked::Not);

    // Unblocking a 1:1 chat doesn't unblock the contact currently.
    Contact::unblock(alice0, a0b_contact_id).await?;

    assert!(!alice1.add_or_lookup_contact(bob).await.is_blocked());
    Contact::block(alice0, a0b_contact_id).await?;
    sync(alice0, alice1).await;
    assert!(alice1.add_or_lookup_contact(bob).await.is_blocked());
    Contact::unblock(alice0, a0b_contact_id).await?;
    sync(alice0, alice1).await;
    assert!(!alice1.add_or_lookup_contact(bob).await.is_blocked());

    // Test accepting and blocking groups. This way we test:
    // - Group chats synchronisation.
    // - That blocking a group deletes it on other devices.
    let fiona = TestContext::new_fiona().await;
    let fiona_grp_chat_id = fiona.create_group_with_members("grp", &[alice0]).await;
    let sent_msg = fiona.send_text(fiona_grp_chat_id, "hi").await;
    let a0_grp_chat_id = alice0.recv_msg(&sent_msg).await.chat_id;
    let a1_grp_chat_id = alice1.recv_msg(&sent_msg).await.chat_id;
    let a1_grp_chat = Chat::load_from_db(alice1, a1_grp_chat_id).await?;
    assert_eq!(a1_grp_chat.blocked, Blocked::Request);
    a0_grp_chat_id.accept(alice0).await?;
    sync(alice0, alice1).await;
    let a1_grp_chat = Chat::load_from_db(alice1, a1_grp_chat_id).await?;
    assert_eq!(a1_grp_chat.blocked, Blocked::Not);
    a0_grp_chat_id.block(alice0).await?;
    sync(alice0, alice1).await;
    assert!(Chat::load_from_db(alice1, a1_grp_chat_id).await.is_err());
    assert!(
        !alice1
            .sql
            .exists("SELECT COUNT(*) FROM chats WHERE id=?", (a1_grp_chat_id,))
            .await?
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_accept_before_first_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = &tcm.bob().await;

    let ba_chat = bob.create_chat(alice0).await;
    let sent_msg = bob.send_text(ba_chat.id, "hi").await;
    let rcvd_msg = alice0.recv_msg(&sent_msg).await;
    let a0b_chat_id = rcvd_msg.chat_id;
    let a0b_contact_id = rcvd_msg.from_id;
    assert_eq!(
        Chat::load_from_db(alice0, a0b_chat_id).await?.blocked,
        Blocked::Request
    );
    a0b_chat_id.accept(alice0).await?;
    let a0b_contact = Contact::get_by_id(alice0, a0b_contact_id).await?;
    assert_eq!(a0b_contact.origin, Origin::CreateChat);
    assert_eq!(alice0.get_chat(bob).await.blocked, Blocked::Not);

    sync(alice0, alice1).await;
    let alice1_contacts = Contact::get_all(alice1, 0, None).await?;
    assert_eq!(alice1_contacts.len(), 1);
    let a1b_contact_id = alice1_contacts[0];
    let a1b_contact = Contact::get_by_id(alice1, a1b_contact_id).await?;
    assert_eq!(a1b_contact.get_addr(), "");
    assert_eq!(a1b_contact.origin, Origin::CreateChat);
    let a1b_chat = alice1.get_chat(bob).await;
    assert_eq!(a1b_chat.blocked, Blocked::Not);
    let chats = Chatlist::try_load(alice1, 0, None, None).await?;
    assert_eq!(chats.len(), 1);

    let rcvd_msg = alice1.recv_msg(&sent_msg).await;
    assert_eq!(rcvd_msg.chat_id, a1b_chat.id);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_block_before_first_msg() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = &tcm.bob().await;

    let ba_chat = bob.create_chat(alice0).await;
    let sent_msg = bob.send_text(ba_chat.id, "hi").await;
    let rcvd_msg = alice0.recv_msg(&sent_msg).await;
    let a0b_chat_id = rcvd_msg.chat_id;
    let a0b_contact_id = rcvd_msg.from_id;
    assert_eq!(
        Chat::load_from_db(alice0, a0b_chat_id).await?.blocked,
        Blocked::Request
    );
    a0b_chat_id.block(alice0).await?;
    let a0b_contact = Contact::get_by_id(alice0, a0b_contact_id).await?;
    assert_eq!(a0b_contact.origin, Origin::IncomingUnknownFrom);
    assert_eq!(
        Chat::load_from_db(alice0, a0b_chat_id).await?.blocked,
        Blocked::Yes
    );

    sync(alice0, alice1).await;
    let alice1_contacts = Contact::get_all(alice1, 0, None).await?;
    assert_eq!(alice1_contacts.len(), 0);

    let rcvd_msg = alice1.recv_msg(&sent_msg).await;
    let a1b_contact_id = rcvd_msg.from_id;
    let a1b_contact = Contact::get_by_id(alice1, a1b_contact_id).await?;
    assert_eq!(a1b_contact.origin, Origin::IncomingUnknownFrom);
    let ChatIdBlocked {
        id: a1b_chat_id,
        blocked: a1b_chat_blocked,
    } = ChatIdBlocked::lookup_by_contact(alice1, a1b_contact_id)
        .await?
        .unwrap();
    assert_eq!(a1b_chat_blocked, Blocked::Yes);
    assert_eq!(rcvd_msg.chat_id, a1b_chat_id);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_delete_chat() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = TestContext::new_bob().await;

    let ba_chat = bob.create_chat(alice0).await;
    let sent_msg = bob.send_text(ba_chat.id, "hi").await;
    let a0b_chat_id = alice0.recv_msg(&sent_msg).await.chat_id;
    let a1b_chat_id = alice1.recv_msg(&sent_msg).await.chat_id;
    a0b_chat_id.accept(alice0).await?;
    sync(alice0, alice1).await;
    a0b_chat_id.delete(alice0).await?;
    sync(alice0, alice1).await;
    alice1.assert_no_chat(a1b_chat_id).await;
    alice1
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::ChatDeleted { .. }))
        .await;

    let bob_grp_chat_id = bob.create_group_with_members("grp", &[alice0]).await;
    let sent_msg = bob.send_text(bob_grp_chat_id, "hi").await;
    let a0_grp_chat_id = alice0.recv_msg(&sent_msg).await.chat_id;
    let a1_grp_chat_id = alice1.recv_msg(&sent_msg).await.chat_id;
    a0_grp_chat_id.accept(alice0).await?;
    sync(alice0, alice1).await;
    a0_grp_chat_id.delete(alice0).await?;
    sync(alice0, alice1).await;
    alice1.assert_no_chat(a1_grp_chat_id).await;
    alice0
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::ChatDeleted { .. }))
        .await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_adhoc_grp() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    let mut chat_ids = Vec::new();
    for a in [alice0, alice1] {
        let msg = receive_imf(
            a,
            b"Subject: =?utf-8?q?Message_from_alice=40example=2Eorg?=\r\n\
                    From: alice@example.org\r\n\
                    To: <bob@example.net>, <fiona@example.org> \r\n\
                    Date: Mon, 2 Dec 2023 16:59:39 +0000\r\n\
                    Message-ID: <Mr.alices_original_mail@example.org>\r\n\
                    Chat-Version: 1.0\r\n\
                    \r\n\
                    hi\r\n",
            false,
        )
        .await?
        .unwrap();
        chat_ids.push(msg.chat_id);
    }
    let chat1 = Chat::load_from_db(alice1, chat_ids[1]).await?;
    assert_eq!(chat1.typ, Chattype::Group);
    assert!(chat1.grpid.is_empty());

    // Test synchronisation on chat blocking because it causes chat deletion currently and thus
    // requires generating a sync message in advance.
    chat_ids[0].block(alice0).await?;
    sync(alice0, alice1).await;
    assert!(Chat::load_from_db(alice1, chat_ids[1]).await.is_err());
    assert!(
        !alice1
            .sql
            .exists("SELECT COUNT(*) FROM chats WHERE id=?", (chat_ids[1],))
            .await?
    );

    Ok(())
}

/// Tests syncing of chat visibility on a self-chat. This way we test:
/// - Self-chat synchronisation.
/// - That sync messages don't unarchive the self-chat.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_visibility() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let a0self_chat_id = alice0.get_self_chat().await.id;

    assert_eq!(
        alice1.get_self_chat().await.get_visibility(),
        ChatVisibility::Normal
    );
    let mut visibilities = ChatVisibility::iter().chain(std::iter::once(ChatVisibility::Normal));
    visibilities.next();
    for v in visibilities {
        a0self_chat_id.set_visibility(alice0, v).await?;
        sync(alice0, alice1).await;
        for a in [alice0, alice1] {
            assert_eq!(a.get_self_chat().await.get_visibility(), v);
        }
    }
    Ok(())
}

/// Tests syncing of chat visibility on device message chat.
///
/// Previously due to a bug pinning "Device Messages"
/// chat resulted in creation of `device@localhost` chat
/// on another device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_device_messages_visibility() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }

    let device_chat_id0 = ChatId::get_for_contact(alice0, ContactId::DEVICE).await?;
    device_chat_id0
        .set_visibility(alice0, ChatVisibility::Pinned)
        .await?;

    sync(alice0, alice1).await;

    let device_chat_id1 = ChatId::get_for_contact(alice1, ContactId::DEVICE).await?;
    let device_chat1 = Chat::load_from_db(alice1, device_chat_id1).await?;
    assert_eq!(device_chat1.get_visibility(), ChatVisibility::Pinned);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_muted() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = TestContext::new_bob().await;
    let a0b_chat_id = alice0.create_chat(&bob).await.id;
    alice1.create_chat(&bob).await;

    assert_eq!(
        alice1.get_chat(&bob).await.mute_duration,
        MuteDuration::NotMuted
    );
    let mute_durations = [
        MuteDuration::Forever,
        MuteDuration::Until(SystemTime::now() + Duration::from_secs(42)),
        MuteDuration::NotMuted,
    ];
    for m in mute_durations {
        set_muted(alice0, a0b_chat_id, m).await?;
        sync(alice0, alice1).await;
        let m = match m {
            MuteDuration::Until(time) => MuteDuration::Until(
                SystemTime::UNIX_EPOCH
                    + Duration::from_secs(time.duration_since(SystemTime::UNIX_EPOCH)?.as_secs()),
            ),
            _ => m,
        };
        assert_eq!(alice1.get_chat(&bob).await.mute_duration, m);
    }
    Ok(())
}

/// Tests that synchronizing broadcast channels via sync-messages works
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_broadcast_and_send_message() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    for a in [alice1, alice2] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = &tcm.bob().await;
    let a1b_contact_id = alice1.add_or_lookup_contact(bob).await.id;

    tcm.section("Alice creates a channel on her first device");
    let a1_broadcast_id = create_broadcast(alice1, "Channel".to_string()).await?;

    tcm.section("The channel syncs to her second device");
    sync(alice1, alice2).await;
    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    let a2_broadcast_id = get_chat_id_by_grpid(alice2, &a1_broadcast_chat.grpid)
        .await?
        .unwrap()
        .0;
    let a2_broadcast_chat = Chat::load_from_db(alice2, a2_broadcast_id).await?;
    assert_eq!(a2_broadcast_chat.get_type(), Chattype::OutBroadcast);
    assert_eq!(a2_broadcast_chat.get_name(), a1_broadcast_chat.get_name());
    assert!(get_chat_contacts(alice2, a2_broadcast_id).await?.is_empty());

    tcm.section("Bob scans Alice's QR code, both of Alice's devices answer");
    let qr = get_securejoin_qr(alice1, Some(a1_broadcast_id))
        .await
        .unwrap();
    sync(alice1, alice2).await; // Sync QR code
    let bob_broadcast_id = tcm
        .exec_securejoin_qr_multi_device(bob, &[alice1, alice2], &qr)
        .await;

    let a2b_contact_id = alice2.add_or_lookup_contact_no_key(bob).await.id;
    assert_eq!(
        get_chat_contacts(alice2, a2_broadcast_id).await?,
        vec![a2b_contact_id]
    );

    tcm.section("Alice's second device sends a message to the channel");
    let sent_msg = alice2.send_text(a2_broadcast_id, "hi").await;
    let msg = bob.recv_msg(&sent_msg).await;
    let chat = Chat::load_from_db(bob, msg.chat_id).await?;
    assert_eq!(chat.get_type(), Chattype::InBroadcast);
    let msg = alice1.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, a1_broadcast_id);

    tcm.section("Alice's first device removes Bob");
    remove_contact_from_chat(alice1, a1_broadcast_id, a1b_contact_id).await?;
    let sent = alice1.pop_sent_msg().await;

    tcm.section("Alice's second device receives the removal-message");
    alice2.recv_msg(&sent).await;
    assert!(get_chat_contacts(alice2, a2_broadcast_id).await?.is_empty());
    assert!(
        get_past_chat_contacts(alice2, a2_broadcast_id)
            .await?
            .is_empty()
    );

    tcm.section("Bob receives the removal-message");
    bob.recv_msg(&sent).await;
    let bob_chat = Chat::load_from_db(bob, bob_broadcast_id).await?;
    assert!(!bob_chat.is_self_in_chat(bob).await?);

    bob.golden_test_chat(bob_broadcast_id, "test_sync_broadcast_bob")
        .await;

    // Alice1 and Alice2 are supposed to show the chat in the same way:
    alice1
        .golden_test_chat(a1_broadcast_id, "test_sync_broadcast_alice1")
        .await;
    alice2
        .golden_test_chat(a2_broadcast_id, "test_sync_broadcast_alice2")
        .await;

    tcm.section("Alice's first device deletes the chat");
    a1_broadcast_id.delete(alice1).await?;
    sync(alice1, alice2).await;
    alice2.assert_no_chat(a2_broadcast_id).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_name() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let a0_broadcast_id = create_broadcast(alice0, "Channel".to_string()).await?;
    sync(alice0, alice1).await;
    let a0_broadcast_chat = Chat::load_from_db(alice0, a0_broadcast_id).await?;

    set_chat_name(alice0, a0_broadcast_id, "Broadcast channel 42").await?;

    let sent = alice0.pop_sent_msg().await;
    let rcvd = alice1.recv_msg(&sent).await;
    assert_eq!(rcvd.from_id, ContactId::SELF);
    assert_eq!(rcvd.to_id, ContactId::SELF);
    assert_eq!(
        rcvd.text,
        "You changed group name from \"Channel\" to \"Broadcast channel 42\"."
    );
    assert_eq!(rcvd.param.get_cmd(), SystemMessage::GroupNameChanged);
    let a1_broadcast_id = get_chat_id_by_grpid(alice1, &a0_broadcast_chat.grpid)
        .await?
        .unwrap()
        .0;
    assert_eq!(rcvd.chat_id, a1_broadcast_id);

    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    assert_eq!(a1_broadcast_chat.get_type(), Chattype::OutBroadcast);
    assert_eq!(a1_broadcast_chat.get_name(), "Broadcast channel 42");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_create_group() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice0 = &tcm.alice().await;
    let alice1 = &tcm.alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = &tcm.bob().await;
    let a0_bob_contact_id = alice0.add_or_lookup_contact_id(bob).await;
    let a1_bob_contact_id = alice1.add_or_lookup_contact_id(bob).await;
    let a0_chat_id = create_group(alice0, "grp").await?;
    sync(alice0, alice1).await;
    let a0_chat = Chat::load_from_db(alice0, a0_chat_id).await?;
    let a1_chat_id = get_chat_id_by_grpid(alice1, &a0_chat.grpid)
        .await?
        .unwrap()
        .0;
    let a1_chat = Chat::load_from_db(alice1, a1_chat_id).await?;
    assert_eq!(a1_chat.get_type(), Chattype::Group);
    assert_eq!(a1_chat.is_promoted(), false);
    assert_eq!(a1_chat.get_name(), "grp");

    set_chat_name(alice0, a0_chat_id, "renamed").await?;
    sync(alice0, alice1).await;
    let a1_chat = Chat::load_from_db(alice1, a1_chat_id).await?;
    assert_eq!(a1_chat.is_promoted(), false);
    assert_eq!(a1_chat.get_name(), "renamed");

    add_contact_to_chat(alice0, a0_chat_id, a0_bob_contact_id).await?;
    sync(alice0, alice1).await;
    let a1_chat = Chat::load_from_db(alice1, a1_chat_id).await?;
    assert_eq!(a1_chat.is_promoted(), false);
    assert_eq!(
        get_chat_contacts(alice1, a1_chat_id).await?,
        [a1_bob_contact_id, ContactId::SELF]
    );

    // Let's test a contact removal from another device.
    remove_contact_from_chat(alice1, a1_chat_id, a1_bob_contact_id).await?;
    sync(alice1, alice0).await;
    let a0_chat = Chat::load_from_db(alice0, a0_chat_id).await?;
    assert_eq!(a0_chat.is_promoted(), false);
    assert_eq!(
        get_chat_contacts(alice0, a0_chat_id).await?,
        [ContactId::SELF]
    );

    let sent_msg = alice0.send_text(a0_chat_id, "hi").await;
    let msg = alice1.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, a1_chat_id);
    assert_eq!(a1_chat_id.is_promoted(alice1).await?, true);
    Ok(())
}

/// Tests sending JPEG image with .png extension.
///
/// This is a regression test, previously sending failed
/// because image was passed to PNG decoder
/// and it failed to decode image.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_jpeg_with_png_ext() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let bytes = include_bytes!("../../test-data/image/screenshot.jpg");
    let file = alice.get_blobdir().join("screenshot.png");
    tokio::fs::write(&file, bytes).await?;
    let mut msg = Message::new(Viewtype::Image);
    msg.set_file_and_deduplicate(&alice, &file, Some("screenshot.png"), None)?;

    let alice_chat = alice.create_chat(&bob).await;
    let sent_msg = alice.send_msg(alice_chat.get_id(), &mut msg).await;
    let _msg = bob.recv_msg(&sent_msg).await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_nonimage_with_png_ext() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat = alice.create_chat(bob).await;

    let bytes = include_bytes!("../../test-data/message/thunderbird_with_autocrypt.eml");
    let file = alice.get_blobdir().join("screenshot.png");

    for vt in [Viewtype::Image, Viewtype::File] {
        tokio::fs::write(&file, bytes).await?;
        let mut msg = Message::new(vt);
        msg.set_file_and_deduplicate(alice, &file, Some("screenshot.png"), None)?;
        let sent_msg = alice.send_msg(alice_chat.get_id(), &mut msg).await;
        assert_eq!(msg.viewtype, Viewtype::File);
        assert_eq!(msg.get_filemime().unwrap(), "application/octet-stream");
        assert_eq!(
            msg.get_filename().unwrap().contains("screenshot"),
            vt == Viewtype::File
        );
        let msg_bob = bob.recv_msg(&sent_msg).await;
        assert_eq!(msg_bob.viewtype, Viewtype::File);
        assert_eq!(msg_bob.get_filemime().unwrap(), "application/octet-stream");
        assert_eq!(
            msg_bob.get_filename().unwrap().contains("screenshot"),
            vt == Viewtype::File
        );
    }
    Ok(())
}

/// Tests that info message is ignored when constructing `In-Reply-To`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_info_not_referenced() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let bob_received_message = tcm.send_recv_accept(alice, bob, "Hi!").await;
    let bob_chat_id = bob_received_message.chat_id;
    add_info_msg(bob, bob_chat_id, "Some info").await?;

    // Bob sends a message.
    // This message should reference Alice's "Hi!" message and not the info message.
    let sent = bob.send_text(bob_chat_id, "Hi hi!").await;
    let mime_message = alice.parse_msg(&sent).await;

    let in_reply_to = mime_message.get_header(HeaderDef::InReplyTo).unwrap();
    assert_eq!(
        in_reply_to,
        format!("<{}>", bob_received_message.rfc724_mid)
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_do_not_overwrite_draft() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let mut msg = Message::new_text("This is a draft message".to_string());
    let self_chat = alice.get_self_chat().await.id;
    self_chat.set_draft(&alice, Some(&mut msg)).await.unwrap();
    let draft1 = self_chat.get_draft(&alice).await?.unwrap();
    SystemTime::shift(Duration::from_secs(1));
    self_chat.set_draft(&alice, Some(&mut msg)).await.unwrap();
    let draft2 = self_chat.get_draft(&alice).await?.unwrap();
    assert_eq!(draft1.timestamp_sort, draft2.timestamp_sort);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_info_contact_id() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;

    async fn pop_recv_and_check(
        alice: &TestContext,
        alice2: &TestContext,
        bob: &TestContext,
        expected_type: SystemMessage,
        expected_alice_id: ContactId,
        expected_bob_id: ContactId,
    ) -> Result<()> {
        let sent_msg = alice.pop_sent_msg().await;
        let msg = sent_msg.load_from_db().await;
        assert_eq!(msg.get_info_type(), expected_type);
        assert_eq!(
            msg.get_info_contact_id(alice).await?,
            Some(expected_alice_id)
        );

        let msg = alice2.recv_msg(&sent_msg).await;
        assert_eq!(msg.get_info_type(), expected_type);
        assert_eq!(
            msg.get_info_contact_id(alice2).await?,
            Some(expected_alice_id)
        );

        let msg = bob.recv_msg(&sent_msg).await;
        assert_eq!(msg.get_info_type(), expected_type);
        assert_eq!(msg.get_info_contact_id(bob).await?, Some(expected_bob_id));

        Ok(())
    }

    // Alice creates group, Bob receives group
    let alice_chat_id = alice.create_group_with_members("play", &[bob]).await;
    let sent_msg1 = alice.send_text(alice_chat_id, "moin").await;

    let msg = bob.recv_msg(&sent_msg1).await;
    let bob_alice_id = msg.from_id;
    assert!(!bob_alice_id.is_special());

    // Alice does group changes, Bob receives them
    set_chat_name(alice, alice_chat_id, "games").await?;
    pop_recv_and_check(
        alice,
        alice2,
        bob,
        SystemMessage::GroupNameChanged,
        ContactId::SELF,
        bob_alice_id,
    )
    .await?;

    let file = alice.get_blobdir().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await?;
    set_chat_profile_image(alice, alice_chat_id, file.to_str().unwrap()).await?;
    pop_recv_and_check(
        alice,
        alice2,
        bob,
        SystemMessage::GroupImageChanged,
        ContactId::SELF,
        bob_alice_id,
    )
    .await?;

    alice_chat_id
        .set_ephemeral_timer(alice, Timer::Enabled { duration: 60 })
        .await?;
    pop_recv_and_check(
        alice,
        alice2,
        bob,
        SystemMessage::EphemeralTimerChanged,
        ContactId::SELF,
        bob_alice_id,
    )
    .await?;

    let alice_fiona_id = alice.add_or_lookup_contact_id(&tcm.fiona().await).await;
    let bob_fiona_id = bob.add_or_lookup_contact_id(&tcm.fiona().await).await;
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_id).await?;
    pop_recv_and_check(
        alice,
        alice2,
        bob,
        SystemMessage::MemberAddedToGroup,
        alice_fiona_id,
        bob_fiona_id,
    )
    .await?;

    remove_contact_from_chat(alice, alice_chat_id, alice_fiona_id).await?;
    pop_recv_and_check(
        alice,
        alice2,
        bob,
        SystemMessage::MemberRemovedFromGroup,
        alice_fiona_id,
        bob_fiona_id,
    )
    .await?;

    // When fiona_id is deleted, get_info_contact_id() returns None.
    // We raw delete in db as Contact::delete() leaves a tombstone (which is great as the tap works longer then)
    alice
        .sql
        .execute("DELETE FROM contacts WHERE id=?", (alice_fiona_id,))
        .await?;
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.get_info_type(), SystemMessage::MemberRemovedFromGroup);
    assert!(msg.get_info_contact_id(alice).await?.is_none());
    assert!(msg.get_info_contact_id(bob).await?.is_none());

    Ok(())
}

/// Test group consistency.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_member_bug() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(fiona).await;

    // Create a group.
    let alice_chat_id = create_group(alice, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;

    // Promote the group.
    let alice_sent_msg = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let bob_received_msg = bob.recv_msg(&alice_sent_msg).await;

    let bob_chat_id = bob_received_msg.get_chat_id();
    bob_chat_id.accept(bob).await?;

    // Alice removes Fiona from the chat.
    remove_contact_from_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    let _alice_sent_add_msg = alice.pop_sent_msg().await;

    SystemTime::shift(Duration::from_secs(3600));

    // Bob sends a message
    // to Alice and Fiona because he still has not received
    // a message about Fiona being removed.
    let bob_sent_msg = bob.send_text(bob_chat_id, "Hi Alice!").await;

    // Alice receives a message.
    // This should not add Fiona back.
    let _alice_received_msg = alice.recv_msg(&bob_sent_msg).await;

    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 2);

    Ok(())
}

/// Test that tombstones for past members are added to chats_contacts table
/// even if the row did not exist before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_past_members() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let fiona = &tcm.fiona().await;
    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(fiona).await;

    tcm.section("Alice creates a chat.");
    let alice_chat_id = create_group(alice, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;

    tcm.section("Alice removes Fiona from the chat.");
    remove_contact_from_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 1);

    tcm.section("Alice adds Bob to the chat.");
    let bob = &tcm.bob().await;
    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;

    tcm.section("Bob receives a message.");
    let add_message = alice.pop_sent_msg().await;
    let bob_add_message = bob.recv_msg(&add_message).await;
    let bob_chat_id = bob_add_message.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    assert_eq!(get_past_chat_contacts(bob, bob_chat_id).await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_non_member_cannot_modify_member_list() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;

    let alice_chat_id = create_group(alice, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    let alice_sent_msg = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let bob_received_msg = bob.recv_msg(&alice_sent_msg).await;
    let bob_chat_id = bob_received_msg.get_chat_id();
    bob_chat_id.accept(bob).await?;

    let fiona = &tcm.fiona().await;
    let bob_fiona_contact_id = bob.add_or_lookup_contact_id(fiona).await;

    // Alice removes Bob and Bob adds Fiona at the same time.
    remove_contact_from_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(bob, bob_chat_id, bob_fiona_contact_id).await?;

    let bob_sent_add_msg = bob.pop_sent_msg().await;

    // Alice ignores Bob's message because Bob is not a member.
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 1);
    alice.recv_msg_trash(&bob_sent_add_msg).await;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 1);

    // The same for removal.
    let bob_alice_contact_id = bob.add_or_lookup_contact_id(alice).await;
    remove_contact_from_chat(bob, bob_chat_id, bob_alice_contact_id).await?;
    let bob_sent_add_msg = bob.pop_sent_msg().await;
    alice.recv_msg_trash(&bob_sent_add_msg).await;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unpromoted_group_no_tombstones() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let fiona = &tcm.fiona().await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(fiona).await;

    let alice_chat_id = create_group(alice, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    remove_contact_from_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 2);

    // There should be no tombstone because the group is not promoted yet.
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    let sent = alice.send_text(alice_chat_id, "Hello group!").await;

    let bob_msg = bob.recv_msg(&sent).await;
    let bob_chat_id = bob_msg.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    assert_eq!(get_past_chat_contacts(bob, bob_chat_id).await?.len(), 0);

    Ok(())
}

/// Test that past members expire after 60 days.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_expire_past_members_after_60_days() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let fiona = &tcm.fiona().await;
    let alice_fiona_contact_id = alice.add_or_lookup_contact_id(fiona).await;

    let alice_chat_id = create_group(alice, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    remove_contact_from_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 1);

    SystemTime::shift(Duration::from_secs(60 * 24 * 60 * 60 + 1));
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    let bob = &tcm.bob().await;
    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;

    let add_message = alice.pop_sent_msg().await;
    let bob_add_message = bob.recv_msg(&add_message).await;
    let bob_chat_id = bob_add_message.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    assert_eq!(get_past_chat_contacts(bob, bob_chat_id).await?.len(), 0);

    Ok(())
}

/// Test that past members are ordered by the timestamp of their removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_past_members_order() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.alice().await;

    let bob = tcm.bob().await;
    let bob_contact_id = t.add_or_lookup_contact_id(&bob).await;
    let charlie = tcm.charlie().await;
    let charlie_contact_id = t.add_or_lookup_contact_id(&charlie).await;
    let fiona = tcm.fiona().await;
    let fiona_contact_id = t.add_or_lookup_contact_id(&fiona).await;

    let chat_id = create_group(t, "Group chat").await?;
    add_contact_to_chat(t, chat_id, bob_contact_id).await?;
    add_contact_to_chat(t, chat_id, charlie_contact_id).await?;
    add_contact_to_chat(t, chat_id, fiona_contact_id).await?;
    t.send_text(chat_id, "Hi! I created a group.").await;

    assert_eq!(get_past_chat_contacts(t, chat_id).await?.len(), 0);

    remove_contact_from_chat(t, chat_id, charlie_contact_id).await?;

    let past_contacts = get_past_chat_contacts(t, chat_id).await?;
    assert_eq!(past_contacts.len(), 1);
    assert_eq!(past_contacts[0], charlie_contact_id);

    SystemTime::shift(Duration::from_secs(5));
    remove_contact_from_chat(t, chat_id, bob_contact_id).await?;

    let past_contacts = get_past_chat_contacts(t, chat_id).await?;
    assert_eq!(past_contacts.len(), 2);
    assert_eq!(past_contacts[0], bob_contact_id);
    assert_eq!(past_contacts[1], charlie_contact_id);

    SystemTime::shift(Duration::from_secs(5));
    remove_contact_from_chat(t, chat_id, fiona_contact_id).await?;

    let past_contacts = get_past_chat_contacts(t, chat_id).await?;
    assert_eq!(past_contacts.len(), 3);
    assert_eq!(past_contacts[0], fiona_contact_id);
    assert_eq!(past_contacts[1], bob_contact_id);
    assert_eq!(past_contacts[2], charlie_contact_id);

    // Adding and removing Bob
    // moves him to the top of past member list.
    SystemTime::shift(Duration::from_secs(5));
    add_contact_to_chat(t, chat_id, bob_contact_id).await?;
    remove_contact_from_chat(t, chat_id, bob_contact_id).await?;

    let past_contacts = get_past_chat_contacts(t, chat_id).await?;
    assert_eq!(past_contacts.len(), 3);
    assert_eq!(past_contacts[0], bob_contact_id);
    assert_eq!(past_contacts[1], fiona_contact_id);
    assert_eq!(past_contacts[2], charlie_contact_id);

    Ok(())
}

/// Test the case when Alice restores a backup older than 60 days
/// with outdated member list.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_restore_backup_after_60_days() -> Result<()> {
    let backup_dir = tempfile::tempdir()?;

    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;
    let fiona = &tcm.fiona().await;

    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    let alice_charlie_contact_id = alice.add_or_lookup_contact_id(charlie).await;

    let alice_chat_id = create_group(alice, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(alice, alice_chat_id, alice_charlie_contact_id).await?;

    let alice_sent_promote = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let bob_rcvd_promote = bob.recv_msg(&alice_sent_promote).await;
    let bob_chat_id = bob_rcvd_promote.chat_id;
    bob_chat_id.accept(bob).await?;

    // Alice exports a backup.
    imex(alice, ImexMode::ExportBackup, backup_dir.path(), None).await?;

    remove_contact_from_chat(alice, alice_chat_id, alice_charlie_contact_id).await?;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 2);
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 1);

    let remove_message = alice.pop_sent_msg().await;
    bob.recv_msg(&remove_message).await;

    // 60 days pass.
    SystemTime::shift(Duration::from_secs(60 * 24 * 60 * 60 + 1));

    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    // Bob adds Fiona to the chat.
    let bob_fiona_contact_id = bob.add_or_lookup_contact_id(fiona).await;
    add_contact_to_chat(bob, bob_chat_id, bob_fiona_contact_id).await?;

    let add_message = bob.pop_sent_msg().await;
    alice.recv_msg(&add_message).await;
    let fiona_add_message = fiona.recv_msg(&add_message).await;
    let fiona_chat_id = fiona_add_message.chat_id;
    fiona_chat_id.accept(fiona).await?;

    // Fiona does not learn about Charlie,
    // even from `Chat-Group-Past-Members`, because tombstone has expired.
    assert_eq!(get_chat_contacts(fiona, fiona_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(fiona, fiona_chat_id).await?.len(), 0);

    // Fiona sends a message
    // so chat is not stale for Bob again.
    // Alice also receives the message,
    // but will import a backup immediately afterwards,
    // so it does not matter.
    let fiona_sent_message = fiona.send_text(fiona_chat_id, "Hi!").await;
    alice.recv_msg(&fiona_sent_message).await;
    bob.recv_msg(&fiona_sent_message).await;

    tcm.section("Alice imports old backup");
    let alice = &tcm.unconfigured().await;
    let backup = has_backup(alice, backup_dir.path()).await?;
    imex(alice, ImexMode::ImportBackup, backup.as_ref(), None).await?;

    // Alice thinks Charlie is in the chat, but does not know about Fiona.
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(bob, bob_chat_id).await?.len(), 0);

    assert_eq!(get_chat_contacts(fiona, fiona_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(fiona, fiona_chat_id).await?.len(), 0);

    // Bob sends a text message to the chat, without a tombstone for Charlie.
    // Alice learns about Fiona.
    let bob_sent_text = bob.send_text(bob_chat_id, "Message.").await;

    tcm.section("Alice sends a message to stale chat");
    let alice_sent_text = alice
        .send_text(alice_chat_id, "Hi! I just restored a backup.")
        .await;

    tcm.section("Alice sent a message to stale chat");
    alice.recv_msg(&bob_sent_text).await;
    fiona.recv_msg(&bob_sent_text).await;

    // Alice did not knew that Charlie is not part of the group
    // when sending a message, so sent it to Charlie.
    bob.recv_msg(&alice_sent_text).await;
    charlie.recv_msg(&alice_sent_text).await;

    // Alice should have learned about Charlie not being part of the group
    // by receiving Bob's message.
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 3);
    assert!(!is_contact_in_chat(alice, alice_chat_id, alice_charlie_contact_id).await?);
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    // This should not add or restore Charlie for Bob and Fiona,
    // Charlie is not part of the chat.
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(bob, bob_chat_id).await?.len(), 0);
    let bob_charlie_contact_id = bob.add_or_lookup_contact_id(charlie).await;
    assert!(!is_contact_in_chat(bob, bob_chat_id, bob_charlie_contact_id).await?);

    assert_eq!(get_chat_contacts(fiona, fiona_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(fiona, fiona_chat_id).await?.len(), 0);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_one_to_one_chat_no_group_member_timestamps() {
    let t = TestContext::new_alice().await;
    let chat = t.create_chat_with_contact("bob", "bob@example.com").await;
    let sent = t.send_text(chat.id, "Hi!").await;
    let payload = sent.payload;
    assert!(!payload.contains("Chat-Group-Member-Timestamps:"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_edit_request() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat = alice.create_chat(bob).await;

    // Alice sends a message with typos, followed by a correction message
    let sent1 = alice.send_text(alice_chat.id, "zext me in delra.cat").await;
    let alice_msg = sent1.load_from_db().await;
    assert_eq!(alice_msg.text, "zext me in delra.cat");

    send_edit_request(alice, alice_msg.id, "Text me on Delta.Chat".to_string()).await?;
    let sent2 = alice.pop_sent_msg().await;
    let test = Message::load_from_db(alice, alice_msg.id).await?;
    assert_eq!(test.text, "Text me on Delta.Chat");

    // Bob receives both messages and has the correct text at the end
    let bob_msg = bob.recv_msg(&sent1).await;
    assert_eq!(bob_msg.text, "zext me in delra.cat");

    bob.recv_msg_opt(&sent2).await;
    let test = Message::load_from_db(bob, bob_msg.id).await?;
    assert_eq!(test.text, "Text me on Delta.Chat");
    assert!(test.is_edited());

    // alice has another device, and sees the correction also there
    let alice2 = tcm.alice().await;
    let alice2_msg = alice2.recv_msg(&sent1).await;
    assert_eq!(alice2_msg.text, "zext me in delra.cat");

    alice2.recv_msg_opt(&sent2).await;
    let test = Message::load_from_db(&alice2, alice2_msg.id).await?;
    assert_eq!(test.text, "Text me on Delta.Chat");
    assert!(test.is_edited());

    // Alice forwards the edited message, the new message shouldn't have the "edited" mark.
    forward_msgs(&alice2, &[test.id], test.chat_id).await?;
    let forwarded = alice2.get_last_msg().await;
    assert!(!forwarded.is_edited());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_edit_saved_messages() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice1 = &tcm.alice().await;
    let alice2 = &tcm.alice().await;

    alice1.set_config_bool(Config::BccSelf, true).await?;
    alice2.set_config_bool(Config::BccSelf, true).await?;

    let alice1_chat_id = ChatId::create_for_contact(alice1, ContactId::SELF).await?;
    let alice1_sent_msg = alice1.send_text(alice1_chat_id, "Original message").await;
    let alice1_msg_id = alice1_sent_msg.sender_msg_id;
    let received_msg = alice2.recv_msg(&alice1_sent_msg).await;
    assert_eq!(received_msg.text, "Original message");

    send_edit_request(alice1, alice1_msg_id, "Edited message".to_string()).await?;
    alice2.recv_msg_trash(&alice1.pop_sent_msg().await).await;
    let received_msg = Message::load_from_db(alice2, received_msg.id).await?;
    assert_eq!(received_msg.text, "Edited message");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_edit_request_after_removal() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat = alice.create_chat(bob).await;

    // Alice sends a messag with typos, followed by a correction message
    let sent1 = alice.send_text(alice_chat.id, "zext me in delra.cat").await;
    let alice_msg = sent1.load_from_db().await;
    send_edit_request(alice, alice_msg.id, "Text me on Delta.Chat".to_string()).await?;
    let sent2 = alice.pop_sent_msg().await;

    // Bob receives first message, deletes it and then ignores the correction
    let bob_msg = bob.recv_msg(&sent1).await;
    let bob_chat_id = bob_msg.chat_id;
    assert_eq!(bob_msg.text, "zext me in delra.cat");
    assert_eq!(bob_chat_id.get_msg_cnt(bob).await?, E2EE_INFO_MSGS + 1);

    delete_msgs(bob, &[bob_msg.id]).await?;
    assert_eq!(bob_chat_id.get_msg_cnt(bob).await?, E2EE_INFO_MSGS);

    bob.recv_msg_trash(&sent2).await;
    assert_eq!(bob_chat_id.get_msg_cnt(bob).await?, E2EE_INFO_MSGS);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cannot_send_edit_request() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let chat_id = alice.create_group_with_members("My Group", &[bob]).await;

    // Alice can edit her message
    let sent1 = alice.send_text(chat_id, "foo").await;
    send_edit_request(alice, sent1.sender_msg_id, "bar".to_string()).await?;

    // Bob cannot edit Alice's message
    let msg = bob.recv_msg(&sent1).await;
    assert!(
        send_edit_request(bob, msg.id, "bar".to_string())
            .await
            .is_err()
    );

    // HTML messages cannot be edited
    let mut msg = Message::new_text("plain text".to_string());
    msg.set_html(Some("<b>html</b> text".to_string()));
    let sent2 = alice.send_msg(chat_id, &mut msg).await;
    assert!(msg.has_html());
    assert!(
        send_edit_request(alice, sent2.sender_msg_id, "foo".to_string())
            .await
            .is_err()
    );

    // Info messages cannot be edited
    set_chat_name(alice, chat_id, "bar").await?;
    let msg = alice.get_last_msg().await;
    assert!(msg.is_info());
    assert_eq!(msg.from_id, ContactId::SELF);
    assert!(
        send_edit_request(alice, msg.id, "bar".to_string())
            .await
            .is_err()
    );

    // If not text was given initally, there is nothing to edit
    // (this also avoids complexity in UI element changes; focus is typos and rewordings)
    let mut msg = Message::new(Viewtype::File);
    msg.make_vcard(alice, &[ContactId::SELF]).await?;
    let sent3 = alice.send_msg(chat_id, &mut msg).await;
    assert!(msg.text.is_empty());
    assert!(
        send_edit_request(alice, sent3.sender_msg_id, "bar".to_string())
            .await
            .is_err()
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_delete_request() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat = alice.create_chat(bob).await;
    let bob_chat = bob.create_chat(alice).await;

    // Bobs sends a message to Alice, so Alice learns Bob's key
    let sent0 = bob.send_text(bob_chat.id, "¡ola!").await;
    alice.recv_msg(&sent0).await;

    // Alice sends a message, then sends a deletion request
    let sent1 = alice.send_text(alice_chat.id, "wtf").await;
    let alice_msg = sent1.load_from_db().await;
    assert_eq!(alice_chat.id.get_msg_cnt(alice).await?, E2EE_INFO_MSGS + 2);

    message::delete_msgs_ex(alice, &[alice_msg.id], true).await?;
    let sent2 = alice.pop_sent_msg().await;
    assert_eq!(alice_chat.id.get_msg_cnt(alice).await?, E2EE_INFO_MSGS + 1);

    // Bob receives both messages and has nothing the end
    let bob_msg = bob.recv_msg(&sent1).await;
    assert_eq!(bob_msg.text, "wtf");
    assert_eq!(bob_msg.chat_id.get_msg_cnt(bob).await?, E2EE_INFO_MSGS + 2);

    bob.recv_msg_opt(&sent2).await;
    assert_eq!(bob_msg.chat_id.get_msg_cnt(bob).await?, E2EE_INFO_MSGS + 1);

    // Alice has another device, and there is also nothing at the end
    let alice2 = &tcm.alice().await;
    alice2.recv_msg(&sent0).await;
    let alice2_msg = alice2.recv_msg(&sent1).await;
    assert_eq!(
        alice2_msg.chat_id.get_msg_cnt(alice2).await?,
        E2EE_INFO_MSGS + 2
    );

    alice2.recv_msg_opt(&sent2).await;
    assert_eq!(
        alice2_msg.chat_id.get_msg_cnt(alice2).await?,
        E2EE_INFO_MSGS + 1
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_delete_request_no_encryption() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let alice_chat = alice.create_email_chat(bob).await;

    // Alice sends a message, then tries to send a deletion request which fails.
    let sent1 = alice.send_text(alice_chat.id, "wtf").await;
    assert!(
        message::delete_msgs_ex(alice, &[sent1.sender_msg_id], true)
            .await
            .is_err()
    );
    sent1.load_from_db().await;
    assert_eq!(alice_chat.id.get_msg_cnt(alice).await?, 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_msgs_2ctx() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat = alice.create_chat(bob).await;
    let alice_sent = alice.send_text(alice_chat.id, "hi").await;
    let bob_alice_msg = bob.recv_msg(&alice_sent).await;
    let bob_chat_id = bob_alice_msg.chat_id;
    bob_chat_id.accept(bob).await?;

    let bob_text = "Hi, did you know we're using the same device so i have access to your profile?";
    let bob_sent = bob.send_text(bob_chat_id, bob_text).await;
    alice.recv_msg(&bob_sent).await;
    let alice_chat_len = alice_chat.id.get_msg_cnt(alice).await?;

    forward_msgs_2ctx(
        bob,
        &[bob_alice_msg.id, bob_sent.sender_msg_id],
        alice,
        alice_chat.id,
    )
    .await?;
    assert_eq!(alice_chat.id.get_msg_cnt(alice).await?, alice_chat_len + 2);
    let msg = alice.get_last_msg().await;
    assert!(msg.is_forwarded());
    assert_eq!(msg.text, bob_text);
    assert_eq!(msg.from_id, ContactId::SELF);

    let sent = alice.pop_sent_msg().await;
    let msg = bob.recv_msg(&sent).await;
    assert!(msg.is_forwarded());
    assert_eq!(msg.text, bob_text);
    assert_eq!(msg.from_id, bob_alice_msg.from_id);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_msgs_2ctx_with_file() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // First, establish a chat between Alice and Bob to have the chat IDs
    let alice_chat = alice.create_chat(bob).await;
    let alice_initial = alice.send_text(alice_chat.id, "hi").await;
    let bob_alice_msg = bob.recv_msg(&alice_initial).await;
    let bob_chat_id = bob_alice_msg.chat_id;
    bob_chat_id.accept(bob).await?;

    // Alice sends a message with an attached file to her self-chat
    let alice_self_chat = alice.get_self_chat().await;
    let file_bytes = b"test file content";
    let file = alice.get_blobdir().join("test.txt");
    tokio::fs::write(&file, file_bytes).await?;

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_and_deduplicate(alice, &file, Some("test.txt"), Some("text/plain"))?;
    msg.set_text("Here's a file".to_string());

    alice.send_msg(alice_self_chat.id, &mut msg).await;
    let alice_self_msg = alice.get_last_msg().await;

    // Verify the file exists in Alice's blobdir
    assert_eq!(alice_self_msg.viewtype, Viewtype::File);
    let alice_original_file_path = alice_self_msg.get_file(alice).unwrap();
    let alice_original_content = tokio::fs::read(&alice_original_file_path).await?;
    assert_eq!(alice_original_content, file_bytes);

    // Alice forwards the message to Bob using forward_msgs_2ctx
    forward_msgs_2ctx(alice, &[alice_self_msg.id], bob, bob_chat_id).await?;

    // Bob should have the forwarded message with the file in his database
    let bob_msg = bob.get_last_msg().await;
    assert_eq!(bob_msg.viewtype, Viewtype::File);
    assert!(bob_msg.is_forwarded());
    assert_eq!(bob_msg.text, "Here's a file");
    assert_eq!(bob_msg.from_id, ContactId::SELF);

    // Verify Bob has the file in his blobdir with correct content
    let bob_file_path = bob_msg.get_file(bob).unwrap();
    let bob_file_content = tokio::fs::read(&bob_file_path).await?;
    assert_eq!(bob_file_content, file_bytes);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_msgs_2ctx_missing_blob() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat = alice.create_chat(bob).await;
    let alice_initial = alice.send_text(alice_chat.id, "hi").await;
    let bob_alice_msg = bob.recv_msg(&alice_initial).await;
    let bob_chat_id = bob_alice_msg.chat_id;
    bob_chat_id.accept(bob).await?;
    // Alice sends a file to her self-chat
    let alice_self_chat = alice.get_self_chat().await;
    let file_bytes = b"test content";
    let file = alice.get_blobdir().join("test.txt");
    tokio::fs::write(&file, file_bytes).await?;

    let mut msg = Message::new(Viewtype::File);
    msg.set_file_and_deduplicate(alice, &file, Some("test.txt"), Some("text/plain"))?;
    msg.set_text("File message".to_string());

    alice.send_msg(alice_self_chat.id, &mut msg).await;
    let alice_self_msg = alice.get_last_msg().await;

    // Delete the blob file from Alice's blobdir to simulate a missing file
    let alice_file_path = alice_self_msg.get_file(alice).unwrap();
    tokio::fs::remove_file(&alice_file_path).await?;

    // Alice tries to forward the message - this should fail with an error
    let result = forward_msgs_2ctx(alice, &[alice_self_msg.id], bob, bob_chat_id).await;
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("Failed to copy blob file")
    );

    Ok(())
}

/// Tests that in multi-device setup
/// second device learns the key of a contact
/// via Autocrypt-Gossip in 1:1 chats.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_oneone_gossip() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice2 = &tcm.alice().await;
    let bob = &tcm.bob().await;

    tcm.section("Alice imports Bob's vCard and sends a message from the first device");
    let alice_chat = alice.create_chat(bob).await;
    let sent_msg = alice.send_text(alice_chat.id, "Hello Bob!").await;

    tcm.section("Alice receives a copy on second device");
    let rcvd_msg = alice2.recv_msg(&sent_msg).await;
    assert_eq!(rcvd_msg.get_showpadlock(), true);

    tcm.section("Alice sends a message from the second device");
    let alice2_chat_id = rcvd_msg.chat_id;
    let sent_msg2 = alice2
        .send_text(alice2_chat_id, "Hello from second device!")
        .await;

    tcm.section("Bob receives a message from the second device");
    let rcvd_msg2 = bob.recv_msg(&sent_msg2).await;
    assert_eq!(rcvd_msg2.get_showpadlock(), true);
    assert_eq!(rcvd_msg2.text, "Hello from second device!");

    tcm.section("Alice sends another message from the first devicer");
    let sent_msg3 = alice.send_text(alice_chat.id, "Hello again, Bob!").await;

    // This message has no Autocrypt-Gossip header,
    // but should still be assigned to key-contact.
    tcm.section("Alice receives a copy of another message on second device");
    let rcvd_msg3 = alice2.recv_msg(&sent_msg3).await;
    assert_eq!(rcvd_msg3.get_showpadlock(), true);
    assert_eq!(rcvd_msg3.chat_id, rcvd_msg.chat_id);

    // Check that there was no gossip.
    let parsed_msg3 = alice2.parse_msg(&sent_msg3).await;
    assert!(!parsed_msg3.header_exists(HeaderDef::AutocryptGossip));

    Ok(())
}

/// Tests that address-contacts cannot be added to encrypted group chats.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_address_contacts_in_group_chats() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    let chat_id = create_group(alice, "Group chat").await?;
    let bob_key_contact_id = alice.add_or_lookup_contact_id(bob).await;
    let charlie_address_contact_id = alice.add_or_lookup_address_contact_id(charlie).await;

    // key-contact should be added successfully.
    add_contact_to_chat(alice, chat_id, bob_key_contact_id).await?;

    // Adding address-contact should fail.
    let res = add_contact_to_chat(alice, chat_id, charlie_address_contact_id).await;
    assert!(res.is_err());

    Ok(())
}

/// Tests that key-contacts cannot be added to ad hoc groups.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_key_contacts_in_adhoc_chats() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    let chat_id = receive_imf(
        alice,
        b"Subject: Email thread\r\n\
          From: alice@example.org\r\n\
          To: Bob <bob@example.net>, Fiona <fiona@example.net>\r\n\
          Date: Mon, 2 Dec 2023 16:59:39 +0000\r\n\
          Message-ID: <alice-mail@example.org>\r\n\
          \r\n\
          Starting a new thread\r\n",
        false,
    )
    .await?
    .unwrap()
    .chat_id;

    let bob_address_contact_id = alice.add_or_lookup_address_contact_id(bob).await;
    let charlie_key_contact_id = alice.add_or_lookup_contact_id(charlie).await;

    // Address-contact should be added successfully.
    add_contact_to_chat(alice, chat_id, bob_address_contact_id).await?;

    // Adding key-contact should fail.
    let res = add_contact_to_chat(alice, chat_id, charlie_key_contact_id).await;
    assert!(res.is_err());

    Ok(())
}

/// Tests that key-contacts cannot be added to an unencrypted (ad hoc) group and the group and
/// messages report that they are unencrypted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_unencrypted_group_chat() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let charlie = &tcm.charlie().await;

    let chat_id = create_group_unencrypted(alice, "Group chat").await?;
    let bob_key_contact_id = alice.add_or_lookup_contact_id(bob).await;
    let charlie_address_contact_id = alice.add_or_lookup_address_contact_id(charlie).await;

    let res = add_contact_to_chat(alice, chat_id, bob_key_contact_id).await;
    assert!(res.is_err());

    add_contact_to_chat(alice, chat_id, charlie_address_contact_id).await?;

    let chat = Chat::load_from_db(alice, chat_id).await?;
    assert!(!chat.is_encrypted(alice).await?);
    let sent_msg = alice.send_text(chat_id, "Hello").await;
    let msg = Message::load_from_db(alice, sent_msg.sender_msg_id).await?;
    assert!(!msg.get_showpadlock());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_group_invalid_name() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let chat_id = create_group(alice, " ").await?;
    let chat = Chat::load_from_db(alice, chat_id).await?;
    assert_eq!(chat.get_name(), "…");
    Ok(())
}

/// Tests that avatar cannot be set in ad hoc groups.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_no_avatar_in_adhoc_chats() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;

    let chat_id = receive_imf(
        alice,
        b"Subject: Email thread\r\n\
          From: alice@example.org\r\n\
          To: Bob <bob@example.net>, Fiona <fiona@example.net>\r\n\
          Date: Mon, 2 Dec 2023 16:59:39 +0000\r\n\
          Message-ID: <alice-mail@example.org>\r\n\
          \r\n\
          Starting a new thread\r\n",
        false,
    )
    .await?
    .unwrap()
    .chat_id;

    // Test that setting avatar in ad hoc group is not possible.
    let file = alice.dir.path().join("avatar.png");
    let bytes = include_bytes!("../../test-data/image/avatar64x64.png");
    tokio::fs::write(&file, bytes).await?;
    let res = set_chat_profile_image(alice, chat_id, file.to_str().unwrap()).await;
    assert!(res.is_err());

    Ok(())
}

/// Tests that long group name with non-ASCII characters is correctly received
/// by other members.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_long_group_name() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let group_name = "δδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδδ";
    let alice_chat_id = create_group(alice, group_name).await?;
    let alice_bob_contact_id = alice.add_or_lookup_contact_id(bob).await;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    let sent = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let bob_chat_id = bob.recv_msg(&sent).await.chat_id;
    let bob_chat = Chat::load_from_db(bob, bob_chat_id).await?;
    assert_eq!(bob_chat.name, group_name);

    Ok(())
}

/// Regression test for the case
/// when Bob leaves the group, joins back and deletes the chat.
/// Previously this resulted in the group
/// never appearing again without removing Bob
/// and readding back because the group was
/// recorded in `leftgrps` for Bob and everyone else
/// thought that Bob is part of the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_leftgrps() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    // Alice creates a group with Bob and Bob accepts it.
    let bob_id = alice.add_or_lookup_contact_id(bob).await;
    let alice_chat_id = create_group(alice, "Group").await?;
    add_contact_to_chat(alice, alice_chat_id, bob_id).await?;
    let alice_sent = alice.send_text(alice_chat_id, "Hi!").await;
    let bob_chat_id = bob.recv_msg(&alice_sent).await.chat_id;
    bob_chat_id.accept(bob).await?;

    // Bob leaves the group.
    remove_contact_from_chat(bob, bob_chat_id, ContactId::SELF).await?;
    let bob_sent = bob.pop_sent_msg().await;
    alice.recv_msg(&bob_sent).await;

    // Alice adds Bob back, Bob recognizes that the chat is the same.
    add_contact_to_chat(alice, alice_chat_id, bob_id).await?;
    let alice_sent = alice.pop_sent_msg().await;
    let bob_chat_id2 = bob.recv_msg(&alice_sent).await.chat_id;
    assert_eq!(bob_chat_id, bob_chat_id2);

    // Bob deletes the chat.
    bob_chat_id.delete(bob).await?;
    let alice_sent = alice.send_text(alice_chat_id, "Hi again!").await;
    let bob_chat_id3 = bob.recv_msg(&alice_sent).await.chat_id;

    // Chat ID is new, but not a trash chat.
    assert_ne!(bob_chat_id3, bob_chat_id);
    assert!(!bob_chat_id3.is_special());

    Ok(())
}
