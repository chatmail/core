use super::*;
use crate::chatlist::get_archived_cnt;
use crate::constants::{DC_GCL_ARCHIVED_ONLY, DC_GCL_NO_SPECIALS};
use crate::headerdef::HeaderDef;
use crate::message::{delete_msgs, MessengerMessage};
use crate::receive_imf::receive_imf;
use crate::test_utils::{sync, TestContext, TestContextManager, TimeShiftFalsePositiveNote};
use strum::IntoEnumIterator;
use tokio::fs;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_chat_info() {
    let t = TestContext::new().await;
    let chat = t.create_chat_with_contact("bob", "bob@example.com").await;
    let info = chat.get_info(&t).await.unwrap();

    // Ensure we can serialize this.
    println!("{}", serde_json::to_string_pretty(&info).unwrap());

    let expected = r#"
            {
                "id": 10,
                "type": 100,
                "name": "bob",
                "archived": false,
                "param": "",
                "gossiped_timestamp": 0,
                "is_sending_locations": false,
                "color": 35391,
                "profile_image": "",
                "draft": "",
                "is_muted": false,
                "ephemeral_timer": "Disabled"
            }
        "#;

    // Ensure we can deserialize this.
    let loaded: ChatInfo = serde_json::from_str(expected).unwrap();
    assert_eq!(info, loaded);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_draft_no_draft() {
    let t = TestContext::new().await;
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
    let t = TestContext::new().await;
    let draft = ChatId::new(42).get_draft(&t).await.unwrap();
    assert!(draft.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_draft() {
    let t = TestContext::new().await;
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
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "abc").await?;

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

    let chat_id2 = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
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
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "abc").await?;

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
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "chat").await?;
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

    let grp_chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "grp").await?;
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
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo")
        .await
        .unwrap();
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

    // Disable encryption so we can inspect raw message contents.
    alice.set_config(Config::E2eeEnabled, Some("0")).await?;
    bob.set_config(Config::E2eeEnabled, Some("0")).await?;

    // Create contact for Bob on the Alice side with name "robert".
    let alice_bob_contact_id = Contact::create(&alice, "robert", "bob@example.net").await?;

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

    // Create and promote a group.
    let alice_chat_id =
        create_group_chat(&alice, ProtectionStatus::Unprotected, "Group chat").await?;
    let alice_fiona_contact_id = Contact::create(&alice, "Fiona", "fiona@example.net").await?;
    add_contact_to_chat(&alice, alice_chat_id, alice_fiona_contact_id).await?;
    let sent = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    assert!(sent.payload.contains("Hi! I created a group."));

    // Alice adds Bob to the chat.
    add_contact_to_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    let sent = alice.pop_sent_msg().await;
    assert!(sent
        .payload
        .contains("I added member Bob (bob@example.net)."));
    // Locally set name "robert" should not leak.
    assert!(!sent.payload.contains("robert"));
    assert_eq!(
        sent.load_from_db().await.get_text(),
        "You added member robert (bob@example.net)."
    );

    // Alice removes Bob from the chat.
    remove_contact_from_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    let sent = alice.pop_sent_msg().await;
    assert!(sent
        .payload
        .contains("I removed member Bob (bob@example.net)."));
    assert!(!sent.payload.contains("robert"));
    assert_eq!(
        sent.load_from_db().await.get_text(),
        "You removed member robert (bob@example.net)."
    );

    // Alice leaves the chat.
    remove_contact_from_chat(&alice, alice_chat_id, ContactId::SELF).await?;
    let sent = alice.pop_sent_msg().await;
    assert!(sent.payload.contains("I left the group."));
    assert_eq!(sent.load_from_db().await.get_text(), "You left the group.");

    Ok(())
}

/// Test parallel removal of user from the chat and leaving the group.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel_member_remove() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    alice.set_config(Config::E2eeEnabled, Some("0")).await?;
    bob.set_config(Config::E2eeEnabled, Some("0")).await?;

    let alice_bob_contact_id = Contact::create(&alice, "Bob", "bob@example.net").await?;
    let alice_fiona_contact_id = Contact::create(&alice, "Fiona", "fiona@example.net").await?;
    let alice_claire_contact_id = Contact::create(&alice, "Claire", "claire@example.net").await?;

    // Create and promote a group.
    let alice_chat_id =
        create_group_chat(&alice, ProtectionStatus::Unprotected, "Group chat").await?;
    add_contact_to_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(&alice, alice_chat_id, alice_fiona_contact_id).await?;
    let alice_sent_msg = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let bob_received_msg = bob.recv_msg(&alice_sent_msg).await;

    let bob_chat_id = bob_received_msg.get_chat_id();
    bob_chat_id.accept(&bob).await?;

    // Alice adds Claire to the chat.
    add_contact_to_chat(&alice, alice_chat_id, alice_claire_contact_id).await?;
    let alice_sent_add_msg = alice.pop_sent_msg().await;

    // Bob leaves the chat.
    remove_contact_from_chat(&bob, bob_chat_id, ContactId::SELF).await?;
    bob.pop_sent_msg().await;

    // Bob receives a msg about Alice adding Claire to the group.
    bob.recv_msg(&alice_sent_add_msg).await;

    SystemTime::shift(Duration::from_secs(3600));

    // Alice sends a message to Bob because the message about leaving is lost.
    let alice_sent_msg = alice.send_text(alice_chat_id, "What a silence!").await;
    bob.recv_msg(&alice_sent_msg).await;

    bob.golden_test_chat(bob_chat_id, "chat_test_parallel_member_remove")
        .await;

    // Alice removes Bob from the chat.
    remove_contact_from_chat(&alice, alice_chat_id, alice_bob_contact_id).await?;
    let alice_sent_remove_msg = alice.pop_sent_msg().await;

    // Bob receives a msg about Alice removing him from the group.
    let bob_received_remove_msg = bob.recv_msg(&alice_sent_remove_msg).await;

    // Test that remove message is rewritten.
    assert_eq!(
        bob_received_remove_msg.get_text(),
        "Member Me (bob@example.net) removed by alice@example.org."
    );

    Ok(())
}

/// Test that member removal is synchronized eventually even if the message is lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_msg_with_implicit_member_removed() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let alice_bob_contact_id =
        Contact::create(&alice, "Bob", &bob.get_config(Config::Addr).await?.unwrap()).await?;
    let fiona_addr = "fiona@example.net";
    let alice_fiona_contact_id = Contact::create(&alice, "Fiona", fiona_addr).await?;
    let bob_fiona_contact_id = Contact::create(&bob, "Fiona", fiona_addr).await?;
    let alice_chat_id =
        create_group_chat(&alice, ProtectionStatus::Unprotected, "Group chat").await?;
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
        .send_text(alice_chat_id, "I have removed Fiona some time ago.")
        .await;
    alice.recv_msg(&sent_msg).await;
    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_modify_chat_multi_device() -> Result<()> {
    let a1 = TestContext::new_alice().await;
    let a2 = TestContext::new_alice().await;
    a1.set_config_bool(Config::BccSelf, true).await?;

    // create group and sync it to the second device
    let a1_chat_id = create_group_chat(&a1, ProtectionStatus::Unprotected, "foo").await?;
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
    let bob = Contact::create(&a1, "", "bob@example.org").await?;
    add_contact_to_chat(&a1, a1_chat_id, bob).await?;
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
    assert_eq!(Chat::load_from_db(&a1, a1_chat_id).await?.name, "bar");
    assert_eq!(Chat::load_from_db(&a2, a2_chat_id).await?.name, "bar");

    // remove member from group
    remove_contact_from_chat(&a1, a1_chat_id, bob).await?;
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

    // Alice creates a group with Bob, Claire and Daisy and then removes Claire and Daisy
    // (time shift is needed as otherwise smeared time from Alice looks to Bob like messages from the future which are all set to "now" then)
    let alice = TestContext::new_alice().await;

    let bob_id = Contact::create(&alice, "", "bob@example.net").await?;
    let claire_id = Contact::create(&alice, "", "claire@foo.de").await?;
    let daisy_id = Contact::create(&alice, "", "daisy@bar.de").await?;

    let alice_chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "foo").await?;
    send_text_msg(&alice, alice_chat_id, "populate".to_string()).await?;

    add_contact_to_chat(&alice, alice_chat_id, bob_id).await?;
    let add1 = alice.pop_sent_msg().await;

    add_contact_to_chat(&alice, alice_chat_id, claire_id).await?;
    let add2 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    add_contact_to_chat(&alice, alice_chat_id, daisy_id).await?;
    let add3 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 4);

    remove_contact_from_chat(&alice, alice_chat_id, claire_id).await?;
    let remove1 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    remove_contact_from_chat(&alice, alice_chat_id, daisy_id).await?;
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
    let alice_chat_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "Group", &[bob])
        .await;
    let alice_sent = alice.send_text(alice_chat_id, "Hi!").await;
    let bob_chat_id = bob.recv_msg(&alice_sent).await.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);

    // Attempt to add member, but message is lost.
    let claire_id = Contact::create(alice, "", "claire@foo.de").await?;
    add_contact_to_chat(alice, alice_chat_id, claire_id).await?;
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

    let bob_id = Contact::create(&alice, "", "bob@example.net").await?;
    let claire_id = Contact::create(&alice, "", "claire@foo.de").await?;
    let daisy_id = Contact::create(&alice, "", "daisy@bar.de").await?;

    let alice_chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "foo").await?;
    add_contact_to_chat(&alice, alice_chat_id, bob_id).await?;
    add_contact_to_chat(&alice, alice_chat_id, claire_id).await?;
    add_contact_to_chat(&alice, alice_chat_id, daisy_id).await?;

    send_text_msg(&alice, alice_chat_id, "populate".to_string()).await?;
    let add = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    remove_contact_from_chat(&alice, alice_chat_id, claire_id).await?;
    let remove1 = alice.pop_sent_msg().await;
    SystemTime::shift(Duration::from_millis(1100));

    remove_contact_from_chat(&alice, alice_chat_id, daisy_id).await?;
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
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    // Create group chat with Bob.
    let alice_chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "foo").await?;
    let bob_contact = Contact::create(&alice, "", "bob@example.net").await?;
    add_contact_to_chat(&alice, alice_chat_id, bob_contact).await?;

    // Alice sends first message to group.
    let sent_msg = alice.send_text(alice_chat_id, "Hello!").await;
    let bob_msg = bob.recv_msg(&sent_msg).await;

    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 2);

    // Bob leaves the group.
    let bob_chat_id = bob_msg.chat_id;
    bob_chat_id.accept(&bob).await?;
    remove_contact_from_chat(&bob, bob_chat_id, ContactId::SELF).await?;

    let leave_msg = bob.pop_sent_msg().await;
    alice.recv_msg(&leave_msg).await;

    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 1);

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
    assert!(chat.get_profile_image(&t).await?.is_some());

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
    assert!(was_device_msg_ever_added(&t, "another-label")
        .await
        .unwrap());

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
    let t = TestContext::new().await;
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
    let t = TestContext::new().await;
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
    assert!(chat_id1
        .set_visibility(&t, ChatVisibility::Archived)
        .await
        .is_ok());
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
    assert!(chat_id2
        .set_visibility(&t, ChatVisibility::Archived)
        .await
        .is_ok());
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
    assert!(chat_id1
        .set_visibility(&t, ChatVisibility::Archived)
        .await
        .is_ok());
    assert!(chat_id2
        .set_visibility(&t, ChatVisibility::Normal)
        .await
        .is_ok());
    assert!(chat_id2
        .set_visibility(&t, ChatVisibility::Normal)
        .await
        .is_ok());
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
    add_info_msg(&t, chat_id, "info", time()).await?;
    assert_eq!(get_archived_cnt(&t).await?, 1);

    // finally, unarchive on sending to not muted chat
    set_muted(&t, chat_id, MuteDuration::NotMuted).await?;
    send_text_msg(&t, chat_id, "out2".to_string()).await?;
    assert_eq!(get_archived_cnt(&t).await?, 0);

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
    let t = TestContext::new().await;

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
    let chat_id3 = create_group_chat(&t, ProtectionStatus::Unprotected, "foo")
        .await
        .unwrap();

    let chatlist = get_chats_from_chat_list(&t, DC_GCL_NO_SPECIALS).await;
    assert_eq!(chatlist, vec![chat_id3, chat_id2, chat_id1]);

    // pin
    assert!(chat_id1
        .set_visibility(&t, ChatVisibility::Pinned)
        .await
        .is_ok());
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
    assert!(chat_id1
        .set_visibility(&t, ChatVisibility::Normal)
        .await
        .is_ok());
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

    assert!(alice_chat_id
        .set_visibility(&alice, ChatVisibility::Pinned)
        .await
        .is_ok());
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
    let t = TestContext::new().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo")
        .await
        .unwrap();
    assert_eq!(
        Chat::load_from_db(&t, chat_id).await.unwrap().get_name(),
        "foo"
    );

    set_chat_name(&t, chat_id, "bar").await.unwrap();
    assert_eq!(
        Chat::load_from_db(&t, chat_id).await.unwrap().get_name(),
        "bar"
    );
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
    let t = TestContext::new().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    assert!(!shall_attach_selfavatar(&t, chat_id).await?);

    let (contact_id, _) = Contact::add_or_lookup(
        &t,
        "",
        &ContactAddress::new("foo@bar.org")?,
        Origin::IncomingUnknownTo,
    )
    .await?;
    add_contact_to_chat(&t, chat_id, contact_id).await?;
    assert!(shall_attach_selfavatar(&t, chat_id).await?);

    chat_id.set_selfavatar_timestamp(&t, time()).await?;
    assert!(!shall_attach_selfavatar(&t, chat_id).await?);

    t.set_config(Config::Selfavatar, None).await?; // setting to None also forces re-sending
    assert!(shall_attach_selfavatar(&t, chat_id).await?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_mute_duration() {
    let t = TestContext::new().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo")
        .await
        .unwrap();
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
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    add_info_msg(&t, chat_id, "foo info", 200000).await?;

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
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let msg_id = add_info_msg_with_cmd(
        &t,
        chat_id,
        "foo bar info",
        SystemMessage::EphemeralTimerChanged,
        10000,
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
async fn test_group_with_removed_message_id() -> Result<()> {
    // Alice creates a group with Bob, sends a message to bob
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let alice_bob_contact = alice.add_or_lookup_contact(&bob).await;
    let contact_id = alice_bob_contact.id;
    let alice_chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "grp").await?;
    let alice_chat = Chat::load_from_db(&alice, alice_chat_id).await?;

    add_contact_to_chat(&alice, alice_chat_id, contact_id).await?;
    assert_eq!(get_chat_contacts(&alice, alice_chat_id).await?.len(), 2);
    send_text_msg(&alice, alice_chat_id, "hi!".to_string()).await?;
    assert_eq!(get_chat_msgs(&alice, alice_chat_id).await?.len(), 1);

    // Alice has an SMTP-server replacing the `Message-ID:`-header (as done eg. by outlook.com).
    let sent_msg = alice.pop_sent_msg().await;
    let msg = sent_msg.payload();
    assert_eq!(msg.match_indices("Message-ID: <").count(), 2);
    assert_eq!(msg.match_indices("References: <").count(), 1);
    let msg = msg.replace("Message-ID: <", "Message-ID: <X.X");
    assert_eq!(msg.match_indices("References: <").count(), 1);

    // Bob receives this message, he may detect group by `References:`- or `Chat-Group:`-header
    receive_imf(&bob, msg.as_bytes(), false).await.unwrap();
    let msg = bob.get_last_msg().await;

    let bob_chat = Chat::load_from_db(&bob, msg.chat_id).await?;
    assert_eq!(bob_chat.grpid, alice_chat.grpid);

    // Bob accepts contact request.
    bob_chat.id.unblock(&bob).await?;

    // Bob answers - simulate a normal MUA by not setting `Chat-*`-headers;
    // moreover, Bob's SMTP-server also replaces the `Message-ID:`-header
    send_text_msg(&bob, bob_chat.id, "ho!".to_string()).await?;
    let sent_msg = bob.pop_sent_msg().await;
    let msg = sent_msg.payload();
    let msg = msg.replace("Message-ID: <", "Message-ID: <X.X");
    let msg = msg.replace("Chat-", "XXXX-");
    assert_eq!(msg.match_indices("Chat-").count(), 0);

    // Alice receives this message - she can still detect the group by the `References:`-header
    receive_imf(&alice, msg.as_bytes(), false).await.unwrap();
    let msg = alice.get_last_msg().await;
    assert_eq!(msg.chat_id, alice_chat_id);
    assert_eq!(msg.text, "ho!".to_string());
    assert_eq!(get_chat_msgs(&alice, alice_chat_id).await?.len(), 2);
    Ok(())
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
    assert!(Chat::load_from_db(&t, chat_id)
        .await
        .unwrap()
        .is_contact_request());
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
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "a chat").await?;
    let color1 = Chat::load_from_db(&t, chat_id).await?.get_color(&t).await?;
    assert_eq!(color1, 0x008772);

    // upper-/lowercase makes a difference for the colors, these are different groups
    // (in contrast to email addresses, where upper-/lowercase is ignored in practise)
    let t = TestContext::new().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "A CHAT").await?;
    let color2 = Chat::load_from_db(&t, chat_id).await?.get_color(&t).await?;
    assert_ne!(color2, color1);
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
    let mime = sent_msg.payload();
    if res_viewtype == Viewtype::Sticker {
        assert_eq!(mime.match_indices("Chat-Content: sticker").count(), 1);
    }

    let msg = bob.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, bob_chat.id);
    assert_eq!(msg.get_viewtype(), res_viewtype);
    let msg_filename = msg.get_filename().unwrap();
    match res_viewtype {
        Viewtype::Sticker => assert_eq!(msg_filename, filename),
        Viewtype::Image => assert!(msg_filename.starts_with("image_")),
        _ => panic!("Not implemented"),
    }
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
async fn test_forward() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    let mut msg = Message::new_text("Hi Bob".to_owned());
    let sent_msg = alice.send_msg(alice_chat.get_id(), &mut msg).await;
    let msg = bob.recv_msg(&sent_msg).await;

    forward_msgs(&bob, &[msg.id], bob_chat.get_id()).await?;

    let forwarded_msg = bob.pop_sent_msg().await;
    let msg = alice.recv_msg(&forwarded_msg).await;
    assert_eq!(msg.get_text(), "Hi Bob");
    assert!(msg.is_forwarded());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_info_msg() -> Result<()> {
    let t = TestContext::new_alice().await;

    let chat_id1 = create_group_chat(&t, ProtectionStatus::Unprotected, "a").await?;
    send_text_msg(&t, chat_id1, "msg one".to_string()).await?;
    let bob_id = Contact::create(&t, "", "bob@example.net").await?;
    add_contact_to_chat(&t, chat_id1, bob_id).await?;
    let msg1 = t.get_last_msg_in(chat_id1).await;
    assert!(msg1.is_info());
    assert!(msg1.get_text().contains("bob@example.net"));

    let chat_id2 = ChatId::create_for_contact(&t, bob_id).await?;
    assert_eq!(get_chat_msgs(&t, chat_id2).await?.len(), 0);
    forward_msgs(&t, &[msg1.id], chat_id2).await?;
    let msg2 = t.get_last_msg_in(chat_id2).await;
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
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let alice_chat = alice.create_chat(&bob).await;
    let bob_chat = bob.create_chat(&alice).await;

    // Alice creates a group with Bob.
    let alice_group_chat_id =
        create_group_chat(&alice, ProtectionStatus::Unprotected, "Group").await?;
    let bob_id = Contact::create(&alice, "Bob", "bob@example.net").await?;
    let claire_id = Contact::create(&alice, "Claire", "claire@example.net").await?;
    add_contact_to_chat(&alice, alice_group_chat_id, bob_id).await?;
    add_contact_to_chat(&alice, alice_group_chat_id, claire_id).await?;
    let sent_group_msg = alice
        .send_text(alice_group_chat_id, "Hi Bob and Claire")
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
    // send a message from Alice to a group with Bob
    let alice = TestContext::new_alice().await;
    alice
        .set_config(Config::Displayname, Some("secretname"))
        .await?;
    let bob_id = Contact::create(&alice, "bob", "bob@example.net").await?;
    let group_id =
        create_group_chat(&alice, ProtectionStatus::Unprotected, "secretgrpname").await?;
    add_contact_to_chat(&alice, group_id, bob_id).await?;
    let mut msg = Message::new_text("bla foo".to_owned());
    let sent_msg = alice.send_msg(group_id, &mut msg).await;
    assert!(sent_msg.payload().contains("secretgrpname"));
    assert!(sent_msg.payload().contains("secretname"));
    assert!(sent_msg.payload().contains("alice"));

    // Bob forwards that message to Claire -
    // Claire should not get information about Alice for the original Group
    let bob = TestContext::new_bob().await;
    let orig_msg = bob.recv_msg(&sent_msg).await;
    let claire_id = Contact::create(&bob, "claire", "claire@foo").await?;
    let single_id = ChatId::create_for_contact(&bob, claire_id).await?;
    let group_id = create_group_chat(&bob, ProtectionStatus::Unprotected, "group2").await?;
    add_contact_to_chat(&bob, group_id, claire_id).await?;
    let broadcast_id = create_broadcast_list(&bob).await?;
    add_contact_to_chat(&bob, broadcast_id, claire_id).await?;
    for chat_id in &[single_id, group_id, broadcast_id] {
        forward_msgs(&bob, &[orig_msg.id], *chat_id).await?;
        let sent_msg = bob.pop_sent_msg().await;
        assert!(sent_msg
            .payload()
            .contains("---------- Forwarded message ----------"));
        assert!(!sent_msg.payload().contains("secretgrpname"));
        assert!(!sent_msg.payload().contains("secretname"));
        assert!(!sent_msg.payload().contains("alice"));
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_save_msgs() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;

    let sent = alice.send_text(alice_chat.get_id(), "hi, bob").await;
    let sent_msg = Message::load_from_db(&alice, sent.sender_msg_id).await?;
    assert!(sent_msg.get_saved_msg_id(&alice).await?.is_none());
    assert!(sent_msg.get_original_msg_id(&alice).await?.is_none());

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

    bob.recv_msg(&sent).await;
    let orig = bob.get_last_msg().await;
    let self_chat = bob.get_self_chat().await;
    save_msgs(&bob, &[orig.id]).await?;
    let saved1 = bob.get_last_msg().await;
    assert_eq!(
        saved1.get_original_msg_id(&bob).await?.unwrap(),
        sent.sender_msg_id
    );
    assert_ne!(saved1.from_id, ContactId::SELF);

    forward_msgs(&bob, &[saved1.id], self_chat.id).await?;
    let saved2 = bob.get_last_msg().await;
    assert!(saved2.get_original_msg_id(&bob).await?.is_none(),);
    assert_eq!(saved2.from_id, ContactId::SELF);

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
    let alice_grp = create_group_chat(&alice, ProtectionStatus::Unprotected, "grp").await?;
    add_contact_to_chat(
        &alice,
        alice_grp,
        Contact::create(&alice, "", "bob@example.net").await?,
    )
    .await?;
    let sent1 = alice.send_text(alice_grp, "alice->bob").await;

    // Alice adds Claire to group and resends her own initial message
    add_contact_to_chat(
        &alice,
        alice_grp,
        Contact::create(&alice, "", "claire@example.org").await?,
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
    assert_eq!(get_chat_msgs(&bob, msg.chat_id).await?.len(), 1);
    bob.recv_msg(&sent2).await;
    assert_eq!(get_chat_contacts(&bob, msg.chat_id).await?.len(), 3);
    assert_eq!(get_chat_msgs(&bob, msg.chat_id).await?.len(), 2);
    let received = bob.recv_msg_opt(&sent3).await;
    // No message should actually be added since we already know this message:
    assert!(received.is_none());
    assert_eq!(get_chat_contacts(&bob, msg.chat_id).await?.len(), 3);
    assert_eq!(get_chat_msgs(&bob, msg.chat_id).await?.len(), 2);

    // Claire does not receive the first message, however, due to resending, she has a similar view as Alice and Bob
    let claire = TestContext::new().await;
    claire.configure_addr("claire@example.org").await;
    claire.recv_msg(&sent2).await;
    let msg = claire.recv_msg(&sent3).await;
    assert_eq!(msg.get_text(), "alice->bob");
    assert_eq!(get_chat_contacts(&claire, msg.chat_id).await?.len(), 3);
    assert_eq!(get_chat_msgs(&claire, msg.chat_id).await?.len(), 2);
    let msg_from = Contact::get_by_id(&claire, msg.get_from_id()).await?;
    assert_eq!(msg_from.get_addr(), "alice@example.org");
    assert!(sent1_ts_sent < msg.timestamp_sent);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_foreign_message_fails() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let alice_grp = create_group_chat(&alice, ProtectionStatus::Unprotected, "grp").await?;
    add_contact_to_chat(
        &alice,
        alice_grp,
        Contact::create(&alice, "", "bob@example.net").await?,
    )
    .await?;
    let sent1 = alice.send_text(alice_grp, "alice->bob").await;

    let bob = TestContext::new_bob().await;
    let msg = bob.recv_msg(&sent1).await;
    assert!(resend_msgs(&bob, &[msg.id]).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_opportunistically_encryption() -> Result<()> {
    // Alice creates group with Bob and sends an initial message
    let alice = TestContext::new_alice().await;
    let alice_grp = create_group_chat(&alice, ProtectionStatus::Unprotected, "grp").await?;
    add_contact_to_chat(
        &alice,
        alice_grp,
        Contact::create(&alice, "", "bob@example.net").await?,
    )
    .await?;
    let sent1 = alice.send_text(alice_grp, "alice->bob").await;

    // Bob now can send an encrypted message
    let bob = TestContext::new_bob().await;
    let msg = bob.recv_msg(&sent1).await;
    assert!(!msg.get_showpadlock());

    msg.chat_id.accept(&bob).await?;
    let sent2 = bob.send_text(msg.chat_id, "bob->alice").await;
    let msg = bob.get_last_msg().await;
    assert!(msg.get_showpadlock());

    // Bob adds Claire and resends his last message: this will drop encryption in opportunistic chats
    add_contact_to_chat(
        &bob,
        msg.chat_id,
        Contact::create(&bob, "", "claire@example.org").await?,
    )
    .await?;
    let _sent3 = bob.pop_sent_msg().await;
    resend_msgs(&bob, &[sent2.sender_msg_id]).await?;
    let _sent4 = bob.pop_sent_msg().await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_info_message_fails() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let alice_grp = create_group_chat(&alice, ProtectionStatus::Unprotected, "grp").await?;
    add_contact_to_chat(
        &alice,
        alice_grp,
        Contact::create(&alice, "", "bob@example.net").await?,
    )
    .await?;
    alice.send_text(alice_grp, "alice->bob").await;

    add_contact_to_chat(
        &alice,
        alice_grp,
        Contact::create(&alice, "", "claire@example.org").await?,
    )
    .await?;
    let sent2 = alice.pop_sent_msg().await;
    assert!(resend_msgs(&alice, &[sent2.sender_msg_id]).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_can_send_group() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = Contact::create(&alice, "", "bob@f.br").await?;
    let chat_id = ChatId::create_for_contact(&alice, bob).await?;
    let chat = Chat::load_from_db(&alice, chat_id).await?;
    assert!(chat.can_send(&alice).await?);
    let chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "foo").await?;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast() -> Result<()> {
    // create two context, send two messages so both know the other
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let chat_alice = alice.create_chat(&bob).await;
    send_text_msg(&alice, chat_alice.id, "hi!".to_string()).await?;
    bob.recv_msg(&alice.pop_sent_msg().await).await;

    let chat_bob = bob.create_chat(&alice).await;
    send_text_msg(&bob, chat_bob.id, "ho!".to_string()).await?;
    let msg = alice.recv_msg(&bob.pop_sent_msg().await).await;
    assert!(msg.get_showpadlock());

    // test broadcast list
    let broadcast_id = create_broadcast_list(&alice).await?;
    add_contact_to_chat(
        &alice,
        broadcast_id,
        get_chat_contacts(&alice, chat_bob.id).await?.pop().unwrap(),
    )
    .await?;
    set_chat_name(&alice, broadcast_id, "Broadcast list").await?;
    {
        let chat = Chat::load_from_db(&alice, broadcast_id).await?;
        assert_eq!(chat.typ, Chattype::Broadcast);
        assert_eq!(chat.name, "Broadcast list");
        assert!(!chat.is_self_talk());

        send_text_msg(&alice, broadcast_id, "ola!".to_string()).await?;
        let msg = alice.get_last_msg().await;
        assert_eq!(msg.chat_id, chat.id);
    }

    {
        let msg = bob.recv_msg(&alice.pop_sent_msg().await).await;
        assert_eq!(msg.get_text(), "ola!");
        assert_eq!(msg.subject, "Broadcast list");
        assert!(!msg.get_showpadlock()); // avoid leaking recipients in encryption data
        let chat = Chat::load_from_db(&bob, msg.chat_id).await?;
        assert_eq!(chat.typ, Chattype::Mailinglist);
        assert_ne!(chat.id, chat_bob.id);
        assert_eq!(chat.name, "Broadcast list");
        assert!(!chat.is_self_talk());
    }

    {
        // Alice changes the name:
        set_chat_name(&alice, broadcast_id, "My great broadcast").await?;
        let sent = alice.send_text(broadcast_id, "I changed the title!").await;

        let msg = bob.recv_msg(&sent).await;
        assert_eq!(msg.subject, "Re: My great broadcast");
        let bob_chat = Chat::load_from_db(&bob, msg.chat_id).await?;
        assert_eq!(bob_chat.name, "My great broadcast");
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_broadcast_multidev() -> Result<()> {
    let alices = [
        TestContext::new_alice().await,
        TestContext::new_alice().await,
    ];
    let bob = TestContext::new_bob().await;
    let a1b_contact_id = alices[1].add_or_lookup_contact(&bob).await.id;

    let a0_broadcast_id = create_broadcast_list(&alices[0]).await?;
    let a0_broadcast_chat = Chat::load_from_db(&alices[0], a0_broadcast_id).await?;
    set_chat_name(&alices[0], a0_broadcast_id, "Broadcast list 42").await?;
    let sent_msg = alices[0].send_text(a0_broadcast_id, "hi").await;
    let msg = alices[1].recv_msg(&sent_msg).await;
    let a1_broadcast_id = get_chat_id_by_grpid(&alices[1], &a0_broadcast_chat.grpid)
        .await?
        .unwrap()
        .0;
    assert_eq!(msg.chat_id, a1_broadcast_id);
    let a1_broadcast_chat = Chat::load_from_db(&alices[1], a1_broadcast_id).await?;
    assert_eq!(a1_broadcast_chat.get_type(), Chattype::Broadcast);
    assert_eq!(a1_broadcast_chat.get_name(), "Broadcast list 42");
    assert!(get_chat_contacts(&alices[1], a1_broadcast_id)
        .await?
        .is_empty());

    add_contact_to_chat(&alices[1], a1_broadcast_id, a1b_contact_id).await?;
    set_chat_name(&alices[1], a1_broadcast_id, "Broadcast list 43").await?;
    let sent_msg = alices[1].send_text(a1_broadcast_id, "hi").await;
    let msg = alices[0].recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, a0_broadcast_id);
    let a0_broadcast_chat = Chat::load_from_db(&alices[0], a0_broadcast_id).await?;
    assert_eq!(a0_broadcast_chat.get_type(), Chattype::Broadcast);
    assert_eq!(a0_broadcast_chat.get_name(), "Broadcast list 42");
    assert!(get_chat_contacts(&alices[0], a0_broadcast_id)
        .await?
        .is_empty());

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
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    let contact_bob = Contact::create(&alice, "Bob", "bob@example.net").await?;
    let contact_fiona = Contact::create(&alice, "", "fiona@example.net").await?;

    let chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "Group").await?;
    assert_eq!(chat_id.get_encryption_info(&alice).await?, "");

    add_contact_to_chat(&alice, chat_id, contact_bob).await?;
    assert_eq!(
        chat_id.get_encryption_info(&alice).await?,
        "No encryption:\n\
            bob@example.net"
    );

    add_contact_to_chat(&alice, chat_id, contact_fiona).await?;
    assert_eq!(
        chat_id.get_encryption_info(&alice).await?,
        "No encryption:\n\
            fiona@example.net\n\
            bob@example.net"
    );

    let direct_chat = bob.create_chat(&alice).await;
    send_text_msg(&bob, direct_chat.id, "Hello!".to_string()).await?;
    alice.recv_msg(&bob.pop_sent_msg().await).await;

    assert_eq!(
        chat_id.get_encryption_info(&alice).await?,
        "No encryption:\n\
            fiona@example.net\n\
            \n\
            End-to-end encryption preferred:\n\
            bob@example.net"
    );

    bob.set_config(Config::E2eeEnabled, Some("0")).await?;
    send_text_msg(&bob, direct_chat.id, "Hello!".to_string()).await?;
    alice.recv_msg(&bob.pop_sent_msg().await).await;

    assert_eq!(
        chat_id.get_encryption_info(&alice).await?,
        "No encryption:\n\
            fiona@example.net\n\
            \n\
            End-to-end encryption available:\n\
            bob@example.net"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_chat_media() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id1 = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let chat_id2 = create_group_chat(&t, ProtectionStatus::Unprotected, "bar").await?;

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
async fn test_blob_renaming() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "Group").await?;
    add_contact_to_chat(
        &alice,
        chat_id,
        Contact::create(&alice, "bob", "bob@example.net").await?,
    )
    .await?;
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
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = TestContext::new_bob().await;

    let ba_chat = bob.create_chat(alice0).await;
    let sent_msg = bob.send_text(ba_chat.id, "hi").await;
    let a0b_chat_id = alice0.recv_msg(&sent_msg).await.chat_id;
    alice1.recv_msg(&sent_msg).await;
    let a0b_contact_id = alice0.add_or_lookup_contact(&bob).await.id;

    assert_eq!(alice1.get_chat(&bob).await.blocked, Blocked::Request);
    a0b_chat_id.accept(alice0).await?;
    sync(alice0, alice1).await;
    assert_eq!(alice1.get_chat(&bob).await.blocked, Blocked::Not);
    a0b_chat_id.block(alice0).await?;
    sync(alice0, alice1).await;
    assert_eq!(alice1.get_chat(&bob).await.blocked, Blocked::Yes);
    a0b_chat_id.unblock(alice0).await?;
    sync(alice0, alice1).await;
    assert_eq!(alice1.get_chat(&bob).await.blocked, Blocked::Not);

    // Unblocking a 1:1 chat doesn't unblock the contact currently.
    Contact::unblock(alice0, a0b_contact_id).await?;

    assert!(!alice1.add_or_lookup_contact(&bob).await.is_blocked());
    Contact::block(alice0, a0b_contact_id).await?;
    sync(alice0, alice1).await;
    assert!(alice1.add_or_lookup_contact(&bob).await.is_blocked());
    Contact::unblock(alice0, a0b_contact_id).await?;
    sync(alice0, alice1).await;
    assert!(!alice1.add_or_lookup_contact(&bob).await.is_blocked());

    // Test accepting and blocking groups. This way we test:
    // - Group chats synchronisation.
    // - That blocking a group deletes it on other devices.
    let fiona = TestContext::new_fiona().await;
    let fiona_grp_chat_id = fiona
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[alice0])
        .await;
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
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = TestContext::new_bob().await;

    let ba_chat = bob.create_chat(alice0).await;
    let sent_msg = bob.send_text(ba_chat.id, "hi").await;
    let a0b_chat_id = alice0.recv_msg(&sent_msg).await.chat_id;
    assert_eq!(alice0.get_chat(&bob).await.blocked, Blocked::Request);
    a0b_chat_id.accept(alice0).await?;
    let a0b_contact = alice0.add_or_lookup_contact(&bob).await;
    assert_eq!(a0b_contact.origin, Origin::CreateChat);
    assert_eq!(alice0.get_chat(&bob).await.blocked, Blocked::Not);

    sync(alice0, alice1).await;
    let a1b_contact = alice1.add_or_lookup_contact(&bob).await;
    assert_eq!(a1b_contact.origin, Origin::CreateChat);
    let a1b_chat = alice1.get_chat(&bob).await;
    assert_eq!(a1b_chat.blocked, Blocked::Not);
    let chats = Chatlist::try_load(alice1, 0, None, None).await?;
    assert_eq!(chats.len(), 1);

    let rcvd_msg = alice1.recv_msg(&sent_msg).await;
    assert_eq!(rcvd_msg.chat_id, a1b_chat.id);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_block_before_first_msg() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = TestContext::new_bob().await;

    let ba_chat = bob.create_chat(alice0).await;
    let sent_msg = bob.send_text(ba_chat.id, "hi").await;
    let a0b_chat_id = alice0.recv_msg(&sent_msg).await.chat_id;
    assert_eq!(alice0.get_chat(&bob).await.blocked, Blocked::Request);
    a0b_chat_id.block(alice0).await?;
    let a0b_contact = alice0.add_or_lookup_contact(&bob).await;
    assert_eq!(a0b_contact.origin, Origin::IncomingUnknownFrom);
    assert_eq!(alice0.get_chat(&bob).await.blocked, Blocked::Yes);

    sync(alice0, alice1).await;
    let a1b_contact = alice1.add_or_lookup_contact(&bob).await;
    assert_eq!(a1b_contact.origin, Origin::Hidden);
    assert!(ChatIdBlocked::lookup_by_contact(alice1, a1b_contact.id)
        .await?
        .is_none());

    let rcvd_msg = alice1.recv_msg(&sent_msg).await;
    let a1b_contact = alice1.add_or_lookup_contact(&bob).await;
    assert_eq!(a1b_contact.origin, Origin::IncomingUnknownFrom);
    let a1b_chat = alice1.get_chat(&bob).await;
    assert_eq!(a1b_chat.blocked, Blocked::Yes);
    assert_eq!(rcvd_msg.chat_id, a1b_chat.id);
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
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_muted() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_broadcast() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let bob = TestContext::new_bob().await;
    let a0b_contact_id = alice0.add_or_lookup_contact(&bob).await.id;

    let a0_broadcast_id = create_broadcast_list(alice0).await?;
    sync(alice0, alice1).await;
    let a0_broadcast_chat = Chat::load_from_db(alice0, a0_broadcast_id).await?;
    let a1_broadcast_id = get_chat_id_by_grpid(alice1, &a0_broadcast_chat.grpid)
        .await?
        .unwrap()
        .0;
    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    assert_eq!(a1_broadcast_chat.get_type(), Chattype::Broadcast);
    assert_eq!(a1_broadcast_chat.get_name(), a0_broadcast_chat.get_name());
    assert!(get_chat_contacts(alice1, a1_broadcast_id).await?.is_empty());
    add_contact_to_chat(alice0, a0_broadcast_id, a0b_contact_id).await?;
    sync(alice0, alice1).await;
    let a1b_contact_id = Contact::lookup_id_by_addr(
        alice1,
        &bob.get_config(Config::Addr).await?.unwrap(),
        Origin::Hidden,
    )
    .await?
    .unwrap();
    assert_eq!(
        get_chat_contacts(alice1, a1_broadcast_id).await?,
        vec![a1b_contact_id]
    );
    let sent_msg = alice1.send_text(a1_broadcast_id, "hi").await;
    let msg = bob.recv_msg(&sent_msg).await;
    let chat = Chat::load_from_db(&bob, msg.chat_id).await?;
    assert_eq!(chat.get_type(), Chattype::Mailinglist);
    let msg = alice0.recv_msg(&sent_msg).await;
    assert_eq!(msg.chat_id, a0_broadcast_id);
    remove_contact_from_chat(alice0, a0_broadcast_id, a0b_contact_id).await?;
    sync(alice0, alice1).await;
    assert!(get_chat_contacts(alice1, a1_broadcast_id).await?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_sync_name() -> Result<()> {
    let alice0 = &TestContext::new_alice().await;
    let alice1 = &TestContext::new_alice().await;
    for a in [alice0, alice1] {
        a.set_config_bool(Config::SyncMsgs, true).await?;
    }
    let a0_broadcast_id = create_broadcast_list(alice0).await?;
    sync(alice0, alice1).await;
    let a0_broadcast_chat = Chat::load_from_db(alice0, a0_broadcast_id).await?;
    set_chat_name(alice0, a0_broadcast_id, "Broadcast list 42").await?;
    sync(alice0, alice1).await;
    let a1_broadcast_id = get_chat_id_by_grpid(alice1, &a0_broadcast_chat.grpid)
        .await?
        .unwrap()
        .0;
    let a1_broadcast_chat = Chat::load_from_db(alice1, a1_broadcast_id).await?;
    assert_eq!(a1_broadcast_chat.get_type(), Chattype::Broadcast);
    assert_eq!(a1_broadcast_chat.get_name(), "Broadcast list 42");
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

/// Tests that info message is ignored when constructing `In-Reply-To`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_info_not_referenced() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let bob_received_message = tcm.send_recv_accept(alice, bob, "Hi!").await;
    let bob_chat_id = bob_received_message.chat_id;
    add_info_msg(bob, bob_chat_id, "Some info", create_smeared_timestamp(bob)).await?;

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

/// Test group consistency.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_add_member_bug() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_bob_contact_id = Contact::create(alice, "Bob", "bob@example.net").await?;
    let alice_fiona_contact_id = Contact::create(alice, "Fiona", "fiona@example.net").await?;

    // Create a group.
    let alice_chat_id =
        create_group_chat(alice, ProtectionStatus::Unprotected, "Group chat").await?;
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
    let alice_fiona_contact_id = Contact::create(alice, "Fiona", "fiona@example.net").await?;

    let alice_chat_id =
        create_group_chat(alice, ProtectionStatus::Unprotected, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    remove_contact_from_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 1);

    let bob = &tcm.bob().await;
    let bob_addr = bob.get_config(Config::Addr).await?.unwrap();
    let alice_bob_contact_id = Contact::create(alice, "Bob", &bob_addr).await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;

    let add_message = alice.pop_sent_msg().await;
    let bob_add_message = bob.recv_msg(&add_message).await;
    let bob_chat_id = bob_add_message.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    assert_eq!(get_past_chat_contacts(bob, bob_chat_id).await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_member_cannot_modify_member_list() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let bob_addr = bob.get_config(Config::Addr).await?.unwrap();
    let alice_bob_contact_id = Contact::create(alice, "Bob", &bob_addr).await?;

    let alice_chat_id =
        create_group_chat(alice, ProtectionStatus::Unprotected, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    let alice_sent_msg = alice
        .send_text(alice_chat_id, "Hi! I created a group.")
        .await;
    let bob_received_msg = bob.recv_msg(&alice_sent_msg).await;
    let bob_chat_id = bob_received_msg.get_chat_id();
    bob_chat_id.accept(bob).await?;

    let bob_fiona_contact_id = Contact::create(bob, "Fiona", "fiona@example.net").await?;

    // Alice removes Bob and Bob adds Fiona at the same time.
    remove_contact_from_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(bob, bob_chat_id, bob_fiona_contact_id).await?;

    let bob_sent_add_msg = bob.pop_sent_msg().await;

    // Alice ignores Bob's message because Bob is not a member.
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 1);
    alice.recv_msg_trash(&bob_sent_add_msg).await;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unpromoted_group_no_tombstones() -> Result<()> {
    let mut tcm = TestContextManager::new();

    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let bob_addr = bob.get_config(Config::Addr).await?.unwrap();
    let alice_bob_contact_id = Contact::create(alice, "Bob", &bob_addr).await?;
    let fiona_addr = "fiona@example.net";
    let alice_fiona_contact_id = Contact::create(alice, "Fiona", fiona_addr).await?;

    let alice_chat_id =
        create_group_chat(alice, ProtectionStatus::Unprotected, "Group chat").await?;
    add_contact_to_chat(alice, alice_chat_id, alice_bob_contact_id).await?;
    add_contact_to_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 3);
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    remove_contact_from_chat(alice, alice_chat_id, alice_fiona_contact_id).await?;
    assert_eq!(get_chat_contacts(alice, alice_chat_id).await?.len(), 2);

    // There should be no tombstone because the group is not promoted yet.
    assert_eq!(get_past_chat_contacts(alice, alice_chat_id).await?.len(), 0);

    let sent = alice.send_text(alice_chat_id, "Hello group!").await;
    let payload = sent.payload();
    assert_eq!(payload.contains("Hello group!"), true);
    assert_eq!(payload.contains(&bob_addr), true);
    assert_eq!(payload.contains(fiona_addr), false);

    let bob_msg = bob.recv_msg(&sent).await;
    let bob_chat_id = bob_msg.chat_id;
    assert_eq!(get_chat_contacts(bob, bob_chat_id).await?.len(), 2);
    assert_eq!(get_past_chat_contacts(bob, bob_chat_id).await?.len(), 0);

    Ok(())
}
