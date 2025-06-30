use std::time::Duration;

use regex::Regex;
use serde_json::json;

use super::*;
use crate::chat::{
    ChatId, ProtectionStatus, add_contact_to_chat, create_broadcast, create_group_chat,
    forward_msgs, remove_contact_from_chat, resend_msgs, send_msg, send_text_msg,
};
use crate::chatlist::Chatlist;
use crate::config::Config;
use crate::download::DownloadState;
use crate::ephemeral;
use crate::receive_imf::{receive_imf, receive_imf_from_inbox};
use crate::test_utils::{TestContext, TestContextManager};
use crate::tools::{self, SystemTime};
use crate::{message, sql};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_is_webxdc_file() -> Result<()> {
    let t = TestContext::new().await;
    assert!(
        !t.is_webxdc_file(
            "bad-ext-no-zip.txt",
            include_bytes!("../../test-data/message/issue_523.txt")
        )
        .await?
    );
    assert!(
        !t.is_webxdc_file(
            "bad-ext-good-zip.txt",
            include_bytes!("../../test-data/webxdc/minimal.xdc")
        )
        .await?
    );
    assert!(
        !t.is_webxdc_file(
            "good-ext-no-zip.xdc",
            include_bytes!("../../test-data/message/issue_523.txt")
        )
        .await?
    );
    assert!(
        !t.is_webxdc_file(
            "good-ext-no-index-html.xdc",
            include_bytes!("../../test-data/webxdc/no-index-html.xdc")
        )
        .await?
    );
    assert!(
        t.is_webxdc_file(
            "good-ext-good-zip.xdc",
            include_bytes!("../../test-data/webxdc/minimal.xdc")
        )
        .await?
    );
    Ok(())
}

fn create_webxdc_instance(t: &TestContext, name: &str, bytes: &[u8]) -> Result<Message> {
    let mut instance = Message::new(Viewtype::File);
    instance.set_file_from_bytes(t, name, bytes, None)?;
    Ok(instance)
}

async fn send_webxdc_instance(t: &TestContext, chat_id: ChatId) -> Result<Message> {
    let mut instance = create_webxdc_instance(
        t,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )?;
    let instance_msg_id = send_msg(t, chat_id, &mut instance).await?;
    assert_eq!(instance.viewtype, Viewtype::Webxdc);
    Message::load_from_db(t, instance_msg_id).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_webxdc_instance() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

    // send as .xdc file
    let instance = send_webxdc_instance(&t, chat_id).await?;
    assert_eq!(instance.viewtype, Viewtype::Webxdc);
    assert_eq!(instance.get_filename(), Some("minimal.xdc".to_string()));
    assert_eq!(instance.chat_id, chat_id);

    // sending using bad extension is not working, even when setting Viewtype to webxdc
    let mut instance = Message::new(Viewtype::Webxdc);
    instance.set_file_from_bytes(&t, "index.html", b"<html>ola!</html>", None)?;
    assert!(send_msg(&t, chat_id, &mut instance).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_invalid_webxdc() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

    // sending invalid .xdc as file is possible, but must not result in Viewtype::Webxdc
    let mut instance = create_webxdc_instance(
        &t,
        "invalid-no-zip-but-7z.xdc",
        include_bytes!("../../test-data/webxdc/invalid-no-zip-but-7z.xdc"),
    )?;
    let instance_id = send_msg(&t, chat_id, &mut instance).await?;
    assert_eq!(instance.viewtype, Viewtype::File);
    let test = Message::load_from_db(&t, instance_id).await?;
    assert_eq!(test.viewtype, Viewtype::File);

    // sending invalid .xdc as Viewtype::Webxdc should fail already on sending
    let mut instance = Message::new(Viewtype::Webxdc);
    instance.set_file_from_bytes(
        &t,
        "invalid2.xdc",
        include_bytes!("../../test-data/webxdc/invalid-no-zip-but-7z.xdc"),
        None,
    )?;
    assert!(send_msg(&t, chat_id, &mut instance).await.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_draft_invalid_webxdc() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

    let mut instance = create_webxdc_instance(
        &t,
        "invalid-no-zip-but-7z.xdc",
        include_bytes!("../../test-data/webxdc/invalid-no-zip-but-7z.xdc"),
    )?;

    // draft should not fail
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    chat_id.get_draft(&t).await.unwrap();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_special_webxdc_format() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

    // chess.xdc is failing for some zip-versions, see #3476, if we know more details about why, we can have a nicer name for the test :)
    let mut instance = create_webxdc_instance(
        &t,
        "chess.xdc",
        include_bytes!("../../test-data/webxdc/chess.xdc"),
    )?;
    let instance_id = send_msg(&t, chat_id, &mut instance).await?;
    let instance = Message::load_from_db(&t, instance_id).await?;
    assert_eq!(instance.viewtype, Viewtype::Webxdc);

    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "Chess Board");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_forward_webxdc_instance() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;
    t.send_webxdc_status_update(
        instance.id,
        r#"{"info": "foo", "summary":"bar", "document":"doc", "payload": 42}"#,
    )
    .await?;
    assert!(!instance.is_forwarded());
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":42,"info":"foo","document":"doc","summary":"bar","serial":1,"max_serial":1}]"#
    );
    assert_eq!(chat_id.get_msg_cnt(&t).await?, 2); // instance and info
    let info = Message::load_from_db(&t, instance.id)
        .await?
        .get_webxdc_info(&t)
        .await?;
    assert_eq!(info.summary, "bar".to_string());
    assert_eq!(info.document, "doc".to_string());

    // forwarding an instance creates a fresh instance; updates etc. are not forwarded
    forward_msgs(&t, &[instance.get_id()], chat_id).await?;
    let instance2 = t.get_last_msg_in(chat_id).await;
    assert!(instance2.is_forwarded());
    assert_eq!(
        t.get_webxdc_status_updates(instance2.id, StatusUpdateSerial(0))
            .await?,
        "[]"
    );
    assert_eq!(chat_id.get_msg_cnt(&t).await?, 3); // two instances, only one info
    let info = Message::load_from_db(&t, instance2.id)
        .await?
        .get_webxdc_info(&t)
        .await?;
    assert_eq!(info.summary, "".to_string());
    assert_eq!(info.document, "".to_string());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_resend_webxdc_instance_and_info() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    // Alice uses webxdc in a group
    alice.set_config_bool(Config::BccSelf, false).await?;
    let alice_grp = create_group_chat(&alice, ProtectionStatus::Unprotected, "grp").await?;
    let alice_instance = send_webxdc_instance(&alice, alice_grp).await?;
    assert_eq!(alice_grp.get_msg_cnt(&alice).await?, 1);
    alice
        .send_webxdc_status_update(
            alice_instance.id,
            r#"{"payload":7,"info": "i","summary":"s"}"#,
        )
        .await?;
    assert_eq!(alice_grp.get_msg_cnt(&alice).await?, 2);
    assert!(alice.get_last_msg_in(alice_grp).await.is_info());

    // Alice adds Bob and resends already used webxdc
    add_contact_to_chat(
        &alice,
        alice_grp,
        alice.add_or_lookup_contact_id(&bob).await,
    )
    .await?;
    assert_eq!(alice_grp.get_msg_cnt(&alice).await?, 3);
    resend_msgs(&alice, &[alice_instance.id]).await?;
    let sent1 = alice.pop_sent_msg().await;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;

    // Bob receives webxdc, legacy info-messages updates are received and added to the chat.
    let bob_instance = bob.recv_msg(&sent1).await;
    bob.recv_msg_trash(&sent2).await;
    assert_eq!(bob_instance.viewtype, Viewtype::Webxdc);
    assert!(!bob_instance.is_info());
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":7,"info":"i","summary":"s","serial":1,"max_serial":1}]"#
    );
    let bob_grp = bob_instance.chat_id;
    assert_eq!(bob.get_last_msg_in(bob_grp).await.id, bob_instance.id);
    assert_eq!(bob_grp.get_msg_cnt(&bob).await?, 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_webxdc_instance() -> Result<()> {
    let t = TestContext::new_alice().await;
    receive_imf(
        &t,
        include_bytes!("../../test-data/message/webxdc_good_extension.eml"),
        false,
    )
    .await?;
    let instance = t.get_last_msg().await;
    assert_eq!(instance.viewtype, Viewtype::Webxdc);
    assert_eq!(instance.get_filename().unwrap(), "minimal.xdc");

    receive_imf(
        &t,
        include_bytes!("../../test-data/message/webxdc_bad_extension.eml"),
        false,
    )
    .await?;
    let instance = t.get_last_msg().await;
    assert_eq!(instance.viewtype, Viewtype::File); // we require the correct extension, only a mime type is not sufficient
    assert_eq!(instance.get_filename().unwrap(), "index.html");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_contact_request() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    // Alice sends an webxdc instance to Bob
    let alice_chat = alice.create_chat(&bob).await;
    let _alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;
    bob.recv_msg(&alice.pop_sent_msg().await).await;

    // Bob can start the webxdc from a contact request (get index.html)
    // but cannot send updates to contact requests
    let bob_instance = bob.get_last_msg().await;
    let bob_chat = Chat::load_from_db(&bob, bob_instance.chat_id).await?;
    assert!(bob_chat.is_contact_request());
    assert!(
        bob_instance
            .get_webxdc_blob(&bob, "index.html")
            .await
            .is_ok()
    );
    assert!(
        bob.send_webxdc_status_update(bob_instance.id, r#"{"payload":42}"#)
            .await
            .is_err()
    );
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        "[]"
    );

    // Once the contact request is accepted, Bob can send updates
    bob_chat.id.accept(&bob).await?;
    assert!(
        bob.send_webxdc_status_update(bob_instance.id, r#"{"payload":42}"#)
            .await
            .is_ok()
    );
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":42,"serial":1,"max_serial":1}]"#
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_update_for_not_downloaded_instance() -> Result<()> {
    // Alice sends a larger instance and an update
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let chat = alice.create_chat(&bob).await;
    bob.set_config(Config::DownloadLimit, Some("40000")).await?;
    let mut alice_instance = create_webxdc_instance(
        &alice,
        "chess.xdc",
        include_bytes!("../../test-data/webxdc/chess.xdc"),
    )?;
    let sent1 = alice.send_msg(chat.id, &mut alice_instance).await;
    let alice_instance = sent1.load_from_db().await;
    alice
        .send_webxdc_status_update(
            alice_instance.id,
            r#"{"payload": 7, "summary":"sum", "document":"doc"}"#,
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;

    // Bob does not download instance but already receives update
    receive_imf_from_inbox(
        &bob,
        &alice_instance.rfc724_mid,
        sent1.payload().as_bytes(),
        false,
        Some(70790),
    )
    .await?;
    let bob_instance = bob.get_last_msg().await;
    bob_instance.chat_id.accept(&bob).await?;
    bob.recv_msg_trash(&sent2).await;
    assert_eq!(bob_instance.download_state, DownloadState::Available);

    // Bob downloads instance, updates should be assigned correctly
    let received_msg = receive_imf_from_inbox(
        &bob,
        &alice_instance.rfc724_mid,
        sent1.payload().as_bytes(),
        false,
        None,
    )
    .await?
    .unwrap();
    assert_eq!(*received_msg.msg_ids.first().unwrap(), bob_instance.id);
    let bob_instance = bob.get_last_msg().await;
    assert_eq!(bob_instance.viewtype, Viewtype::Webxdc);
    assert_eq!(bob_instance.download_state, DownloadState::Done);
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":7,"document":"doc","summary":"sum","serial":1,"max_serial":1}]"#
    );
    let info = bob_instance.get_webxdc_info(&bob).await?;
    assert_eq!(info.document, "doc");
    assert_eq!(info.summary, "sum");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_webxdc_instance() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;
    let now = tools::time();
    t.receive_status_update(
        ContactId::SELF,
        &instance,
        now,
        true,
        r#"{"updates":[{"payload":1}]}"#,
    )
    .await?;
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM msgs_status_updates;", ())
            .await?,
        1
    );

    message::delete_msgs(&t, &[instance.id]).await?;
    sql::housekeeping(&t).await?;
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM msgs_status_updates;", ())
            .await?,
        0
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_chat_with_webxdc() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;
    let now = tools::time();
    t.receive_status_update(
        ContactId::SELF,
        &instance,
        now,
        true,
        r#"{"updates":[{"payload":1}, {"payload":2}]}"#,
    )
    .await?;
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM msgs_status_updates;", ())
            .await?,
        2
    );

    chat_id.delete(&t).await?;
    sql::housekeeping(&t).await?;
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM msgs_status_updates;", ())
            .await?,
        0
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_webxdc_draft() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

    let mut instance = create_webxdc_instance(
        &t,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let instance = chat_id.get_draft(&t).await?.unwrap();
    t.send_webxdc_status_update(instance.id, r#"{"payload": 42}"#)
        .await?;
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":42,"serial":1,"max_serial":1}]"#.to_string()
    );

    // set_draft(None) deletes the message without the need to simulate network
    chat_id.set_draft(&t, None).await?;
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        "[]".to_string()
    );
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM msgs_status_updates;", ())
            .await?,
        0
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_status_update_record() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;

    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        "[]"
    );

    let update_id1 = t
        .create_status_update_record(
            &instance,
            StatusUpdateItem {
                payload: json!({"foo": "bar"}),
                info: None,
                href: None,
                document: None,
                summary: None,
                uid: Some("iecie2Ze".to_string()),
                notify: None,
            },
            1640178619,
            true,
            ContactId::SELF,
        )
        .await?
        .unwrap();
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":1}]"#
    );

    // Update with duplicate update ID is received.
    // Whatever the payload is, update should be ignored just because ID is duplicate.
    let update_id1_duplicate = t
        .create_status_update_record(
            &instance,
            StatusUpdateItem {
                payload: json!({"nothing": "this should be ignored"}),
                info: None,
                href: None,
                document: None,
                summary: None,
                uid: Some("iecie2Ze".to_string()),
                notify: None,
            },
            1640178619,
            true,
            ContactId::SELF,
        )
        .await?;
    assert_eq!(update_id1_duplicate, None);

    assert!(
        t.send_webxdc_status_update(instance.id, "\n\n\n")
            .await
            .is_err()
    );

    assert!(
        t.send_webxdc_status_update(instance.id, "bad json")
            .await
            .is_err()
    );

    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":1}]"#
    );

    let update_id2 = t
        .create_status_update_record(
            &instance,
            StatusUpdateItem {
                payload: json!({"foo2": "bar2"}),
                info: None,
                href: None,
                document: None,
                summary: None,
                uid: None,
                notify: None,
            },
            1640178619,
            true,
            ContactId::SELF,
        )
        .await?
        .unwrap();
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, update_id1).await?,
        r#"[{"payload":{"foo2":"bar2"},"serial":3,"max_serial":3}]"#
    );
    t.create_status_update_record(
        &instance,
        StatusUpdateItem {
            payload: Value::Bool(true),
            info: None,
            href: None,
            document: None,
            summary: None,
            uid: None,
            notify: None,
        },
        1640178619,
        true,
        ContactId::SELF,
    )
    .await?;
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":4},
{"payload":{"foo2":"bar2"},"serial":3,"max_serial":4},
{"payload":true,"serial":4,"max_serial":4}]"#
    );

    t.send_webxdc_status_update(
        instance.id,
        r#"{"payload" : 1, "sender": "that is not used"}"#,
    )
    .await?;
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, update_id2).await?,
        r#"[{"payload":true,"serial":4,"max_serial":5},
{"payload":1,"serial":5,"max_serial":5}]"#
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_receive_status_update() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;
    let now = tools::time();

    assert!(
        t.receive_status_update(ContactId::SELF, &instance, now, true, r#"foo: bar"#)
            .await
            .is_err()
    ); // no json
    assert!(
        t.receive_status_update(
            ContactId::SELF,
            &instance,
            now,
            true,
            r#"{"updada":[{"payload":{"foo":"bar"}}]}"#
        )
        .await
        .is_err()
    ); // "updates" object missing
    assert!(
        t.receive_status_update(
            ContactId::SELF,
            &instance,
            now,
            true,
            r#"{"updates":[{"foo":"bar"}]}"#
        )
        .await
        .is_err()
    ); // "payload" field missing
    assert!(
        t.receive_status_update(
            ContactId::SELF,
            &instance,
            now,
            true,
            r#"{"updates":{"payload":{"foo":"bar"}}}"#
        )
        .await
        .is_err()
    ); // not an array

    t.receive_status_update(
        ContactId::SELF,
        &instance,
        now,
        true,
        r#"{"updates":[{"payload":{"foo":"bar"}, "someTrash": "definitely TrAsH"}]}"#,
    )
    .await?;
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":1}]"#
    );

    t.receive_status_update(
        ContactId::SELF,
        &instance,
        now,
        true,
        r#" {"updates": [ {"payload" :42} , {"payload": 23} ] } "#,
    )
    .await?;
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":3},
{"payload":42,"serial":2,"max_serial":3},
{"payload":23,"serial":3,"max_serial":3}]"#
    );

    t.receive_status_update(
        ContactId::SELF,
        &instance,
        now,
        true,
        r#" {"updates": [ {"payload" :"ok", "future_item": "test"}  ], "from": "future" } "#,
    )
    .await?; // ignore members that may be added in the future
    assert_eq!(
        t.get_webxdc_status_updates(instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":4},
{"payload":42,"serial":2,"max_serial":4},
{"payload":23,"serial":3,"max_serial":4},
{"payload":"ok","serial":4,"max_serial":4}]"#
    );

    Ok(())
}

async fn expect_status_update_event(t: &TestContext, instance_id: MsgId) -> Result<()> {
    let event = t
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::WebxdcStatusUpdate { .. }))
        .await;
    match event {
        EventType::WebxdcStatusUpdate {
            msg_id,
            status_update_serial: _,
        } => {
            assert_eq!(msg_id, instance_id);
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_webxdc_status_update() -> Result<()> {
    let alice = TestContext::new_alice().await;
    alice.set_config_bool(Config::BccSelf, true).await?;
    let bob = TestContext::new_bob().await;

    // Alice sends an webxdc instance and a status update
    let alice_chat = alice.create_email_chat(&bob).await;
    let alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;
    let sent1 = &alice.pop_sent_msg().await;
    assert_eq!(alice_instance.viewtype, Viewtype::Webxdc);
    assert!(!sent1.payload().contains("report-type=status-update"));

    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"payload" : {"foo":"bar"}}"#)
        .await?;
    alice.flush_status_updates().await?;
    expect_status_update_event(&alice, alice_instance.id).await?;
    let sent2 = &alice.pop_sent_msg().await;
    let alice_update = sent2.load_from_db().await;
    assert!(alice_update.hidden);
    assert_eq!(alice_update.viewtype, Viewtype::Text);
    assert_eq!(alice_update.get_filename(), None);
    assert_eq!(alice_update.text, BODY_DESCR.to_string());
    assert_eq!(alice_update.chat_id, alice_instance.chat_id);
    assert_eq!(
        alice_update.parent(&alice).await?.unwrap().id,
        alice_instance.id
    );
    assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 1);
    assert!(sent2.payload().contains("report-type=status-update"));
    assert!(sent2.payload().contains(BODY_DESCR));
    assert_eq!(
        alice
            .get_webxdc_status_updates(alice_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":1}]"#
    );

    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"payload":{"snipp":"snapp"}}"#)
        .await?;
    assert_eq!(
        alice
            .get_webxdc_status_updates(alice_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":2},
{"payload":{"snipp":"snapp"},"serial":2,"max_serial":2}]"#
    );

    // Bob receives all messages
    let bob_instance = bob.recv_msg(sent1).await;
    let bob_chat_id = bob_instance.chat_id;
    assert_eq!(bob_instance.rfc724_mid, alice_instance.rfc724_mid);
    assert_eq!(bob_instance.viewtype, Viewtype::Webxdc);
    assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 1);

    let bob_received_update = bob.recv_msg_opt(sent2).await;
    assert!(bob_received_update.is_none());
    expect_status_update_event(&bob, bob_instance.id).await?;
    assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 1);

    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":1}]"#
    );

    // Alice has a second device and also receives messages there
    let alice2 = TestContext::new_alice().await;
    alice2.recv_msg(sent1).await;
    alice2.recv_msg_trash(sent2).await;
    let alice2_instance = alice2.get_last_msg().await;
    let alice2_chat_id = alice2_instance.chat_id;
    assert_eq!(alice2_instance.viewtype, Viewtype::Webxdc);
    assert_eq!(alice2_chat_id.get_msg_cnt(&alice2).await?, 1);

    // To support the second device, Alice has enabled bcc_self and will receive their own messages;
    // these messages, however, should be ignored
    alice.recv_msg_opt(sent1).await;
    alice.recv_msg_opt(sent2).await;
    assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 1);
    assert_eq!(
        alice
            .get_webxdc_status_updates(alice_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":2},
{"payload":{"snipp":"snapp"},"serial":2,"max_serial":2}]"#
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_big_webxdc_status_update() -> Result<()> {
    let alice = TestContext::new_alice().await;
    alice.set_config_bool(Config::BccSelf, true).await?;
    let bob = TestContext::new_bob().await;

    let alice_chat = alice.create_chat(&bob).await;
    let alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;
    let sent1 = &alice.pop_sent_msg().await;
    assert_eq!(alice_instance.viewtype, Viewtype::Webxdc);
    assert!(!sent1.payload().contains("report-type=status-update"));

    let update1_str = r#"{"payload":{"foo":""#.to_string()
        + &String::from_utf8(vec![b'a'; STATUS_UPDATE_SIZE_MAX])?
        + r#""}"#;
    alice
        .send_webxdc_status_update(alice_instance.id, &(update1_str.clone() + "}"))
        .await?;
    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"payload" : {"foo":"bar2"}}"#)
        .await?;
    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"payload" : {"foo":"bar3"}}"#)
        .await?;
    alice.flush_status_updates().await?;

    // There's the message stack, so we pop messages in the reverse order.
    let sent3 = &alice.pop_sent_msg().await;
    let alice_update = sent3.load_from_db().await;
    assert_eq!(alice_update.text, BODY_DESCR.to_string());
    let sent2 = &alice.pop_sent_msg().await;
    let alice_update = sent2.load_from_db().await;
    assert_eq!(alice_update.text, BODY_DESCR.to_string());
    assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 1);

    // Bob receives the instance.
    let bob_instance = bob.recv_msg(sent1).await;
    let bob_chat_id = bob_instance.chat_id;
    assert_eq!(bob_instance.rfc724_mid, alice_instance.rfc724_mid);
    assert_eq!(bob_instance.viewtype, Viewtype::Webxdc);
    assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 1);

    // Bob receives the status updates.
    bob.recv_msg_trash(sent2).await;
    expect_status_update_event(&bob, bob_instance.id).await?;
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        "[".to_string() + &update1_str + r#","serial":1,"max_serial":1}]"#
    );
    bob.recv_msg_trash(sent3).await;
    for _ in 0..2 {
        expect_status_update_event(&bob, bob_instance.id).await?;
    }
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(1))
            .await?,
        r#"[{"payload":{"foo":"bar2"},"serial":2,"max_serial":3},
{"payload":{"foo":"bar3"},"serial":3,"max_serial":3}]"#
    );
    assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_render_webxdc_status_update_object() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "a chat").await?;
    let mut instance = create_webxdc_instance(
        &t,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let (first, last) = (StatusUpdateSerial(1), StatusUpdateSerial::MAX);
    assert_eq!(
        t.render_webxdc_status_update_object(instance.id, first, last, None)
            .await?,
        (None, StatusUpdateSerial(u32::MAX))
    );

    t.send_webxdc_status_update(instance.id, r#"{"payload": 1}"#)
        .await?;
    let (object, first_new) = t
        .render_webxdc_status_update_object(instance.id, first, last, None)
        .await?;
    assert!(object.is_some());
    assert_eq!(first_new, StatusUpdateSerial(u32::MAX));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_render_webxdc_status_update_object_range() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "a chat").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;
    t.send_webxdc_status_update(instance.id, r#"{"payload": 1}"#)
        .await?;
    t.send_webxdc_status_update(instance.id, r#"{"payload": 2}"#)
        .await?;
    t.send_webxdc_status_update(instance.id, r#"{"payload": 3}"#)
        .await?;
    t.send_webxdc_status_update(instance.id, r#"{"payload": 4}"#)
        .await?;
    let (json, first_new) = t
        .render_webxdc_status_update_object(
            instance.id,
            StatusUpdateSerial(2),
            StatusUpdateSerial(3),
            None,
        )
        .await?;
    let json = json.unwrap();
    assert_eq!(first_new, StatusUpdateSerial(4));
    let json = Regex::new(r#""uid":"[^"]*""#)
        .unwrap()
        .replace_all(&json, "XXX");
    assert_eq!(
        json,
        "{\"updates\":[{\"payload\":2,XXX},\n{\"payload\":3,XXX}]}"
    );

    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM smtp_status_updates", ())
            .await?,
        1
    );
    t.flush_status_updates().await?;
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM smtp_status_updates", ())
            .await?,
        0
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_pop_status_update() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "a chat").await?;
    let instance1 = send_webxdc_instance(&t, chat_id).await?;
    let instance2 = send_webxdc_instance(&t, chat_id).await?;
    let instance3 = send_webxdc_instance(&t, chat_id).await?;
    assert!(t.smtp_status_update_get().await?.is_none());

    t.send_webxdc_status_update(instance1.id, r#"{"payload": "1a"}"#)
        .await?;
    t.send_webxdc_status_update(instance2.id, r#"{"payload": "2a"}"#)
        .await?;
    t.send_webxdc_status_update(instance2.id, r#"{"payload": "2b"}"#)
        .await?;
    t.send_webxdc_status_update(instance3.id, r#"{"payload": "3a"}"#)
        .await?;
    t.send_webxdc_status_update(instance3.id, r#"{"payload": "3b"}"#)
        .await?;
    t.send_webxdc_status_update(instance3.id, r#"{"payload": "3c"}"#)
        .await?;
    assert_eq!(
        t.sql
            .count("SELECT COUNT(*) FROM smtp_status_updates", ())
            .await?,
        3
    );

    // order of smtp_status_update_get() is not defined, therefore the more complicated test
    let mut instances_checked = 0;
    for i in 0..3 {
        let (instance, min_ser, max_ser) = t.smtp_status_update_get().await?.unwrap();
        t.smtp_status_update_pop_serials(
            instance,
            min_ser,
            StatusUpdateSerial::new(max_ser.to_u32().checked_add(1).unwrap()),
        )
        .await?;
        let min_ser: u32 = min_ser.try_into()?;
        if instance == instance1.id {
            assert_eq!(min_ser, max_ser.to_u32());

            instances_checked += 1;
        } else if instance == instance2.id {
            assert_eq!(min_ser, max_ser.to_u32() - 1);

            instances_checked += 1;
        } else if instance == instance3.id {
            assert_eq!(min_ser, max_ser.to_u32() - 2);
            instances_checked += 1;
        } else {
            bail!("unexpected instance");
        }
        assert_eq!(
            t.sql
                .count("SELECT COUNT(*) FROM smtp_status_updates", ())
                .await?,
            2 - i
        );
    }
    assert_eq!(instances_checked, 3);
    assert!(t.smtp_status_update_get().await?.is_none());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_draft_and_send_webxdc_status_update() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat_id = alice.create_email_chat(&bob).await.id;

    // prepare webxdc instance,
    // status updates are not sent for drafts, therefore send_webxdc_status_update() returns Ok(None)
    let mut alice_instance = create_webxdc_instance(
        &alice,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )?;
    alice_chat_id
        .set_draft(&alice, Some(&mut alice_instance))
        .await?;
    let mut alice_instance = alice_chat_id.get_draft(&alice).await?.unwrap();

    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"payload": {"foo":"bar"}}"#)
        .await?;
    expect_status_update_event(&alice, alice_instance.id).await?;
    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"payload":42, "info":"i"}"#)
        .await?;
    expect_status_update_event(&alice, alice_instance.id).await?;
    assert_eq!(
        alice
            .sql
            .count("SELECT COUNT(*) FROM smtp_status_updates", ())
            .await?,
        0
    );
    assert!(!alice.get_last_msg().await.is_info()); // 'info: "i"' message not added in draft mode

    // send webxdc instance,
    // the initial status updates are sent together in the same message
    let alice_instance_id = send_msg(&alice, alice_chat_id, &mut alice_instance).await?;
    let sent1 = alice.pop_sent_msg().await;
    let alice_instance = Message::load_from_db(&alice, alice_instance_id).await?;
    assert_eq!(alice_instance.viewtype, Viewtype::Webxdc);
    assert_eq!(
        alice_instance.get_filename(),
        Some("minimal.xdc".to_string())
    );
    assert_eq!(alice_instance.chat_id, alice_chat_id);

    // bob receives the instance together with the initial updates in a single message
    let bob_instance = bob.recv_msg(&sent1).await;
    assert_eq!(bob_instance.viewtype, Viewtype::Webxdc);
    assert_eq!(bob_instance.get_filename().unwrap(), "minimal.xdc");
    assert!(sent1.payload().contains("Content-Type: application/json"));
    assert!(sent1.payload().contains("status-update.json"));
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":2},
{"payload":42,"info":"i","serial":2,"max_serial":2}]"#
    );
    assert!(!bob.get_last_msg().await.is_info()); // 'info: "i"' message not added in draft mode

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_webxdc_status_update_to_non_webxdc() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let msg_id = send_text_msg(&t, chat_id, "ho!".to_string()).await?;
    assert!(
        t.send_webxdc_status_update(msg_id, r#"{"foo":"bar"}"#)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_webxdc_blob() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;

    let buf = instance.get_webxdc_blob(&t, "index.html").await?;
    assert_eq!(buf.len(), 188);
    assert!(String::from_utf8_lossy(&buf).contains("document.write"));

    assert!(
        instance
            .get_webxdc_blob(&t, "not-existent.html")
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_webxdc_blob_default_icon() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;

    let buf = instance.get_webxdc_blob(&t, WEBXDC_DEFAULT_ICON).await?;
    assert!(buf.len() > 100);
    assert!(String::from_utf8_lossy(&buf).contains("PNG\r\n"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_webxdc_blob_with_absolute_paths() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;

    let buf = instance.get_webxdc_blob(&t, "/index.html").await?;
    assert!(String::from_utf8_lossy(&buf).contains("document.write"));

    assert!(instance.get_webxdc_blob(&t, "/not-there").await.is_err());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_webxdc_blob_with_subdirs() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
    let mut instance = create_webxdc_instance(
        &t,
        "some-files.xdc",
        include_bytes!("../../test-data/webxdc/some-files.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;

    let buf = instance.get_webxdc_blob(&t, "index.html").await?;
    assert_eq!(buf.len(), 65);
    assert!(String::from_utf8_lossy(&buf).contains("many files"));

    let buf = instance.get_webxdc_blob(&t, "subdir/bla.txt").await?;
    assert_eq!(buf.len(), 4);
    assert!(String::from_utf8_lossy(&buf).starts_with("bla"));

    let buf = instance
        .get_webxdc_blob(&t, "subdir/subsubdir/text.md")
        .await?;
    assert_eq!(buf.len(), 24);
    assert!(String::from_utf8_lossy(&buf).starts_with("this is a markdown file"));

    let buf = instance
        .get_webxdc_blob(&t, "subdir/subsubdir/text2.md")
        .await?;
    assert_eq!(buf.len(), 22);
    assert!(String::from_utf8_lossy(&buf).starts_with("another markdown"));

    let buf = instance
        .get_webxdc_blob(&t, "anotherdir/anothersubsubdir/foo.txt")
        .await?;
    assert_eq!(buf.len(), 4);
    assert!(String::from_utf8_lossy(&buf).starts_with("foo"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_webxdc_manifest() -> Result<()> {
    let result = parse_webxdc_manifest(r#"key = syntax error"#.as_bytes());
    assert!(result.is_err());

    let manifest = parse_webxdc_manifest(r#"no_name = "no name, no icon""#.as_bytes())?;
    assert_eq!(manifest.name, None);

    let manifest = parse_webxdc_manifest(r#"name = "name, no icon""#.as_bytes())?;
    assert_eq!(manifest.name, Some("name, no icon".to_string()));

    let manifest = parse_webxdc_manifest(
        r#"name = "foo"
icon = "bar""#
            .as_bytes(),
    )?;
    assert_eq!(manifest.name, Some("foo".to_string()));

    let manifest = parse_webxdc_manifest(
        r#"name = "foz"
icon = "baz"
add_item = "that should be just ignored"

[section]
sth_for_the = "future""#
            .as_bytes(),
    )?;
    assert_eq!(manifest.name, Some("foz".to_string()));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_webxdc_manifest_min_api() -> Result<()> {
    let manifest = parse_webxdc_manifest(r#"min_api = 3"#.as_bytes())?;
    assert_eq!(manifest.min_api, Some(3));

    let result = parse_webxdc_manifest(r#"min_api = "1""#.as_bytes());
    assert!(result.is_err());

    let result = parse_webxdc_manifest(r#"min_api = 1.2"#.as_bytes());
    assert!(result.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parse_webxdc_manifest_source_code_url() -> Result<()> {
    let result = parse_webxdc_manifest(r#"source_code_url = 3"#.as_bytes());
    assert!(result.is_err());

    let manifest = parse_webxdc_manifest(r#"source_code_url = "https://foo.bar""#.as_bytes())?;
    assert_eq!(
        manifest.source_code_url,
        Some("https://foo.bar".to_string())
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_min_api_too_large() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "chat").await?;
    let mut instance = create_webxdc_instance(
        &t,
        "with-min-api-1001.xdc",
        include_bytes!("../../test-data/webxdc/with-min-api-1001.xdc"),
    )?;
    send_msg(&t, chat_id, &mut instance).await?;

    let instance = t.get_last_msg().await;
    let html = instance.get_webxdc_blob(&t, "index.html").await?;
    assert!(String::from_utf8_lossy(&html).contains("requires a newer Delta Chat version"));

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_webxdc_info() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

    let instance = send_webxdc_instance(&t, chat_id).await?;
    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "minimal.xdc");
    assert_eq!(info.icon, WEBXDC_DEFAULT_ICON.to_string());
    assert_eq!(info.send_update_interval, 10000);
    assert_eq!(info.send_update_max_size, RECOMMENDED_FILE_SIZE as usize);

    let mut instance = create_webxdc_instance(
        &t,
        "with-manifest-empty-name.xdc",
        include_bytes!("../../test-data/webxdc/with-manifest-empty-name.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "with-manifest-empty-name.xdc");
    assert_eq!(info.icon, WEBXDC_DEFAULT_ICON.to_string());

    let mut instance = create_webxdc_instance(
        &t,
        "with-manifest-no-name.xdc",
        include_bytes!("../../test-data/webxdc/with-manifest-no-name.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "with-manifest-no-name.xdc");
    assert_eq!(info.icon, WEBXDC_DEFAULT_ICON.to_string());

    let mut instance = create_webxdc_instance(
        &t,
        "with-minimal-manifest.xdc",
        include_bytes!("../../test-data/webxdc/with-minimal-manifest.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "nice app!");
    assert_eq!(info.icon, WEBXDC_DEFAULT_ICON.to_string());

    let mut instance = create_webxdc_instance(
        &t,
        "with-manifest-and-png-icon.xdc",
        include_bytes!("../../test-data/webxdc/with-manifest-and-png-icon.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "with some icon");
    assert_eq!(info.icon, "icon.png");

    let mut instance = create_webxdc_instance(
        &t,
        "with-png-icon.xdc",
        include_bytes!("../../test-data/webxdc/with-png-icon.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "with-png-icon.xdc");
    assert_eq!(info.icon, "icon.png");

    let mut instance = create_webxdc_instance(
        &t,
        "with-jpg-icon.xdc",
        include_bytes!("../../test-data/webxdc/with-jpg-icon.xdc"),
    )?;
    chat_id.set_draft(&t, Some(&mut instance)).await?;
    let info = instance.get_webxdc_info(&t).await?;
    assert_eq!(info.name, "with-jpg-icon.xdc");
    assert_eq!(info.icon, "icon.jpg");

    let msg_id = send_text_msg(&t, chat_id, "foo".to_string()).await?;
    let msg = Message::load_from_db(&t, msg_id).await?;
    let result = msg.get_webxdc_info(&t).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_get_webxdc_self_addr() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

    let instance = send_webxdc_instance(&t, chat_id).await?;
    let info1 = instance.get_webxdc_info(&t).await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;
    let info2 = instance.get_webxdc_info(&t).await?;

    let real_addr = t.get_primary_self_addr().await?;
    assert!(!info1.self_addr.contains(&real_addr));
    assert_ne!(info1.self_addr, info2.self_addr);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_info_summary() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    // Alice creates an webxdc instance and updates summary
    let alice_chat = alice.create_chat(&bob).await;
    let alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;
    let sent_instance = &alice.pop_sent_msg().await;
    let info = alice_instance.get_webxdc_info(&alice).await?;
    assert_eq!(info.summary, "".to_string());

    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"summary":"sum: 1", "payload":1}"#)
        .await?;
    alice.flush_status_updates().await?;
    let sent_update1 = &alice.pop_sent_msg().await;
    let info = Message::load_from_db(&alice, alice_instance.id)
        .await?
        .get_webxdc_info(&alice)
        .await?;
    assert_eq!(info.summary, "sum: 1".to_string());

    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"summary":"sum: 2", "payload":2}"#)
        .await?;
    alice.flush_status_updates().await?;
    let sent_update2 = &alice.pop_sent_msg().await;
    let info = Message::load_from_db(&alice, alice_instance.id)
        .await?
        .get_webxdc_info(&alice)
        .await?;
    assert_eq!(info.summary, "sum: 2".to_string());

    // Bob receives the updates
    let bob_instance = bob.recv_msg(sent_instance).await;
    bob.recv_msg_trash(sent_update1).await;
    bob.recv_msg_trash(sent_update2).await;
    let info = Message::load_from_db(&bob, bob_instance.id)
        .await?
        .get_webxdc_info(&bob)
        .await?;
    assert_eq!(info.summary, "sum: 2".to_string());

    // Alice has a second device and also receives the updates there
    let alice2 = TestContext::new_alice().await;
    let alice2_instance = alice2.recv_msg(sent_instance).await;
    alice2.recv_msg_trash(sent_update1).await;
    alice2.recv_msg_trash(sent_update2).await;
    let info = Message::load_from_db(&alice2, alice2_instance.id)
        .await?
        .get_webxdc_info(&alice2)
        .await?;
    assert_eq!(info.summary, "sum: 2".to_string());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_document_name() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    // Alice creates an webxdc instance and updates document name
    let alice_chat = alice.create_chat(&bob).await;
    let alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;
    let sent_instance = &alice.pop_sent_msg().await;
    let info = alice_instance.get_webxdc_info(&alice).await?;
    assert_eq!(info.document, "".to_string());
    assert_eq!(info.summary, "".to_string());

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            r#"{"document":"my file", "payload":1337}"#,
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent_update1 = &alice.pop_sent_msg().await;
    let info = Message::load_from_db(&alice, alice_instance.id)
        .await?
        .get_webxdc_info(&alice)
        .await?;
    assert_eq!(info.document, "my file".to_string());
    assert_eq!(info.summary, "".to_string());

    // Bob receives the updates
    let bob_instance = bob.recv_msg(sent_instance).await;
    bob.recv_msg_trash(sent_update1).await;
    let info = Message::load_from_db(&bob, bob_instance.id)
        .await?
        .get_webxdc_info(&bob)
        .await?;
    assert_eq!(info.document, "my file".to_string());
    assert_eq!(info.summary, "".to_string());

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_info_msg() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    // Alice sends update with an info message
    let alice_chat = alice.create_chat(&bob).await;
    let alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;
    let sent1 = &alice.pop_sent_msg().await;
    assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 1);

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            r#"{"info":"this appears in-chat", "payload":"sth. else"}"#,
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = &alice.pop_sent_msg().await;
    assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 2);
    let info_msg = alice.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.get_info_type(), SystemMessage::WebxdcInfoMessage);
    assert_eq!(info_msg.from_id, ContactId::SELF);
    assert_eq!(info_msg.get_text(), "this appears in-chat");
    assert_eq!(
        info_msg.parent(&alice).await?.unwrap().id,
        alice_instance.id
    );
    assert!(info_msg.quoted_message(&alice).await?.is_none());
    assert_eq!(
        alice
            .get_webxdc_status_updates(alice_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":"sth. else","info":"this appears in-chat","serial":1,"max_serial":1}]"#
    );

    // Bob receives all messages
    let bob_instance = bob.recv_msg(sent1).await;
    let bob_chat_id = bob_instance.chat_id;
    bob.recv_msg_trash(sent2).await;
    assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 2);
    let info_msg = bob.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.get_info_type(), SystemMessage::WebxdcInfoMessage);
    assert!(!info_msg.from_id.is_special());
    assert_eq!(info_msg.get_text(), "this appears in-chat");
    assert_eq!(info_msg.parent(&bob).await?.unwrap().id, bob_instance.id);
    assert!(info_msg.quoted_message(&bob).await?.is_none());
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":"sth. else","info":"this appears in-chat","serial":1,"max_serial":1}]"#
    );

    // Alice has a second device and also receives the info message there
    let alice2 = TestContext::new_alice().await;
    let alice2_instance = alice2.recv_msg(sent1).await;
    let alice2_chat_id = alice2_instance.chat_id;
    alice2.recv_msg_trash(sent2).await;
    assert_eq!(alice2_chat_id.get_msg_cnt(&alice2).await?, 2);
    let info_msg = alice2.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.get_info_type(), SystemMessage::WebxdcInfoMessage);
    assert_eq!(info_msg.from_id, ContactId::SELF);
    assert_eq!(info_msg.get_text(), "this appears in-chat");
    assert_eq!(
        info_msg.parent(&alice2).await?.unwrap().id,
        alice2_instance.id
    );
    assert!(info_msg.quoted_message(&alice2).await?.is_none());
    assert_eq!(
        alice2
            .get_webxdc_status_updates(alice2_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":"sth. else","info":"this appears in-chat","serial":1,"max_serial":1}]"#
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_info_msg_cleanup_series() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;
    let sent1 = &alice.pop_sent_msg().await;

    // Alice sends two info messages in a row;
    // the second one removes the first one as there is nothing in between
    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"info":"i1", "payload":1}"#)
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = &alice.pop_sent_msg().await;
    assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 2);
    alice
        .send_webxdc_status_update(alice_instance.id, r#"{"info":"i2", "payload":2}"#)
        .await?;
    alice.flush_status_updates().await?;
    let sent3 = &alice.pop_sent_msg().await;
    assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 2);
    let info_msg = alice.get_last_msg().await;
    assert_eq!(info_msg.get_text(), "i2");

    // When Bob receives the messages, they should be cleaned up as well
    let bob_instance = bob.recv_msg(sent1).await;
    let bob_chat_id = bob_instance.chat_id;
    bob.recv_msg_trash(sent2).await;
    assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 2);
    bob.recv_msg_trash(sent3).await;
    assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 2);
    let info_msg = bob.get_last_msg().await;
    assert_eq!(info_msg.get_text(), "i2");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_info_msg_no_cleanup_on_interrupted_series() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "c").await?;
    let instance = send_webxdc_instance(&t, chat_id).await?;

    t.send_webxdc_status_update(instance.id, r#"{"info":"i1", "payload":1}"#)
        .await?;
    assert_eq!(chat_id.get_msg_cnt(&t).await?, 2);
    send_text_msg(&t, chat_id, "msg between info".to_string()).await?;
    assert_eq!(chat_id.get_msg_cnt(&t).await?, 3);
    t.send_webxdc_status_update(instance.id, r#"{"info":"i2", "payload":2}"#)
        .await?;
    assert_eq!(chat_id.get_msg_cnt(&t).await?, 4);

    Ok(())
}

// check that `info.internet_access` is not set for normal, non-integrated webxdc -
// even if they use the deprecated option `request_internet_access` in manifest.toml
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_no_internet_access() -> Result<()> {
    let t = TestContext::new_alice().await;
    let self_id = t.get_self_chat().await.id;
    let single_id = t.create_chat_with_contact("bob", "bob@e.com").await.id;
    let group_id = create_group_chat(&t, ProtectionStatus::Unprotected, "chat").await?;
    let broadcast_id = create_broadcast(&t, "Channel".to_string()).await?;

    for chat_id in [self_id, single_id, group_id, broadcast_id] {
        for internet_xdc in [true, false] {
            let mut instance = create_webxdc_instance(
                &t,
                "foo.xdc",
                if internet_xdc {
                    include_bytes!("../../test-data/webxdc/request-internet-access.xdc")
                } else {
                    include_bytes!("../../test-data/webxdc/minimal.xdc")
                },
            )?;
            let instance_id = send_msg(&t, chat_id, &mut instance).await?;
            t.send_webxdc_status_update(
                instance_id,
                r#"{"summary":"real summary", "payload": 42}"#,
            )
            .await?;
            let instance = Message::load_from_db(&t, instance_id).await?;
            let info = instance.get_webxdc_info(&t).await?;
            assert_eq!(info.internet_access, false);
        }
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_chatlist_summary() -> Result<()> {
    let t = TestContext::new_alice().await;
    let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "chat").await?;
    let mut instance = create_webxdc_instance(
        &t,
        "with-minimal-manifest.xdc",
        include_bytes!("../../test-data/webxdc/with-minimal-manifest.xdc"),
    )?;
    send_msg(&t, chat_id, &mut instance).await?;

    let chatlist = Chatlist::try_load(&t, 0, None, None).await?;
    assert_eq!(chatlist.len(), 1);
    let summary = chatlist.get_summary(&t, 0, None).await?;
    assert_eq!(summary.text, "nice app!".to_string());
    assert_eq!(summary.thumbnail_path.unwrap(), "webxdc-icon://last-msg-id");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_and_text() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;

    // Alice sends instance and adds some text
    let alice_chat = alice.create_chat(&bob).await;
    let mut alice_instance = create_webxdc_instance(
        &alice,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )?;
    alice_instance.set_text("user added text".to_string());
    send_msg(&alice, alice_chat.id, &mut alice_instance).await?;
    let alice_instance = alice.get_last_msg().await;
    assert_eq!(alice_instance.get_text(), "user added text");

    // Bob receives that instance
    let sent1 = alice.pop_sent_msg().await;
    let bob_instance = bob.recv_msg(&sent1).await;
    assert_eq!(bob_instance.get_text(), "user added text");

    // Alice's second device receives the instance as well
    let alice2 = TestContext::new_alice().await;
    let alice2_instance = alice2.recv_msg(&sent1).await;
    assert_eq!(alice2_instance.get_text(), "user added text");

    Ok(())
}

async fn helper_send_receive_status_update(
    bob: &TestContext,
    alice: &TestContext,
    bob_instance: &Message,
    alice_instance: &Message,
) -> Result<String> {
    bob.send_webxdc_status_update(
        bob_instance.id,
        r#"{"payload":7,"info": "i","summary":"s"}"#,
    )
    .await?;
    bob.flush_status_updates().await?;
    let msg = bob.pop_sent_msg().await;
    alice.recv_msg_trash(&msg).await;
    alice
        .get_webxdc_status_updates(alice_instance.id, StatusUpdateSerial(0))
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_reject_updates_from_non_groupmembers() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let contact_bob = alice.add_or_lookup_contact_id(bob).await;
    let chat_id = create_group_chat(alice, ProtectionStatus::Unprotected, "Group").await?;
    add_contact_to_chat(alice, chat_id, contact_bob).await?;
    let instance = send_webxdc_instance(alice, chat_id).await?;
    bob.recv_msg(&alice.pop_sent_msg().await).await;
    let bob_instance = bob.get_last_msg().await;
    Chat::load_from_db(bob, bob_instance.chat_id)
        .await?
        .id
        .accept(bob)
        .await?;

    let status = helper_send_receive_status_update(bob, alice, &bob_instance, &instance).await?;
    assert_eq!(
        status,
        r#"[{"payload":7,"info":"i","summary":"s","serial":1,"max_serial":1}]"#
    );

    remove_contact_from_chat(alice, chat_id, contact_bob).await?;
    alice.pop_sent_msg().await;
    let status = helper_send_receive_status_update(bob, alice, &bob_instance, &instance).await?;

    assert_eq!(
        status,
        r#"[{"payload":7,"info":"i","summary":"s","serial":1,"max_serial":1}]"#
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_delete_event() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let chat_id = create_group_chat(&alice, ProtectionStatus::Unprotected, "foo").await?;
    let instance = send_webxdc_instance(&alice, chat_id).await?;
    message::delete_msgs(&alice, &[instance.id]).await?;
    alice
        .evtracker
        .get_matching(|evt| matches!(evt, EventType::WebxdcInstanceDeleted { .. }))
        .await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn change_logging_webxdc() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let chat_id = ChatId::create_for_contact(&alice, ContactId::SELF).await?;

    assert_eq!(
        alice
            .sql
            .count("SELECT COUNT(*) FROM msgs_status_updates;", ())
            .await?,
        0
    );

    let mut instance = create_webxdc_instance(
        &alice,
        "debug_logging.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )?;
    assert!(alice.debug_logging.read().unwrap().is_none());
    send_msg(&alice, chat_id, &mut instance).await?;
    assert!(alice.debug_logging.read().unwrap().is_some());

    alice.emit_event(EventType::Info("hi".to_string()));
    alice
        .evtracker
        .get_matching(|ev| matches!(*ev, EventType::WebxdcStatusUpdate { .. }))
        .await;
    assert!(
        alice
            .sql
            .count("SELECT COUNT(*) FROM msgs_status_updates;", ())
            .await?
            > 0
    );
    Ok(())
}

/// Tests extensibility of WebXDC updates.
///
/// If an update sent by WebXDC contains unknown properties,
/// such as `aNewUnknownProperty` or a reserved property
/// like `serial` or `max_serial`,
/// they are silently dropped and are not sent over the wire.
///
/// This ensures new WebXDC can try to send new properties
/// added in later revisions of the WebXDC API
/// and this will not result in a failure to send the whole update.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_send_webxdc_status_update_extensibility() -> Result<()> {
    let alice = TestContext::new_alice().await;
    let bob = TestContext::new_bob().await;
    let alice_chat = alice.create_chat(&bob).await;
    let alice_instance = send_webxdc_instance(&alice, alice_chat.id).await?;

    let bob_instance = bob.recv_msg(&alice.pop_sent_msg().await).await;

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            r#"{"payload":"p","info":"i","aNewUnknownProperty":"x","max_serial":123}"#,
        )
        .await?;
    alice.flush_status_updates().await?;
    let received_update = bob.recv_msg_opt(&alice.pop_sent_msg().await).await;
    assert!(received_update.is_none());

    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":"p","info":"i","serial":1,"max_serial":1}]"#
    );

    Ok(())
}

// NB: This test also checks that a contact is not marked as bot after receiving from it a
// webxdc instance and status updates.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_status_update_vs_delete_device_after() -> Result<()> {
    let alice = &TestContext::new_alice().await;
    let bob = &TestContext::new_bob().await;
    bob.set_config(Config::DeleteDeviceAfter, Some("3600"))
        .await?;
    let alice_chat = alice.create_chat(bob).await;
    let alice_instance = send_webxdc_instance(alice, alice_chat.id).await?;
    let bob_instance = bob.recv_msg(&alice.pop_sent_msg().await).await;
    assert_eq!(bob.add_or_lookup_contact(alice).await.is_bot(), false);

    SystemTime::shift(Duration::from_secs(1800));
    let mut update = Message {
        chat_id: alice_chat.id,
        viewtype: Viewtype::Text,
        text: "I'm an update".to_string(),
        hidden: true,
        ..Default::default()
    };
    update.param.set_cmd(SystemMessage::WebxdcStatusUpdate);
    update
        .param
        .set(Param::Arg, r#"{"updates":[{"payload":{"foo":"bar"}}]}"#);
    update.set_quote(alice, Some(&alice_instance)).await?;
    let sent_msg = alice.send_msg(alice_chat.id, &mut update).await;
    bob.recv_msg_trash(&sent_msg).await;
    assert_eq!(bob.add_or_lookup_contact(alice).await.is_bot(), false);
    assert_eq!(
        bob.get_webxdc_status_updates(bob_instance.id, StatusUpdateSerial(0))
            .await?,
        r#"[{"payload":{"foo":"bar"},"serial":1,"max_serial":1}]"#
    );
    assert_eq!(bob.add_or_lookup_contact(alice).await.is_bot(), false);

    SystemTime::shift(Duration::from_secs(2700));
    ephemeral::delete_expired_messages(bob, tools::time()).await?;
    let bob_instance = Message::load_from_db(bob, bob_instance.id).await?;
    assert_eq!(bob_instance.chat_id.is_trash(), false);

    Ok(())
}

async fn has_incoming_webxdc_event(
    t: &TestContext,
    expected_msg: Message,
    expected_text: &str,
) -> bool {
    t.evtracker
        .get_matching_opt(t, |evt| {
            if let EventType::IncomingWebxdcNotify { msg_id, text, .. } = evt {
                *msg_id == expected_msg.id && text == expected_text
            } else {
                false
            }
        })
        .await
        .is_some()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_notify_one() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    let grp_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[&bob, &fiona])
        .await;
    let alice_instance = send_webxdc_instance(&alice, grp_id).await?;
    let sent1 = alice.pop_sent_msg().await;
    let bob_instance = bob.recv_msg(&sent1).await;
    let _fiona_instance = fiona.recv_msg(&sent1).await;

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            &format!(
                "{{\"payload\":7,\"info\": \"Alice moved\",\"notify\":{{\"{}\": \"Your move!\"}} }}",
                bob_instance.get_webxdc_self_addr(&bob).await?
            ),
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;
    let info_msg = alice.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.text, "Alice moved");
    assert!(!has_incoming_webxdc_event(&alice, info_msg, "").await);

    bob.recv_msg_trash(&sent2).await;
    let info_msg = bob.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.text, "Alice moved");
    assert!(has_incoming_webxdc_event(&bob, info_msg, "Your move!").await);

    fiona.recv_msg_trash(&sent2).await;
    let info_msg = fiona.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.text, "Alice moved");
    assert!(!has_incoming_webxdc_event(&fiona, info_msg, "").await);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_notify_multiple() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    let grp_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[&bob, &fiona])
        .await;
    let alice_instance = send_webxdc_instance(&alice, grp_id).await?;
    let sent1 = alice.pop_sent_msg().await;
    let bob_instance = bob.recv_msg(&sent1).await;
    let fiona_instance = fiona.recv_msg(&sent1).await;

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            &format!(
                "{{\"payload\":7,\"info\": \"moved\", \"summary\": \"move summary\", \"notify\":{{\"{}\":\"move, Bob\",\"{}\":\"move, Fiona\"}} }}",
                bob_instance.get_webxdc_self_addr(&bob).await?,
                fiona_instance.get_webxdc_self_addr(&fiona).await?
            ),

        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;
    let info_msg = alice.get_last_msg().await;
    assert!(info_msg.is_info());
    assert!(!has_incoming_webxdc_event(&alice, info_msg, "").await);

    bob.recv_msg_trash(&sent2).await;
    let info_msg = bob.get_last_msg().await;
    assert!(info_msg.is_info());
    assert!(has_incoming_webxdc_event(&bob, info_msg, "move, Bob").await);

    fiona.recv_msg_trash(&sent2).await;
    let info_msg = fiona.get_last_msg().await;
    assert!(info_msg.is_info());
    assert!(has_incoming_webxdc_event(&fiona, info_msg, "move, Fiona").await);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_no_notify_self() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let alice2 = tcm.alice().await;

    let grp_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[])
        .await;
    let alice_instance = send_webxdc_instance(&alice, grp_id).await?;
    let sent1 = alice.pop_sent_msg().await;
    let alice2_instance = alice2.recv_msg(&sent1).await;
    assert_eq!(
        alice_instance.get_webxdc_self_addr(&alice).await?,
        alice2_instance.get_webxdc_self_addr(&alice2).await?
    );

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            &format!(
                "{{\"payload\":7,\"info\": \"moved\", \"notify\":{{\"{}\": \"bla\"}} }}",
                alice2_instance.get_webxdc_self_addr(&alice2).await?
            ),
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;
    let info_msg = alice.get_last_msg().await;
    assert!(info_msg.is_info());
    assert!(!has_incoming_webxdc_event(&alice, info_msg, "").await);

    alice2.recv_msg_trash(&sent2).await;
    let info_msg = alice2.get_last_msg().await;
    assert!(info_msg.is_info());
    assert!(!has_incoming_webxdc_event(&alice2, info_msg, "").await);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_notify_all() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    let grp_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[&bob, &fiona])
        .await;
    let alice_instance = send_webxdc_instance(&alice, grp_id).await?;
    let sent1 = alice.pop_sent_msg().await;
    bob.recv_msg(&sent1).await;
    fiona.recv_msg(&sent1).await;

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            "{\"payload\":7,\"info\": \"go\", \"notify\":{\"*\":\"notify all\"} }",
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;
    let info_msg = alice.get_last_msg().await;
    assert_eq!(info_msg.text, "go");
    assert!(!has_incoming_webxdc_event(&alice, info_msg, "").await);

    bob.recv_msg_trash(&sent2).await;
    let info_msg = bob.get_last_msg().await;
    assert_eq!(info_msg.text, "go");
    assert!(has_incoming_webxdc_event(&bob, info_msg, "notify all").await);

    fiona.recv_msg_trash(&sent2).await;
    let info_msg = fiona.get_last_msg().await;
    assert_eq!(info_msg.text, "go");
    assert!(has_incoming_webxdc_event(&fiona, info_msg, "notify all").await);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_notify_bob_and_all() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    let grp_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[&bob, &fiona])
        .await;
    let alice_instance = send_webxdc_instance(&alice, grp_id).await?;
    let sent1 = alice.pop_sent_msg().await;
    let bob_instance = bob.recv_msg(&sent1).await;
    let fiona_instance = fiona.recv_msg(&sent1).await;

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            &format!(
                "{{\"payload\":7, \"notify\":{{\"{}\": \"notify bob\",\"*\": \"notify all\"}} }}",
                bob_instance.get_webxdc_self_addr(&bob).await?
            ),
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;
    bob.recv_msg_trash(&sent2).await;
    fiona.recv_msg_trash(&sent2).await;
    assert!(has_incoming_webxdc_event(&bob, bob_instance, "notify bob").await);
    assert!(has_incoming_webxdc_event(&fiona, fiona_instance, "notify all").await);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_notify_all_and_bob() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;
    let fiona = tcm.fiona().await;

    let grp_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[&bob, &fiona])
        .await;
    let alice_instance = send_webxdc_instance(&alice, grp_id).await?;
    let sent1 = alice.pop_sent_msg().await;
    let bob_instance = bob.recv_msg(&sent1).await;
    let fiona_instance = fiona.recv_msg(&sent1).await;

    alice
        .send_webxdc_status_update(
            alice_instance.id,
            &format!(
                "{{\"payload\":7, \"notify\":{{\"*\": \"notify all\", \"{}\": \"notify bob\"}} }}",
                bob_instance.get_webxdc_self_addr(&bob).await?
            ),
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;
    bob.recv_msg_trash(&sent2).await;
    fiona.recv_msg_trash(&sent2).await;
    assert!(has_incoming_webxdc_event(&bob, bob_instance, "notify bob").await);
    assert!(has_incoming_webxdc_event(&fiona, fiona_instance, "notify all").await);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_href() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = tcm.alice().await;
    let bob = tcm.bob().await;

    let grp_id = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "grp", &[&bob])
        .await;
    let instance = send_webxdc_instance(&alice, grp_id).await?;
    let sent1 = alice.pop_sent_msg().await;

    alice
        .send_webxdc_status_update(
            instance.id,
            r##"{"payload": "my deeplink data", "info": "my move!", "href": "#foobar"}"##,
        )
        .await?;
    alice.flush_status_updates().await?;
    let sent2 = alice.pop_sent_msg().await;
    let info_msg = alice.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.get_webxdc_href(), Some("#foobar".to_string()));

    bob.recv_msg(&sent1).await;
    bob.recv_msg_trash(&sent2).await;
    let info_msg = bob.get_last_msg().await;
    assert!(info_msg.is_info());
    assert_eq!(info_msg.get_webxdc_href(), Some("#foobar".to_string()));

    Ok(())
}

/// Test that the draft `selfAddr` is equal to the `selfAddr` of the sent message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_self_addr_consistency() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let alice_chat = alice
        .create_group_with_members(ProtectionStatus::Unprotected, "No friends :(", &[])
        .await;
    let mut instance = create_webxdc_instance(
        alice,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
    )?;
    alice_chat.set_draft(alice, Some(&mut instance)).await?;
    let mut instance = alice_chat.get_draft(alice).await?.unwrap();
    let self_addr = instance.get_webxdc_self_addr(alice).await?;
    let sent = alice.send_msg(alice_chat, &mut instance).await;
    let db_msg = Message::load_from_db(alice, sent.sender_msg_id).await?;
    assert_eq!(db_msg.get_webxdc_self_addr(alice).await?, self_addr);
    assert_eq!(alice_chat.get_msg_cnt(alice).await?, 1);
    Ok(())
}
