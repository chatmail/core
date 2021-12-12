//! # Handle W30 messages.

use crate::constants::Viewtype;
use crate::context::Context;
use crate::message::{Message, MessageState, MsgId};
use crate::mimeparser::SystemMessage;
use crate::param::Param;
use crate::{chat, EventType};
use anyhow::{bail, Result};
use lettre_email::mime::{self};
use lettre_email::PartBuilder;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::convert::TryFrom;

pub const W30_SUFFIX: &str = "w30";

/// Status Update ID.
#[derive(
    Debug, Copy, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct StatusUpdateId(u32);

impl StatusUpdateId {
    /// Create a new [MsgId].
    pub fn new(id: u32) -> StatusUpdateId {
        StatusUpdateId(id)
    }

    /// Gets StatusUpdateId as untyped integer.
    /// Avoid using this outside ffi.
    pub fn to_u32(self) -> u32 {
        self.0
    }
}

impl rusqlite::types::ToSql for StatusUpdateId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput> {
        let val = rusqlite::types::Value::Integer(self.0 as i64);
        let out = rusqlite::types::ToSqlOutput::Owned(val);
        Ok(out)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct StatusUpdateItem {
    payload: Value,
}

impl Context {
    pub(crate) async fn is_w30_file(&self, filename: &str, _decoded_data: &[u8]) -> Result<bool> {
        if filename.ends_with(W30_SUFFIX) {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn create_status_update_record(
        &self,
        instance_msg_id: MsgId,
        payload: &str,
    ) -> Result<StatusUpdateId> {
        let payload = payload.trim();
        if payload.is_empty() {
            bail!("create_status_update_record: empty payload");
        }
        let _test: Value = serde_json::from_str(payload)?; // checks if input data are valid json

        let rowid = self
            .sql
            .insert(
                "INSERT INTO msgs_status_updates (msg_id, payload) VALUES(?, ?);",
                paramsv![instance_msg_id, payload],
            )
            .await?;
        Ok(StatusUpdateId(u32::try_from(rowid)?))
    }

    /// Sends a status update for an w30 instance.
    ///
    /// If the instance is a draft,
    /// the status update is sent once the instance is actually sent.
    ///
    /// If an update is sent immediately, the message-id of the update-message is returned,
    /// this update-message is visible in chats, however, the id may be useful.
    pub async fn send_w30_status_update(
        &self,
        instance_msg_id: MsgId,
        descr: &str,
        payload: &str,
    ) -> Result<Option<MsgId>> {
        let instance = Message::load_from_db(self, instance_msg_id).await?;
        if instance.viewtype != Viewtype::W30 {
            bail!("send_w30_status_update: is no w30 message");
        }

        let status_update_id = self
            .create_status_update_record(instance_msg_id, payload)
            .await?;

        match instance.state {
            MessageState::Undefined | MessageState::OutPreparing | MessageState::OutDraft => {
                // send update once the instance is actually send;
                // on sending, the updates are retrieved using get_w30_status_updates_with_format() then.
                Ok(None)
            }
            _ => {
                // send update now
                // (also send updates on MessagesState::Failed, maybe only one member cannot receive)
                let mut status_update = Message {
                    chat_id: instance.chat_id,
                    viewtype: Viewtype::Text,
                    text: Some(descr.to_string()),
                    hidden: true,
                    ..Default::default()
                };
                status_update.param.set_cmd(SystemMessage::W30StatusUpdate);
                status_update.param.set(
                    Param::Arg,
                    self.get_w30_status_updates_with_format(
                        instance_msg_id,
                        Some(status_update_id),
                        true,
                    )
                    .await?,
                );
                status_update.set_quote(self, &instance).await?;
                let status_update_msg_id =
                    chat::send_msg(self, instance.chat_id, &mut status_update).await?;
                Ok(Some(status_update_msg_id))
            }
        }
    }

    pub(crate) async fn build_status_update_part(&self, json: &str) -> PartBuilder {
        PartBuilder::new()
            .content_type(&"application/json".parse::<mime::Mime>().unwrap())
            .header((
                "Content-Disposition",
                "attachment; filename=\"status-update.json\"",
            ))
            .body(json)
    }

    /// Receives status updates from receive_imf to the database
    /// and sends out an event.
    ///
    /// `msg_id` may be an instance (in case there are initial status updates)
    /// or a reply to an instance (for all other updates).
    ///
    /// `json` is an array containing one or more payloads as created by send_w30_status_update(),
    /// the array is parsed using serde, the single payloads are used as is.
    pub(crate) async fn receive_status_update(&self, msg_id: MsgId, json: &str) -> Result<()> {
        let msg = Message::load_from_db(self, msg_id).await?;
        let instance = if msg.viewtype == Viewtype::W30 {
            msg
        } else if let Some(parent) = msg.parent(self).await? {
            if parent.viewtype == Viewtype::W30 {
                parent
            } else {
                bail!("receive_status_update: message is not the child of a W30 message.")
            }
        } else {
            bail!("receive_status_update: status message has no parent.")
        };

        let update_items: Vec<StatusUpdateItem> = serde_json::from_str(json)?;
        for update_item in update_items {
            let status_update_id = self
                .create_status_update_record(
                    instance.id,
                    &*serde_json::to_string(&update_item.payload)?,
                )
                .await?;
            self.emit_event(EventType::W30StatusUpdate {
                msg_id: instance.id,
                status_update_id,
            });
        }

        Ok(())
    }

    /// Returns status updates as an JSON-array.
    ///
    /// The updates may be filtered by a given status_update_id;
    /// if no updates are available, an empty JSON-array is returned.
    pub async fn get_w30_status_updates(
        &self,
        instance_msg_id: MsgId,
        status_update_id: Option<StatusUpdateId>,
    ) -> Result<String> {
        self.get_w30_status_updates_with_format(instance_msg_id, status_update_id, false)
            .await
    }

    /// Returns status updates as JSON-array.
    ///
    /// If `for_wire` is `false`, the result is suitable to be passed to the app,
    /// that get back exactly the payloads as sent:
    /// `["any update data", "another update data"]`
    /// get_w30_status_updates() returns this format.
    ///
    /// If `for_wire` is `true`, the payload is wrapped to an object
    /// and can be enhanced in the future:
    /// `[{"payload":"any update data"},{"payload":"another update data"}]`
    /// This is suitable for sending objects  that are not visible to apps:
    pub(crate) async fn get_w30_status_updates_with_format(
        &self,
        instance_msg_id: MsgId,
        status_update_id: Option<StatusUpdateId>,
        for_wire: bool,
    ) -> Result<String> {
        let json = self
            .sql
            .query_map(
                "SELECT payload FROM msgs_status_updates WHERE msg_id=? AND (1=? OR id=?)",
                paramsv![
                    instance_msg_id,
                    if status_update_id.is_some() { 0 } else { 1 },
                    status_update_id.unwrap_or(StatusUpdateId(0))
                ],
                |row| row.get::<_, String>(0),
                |rows| {
                    let mut json = String::default();
                    for row in rows {
                        let payload = row?;
                        if !json.is_empty() {
                            json.push_str(",\n");
                        }
                        if for_wire {
                            json.push_str("{\"payload\":");
                        }
                        json.push_str(&payload);
                        if for_wire {
                            json.push('}');
                        }
                    }
                    Ok(json)
                },
            )
            .await?;
        Ok(format!("[{}]", json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::{create_group_chat, send_msg, send_text_msg, ChatId, ProtectionStatus};
    use crate::dc_receive_imf::dc_receive_imf;
    use crate::test_utils::TestContext;
    use crate::Event;
    use async_std::fs::File;
    use async_std::io::WriteExt;
    use async_std::prelude::*;
    use std::time::Duration;

    #[async_std::test]
    async fn test_is_w30_file() -> Result<()> {
        let t = TestContext::new().await;
        assert!(
            !t.is_w30_file(
                "issue_523.txt",
                include_bytes!("../test-data/message/issue_523.txt")
            )
            .await?
        );
        assert!(
            t.is_w30_file(
                "minimal.w30",
                include_bytes!("../test-data/w30/minimal.w30")
            )
            .await?
        );
        Ok(())
    }

    async fn create_w30_instance(t: &TestContext) -> Result<Message> {
        let file = t.get_blobdir().join("index.w30");
        File::create(&file)
            .await?
            .write_all("<html>ola!</html>".as_ref())
            .await?;
        let mut instance = Message::new(Viewtype::File);
        instance.set_file(file.to_str().unwrap(), None);
        Ok(instance)
    }

    async fn send_w30_instance(t: &TestContext, chat_id: ChatId) -> Result<Message> {
        let mut instance = create_w30_instance(t).await?;
        let instance_msg_id = send_msg(t, chat_id, &mut instance).await?;
        Message::load_from_db(t, instance_msg_id).await
    }

    #[async_std::test]
    async fn test_send_w30_instance() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

        // send as .w30 file
        let instance = send_w30_instance(&t, chat_id).await?;
        assert_eq!(instance.viewtype, Viewtype::W30);
        assert_eq!(instance.get_filename(), Some("index.w30".to_string()));
        assert_eq!(instance.chat_id, chat_id);

        // sending using bad extension is not working, even when setting Viewtype to W30
        let file = t.get_blobdir().join("index.html");
        File::create(&file)
            .await?
            .write_all("<html>ola!</html>".as_ref())
            .await?;
        let mut instance = Message::new(Viewtype::W30);
        instance.set_file(file.to_str().unwrap(), None);
        assert!(send_msg(&t, chat_id, &mut instance).await.is_err());

        Ok(())
    }

    #[async_std::test]
    async fn test_receive_w30_instance() -> Result<()> {
        let t = TestContext::new_alice().await;
        dc_receive_imf(
            &t,
            include_bytes!("../test-data/message/w30_good_extension.eml"),
            "INBOX",
            1,
            false,
        )
        .await?;
        let instance = t.get_last_msg().await;
        assert_eq!(instance.viewtype, Viewtype::W30);
        assert_eq!(instance.get_filename(), Some("index.w30".to_string()));

        dc_receive_imf(
            &t,
            include_bytes!("../test-data/message/w30_bad_extension.eml"),
            "INBOX",
            2,
            false,
        )
        .await?;
        let instance = t.get_last_msg().await;
        assert_eq!(instance.viewtype, Viewtype::File); // we require the correct extension, only a mime type is not sufficient
        assert_eq!(instance.get_filename(), Some("index.html".to_string()));

        Ok(())
    }

    #[async_std::test]
    async fn test_delete_w30_instance() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;

        let mut instance = create_w30_instance(&t).await?;
        chat_id.set_draft(&t, Some(&mut instance)).await?;
        let instance = chat_id.get_draft(&t).await?.unwrap();
        t.send_w30_status_update(instance.id, "descr", "42").await?;
        assert_eq!(
            t.get_w30_status_updates(instance.id, None).await?,
            "[42]".to_string()
        );

        // set_draft(None) deletes the message without the need to simulate network
        chat_id.set_draft(&t, None).await?;
        assert_eq!(
            t.get_w30_status_updates(instance.id, None).await?,
            "[]".to_string()
        );
        assert_eq!(
            t.sql
                .count("SELECT COUNT(*) FROM msgs_status_updates;", paramsv![],)
                .await?,
            0
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_create_status_update_record() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
        let instance = send_w30_instance(&t, chat_id).await?;

        assert_eq!(t.get_w30_status_updates(instance.id, None).await?, "[]");

        let id = t
            .create_status_update_record(instance.id, "\n\n{\"foo\":\"bar\"}\n")
            .await?;
        assert_eq!(
            t.get_w30_status_updates(instance.id, Some(id)).await?,
            r#"[{"foo":"bar"}]"#
        );

        assert!(t
            .create_status_update_record(instance.id, "\n\n\n")
            .await
            .is_err());
        assert!(t
            .create_status_update_record(instance.id, "bad json")
            .await
            .is_err());
        assert_eq!(
            t.get_w30_status_updates(instance.id, Some(id)).await?,
            r#"[{"foo":"bar"}]"#
        );
        assert_eq!(
            t.get_w30_status_updates(instance.id, None).await?,
            r#"[{"foo":"bar"}]"#
        );

        let id = t
            .create_status_update_record(instance.id, r#"{"foo2":"bar2"}"#)
            .await?;
        assert_eq!(
            t.get_w30_status_updates(instance.id, Some(id)).await?,
            r#"[{"foo2":"bar2"}]"#
        );
        t.create_status_update_record(instance.id, "true").await?;
        assert_eq!(
            t.get_w30_status_updates(instance.id, None).await?,
            r#"[{"foo":"bar"},
{"foo2":"bar2"},
true]"#
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_receive_status_update() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
        let instance = send_w30_instance(&t, chat_id).await?;

        assert!(t
            .receive_status_update(instance.id, r#"foo: bar"#)
            .await
            .is_err()); // no json
        assert!(t
            .receive_status_update(instance.id, r#"[{"foo":"bar"}]"#)
            .await
            .is_err()); // "payload" field missing
        assert!(t
            .receive_status_update(instance.id, r#"{"payload":{"foo":"bar"}}"#)
            .await
            .is_err()); // not an array

        t.receive_status_update(instance.id, r#"[{"payload":{"foo":"bar"}}]"#)
            .await?;
        assert_eq!(
            t.get_w30_status_updates(instance.id, None).await?,
            r#"[{"foo":"bar"}]"#
        );

        t.receive_status_update(instance.id, r#" [ {"payload" :42} , {"payload": 23} ] "#)
            .await?;
        assert_eq!(
            t.get_w30_status_updates(instance.id, None).await?,
            r#"[{"foo":"bar"},
42,
23]"#
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_send_w30_status_update() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let bob = TestContext::new_bob().await;

        // Alice sends an w30 instance and a status update
        let alice_chat = alice.create_chat(&bob).await;
        let alice_instance = send_w30_instance(&alice, alice_chat.id).await?;
        let sent1 = &alice.pop_sent_msg().await;
        assert_eq!(alice_instance.viewtype, Viewtype::W30);
        assert!(!sent1.payload().contains("report-type=status-update"));

        let status_update_msg_id = alice
            .send_w30_status_update(alice_instance.id, "descr text", r#"{"foo":"bar"}"#)
            .await?
            .unwrap();
        let sent2 = &alice.pop_sent_msg().await;
        let alice_update = Message::load_from_db(&alice, status_update_msg_id).await?;
        assert!(alice_update.hidden);
        assert_eq!(alice_update.viewtype, Viewtype::Text);
        assert_eq!(alice_update.get_filename(), None);
        assert_eq!(alice_update.text, Some("descr text".to_string()));
        assert_eq!(alice_update.chat_id, alice_instance.chat_id);
        assert_eq!(
            alice_update.parent(&alice).await?.unwrap().id,
            alice_instance.id
        );
        assert_eq!(alice_chat.id.get_msg_cnt(&alice).await?, 1);
        assert!(sent2.payload().contains("report-type=status-update"));
        assert!(sent2.payload().contains("descr text"));
        assert_eq!(
            alice
                .get_w30_status_updates(alice_instance.id, None)
                .await?,
            r#"[{"foo":"bar"}]"#
        );

        alice
            .send_w30_status_update(alice_instance.id, "bla text", r#"{"snipp":"snapp"}"#)
            .await?
            .unwrap();
        assert_eq!(
            alice
                .get_w30_status_updates(alice_instance.id, None)
                .await?,
            r#"[{"foo":"bar"},
{"snipp":"snapp"}]"#
        );

        // Bob receives all messages
        bob.recv_msg(sent1).await;
        let bob_instance = bob.get_last_msg().await;
        let bob_chat_id = bob_instance.chat_id;
        assert_eq!(bob_instance.rfc724_mid, alice_instance.rfc724_mid);
        assert_eq!(bob_instance.viewtype, Viewtype::W30);
        assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 1);

        let (event_tx, event_rx) = async_std::channel::bounded(100);
        bob.add_event_sink(move |event: Event| {
            let event_tx = event_tx.clone();
            async move {
                if let EventType::W30StatusUpdate { .. } = event.typ {
                    event_tx.try_send(event).unwrap();
                }
            }
        })
        .await;
        bob.recv_msg(sent2).await;
        let event = event_rx
            .recv()
            .timeout(Duration::from_secs(10))
            .await
            .expect("timeout waiting for W30StatusUpdate event")
            .expect("missing W30StatusUpdate event");
        match event.typ {
            EventType::W30StatusUpdate {
                msg_id,
                status_update_id,
            } => {
                assert_eq!(
                    bob.get_w30_status_updates(msg_id, Some(status_update_id))
                        .await?,
                    r#"[{"foo":"bar"}]"#
                );
                assert_eq!(msg_id, bob_instance.id);
            }
            _ => panic!("Wrong event type"),
        }
        assert_eq!(bob_chat_id.get_msg_cnt(&bob).await?, 1);

        assert_eq!(
            bob.get_w30_status_updates(bob_instance.id, None).await?,
            r#"[{"foo":"bar"}]"#
        );

        // Alice has a second device and also receives messages there
        let alice2 = TestContext::new_alice().await;
        alice2.recv_msg(sent1).await;
        alice2.recv_msg(sent2).await;
        let alice2_instance = alice2.get_last_msg().await;
        let alice2_chat_id = alice2_instance.chat_id;
        assert_eq!(alice2_instance.viewtype, Viewtype::W30);
        assert_eq!(alice2_chat_id.get_msg_cnt(&alice2).await?, 1);

        Ok(())
    }

    #[async_std::test]
    async fn test_draft_and_send_w30_status_update() -> Result<()> {
        let alice = TestContext::new_alice().await;
        let bob = TestContext::new_bob().await;
        let alice_chat_id = alice.create_chat(&bob).await.id;

        // prepare w30 instance,
        // status updates are not sent for drafts, therefore send_w30_status_update() returns Ok(None)
        let mut alice_instance = create_w30_instance(&alice).await?;
        alice_chat_id
            .set_draft(&alice, Some(&mut alice_instance))
            .await?;
        let mut alice_instance = alice_chat_id.get_draft(&alice).await?.unwrap();

        let status_update_msg_id = alice
            .send_w30_status_update(alice_instance.id, "descr", r#"{"foo":"bar"}"#)
            .await?;
        assert_eq!(status_update_msg_id, None);
        let status_update_msg_id = alice
            .send_w30_status_update(alice_instance.id, "descr", r#"42"#)
            .await?;
        assert_eq!(status_update_msg_id, None);

        // send w30 instance,
        // the initial status updates are sent together in the same message
        let alice_instance_id = send_msg(&alice, alice_chat_id, &mut alice_instance).await?;
        let sent1 = alice.pop_sent_msg().await;
        let alice_instance = Message::load_from_db(&alice, alice_instance_id).await?;
        assert_eq!(alice_instance.viewtype, Viewtype::W30);
        assert_eq!(alice_instance.get_filename(), Some("index.w30".to_string()));
        assert_eq!(alice_instance.chat_id, alice_chat_id);

        // bob receives the instance together with the initial updates in a single message
        bob.recv_msg(&sent1).await;
        let bob_instance = bob.get_last_msg().await;
        assert_eq!(bob_instance.viewtype, Viewtype::W30);
        assert_eq!(bob_instance.get_filename(), Some("index.w30".to_string()));
        assert!(sent1.payload().contains("Content-Type: application/json"));
        assert!(sent1.payload().contains("status-update.json"));
        assert!(sent1.payload().contains(r#""payload":{"foo":"bar"}"#));
        assert_eq!(
            bob.get_w30_status_updates(bob_instance.id, None).await?,
            r#"[{"foo":"bar"},
42]"#
        );

        Ok(())
    }

    #[async_std::test]
    async fn test_send_w30_status_update_to_non_w30() -> Result<()> {
        let t = TestContext::new_alice().await;
        let chat_id = create_group_chat(&t, ProtectionStatus::Unprotected, "foo").await?;
        let msg_id = send_text_msg(&t, chat_id, "ho!".to_string()).await?;
        assert!(t
            .send_w30_status_update(msg_id, "descr", r#"{"foo":"bar"}"#)
            .await
            .is_err());
        Ok(())
    }
}
