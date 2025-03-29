//! # Synchronize items between devices.

use anyhow::Result;
use mail_builder::mime::MimePart;
use serde::{Deserialize, Serialize};

use crate::chat::{self, ChatId};
use crate::config::Config;
use crate::constants::Blocked;
use crate::contact::ContactId;
use crate::context::Context;
use crate::log::LogExt;
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::param::Param;
use crate::sync::SyncData::{AddQrToken, AlterChat, DeleteQrToken};
use crate::token::Namespace;
use crate::tools::time;
use crate::{message, stock_str, token};
use std::collections::HashSet;

/// Whether to send device sync messages. Aimed for usage in the internal API.
#[derive(Debug, PartialEq)]
pub(crate) enum Sync {
    Nosync,
    Sync,
}

impl From<Sync> for bool {
    fn from(sync: Sync) -> bool {
        match sync {
            Sync::Nosync => false,
            Sync::Sync => true,
        }
    }
}

impl From<bool> for Sync {
    fn from(sync: bool) -> Sync {
        match sync {
            false => Sync::Nosync,
            true => Sync::Sync,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct QrTokenData {
    pub(crate) invitenumber: String,
    pub(crate) auth: String,
    pub(crate) grpid: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum SyncData {
    AddQrToken(QrTokenData),
    DeleteQrToken(QrTokenData),
    AlterChat {
        id: chat::SyncId,
        action: chat::SyncAction,
    },
    Config {
        key: Config,
        val: String,
    },
    SaveMessage {
        src: String,  // RFC724 id (i.e. "Message-Id" header)
        dest: String, // RFC724 id (i.e. "Message-Id" header)
    },
    DeleteMessages {
        msgs: Vec<String>, // RFC724 id (i.e. "Message-Id" header)
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum SyncDataOrUnknown {
    SyncData(SyncData),
    Unknown(serde_json::Value),
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SyncItem {
    timestamp: i64,

    data: SyncDataOrUnknown,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SyncItems {
    items: Vec<SyncItem>,
}

impl From<SyncData> for SyncDataOrUnknown {
    fn from(sync_data: SyncData) -> Self {
        Self::SyncData(sync_data)
    }
}

impl Context {
    /// Adds an item to the list of items that should be synchronized to other devices.
    ///
    /// NB: Private and `pub(crate)` functions shouldn't call this unless `Sync::Sync` is explicitly
    /// passed to them. This way it's always clear whether the code performs synchronisation.
    pub(crate) async fn add_sync_item(&self, data: SyncData) -> Result<()> {
        self.add_sync_item_with_timestamp(data, time()).await
    }

    /// Adds item and timestamp to the list of items that should be synchronized to other devices.
    /// If device synchronization is disabled, the function does nothing.
    async fn add_sync_item_with_timestamp(&self, data: SyncData, timestamp: i64) -> Result<()> {
        if !self.should_send_sync_msgs().await? {
            return Ok(());
        }

        let item = SyncItem {
            timestamp,
            data: data.into(),
        };
        let item = serde_json::to_string(&item)?;
        self.sql
            .execute("INSERT INTO multi_device_sync (item) VALUES(?);", (item,))
            .await?;

        Ok(())
    }

    /// Adds most recent qr-code tokens for the given group or self-contact to the list of items to
    /// be synced. If device synchronization is disabled,
    /// no tokens exist or the chat is unpromoted, the function does nothing.
    /// The caller should call `SchedulerState::interrupt_inbox()` on its own to trigger sending.
    pub(crate) async fn sync_qr_code_tokens(&self, grpid: Option<&str>) -> Result<()> {
        if !self.should_send_sync_msgs().await? {
            return Ok(());
        }
        if let (Some(invitenumber), Some(auth)) = (
            token::lookup(self, Namespace::InviteNumber, grpid).await?,
            token::lookup(self, Namespace::Auth, grpid).await?,
        ) {
            self.add_sync_item(SyncData::AddQrToken(QrTokenData {
                invitenumber,
                auth,
                grpid: grpid.map(|s| s.to_string()),
            }))
            .await?;
        }
        Ok(())
    }

    /// Adds deleted qr-code token to the list of items to be synced
    /// so that the token also gets deleted on the other devices.
    /// This interrupts SMTP on its own.
    pub(crate) async fn sync_qr_code_token_deletion(
        &self,
        invitenumber: String,
        auth: String,
    ) -> Result<()> {
        self.add_sync_item(SyncData::DeleteQrToken(QrTokenData {
            invitenumber,
            auth,
            grpid: None,
        }))
        .await?;
        self.scheduler.interrupt_inbox().await;
        Ok(())
    }

    /// Sends out a self-sent message with items to be synchronized, if any.
    ///
    /// Mustn't be called from multiple tasks in parallel to avoid sending the same sync items twice
    /// because sync items are removed from the db only after successful sending. We guarantee this
    /// by calling `send_sync_msg()` only from the inbox loop.
    pub async fn send_sync_msg(&self) -> Result<Option<MsgId>> {
        if let Some((json, ids)) = self.build_sync_json().await? {
            let chat_id =
                ChatId::create_for_contact_with_blocked(self, ContactId::SELF, Blocked::Yes)
                    .await?;
            let mut msg = Message {
                chat_id,
                viewtype: Viewtype::Text,
                text: stock_str::sync_msg_body(self).await,
                hidden: true,
                subject: stock_str::sync_msg_subject(self).await,
                ..Default::default()
            };
            msg.param.set_cmd(SystemMessage::MultiDeviceSync);
            msg.param.set(Param::Arg, json);
            msg.param.set(Param::Arg2, ids);
            msg.param.set_int(Param::GuaranteeE2ee, 1);
            Ok(Some(chat::send_msg(self, chat_id, &mut msg).await?))
        } else {
            Ok(None)
        }
    }

    /// Copies all sync items to a JSON string and clears the sync-table.
    /// Returns the JSON string and a comma-separated string of the IDs used.
    pub(crate) async fn build_sync_json(&self) -> Result<Option<(String, String)>> {
        let (ids, serialized) = self
            .sql
            .query_map(
                "SELECT id, item FROM multi_device_sync ORDER BY id;",
                (),
                |row| Ok((row.get::<_, u32>(0)?, row.get::<_, String>(1)?)),
                |rows| {
                    let mut ids = vec![];
                    let mut serialized = String::default();
                    for row in rows {
                        let (id, item) = row?;
                        ids.push(id);
                        if !serialized.is_empty() {
                            serialized.push_str(",\n");
                        }
                        serialized.push_str(&item);
                    }
                    Ok((ids, serialized))
                },
            )
            .await?;

        if ids.is_empty() {
            Ok(None)
        } else {
            Ok(Some((
                format!("{{\"items\":[\n{serialized}\n]}}"),
                ids.iter()
                    .map(|x| x.to_string())
                    .collect::<Vec<String>>()
                    .join(","),
            )))
        }
    }

    pub(crate) fn build_sync_part(&self, json: String) -> MimePart<'static> {
        MimePart::new("application/json", json).attachment("multi-device-sync.json")
    }

    /// Takes a JSON string created by `build_sync_json()`
    /// and construct `SyncItems` from it.
    pub(crate) fn parse_sync_items(&self, serialized: String) -> Result<SyncItems> {
        let sync_items: SyncItems = serde_json::from_str(&serialized)?;
        Ok(sync_items)
    }

    /// Executes sync items sent by other device.
    ///
    /// CAVE: When changing the code to handle other sync items,
    /// take care that does not result in calls to `add_sync_item()`
    /// as otherwise we would add in a dead-loop between two devices
    /// sending message back and forth.
    ///
    /// If an error is returned, the caller shall not try over because some sync items could be
    /// already executed. Sync items are considered independent and executed in the given order but
    /// regardless of whether executing of the previous items succeeded.
    pub(crate) async fn execute_sync_items(&self, items: &SyncItems) {
        info!(self, "executing {} sync item(s)", items.items.len());
        for item in &items.items {
            match &item.data {
                SyncDataOrUnknown::SyncData(data) => match data {
                    AddQrToken(token) => self.add_qr_token(token).await,
                    DeleteQrToken(token) => self.delete_qr_token(token).await,
                    AlterChat { id, action } => self.sync_alter_chat(id, action).await,
                    SyncData::Config { key, val } => self.sync_config(key, val).await,
                    SyncData::SaveMessage { src, dest } => self.save_message(src, dest).await,
                    SyncData::DeleteMessages { msgs } => self.sync_message_deletion(msgs).await,
                },
                SyncDataOrUnknown::Unknown(data) => {
                    warn!(self, "Ignored unknown sync item: {data}.");
                    Ok(())
                }
            }
            .log_err(self)
            .ok();
        }

        // Since there was a sync message, we know that there is a second device.
        // Set BccSelf to true if it isn't already.
        if !items.items.is_empty() && !self.get_config_bool(Config::BccSelf).await.unwrap_or(true) {
            self.set_config_ex(Sync::Nosync, Config::BccSelf, Some("1"))
                .await
                .log_err(self)
                .ok();
        }
    }

    async fn add_qr_token(&self, token: &QrTokenData) -> Result<()> {
        let grpid = token.grpid.as_deref();
        token::save(self, Namespace::InviteNumber, grpid, &token.invitenumber).await?;
        token::save(self, Namespace::Auth, grpid, &token.auth).await?;
        Ok(())
    }

    async fn delete_qr_token(&self, token: &QrTokenData) -> Result<()> {
        token::delete(self, Namespace::InviteNumber, &token.invitenumber).await?;
        token::delete(self, Namespace::Auth, &token.auth).await?;
        Ok(())
    }

    async fn save_message(&self, src_rfc724_mid: &str, dest_rfc724_mid: &String) -> Result<()> {
        if let Some((src_msg_id, _)) = message::rfc724_mid_exists(self, src_rfc724_mid).await? {
            chat::save_copy_in_self_talk(self, &src_msg_id, dest_rfc724_mid).await?;
        }
        Ok(())
    }

    async fn sync_message_deletion(&self, msgs: &Vec<String>) -> Result<()> {
        let mut modified_chat_ids = HashSet::new();
        let mut msg_ids = Vec::new();
        for rfc724_mid in msgs {
            if let Some((msg_id, _)) = message::rfc724_mid_exists(self, rfc724_mid).await? {
                if let Some(msg) = Message::load_from_db_optional(self, msg_id).await? {
                    message::delete_msg_locally(self, &msg).await?;
                    msg_ids.push(msg.id);
                    modified_chat_ids.insert(msg.chat_id);
                } else {
                    warn!(self, "Sync message delete: Database entry does not exist.");
                }
            } else {
                warn!(self, "Sync message delete: {rfc724_mid:?} not found.");
            }
        }
        message::delete_msgs_locally_done(self, &msg_ids, modified_chat_ids).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use anyhow::bail;

    use super::*;
    use crate::chat::{remove_contact_from_chat, Chat, ProtectionStatus};
    use crate::chatlist::Chatlist;
    use crate::contact::{Contact, Origin};
    use crate::securejoin::get_securejoin_qr;
    use crate::test_utils::{self, TestContext, TestContextManager};
    use crate::tools::SystemTime;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_config_sync_msgs() -> Result<()> {
        let t = TestContext::new_alice().await;
        assert_eq!(t.get_config_bool(Config::SyncMsgs).await?, false);
        assert_eq!(t.get_config_bool(Config::BccSelf).await?, true);
        assert_eq!(t.should_send_sync_msgs().await?, false);

        t.set_config_bool(Config::SyncMsgs, true).await?;
        assert_eq!(t.get_config_bool(Config::SyncMsgs).await?, true);
        assert_eq!(t.get_config_bool(Config::BccSelf).await?, true);
        assert_eq!(t.should_send_sync_msgs().await?, true);

        t.set_config_bool(Config::BccSelf, false).await?;
        assert_eq!(t.get_config_bool(Config::SyncMsgs).await?, true);
        assert_eq!(t.get_config_bool(Config::BccSelf).await?, false);
        assert_eq!(t.should_send_sync_msgs().await?, false);

        t.set_config_bool(Config::SyncMsgs, false).await?;
        assert_eq!(t.get_config_bool(Config::SyncMsgs).await?, false);
        assert_eq!(t.get_config_bool(Config::BccSelf).await?, false);
        assert_eq!(t.should_send_sync_msgs().await?, false);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_build_sync_json() -> Result<()> {
        let t = TestContext::new_alice().await;
        t.set_config_bool(Config::SyncMsgs, true).await?;

        assert!(t.build_sync_json().await?.is_none());

        // Having one test on `SyncData::AlterChat` is sufficient here as
        // `chat::SyncAction::SetMuted` introduces enums inside items and `SystemTime`. Let's avoid
        // in-depth testing of the serialiser here which is an external crate.
        t.add_sync_item_with_timestamp(
            SyncData::AlterChat {
                id: chat::SyncId::ContactAddr("bob@example.net".to_string()),
                action: chat::SyncAction::SetMuted(chat::MuteDuration::Until(
                    SystemTime::UNIX_EPOCH + Duration::from_millis(42999),
                )),
            },
            1631781315,
        )
        .await?;

        t.add_sync_item_with_timestamp(
            SyncData::AddQrToken(QrTokenData {
                invitenumber: "testinvite".to_string(),
                auth: "testauth".to_string(),
                grpid: Some("group123".to_string()),
            }),
            1631781316,
        )
        .await?;
        t.add_sync_item_with_timestamp(
            SyncData::DeleteQrToken(QrTokenData {
                invitenumber: "123!?\":.;{}".to_string(),
                auth: "456".to_string(),
                grpid: None,
            }),
            1631781317,
        )
        .await?;

        let (serialized, ids) = t.build_sync_json().await?.unwrap();
        assert_eq!(
            serialized,
            r#"{"items":[
{"timestamp":1631781315,"data":{"AlterChat":{"id":{"ContactAddr":"bob@example.net"},"action":{"SetMuted":{"Until":{"secs_since_epoch":42,"nanos_since_epoch":999000000}}}}}},
{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"testinvite","auth":"testauth","grpid":"group123"}}},
{"timestamp":1631781317,"data":{"DeleteQrToken":{"invitenumber":"123!?\":.;{}","auth":"456","grpid":null}}}
]}"#
        );

        assert!(t.build_sync_json().await?.is_some());
        t.sql
            .execute(
                &format!("DELETE FROM multi_device_sync WHERE id IN ({ids})"),
                (),
            )
            .await?;
        assert!(t.build_sync_json().await?.is_none());

        let sync_items = t.parse_sync_items(serialized)?;
        assert_eq!(sync_items.items.len(), 3);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_build_sync_json_sync_msgs_off() -> Result<()> {
        let t = TestContext::new_alice().await;
        t.set_config_bool(Config::SyncMsgs, false).await?;
        t.add_sync_item(SyncData::AddQrToken(QrTokenData {
            invitenumber: "testinvite".to_string(),
            auth: "testauth".to_string(),
            grpid: Some("group123".to_string()),
        }))
        .await?;
        assert!(t.build_sync_json().await?.is_none());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_parse_sync_items() -> Result<()> {
        let t = TestContext::new_alice().await;

        assert!(t.parse_sync_items(r#"{bad json}"#.to_string()).is_err());

        assert!(t.parse_sync_items(r#"{"badname":[]}"#.to_string()).is_err());

        for bad_item_example in [
            r#"{"items":[{"timestamp":1631781316,"data":{"BadItem":{"invitenumber":"in","auth":"a","grpid":null}}}]}"#,
            r#"{"items":[{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":123}}}]}"#, // `123` is invalid for `String`
            r#"{"items":[{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":true}}}]}"#, // `true` is invalid for `String`
            r#"{"items":[{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":[]}}}]}"#, // `[]` is invalid for `String`
            r#"{"items":[{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":{}}}}]}"#, // `{}` is invalid for `String`
            r#"{"items":[{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","grpid":null}}}]}"#, // missing field
            r#"{"items":[{"timestamp":1631781316,"data":{"AlterChat":{"id":{"ContactAddr":"bob@example.net"},"action":"Burn"}}}]}"#, // Unknown enum value
        ] {
            let sync_items = t.parse_sync_items(bad_item_example.to_string()).unwrap();
            assert_eq!(sync_items.items.len(), 1);
            assert!(matches!(sync_items.items[0].timestamp, 1631781316));
            assert!(matches!(
                sync_items.items[0].data,
                SyncDataOrUnknown::Unknown(_)
            ));
        }

        // Test enums inside items and SystemTime
        let sync_items = t.parse_sync_items(
            r#"{"items":[{"timestamp":1631781318,"data":{"AlterChat":{"id":{"ContactAddr":"bob@example.net"},"action":{"SetMuted":{"Until":{"secs_since_epoch":42,"nanos_since_epoch":999000000}}}}}}]}"#.to_string(),
        )?;
        assert_eq!(sync_items.items.len(), 1);
        let SyncDataOrUnknown::SyncData(AlterChat { id, action }) =
            &sync_items.items.first().unwrap().data
        else {
            bail!("bad item");
        };
        assert_eq!(
            *id,
            chat::SyncId::ContactAddr("bob@example.net".to_string())
        );
        assert_eq!(
            *action,
            chat::SyncAction::SetMuted(chat::MuteDuration::Until(
                SystemTime::UNIX_EPOCH + Duration::from_millis(42999)
            ))
        );

        // empty item list is okay
        assert_eq!(
            t.parse_sync_items(r#"{"items":[]}"#.to_string())?
                .items
                .len(),
            0
        );

        // to allow forward compatibility, additional fields should not break parsing
        let sync_items = t
            .parse_sync_items(
                r#"{"items":[
{"timestamp":1631781316,"data":{"DeleteQrToken":{"invitenumber":"in","auth":"yip","grpid":null}}},
{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":"yip","additional":123,"grpid":null}}}
]}"#
                .to_string(),
            )
            ?;
        assert_eq!(sync_items.items.len(), 2);

        let sync_items = t.parse_sync_items(
            r#"{"items":[
{"timestamp":1631781318,"data":{"AddQrToken":{"invitenumber":"in","auth":"yip","grpid":null}}}
],"additional":"field"}"#
                .to_string(),
        )?;

        assert_eq!(sync_items.items.len(), 1);
        if let SyncDataOrUnknown::SyncData(AddQrToken(token)) =
            &sync_items.items.first().unwrap().data
        {
            assert_eq!(token.invitenumber, "in");
            assert_eq!(token.auth, "yip");
            assert_eq!(token.grpid, None);
        } else {
            bail!("bad item");
        }

        // to allow backward compatibility, missing `Option<>` should not break parsing
        let sync_items = t.parse_sync_items(
               r#"{"items":[{"timestamp":1631781319,"data":{"AddQrToken":{"invitenumber":"in","auth":"a"}}}]}"#.to_string(),
           )
           ?;
        assert_eq!(sync_items.items.len(), 1);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_execute_sync_items() -> Result<()> {
        let t = TestContext::new_alice().await;

        assert!(!token::exists(&t, Namespace::Auth, "yip-auth").await?);

        let sync_items = t
            .parse_sync_items(
                r#"{"items":[
{"timestamp":1631781315,"data":{"AlterChat":{"id":{"ContactAddr":"bob@example.net"},"action":"Block"}}},
{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"yip-in","auth":"a"}}},
{"timestamp":1631781316,"data":{"DeleteQrToken":{"invitenumber":"in","auth":"delete unexistent, shall continue"}}},
{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":"yip-auth"}}},
{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":"foo","grpid":"non-existent"}}},
{"timestamp":1631781316,"data":{"AddQrToken":{"invitenumber":"in","auth":"directly deleted"}}},
{"timestamp":1631781316,"data":{"DeleteQrToken":{"invitenumber":"in","auth":"directly deleted"}}}
]}"#
                .to_string(),
            )
            ?;
        t.execute_sync_items(&sync_items).await;

        assert!(
            Contact::lookup_id_by_addr(&t, "bob@example.net", Origin::Unknown)
                .await?
                .is_none()
        );
        assert!(token::exists(&t, Namespace::InviteNumber, "yip-in").await?);
        assert!(token::exists(&t, Namespace::Auth, "yip-auth").await?);
        assert!(!token::exists(&t, Namespace::Auth, "non-existent").await?);
        assert!(!token::exists(&t, Namespace::Auth, "directly deleted").await?);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_send_sync_msg() -> Result<()> {
        let alice = TestContext::new_alice().await;
        alice.set_config_bool(Config::SyncMsgs, true).await?;
        alice
            .add_sync_item(SyncData::AddQrToken(QrTokenData {
                invitenumber: "in".to_string(),
                auth: "testtoken".to_string(),
                grpid: None,
            }))
            .await?;
        let msg_id = alice.send_sync_msg().await?.unwrap();
        let msg = Message::load_from_db(&alice, msg_id).await?;
        let chat = Chat::load_from_db(&alice, msg.chat_id).await?;
        assert!(chat.is_self_talk());

        // check that the used self-talk is not visible to the user
        // but that creation will still work (in this case, the chat is empty)
        assert_eq!(Chatlist::try_load(&alice, 0, None, None).await?.len(), 0);
        let chat_id = ChatId::create_for_contact(&alice, ContactId::SELF).await?;
        let chat = Chat::load_from_db(&alice, chat_id).await?;
        assert!(chat.is_self_talk());
        assert_eq!(Chatlist::try_load(&alice, 0, None, None).await?.len(), 1);
        let msgs = chat::get_chat_msgs(&alice, chat_id).await?;
        assert_eq!(msgs.len(), 0);

        // let alice's other device receive and execute the sync message,
        // also here, self-talk should stay hidden
        let sent_msg = alice.pop_sent_sync_msg().await;
        let alice2 = TestContext::new_alice().await;
        alice2.set_config_bool(Config::SyncMsgs, true).await?;
        alice2.recv_msg_trash(&sent_msg).await;
        assert!(token::exists(&alice2, token::Namespace::Auth, "testtoken").await?);
        assert_eq!(Chatlist::try_load(&alice2, 0, None, None).await?.len(), 0);

        // Sync messages are "auto-generated", but they mustn't make the self-contact a bot.
        let self_contact = alice2.add_or_lookup_contact(&alice2).await;
        assert!(!self_contact.is_bot());

        // the same sync message sent to bob must not be executed
        let bob = TestContext::new_bob().await;
        bob.recv_msg(&sent_msg).await;
        assert!(!token::exists(&bob, token::Namespace::Auth, "testtoken").await?);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_send_sync_msg_enables_bccself() -> Result<()> {
        for (chatmail, sync_message_sent) in
            [(false, false), (false, true), (true, false), (true, true)]
        {
            let alice1 = TestContext::new_alice().await;
            let alice2 = TestContext::new_alice().await;

            // SyncMsgs defaults to true on real devices, but in tests it defaults to false,
            // so we need to enable it
            alice1.set_config_bool(Config::SyncMsgs, true).await?;
            alice2.set_config_bool(Config::SyncMsgs, true).await?;

            if chatmail {
                alice1.set_config_bool(Config::IsChatmail, true).await?;
                alice2.set_config_bool(Config::IsChatmail, true).await?;
            } else {
                alice2.set_config_bool(Config::BccSelf, false).await?;
            }

            alice1.set_config_bool(Config::BccSelf, true).await?;

            let sent_msg = if sync_message_sent {
                alice1
                    .add_sync_item(SyncData::AddQrToken(QrTokenData {
                        invitenumber: "in".to_string(),
                        auth: "testtoken".to_string(),
                        grpid: None,
                    }))
                    .await?;
                alice1.send_sync_msg().await?.unwrap();
                alice1.pop_sent_sync_msg().await
            } else {
                let chat = alice1.get_self_chat().await;
                alice1.send_text(chat.id, "Hi").await
            };

            // On chatmail accounts, BccSelf defaults to false.
            // When receiving a sync message from another device,
            // there obviously is a multi-device-setup, and BccSelf
            // should be enabled.
            assert_eq!(alice2.get_config_bool(Config::BccSelf).await?, false);

            alice2.recv_msg_opt(&sent_msg).await;
            assert_eq!(
                alice2.get_config_bool(Config::BccSelf).await?,
                // BccSelf should be enabled when receiving a sync message,
                // but not when receiving another outgoing message
                // because we might have forgotten it and it then it might have been forwarded to us again
                // (though of course this is very unlikely).
                sync_message_sent
            );
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_bot_no_sync_msgs() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let bob = &tcm.bob().await;
        alice.set_config_bool(Config::SyncMsgs, true).await?;
        let chat_id = alice.create_chat(bob).await.id;

        chat::send_text_msg(alice, chat_id, "hi".to_string()).await?;
        alice
            .set_config(Config::Displayname, Some("Alice Human"))
            .await?;
        alice.send_sync_msg().await?;
        alice.pop_sent_sync_msg().await;
        let msg = bob.recv_msg(&alice.pop_sent_msg().await).await;
        assert_eq!(msg.text, "hi");

        alice.set_config_bool(Config::Bot, true).await?;
        chat::send_text_msg(alice, chat_id, "hi".to_string()).await?;
        alice
            .set_config(Config::Displayname, Some("Alice Bot"))
            .await?;
        let msg = bob.recv_msg(&alice.pop_sent_msg().await).await;
        assert_eq!(msg.text, "hi");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unpromoted_group_qr_sync() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        alice.set_config_bool(Config::SyncMsgs, true).await?;
        let alice_chatid =
            chat::create_group_chat(alice, ProtectionStatus::Protected, "the chat").await?;
        let qr = get_securejoin_qr(alice, Some(alice_chatid)).await?;

        // alice2 syncs the QR code token.
        let alice2 = &tcm.alice().await;
        alice2.set_config_bool(Config::SyncMsgs, true).await?;
        test_utils::sync(alice, alice2).await;

        let bob = &tcm.bob().await;
        tcm.exec_securejoin_qr(bob, alice, &qr).await;
        let msg_id = alice.send_sync_msg().await?;
        // Core <= v1.143 doesn't sync QR code tokens immediately, so current Core does that when a
        // group is promoted for compatibility (because the group could be created by older Core).
        // TODO: assert!(msg_id.is_none());
        assert!(msg_id.is_some());
        let sent = alice.pop_sent_sync_msg().await;
        let msg = alice.parse_msg(&sent).await;
        let mut sync_items = msg.sync_items.unwrap().items;
        assert_eq!(sync_items.len(), 1);
        let data = sync_items.pop().unwrap().data;
        let SyncDataOrUnknown::SyncData(AddQrToken(_)) = data else {
            unreachable!();
        };

        // Remove Bob because alice2 doesn't have their key.
        let alice_bob_id = alice.add_or_lookup_contact(bob).await.id;
        remove_contact_from_chat(alice, alice_chatid, alice_bob_id).await?;
        alice.pop_sent_msg().await;
        let sent = alice
            .send_text(alice_chatid, "Promoting group to another device")
            .await;
        alice2.recv_msg(&sent).await;

        let fiona = &tcm.fiona().await;
        tcm.exec_securejoin_qr(fiona, alice2, &qr).await;
        let msg = fiona.get_last_msg().await;
        assert_eq!(msg.text, "Member Me added by alice@example.org.");
        Ok(())
    }
}
