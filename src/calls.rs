//! # Handle calls.
//!
//! Internally, calls a bound to the user-visible info message initializing the call.
//! This means, the "Call ID" is a "Message ID" currently - similar to webxdc.
//! So, no database changes are needed at this stage.
//! When it comes to relay calls over iroh, we may need a dedicated table, and this may change.
use crate::chat::{send_msg, Chat, ChatId};
use crate::constants::Chattype;
use crate::context::Context;
use crate::events::EventType;
use crate::message::{self, rfc724_mid_exists, Message, MsgId, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::Param;
use crate::sync::SyncData;
use crate::tools::time;
use anyhow::{anyhow, ensure, Result};
use std::time::Duration;
use tokio::task;
use tokio::time::sleep;

/// How long callee's or caller's phone ring.
///
/// For the callee, this is to prevent endless ringing
/// in case the initial "call" is received, but then the caller went offline.
/// Moreover, this prevents outdated calls to ring
/// in case the initial "call" message arrives delayed.
///
/// For the caller, this means they should also not wait longer,
/// as the callee won't start the call afterwards.
const RINGING_SECONDS: i64 = 60;

/// Information about the status of a call.
#[derive(Debug, Default)]
pub struct CallInfo {
    /// Incoming our outgoing call?
    pub incoming: bool,

    /// Was an incoming call accepted on this device?
    /// On other devices, this is never set and for outgoing calls, this is never set.
    pub accepted: bool,

    /// Info message referring to the call.
    pub msg: Message,
}

impl CallInfo {
    fn is_stale_call(&self) -> bool {
        self.remaining_ring_seconds() <= 0
    }

    fn remaining_ring_seconds(&self) -> i64 {
        let remaining_seconds = self.msg.timestamp_sent + RINGING_SECONDS - time();
        remaining_seconds.clamp(0, RINGING_SECONDS)
    }

    async fn update_text(&self, context: &Context, text: &str) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE msgs SET txt=?, txt_normalized=? WHERE id=?;",
                (text, message::normalize_text(text), self.msg.id),
            )
            .await?;
        Ok(())
    }
}

impl Context {
    /// Start an outgoing call.
    pub async fn place_outgoing_call(&self, chat_id: ChatId) -> Result<MsgId> {
        let chat = Chat::load_from_db(self, chat_id).await?;
        ensure!(chat.typ == Chattype::Single && !chat.is_self_talk());

        let mut call = Message {
            viewtype: Viewtype::Text,
            text: "Calling...".into(),
            ..Default::default()
        };
        call.param.set_cmd(SystemMessage::OutgoingCall);
        call.id = send_msg(self, chat_id, &mut call).await?;

        let wait = RINGING_SECONDS;
        task::spawn(Context::emit_end_call_if_unaccepted(
            self.clone(),
            wait.try_into()?,
            call.id,
        ));

        Ok(call.id)
    }

    /// Accept an incoming call.
    pub async fn accept_incoming_call(&self, call_id: MsgId) -> Result<()> {
        let call: CallInfo = self.load_call_by_root_id(call_id).await?;
        ensure!(call.incoming);

        let chat = Chat::load_from_db(self, call.msg.chat_id).await?;
        if chat.is_contact_request() {
            chat.id.accept(self).await?;
        }

        call.msg.clone().mark_call_as_accepted(self).await?;

        // send an acceptance message around: to the caller as well as to the other devices of the callee
        let mut msg = Message {
            viewtype: Viewtype::Text,
            text: "Call accepted".into(),
            ..Default::default()
        };
        msg.param.set_cmd(SystemMessage::CallAccepted);
        msg.set_quote(self, Some(&call.msg)).await?;
        msg.id = send_msg(self, call.msg.chat_id, &mut msg).await?;
        self.emit_event(EventType::IncomingCallAccepted {
            msg_id: call.msg.id,
        });
        Ok(())
    }

    /// Cancel, reject for hangup an incoming or outgoing call.
    pub async fn end_call(&self, call_id: MsgId) -> Result<()> {
        let call: CallInfo = self.load_call_by_root_id(call_id).await?;

        if call.accepted || !call.incoming {
            let mut msg = Message {
                viewtype: Viewtype::Text,
                text: "Call ended".into(),
                ..Default::default()
            };
            msg.param.set_cmd(SystemMessage::CallEnded);
            msg.set_quote(self, Some(&call.msg)).await?;
            msg.id = send_msg(self, call.msg.chat_id, &mut msg).await?;
        } else if call.incoming {
            // to protect privacy, we do not send a message to others from callee for unaccepted calls
            self.add_sync_item(SyncData::RejectIncomingCall {
                msg: call.msg.rfc724_mid,
            })
            .await?;
            self.scheduler.interrupt_inbox().await;
        }

        self.emit_event(EventType::CallEnded {
            msg_id: call.msg.id,
        });
        Ok(())
    }

    async fn emit_end_call_if_unaccepted(
        context: Context,
        wait: u64,
        call_id: MsgId,
    ) -> Result<()> {
        sleep(Duration::from_secs(wait)).await;
        let call = context.load_call_by_root_id(call_id).await?;
        if !call.accepted {
            context.emit_event(EventType::CallEnded {
                msg_id: call.msg.id,
            });
        }
        Ok(())
    }

    pub(crate) async fn handle_call_msg(
        &self,
        mime_message: &MimeMessage,
        call_or_child_id: MsgId,
    ) -> Result<()> {
        match mime_message.is_system_message {
            SystemMessage::IncomingCall => {
                let call = self.load_call_by_root_id(call_or_child_id).await?;
                if call.incoming {
                    if call.is_stale_call() {
                        call.update_text(self, "Missed call").await?;
                        self.emit_incoming_msg(call.msg.chat_id, call_or_child_id);
                    } else {
                        self.emit_msgs_changed(call.msg.chat_id, call_or_child_id);
                        self.emit_event(EventType::IncomingCall {
                            msg_id: call.msg.id,
                        });
                        let wait = call.remaining_ring_seconds();
                        task::spawn(Context::emit_end_call_if_unaccepted(
                            self.clone(),
                            wait.try_into()?,
                            call.msg.id,
                        ));
                    }
                } else {
                    self.emit_msgs_changed(call.msg.chat_id, call_or_child_id);
                }
            }
            SystemMessage::CallAccepted => {
                let call = self.load_call_by_child_id(call_or_child_id).await?;
                self.emit_msgs_changed(call.msg.chat_id, call_or_child_id);
                if call.incoming {
                    self.emit_event(EventType::IncomingCallAccepted {
                        msg_id: call.msg.id,
                    });
                } else {
                    call.msg.clone().mark_call_as_accepted(self).await?;
                    self.emit_event(EventType::OutgoingCallAccepted {
                        msg_id: call.msg.id,
                    });
                }
            }
            SystemMessage::CallEnded => {
                let call = self.load_call_by_child_id(call_or_child_id).await?;
                self.emit_msgs_changed(call.msg.chat_id, call_or_child_id);
                self.emit_event(EventType::CallEnded {
                    msg_id: call.msg.id,
                });
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) async fn sync_call_rejection(&self, rfc724_mid: &str) -> Result<()> {
        if let Some((msg_id, _)) = rfc724_mid_exists(self, rfc724_mid).await? {
            let call = self.load_call_by_root_id(msg_id).await?;
            self.emit_event(EventType::CallEnded {
                msg_id: call.msg.id,
            });
        }
        Ok(())
    }

    async fn load_call_by_root_id(&self, call_id: MsgId) -> Result<CallInfo> {
        let call = Message::load_from_db(self, call_id).await?;
        self.load_call_by_message(call)
    }

    async fn load_call_by_child_id(&self, child_id: MsgId) -> Result<CallInfo> {
        let child = Message::load_from_db(self, child_id).await?;
        if let Some(call) = child.parent(self).await? {
            self.load_call_by_message(call)
        } else {
            Err(anyhow!("Call parent missing"))
        }
    }

    fn load_call_by_message(&self, call: Message) -> Result<CallInfo> {
        ensure!(
            call.get_info_type() == SystemMessage::IncomingCall
                || call.get_info_type() == SystemMessage::OutgoingCall
        );

        Ok(CallInfo {
            incoming: call.get_info_type() == SystemMessage::IncomingCall,
            accepted: call.is_call_accepted()?,
            msg: call,
        })
    }
}

impl Message {
    async fn mark_call_as_accepted(&mut self, context: &Context) -> Result<()> {
        ensure!(
            self.get_info_type() == SystemMessage::IncomingCall
                || self.get_info_type() == SystemMessage::OutgoingCall
        );
        self.param.set_int(Param::Arg, 1);
        self.update_param(context).await?;
        Ok(())
    }

    fn is_call_accepted(&self) -> Result<bool> {
        ensure!(
            self.get_info_type() == SystemMessage::IncomingCall
                || self.get_info_type() == SystemMessage::OutgoingCall
        );
        Ok(self.param.get_int(Param::Arg) == Some(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::test_utils::{sync, TestContext, TestContextManager};

    async fn setup_call() -> Result<(
        TestContext, // Alice's 1st device
        TestContext, // Alice's 2nd device
        Message,     // Call message from view of Alice
        TestContext, // Bob's 1st device
        TestContext, // Bob's 2nd device
        Message,     // Call message from view of Bob
        Message,     // Call message from view of Bob's 2nd device
    )> {
        let mut tcm = TestContextManager::new();
        let alice = tcm.alice().await;
        let alice2 = tcm.alice().await;
        let bob = tcm.bob().await;
        let bob2 = tcm.bob().await;
        for t in [&alice, &alice2, &bob, &bob2] {
            t.set_config_bool(Config::SyncMsgs, true).await?;
        }

        // Alice creates a chat with Bob and places an outgoing call there.
        // Alice's other device sees the same message as an outgoing call.
        let alice_chat = alice.create_chat(&bob).await;
        let test_msg_id = alice.place_outgoing_call(alice_chat.id).await?;
        let sent1 = alice.pop_sent_msg().await;
        let alice_call = Message::load_from_db(&alice, sent1.sender_msg_id).await?;
        assert_eq!(sent1.sender_msg_id, test_msg_id);
        assert!(alice_call.is_info());
        assert_eq!(alice_call.get_info_type(), SystemMessage::OutgoingCall);
        let info = alice.load_call_by_root_id(alice_call.id).await?;
        assert!(!info.accepted);

        let alice2_call = alice2.recv_msg(&sent1).await;
        assert!(alice2_call.is_info());
        assert_eq!(alice2_call.get_info_type(), SystemMessage::OutgoingCall);
        let info = alice2.load_call_by_root_id(alice2_call.id).await?;
        assert!(!info.accepted);

        // Bob receives the message referring to the call on two devices;
        // it is an incoming call from the view of Bob
        let bob_call = bob.recv_msg(&sent1).await;
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::IncomingCall { .. }))
            .await;
        assert!(bob_call.is_info());
        assert_eq!(bob_call.get_info_type(), SystemMessage::IncomingCall);

        let bob2_call = bob2.recv_msg(&sent1).await;
        assert!(bob2_call.is_info());
        assert_eq!(bob2_call.get_info_type(), SystemMessage::IncomingCall);

        Ok((alice, alice2, alice_call, bob, bob2, bob_call, bob2_call))
    }

    async fn accept_call() -> Result<(
        TestContext,
        TestContext,
        Message,
        TestContext,
        TestContext,
        Message,
    )> {
        let (alice, alice2, alice_call, bob, bob2, bob_call, bob2_call) = setup_call().await?;

        // Bob accepts the incoming call, this does not add an additional message to the chat
        bob.accept_incoming_call(bob_call.id).await?;
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::IncomingCallAccepted { .. }))
            .await;
        let sent2 = bob.pop_sent_msg().await;
        let info = bob.load_call_by_root_id(bob_call.id).await?;
        assert!(info.accepted);

        bob2.recv_msg(&sent2).await;
        bob2.evtracker
            .get_matching(|evt| matches!(evt, EventType::IncomingCallAccepted { .. }))
            .await;
        let info = bob2.load_call_by_root_id(bob2_call.id).await?;
        assert!(!info.accepted); // "accepted" is only true on the device that does the call

        // Alice receives the acceptance message
        alice.recv_msg(&sent2).await;
        alice
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::OutgoingCallAccepted { .. }))
            .await;

        alice2.recv_msg(&sent2).await;
        alice2
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::OutgoingCallAccepted { .. }))
            .await;
        Ok((alice, alice2, alice_call, bob, bob2, bob_call))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accept_call_callee_ends() -> Result<()> {
        // Alice calls Bob, Bob accepts
        let (alice, alice2, _alice_call, bob, bob2, bob_call) = accept_call().await?;

        // Bob has accepted the call and also ends it
        bob.end_call(bob_call.id).await?;
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;
        let sent3 = bob.pop_sent_msg().await;

        bob2.recv_msg(&sent3).await;
        bob2.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        // Alice receives the ending message
        alice.recv_msg(&sent3).await;
        alice
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        alice2.recv_msg(&sent3).await;
        alice2
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_accept_call_caller_ends() -> Result<()> {
        // Alice calls Bob, Bob accepts
        let (alice, alice2, _alice_call, bob, bob2, bob_call) = accept_call().await?;

        // Bob has accepted the call but Alice ends it
        alice.end_call(bob_call.id).await?;
        alice
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;
        let sent3 = alice.pop_sent_msg().await;

        alice2.recv_msg(&sent3).await;
        alice2
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        // Bob receives the ending message
        bob.recv_msg(&sent3).await;
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        bob2.recv_msg(&sent3).await;
        bob2.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_callee_rejects_call() -> Result<()> {
        // Alice calls Bob
        let (_alice, _alice2, _alice_call, bob, bob2, bob_call, _bob2_call) = setup_call().await?;

        // Bob does not want to talk with Alice.
        // To protect Bob's privacy, no message is sent to Alice (who will time out).
        // To let Bob close the call window on all devices, a sync message is used instead.
        bob.end_call(bob_call.id).await?;
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        sync(&bob, &bob2).await;
        bob2.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_caller_cancels_call() -> Result<()> {
        // Alice calls Bob
        let (alice, alice2, alice_call, bob, bob2, _bob_call, _bob2_call) = setup_call().await?;

        // Alice changes their mind before Bob picks up
        alice.end_call(alice_call.id).await?;
        alice
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;
        let sent3 = alice.pop_sent_msg().await;

        alice2.recv_msg(&sent3).await;
        alice2
            .evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        // Bob receives the ending message
        bob.recv_msg(&sent3).await;
        bob.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        bob2.recv_msg(&sent3).await;
        bob2.evtracker
            .get_matching(|evt| matches!(evt, EventType::CallEnded { .. }))
            .await;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_is_stale_call() -> Result<()> {
        // a call started now is not stale
        let call_info = CallInfo {
            msg: Message {
                timestamp_sent: time(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!call_info.is_stale_call());
        assert_eq!(call_info.remaining_ring_seconds(), RINGING_SECONDS);

        // call started 5 seconds ago, this is not stale as well
        let call_info = CallInfo {
            msg: Message {
                timestamp_sent: time() - 5,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!call_info.is_stale_call());
        assert_eq!(call_info.remaining_ring_seconds(), RINGING_SECONDS - 5);

        // a call started one hour ago is clearly stale
        let call_info = CallInfo {
            msg: Message {
                timestamp_sent: time() - 3600,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(call_info.is_stale_call());
        assert_eq!(call_info.remaining_ring_seconds(), 0);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_mark_call_as_accepted() -> Result<()> {
        let (alice, _alice2, alice_call, _bob, _bob2, _bob_call, _bob2_call) = setup_call().await?;
        assert!(!alice_call.is_call_accepted()?);

        let mut alice_call = Message::load_from_db(&alice, alice_call.id).await?;
        assert!(!alice_call.is_call_accepted()?);
        alice_call.mark_call_as_accepted(&alice).await?;
        assert!(alice_call.is_call_accepted()?);

        let alice_call = Message::load_from_db(&alice, alice_call.id).await?;
        assert!(alice_call.is_call_accepted()?);

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_udpate_call_text() -> Result<()> {
        let (alice, _alice2, alice_call, _bob, _bob2, _bob_call, _bob2_call) = setup_call().await?;

        let call_info = alice.load_call_by_root_id(alice_call.id).await?;
        call_info.update_text(&alice, "foo bar").await?;

        let alice_call = Message::load_from_db(&alice, alice_call.id).await?;
        assert_eq!(alice_call.get_text(), "foo bar");

        Ok(())
    }
}
