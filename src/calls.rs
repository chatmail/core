//! # Handle calls.
//!
//! Internally, calls are bound to the user-visible info message initializing the call.
//! This means, the "Call ID" is a "Message ID" currently - similar to webxdc.
use crate::chat::{Chat, ChatId, send_msg};
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::context::Context;
use crate::events::EventType;
use crate::headerdef::HeaderDef;
use crate::message::{self, Message, MsgId, Viewtype, rfc724_mid_exists};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::Param;
use crate::sync::SyncData;
use crate::tools::time;
use anyhow::{Result, ensure};
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
    /// Incoming or outgoing call?
    pub is_incoming: bool,

    /// Was an incoming call accepted on this device?
    /// For privacy reasons, only for accepted incoming calls, callee sends a message to caller on `end_call()`.
    /// On other devices and for outgoing calls, `is_accepted` is never set.
    pub is_accepted: bool,

    /// User-defined text as given to place_outgoing_call()
    pub place_call_info: String,

    /// User-defined text as given to accept_incoming_call()
    pub accept_call_info: String,

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
                "UPDATE msgs SET txt=?, txt_normalized=? WHERE id=?",
                (text, message::normalize_text(text), self.msg.id),
            )
            .await?;
        Ok(())
    }
}

impl Context {
    /// Start an outgoing call.
    pub async fn place_outgoing_call(
        &self,
        chat_id: ChatId,
        place_call_info: String,
    ) -> Result<MsgId> {
        let chat = Chat::load_from_db(self, chat_id).await?;
        ensure!(chat.typ == Chattype::Single && !chat.is_self_talk());

        let mut call = Message {
            viewtype: Viewtype::Call,
            text: "📞 Calling...".into(),
            ..Default::default()
        };
        call.param.set(Param::WebrtcRoom, &place_call_info);
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
    pub async fn accept_incoming_call(
        &self,
        call_id: MsgId,
        accept_call_info: String,
    ) -> Result<()> {
        let mut call: CallInfo = self.load_call_by_id(call_id).await?;
        ensure!(call.is_incoming);

        let chat = Chat::load_from_db(self, call.msg.chat_id).await?;
        if chat.is_contact_request() {
            chat.id.accept(self).await?;
        }

        call.msg
            .mark_call_as_accepted(self, accept_call_info.to_string())
            .await?;

        // send an acceptance message around: to the caller as well as to the other devices of the callee
        let mut msg = Message {
            viewtype: Viewtype::Text,
            text: "Call accepted".into(),
            ..Default::default()
        };
        msg.param.set_cmd(SystemMessage::CallAccepted);
        msg.param
            .set(Param::WebrtcAccepted, accept_call_info.to_string());
        msg.set_quote(self, Some(&call.msg)).await?;
        msg.id = send_msg(self, call.msg.chat_id, &mut msg).await?;
        self.emit_event(EventType::IncomingCallAccepted {
            msg_id: call.msg.id,
            accept_call_info,
        });
        Ok(())
    }

    /// Cancel, reject or hangup an incoming or outgoing call.
    pub async fn end_call(&self, call_id: MsgId) -> Result<()> {
        let call: CallInfo = self.load_call_by_id(call_id).await?;

        if call.is_accepted || !call.is_incoming {
            let mut msg = Message {
                viewtype: Viewtype::Text,
                text: "Call ended".into(),
                ..Default::default()
            };
            msg.param.set_cmd(SystemMessage::CallEnded);
            msg.set_quote(self, Some(&call.msg)).await?;
            msg.id = send_msg(self, call.msg.chat_id, &mut msg).await?;
        } else if call.is_incoming {
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
        let call = context.load_call_by_id(call_id).await?;
        if !call.is_accepted {
            context.emit_event(EventType::CallEnded {
                msg_id: call.msg.id,
            });
        }
        Ok(())
    }

    pub(crate) async fn handle_call_msg(
        &self,
        mime_message: &MimeMessage,
        call_id: MsgId,
    ) -> Result<()> {
        if mime_message.is_call() {
            let call = self.load_call_by_id(call_id).await?;
            if call.is_incoming {
                if call.is_stale_call() {
                    call.update_text(self, "Missed call").await?;
                    self.emit_incoming_msg(call.msg.chat_id, call_id);
                } else {
                    self.emit_msgs_changed(call.msg.chat_id, call_id);
                    self.emit_event(EventType::IncomingCall {
                        msg_id: call.msg.id,
                        place_call_info: call.place_call_info.to_string(),
                    });
                    let wait = call.remaining_ring_seconds();
                    task::spawn(Context::emit_end_call_if_unaccepted(
                        self.clone(),
                        wait.try_into()?,
                        call.msg.id,
                    ));
                }
            } else {
                self.emit_msgs_changed(call.msg.chat_id, call_id);
            }
        } else {
            match mime_message.is_system_message {
                SystemMessage::CallAccepted => {
                    let call = self.load_call_by_id(call_id).await?;
                    self.emit_msgs_changed(call.msg.chat_id, call_id);
                    if call.is_incoming {
                        self.emit_event(EventType::IncomingCallAccepted {
                            msg_id: call.msg.id,
                            accept_call_info: call.accept_call_info,
                        });
                    } else {
                        let accept_call_info = mime_message
                            .get_header(HeaderDef::ChatWebrtcAccepted)
                            .unwrap_or_default();
                        call.msg
                            .clone()
                            .mark_call_as_accepted(self, accept_call_info.to_string())
                            .await?;
                        self.emit_event(EventType::OutgoingCallAccepted {
                            msg_id: call.msg.id,
                            accept_call_info: accept_call_info.to_string(),
                        });
                    }
                }
                SystemMessage::CallEnded => {
                    let call = self.load_call_by_id(call_id).await?;
                    self.emit_msgs_changed(call.msg.chat_id, call_id);
                    self.emit_event(EventType::CallEnded {
                        msg_id: call.msg.id,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) async fn sync_call_rejection(&self, rfc724_mid: &str) -> Result<()> {
        if let Some((msg_id, _)) = rfc724_mid_exists(self, rfc724_mid).await? {
            self.emit_event(EventType::CallEnded { msg_id });
        }
        Ok(())
    }

    async fn load_call_by_id(&self, call_id: MsgId) -> Result<CallInfo> {
        let call = Message::load_from_db(self, call_id).await?;
        self.load_call_by_message(call)
    }

    fn load_call_by_message(&self, call: Message) -> Result<CallInfo> {
        ensure!(call.viewtype == Viewtype::Call);

        Ok(CallInfo {
            is_incoming: call.get_from_id() != ContactId::SELF,
            is_accepted: call.is_call_accepted()?,
            place_call_info: call
                .param
                .get(Param::WebrtcRoom)
                .unwrap_or_default()
                .to_string(),
            accept_call_info: call
                .param
                .get(Param::WebrtcAccepted)
                .unwrap_or_default()
                .to_string(),
            msg: call,
        })
    }
}

impl Message {
    async fn mark_call_as_accepted(
        &mut self,
        context: &Context,
        accept_call_info: String,
    ) -> Result<()> {
        ensure!(self.viewtype == Viewtype::Call);
        self.param.set_int(Param::Arg, 1);
        self.param.set(Param::WebrtcAccepted, accept_call_info);
        self.update_param(context).await?;
        Ok(())
    }

    fn is_call_accepted(&self) -> Result<bool> {
        ensure!(self.viewtype == Viewtype::Call);
        Ok(self.param.get_int(Param::Arg) == Some(1))
    }
}

#[cfg(test)]
mod calls_tests;
