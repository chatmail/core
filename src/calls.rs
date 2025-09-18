//! # Handle calls.
//!
//! Internally, calls are bound a user-visible message initializing the call.
//! This means, the "Call ID" is a "Message ID" - similar to Webxdc IDs.
use crate::chat::{Chat, ChatId, send_msg};
use crate::constants::Chattype;
use crate::contact::ContactId;
use crate::context::Context;
use crate::events::EventType;
use crate::headerdef::HeaderDef;
use crate::log::{info, warn};
use crate::message::{self, Message, MsgId, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::param::Param;
use crate::tools::time;
use anyhow::{Context as _, Result, ensure};
use sdp::SessionDescription;
use std::io::Cursor;
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

/// For persisting parameters in the call, we use Param::Arg*
const CALL_ACCEPTED_TIMESTAMP: Param = Param::Arg;
const CALL_ENDED_TIMESTAMP: Param = Param::Arg4;

/// Information about the status of a call.
#[derive(Debug, Default)]
pub struct CallInfo {
    /// User-defined text as given to place_outgoing_call()
    pub place_call_info: String,

    /// User-defined text as given to accept_incoming_call()
    pub accept_call_info: String,

    /// Message referring to the call.
    /// Data are persisted along with the message using Param::Arg*
    pub msg: Message,
}

impl CallInfo {
    fn is_incoming(&self) -> bool {
        self.msg.from_id != ContactId::SELF
    }

    fn is_stale(&self) -> bool {
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

    async fn update_text_duration(&self, context: &Context) -> Result<()> {
        let minutes = self.get_duration_seconds() / 60;
        let duration = match minutes {
            0 => "<1 minute".to_string(),
            1 => "1 minute".to_string(),
            n => format!("{} minutes", n),
        };

        if self.is_incoming() {
            self.update_text(context, &format!("Incoming call\n{duration}"))
                .await?;
        } else {
            self.update_text(context, &format!("Outgoing call\n{duration}"))
                .await?;
        }
        Ok(())
    }

    /// Mark calls as accepted.
    /// This is needed for all devices where a stale-timer runs, to prevent accepted calls being terminated as stale.
    async fn mark_as_accepted(&mut self, context: &Context) -> Result<()> {
        self.msg.param.set_i64(CALL_ACCEPTED_TIMESTAMP, time());
        self.msg.update_param(context).await?;
        Ok(())
    }

    fn is_accepted(&self) -> bool {
        self.msg.param.exists(CALL_ACCEPTED_TIMESTAMP)
    }

    async fn mark_as_ended(&mut self, context: &Context) -> Result<()> {
        self.msg.param.set_i64(CALL_ENDED_TIMESTAMP, time());
        self.msg.update_param(context).await?;
        Ok(())
    }

    fn is_ended(&self) -> bool {
        self.msg.param.exists(CALL_ENDED_TIMESTAMP)
    }

    fn get_duration_seconds(&self) -> i64 {
        if let (Some(start), Some(end)) = (
            self.msg.param.get_i64(CALL_ACCEPTED_TIMESTAMP),
            self.msg.param.get_i64(CALL_ENDED_TIMESTAMP),
        ) {
            let seconds = end - start;
            if seconds <= 0 {
                return 1;
            }
            return seconds;
        }
        0
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
            text: "Outgoing call".into(),
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
        ensure!(call.is_incoming());
        if call.is_accepted() || call.is_ended() {
            info!(self, "Call already accepted/ended");
            return Ok(());
        }

        call.mark_as_accepted(self).await?;
        let chat = Chat::load_from_db(self, call.msg.chat_id).await?;
        if chat.is_contact_request() {
            chat.id.accept(self).await?;
        }

        // send an acceptance message around: to the caller as well as to the other devices of the callee
        let mut msg = Message {
            viewtype: Viewtype::Text,
            text: "[Call accepted]".into(),
            ..Default::default()
        };
        msg.param.set_cmd(SystemMessage::CallAccepted);
        msg.hidden = true;
        msg.param
            .set(Param::WebrtcAccepted, accept_call_info.to_string());
        msg.set_quote(self, Some(&call.msg)).await?;
        msg.id = send_msg(self, call.msg.chat_id, &mut msg).await?;
        self.emit_event(EventType::IncomingCallAccepted {
            msg_id: call.msg.id,
        });
        self.emit_msgs_changed(call.msg.chat_id, call_id);
        Ok(())
    }

    /// Cancel, decline or hangup an incoming or outgoing call.
    pub async fn end_call(&self, call_id: MsgId) -> Result<()> {
        let mut call: CallInfo = self.load_call_by_id(call_id).await?;
        if call.is_ended() {
            info!(self, "Call already ended");
            return Ok(());
        }
        call.mark_as_ended(self).await?;

        if !call.is_accepted() {
            if call.is_incoming() {
                call.update_text(self, "Declined call").await?;
            } else {
                call.update_text(self, "Cancelled call").await?;
            }
        } else {
            call.update_text_duration(self).await?;
        }

        let mut msg = Message {
            viewtype: Viewtype::Text,
            text: "[Call ended]".into(),
            ..Default::default()
        };
        msg.param.set_cmd(SystemMessage::CallEnded);
        msg.hidden = true;
        msg.set_quote(self, Some(&call.msg)).await?;
        msg.id = send_msg(self, call.msg.chat_id, &mut msg).await?;

        self.emit_event(EventType::CallEnded {
            msg_id: call.msg.id,
        });
        self.emit_msgs_changed(call.msg.chat_id, call_id);
        Ok(())
    }

    async fn emit_end_call_if_unaccepted(
        context: Context,
        wait: u64,
        call_id: MsgId,
    ) -> Result<()> {
        sleep(Duration::from_secs(wait)).await;
        let mut call = context.load_call_by_id(call_id).await?;
        if !call.is_accepted() && !call.is_ended() {
            call.mark_as_ended(&context).await?;
            if call.is_incoming() {
                call.update_text(&context, "Missed call").await?;
            } else {
                call.update_text(&context, "Cancelled call").await?;
            }
            context.emit_msgs_changed(call.msg.chat_id, call_id);
            context.emit_event(EventType::CallEnded {
                msg_id: call.msg.id,
            });
        }
        Ok(())
    }

    pub(crate) async fn handle_call_msg(
        &self,
        call_id: MsgId,
        mime_message: &MimeMessage,
        from_id: ContactId,
    ) -> Result<()> {
        if mime_message.is_call() {
            let call = self.load_call_by_id(call_id).await?;

            if call.is_incoming() {
                if call.is_stale() {
                    call.update_text(self, "Missed call").await?;
                    self.emit_incoming_msg(call.msg.chat_id, call_id); // notify missed call
                } else {
                    call.update_text(self, "Incoming call").await?;
                    self.emit_msgs_changed(call.msg.chat_id, call_id); // ringing calls are not additionally notified
                    let has_video = match sdp_has_video(&call.place_call_info) {
                        Ok(has_video) => has_video,
                        Err(err) => {
                            warn!(self, "Failed to determine if SDP offer has video: {err:#}.");
                            false
                        }
                    };
                    self.emit_event(EventType::IncomingCall {
                        msg_id: call.msg.id,
                        place_call_info: call.place_call_info.to_string(),
                        has_video,
                    });
                    let wait = call.remaining_ring_seconds();
                    task::spawn(Context::emit_end_call_if_unaccepted(
                        self.clone(),
                        wait.try_into()?,
                        call.msg.id,
                    ));
                }
            } else {
                call.update_text(self, "Outgoing call").await?;
                self.emit_msgs_changed(call.msg.chat_id, call_id);
            }
        } else {
            match mime_message.is_system_message {
                SystemMessage::CallAccepted => {
                    let mut call = self.load_call_by_id(call_id).await?;
                    if call.is_ended() || call.is_accepted() {
                        info!(self, "CallAccepted received for accepted/ended call");
                        return Ok(());
                    }

                    call.mark_as_accepted(self).await?;
                    self.emit_msgs_changed(call.msg.chat_id, call_id);
                    if call.is_incoming() {
                        self.emit_event(EventType::IncomingCallAccepted {
                            msg_id: call.msg.id,
                        });
                    } else {
                        let accept_call_info = mime_message
                            .get_header(HeaderDef::ChatWebrtcAccepted)
                            .unwrap_or_default();
                        self.emit_event(EventType::OutgoingCallAccepted {
                            msg_id: call.msg.id,
                            accept_call_info: accept_call_info.to_string(),
                        });
                    }
                }
                SystemMessage::CallEnded => {
                    let mut call = self.load_call_by_id(call_id).await?;
                    if call.is_ended() {
                        // may happen eg. if a a message is missed
                        info!(self, "CallEnded received for ended call");
                        return Ok(());
                    }

                    call.mark_as_ended(self).await?;
                    if !call.is_accepted() {
                        if call.is_incoming() {
                            if from_id == ContactId::SELF {
                                call.update_text(self, "Declined call").await?;
                            } else {
                                call.update_text(self, "Missed call").await?;
                            }
                        } else {
                            // outgoing
                            if from_id == ContactId::SELF {
                                call.update_text(self, "Cancelled call").await?;
                            } else {
                                call.update_text(self, "Declined call").await?;
                            }
                        }
                    } else {
                        call.update_text_duration(self).await?;
                    }

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

    async fn load_call_by_id(&self, call_id: MsgId) -> Result<CallInfo> {
        let call = Message::load_from_db(self, call_id).await?;
        self.load_call_by_message(call)
    }

    fn load_call_by_message(&self, call: Message) -> Result<CallInfo> {
        ensure!(call.viewtype == Viewtype::Call);

        Ok(CallInfo {
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

/// Returns true if SDP offer has a video.
fn sdp_has_video(sdp: &str) -> Result<bool> {
    let mut cursor = Cursor::new(sdp);
    let session_description =
        SessionDescription::unmarshal(&mut cursor).context("Failed to parse SDP")?;
    for media_description in &session_description.media_descriptions {
        if media_description.media_name.media == "video" {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod calls_tests;
