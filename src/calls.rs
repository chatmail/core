//! # Handle calls.
//!
//! Internally, calls are bound a user-visible message initializing the call.
//! This means, the "Call ID" is a "Message ID" - similar to Webxdc IDs.
use crate::chat::ChatIdBlocked;
use crate::chat::{Chat, ChatId, send_msg};
use crate::config::Config;
use crate::constants::{Blocked, Chattype};
use crate::contact::ContactId;
use crate::context::{Context, WeakContext};
use crate::events::EventType;
use crate::headerdef::HeaderDef;
use crate::log::warn;
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::{MimeMessage, SystemMessage};
use crate::net::dns::lookup_host_with_cache;
use crate::param::Param;
use crate::stock_str;
use crate::tools::{normalize_text, time};
use anyhow::{Context as _, Result, ensure};
use deltachat_derive::{FromSql, ToSql};
use num_traits::FromPrimitive;
use serde::Serialize;
use std::str::FromStr;
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
const RINGING_SECONDS: i64 = 120;

// For persisting parameters in the call, we use Param::Arg*

const CALL_ACCEPTED_TIMESTAMP: Param = Param::Arg;
const CALL_ENDED_TIMESTAMP: Param = Param::Arg4;

const STUN_PORT: u16 = 3478;

/// Set if incoming call was ended explicitly
/// by the other side before we accepted it.
///
/// It is used to distinguish "ended" calls
/// that are rejected by us from the calls
/// canceled by the other side
/// immediately after ringing started.
const CALL_CANCELED_TIMESTAMP: Param = Param::Arg2;

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
    /// Returns true if the call is an incoming call.
    pub fn is_incoming(&self) -> bool {
        self.msg.from_id != ContactId::SELF
    }

    /// Returns true if the call should not ring anymore.
    pub fn is_stale(&self) -> bool {
        (self.is_incoming() || self.msg.timestamp_sent != 0) && self.remaining_ring_seconds() <= 0
    }

    fn remaining_ring_seconds(&self) -> i64 {
        #[expect(clippy::arithmetic_side_effects)]
        let remaining_seconds = self.msg.timestamp_sent + RINGING_SECONDS - time();
        remaining_seconds.clamp(0, RINGING_SECONDS)
    }

    async fn update_text(&self, context: &Context, text: &str) -> Result<()> {
        context
            .sql
            .execute(
                "UPDATE msgs SET txt=?, txt_normalized=? WHERE id=?",
                (text, normalize_text(text), self.msg.id),
            )
            .await?;
        Ok(())
    }

    async fn update_text_duration(&self, context: &Context) -> Result<()> {
        let minutes = self.duration_seconds() / 60;
        let duration = match minutes {
            0 => "<1 minute".to_string(),
            1 => "1 minute".to_string(),
            n => format!("{n} minutes"),
        };

        if self.is_incoming() {
            let incoming_call_str =
                stock_str::incoming_call(context, self.has_video_initially()).await;
            self.update_text(context, &format!("{incoming_call_str}\n{duration}"))
                .await?;
        } else {
            let outgoing_call_str =
                stock_str::outgoing_call(context, self.has_video_initially()).await;
            self.update_text(context, &format!("{outgoing_call_str}\n{duration}"))
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

    /// Returns true if the call is accepted.
    pub fn is_accepted(&self) -> bool {
        self.msg.param.exists(CALL_ACCEPTED_TIMESTAMP)
    }

    /// Returns true if the call is started as a video call.
    pub fn has_video_initially(&self) -> bool {
        self.msg
            .param
            .get_bool(Param::WebrtcHasVideoInitially)
            .unwrap_or(false)
    }

    /// Returns true if the call is missed
    /// because the caller canceled it
    /// explicitly before ringing stopped.
    ///
    /// For outgoing calls this means
    /// the receiver has rejected the call
    /// explicitly.
    pub fn is_canceled(&self) -> bool {
        self.msg.param.exists(CALL_CANCELED_TIMESTAMP)
    }

    async fn mark_as_ended(&mut self, context: &Context) -> Result<()> {
        self.msg.param.set_i64(CALL_ENDED_TIMESTAMP, time());
        self.msg.update_param(context).await?;
        Ok(())
    }

    /// Explicitly mark the call as canceled.
    ///
    /// For incoming calls this should be called
    /// when "call ended" message is received
    /// from the caller before we picked up the call.
    /// In this case the call becomes "missed" early
    /// before the ringing timeout.
    async fn mark_as_canceled(&mut self, context: &Context) -> Result<()> {
        let now = time();
        self.msg.param.set_i64(CALL_ENDED_TIMESTAMP, now);
        self.msg.param.set_i64(CALL_CANCELED_TIMESTAMP, now);
        self.msg.update_param(context).await?;
        Ok(())
    }

    /// Returns true if the call is ended.
    pub fn is_ended(&self) -> bool {
        self.msg.param.exists(CALL_ENDED_TIMESTAMP)
    }

    /// Returns call duration in seconds.
    #[expect(clippy::arithmetic_side_effects)]
    pub fn duration_seconds(&self) -> i64 {
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
        has_video_initially: bool,
    ) -> Result<MsgId> {
        let chat = Chat::load_from_db(self, chat_id).await?;
        ensure!(
            chat.typ == Chattype::Single,
            "Can only place calls in 1:1 chats"
        );
        ensure!(!chat.is_self_talk(), "Cannot call self");

        let outgoing_call_str = stock_str::outgoing_call(self, has_video_initially).await;
        let mut call = Message {
            viewtype: Viewtype::Call,
            text: outgoing_call_str,
            ..Default::default()
        };
        call.param.set(Param::WebrtcRoom, &place_call_info);
        call.param
            .set_int(Param::WebrtcHasVideoInitially, has_video_initially.into());
        call.id = send_msg(self, chat_id, &mut call).await?;

        let wait = RINGING_SECONDS;
        let context = self.get_weak_context();
        task::spawn(Context::emit_end_call_if_unaccepted(
            context,
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
        let mut call: CallInfo = self.load_call_by_id(call_id).await?.with_context(|| {
            format!("accept_incoming_call is called with {call_id} which does not refer to a call")
        })?;
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
            chat_id: call.msg.chat_id,
        });
        self.emit_msgs_changed(call.msg.chat_id, call_id);
        Ok(())
    }

    /// Cancel, decline or hangup an incoming or outgoing call.
    pub async fn end_call(&self, call_id: MsgId) -> Result<()> {
        let mut call: CallInfo = self.load_call_by_id(call_id).await?.with_context(|| {
            format!("end_call is called with {call_id} which does not refer to a call")
        })?;
        if call.is_ended() {
            info!(self, "Call already ended");
            return Ok(());
        }

        if !call.is_accepted() {
            if call.is_incoming() {
                call.mark_as_ended(self).await?;
                let declined_call_str = stock_str::declined_call(self).await;
                call.update_text(self, &declined_call_str).await?;
            } else {
                call.mark_as_canceled(self).await?;
                let canceled_call_str = stock_str::canceled_call(self).await;
                call.update_text(self, &canceled_call_str).await?;
            }
        } else {
            call.mark_as_ended(self).await?;
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
            chat_id: call.msg.chat_id,
        });
        self.emit_msgs_changed(call.msg.chat_id, call_id);
        Ok(())
    }

    async fn emit_end_call_if_unaccepted(
        context: WeakContext,
        wait: u64,
        call_id: MsgId,
    ) -> Result<()> {
        sleep(Duration::from_secs(wait)).await;
        let context = context.upgrade()?;
        let Some(mut call) = context.load_call_by_id(call_id).await? else {
            warn!(
                context,
                "emit_end_call_if_unaccepted is called with {call_id} which does not refer to a call."
            );
            return Ok(());
        };
        if !call.is_accepted() && !call.is_ended() {
            if call.is_incoming() {
                call.mark_as_canceled(&context).await?;
                let missed_call_str = stock_str::missed_call(&context).await;
                call.update_text(&context, &missed_call_str).await?;
            } else {
                call.mark_as_ended(&context).await?;
                let canceled_call_str = stock_str::canceled_call(&context).await;
                call.update_text(&context, &canceled_call_str).await?;
            }
            context.emit_msgs_changed(call.msg.chat_id, call_id);
            context.emit_event(EventType::CallEnded {
                msg_id: call.msg.id,
                chat_id: call.msg.chat_id,
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
            let Some(call) = self.load_call_by_id(call_id).await? else {
                warn!(self, "{call_id} does not refer to a call message");
                return Ok(());
            };

            if call.is_incoming() {
                if call.is_stale() {
                    let missed_call_str = stock_str::missed_call(self).await;
                    call.update_text(self, &missed_call_str).await?;
                    self.emit_incoming_msg(call.msg.chat_id, call_id); // notify missed call
                } else {
                    let incoming_call_str =
                        stock_str::incoming_call(self, call.has_video_initially()).await;
                    call.update_text(self, &incoming_call_str).await?;
                    self.emit_msgs_changed(call.msg.chat_id, call_id); // ringing calls are not additionally notified
                    let can_call_me = match who_can_call_me(self).await? {
                        WhoCanCallMe::Contacts => ChatIdBlocked::lookup_by_contact(self, from_id)
                            .await?
                            .is_some_and(|chat_id_blocked| {
                                match chat_id_blocked.blocked {
                                    Blocked::Not => true,
                                    Blocked::Yes | Blocked::Request => {
                                        // Do not notify about incoming calls
                                        // from contact requests and blocked contacts.
                                        //
                                        // User can still access the call and accept it
                                        // via the chat in case of contact requests.
                                        false
                                    }
                                }
                            }),
                        WhoCanCallMe::Everybody => ChatIdBlocked::lookup_by_contact(self, from_id)
                            .await?
                            .is_none_or(|chat_id_blocked| chat_id_blocked.blocked != Blocked::Yes),
                        WhoCanCallMe::Nobody => false,
                    };
                    if can_call_me {
                        self.emit_event(EventType::IncomingCall {
                            msg_id: call.msg.id,
                            chat_id: call.msg.chat_id,
                            place_call_info: call.place_call_info.to_string(),
                            has_video: call.has_video_initially(),
                        });
                    }
                    let wait = call.remaining_ring_seconds();
                    let context = self.get_weak_context();
                    task::spawn(Context::emit_end_call_if_unaccepted(
                        context,
                        wait.try_into()?,
                        call.msg.id,
                    ));
                }
            } else {
                let outgoing_call_str =
                    stock_str::outgoing_call(self, call.has_video_initially()).await;
                call.update_text(self, &outgoing_call_str).await?;
                self.emit_msgs_changed(call.msg.chat_id, call_id);
            }
        } else {
            match mime_message.is_system_message {
                SystemMessage::CallAccepted => {
                    let Some(mut call) = self.load_call_by_id(call_id).await? else {
                        warn!(self, "{call_id} does not refer to a call message");
                        return Ok(());
                    };

                    if call.is_ended() || call.is_accepted() {
                        info!(self, "CallAccepted received for accepted/ended call");
                        return Ok(());
                    }

                    call.mark_as_accepted(self).await?;
                    self.emit_msgs_changed(call.msg.chat_id, call_id);
                    if call.is_incoming() {
                        self.emit_event(EventType::IncomingCallAccepted {
                            msg_id: call.msg.id,
                            chat_id: call.msg.chat_id,
                        });
                    } else {
                        let accept_call_info = mime_message
                            .get_header(HeaderDef::ChatWebrtcAccepted)
                            .unwrap_or_default();
                        self.emit_event(EventType::OutgoingCallAccepted {
                            msg_id: call.msg.id,
                            chat_id: call.msg.chat_id,
                            accept_call_info: accept_call_info.to_string(),
                        });
                    }
                }
                SystemMessage::CallEnded => {
                    let Some(mut call) = self.load_call_by_id(call_id).await? else {
                        warn!(self, "{call_id} does not refer to a call message");
                        return Ok(());
                    };

                    if call.is_ended() {
                        // may happen eg. if a a message is missed
                        info!(self, "CallEnded received for ended call");
                        return Ok(());
                    }

                    if !call.is_accepted() {
                        if call.is_incoming() {
                            if from_id == ContactId::SELF {
                                call.mark_as_ended(self).await?;
                                let declined_call_str = stock_str::declined_call(self).await;
                                call.update_text(self, &declined_call_str).await?;
                            } else {
                                call.mark_as_canceled(self).await?;
                                let missed_call_str = stock_str::missed_call(self).await;
                                call.update_text(self, &missed_call_str).await?;
                            }
                        } else {
                            // outgoing
                            if from_id == ContactId::SELF {
                                call.mark_as_canceled(self).await?;
                                let canceled_call_str = stock_str::canceled_call(self).await;
                                call.update_text(self, &canceled_call_str).await?;
                            } else {
                                call.mark_as_ended(self).await?;
                                let declined_call_str = stock_str::declined_call(self).await;
                                call.update_text(self, &declined_call_str).await?;
                            }
                        }
                    } else {
                        call.mark_as_ended(self).await?;
                        call.update_text_duration(self).await?;
                    }

                    self.emit_msgs_changed(call.msg.chat_id, call_id);
                    self.emit_event(EventType::CallEnded {
                        msg_id: call.msg.id,
                        chat_id: call.msg.chat_id,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Loads information about the call given its ID.
    ///
    /// If the message referred to by ID is
    /// not a call message, returns `None`.
    pub async fn load_call_by_id(&self, call_id: MsgId) -> Result<Option<CallInfo>> {
        let call = Message::load_from_db(self, call_id).await?;
        Ok(self.load_call_by_message(call))
    }

    // Loads information about the call given the `Message`.
    //
    // If the `Message` is not a call message, returns `None`
    fn load_call_by_message(&self, call: Message) -> Option<CallInfo> {
        if call.viewtype != Viewtype::Call {
            // This can happen e.g. if a "call accepted"
            // or "call ended" message is received
            // with `In-Reply-To` referring to non-call message.
            return None;
        }

        Some(CallInfo {
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

/// State of the call for display in the message bubble.
#[derive(Debug, PartialEq, Eq)]
pub enum CallState {
    /// Fresh incoming or outgoing call that is still ringing.
    ///
    /// There is no separate state for outgoing call
    /// that has been dialled but not ringing on the other side yet
    /// as we don't know whether the other side received our call.
    Alerting,

    /// Active call.
    Active,

    /// Completed call that was once active
    /// and then was terminated for any reason.
    Completed {
        /// Call duration in seconds.
        duration: i64,
    },

    /// Incoming call that was not picked up within a timeout
    /// or was explicitly ended by the caller before we picked up.
    Missed,

    /// Incoming call that was explicitly ended on our side
    /// before picking up or outgoing call
    /// that was declined before the timeout.
    Declined,

    /// Outgoing call that has been canceled on our side
    /// before receiving a response.
    ///
    /// Incoming calls cannot be canceled,
    /// on the receiver side canceled calls
    /// usually result in missed calls.
    Canceled,
}

/// Returns call state given the message ID.
///
/// Returns an error if the message is not a call message.
pub async fn call_state(context: &Context, msg_id: MsgId) -> Result<CallState> {
    let call = context
        .load_call_by_id(msg_id)
        .await?
        .with_context(|| format!("{msg_id} is not a call message"))?;
    let state = if call.is_incoming() {
        if call.is_accepted() {
            if call.is_ended() {
                CallState::Completed {
                    duration: call.duration_seconds(),
                }
            } else {
                CallState::Active
            }
        } else if call.is_canceled() {
            // Call was explicitly canceled
            // by the caller before we picked it up.
            CallState::Missed
        } else if call.is_ended() {
            CallState::Declined
        } else if call.is_stale() {
            CallState::Missed
        } else {
            CallState::Alerting
        }
    } else if call.is_accepted() {
        if call.is_ended() {
            CallState::Completed {
                duration: call.duration_seconds(),
            }
        } else {
            CallState::Active
        }
    } else if call.is_canceled() {
        CallState::Canceled
    } else if call.is_ended() || call.is_stale() {
        CallState::Declined
    } else {
        CallState::Alerting
    };
    Ok(state)
}

/// ICE server for JSON serialization.
#[derive(Serialize, Debug, Clone, PartialEq)]
struct IceServer {
    /// STUN or TURN URLs.
    pub urls: Vec<String>,

    /// Username for TURN server authentication.
    pub username: Option<String>,

    /// Password for logging into the server.
    pub credential: Option<String>,
}

/// Creates ICE servers from a line received over IMAP METADATA.
///
/// IMAP METADATA returns a line such as
/// `example.com:3478:1758650868:8Dqkyyu11MVESBqjbIylmB06rv8=`
///
/// 1758650868 is the username and expiration timestamp
/// at the same time,
/// while `8Dqkyyu11MVESBqjbIylmB06rv8=`
/// is the password.
pub(crate) async fn create_ice_servers_from_metadata(
    metadata: &str,
) -> Result<(i64, Vec<UnresolvedIceServer>)> {
    let (hostname, rest) = metadata.split_once(':').context("Missing hostname")?;
    let (port, rest) = rest.split_once(':').context("Missing port")?;
    let port = u16::from_str(port).context("Failed to parse the port")?;
    let (ts, password) = rest.split_once(':').context("Missing timestamp")?;
    let expiration_timestamp = i64::from_str(ts).context("Failed to parse the timestamp")?;
    let ice_servers = vec![UnresolvedIceServer::Turn {
        hostname: hostname.to_string(),
        port,
        username: ts.to_string(),
        credential: password.to_string(),
    }];
    Ok((expiration_timestamp, ice_servers))
}

/// STUN or TURN server with unresolved DNS name.
#[derive(Debug, Clone)]
pub(crate) enum UnresolvedIceServer {
    /// STUN server.
    Stun { hostname: String, port: u16 },

    /// TURN server with the username and password.
    Turn {
        hostname: String,
        port: u16,
        username: String,
        credential: String,
    },
}

/// Resolves domain names of ICE servers.
///
/// On failure to resolve, logs the error
/// and skips the server, but does not fail.
pub(crate) async fn resolve_ice_servers(
    context: &Context,
    unresolved_ice_servers: Vec<UnresolvedIceServer>,
) -> Result<String> {
    let mut result: Vec<IceServer> = Vec::new();

    // Do not use cache because there is no TLS.
    let load_cache = false;

    for unresolved_ice_server in unresolved_ice_servers {
        match unresolved_ice_server {
            UnresolvedIceServer::Stun { hostname, port } => {
                match lookup_host_with_cache(context, &hostname, port, "", load_cache).await {
                    Ok(addrs) => {
                        let urls: Vec<String> = addrs
                            .into_iter()
                            .map(|addr| format!("stun:{addr}"))
                            .collect();
                        let stun_server = IceServer {
                            urls,
                            username: None,
                            credential: None,
                        };
                        result.push(stun_server);
                    }
                    Err(err) => {
                        warn!(
                            context,
                            "Failed to resolve STUN {hostname}:{port}: {err:#}."
                        );
                    }
                }
            }
            UnresolvedIceServer::Turn {
                hostname,
                port,
                username,
                credential,
            } => match lookup_host_with_cache(context, &hostname, port, "", load_cache).await {
                Ok(addrs) => {
                    let urls: Vec<String> = addrs
                        .into_iter()
                        .map(|addr| format!("turn:{addr}"))
                        .collect();
                    let turn_server = IceServer {
                        urls,
                        username: Some(username),
                        credential: Some(credential),
                    };
                    result.push(turn_server);
                }
                Err(err) => {
                    warn!(
                        context,
                        "Failed to resolve TURN {hostname}:{port}: {err:#}."
                    );
                }
            },
        }
    }
    let json = serde_json::to_string(&result)?;
    Ok(json)
}

/// Creates JSON with ICE servers when no TURN servers are known.
pub(crate) fn create_fallback_ice_servers() -> Vec<UnresolvedIceServer> {
    // Do not use public STUN server from https://stunprotocol.org/.
    // It changes the hostname every year
    // (e.g. stunserver2025.stunprotocol.org
    // which was previously stunserver2024.stunprotocol.org)
    // because of bandwidth costs:
    // <https://github.com/jselbie/stunserver/issues/50>

    vec![
        UnresolvedIceServer::Stun {
            hostname: "nine.testrun.org".to_string(),
            port: STUN_PORT,
        },
        UnresolvedIceServer::Turn {
            hostname: "turn.delta.chat".to_string(),
            port: STUN_PORT,
            username: "public".to_string(),
            credential: "o4tR7yG4rG2slhXqRUf9zgmHz".to_string(),
        },
    ]
}

/// Returns JSON with ICE servers.
///
/// <https://developer.mozilla.org/en-US/docs/Web/API/RTCPeerConnection/RTCPeerConnection#iceservers>
///
/// All returned servers are resolved to their IP addresses.
/// The primary point of DNS lookup is that Delta Chat Desktop
/// relies on the servers being specified by IP,
/// because it itself cannot utilize DNS. See
/// <https://github.com/deltachat/deltachat-desktop/issues/5447>.
pub async fn ice_servers(context: &Context) -> Result<String> {
    if let Some(ref metadata) = *context.metadata.read().await {
        let ice_servers = resolve_ice_servers(context, metadata.ice_servers.clone()).await?;
        Ok(ice_servers)
    } else {
        Ok("[]".to_string())
    }
}

/// "Who can call me" config options.
#[derive(
    Debug, Default, Display, Clone, Copy, PartialEq, Eq, FromPrimitive, ToPrimitive, FromSql, ToSql,
)]
#[repr(u8)]
pub enum WhoCanCallMe {
    /// Everybody can call me if they are not blocked.
    ///
    /// This includes contact requests.
    Everybody = 0,

    /// Every contact who is not blocked and not a contact request, can call.
    #[default]
    Contacts = 1,

    /// Nobody can call me.
    Nobody = 2,
}

/// Returns currently configuration of the "who can call me" option.
async fn who_can_call_me(context: &Context) -> Result<WhoCanCallMe> {
    let who_can_call_me =
        WhoCanCallMe::from_i32(context.get_config_int(Config::WhoCanCallMe).await?)
            .unwrap_or_default();
    Ok(who_can_call_me)
}

#[cfg(test)]
mod calls_tests;
