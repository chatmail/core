use anyhow::Result;

use deltachat::calls::{call_state, sdp_has_video, CallState};
use deltachat::context::Context;
use deltachat::message::MsgId;
use serde::Serialize;
use typescript_type_def::TypeDef;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "CallInfo", rename_all = "camelCase")]
pub struct JsonrpcCallInfo {
    /// SDP offer.
    ///
    /// Can be used to manually answer the call
    /// even if incoming call event was missed.
    pub sdp_offer: String,

    /// True if SDP offer has a video.
    pub has_video: bool,

    /// Call state.
    ///
    /// For example, if the call is accepted, active, canceled, declined etc.
    pub state: JsonrpcCallState,
}

impl JsonrpcCallInfo {
    pub async fn from_msg_id(context: &Context, msg_id: MsgId) -> Result<JsonrpcCallInfo> {
        let call_info = context.load_call_by_id(msg_id).await?;
        let sdp_offer = call_info.place_call_info.clone();
        let has_video = sdp_has_video(&sdp_offer).unwrap_or_default();
        let state = JsonrpcCallState::from_msg_id(context, msg_id).await?;

        Ok(JsonrpcCallInfo {
            sdp_offer,
            has_video,
            state,
        })
    }
}

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "CallState", tag = "kind")]
pub enum JsonrpcCallState {
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

impl JsonrpcCallState {
    pub async fn from_msg_id(context: &Context, msg_id: MsgId) -> Result<JsonrpcCallState> {
        let call_state = call_state(context, msg_id).await?;

        let jsonrpc_call_state = match call_state {
            CallState::Alerting => JsonrpcCallState::Alerting,
            CallState::Active => JsonrpcCallState::Active,
            CallState::Completed { duration } => JsonrpcCallState::Completed { duration },
            CallState::Missed => JsonrpcCallState::Missed,
            CallState::Declined => JsonrpcCallState::Declined,
            CallState::Canceled => JsonrpcCallState::Canceled,
        };

        Ok(jsonrpc_call_state)
    }
}
