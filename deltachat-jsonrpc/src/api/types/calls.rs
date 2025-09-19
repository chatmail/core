use anyhow::Result;

use deltachat::context::Context;
use deltachat::message::MsgId;
use serde::Serialize;
use typescript_type_def::TypeDef;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "CallInfo", rename_all = "camelCase")]
pub struct JsonrpcCallInfo {
    /// True if the call is an incoming call.
    pub is_incoming: bool,

    /// True if the call should not ring anymore.
    pub is_stale: bool,

    /// True if the call is accepted.
    pub is_accepted: bool,

    /// True if the call has been ended.
    pub is_ended: bool,

    /// Call duration in seconds.
    pub duration: i64,

    /// SDP offer.
    ///
    /// Can be used to manually answer the call
    /// even if incoming call event was missed.
    pub sdp_offer: String,
}

impl JsonrpcCallInfo {
    pub async fn from_msg_id(context: &Context, msg_id: MsgId) -> Result<JsonrpcCallInfo> {
        let call_info = context.load_call_by_id(msg_id).await?;

        let is_incoming = call_info.is_incoming();
        let is_stale = call_info.is_stale();
        let is_accepted = call_info.is_accepted();
        let is_ended = call_info.is_ended();
        let duration = call_info.duration_seconds();
        let sdp_offer = call_info.place_call_info.clone();

        Ok(JsonrpcCallInfo {
            is_incoming,
            is_stale,
            is_accepted,
            is_ended,
            duration,
            sdp_offer,
        })
    }
}
