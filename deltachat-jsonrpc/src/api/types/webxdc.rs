use deltachat::{
    context::Context,
    message::{Message, MsgId},
    webxdc::WebxdcInfo,
};
use serde::Serialize;
use typescript_type_def::TypeDef;

use super::maybe_empty_string_to_option;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "WebxdcMessageInfo", rename_all = "camelCase")]
pub struct WebxdcMessageInfo {
    /// The name of the app.
    ///
    /// Defaults to the filename if not set in the manifest.
    name: String,
    /// App icon file name.
    /// Defaults to an standard icon if nothing is set in the manifest.
    ///
    /// To get the file, use dc_msg_get_webxdc_blob(). (not yet in jsonrpc, use rust api or cffi for it)
    ///
    /// App icons should should be square,
    /// the implementations will add round corners etc. as needed.
    icon: String,
    /// if the Webxdc represents a document, then this is the name of the document
    document: Option<String>,
    /// short string describing the state of the app,
    /// sth. as "2 votes", "Highscore: 123",
    /// can be changed by the apps
    summary: Option<String>,
    /// URL where the source code of the Webxdc and other information can be found;
    /// defaults to an empty string.
    /// Implementations may offer an menu or a button to open this URL.
    source_code_url: Option<String>,
    /// True if full internet access should be granted to the app.
    internet_access: bool,
    /// Address to be used for `window.webxdc.selfAddr` in JS land.
    self_addr: String,
    /// Milliseconds to wait before calling `sendUpdate()` again since the last call.
    /// Should be exposed to `window.sendUpdateInterval` in JS land.
    send_update_interval: usize,
    /// Maximum number of bytes accepted for a serialized update object.
    /// Should be exposed to `window.sendUpdateMaxSize` in JS land.
    send_update_max_size: usize,
}

impl WebxdcMessageInfo {
    pub async fn get_for_message(
        context: &Context,
        instance_message_id: MsgId,
    ) -> anyhow::Result<Self> {
        let message = Message::load_from_db(context, instance_message_id).await?;
        let WebxdcInfo {
            name,
            icon,
            document,
            summary,
            source_code_url,
            request_integration: _,
            internet_access,
            self_addr,
            send_update_interval_ms,
            send_update_max_size,
        } = message.get_webxdc_info(context).await?;

        Ok(Self {
            name,
            icon,
            document: maybe_empty_string_to_option(document),
            summary: maybe_empty_string_to_option(summary),
            source_code_url: maybe_empty_string_to_option(source_code_url),
            internet_access,
            self_addr,
            send_update_interval: send_update_interval_ms,
            send_update_max_size,
        })
    }
}
