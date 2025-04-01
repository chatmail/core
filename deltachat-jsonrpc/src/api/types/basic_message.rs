use anyhow::{Context as _, Result};

use deltachat::context::Context;
use deltachat::message::Message;
use deltachat::message::MsgId;
use num_traits::cast::ToPrimitive;
use serde::Serialize;
use typescript_type_def::TypeDef;

use super::message::DownloadState;
use super::message::MessageViewtype;
use super::message::SystemMessageType;

#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum BasicMessageLoadResult {
    Message(BasicMessageObject),
    LoadingError { error: String },
}

/// Message that only has basic properties that doen't require additional db calls
#[derive(Serialize, TypeDef, schemars::JsonSchema)]
#[serde(rename = "BasicMessage", rename_all = "camelCase")]
pub struct BasicMessageObject {
    id: u32,
    chat_id: u32,
    from_id: u32,

    text: String,

    is_edited: bool,

    /// Check if a message has a POI location bound to it.
    /// These locations are also returned by `get_locations` method.
    /// The UI may decide to display a special icon beside such messages.
    has_location: bool,
    has_html: bool,
    view_type: MessageViewtype,
    state: u32,

    /// An error text, if there is one.
    error: Option<String>,

    timestamp: i64,
    sort_timestamp: i64,
    received_timestamp: i64,
    has_deviating_timestamp: bool,

    // summary - use/create another function if you need it
    subject: String,
    show_padlock: bool,
    is_setupmessage: bool,
    is_info: bool,
    is_forwarded: bool,

    /// True if the message was sent by a bot.
    is_bot: bool,

    /// when is_info is true this describes what type of system message it is
    system_message_type: SystemMessageType,

    duration: i32,
    dimensions_height: i32,
    dimensions_width: i32,

    videochat_type: Option<u32>,
    videochat_url: Option<String>,

    override_sender_name: Option<String>,

    setup_code_begin: Option<String>,

    file: Option<String>,
    file_mime: Option<String>,
    file_name: Option<String>,

    webxdc_href: Option<String>,

    download_state: DownloadState,

    original_msg_id: Option<u32>,

    saved_message_id: Option<u32>,
}

impl BasicMessageObject {
    pub async fn from_msg_id(context: &Context, msg_id: MsgId) -> Result<Option<Self>> {
        let Some(message) = Message::load_from_db_optional(context, msg_id).await? else {
            return Ok(None);
        };

        let override_sender_name = message.get_override_sender_name();

        let download_state = message.download_state().into();

        let message_object = Self {
            id: msg_id.to_u32(),
            chat_id: message.get_chat_id().to_u32(),
            from_id: message.get_from_id().to_u32(),
            text: message.get_text(),
            is_edited: message.is_edited(),
            has_location: message.has_location(),
            has_html: message.has_html(),
            view_type: message.get_viewtype().into(),
            state: message
                .get_state()
                .to_u32()
                .context("state conversion to number failed")?,
            error: message.error(),

            timestamp: message.get_timestamp(),
            sort_timestamp: message.get_sort_timestamp(),
            received_timestamp: message.get_received_timestamp(),
            has_deviating_timestamp: message.has_deviating_timestamp(),

            subject: message.get_subject().to_owned(),
            show_padlock: message.get_showpadlock(),
            is_setupmessage: message.is_setupmessage(),
            is_info: message.is_info(),
            is_forwarded: message.is_forwarded(),
            is_bot: message.is_bot(),
            system_message_type: message.get_info_type().into(),

            duration: message.get_duration(),
            dimensions_height: message.get_height(),
            dimensions_width: message.get_width(),

            videochat_type: match message.get_videochat_type() {
                Some(vct) => Some(
                    vct.to_u32()
                        .context("videochat type conversion to number failed")?,
                ),
                None => None,
            },
            videochat_url: message.get_videochat_url(),

            override_sender_name,

            setup_code_begin: message.get_setupcodebegin(context).await,

            file: match message.get_file(context) {
                Some(path_buf) => path_buf.to_str().map(|s| s.to_owned()),
                None => None,
            }, //BLOBS
            file_mime: message.get_filemime(),
            file_name: message.get_filename(),

            // On a WebxdcInfoMessage this might include a hash holding
            // information about a specific position or state in a webxdc app
            webxdc_href: message.get_webxdc_href(),

            download_state,

            original_msg_id: message
                .get_original_msg_id(context)
                .await?
                .map(|id| id.to_u32()),

            saved_message_id: message
                .get_saved_msg_id(context)
                .await?
                .map(|id| id.to_u32()),
        };
        Ok(Some(message_object))
    }
}
