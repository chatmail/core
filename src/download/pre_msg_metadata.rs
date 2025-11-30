use anyhow::{Context as _, Result};
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

use crate::context::Context;
use crate::log::warn;
use crate::message::Message;
use crate::message::Viewtype;
use crate::param::{Param, Params};

/// Metadata contained in PreMessage that describes the Full Message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreMsgMetadata {
    /// size of the attachment in bytes
    pub(crate) size: u64,
    /// Real viewtype of message
    pub(crate) viewtype: Viewtype,
    /// the original file name
    pub(crate) filename: String,
    /// Dimensions: width and height of image or video
    pub(crate) dimensions: Option<(i32, i32)>,
    /// Duration of audio file or video in milliseconds
    pub(crate) duration: Option<i32>,
}

impl PreMsgMetadata {
    // Returns PreMsgMetadata for messages with files and None for messages without file attachment
    pub(crate) async fn from_msg(context: &Context, message: &Message) -> Result<Option<Self>> {
        if !message.viewtype.has_file() {
            return Ok(None);
        }

        let size = message
            .get_filebytes(context)
            .await?
            .context("unexpected: file has no size")?;
        let filename = message
            .param
            .get(Param::Filename)
            .unwrap_or_default()
            .to_owned();
        let dimensions = {
            match (
                message.param.get_int(Param::Width),
                message.param.get_int(Param::Height),
            ) {
                (None, None) => None,
                (Some(width), Some(height)) => Some((width, height)),
                _ => {
                    warn!(context, "Message has misses either width or height");
                    None
                }
            }
        };
        let duration = message.param.get_int(Param::Duration);

        Ok(Some(Self {
            size,
            filename,
            viewtype: message.viewtype,
            dimensions,
            duration,
        }))
    }

    pub(crate) fn to_header_value(&self) -> Result<String> {
        Ok(serde_json::to_string(&self)?)
    }

    pub(crate) fn try_from_header_value(value: &str) -> Result<Self> {
        Ok(serde_json::from_str(value)?)
    }
}

impl Params {
    /// Applies data from pre_msg_metadata to Params
    pub(crate) fn apply_from_pre_msg_metadata(
        &mut self,
        pre_msg_metadata: &PreMsgMetadata,
    ) -> &mut Self {
        self.set(Param::FullMessageFileBytes, pre_msg_metadata.size);
        if !pre_msg_metadata.filename.is_empty() {
            self.set(Param::Filename, &pre_msg_metadata.filename);
        }
        self.set_i64(
            Param::FullMessageViewtype,
            pre_msg_metadata.viewtype.to_i64().unwrap_or_default(),
        );
        if let Some((width, height)) = pre_msg_metadata.dimensions {
            self.set(Param::Width, width);
            self.set(Param::Height, height);
        }
        if let Some(duration) = pre_msg_metadata.duration {
            self.set(Param::Duration, duration);
        }

        self
    }
}

#[cfg(test)]
mod tests {
    // todo build from message (different types: file, image, audio)
    // todo create artifically and serialize to header
    // todo deserialize from header
}
