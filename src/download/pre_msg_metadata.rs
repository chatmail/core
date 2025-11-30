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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) dimensions: Option<(i32, i32)>,
    /// Duration of audio file or video in milliseconds
    #[serde(skip_serializing_if = "Option::is_none")]
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
    use anyhow::Result;
    use pretty_assertions::assert_eq;

    use crate::{
        message::{Message, Viewtype},
        test_utils::{TestContextManager, create_test_image},
    };

    use super::PreMsgMetadata;

    /// Build from message with file attachment
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_build_from_file_msg() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;

        let mut file_msg = Message::new(Viewtype::File);
        file_msg.set_file_from_bytes(alice, "test.bin", &vec![0u8; 1_000_000], None)?;
        let pre_mesage_metadata = PreMsgMetadata::from_msg(alice, &file_msg).await?;
        assert_eq!(
            pre_mesage_metadata,
            Some(PreMsgMetadata {
                size: 1_000_000,
                viewtype: Viewtype::File,
                filename: "test.bin".to_string(),
                dimensions: None,
                duration: None,
            })
        );
        Ok(())
    }

    /// Build from message with image attachment
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_build_from_image_msg() -> Result<()> {
        let mut tcm = TestContextManager::new();
        let alice = &tcm.alice().await;
        let mut image_msg = Message::new(Viewtype::Image);

        let (width, height) = (1080, 1920);
        let test_img = create_test_image(width, height)?;
        image_msg.set_file_from_bytes(alice, "vacation.png", &test_img, None)?;
        // this is usually done while sending,
        // but we don't send it here, so we need to call it ourself
        image_msg.try_calc_and_set_dimensions(alice).await?;
        let pre_mesage_metadata = PreMsgMetadata::from_msg(alice, &image_msg).await?;
        assert_eq!(
            pre_mesage_metadata,
            Some(PreMsgMetadata {
                size: 1816098,
                viewtype: Viewtype::Image,
                filename: "vacation.png".to_string(),
                dimensions: Some((width as i32, height as i32)),
                duration: None,
            })
        );

        Ok(())
    }

    /// Test that serialisation results in expected format
    #[test]
    fn test_serialize_to_header() -> Result<()> {
        assert_eq!(
            PreMsgMetadata {
                size: 1_000_000,
                viewtype: Viewtype::File,
                filename: "test.bin".to_string(),
                dimensions: None,
                duration: None,
            }
            .to_header_value()?,
            "{\"size\":1000000,\"viewtype\":\"File\",\"filename\":\"test.bin\"}"
        );
        assert_eq!(
            PreMsgMetadata {
                size: 5_342_765,
                viewtype: Viewtype::Image,
                filename: "vacation.png".to_string(),
                dimensions: Some((1080, 1920)),
                duration: None,
            }
            .to_header_value()?,
            "{\"size\":5342765,\"viewtype\":\"Image\",\"filename\":\"vacation.png\",\"dimensions\":[1080,1920]}"
        );
        assert_eq!(
            PreMsgMetadata {
                size: 5_000,
                viewtype: Viewtype::Audio,
                filename: "audio-DD-MM-YY.ogg".to_string(),
                dimensions: None,
                duration: Some(152_310),
            }
            .to_header_value()?,
            "{\"size\":5000,\"viewtype\":\"Audio\",\"filename\":\"audio-DD-MM-YY.ogg\",\"duration\":152310}"
        );

        Ok(())
    }

    /// Test that deserialisation from expected format works
    /// This test will become important for compatibility between versions in the future
    #[test]
    fn test_deserialize_from_header() -> Result<()> {
        assert_eq!(
            serde_json::from_str::<PreMsgMetadata>(
                "{\"size\":1000000,\"viewtype\":\"File\",\"filename\":\"test.bin\",\"dimensions\":null,\"duration\":null}"
            )?,
            PreMsgMetadata {
                size: 1_000_000,
                viewtype: Viewtype::File,
                filename: "test.bin".to_string(),
                dimensions: None,
                duration: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<PreMsgMetadata>(
                "{\"size\":5342765,\"viewtype\":\"Image\",\"filename\":\"vacation.png\",\"dimensions\":[1080,1920]}"
            )?,
            PreMsgMetadata {
                size: 5_342_765,
                viewtype: Viewtype::Image,
                filename: "vacation.png".to_string(),
                dimensions: Some((1080, 1920)),
                duration: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<PreMsgMetadata>(
                "{\"size\":5000,\"viewtype\":\"Audio\",\"filename\":\"audio-DD-MM-YY.ogg\",\"duration\":152310}"
            )?,
            PreMsgMetadata {
                size: 5_000,
                viewtype: Viewtype::Audio,
                filename: "audio-DD-MM-YY.ogg".to_string(),
                dimensions: None,
                duration: Some(152_310),
            }
        );

        Ok(())
    }
}
