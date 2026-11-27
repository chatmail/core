use anyhow::Result;
use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipEntryBuilder};
use futures::io::Cursor as FuturesCursor;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

use crate::chat::ChatId;
use crate::message::{MsgId, Viewtype};
use crate::test_utils::{SentMessage, TestContext, create_test_image, send_large_file_message};

pub async fn big_webxdc_app() -> Result<Vec<u8>> {
    let futures_cursor = FuturesCursor::new(Vec::new());
    let mut buffer = futures_cursor.compat_write();
    let mut writer = ZipFileWriter::with_tokio(&mut buffer);
    writer
        .write_entry_whole(
            ZipEntryBuilder::new("index.html".into(), Compression::Stored),
            &[0u8; 1_000_000],
        )
        .await?;
    writer.close().await?;
    Ok(buffer.into_inner().into_inner())
}

pub async fn send_large_webxdc_message<'a>(
    sender: &'a TestContext,
    target_chat: ChatId,
) -> Result<(SentMessage<'a>, SentMessage<'a>, MsgId)> {
    let big_webxdc_app = big_webxdc_app().await?;
    send_large_file_message(sender, target_chat, Viewtype::Webxdc, &big_webxdc_app).await
}

pub async fn send_large_image_message<'a>(
    sender: &'a TestContext,
    target_chat: ChatId,
) -> Result<(SentMessage<'a>, SentMessage<'a>, MsgId)> {
    let (width, height) = (1080, 1920);
    let test_img = create_test_image(width, height)?;
    send_large_file_message(sender, target_chat, Viewtype::Image, &test_img).await
}
