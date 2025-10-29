use anyhow::Result;
use async_zip::tokio::write::ZipFileWriter;
use async_zip::{Compression, ZipEntryBuilder};
use futures::io::Cursor as FuturesCursor;
use pretty_assertions::assert_eq;
use tokio_util::compat::FuturesAsyncWriteCompatExt;

use crate::chat::{self, ChatId};
use crate::download::PRE_MSG_ATTACHMENT_SIZE_THRESHOLD;
use crate::message::{Message, MsgId, Viewtype};
use crate::test_utils::{SentMessage, TestContext, create_test_image};

pub async fn send_large_file_message<'a>(
    sender: &'a TestContext,
    target_chat: ChatId,
    view_type: Viewtype,
    content: &[u8],
) -> Result<(SentMessage<'a>, SentMessage<'a>, MsgId)> {
    let mut msg = Message::new(view_type);
    let file_name = if view_type == Viewtype::Webxdc {
        "test.xdc"
    } else {
        "test.bin"
    };
    msg.set_file_from_bytes(sender, file_name, content, None)?;
    msg.set_text("test".to_owned());

    // assert that test attachment is bigger than limit
    assert!(msg.get_filebytes(sender).await?.unwrap() > PRE_MSG_ATTACHMENT_SIZE_THRESHOLD);

    let msg_id = chat::send_msg(sender, target_chat, &mut msg).await?;
    let smtp_rows = sender.get_smtp_rows_for_msg(msg_id).await;

    assert_eq!(smtp_rows.len(), 2);
    let pre_message = smtp_rows.first().expect("Pre-Message exists");
    let post_message = smtp_rows.get(1).expect("Post-Message exists");
    Ok((pre_message.to_owned(), post_message.to_owned(), msg_id))
}

pub async fn send_large_webxdc_message<'a>(
    sender: &'a TestContext,
    target_chat: ChatId,
) -> Result<(SentMessage<'a>, SentMessage<'a>, MsgId)> {
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
    let big_webxdc_app = buffer.into_inner().into_inner();
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
