use anyhow::Result;
use pretty_assertions::assert_eq;

use crate::message::Viewtype;
use crate::test_utils::TestContextManager;
use crate::tests::pre_messages::util::{
    send_large_file_message, send_large_image_message, send_large_webxdc_message,
};

/// Test the addition of the download info to message text
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_additional_text_on_different_viewtypes() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;
    let a_group_id = alice.create_group_with_members("test group", &[bob]).await;

    tcm.section("Test metadata preview text for File");
    let (pre_message, _, _) =
        send_large_file_message(alice, a_group_id, Viewtype::File, &vec![0u8; 1_000_000]).await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.text, "test".to_owned());
    assert_eq!(msg.get_text(), "test [test.bin – 976.56 KiB]".to_owned());

    tcm.section("Test metadata preview text for webxdc app");
    let (pre_message, _, _) = send_large_webxdc_message(alice, a_group_id).await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.text, "test".to_owned());
    assert_eq!(msg.get_post_message_viewtype(), Some(Viewtype::Webxdc));
    assert_eq!(msg.get_text(), "test [Mini App – 976.68 KiB]".to_owned());

    tcm.section("Test metadata preview text for Image");

    let (pre_message, _, _) = send_large_image_message(alice, a_group_id).await?;
    let msg = bob.recv_msg(&pre_message).await;
    assert_eq!(msg.text, "test".to_owned());
    assert_eq!(msg.get_text(), "test [Image – 146.12 KiB]".to_owned());

    Ok(())
}
