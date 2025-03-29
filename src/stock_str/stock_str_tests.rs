use num_traits::ToPrimitive;

use super::*;
use crate::chat::delete_and_reset_all_device_msgs;
use crate::chatlist::Chatlist;
use crate::test_utils::TestContext;

#[test]
fn test_enum_mapping() {
    assert_eq!(StockMessage::NoMessages.to_usize().unwrap(), 1);
    assert_eq!(StockMessage::SelfMsg.to_usize().unwrap(), 2);
}

#[test]
fn test_fallback() {
    assert_eq!(StockMessage::NoMessages.fallback(), "No messages.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_stock_translation() {
    let t = TestContext::new().await;
    t.set_stock_translation(StockMessage::NoMessages, "xyz".to_string())
        .await
        .unwrap();
    assert_eq!(no_messages(&t).await, "xyz")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_set_stock_translation_wrong_replacements() {
    let t = TestContext::new().await;
    assert!(t
        .ctx
        .set_stock_translation(StockMessage::NoMessages, "xyz %1$s ".to_string())
        .await
        .is_err());
    assert!(t
        .ctx
        .set_stock_translation(StockMessage::NoMessages, "xyz %2$s ".to_string())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stock_str() {
    let t = TestContext::new().await;
    assert_eq!(no_messages(&t).await, "No messages.");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stock_string_repl_str() {
    let t = TestContext::new().await;
    let contact_id = Contact::create(&t.ctx, "Someone", "someone@example.org")
        .await
        .unwrap();
    let contact = Contact::get_by_id(&t.ctx, contact_id).await.unwrap();
    // uses %1$s substitution
    assert_eq!(contact_verified(&t, &contact).await, "Someone verified.");
    // We have no string using %1$d to test...
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stock_system_msg_simple() {
    let t = TestContext::new().await;
    assert_eq!(
        msg_location_enabled(&t).await,
        "Location streaming enabled."
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stock_system_msg_add_member_by_me() {
    let t = TestContext::new().await;
    assert_eq!(
        msg_add_member_remote(&t, "alice@example.org").await,
        "I added member alice@example.org."
    );
    assert_eq!(
        msg_add_member_local(&t, "alice@example.org", ContactId::SELF).await,
        "You added member alice@example.org."
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stock_system_msg_add_member_by_me_with_displayname() {
    let t = TestContext::new().await;
    Contact::create(&t, "Alice", "alice@example.org")
        .await
        .expect("failed to create contact");
    assert_eq!(
        msg_add_member_remote(&t, "alice@example.org").await,
        "I added member alice@example.org."
    );
    assert_eq!(
        msg_add_member_local(&t, "alice@example.org", ContactId::SELF).await,
        "You added member Alice."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stock_system_msg_add_member_by_other_with_displayname() {
    let t = TestContext::new().await;
    let contact_id = {
        Contact::create(&t, "Alice", "alice@example.org")
            .await
            .expect("Failed to create contact Alice");
        Contact::create(&t, "Bob", "bob@example.com")
            .await
            .expect("failed to create bob")
    };
    assert_eq!(
        msg_add_member_local(&t, "alice@example.org", contact_id,).await,
        "Member Alice added by Bob."
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_quota_exceeding_stock_str() -> Result<()> {
    let t = TestContext::new().await;
    let str = quota_exceeding(&t, 81).await;
    assert!(str.contains("81% "));
    assert!(str.contains("100% "));
    assert!(!str.contains("%%"));
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_partial_download_msg_body() -> Result<()> {
    let t = TestContext::new().await;
    let str = partial_download_msg_body(&t, 1024 * 1024).await;
    assert_eq!(str, "1 MiB message");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_update_device_chats() {
    let t = TestContext::new().await;
    t.update_device_chats().await.ok();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 2);

    let chat0 = Chat::load_from_db(&t, chats.get_chat_id(0).unwrap())
        .await
        .unwrap();
    let (self_talk_id, device_chat_id) = if chat0.is_self_talk() {
        (chats.get_chat_id(0).unwrap(), chats.get_chat_id(1).unwrap())
    } else {
        (chats.get_chat_id(1).unwrap(), chats.get_chat_id(0).unwrap())
    };

    // delete self-talk first; this adds a message to device-chat about how self-talk can be restored
    let device_chat_msgs_before = chat::get_chat_msgs(&t, device_chat_id).await.unwrap().len();
    self_talk_id.delete(&t).await.ok();
    assert_eq!(
        chat::get_chat_msgs(&t, device_chat_id).await.unwrap().len(),
        device_chat_msgs_before + 1
    );

    // delete device chat
    device_chat_id.delete(&t).await.ok();

    // check, that the chatlist is empty
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);

    // a subsequent call to update_device_chats() must not re-add manually deleted messages or chats
    t.update_device_chats().await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);

    // Reset all device messages. This normally happens due to account export and import.
    // Check that update_device_chats() does not add welcome message for imported account.
    delete_and_reset_all_device_msgs(&t).await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);

    t.update_device_chats().await.unwrap();
    let chats = Chatlist::try_load(&t, 0, None, None).await.unwrap();
    assert_eq!(chats.len(), 0);
}
