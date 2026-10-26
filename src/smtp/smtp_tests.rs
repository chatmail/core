use std::collections::BTreeMap;

use anyhow::{Result, bail, format_err};
use bytes::Bytes;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::{mpsc, oneshot};

use super::sorted_transport_ids;
use crate::chat;
use crate::config::Config;
use crate::constants::DEFAULT_MAX_SMTP_RCPT_TO;
use crate::message;
use crate::message::{Message, MessageState};
use crate::receive_imf::receive_imf;
use crate::scheduler::connectivity::{ConnectivityStore, DetailedConnectivity};
use crate::smtp::SendResult;
use crate::smtp::Smtp;
use crate::smtp::connection_actor::{ConnectionActorHandle, ConnectionActorMessage};
use crate::test_utils::{TestContext, TestContextManager};
use crate::transport;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_candidates() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let t = &tcm.unconfigured().await;

    transport::add_pseudo_transport(t, "foo@example.net").await?;
    transport::add_pseudo_transport(t, "bar@example.net").await?;
    transport::add_pseudo_transport(t, "baz@example.net").await?;

    // By default first added transport is used first.
    assert_eq!(sorted_transport_ids(t).await?, [1, 2, 3]);

    super::record_success(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [3, 1, 2]);

    super::record_success(t, 2).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 3, 1]);

    super::record_success(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [3, 2, 1]);

    super::record_failure(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 3]);

    // New transport is added before all failing transports.
    transport::add_pseudo_transport(t, "qux@example.net").await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 4, 3]);

    super::record_success(t, 4).await?;
    assert_eq!(sorted_transport_ids(t).await?, [4, 2, 1, 3]);

    super::record_failure(t, 4).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 3, 4]);
    super::record_failure(t, 3).await?;
    assert_eq!(sorted_transport_ids(t).await?, [2, 1, 4, 3]);
    super::record_failure(t, 2).await?;
    assert_eq!(sorted_transport_ids(t).await?, [1, 4, 3, 2]);

    Ok(())
}

async fn start_smtp_loop(
    t: &TestContext,
) -> Result<(
    Vec<mpsc::Receiver<ConnectionActorMessage>>,
    async_channel::Sender<()>,
    tokio::task::JoinHandle<()>,
    ConnectivityStore,
)> {
    let transport_ids: Vec<(u32, String)> = t
        .sql
        .query_map_vec("SELECT id, addr FROM transports ORDER BY id", (), |row| {
            let transport_id: u32 = row.get(0)?;
            let addr: String = row.get(1)?;
            Ok((transport_id, addr))
        })
        .await?;

    let mut connectors: BTreeMap<u32, ConnectionActorHandle> = BTreeMap::new();
    let mut receivers = Vec::new();
    for (transport_id, addr) in transport_ids {
        let addr = async_smtp::EmailAddress::new(addr)?;
        let (sender, receiver) = mpsc::channel(2);
        let handle = ConnectionActorHandle::new(sender, addr);
        connectors.insert(transport_id, handle);
        receivers.push(receiver);
    }

    let (idle_interrupt_sender, idle_interrupt_receiver) = async_channel::bounded(1);
    let smtp = Smtp::with_connection_actors(connectors);
    let connectivity = smtp.connectivity.clone();
    let join_handle = tokio::task::spawn(crate::scheduler::smtp_loop(
        t.ctx.clone(),
        smtp,
        idle_interrupt_receiver,
    ));

    Ok((receivers, idle_interrupt_sender, join_handle, connectivity))
}

async fn expect_connect(
    actor_rx: &mut mpsc::Receiver<ConnectionActorMessage>,
) -> Result<oneshot::Sender<Result<()>>> {
    let Some(request) = actor_rx.recv().await else {
        bail!("Failed to receive a request");
    };
    match request {
        ConnectionActorMessage::Connect { callback } => Ok(callback),
        request => Err(format_err!(
            "Unexpected request {request:?}, expected Connect"
        )),
    }
}

async fn expect_sendmail(
    actor_rx: &mut mpsc::Receiver<ConnectionActorMessage>,
) -> Result<(
    oneshot::Sender<SendResult>,
    Vec<async_smtp::EmailAddress>,
    Bytes,
)> {
    let Some(request) = actor_rx.recv().await else {
        bail!("Failed to receive a request");
    };
    match request {
        ConnectionActorMessage::SendMail {
            callback,
            recipients,
            data,
        } => Ok((callback, recipients, data)),
        request => Err(format_err!(
            "Unexpected request {request:?}, expected SendMail"
        )),
    }
}

async fn assert_message_text(context: &TestContext, data: &[u8], text: &str) {
    let seen = false;
    let received_msg = receive_imf(context, data, seen)
        .await
        .expect("Failed to receive the message")
        .expect("Received no message");
    let msg_id = *received_msg.msg_ids.last().unwrap();
    let msg = Message::load_from_db(context, msg_id)
        .await
        .expect("Failed to load the message");
    assert_eq!(msg.text, text);
}

/// Tests that if message sending temporary fails, it is retried before sending messages that were queued later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_temporary_failure_no_reordering() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    let alice_chat_id = alice.create_chat_id(bob).await;

    for i in 1..=3 {
        let mut msg = Message::new_text(format!("Message {i}"));
        chat::send_msg(alice, alice_chat_id, &mut msg).await?;
    }

    idle_interrupt_sender.send(()).await?;
    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 2);
    assert_message_text(bob, &data, "Message 1").await;
    callback.send(SendResult::Success).unwrap();

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 2);
    callback
        .send(SendResult::TemporaryFailure(format_err!(
            "SMTP server rejected the second message"
        )))
        .unwrap();
    alice
        .assert_warn("SMTP server rejected the second message")
        .await;

    idle_interrupt_sender.send(()).await?;

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 2);
    assert_message_text(bob, &data, "Message 2").await;
    callback.send(SendResult::Success).unwrap();

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_message_text(bob, &data, "Message 3").await;
    assert_eq!(recipients.len(), 2);
    callback.send(SendResult::Success).unwrap();

    drop(idle_interrupt_sender);
    join_handle.await?;

    Ok(())
}

/// Tests that permanent SMTP failure results in a visible error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_permanent_failure() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    let alice_chat_id = alice.create_chat_id(bob).await;

    let mut msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, alice_chat_id, &mut msg).await?;

    idle_interrupt_sender.send(()).await?;
    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    callback
        .send(SendResult::PermanentFailure(format_err!(
            "SMTP server returned permanent failure"
        )))
        .unwrap();
    assert_eq!(recipients.len(), 2);

    // Warning about failing a message.
    alice
        .assert_warn("SMTP server returned permanent failure")
        .await;

    // Warning about SMTP transport returning a permanent failure.
    alice
        .assert_warn("Failed to send message: SMTP server returned permanent failure.")
        .await;

    drop(idle_interrupt_sender);
    join_handle.await?;

    let msg = Message::load_from_db(alice, msg.id).await?;
    assert_eq!(msg.state, MessageState::OutFailed);
    assert_eq!(
        msg.error.expect("Message should have failed"),
        "SMTP server returned permanent failure"
    );

    Ok(())
}

/// Tests that a message fails when reaching 7th try.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_retry_limit() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    let alice_chat_id = alice.create_chat_id(bob).await;

    let mut msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, alice_chat_id, &mut msg).await?;

    for i in 1..=7 {
        idle_interrupt_sender.send(()).await?;
        let callback = expect_connect(&mut alice_actors_rx[0]).await?;
        callback.send(Ok(())).unwrap();

        if i == 7 {
            alice
                .assert_warn("Number of retries exceeded the limit.")
                .await;
        } else {
            let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
            callback
                .send(SendResult::TemporaryFailure(format_err!(
                    "SMTP server rejected the message on try {i}"
                )))
                .unwrap();
            assert_eq!(recipients.len(), 2);
            alice.assert_warn(&format!("Failed to send message: Temporary SMTP failure: SMTP server rejected the message on try {i}.")).await;
        }
    }

    drop(idle_interrupt_sender);
    join_handle.await?;

    let msg = Message::load_from_db(alice, msg.id).await?;
    assert_eq!(msg.state, MessageState::OutFailed);
    assert_eq!(
        msg.error.expect("Message should have failed"),
        "Number of retries exceeded the limit."
    );

    Ok(())
}

/// Tests that a message enqueued after an MDN takes higher priority than MDN.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_loop_sends_messages_before_mdns() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    let alice_chat_id = alice.create_chat_id(bob).await;
    let bob_chat_id = bob.create_chat_id(alice).await;

    // Bob sends a message to Alice, so Alice can send an MDN.
    let bob_sent_msg = bob.send_text(bob_chat_id, "Hello, Alice!").await;
    let alice_msg1 = alice.recv_msg(&bob_sent_msg).await;

    // Alice marks the message as read first and sends a reply afterwards,
    // but a reply should be sent before an MDN once SMTP loop is interrupted.
    message::markseen_msgs(alice, vec![alice_msg1.id]).await?;
    let mut bob_msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, alice_chat_id, &mut bob_msg).await?;
    idle_interrupt_sender.send(()).await?;

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    callback.send(SendResult::Success).unwrap();
    assert_eq!(recipients.len(), 2);
    assert_message_text(bob, &data, "Hello, Bob!").await;

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();
    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    callback.send(SendResult::Success).unwrap();
    assert_eq!(recipients.len(), 2);

    drop(idle_interrupt_sender);
    join_handle.await?;

    assert_eq!(
        bob_sent_msg.sender_msg_id.get_state(bob).await?,
        MessageState::OutDelivered
    );
    let seen = false;
    receive_imf(bob, &data, seen).await?.unwrap();
    assert_eq!(
        bob_sent_msg.sender_msg_id.get_state(bob).await?,
        MessageState::OutMdnRcvd
    );

    Ok(())
}

/// Tests that MDNs sent to the same recipient are merged into a single message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_loop_aggregates_mdns() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    // Add Bob so messages don't arrive as a contact request.
    alice.create_chat_id(bob).await;

    let bob_chat_id = bob.create_chat_id(alice).await;

    let bob_sent_msg1 = bob.send_text(bob_chat_id, "Hello, Alice!").await;
    let alice_msg1 = alice.recv_msg(&bob_sent_msg1).await;
    let bob_sent_msg2 = bob.send_text(bob_chat_id, "Hi!").await;
    let alice_msg2 = alice.recv_msg(&bob_sent_msg2).await;
    let bob_sent_msg3 = bob.send_text(bob_chat_id, "Hello again!").await;
    let alice_msg3 = alice.recv_msg(&bob_sent_msg3).await;

    // Alice marks all three messages as seen in two calls.
    // This should still result in a single MDN.
    message::markseen_msgs(alice, vec![alice_msg2.id, alice_msg3.id]).await?;
    message::markseen_msgs(alice, vec![alice_msg1.id]).await?;

    idle_interrupt_sender.send(()).await?;

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    callback.send(SendResult::Success).unwrap();
    assert_eq!(recipients.len(), 2);

    let seen = false;
    receive_imf(bob, &data, seen).await?.unwrap();
    for bob_sent_msg in [bob_sent_msg1, bob_sent_msg2, bob_sent_msg3] {
        assert_eq!(
            bob_sent_msg.sender_msg_id.get_state(bob).await?,
            MessageState::OutMdnRcvd
        );
    }

    drop(idle_interrupt_sender);
    join_handle.await?;

    Ok(())
}

/// Tests MDN sending failures, both temporary and permanent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_loop_mdn_sending_failures() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    // Add Bob so messages don't arrive as a contact request.
    alice.create_chat_id(bob).await;

    let bob_chat_id = bob.create_chat_id(alice).await;
    let bob_sent_msg = bob.send_text(bob_chat_id, "Hello, Alice!").await;
    let alice_msg = alice.recv_msg(&bob_sent_msg).await;

    message::markseen_msgs(alice, vec![alice_msg.id]).await?;

    idle_interrupt_sender.send(()).await?;

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 2);
    callback
        .send(SendResult::TemporaryFailure(format_err!(
            "Temporary MDN sending failure"
        )))
        .unwrap();

    alice
        .assert_warn("Failed to send MDNs: Temporary error while sending an MDN.")
        .await;

    idle_interrupt_sender.send(()).await?;
    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 2);
    callback
        .send(SendResult::PermanentFailure(format_err!(
            "Permanent MDN sending failure"
        )))
        .unwrap();
    alice
        .assert_warn("removing it: Permanent MDN sending failure.")
        .await;
    alice
        .assert_warn("Failed to send MDNs: Permanent MDN sending failure.")
        .await;

    drop(idle_interrupt_sender);
    join_handle.await?;

    assert_eq!(
        alice
            .sql
            .count("SELECT COUNT(*) FROM smtp_mdns", ())
            .await?,
        0
    );

    Ok(())
}

/// Tests that messages with more than [`DEFAULT_MAX_SMTP_RCPT_TO`] recipients are sent in multiple chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_chunking_success() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    alice.set_config_bool(Config::BccSelf, false).await?;

    let mut additional_contexts = Vec::new();
    for i in 1..=DEFAULT_MAX_SMTP_RCPT_TO + 5 {
        let ctx = tcm.unconfigured().await;
        let addr = format!("foo{i}@example.net");
        transport::add_pseudo_transport(&ctx, &addr).await?;
        additional_contexts.push(ctx);
    }

    let chat_id = chat::create_group(alice, "Group").await?;
    for additional_context in &additional_contexts {
        let contact_id = alice.add_or_lookup_contact_id(additional_context).await;
        chat::add_contact_to_chat(alice, chat_id, contact_id).await?;
    }

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;
    let mut msg = Message::new_text("Hello, I created a group!".to_string());
    chat::send_msg(alice, chat_id, &mut msg).await?;
    idle_interrupt_sender.send(()).await?;

    // First chunk contains `DEFAULT_MAX_SMTP_RCPT_TO` recipients.
    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();
    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), DEFAULT_MAX_SMTP_RCPT_TO as usize);
    callback.send(SendResult::Success).unwrap();

    // Second chunk contains remaining 5 recipients.
    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 5);
    callback.send(SendResult::Success).unwrap();

    drop(idle_interrupt_sender);
    join_handle.await?;

    assert_eq!(
        alice_actors_rx[0].try_recv().err(),
        Some(TryRecvError::Disconnected)
    );

    Ok(())
}

/// Tests that on temporary failure of the second chunk, only the second chunk is retried.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_chunking_temporary_failure() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    alice.set_config_bool(Config::BccSelf, false).await?;

    let mut additional_contexts = Vec::new();
    for i in 1..=DEFAULT_MAX_SMTP_RCPT_TO + 5 {
        let ctx = tcm.unconfigured().await;
        let addr = format!("foo{i}@example.net");
        transport::add_pseudo_transport(&ctx, &addr).await?;
        additional_contexts.push(ctx);
    }

    let chat_id = chat::create_group(alice, "Group").await?;
    for additional_context in &additional_contexts {
        let contact_id = alice.add_or_lookup_contact_id(additional_context).await;
        chat::add_contact_to_chat(alice, chat_id, contact_id).await?;
    }

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, connectivity) =
        start_smtp_loop(alice).await?;
    let mut msg = Message::new_text("Hello, I created a group!".to_string());
    chat::send_msg(alice, chat_id, &mut msg).await?;

    idle_interrupt_sender.send(()).await?;
    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    // First chunk contains `DEFAULT_MAX_SMTP_RCPT_TO` recipients.
    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), DEFAULT_MAX_SMTP_RCPT_TO as usize);
    callback.send(SendResult::Success).unwrap();

    // Second chunk contains remaining 5 recipients.
    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 5);
    callback
        .send(SendResult::TemporaryFailure(format_err!(
            "Failed to send second chunk"
        )))
        .unwrap();

    idle_interrupt_sender.send(()).await?;
    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    assert_eq!(recipients.len(), 5);
    callback.send(SendResult::Success).unwrap();

    drop(idle_interrupt_sender);
    join_handle.await?;
    assert_eq!(connectivity.get_detailed(), DetailedConnectivity::Idle);

    assert!(alice_actors_rx[0].try_recv().is_err());

    alice
        .assert_warn("Failed to send message: Temporary SMTP failure: Failed to send second chunk.")
        .await;

    Ok(())
}

/// Tests that if sending over existing transports fails,
/// message can be sent over a new transport that is added later.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_loop_failover_to_new_transport() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, connectivity) =
        start_smtp_loop(alice).await?;

    let alice_chat_id = alice.create_chat_id(bob).await;

    let mut msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, alice_chat_id, &mut msg).await?;
    idle_interrupt_sender.send(()).await?;

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Ok(())).unwrap();
    let (callback, recipients, _data) = expect_sendmail(&mut alice_actors_rx[0]).await?;
    callback
        .send(SendResult::TemporaryFailure(format_err!(
            "First transport does not really work"
        )))
        .unwrap();
    alice
        .assert_warn(
            "Failed to send message: Temporary SMTP failure: First transport does not really work.",
        )
        .await;
    assert_eq!(recipients.len(), 2);

    drop(idle_interrupt_sender);
    join_handle.await?;

    assert_eq!(
        connectivity.get_detailed(),
        DetailedConnectivity::Error("First transport does not really work".to_string())
    );

    transport::add_pseudo_transport(alice, "newtransport@example.net").await?;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    let callback = expect_connect(&mut alice_actors_rx[1]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[1]).await?;
    callback.send(SendResult::Success).unwrap();

    // Two bcc-self addresses and the address of Bob.
    assert_eq!(recipients.len(), 3);

    drop(idle_interrupt_sender);
    join_handle.await?;

    assert_message_text(bob, &data, "Hello, Bob!").await;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_loop_multiple_transports() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    transport::add_pseudo_transport(alice, "foo@example.net").await?;
    transport::add_pseudo_transport(alice, "bar@example.net").await?;

    let (mut alice_actors_rx, idle_interrupt_sender, join_handle, _connectivity) =
        start_smtp_loop(alice).await?;

    let chat_id = alice.create_chat_id(bob).await;
    let mut msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, chat_id, &mut msg).await?;
    idle_interrupt_sender.send(()).await?;

    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    callback.send(Err(format_err!("Timeout"))).unwrap();

    let callback = expect_connect(&mut alice_actors_rx[1]).await?;
    callback.send(Ok(())).unwrap();

    let (callback, recipients, data) = expect_sendmail(&mut alice_actors_rx[1]).await?;

    assert_eq!(
        alice_actors_rx[0].try_recv().err(),
        Some(TryRecvError::Empty)
    );
    assert_eq!(
        alice_actors_rx[2].try_recv().err(),
        Some(TryRecvError::Empty)
    );

    // 3 bcc-self addresses and Bob
    assert_eq!(recipients.len(), 4);

    callback.send(SendResult::Success).unwrap();
    assert_message_text(bob, &data, "Hello, Bob!").await;

    // Alice sends another message, this time the last successful transport should be tried first.
    let mut msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, chat_id, &mut msg).await?;
    idle_interrupt_sender.send(()).await?;
    let callback = expect_connect(&mut alice_actors_rx[1]).await?;
    assert_eq!(
        alice_actors_rx[0].try_recv().err(),
        Some(TryRecvError::Empty)
    );
    assert_eq!(
        alice_actors_rx[2].try_recv().err(),
        Some(TryRecvError::Empty)
    );
    callback.send(Err(format_err!("Timeout"))).unwrap();

    // First transport never failed, we just did not manage to connect to it,
    // so it is the next one to try.
    let callback = expect_connect(&mut alice_actors_rx[0]).await?;
    assert_eq!(
        alice_actors_rx[1].try_recv().err(),
        Some(TryRecvError::Empty)
    );
    assert_eq!(
        alice_actors_rx[2].try_recv().err(),
        Some(TryRecvError::Empty)
    );
    callback.send(Err(format_err!("Timeout"))).unwrap();

    // Finally third transport is tried.
    let callback = expect_connect(&mut alice_actors_rx[2]).await?;

    // Drop interrupt sender so SMTP is closed cleanly afterwards.
    drop(idle_interrupt_sender);
    callback.send(Ok(())).unwrap();

    let (callback, ..) = expect_sendmail(&mut alice_actors_rx[2]).await?;
    callback.send(SendResult::Success).unwrap();
    join_handle.await?;

    Ok(())
}
