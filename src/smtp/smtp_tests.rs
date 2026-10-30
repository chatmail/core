use std::collections::BTreeMap;

use anyhow::{Result, format_err};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;

use super::sorted_transport_ids;
use crate::chat;
use crate::message::Message;
use crate::receive_imf::receive_imf;
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
    let join_handle = tokio::task::spawn(crate::scheduler::smtp_loop(
        t.ctx.clone(),
        smtp,
        idle_interrupt_receiver,
    ));

    Ok((receivers, idle_interrupt_sender, join_handle))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_smtp_loop() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &tcm.alice().await;
    let bob = &tcm.bob().await;

    transport::add_pseudo_transport(alice, "foo@example.net").await?;
    transport::add_pseudo_transport(alice, "bar@example.net").await?;

    let (mut receivers, idle_interrupt_sender, join_handle) = start_smtp_loop(alice).await?;

    let chat_id = alice.create_chat_id(bob).await;
    let mut msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, chat_id, &mut msg).await?;
    idle_interrupt_sender.send(()).await?;

    let Some(ConnectionActorMessage::Connect { callback }) = receivers[0].recv().await else {
        panic!("Unexpected request");
    };
    callback.send(Err(format_err!("Timeout"))).unwrap();

    let Some(ConnectionActorMessage::Connect { callback }) = receivers[1].recv().await else {
        panic!("Unexpected request");
    };
    callback.send(Ok(())).unwrap();

    let Some(ConnectionActorMessage::SendMail {
        callback,
        recipients,
        data,
    }) = receivers[1].recv().await
    else {
        panic!("Unexpected request");
    };

    assert_eq!(receivers[0].try_recv().err(), Some(TryRecvError::Empty));
    assert_eq!(receivers[2].try_recv().err(), Some(TryRecvError::Empty));

    // 3 bcc-self addresses and Bob
    assert_eq!(recipients.len(), 4);

    callback.send(SendResult::Success).unwrap();
    let seen = false;
    let bob_received_msg = receive_imf(bob, data.as_ref(), seen).await?.unwrap();
    let bob_msg_id = *bob_received_msg.msg_ids.last().unwrap();
    let bob_msg = Message::load_from_db(bob, bob_msg_id).await?;
    assert_eq!(bob_msg.text, "Hello, Bob!");

    // Alice sends another message, this time the last successful transport should be tried first.
    let mut msg = Message::new_text("Hello, Bob!".to_string());
    chat::send_msg(alice, chat_id, &mut msg).await?;
    idle_interrupt_sender.send(()).await?;
    let Some(ConnectionActorMessage::Connect { callback }) = receivers[1].recv().await else {
        panic!("Unexpected request");
    };
    assert_eq!(receivers[0].try_recv().err(), Some(TryRecvError::Empty));
    assert_eq!(receivers[2].try_recv().err(), Some(TryRecvError::Empty));
    callback.send(Err(format_err!("Timeout"))).unwrap();

    // First transport never failed, we just did not manage to connect to it,
    // so it is the next one to try.
    let Some(ConnectionActorMessage::Connect { callback }) = receivers[0].recv().await else {
        panic!("Unexpected request");
    };
    assert_eq!(receivers[1].try_recv().err(), Some(TryRecvError::Empty));
    assert_eq!(receivers[2].try_recv().err(), Some(TryRecvError::Empty));
    callback.send(Err(format_err!("Timeout"))).unwrap();

    // Finally third transport is tried.
    let Some(ConnectionActorMessage::Connect { callback }) = receivers[2].recv().await else {
        panic!("Unexpected request");
    };

    // Drop interrupt sender so SMTP is closed cleanly afterwards.
    drop(idle_interrupt_sender);
    callback.send(Ok(())).unwrap();

    let Some(ConnectionActorMessage::SendMail { callback, .. }) = receivers[2].recv().await else {
        panic!("Unexpected request");
    };
    callback.send(SendResult::Success).unwrap();
    join_handle.await?;

    Ok(())
}
