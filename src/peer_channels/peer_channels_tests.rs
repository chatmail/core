use super::*;
use crate::{
    EventType,
    chat::{self, ChatId, add_contact_to_chat, resend_msgs, send_msg},
    imap::ServerMetadata,
    message::{Message, Viewtype},
    receive_imf::receive_imf,
    test_utils::{TestContext, TestContextManager},
    transport::add_pseudo_transport,
};

/// Adds a transport announcing an iroh relay,
/// like a chatmail server does via IMAP METADATA.
async fn announce_relay(ctx: &TestContext, addr: &str, url: &str) -> Result<()> {
    add_pseudo_transport(ctx, addr).await?;
    let (_, transport_id) = published_transports(ctx)
        .await?
        .into_iter()
        .find(|(a, _)| a == addr)
        .context("Transport not found")?;
    ctx.metadata.write().await.insert(
        transport_id,
        ServerMetadata {
            iroh_relay: Some(Url::parse(url)?),
            ..Default::default()
        },
    );
    Ok(())
}

#[test]
fn test_relay_probe_url() {
    let probe = |url| relay_probe_url(&Url::parse(url).unwrap()).unwrap();
    assert_eq!(
        probe("https://relay.example.org").as_str(),
        "https://relay.example.org/generate_204"
    );
    assert_eq!(
        probe("https://relay.example.org/some/path").as_str(),
        "https://relay.example.org/some/path/generate_204"
    );
}

/// Returns the relay of the node address to advertise, if any.
async fn selected_iroh_relay(ctx: &TestContext) -> Result<Option<RelayUrl>> {
    let iroh = ctx.get_active_or_init_iroh().await?;
    Ok(iroh
        .get_relay_node_addr()
        .ok()
        .and_then(|addr| addr.relay_url().cloned()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_select_working_iroh_relay() -> Result<()> {
    // CI chatmail relay is used as a known-working candidate because
    // mocking out the serving of https requests is not worth it, and,
    // besides, it's also useful to exercise production code paths
    // which the core Python tests do a lot already.
    const WORKING_RELAY: &str = "https://ci-chatmail.testrun.org";

    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;

    announce_relay(alice, "one@example.net", "https://127.0.0.1:9").await?;
    assert_eq!(selected_iroh_relay(alice).await?, None);

    // Relays announced by unpublished transports are not used
    announce_relay(alice, "two@example.net", WORKING_RELAY).await?;
    alice
        .set_transport_unpublished("two@example.net", true)
        .await?;
    assert_eq!(selected_iroh_relay(alice).await?, None);

    // The endpoint is initialized again on the next use
    // because it has no working relay and is not in use yet.
    announce_relay(alice, "three@example.net", "https://192.0.2.1").await?;
    announce_relay(alice, "four@example.net", WORKING_RELAY).await?;
    announce_relay(alice, "five@example.net", "https://192.0.2.2").await?;
    assert_eq!(
        selected_iroh_relay(alice).await?,
        Some(RelayUrl::from(Url::parse(WORKING_RELAY)?))
    );
    Ok(())
}

/// An io stop racing an iroh initialization wins,
/// so no iroh survives it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_stop_io_while_initializing_iroh() -> Result<()> {
    let alice = &TestContext::new_alice().await;

    // Hold the mutex so that both tasks below wait for it,
    // the initialization first and the io stop behind it.
    let guard = alice.iroh_init_mutex.lock().await;
    let init_ctx = alice.ctx.clone();
    let init = tokio::spawn(async move { init_ctx.get_active_or_init_iroh().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stop_ctx = alice.ctx.clone();
    let stop = tokio::spawn(async move { stop_ctx.stop_io().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(guard);

    assert!(init.await?.is_err());
    stop.await?;
    assert!(alice.iroh.read().await.is_none());
    Ok(())
}

/// Iroh without a working relay joins channels
/// but sends no advertisement.
/// It is kept while in use and replaced afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_relayless_endpoint() -> Result<()> {
    const WORKING_RELAY: &str = "https://ci-chatmail.testrun.org";

    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;
    let bob = &tcm.bob().await;

    let alice_chat = alice.create_chat(bob).await;
    let mut instance = Message::new(Viewtype::File);
    instance.set_file_from_bytes(
        alice,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
        None,
    )?;
    send_msg(alice, alice_chat.id, &mut instance).await?;
    let alice_webxdc = alice.get_last_msg().await;
    alice.pop_sent_msg().await;

    // Without a working relay the channel is joined
    // but no advertisement is sent.
    announce_relay(alice, "broken@example.net", "https://127.0.0.1:9").await?;
    assert!(
        send_webxdc_realtime_advertisement(alice, alice_webxdc.id)
            .await?
            .is_some()
    );
    assert_eq!(selected_iroh_relay(alice).await?, None);

    // Iroh is kept while its channel is in use,
    // so a relay announced later is not picked up yet.
    let working_relay = Some(RelayUrl::from(Url::parse(WORKING_RELAY)?));
    announce_relay(alice, "working@example.net", WORKING_RELAY).await?;
    assert_eq!(selected_iroh_relay(alice).await?, None);

    // The unused iroh is replaced on the next use.
    leave_webxdc_realtime(alice, alice_webxdc.id).await?;
    assert_eq!(selected_iroh_relay(alice).await?, working_relay);

    // Disabling realtime does not tear down iroh,
    // but sending and advertising become no-ops.
    alice
        .set_config_bool(Config::WebxdcRealtimeEnabled, false)
        .await?;
    send_webxdc_realtime_data(alice, alice_webxdc.id, b"ignored".to_vec()).await?;
    assert!(
        send_webxdc_realtime_advertisement(alice, alice_webxdc.id)
            .await?
            .is_none()
    );
    assert!(alice.iroh.read().await.is_some());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_can_communicate() {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;
    let bob = &mut tcm.bob().await;

    // Alice sends webxdc to bob
    let alice_chat = alice.create_chat(bob).await;
    let mut instance = Message::new(Viewtype::File);
    instance
        .set_file_from_bytes(
            alice,
            "minimal.xdc",
            include_bytes!("../../test-data/webxdc/minimal.xdc"),
            None,
        )
        .unwrap();

    send_msg(alice, alice_chat.id, &mut instance).await.unwrap();
    let alice_webxdc = alice.get_last_msg().await;
    assert_eq!(alice_webxdc.get_viewtype(), Viewtype::Webxdc);

    let webxdc = alice.pop_sent_msg().await;
    let bob_webxdc = bob.recv_msg(&webxdc).await;
    assert_eq!(bob_webxdc.get_viewtype(), Viewtype::Webxdc);

    bob_webxdc.chat_id.accept(bob).await.unwrap();

    // Alice advertises herself.
    send_webxdc_realtime_advertisement(alice, alice_webxdc.id)
        .await
        .unwrap();

    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;
    loop {
        let event = bob.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeAdvertisementReceived { msg_id } = event.typ {
            assert!(msg_id == bob_webxdc.id);
            break;
        }
    }

    // Bob adds alice to gossip peers.
    let members = get_iroh_gossip_peers(bob, bob_webxdc.id)
        .await
        .unwrap()
        .into_iter()
        .map(|addr| addr.node_id)
        .collect::<Vec<_>>();

    assert_eq!(
        members,
        vec![
            alice
                .get_active_or_init_iroh()
                .await
                .unwrap()
                .get_relay_node_addr()
                .unwrap()
                .node_id
        ]
    );

    bob.get_active_or_init_iroh()
        .await
        .unwrap()
        .join_and_subscribe_gossip(bob, bob_webxdc.id)
        .await
        .unwrap()
        .unwrap()
        .await
        .unwrap();

    // Alice sends ephemeral message
    alice
        .get_active_or_init_iroh()
        .await
        .unwrap()
        .send_webxdc_realtime_data(alice, alice_webxdc.id, "alice -> bob".as_bytes().to_vec())
        .await
        .unwrap();

    loop {
        let event = bob.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeData { data, .. } = event.typ {
            if data == "alice -> bob".as_bytes() {
                break;
            } else {
                panic!(
                    "Unexpected status update: {}",
                    String::from_utf8_lossy(&data)
                );
            }
        }
    }
    // Bob sends ephemeral message
    bob.get_active_or_init_iroh()
        .await
        .unwrap()
        .send_webxdc_realtime_data(bob, bob_webxdc.id, "bob -> alice".as_bytes().to_vec())
        .await
        .unwrap();

    loop {
        let event = alice.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeData { data, .. } = event.typ {
            if data == "bob -> alice".as_bytes() {
                break;
            } else {
                panic!(
                    "Unexpected status update: {}",
                    String::from_utf8_lossy(&data)
                );
            }
        }
    }

    // Alice adds bob to gossip peers.
    let members = get_iroh_gossip_peers(alice, alice_webxdc.id)
        .await
        .unwrap()
        .into_iter()
        .map(|addr| addr.node_id)
        .collect::<Vec<_>>();

    assert_eq!(
        members,
        vec![
            bob.get_active_or_init_iroh()
                .await
                .unwrap()
                .get_relay_node_addr()
                .unwrap()
                .node_id
        ]
    );

    bob.get_active_or_init_iroh()
        .await
        .unwrap()
        .send_webxdc_realtime_data(bob, bob_webxdc.id, "bob -> alice 2".as_bytes().to_vec())
        .await
        .unwrap();

    loop {
        let event = alice.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeData { data, .. } = event.typ {
            if data == "bob -> alice 2".as_bytes() {
                break;
            } else {
                panic!(
                    "Unexpected status update: {}",
                    String::from_utf8_lossy(&data)
                );
            }
        }
    }

    // Calling stop_io() closes iroh endpoint as well,
    // even though I/O was not started in this test.
    assert!(alice.iroh.read().await.is_some());
    alice.stop_io().await;
    assert!(alice.iroh.read().await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_duplicated_out_of_order_advertisement() -> Result<()> {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;
    let bob = &mut tcm.bob().await;

    let alice_chat = alice.create_chat(bob).await;
    let mut instance = Message::new(Viewtype::File);
    instance.set_file_from_bytes(
        alice,
        "minimal.xdc",
        include_bytes!("../../test-data/webxdc/minimal.xdc"),
        None,
    )?;

    send_msg(alice, alice_chat.id, &mut instance).await?;
    let alice_webxdc = alice.get_last_msg().await;
    assert_eq!(alice_webxdc.get_viewtype(), Viewtype::Webxdc);

    let webxdc = alice.pop_sent_msg().await;
    // Imagine that at this point Alice learns about Bob's new transport...
    send_webxdc_realtime_advertisement(alice, alice_webxdc.id).await?;
    let advertisement = alice.pop_sent_msg().await;

    // Bob receives an out-of-order advertisement from his new transport.
    receive_imf(bob, advertisement.payload().as_bytes(), false).await?;

    let bob_webxdc = bob.recv_msg(&webxdc).await;
    assert_eq!(bob_webxdc.get_viewtype(), Viewtype::Webxdc);

    bob_webxdc.chat_id.accept(bob).await?;

    bob.recv_msg_trash(&advertisement).await;
    loop {
        let event = bob.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeAdvertisementReceived { msg_id } = event.typ {
            assert!(msg_id == bob_webxdc.id);
            break;
        }
    }
    let members = get_iroh_gossip_peers(bob, bob_webxdc.id)
        .await?
        .into_iter()
        .map(|addr| addr.node_id)
        .collect::<Vec<_>>();
    assert_eq!(
        members,
        vec![
            alice
                .get_active_or_init_iroh()
                .await
                .unwrap()
                .get_relay_node_addr()
                .unwrap()
                .node_id
        ]
    );
    bob.assert_warn("Cannot add iroh peer").await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_can_reconnect() {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;
    let bob = &mut tcm.bob().await;

    assert!(
        alice
            .get_config_bool(Config::WebxdcRealtimeEnabled)
            .await
            .unwrap()
    );
    // Alice sends webxdc to bob
    let alice_chat = alice.create_chat(bob).await;
    let mut instance = Message::new(Viewtype::File);
    instance
        .set_file_from_bytes(
            alice,
            "minimal.xdc",
            include_bytes!("../../test-data/webxdc/minimal.xdc"),
            None,
        )
        .unwrap();

    send_msg(alice, alice_chat.id, &mut instance).await.unwrap();
    let alice_webxdc = alice.get_last_msg().await;
    assert_eq!(alice_webxdc.get_viewtype(), Viewtype::Webxdc);

    let webxdc = alice.pop_sent_msg().await;
    let bob_webxdc = bob.recv_msg(&webxdc).await;
    assert_eq!(bob_webxdc.get_viewtype(), Viewtype::Webxdc);

    bob_webxdc.chat_id.accept(bob).await.unwrap();

    // Alice advertises herself.
    send_webxdc_realtime_advertisement(alice, alice_webxdc.id)
        .await
        .unwrap();

    bob.recv_msg_trash(&alice.pop_sent_msg().await).await;

    // Bob adds alice to gossip peers.
    let members = get_iroh_gossip_peers(bob, bob_webxdc.id)
        .await
        .unwrap()
        .into_iter()
        .map(|addr| addr.node_id)
        .collect::<Vec<_>>();

    assert_eq!(
        members,
        vec![
            alice
                .get_active_or_init_iroh()
                .await
                .unwrap()
                .get_relay_node_addr()
                .unwrap()
                .node_id
        ]
    );

    bob.get_active_or_init_iroh()
        .await
        .unwrap()
        .join_and_subscribe_gossip(bob, bob_webxdc.id)
        .await
        .unwrap()
        .unwrap()
        .await
        .unwrap();

    // Alice sends ephemeral message
    alice
        .get_active_or_init_iroh()
        .await
        .unwrap()
        .send_webxdc_realtime_data(alice, alice_webxdc.id, "alice -> bob".as_bytes().to_vec())
        .await
        .unwrap();

    loop {
        let event = bob.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeData { data, .. } = event.typ {
            if data == "alice -> bob".as_bytes() {
                break;
            } else {
                panic!(
                    "Unexpected status update: {}",
                    String::from_utf8_lossy(&data)
                );
            }
        }
    }

    let bob_topic = get_iroh_topic_for_msg(bob, bob_webxdc.id)
        .await
        .unwrap()
        .unwrap();
    let bob_sequence_number = bob
        .iroh
        .read()
        .await
        .as_ref()
        .unwrap()
        .sequence_numbers
        .lock()
        .get(&bob_topic)
        .copied();
    leave_webxdc_realtime(bob, bob_webxdc.id).await.unwrap();
    let bob_sequence_number_after = bob
        .iroh
        .read()
        .await
        .as_ref()
        .unwrap()
        .sequence_numbers
        .lock()
        .get(&bob_topic)
        .copied();
    // Check that sequence number is persisted when leaving the channel.
    assert_eq!(bob_sequence_number, bob_sequence_number_after);

    bob.get_active_or_init_iroh()
        .await
        .unwrap()
        .join_and_subscribe_gossip(bob, bob_webxdc.id)
        .await
        .unwrap()
        .unwrap()
        .await
        .unwrap();

    bob.get_active_or_init_iroh()
        .await
        .unwrap()
        .send_webxdc_realtime_data(bob, bob_webxdc.id, "bob -> alice".as_bytes().to_vec())
        .await
        .unwrap();

    loop {
        let event = alice.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeData { data, .. } = event.typ {
            if data == "bob -> alice".as_bytes() {
                break;
            } else {
                panic!(
                    "Unexpected status update: {}",
                    String::from_utf8_lossy(&data)
                );
            }
        }
    }

    // channel is only used to remember if an advertisement has been sent
    // bob for example does not change the channels because he never sends an
    // advertisement
    assert_eq!(
        alice
            .iroh
            .read()
            .await
            .as_ref()
            .unwrap()
            .iroh_channels
            .read()
            .await
            .len(),
        1
    );
    leave_webxdc_realtime(alice, alice_webxdc.id).await.unwrap();
    let topic = get_iroh_topic_for_msg(alice, alice_webxdc.id)
        .await
        .unwrap()
        .unwrap();
    assert!(
        alice
            .iroh
            .read()
            .await
            .as_ref()
            .unwrap()
            .iroh_channels
            .read()
            .await
            .get(&topic)
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_parallel_connect() {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;
    let bob = &mut tcm.bob().await;

    let chat = alice.create_chat(bob).await.id;

    let mut instance = Message::new(Viewtype::File);
    instance
        .set_file_from_bytes(
            alice,
            "minimal.xdc",
            include_bytes!("../../test-data/webxdc/minimal.xdc"),
            None,
        )
        .unwrap();
    connect_alice_bob(alice, chat, &mut instance, bob).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_webxdc_resend() {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;
    let bob = &mut tcm.bob().await;
    let group = chat::create_group(alice, "group chat").await.unwrap();

    // Alice sends webxdc to bob
    let mut instance = Message::new(Viewtype::File);
    instance
        .set_file_from_bytes(
            alice,
            "minimal.xdc",
            include_bytes!("../../test-data/webxdc/minimal.xdc"),
            None,
        )
        .unwrap();

    add_contact_to_chat(alice, group, alice.add_or_lookup_contact_id(bob).await)
        .await
        .unwrap();

    connect_alice_bob(alice, group, &mut instance, bob).await;

    // fiona joins late
    let fiona = &mut tcm.fiona().await;

    add_contact_to_chat(alice, group, alice.add_or_lookup_contact_id(fiona).await)
        .await
        .unwrap();

    resend_msgs(alice, &[instance.id]).await.unwrap();
    let msg = alice.pop_sent_msg().await;
    let fiona_instance = fiona.recv_msg(&msg).await;
    fiona_instance.chat_id.accept(fiona).await.unwrap();
    assert!(fiona.ctx.iroh.read().await.is_none());

    let fiona_connect_future = send_webxdc_realtime_advertisement(fiona, fiona_instance.id)
        .await
        .unwrap()
        .unwrap();
    let fiona_advert = fiona.pop_sent_msg().await;
    alice.recv_msg_trash(&fiona_advert).await;

    fiona_connect_future.await.unwrap();

    let realtime_send_loop = async {
        // Keep sending in a loop because right after joining
        // Fiona may miss messages.
        loop {
            send_webxdc_realtime_data(alice, instance.id, b"alice -> bob & fiona".into())
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    };
    fiona.assert_warn("Missing key for bob@example.net").await;
    let realtime_receive_loop = async {
        loop {
            let event = fiona.evtracker.recv().await.unwrap();
            if let EventType::WebxdcRealtimeData { data, .. } = event.typ {
                if data == b"alice -> bob & fiona" {
                    break;
                } else {
                    panic!(
                        "Unexpected status update: {}",
                        String::from_utf8_lossy(&data)
                    );
                }
            }
        }
    };
    tokio::select!(
        _ = realtime_send_loop => {
            panic!("Send loop should never finish");
        },
        _ = realtime_receive_loop => {
            return;
        }
    );
}

async fn connect_alice_bob(
    alice: &mut TestContext,
    alice_chat_id: ChatId,
    instance: &mut Message,
    bob: &mut TestContext,
) {
    send_msg(alice, alice_chat_id, instance).await.unwrap();
    let alice_webxdc = alice.get_last_msg().await;

    let webxdc = alice.pop_sent_msg().await;
    let bob_webxdc = bob.recv_msg(&webxdc).await;
    assert_eq!(bob_webxdc.get_viewtype(), Viewtype::Webxdc);

    bob_webxdc.chat_id.accept(bob).await.unwrap();

    eprintln!("Sending advertisements");
    // Alice advertises herself.
    let alice_advertisement_future = send_webxdc_realtime_advertisement(alice, alice_webxdc.id)
        .await
        .unwrap()
        .unwrap();
    let alice_advertisement = alice.pop_sent_msg().await;

    let bob_advertisement_future = send_webxdc_realtime_advertisement(bob, bob_webxdc.id)
        .await
        .unwrap()
        .unwrap();
    let bob_advertisement = bob.pop_sent_msg().await;

    eprintln!("Receiving advertisements");
    bob.recv_msg_trash(&alice_advertisement).await;
    alice.recv_msg_trash(&bob_advertisement).await;

    eprintln!("Alice and Bob wait for connection");
    alice_advertisement_future.await.unwrap();
    bob_advertisement_future.await.unwrap();

    // Alice sends ephemeral message
    eprintln!("Sending ephemeral message");
    send_webxdc_realtime_data(alice, alice_webxdc.id, b"alice -> bob".into())
        .await
        .unwrap();

    eprintln!("Waiting for ephemeral message");
    loop {
        let event = bob.evtracker.recv().await.unwrap();
        if let EventType::WebxdcRealtimeData { data, .. } = event.typ {
            if data == b"alice -> bob" {
                break;
            } else {
                panic!(
                    "Unexpected status update: {}",
                    String::from_utf8_lossy(&data)
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_peer_channels_disabled() {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;

    alice
        .set_config_bool(Config::WebxdcRealtimeEnabled, false)
        .await
        .unwrap();

    // creates iroh endpoint as side effect
    send_webxdc_realtime_advertisement(alice, MsgId::new(1))
        .await
        .unwrap();

    assert!(alice.ctx.iroh.read().await.is_none());

    // creates iroh endpoint as side effect
    send_webxdc_realtime_data(alice, MsgId::new(1), vec![])
        .await
        .unwrap();

    assert!(alice.ctx.iroh.read().await.is_none());

    leave_webxdc_realtime(alice, MsgId::new(1)).await.unwrap();

    assert!(alice.ctx.iroh.read().await.is_none());

    // This internal function should return error
    // if accidentally called with the setting disabled.
    assert!(alice.ctx.get_active_or_init_iroh().await.is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_leave_webxdc_realtime_uninitialized() {
    let mut tcm = TestContextManager::new();
    let alice = &mut tcm.alice().await;

    alice
        .set_config_bool(Config::WebxdcRealtimeEnabled, true)
        .await
        .unwrap();

    assert!(alice.ctx.iroh.read().await.is_none());
    leave_webxdc_realtime(alice, MsgId::new(1)).await.unwrap();
    assert!(alice.ctx.iroh.read().await.is_none());
}
