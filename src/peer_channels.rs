//! Peer channels for realtime communication in webxdcs.
//!
//! We use Iroh as an ephemeral peer channels provider to create direct communication
//! channels between webxdcs. See [here](https://webxdc.org/docs/spec/joinRealtimeChannel.html) for the webxdc specs.
//!
//! Ephemeral channels should be established lazily, to avoid bootstrapping p2p connectivity
//! when it's not required. Only when a webxdc subscribes to realtime data or when a reatlime message is sent,
//! the p2p machinery should be started.
//!
//! Adding peer channels to webxdc needs upfront negotiation of a topic and sharing of public keys so that
//! nodes can connect to each other. The explicit approach is as follows:
//!
//! 1. We introduce a new [`IrohGossipTopic`](crate::headerdef::HeaderDef::IrohGossipTopic) message header with a random 32-byte TopicId,
//!    securely generated on the initial webxdc sender's device. This message header is encrypted
//!    and sent in the same message as the webxdc application.
//! 2. Whenever `joinRealtimeChannel().setListener()` or `joinRealtimeChannel().send()` is called by the webxdc application,
//!    we start a routine to establish p2p connectivity and join the gossip swarm with Iroh.
//! 3. The first step of this routine is to introduce yourself with a regular message containing the [`IrohNodeAddr`](crate::headerdef::HeaderDef::IrohNodeAddr).
//!    This message contains the users relay-server and public key.
//!    Direct IP address is not included as this information can be persisted by email providers.
//! 4. After the announcement, the sending peer joins the gossip swarm with an empty list of peer IDs (as they don't know anyone yet).
//! 5. Upon receiving an announcement message, other peers store the sender's [NodeAddr] in the database
//!    (scoped per WebXDC app instance/message-id). The other peers can then join the gossip with `joinRealtimeChannel().setListener()`
//!    and `joinRealtimeChannel().send()` just like the other peers.

use anyhow::{Context as _, Result, anyhow, bail, ensure};
use data_encoding::BASE32_NOPAD;
use futures_lite::StreamExt;
use iroh::{Endpoint, NodeAddr, NodeId, PublicKey, RelayMode, RelayUrl, SecretKey};
use iroh_gossip::net::{Event, GOSSIP_ALPN, Gossip, GossipEvent, JoinOptions};
use iroh_gossip::proto::TopicId;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{RwLock, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use url::Url;

use crate::EventType;
use crate::chat::send_msg;
use crate::config::Config;
use crate::context::Context;
use crate::log::{LogExt, warn};
use crate::message::{Message, MsgId, Viewtype};
use crate::mimeparser::SystemMessage;
use crate::net::http::probe_iroh_url;
use crate::net::run_connection_attempts;
use crate::transport::published_transports;

/// The length of an ed25519 `PublicKey`, in bytes.
const PUBLIC_KEY_LENGTH: usize = 32;
const PUBLIC_KEY_STUB: &[u8] = "static_string".as_bytes();

/// Timeout for probing an iroh relay candidate.
const RELAY_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Store Iroh peer channels for the context.
#[derive(Debug)]
pub struct Iroh {
    /// Iroh router  needed for Iroh peer channels.
    pub(crate) router: iroh::protocol::Router,

    /// [Gossip] needed for Iroh peer channels.
    pub(crate) gossip: Gossip,

    /// Sequence numbers for gossip channels.
    pub(crate) sequence_numbers: Mutex<HashMap<TopicId, i32>>,

    /// Topics for which an advertisement has already been sent.
    pub(crate) iroh_channels: RwLock<HashMap<TopicId, ChannelState>>,

    /// Currently used Iroh public key.
    ///
    /// This is attached to every message to work around `iroh_gossip` deduplication.
    pub(crate) public_key: PublicKey,

    /// Home relay URL probed successfully when Iroh was created.
    working_relay_url: Option<RelayUrl>,
}

impl Iroh {
    /// Notify the endpoint that the network has changed.
    pub(crate) async fn network_change(&self) {
        self.router.endpoint().network_change().await
    }

    /// Closes the QUIC endpoint.
    pub(crate) async fn close(&self) -> Result<()> {
        self.router.shutdown().await.context("Closing iroh failed")
    }

    /// Join a topic and create the subscriber loop for it.
    ///
    /// If there is no gossip, create it.
    ///
    /// The returned future resolves when the swarm becomes operational.
    async fn join_and_subscribe_gossip(
        &self,
        ctx: &Context,
        msg_id: MsgId,
    ) -> Result<Option<oneshot::Receiver<()>>> {
        let topic = get_iroh_topic_for_msg(ctx, msg_id)
            .await?
            .with_context(|| format!("Message {msg_id} has no gossip topic"))?;

        // Take exclusive lock to make sure
        // no other thread can create a second gossip subscription
        // after we check that it does not exist and before we create a new one.
        // Otherwise we would receive every message twice or more times.
        let mut iroh_channels = self.iroh_channels.write().await;
        ensure!(
            !ctx.left_topics.lock().contains(&topic),
            "Realtime channel for {msg_id} was left"
        );

        if iroh_channels.contains_key(&topic) {
            return Ok(None);
        }

        let peers = get_iroh_gossip_peers(ctx, msg_id).await?;
        let node_ids = peers.iter().map(|p| p.node_id).collect::<Vec<_>>();

        info!(
            ctx,
            "IROH_REALTIME: Joining gossip {topic} with peers: {:?}.", node_ids,
        );

        // Inform iroh of potentially new node addresses
        for node_addr in &peers {
            if !node_addr.is_empty() {
                self.router.endpoint().add_node_addr(node_addr.clone())?;
            }
        }

        let (join_tx, join_rx) = oneshot::channel();

        let (gossip_sender, gossip_receiver) = self
            .gossip
            .subscribe_with_opts(topic, JoinOptions::with_bootstrap(node_ids))
            .split();

        let ctx = ctx.clone();
        let subscribe_loop = tokio::spawn(async move {
            if let Err(e) = subscribe_loop(&ctx, gossip_receiver, topic, msg_id, join_tx).await {
                warn!(ctx, "subscribe_loop failed: {e}")
            }
        });

        iroh_channels.insert(topic, ChannelState::new(subscribe_loop, gossip_sender));

        Ok(Some(join_rx))
    }

    /// Add gossip peer to realtime channel if it is already active.
    pub async fn maybe_add_gossip_peer(&self, topic: TopicId, peer: NodeAddr) -> Result<()> {
        if self.iroh_channels.read().await.get(&topic).is_some() {
            self.router.endpoint().add_node_addr(peer.clone())?;
            self.gossip.subscribe(topic, vec![peer.node_id])?;
        }
        Ok(())
    }

    /// Send realtime data to the gossip swarm.
    pub async fn send_webxdc_realtime_data(
        &self,
        ctx: &Context,
        msg_id: MsgId,
        mut data: Vec<u8>,
    ) -> Result<()> {
        let topic = get_iroh_topic_for_msg(ctx, msg_id)
            .await?
            .with_context(|| format!("Message {msg_id} has no gossip topic"))?;
        self.join_and_subscribe_gossip(ctx, msg_id).await?;

        let seq_num = self.get_and_incr(&topic);

        let mut iroh_channels = self.iroh_channels.write().await;
        let state = iroh_channels
            .get_mut(&topic)
            .context("Just created state does not exist")?;
        data.extend(seq_num.to_le_bytes());
        data.extend(self.public_key.as_bytes());

        state.sender.broadcast(data.into()).await?;

        if env::var("REALTIME_DEBUG").is_ok() {
            info!(ctx, "Sent realtime data");
        }

        Ok(())
    }

    fn get_and_incr(&self, topic: &TopicId) -> i32 {
        let mut sequence_numbers = self.sequence_numbers.lock();
        let entry = sequence_numbers.entry(*topic).or_default();
        *entry = entry.wrapping_add(1);
        *entry
    }

    /// Returns the iroh [NodeAddr] with the working relay URL
    /// and without direct IP addresses.
    pub(crate) fn get_relay_node_addr(&self) -> Result<NodeAddr> {
        let relay_url = self
            .working_relay_url
            .clone()
            .context("No working iroh relay, peers cannot reach us")?;
        Ok(NodeAddr::new(self.public_key).with_relay_url(relay_url))
    }

    /// Leave the realtime channel for a given topic.
    pub(crate) async fn leave_realtime(&self, topic: TopicId) -> Result<()> {
        if let Some(channel) = self.iroh_channels.write().await.remove(&topic) {
            // Dropping the last GossipTopic results in quitting the topic.
            // It is split into GossipReceiver and GossipSender.
            // GossipSender (`channel.sender`) is dropped automatically.

            // Subscribe loop owns GossipReceiver.
            // Aborting it and waiting for it to be dropped
            // drops the receiver.
            channel.subscribe_loop.abort();
            let _ = channel.subscribe_loop.await;
        }
        Ok(())
    }
}

/// Single gossip channel state.
#[derive(Debug)]
pub(crate) struct ChannelState {
    /// The subscribe loop handle.
    subscribe_loop: JoinHandle<()>,

    sender: iroh_gossip::net::GossipSender,
}

impl ChannelState {
    fn new(subscribe_loop: JoinHandle<()>, sender: iroh_gossip::net::GossipSender) -> Self {
        Self {
            subscribe_loop,
            sender,
        }
    }
}

/// Returns the URL to probe for the given iroh relay.
///
/// The probe path is appended to any path of the relay URL
/// so that relays served under a path prefix can be probed too.
fn relay_probe_url(relay_url: &Url) -> Result<Url> {
    let mut probe_url = relay_url.clone();
    probe_url
        .path_segments_mut()
        .map_err(|()| anyhow!("Relay URL {relay_url} cannot be a base"))?
        .pop_if_empty()
        .push("generate_204");
    Ok(probe_url)
}

/// Selects a working iroh relay among the candidates.
async fn select_iroh_relay(context: &Context, candidates: &[Url]) -> Result<Url> {
    let probes = candidates.iter().cloned().map(|candidate| {
        let context = context.clone();
        async move {
            let probe_target = relay_probe_url(&candidate)?;
            timeout(
                RELAY_PROBE_TIMEOUT,
                probe_iroh_url(&context, probe_target.as_str()),
            )
            .await
            .with_context(|| format!("Timeout probing iroh relay {candidate}"))?
            .with_context(|| format!("Failed to probe iroh relay {candidate}"))?;
            Ok(candidate)
        }
    });
    let selected = run_connection_attempts(probes).await?;
    info!(context, "Selected iroh relay {selected}.");
    Ok(selected)
}

/// Returns the deduplicated iroh relay URLs announced by the published transports.
async fn published_iroh_relays(context: &Context) -> Result<Vec<Url>> {
    let published = published_transports(context).await?;
    let metadata = context.metadata.read().await;
    let mut relays: Vec<Url> = Vec::new();
    for (_, transport_id) in published {
        if let Some(url) = metadata
            .get(&transport_id)
            .and_then(|conf| conf.iroh_relay.clone())
            && !relays.contains(&url)
        {
            relays.push(url);
        }
    }
    Ok(relays)
}

impl Context {
    /// Creates the iroh endpoint, gossip and router.
    ///
    /// Iroh is created even in the rare case
    /// that no relay candidate works;
    /// peers cannot reach us then,
    /// but we can still dial out through their relays.
    async fn init_iroh(&self) -> Result<Iroh> {
        if !self.get_config_bool(Config::WebxdcRealtimeEnabled).await? {
            bail!("Attempt to initialize Iroh when realtime is disabled");
        }
        info!(self, "Initializing Iroh for realtime channels.");
        let relay_candidates = published_iroh_relays(self).await?;
        let working_relay_url = if relay_candidates.is_empty() {
            warn!(self, "No iroh relay, peers cannot reach us.");
            None
        } else {
            select_iroh_relay(self, &relay_candidates)
                .await
                .context("No working iroh relay")
                .log_err(self)
                .ok()
                .map(RelayUrl::from)
        };
        let relay_mode = match &working_relay_url {
            Some(relay_url) => RelayMode::Custom(relay_url.clone().into()),
            None => RelayMode::Disabled,
        };
        let secret_key = SecretKey::generate(rand_old::rngs::OsRng);
        let public_key = secret_key.public();
        let endpoint = Box::pin(
            Endpoint::builder()
                .tls_x509() // For compatibility with iroh <0.34.0
                .secret_key(secret_key)
                .alpns(vec![GOSSIP_ALPN.to_vec()])
                .relay_mode(relay_mode)
                .bind(),
        )
        .await?;

        // create gossip
        // Allow messages up to 128 KB in size.
        // We set the limit to 128 KiB to account for internal overhead,
        // but only guarantee 128 KB of payload to WebXDC developers.

        let gossip = Gossip::builder()
            .max_message_size(128 * 1024)
            .spawn(endpoint.clone())
            .await?;

        let router = iroh::protocol::Router::builder(endpoint)
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn();

        Ok(Iroh {
            router,
            gossip,
            sequence_numbers: Mutex::new(HashMap::new()),
            iroh_channels: RwLock::new(HashMap::new()),
            public_key,
            working_relay_url,
        })
    }

    /// Returns iroh while it has a working relay
    /// or channels through which peers may have been dialed.
    async fn get_active_iroh(&self) -> Option<Arc<Iroh>> {
        let iroh = self.iroh.read().await.clone()?;
        if iroh.working_relay_url.is_some() || !iroh.iroh_channels.read().await.is_empty() {
            Some(iroh)
        } else {
            None
        }
    }

    /// Returns active iroh, initializing it if necessary.
    ///
    /// Concurrent calls are serialized, and a call racing [`Context::stop_io`] fails
    /// rather than leaving iroh running after the stop.
    /// Inactive iroh is replaced, probing the relay candidates again.
    pub(crate) async fn get_active_or_init_iroh(&self) -> Result<Arc<Iroh>> {
        if let Some(iroh) = self.get_active_iroh().await {
            return Ok(iroh);
        }

        let io_stop_count = self.io_stop_count.load(Ordering::Relaxed);
        let _guard = self.iroh_init_mutex.lock().await;

        if let Some(iroh) = self.get_active_iroh().await {
            return Ok(iroh);
        }
        if self.io_stop_count.load(Ordering::Relaxed) != io_stop_count {
            bail!("Io was stopped");
        }

        // Close the inactive instance to probe the relay candidates anew,
        // unless a concurrent task still uses it; share it with them then.
        if let Some(iroh) = self.close_unused_iroh().await {
            return Ok(iroh);
        }

        let iroh = Arc::new(self.init_iroh().await?);
        *self.iroh.write().await = Some(iroh.clone());
        Ok(iroh)
    }

    /// Closes iroh if no channel and no concurrent task uses it,
    /// so that it stops using the network until realtime is used again.
    /// Returns the instance kept because it is still in use, if any.
    ///
    /// The next use initializes iroh again and probes the relay candidates,
    /// so a relay that stopped working meanwhile is not used again.
    pub(crate) async fn close_unused_iroh(&self) -> Option<Arc<Iroh>> {
        let mut slot = self.iroh.write().await;
        let iroh = slot.take()?;
        // A reference besides ours means somebody is about to use iroh.
        if Arc::strong_count(&iroh) > 1 || !iroh.iroh_channels.read().await.is_empty() {
            *slot = Some(iroh.clone());
            return Some(iroh);
        }
        drop(slot);

        info!(self, "Closing iroh, no realtime channel uses it.");
        iroh.close().await.log_err(self).ok();
        None
    }

    pub(crate) async fn maybe_add_gossip_peer(&self, topic: TopicId, peer: NodeAddr) -> Result<()> {
        if let Some(iroh) = self.get_active_iroh().await {
            info!(
                self,
                "Adding (maybe existing) peer with id {} to {topic}.", peer.node_id
            );
            iroh.maybe_add_gossip_peer(topic, peer).await?;
        }
        Ok(())
    }
}

/// Cache a peers [NodeId] for one topic.
pub(crate) async fn iroh_add_peer_for_topic(
    ctx: &Context,
    msg_id: MsgId,
    topic: TopicId,
    peer: NodeId,
    relay_server: Option<&str>,
) -> Result<()> {
    ctx.sql
        .execute(
            "INSERT OR REPLACE INTO iroh_gossip_peers (msg_id, public_key, topic, relay_server) VALUES (?, ?, ?, ?)",
            (msg_id, peer.as_bytes(), topic.as_bytes(), relay_server),
        )
        .await?;
    Ok(())
}

/// Add gossip peer from `Iroh-Node-Addr` header to WebXDC message identified by `instance_id`.
pub async fn add_gossip_peer_from_header(
    context: &Context,
    instance_id: MsgId,
    node_addr: &str,
) -> Result<()> {
    if !context
        .get_config_bool(Config::WebxdcRealtimeEnabled)
        .await?
    {
        return Ok(());
    }

    let node_addr =
        serde_json::from_str::<NodeAddr>(node_addr).context("Failed to parse node address")?;

    info!(
        context,
        "Adding iroh peer with node id {} to the topic of {instance_id}.", node_addr.node_id
    );

    context.emit_event(EventType::WebxdcRealtimeAdvertisementReceived {
        msg_id: instance_id,
    });

    let Some(topic) = get_iroh_topic_for_msg(context, instance_id).await? else {
        warn!(
            context,
            "Could not add iroh peer because {instance_id} has no topic."
        );
        return Ok(());
    };

    let node_id = node_addr.node_id;
    let relay_server = node_addr.relay_url().map(|relay| relay.as_str());
    iroh_add_peer_for_topic(context, instance_id, topic, node_id, relay_server).await?;

    context.maybe_add_gossip_peer(topic, node_addr).await?;
    Ok(())
}

/// Insert topicId into the database so that we can use it to retrieve the topic.
pub(crate) async fn insert_topic_stub(ctx: &Context, msg_id: MsgId, topic: TopicId) -> Result<()> {
    ctx.sql
        .execute(
            "INSERT OR REPLACE INTO iroh_gossip_peers (msg_id, public_key, topic, relay_server) VALUES (?, ?, ?, ?)",
            (msg_id, PUBLIC_KEY_STUB, topic.as_bytes(), Option::<&str>::None),
        )
        .await?;
    Ok(())
}

/// Get a list of [NodeAddr]s for one webxdc.
async fn get_iroh_gossip_peers(ctx: &Context, msg_id: MsgId) -> Result<Vec<NodeAddr>> {
    ctx.sql
        .query_map(
            "SELECT public_key, relay_server FROM iroh_gossip_peers WHERE msg_id = ? AND public_key != ?",
            (msg_id, PUBLIC_KEY_STUB),
            |row| {
                let key:  Vec<u8> = row.get(0)?;
                let server: Option<String> = row.get(1)?;
                Ok((key, server))
            },
            |g| {
                g.map(|data| {
                    let (key, server) = data?;
                    let server = server.map(|data| Ok::<_, url::ParseError>(RelayUrl::from(Url::parse(&data)?))).transpose()?;
                    let id = NodeId::from_bytes(&key.try_into()
                    .map_err(|_| anyhow!("Can't convert sql data to [u8; 32]"))?)?;
                    Ok::<_, anyhow::Error>(NodeAddr::from_parts(
                        id, server, vec![]
                    ))
                })
                .collect::<std::result::Result<Vec<_>, _>>()
            },
        )
        .await
}

/// Get the topic for a given [MsgId].
pub(crate) async fn get_iroh_topic_for_msg(
    ctx: &Context,
    msg_id: MsgId,
) -> Result<Option<TopicId>> {
    if let Some(bytes) = ctx
        .sql
        .query_get_value::<Vec<u8>>(
            "SELECT topic FROM iroh_gossip_peers WHERE msg_id = ? LIMIT 1",
            (msg_id,),
        )
        .await
        .context("Couldn't restore topic from db")?
    {
        let topic_id = TopicId::from_bytes(
            bytes
                .try_into()
                .map_err(|_| anyhow!("Could not convert stored topic ID"))?,
        );
        Ok(Some(topic_id))
    } else {
        Ok(None)
    }
}

/// Send a gossip advertisement to the chat that [MsgId] belongs to.
/// This method should be called from the frontend when `joinRealtimeChannel` is called.
///
/// The channel is joined even without a working relay,
/// but no advertisement is sent then
/// because peers could not reach us anyway.
pub async fn send_webxdc_realtime_advertisement(
    ctx: &Context,
    msg_id: MsgId,
) -> Result<Option<oneshot::Receiver<()>>> {
    if !ctx.get_config_bool(Config::WebxdcRealtimeEnabled).await? {
        return Ok(None);
    }

    if let Some(topic) = get_iroh_topic_for_msg(ctx, msg_id).await? {
        ctx.left_topics.lock().remove(&topic);
    }
    let iroh = ctx.get_active_or_init_iroh().await?;
    let conn = iroh.join_and_subscribe_gossip(ctx, msg_id).await?;
    if iroh.working_relay_url.is_none() {
        warn!(ctx, "Not sending realtime advertisement without a relay.");
        return Ok(conn);
    }

    let webxdc = Message::load_from_db(ctx, msg_id).await?;
    let mut msg = Message::new(Viewtype::Text);
    msg.hidden = true;
    msg.param.set_cmd(SystemMessage::IrohNodeAddr);
    msg.in_reply_to = Some(webxdc.rfc724_mid.clone());
    send_msg(ctx, webxdc.chat_id, &mut msg).await?;
    info!(ctx, "IROH_REALTIME: Sent realtime advertisement");
    Ok(conn)
}

/// Send realtime data to other peers using iroh.
///
/// This works even without a working relay of our own
/// because joined peers are dialed through their advertised relays.
pub async fn send_webxdc_realtime_data(ctx: &Context, msg_id: MsgId, data: Vec<u8>) -> Result<()> {
    if !ctx.get_config_bool(Config::WebxdcRealtimeEnabled).await? {
        return Ok(());
    }

    let iroh = ctx.get_active_or_init_iroh().await?;
    iroh.send_webxdc_realtime_data(ctx, msg_id, data).await?;
    Ok(())
}

/// Leave the gossip of the webxdc with given [MsgId].
///
/// NB: When this is called before closing a webxdc app in UIs, it must be guaranteed that
/// `send_webxdc_realtime_*()` functions aren't called for the given `msg_id` anymore until the app
/// is open again.
pub async fn leave_webxdc_realtime(ctx: &Context, msg_id: MsgId) -> Result<()> {
    let Some(topic) = get_iroh_topic_for_msg(ctx, msg_id).await? else {
        return Ok(());
    };
    ctx.left_topics.lock().insert(topic);
    let Some(iroh) = ctx.get_active_iroh().await else {
        return Ok(());
    };
    iroh.leave_realtime(topic).await?;
    info!(ctx, "IROH_REALTIME: Left gossip for message {msg_id}");

    Ok(())
}

/// Creates a new random gossip topic.
fn create_random_topic() -> TopicId {
    TopicId::from_bytes(rand::random())
}

/// Creates `Iroh-Gossip-Header` with a new random topic
/// and stores the topic for the message.
pub(crate) async fn create_iroh_header(ctx: &Context, msg_id: MsgId) -> Result<String> {
    let topic = create_random_topic();
    insert_topic_stub(ctx, msg_id, topic).await?;
    let topic_string = BASE32_NOPAD.encode(topic.as_bytes()).to_ascii_lowercase();
    Ok(topic_string)
}

/// Converts `Iroh-Gossip-Header` contents to iroh topic ID.
pub(crate) fn iroh_topic_from_str(topic: &str) -> Result<TopicId> {
    let mut topic_raw = [0u8; 32];
    BASE32_NOPAD
        .decode_mut(topic.to_ascii_uppercase().as_bytes(), &mut topic_raw)
        .map_err(|e| e.error)
        .context("Wrong gossip topic header")?;

    let topic = TopicId::from_bytes(topic_raw);
    Ok(topic)
}

#[expect(clippy::arithmetic_side_effects)]
async fn subscribe_loop(
    context: &Context,
    mut stream: iroh_gossip::net::GossipReceiver,
    topic: TopicId,
    msg_id: MsgId,
    join_tx: oneshot::Sender<()>,
) -> Result<()> {
    let mut join_tx = Some(join_tx);

    while let Some(event) = stream.try_next().await? {
        match event {
            Event::Gossip(event) => match event {
                GossipEvent::Joined(nodes) => {
                    if let Some(join_tx) = join_tx.take() {
                        // Try to notify that at least one peer joined,
                        // but ignore the error if receiver is dropped and nobody listens.
                        join_tx.send(()).ok();
                    }

                    for node in nodes {
                        iroh_add_peer_for_topic(context, msg_id, topic, node, None).await?;
                    }
                }
                GossipEvent::NeighborUp(node) => {
                    info!(context, "IROH_REALTIME: NeighborUp: {}", node.to_string());
                    iroh_add_peer_for_topic(context, msg_id, topic, node, None).await?;
                }
                GossipEvent::NeighborDown(_node) => {}
                GossipEvent::Received(message) => {
                    info!(context, "IROH_REALTIME: Received realtime data");
                    context.emit_event(EventType::WebxdcRealtimeData {
                        msg_id,
                        data: message
                            .content
                            .get(0..message.content.len() - 4 - PUBLIC_KEY_LENGTH)
                            .context("too few bytes in iroh message")?
                            .into(),
                    });
                }
            },
            Event::Lagged => {
                warn!(context, "Gossip lost some messages");
            }
        };
    }
    Ok(())
}

#[cfg(test)]
mod peer_channels_tests;
