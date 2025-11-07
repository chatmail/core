use std::cmp;
use std::iter::{self, once};
use std::num::NonZeroUsize;

use anyhow::{Context as _, Error, Result, bail};
use async_channel::{self as channel, Receiver, Sender};
use futures::future::try_join_all;
use futures_lite::FutureExt;
use tokio::sync::{RwLock, oneshot};
use tokio::task;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

pub(crate) use self::connectivity::ConnectivityStore;
use crate::config::{self, Config};
use crate::contact::{ContactId, RecentlySeenLoop};
use crate::context::Context;
use crate::download::{DownloadState, download_msg};
use crate::ephemeral::{self, delete_expired_imap_messages};
use crate::events::EventType;
use crate::imap::{FolderMeaning, Imap, session::Session};
use crate::location;
use crate::log::{LogExt, warn};
use crate::message::MsgId;
use crate::smtp::{Smtp, send_smtp_messages};
use crate::sql;
use crate::stats::maybe_send_stats;
use crate::tools::{self, duration_to_str, maybe_add_time_based_warnings, time, time_elapsed};
use crate::{constants, stats};

pub(crate) mod connectivity;

/// State of the IO scheduler, as stored on the [`Context`].
///
/// The IO scheduler can be stopped or started, but core can also pause it.  After pausing
/// the IO scheduler will be restarted only if it was running before paused or
/// [`Context::start_io`] was called in the meantime while it was paused.
#[derive(Debug, Default)]
pub(crate) struct SchedulerState {
    inner: RwLock<InnerSchedulerState>,
}

impl SchedulerState {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    /// Whether the scheduler is currently running.
    pub(crate) async fn is_running(&self) -> bool {
        let inner = self.inner.read().await;
        matches!(*inner, InnerSchedulerState::Started(_))
    }

    /// Starts the scheduler if it is not yet started.
    pub(crate) async fn start(&self, context: &Context) {
        let mut inner = self.inner.write().await;
        match *inner {
            InnerSchedulerState::Started(_) => (),
            InnerSchedulerState::Stopped => Self::do_start(&mut inner, context).await,
            InnerSchedulerState::Paused {
                ref mut started, ..
            } => *started = true,
        }
        context.update_connectivities(&inner);
    }

    /// Starts the scheduler if it is not yet started.
    async fn do_start(inner: &mut InnerSchedulerState, context: &Context) {
        info!(context, "starting IO");

        // Notify message processing loop
        // to allow processing old messages after restart.
        context.new_msgs_notify.notify_one();

        match Scheduler::start(context).await {
            Ok(scheduler) => {
                *inner = InnerSchedulerState::Started(scheduler);
                context.emit_event(EventType::ConnectivityChanged);
            }
            Err(err) => error!(context, "Failed to start IO: {:#}", err),
        }
    }

    /// Stops the scheduler if it is currently running.
    pub(crate) async fn stop(&self, context: &Context) {
        let mut inner = self.inner.write().await;
        match *inner {
            InnerSchedulerState::Started(_) => {
                Self::do_stop(&mut inner, context, InnerSchedulerState::Stopped).await
            }
            InnerSchedulerState::Stopped => (),
            InnerSchedulerState::Paused {
                ref mut started, ..
            } => *started = false,
        }
        context.update_connectivities(&inner);
    }

    /// Stops the scheduler if it is currently running.
    async fn do_stop(
        inner: &mut InnerSchedulerState,
        context: &Context,
        new_state: InnerSchedulerState,
    ) {
        // Sending an event wakes up event pollers (get_next_event)
        // so the caller of stop_io() can arrange for proper termination.
        // For this, the caller needs to instruct the event poller
        // to terminate on receiving the next event and then call stop_io()
        // which will emit the below event(s)
        info!(context, "stopping IO");

        // Wake up message processing loop even if there are no messages
        // to allow for clean shutdown.
        context.new_msgs_notify.notify_one();

        let debug_logging = context
            .debug_logging
            .write()
            .expect("RwLock is poisoned")
            .take();
        if let Some(debug_logging) = debug_logging {
            debug_logging.loop_handle.abort();
            debug_logging.loop_handle.await.ok();
        }
        let prev_state = std::mem::replace(inner, new_state);
        context.emit_event(EventType::ConnectivityChanged);
        match prev_state {
            InnerSchedulerState::Started(scheduler) => scheduler.stop(context).await,
            InnerSchedulerState::Stopped | InnerSchedulerState::Paused { .. } => (),
        }
    }

    /// Pauses the IO scheduler.
    ///
    /// If it is currently running the scheduler will be stopped.  When the
    /// [`IoPausedGuard`] is dropped the scheduler is started again.
    ///
    /// If in the meantime [`SchedulerState::start`] or [`SchedulerState::stop`] is called
    /// resume will do the right thing and restore the scheduler to the state requested by
    /// the last call.
    pub(crate) async fn pause(&'_ self, context: &Context) -> Result<IoPausedGuard> {
        {
            let mut inner = self.inner.write().await;
            match *inner {
                InnerSchedulerState::Started(_) => {
                    let new_state = InnerSchedulerState::Paused {
                        started: true,
                        pause_guards_count: NonZeroUsize::new(1).unwrap(),
                    };
                    Self::do_stop(&mut inner, context, new_state).await;
                }
                InnerSchedulerState::Stopped => {
                    *inner = InnerSchedulerState::Paused {
                        started: false,
                        pause_guards_count: NonZeroUsize::new(1).unwrap(),
                    };
                }
                InnerSchedulerState::Paused {
                    ref mut pause_guards_count,
                    ..
                } => {
                    *pause_guards_count = pause_guards_count
                        .checked_add(1)
                        .ok_or_else(|| Error::msg("Too many pause guards active"))?
                }
            }
            context.update_connectivities(&inner);
        }

        let (tx, rx) = oneshot::channel();
        let context = context.clone();
        tokio::spawn(async move {
            rx.await.ok();
            let mut inner = context.scheduler.inner.write().await;
            match *inner {
                InnerSchedulerState::Started(_) => {
                    warn!(&context, "IoPausedGuard resume: started instead of paused");
                }
                InnerSchedulerState::Stopped => {
                    warn!(&context, "IoPausedGuard resume: stopped instead of paused");
                }
                InnerSchedulerState::Paused {
                    ref started,
                    ref mut pause_guards_count,
                } => {
                    if *pause_guards_count == NonZeroUsize::new(1).unwrap() {
                        match *started {
                            true => SchedulerState::do_start(&mut inner, &context).await,
                            false => *inner = InnerSchedulerState::Stopped,
                        }
                    } else {
                        let new_count = pause_guards_count.get() - 1;
                        // SAFETY: Value was >=2 before due to if condition
                        *pause_guards_count = NonZeroUsize::new(new_count).unwrap();
                    }
                }
            }
            context.update_connectivities(&inner);
        });
        Ok(IoPausedGuard { sender: Some(tx) })
    }

    /// Restarts the scheduler, only if it is running.
    pub(crate) async fn restart(&self, context: &Context) {
        info!(context, "restarting IO");
        if self.is_running().await {
            self.stop(context).await;
            self.start(context).await;
        }
    }

    /// Indicate that the network likely has come back.
    pub(crate) async fn maybe_network(&self) {
        let inner = self.inner.read().await;
        let (inbox, oboxes) = match *inner {
            InnerSchedulerState::Started(ref scheduler) => {
                scheduler.maybe_network();
                let inbox = scheduler.inbox.conn_state.state.connectivity.clone();
                let oboxes = scheduler
                    .oboxes
                    .iter()
                    .map(|b| b.conn_state.state.connectivity.clone())
                    .collect::<Vec<_>>();
                (inbox, oboxes)
            }
            _ => return,
        };
        drop(inner);
        connectivity::idle_interrupted(inbox, oboxes);
    }

    /// Indicate that the network likely is lost.
    pub(crate) async fn maybe_network_lost(&self, context: &Context) {
        let inner = self.inner.read().await;
        let stores = match *inner {
            InnerSchedulerState::Started(ref scheduler) => {
                scheduler.maybe_network_lost();
                scheduler
                    .boxes()
                    .map(|b| b.conn_state.state.connectivity.clone())
                    .collect()
            }
            _ => return,
        };
        drop(inner);
        connectivity::maybe_network_lost(context, stores);
    }

    pub(crate) async fn interrupt_inbox(&self) {
        let inner = self.inner.read().await;
        if let InnerSchedulerState::Started(ref scheduler) = *inner {
            scheduler.interrupt_inbox();
        }
    }

    /// Interrupt optional boxes (mvbox currently) loops.
    pub(crate) async fn interrupt_oboxes(&self) {
        let inner = self.inner.read().await;
        if let InnerSchedulerState::Started(ref scheduler) = *inner {
            scheduler.interrupt_oboxes();
        }
    }

    pub(crate) async fn interrupt_smtp(&self) {
        let inner = self.inner.read().await;
        if let InnerSchedulerState::Started(ref scheduler) = *inner {
            scheduler.interrupt_smtp();
        }
    }

    pub(crate) async fn interrupt_ephemeral_task(&self) {
        let inner = self.inner.read().await;
        if let InnerSchedulerState::Started(ref scheduler) = *inner {
            scheduler.interrupt_ephemeral_task();
        }
    }

    pub(crate) async fn interrupt_location(&self) {
        let inner = self.inner.read().await;
        if let InnerSchedulerState::Started(ref scheduler) = *inner {
            scheduler.interrupt_location();
        }
    }

    pub(crate) async fn interrupt_recently_seen(&self, contact_id: ContactId, timestamp: i64) {
        let inner = self.inner.read().await;
        if let InnerSchedulerState::Started(ref scheduler) = *inner {
            scheduler.interrupt_recently_seen(contact_id, timestamp);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) enum InnerSchedulerState {
    Started(Scheduler),
    #[default]
    Stopped,
    Paused {
        started: bool,
        pause_guards_count: NonZeroUsize,
    },
}

/// Guard to make sure the IO Scheduler is resumed.
///
/// Returned by [`SchedulerState::pause`].  To resume the IO scheduler simply drop this
/// guard.
#[derive(Default, Debug)]
pub(crate) struct IoPausedGuard {
    sender: Option<oneshot::Sender<()>>,
}

impl Drop for IoPausedGuard {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            // Can only fail if receiver is dropped, but then we're already resumed.
            sender.send(()).ok();
        }
    }
}

#[derive(Debug)]
struct SchedBox {
    meaning: FolderMeaning,
    conn_state: ImapConnectionState,

    /// IMAP loop task handle.
    handle: task::JoinHandle<()>,
}

/// Job and connection scheduler.
#[derive(Debug)]
pub(crate) struct Scheduler {
    inbox: SchedBox,
    /// Optional boxes -- mvbox.
    oboxes: Vec<SchedBox>,
    smtp: SmtpConnectionState,
    smtp_handle: task::JoinHandle<()>,
    ephemeral_handle: task::JoinHandle<()>,
    ephemeral_interrupt_send: Sender<()>,
    location_handle: task::JoinHandle<()>,
    location_interrupt_send: Sender<()>,

    recently_seen_loop: RecentlySeenLoop,
}

async fn download_msgs(context: &Context, session: &mut Session) -> Result<()> {
    let msg_ids = context
        .sql
        .query_map_vec("SELECT msg_id FROM download", (), |row| {
            let msg_id: MsgId = row.get(0)?;
            Ok(msg_id)
        })
        .await?;

    for msg_id in msg_ids {
        if let Err(err) = download_msg(context, msg_id, session).await {
            warn!(context, "Failed to download message {msg_id}: {:#}.", err);

            // Update download state to failure
            // so it can be retried.
            //
            // On success update_download_state() is not needed
            // as receive_imf() already
            // set the state and emitted the event.
            msg_id
                .update_download_state(context, DownloadState::Failure)
                .await?;
        }
        context
            .sql
            .execute("DELETE FROM download WHERE msg_id=?", (msg_id,))
            .await?;
    }

    Ok(())
}

async fn inbox_loop(
    ctx: Context,
    started: oneshot::Sender<()>,
    inbox_handlers: ImapConnectionHandlers,
) {
    use futures::future::FutureExt;

    info!(ctx, "Starting inbox loop.");
    let ImapConnectionHandlers {
        mut connection,
        stop_token,
    } = inbox_handlers;

    let ctx1 = ctx.clone();
    let fut = async move {
        let ctx = ctx1;
        if let Err(()) = started.send(()) {
            warn!(ctx, "Inbox loop, missing started receiver.");
            return;
        };

        let mut old_session: Option<Session> = None;
        loop {
            let session = if let Some(session) = old_session.take() {
                session
            } else {
                info!(ctx, "Preparing new IMAP session for inbox.");
                match connection.prepare(&ctx).await {
                    Err(err) => {
                        warn!(ctx, "Failed to prepare inbox connection: {err:#}.");
                        continue;
                    }
                    Ok(session) => session,
                }
            };

            match inbox_fetch_idle(&ctx, &mut connection, session).await {
                Err(err) => warn!(ctx, "Failed inbox fetch_idle: {err:#}."),
                Ok(session) => {
                    info!(
                        ctx,
                        "IMAP loop iteration for inbox finished, keeping the session."
                    );
                    old_session = Some(session);
                }
            }
        }
    };

    stop_token
        .cancelled()
        .map(|_| {
            info!(ctx, "Shutting down inbox loop.");
        })
        .race(fut)
        .await;
}

/// Convert folder meaning
/// used internally by [fetch_idle] and [Context::background_fetch].
///
/// Returns folder configuration key and folder name
/// if such folder is configured, `Ok(None)` otherwise.
pub async fn convert_folder_meaning(
    ctx: &Context,
    folder_meaning: FolderMeaning,
) -> Result<Option<(Config, String)>> {
    let folder_config = match folder_meaning.to_config() {
        Some(c) => c,
        None => {
            // Such folder cannot be configured,
            // e.g. a `FolderMeaning::Spam` folder.
            return Ok(None);
        }
    };

    let folder = ctx
        .get_config(folder_config)
        .await
        .with_context(|| format!("Failed to retrieve {folder_config} folder"))?;

    if let Some(watch_folder) = folder {
        Ok(Some((folder_config, watch_folder)))
    } else {
        Ok(None)
    }
}

async fn inbox_fetch_idle(ctx: &Context, imap: &mut Imap, mut session: Session) -> Result<Session> {
    if !ctx.get_config_bool(Config::FixIsChatmail).await? {
        ctx.set_config_internal(
            Config::IsChatmail,
            crate::config::from_bool(session.is_chatmail()),
        )
        .await?;
    }

    // Update quota no more than once a minute.
    if ctx.quota_needs_update(60).await {
        if let Err(err) = ctx.update_recent_quota(&mut session).await {
            warn!(ctx, "Failed to update quota: {:#}.", err);
        }
    }

    if let Ok(()) = imap.resync_request_receiver.try_recv() {
        if let Err(err) = session.resync_folders(ctx).await {
            warn!(ctx, "Failed to resync folders: {:#}.", err);
            imap.resync_request_sender.try_send(()).ok();
        }
    }

    maybe_add_time_based_warnings(ctx).await;

    match ctx.get_config_i64(Config::LastHousekeeping).await {
        Ok(last_housekeeping_time) => {
            let next_housekeeping_time =
                last_housekeeping_time.saturating_add(constants::HOUSEKEEPING_PERIOD);
            if next_housekeeping_time <= time() {
                sql::housekeeping(ctx).await.log_err(ctx).ok();
            }
        }
        Err(err) => {
            warn!(ctx, "Failed to get last housekeeping time: {}", err);
        }
    };

    maybe_send_stats(ctx).await.log_err(ctx).ok();
    match ctx.get_config_bool(Config::FetchedExistingMsgs).await {
        Ok(fetched_existing_msgs) => {
            if !fetched_existing_msgs {
                // Consider it done even if we fail.
                //
                // This operation is not critical enough to retry,
                // especially if the error is persistent.
                if let Err(err) = ctx
                    .set_config_internal(Config::FetchedExistingMsgs, config::from_bool(true))
                    .await
                {
                    warn!(ctx, "Can't set Config::FetchedExistingMsgs: {:#}", err);
                }

                if let Err(err) = imap.fetch_existing_msgs(ctx, &mut session).await {
                    warn!(ctx, "Failed to fetch existing messages: {:#}", err);
                }
            }
        }
        Err(err) => {
            warn!(ctx, "Can't get Config::FetchedExistingMsgs: {:#}", err);
        }
    }

    download_msgs(ctx, &mut session)
        .await
        .context("Failed to download messages")?;
    session
        .fetch_metadata(ctx)
        .await
        .context("Failed to fetch metadata")?;
    session
        .register_token(ctx)
        .await
        .context("Failed to register push token")?;

    let session = fetch_idle(ctx, imap, session, FolderMeaning::Inbox).await?;
    Ok(session)
}

/// Implement a single iteration of IMAP loop.
///
/// This function performs all IMAP operations on a single folder, selecting it if necessary and
/// handling all the errors. In case of an error, an error is returned and connection is dropped,
/// otherwise connection is returned.
async fn fetch_idle(
    ctx: &Context,
    connection: &mut Imap,
    mut session: Session,
    folder_meaning: FolderMeaning,
) -> Result<Session> {
    let Some((folder_config, watch_folder)) = convert_folder_meaning(ctx, folder_meaning).await?
    else {
        // The folder is not configured.
        // For example, this happens if the server does not have Sent folder
        // but watching Sent folder is enabled.
        connection.connectivity.set_not_configured(ctx);
        connection.idle_interrupt_receiver.recv().await.ok();
        bail!("Cannot fetch folder {folder_meaning} because it is not configured");
    };

    if folder_config == Config::ConfiguredInboxFolder {
        let mvbox;
        let syncbox = match ctx.should_move_sync_msgs().await? {
            false => &watch_folder,
            true => {
                mvbox = ctx.get_config(Config::ConfiguredMvboxFolder).await?;
                mvbox.as_deref().unwrap_or(&watch_folder)
            }
        };
        session
            .send_sync_msgs(ctx, syncbox)
            .await
            .context("fetch_idle: send_sync_msgs")
            .log_err(ctx)
            .ok();

        session
            .store_seen_flags_on_imap(ctx)
            .await
            .context("store_seen_flags_on_imap")?;
    }

    if !ctx.should_delete_to_trash().await?
        || ctx
            .get_config(Config::ConfiguredTrashFolder)
            .await?
            .is_some()
    {
        // Fetch the watched folder.
        connection
            .fetch_move_delete(ctx, &mut session, &watch_folder, folder_meaning)
            .await
            .context("fetch_move_delete")?;

        // Mark expired messages for deletion. Marked messages will be deleted from the server
        // on the next iteration of `fetch_move_delete`. `delete_expired_imap_messages` is not
        // called right before `fetch_move_delete` because it is not well optimized and would
        // otherwise slow down message fetching.
        delete_expired_imap_messages(ctx)
            .await
            .context("delete_expired_imap_messages")?;
    } else if folder_config == Config::ConfiguredInboxFolder {
        session.last_full_folder_scan.lock().await.take();
    }

    // Scan additional folders only after finishing fetching the watched folder.
    //
    // On iOS the application has strictly limited time to work in background, so we may not
    // be able to scan all folders before time is up if there are many of them.
    if folder_config == Config::ConfiguredInboxFolder {
        // Only scan on the Inbox thread in order to prevent parallel scans, which might lead to duplicate messages
        match connection
            .scan_folders(ctx, &mut session)
            .await
            .context("scan_folders")
        {
            Err(err) => {
                // Don't reconnect, if there is a problem with the connection we will realize this when IDLEing
                // but maybe just one folder can't be selected or something
                warn!(ctx, "{:#}", err);
            }
            Ok(true) => {
                // Fetch the watched folder again in case scanning other folder moved messages
                // there.
                //
                // In most cases this will select the watched folder and return because there are
                // no new messages. We want to select the watched folder anyway before going IDLE
                // there, so this does not take additional protocol round-trip.
                connection
                    .fetch_move_delete(ctx, &mut session, &watch_folder, folder_meaning)
                    .await
                    .context("fetch_move_delete after scan_folders")?;
            }
            Ok(false) => {}
        }
    }

    // Synchronize Seen flags.
    session
        .sync_seen_flags(ctx, &watch_folder)
        .await
        .context("sync_seen_flags")
        .log_err(ctx)
        .ok();

    connection.connectivity.set_idle(ctx);

    ctx.emit_event(EventType::ImapInboxIdle);

    if !session.can_idle() {
        info!(
            ctx,
            "IMAP session does not support IDLE, going to fake idle."
        );
        connection.fake_idle(ctx, watch_folder).await?;
        return Ok(session);
    }

    if ctx
        .get_config_bool(Config::DisableIdle)
        .await
        .context("Failed to get disable_idle config")
        .log_err(ctx)
        .unwrap_or_default()
    {
        info!(ctx, "IMAP IDLE is disabled, going to fake idle.");
        connection.fake_idle(ctx, watch_folder).await?;
        return Ok(session);
    }

    info!(
        ctx,
        "IMAP session in folder {watch_folder:?} supports IDLE, using it."
    );
    let session = session
        .idle(
            ctx,
            connection.idle_interrupt_receiver.clone(),
            &watch_folder,
        )
        .await
        .context("idle")?;

    Ok(session)
}

async fn simple_imap_loop(
    ctx: Context,
    started: oneshot::Sender<()>,
    inbox_handlers: ImapConnectionHandlers,
    folder_meaning: FolderMeaning,
) {
    use futures::future::FutureExt;

    info!(ctx, "Starting simple loop for {folder_meaning}.");
    let ImapConnectionHandlers {
        mut connection,
        stop_token,
    } = inbox_handlers;

    let ctx1 = ctx.clone();

    let fut = async move {
        let ctx = ctx1;
        if let Err(()) = started.send(()) {
            warn!(
                ctx,
                "Simple imap loop for {folder_meaning}, missing started receiver."
            );
            return;
        }

        let mut old_session: Option<Session> = None;
        loop {
            let session = if let Some(session) = old_session.take() {
                session
            } else {
                info!(ctx, "Preparing new IMAP session for {folder_meaning}.");
                match connection.prepare(&ctx).await {
                    Err(err) => {
                        warn!(
                            ctx,
                            "Failed to prepare {folder_meaning} connection: {err:#}."
                        );
                        continue;
                    }
                    Ok(session) => session,
                }
            };

            match fetch_idle(&ctx, &mut connection, session, folder_meaning).await {
                Err(err) => warn!(ctx, "Failed fetch_idle: {err:#}"),
                Ok(session) => {
                    info!(
                        ctx,
                        "IMAP loop iteration for {folder_meaning} finished, keeping the session"
                    );
                    old_session = Some(session);
                }
            }
        }
    };

    stop_token
        .cancelled()
        .map(|_| {
            info!(ctx, "Shutting down IMAP loop for {folder_meaning}.");
        })
        .race(fut)
        .await;
}

async fn smtp_loop(
    ctx: Context,
    started: oneshot::Sender<()>,
    smtp_handlers: SmtpConnectionHandlers,
) {
    use futures::future::FutureExt;

    info!(ctx, "Starting SMTP loop.");
    let SmtpConnectionHandlers {
        mut connection,
        stop_token,
        idle_interrupt_receiver,
    } = smtp_handlers;

    let ctx1 = ctx.clone();
    let fut = async move {
        let ctx = ctx1;
        if let Err(()) = started.send(()) {
            warn!(&ctx, "SMTP loop, missing started receiver.");
            return;
        }

        let mut timeout = None;
        loop {
            if let Err(err) = send_smtp_messages(&ctx, &mut connection).await {
                warn!(ctx, "send_smtp_messages failed: {:#}.", err);
                timeout = Some(timeout.unwrap_or(30));
            } else {
                timeout = None;
                let duration_until_can_send = ctx.ratelimit.read().await.until_can_send();
                if !duration_until_can_send.is_zero() {
                    info!(
                        ctx,
                        "smtp got rate limited, waiting for {} until can send again",
                        duration_to_str(duration_until_can_send)
                    );
                    tokio::time::sleep(duration_until_can_send).await;
                    continue;
                }
            }

            stats::maybe_update_message_stats(&ctx)
                .await
                .log_err(&ctx)
                .ok();

            // Fake Idle
            info!(ctx, "SMTP fake idle started.");
            match &connection.last_send_error {
                None => connection.connectivity.set_idle(&ctx),
                Some(err) => connection.connectivity.set_err(&ctx, err),
            }

            // If send_smtp_messages() failed, we set a timeout for the fake-idle so that
            // sending is retried (at the latest) after the timeout. If sending fails
            // again, we increase the timeout exponentially, in order not to do lots of
            // unnecessary retries.
            if let Some(t) = timeout {
                let now = tools::Time::now();
                info!(
                    ctx,
                    "SMTP has messages to retry, planning to retry {t} seconds later."
                );
                let duration = std::time::Duration::from_secs(t);
                tokio::time::timeout(duration, async {
                    idle_interrupt_receiver.recv().await.unwrap_or_default()
                })
                .await
                .unwrap_or_default();
                let slept = time_elapsed(&now).as_secs();
                timeout = Some(cmp::max(
                    t,
                    slept.saturating_add(rand::random_range((slept / 2)..=slept)),
                ));
            } else {
                info!(ctx, "SMTP has no messages to retry, waiting for interrupt.");
                idle_interrupt_receiver.recv().await.unwrap_or_default();
            };

            info!(ctx, "SMTP fake idle interrupted.")
        }
    };

    stop_token
        .cancelled()
        .map(|_| {
            info!(ctx, "Shutting down SMTP loop.");
        })
        .race(fut)
        .await;
}

impl Scheduler {
    /// Start the scheduler.
    pub async fn start(ctx: &Context) -> Result<Self> {
        let (smtp, smtp_handlers) = SmtpConnectionState::new();

        let (smtp_start_send, smtp_start_recv) = oneshot::channel();
        let (ephemeral_interrupt_send, ephemeral_interrupt_recv) = channel::bounded(1);
        let (location_interrupt_send, location_interrupt_recv) = channel::bounded(1);

        let mut oboxes = Vec::new();
        let mut start_recvs = Vec::new();

        let (conn_state, inbox_handlers) = ImapConnectionState::new(ctx).await?;
        let (inbox_start_send, inbox_start_recv) = oneshot::channel();
        let handle = {
            let ctx = ctx.clone();
            task::spawn(inbox_loop(ctx, inbox_start_send, inbox_handlers))
        };
        let inbox = SchedBox {
            meaning: FolderMeaning::Inbox,
            conn_state,
            handle,
        };
        start_recvs.push(inbox_start_recv);

        if ctx.should_watch_mvbox().await? {
            let (conn_state, handlers) = ImapConnectionState::new(ctx).await?;
            let (start_send, start_recv) = oneshot::channel();
            let ctx = ctx.clone();
            let meaning = FolderMeaning::Mvbox;
            let handle = task::spawn(simple_imap_loop(ctx, start_send, handlers, meaning));
            oboxes.push(SchedBox {
                meaning,
                conn_state,
                handle,
            });
            start_recvs.push(start_recv);
        }

        let smtp_handle = {
            let ctx = ctx.clone();
            task::spawn(smtp_loop(ctx, smtp_start_send, smtp_handlers))
        };
        start_recvs.push(smtp_start_recv);

        let ephemeral_handle = {
            let ctx = ctx.clone();
            task::spawn(async move {
                ephemeral::ephemeral_loop(&ctx, ephemeral_interrupt_recv).await;
            })
        };

        let location_handle = {
            let ctx = ctx.clone();
            task::spawn(async move {
                location::location_loop(&ctx, location_interrupt_recv).await;
            })
        };

        let recently_seen_loop = RecentlySeenLoop::new(ctx.clone());

        let res = Self {
            inbox,
            oboxes,
            smtp,
            smtp_handle,
            ephemeral_handle,
            ephemeral_interrupt_send,
            location_handle,
            location_interrupt_send,
            recently_seen_loop,
        };

        // wait for all loops to be started
        if let Err(err) = try_join_all(start_recvs).await {
            bail!("failed to start scheduler: {err}");
        }

        info!(ctx, "scheduler is running");
        Ok(res)
    }

    fn boxes(&self) -> iter::Chain<iter::Once<&SchedBox>, std::slice::Iter<'_, SchedBox>> {
        once(&self.inbox).chain(self.oboxes.iter())
    }

    fn maybe_network(&self) {
        for b in self.boxes() {
            b.conn_state.interrupt();
        }
        self.interrupt_smtp();
    }

    fn maybe_network_lost(&self) {
        for b in self.boxes() {
            b.conn_state.interrupt();
        }
        self.interrupt_smtp();
    }

    fn interrupt_inbox(&self) {
        self.inbox.conn_state.interrupt();
    }

    fn interrupt_oboxes(&self) {
        for b in &self.oboxes {
            b.conn_state.interrupt();
        }
    }

    fn interrupt_smtp(&self) {
        self.smtp.interrupt();
    }

    fn interrupt_ephemeral_task(&self) {
        self.ephemeral_interrupt_send.try_send(()).ok();
    }

    fn interrupt_location(&self) {
        self.location_interrupt_send.try_send(()).ok();
    }

    fn interrupt_recently_seen(&self, contact_id: ContactId, timestamp: i64) {
        self.recently_seen_loop.try_interrupt(contact_id, timestamp);
    }

    /// Halt the scheduler.
    ///
    /// It consumes the scheduler and never fails to stop it. In the worst case, long-running tasks
    /// are forcefully terminated if they cannot shutdown within the timeout.
    pub(crate) async fn stop(self, context: &Context) {
        // Send stop signals to tasks so they can shutdown cleanly.
        for b in self.boxes() {
            b.conn_state.stop();
        }
        self.smtp.stop();

        // Actually shutdown tasks.
        let timeout_duration = std::time::Duration::from_secs(30);

        let tracker = TaskTracker::new();
        for b in once(self.inbox).chain(self.oboxes) {
            let context = context.clone();
            tracker.spawn(async move {
                tokio::time::timeout(timeout_duration, b.handle)
                    .await
                    .log_err(&context)
            });
        }
        {
            let context = context.clone();
            tracker.spawn(async move {
                tokio::time::timeout(timeout_duration, self.smtp_handle)
                    .await
                    .log_err(&context)
            });
        }
        tracker.close();
        tracker.wait().await;

        // Abort tasks, then await them to ensure the `Future` is dropped.
        // Just aborting the task may keep resources such as `Context` clone
        // moved into it indefinitely, resulting in database not being
        // closed etc.
        self.ephemeral_handle.abort();
        self.ephemeral_handle.await.ok();
        self.location_handle.abort();
        self.location_handle.await.ok();
        self.recently_seen_loop.abort().await;
    }
}

/// Connection state logic shared between imap and smtp connections.
#[derive(Debug)]
struct ConnectionState {
    /// Cancellation token to interrupt the whole connection.
    stop_token: CancellationToken,
    /// Channel to interrupt idle.
    idle_interrupt_sender: Sender<()>,
    /// Mutex to pass connectivity info between IMAP/SMTP threads and the API
    connectivity: ConnectivityStore,
}

impl ConnectionState {
    /// Shutdown this connection completely.
    fn stop(&self) {
        // Trigger shutdown of the run loop.
        self.stop_token.cancel();
    }

    fn interrupt(&self) {
        // Use try_send to avoid blocking on interrupts.
        self.idle_interrupt_sender.try_send(()).ok();
    }
}

#[derive(Debug)]
pub(crate) struct SmtpConnectionState {
    state: ConnectionState,
}

impl SmtpConnectionState {
    fn new() -> (Self, SmtpConnectionHandlers) {
        let stop_token = CancellationToken::new();
        let (idle_interrupt_sender, idle_interrupt_receiver) = channel::bounded(1);

        let handlers = SmtpConnectionHandlers {
            connection: Smtp::new(),
            stop_token: stop_token.clone(),
            idle_interrupt_receiver,
        };

        let state = ConnectionState {
            stop_token,
            idle_interrupt_sender,
            connectivity: handlers.connection.connectivity.clone(),
        };

        let conn = SmtpConnectionState { state };

        (conn, handlers)
    }

    /// Interrupt any form of idle.
    fn interrupt(&self) {
        self.state.interrupt();
    }

    /// Shutdown this connection completely.
    fn stop(&self) {
        self.state.stop();
    }
}

struct SmtpConnectionHandlers {
    connection: Smtp,
    stop_token: CancellationToken,
    idle_interrupt_receiver: Receiver<()>,
}

#[derive(Debug)]
pub(crate) struct ImapConnectionState {
    state: ConnectionState,
}

impl ImapConnectionState {
    /// Construct a new connection.
    async fn new(context: &Context) -> Result<(Self, ImapConnectionHandlers)> {
        let stop_token = CancellationToken::new();
        let (idle_interrupt_sender, idle_interrupt_receiver) = channel::bounded(1);

        let handlers = ImapConnectionHandlers {
            connection: Imap::new_configured(context, idle_interrupt_receiver).await?,
            stop_token: stop_token.clone(),
        };

        let state = ConnectionState {
            stop_token,
            idle_interrupt_sender,
            connectivity: handlers.connection.connectivity.clone(),
        };

        let conn = ImapConnectionState { state };

        Ok((conn, handlers))
    }

    /// Interrupt any form of idle.
    fn interrupt(&self) {
        self.state.interrupt();
    }

    /// Shutdown this connection completely.
    fn stop(&self) {
        self.state.stop();
    }
}

#[derive(Debug)]
struct ImapConnectionHandlers {
    connection: Imap,
    stop_token: CancellationToken,
}
