//! Transfer a backup to an other device.
//!
//! This module provides support for using [iroh](https://iroh.computer/)
//! to initiate transfer of a backup to another device using a QR code.
//!
//! There are two parties to this:
//! - The *Provider*, which starts a server and listens for connections.
//! - The *Getter*, which connects to the server and retrieves the data.
//!
//! Both the provider and the getter are authenticated:
//!
//! - The provider is known by its *peer ID*.
//! - The provider needs an *authentication token* from the getter before it accepts a
//!   connection.
//!
//! Both these are transferred in the QR code offered to the getter.  This ensures that the
//! getter can not connect to an impersonated provider and the provider does not offer the
//! download to an impersonated getter.
//!
//! Protocol starts by getter opening a bidirectional QUIC stream
//! to the provider and sending authentication token.
//! Provider verifies received authentication token,
//! sends the size of all files in a backup (database and all blobs)
//! as an unsigned 64-bit big endian integer and streams the backup in tar format.
//! Getter receives the backup and acknowledges successful reception
//! by sending a single byte.
//! Provider closes the endpoint after receiving an acknowledgment.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{Context as _, Result, bail, format_err};
use futures_lite::FutureExt;
use iroh::{Endpoint, RelayMode};
use tokio::fs;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::chat::add_device_msg;
use crate::context::Context;
use crate::imex::BlobDirContents;
use crate::log::warn;
use crate::message::Message;
use crate::qr::Qr;
use crate::stock_str::backup_transfer_msg_body;
use crate::tools::{TempPathGuard, create_id, time};
use crate::{EventType, e2ee};

use super::{DBFILE_BACKUP_NAME, export_backup_stream, export_database, import_backup_stream};

/// ALPN protocol identifier for the backup transfer protocol.
const BACKUP_ALPN: &[u8] = b"/deltachat/backup";

/// Provide or send a backup of this device.
///
/// This creates a backup of the current device and starts a service which offers another
/// device to download this backup.
///
/// This does not make a full backup on disk, only the SQLite database is created on disk,
/// the blobs in the blob directory are not copied.
///
/// This starts a task which acquires the global "ongoing" mutex.  If you need to stop the
/// task use the [`Context::stop_ongoing`] mechanism.
#[derive(Debug)]
pub struct BackupProvider {
    /// iroh endpoint.
    _endpoint: Endpoint,

    /// iroh address.
    node_addr: iroh::NodeAddr,

    /// Authentication token that should be submitted
    /// to retrieve the backup.
    auth_token: String,

    /// Handle for the task accepting backup transfer requests.
    handle: JoinHandle<Result<()>>,

    /// Guard to cancel the provider on drop.
    _drop_guard: tokio_util::sync::DropGuard,
}

impl BackupProvider {
    /// Prepares for sending a backup to a second device.
    ///
    /// Before calling this function all I/O must be stopped so that no changes to the blobs
    /// or database are happening, this is done by calling the [`Accounts::stop_io`] or
    /// [`Context::stop_io`] APIs first.
    ///
    /// This will acquire the global "ongoing process" mutex, which can be used to cancel
    /// the process.
    ///
    /// [`Accounts::stop_io`]: crate::accounts::Accounts::stop_io
    pub async fn prepare(context: &Context) -> Result<Self> {
        let relay_mode = RelayMode::Disabled;
        let endpoint = Endpoint::builder()
            .tls_x509() // For compatibility with iroh <0.34.0
            .alpns(vec![BACKUP_ALPN.to_vec()])
            .relay_mode(relay_mode)
            .bind()
            .await?;
        let node_addr = endpoint.node_addr().await?;

        // Acquire global "ongoing" mutex.
        let cancel_token = context.alloc_ongoing().await?;
        let paused_guard = context.scheduler.pause(context).await?;
        let context_dir = context
            .get_blobdir()
            .parent()
            .context("Context dir not found")?;

        // before we export, make sure the private key exists
        e2ee::ensure_secret_key_exists(context)
            .await
            .context("Cannot create private key or private key not available")?;

        let dbfile = context_dir.join(DBFILE_BACKUP_NAME);
        if fs::metadata(&dbfile).await.is_ok() {
            fs::remove_file(&dbfile).await?;
            warn!(context, "Previous database export deleted");
        }
        let dbfile = TempPathGuard::new(dbfile);

        // Authentication token that receiver should send us to receive a backup.
        let auth_token = create_id();

        let passphrase = String::new();

        export_database(context, &dbfile, passphrase, time())
            .await
            .context("Database export failed")?;

        let drop_token = CancellationToken::new();
        let handle = {
            let context = context.clone();
            let drop_token = drop_token.clone();
            let endpoint = endpoint.clone();
            let auth_token = auth_token.clone();
            tokio::spawn(async move {
                Self::accept_loop(
                    context.clone(),
                    endpoint,
                    auth_token,
                    cancel_token,
                    drop_token,
                    dbfile,
                )
                .await;
                info!(context, "Finished accept loop.");

                context.free_ongoing().await;

                // Explicit drop to move the guards into this future
                drop(paused_guard);
                Ok(())
            })
        };
        Ok(Self {
            _endpoint: endpoint,
            node_addr,
            auth_token,
            handle,
            _drop_guard: drop_token.drop_guard(),
        })
    }

    async fn handle_connection(
        context: Context,
        conn: iroh::endpoint::Connecting,
        auth_token: String,
        dbfile: Arc<TempPathGuard>,
    ) -> Result<()> {
        let conn = conn.await?;
        let (mut send_stream, mut recv_stream) = conn.accept_bi().await?;

        // Read authentication token from the stream.
        let mut received_auth_token = vec![0u8; auth_token.len()];
        recv_stream.read_exact(&mut received_auth_token).await?;
        if received_auth_token.as_slice() != auth_token.as_bytes() {
            warn!(context, "Received wrong backup authentication token.");
            return Ok(());
        }

        info!(context, "Received valid backup authentication token.");
        // Emit a nonzero progress so that UIs can display smth like "Transferring...".
        context.emit_event(EventType::ImexProgress(1));

        let blobdir = BlobDirContents::new(&context).await?;

        let mut file_size = dbfile.metadata()?.len();
        for blob in blobdir.iter() {
            file_size = file_size
                .checked_add(blob.to_abs_path().metadata()?.len())
                .context("File size overflow")?;
        }

        send_stream.write_all(&file_size.to_be_bytes()).await?;

        export_backup_stream(&context, &dbfile, blobdir, send_stream, file_size)
            .await
            .context("Failed to write backup into QUIC stream")?;
        info!(context, "Finished writing backup into QUIC stream.");
        let mut buf = [0u8; 1];
        info!(context, "Waiting for acknowledgment.");
        recv_stream.read_exact(&mut buf).await?;
        info!(context, "Received backup reception acknowledgement.");
        context.emit_event(EventType::ImexProgress(1000));

        let mut msg = Message::new_text(backup_transfer_msg_body(&context).await);
        add_device_msg(&context, None, Some(&mut msg)).await?;

        Ok(())
    }

    async fn accept_loop(
        context: Context,
        endpoint: Endpoint,
        auth_token: String,
        cancel_token: async_channel::Receiver<()>,
        drop_token: CancellationToken,
        dbfile: TempPathGuard,
    ) {
        let dbfile = Arc::new(dbfile);
        loop {
            tokio::select! {
                biased;

                conn = endpoint.accept() => {
                    if let Some(conn) = conn {
                        let conn = match conn.accept() {
                            Ok(conn) => conn,
                            Err(err) => {
                               warn!(context, "Failed to accept iroh connection: {err:#}.");
                               continue;
                            }
                        };
                        // Got a new in-progress connection.
                        let context = context.clone();
                        let auth_token = auth_token.clone();
                        let dbfile = dbfile.clone();
                        if let Err(err) = Self::handle_connection(context.clone(), conn, auth_token, dbfile).race(
                            async {
                                cancel_token.recv().await.ok();
                                Err(format_err!("Backup transfer canceled"))
                            }
                        ).race(
                            async {
                                drop_token.cancelled().await;
                                Err(format_err!("Backup provider dropped"))
                            }
                        ).await {
                            error!(context, "Error while handling backup connection: {err:#}.");
                            context.emit_event(EventType::ImexProgress(0));
                            break;
                        } else {
                            info!(context, "Backup transfer finished successfully.");
                            break;
                        }
                    } else {
                        break;
                    }
                },
                _ = cancel_token.recv() => {
                    info!(context, "Backup transfer canceled by the user, stopping accept loop.");
                    context.emit_event(EventType::ImexProgress(0));
                    break;
                }
                _ = drop_token.cancelled() => {
                    info!(context, "Backup transfer canceled by dropping the provider, stopping accept loop.");
                    context.emit_event(EventType::ImexProgress(0));
                    break;
                }
            }
        }
    }

    /// Returns a QR code that allows fetching this backup.
    ///
    /// This QR code can be passed to [`get_backup`] on a (different) device.
    pub fn qr(&self) -> Qr {
        Qr::Backup2 {
            node_addr: self.node_addr.clone(),

            auth_token: self.auth_token.clone(),
        }
    }
}

impl Future for BackupProvider {
    type Output = Result<()>;

    /// Waits for the backup transfer to complete.
    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx)?
    }
}

pub async fn get_backup2(
    context: &Context,
    node_addr: iroh::NodeAddr,
    auth_token: String,
) -> Result<()> {
    let relay_mode = RelayMode::Disabled;

    let endpoint = Endpoint::builder()
        .tls_x509() // For compatibility with iroh <0.34.0
        .relay_mode(relay_mode)
        .bind()
        .await?;

    let conn = endpoint.connect(node_addr, BACKUP_ALPN).await?;
    let (mut send_stream, mut recv_stream) = conn.open_bi().await?;
    info!(context, "Sending backup authentication token.");
    send_stream.write_all(auth_token.as_bytes()).await?;

    let passphrase = String::new();
    info!(context, "Starting to read backup from the stream.");

    let mut file_size_buf = [0u8; 8];
    recv_stream.read_exact(&mut file_size_buf).await?;
    let file_size = u64::from_be_bytes(file_size_buf);
    info!(context, "Received backup file size.");
    // Emit a nonzero progress so that UIs can display smth like "Transferring...".
    context.emit_event(EventType::ImexProgress(1));

    import_backup_stream(context, recv_stream, file_size, passphrase)
        .await
        .context("Failed to import backup from QUIC stream")?;
    info!(context, "Finished importing backup from the stream.");
    context.emit_event(EventType::ImexProgress(1000));

    // Send an acknowledgement, but ignore the errors.
    // We have imported backup successfully already.
    send_stream.write_all(b".").await.ok();
    send_stream.finish().ok();
    info!(context, "Sent backup reception acknowledgment.");

    // Wait for the peer to acknowledge reception of the acknowledgement
    // before closing the connection.
    _ = send_stream.stopped().await;

    Ok(())
}

/// Contacts a backup provider and receives the backup from it.
///
/// This uses a QR code to contact another instance of deltachat which is providing a backup
/// using the [`BackupProvider`].  Once connected it will authenticate using the secrets in
/// the QR code and retrieve the backup.
///
/// This is a long running operation which will return only when completed.
///
/// Using [`Qr`] as argument is a bit odd as it only accepts specific variant of it.  It
/// does avoid having [`iroh::NodeAddr`] in the primary API however, without
/// having to revert to untyped bytes.
pub async fn get_backup(context: &Context, qr: Qr) -> Result<()> {
    match qr {
        Qr::Backup2 {
            node_addr,
            auth_token,
        } => {
            let cancel_token = context.alloc_ongoing().await?;
            let res = get_backup2(context, node_addr, auth_token)
                .race(async {
                    cancel_token.recv().await.ok();
                    Err(format_err!("Backup reception canceled"))
                })
                .await;
            if let Err(ref res) = res {
                error!(context, "{:#}", res);
                context.emit_event(EventType::ImexProgress(0));
            }
            context.free_ongoing().await;
            res?;
        }
        _ => bail!("QR code for backup must be of type DCBACKUP2"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::chat::{ChatItem, get_chat_msgs, send_msg};
    use crate::message::Viewtype;
    use crate::test_utils::TestContextManager;

    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_send_receive() {
        let mut tcm = TestContextManager::new();

        // Create first device.
        let ctx0 = tcm.alice().await;

        // Write a message in the self chat
        let self_chat = ctx0.get_self_chat().await;
        let mut msg = Message::new_text("hi there".to_string());
        send_msg(&ctx0, self_chat.id, &mut msg).await.unwrap();

        // Send an attachment in the self chat
        let file = ctx0.get_blobdir().join("hello.txt");
        fs::write(&file, "i am attachment").await.unwrap();
        let mut msg = Message::new(Viewtype::File);
        msg.set_file_and_deduplicate(&ctx0, &file, Some("hello.txt"), Some("text/plain"))
            .unwrap();
        send_msg(&ctx0, self_chat.id, &mut msg).await.unwrap();

        // Prepare to transfer backup.
        let provider = BackupProvider::prepare(&ctx0).await.unwrap();

        // Set up second device.
        let ctx1 = tcm.unconfigured().await;
        get_backup(&ctx1, provider.qr()).await.unwrap();

        // Make sure the provider finishes without an error.
        tokio::time::timeout(Duration::from_secs(30), provider)
            .await
            .expect("timed out")
            .expect("error in provider");

        // Check that we have the self message.
        let self_chat = ctx1.get_self_chat().await;
        let msgs = get_chat_msgs(&ctx1, self_chat.id).await.unwrap();
        assert_eq!(msgs.len(), 2);
        let msgid = match msgs.first().unwrap() {
            ChatItem::Message { msg_id } => msg_id,
            _ => panic!("wrong chat item"),
        };
        let msg = Message::load_from_db(&ctx1, *msgid).await.unwrap();
        let text = msg.get_text();
        assert_eq!(text, "hi there");
        let msgid = match msgs.get(1).unwrap() {
            ChatItem::Message { msg_id } => msg_id,
            _ => panic!("wrong chat item"),
        };
        let msg = Message::load_from_db(&ctx1, *msgid).await.unwrap();

        let path = msg.get_file(&ctx1).unwrap();
        assert_eq!(
            // That's the hash of the file:
            path.with_file_name("ac1d2d284757656a8d41dc40aae4136.txt"),
            path
        );
        assert_eq!("hello.txt", msg.get_filename().unwrap());
        let text = fs::read_to_string(&path).await.unwrap();
        assert_eq!(text, "i am attachment");

        let path = path.with_file_name("saved.txt");
        msg.save_file(&ctx1, &path).await.unwrap();
        let text = fs::read_to_string(&path).await.unwrap();
        assert_eq!(text, "i am attachment");
        assert!(msg.save_file(&ctx1, &path).await.is_err());

        // Check that both received the ImexProgress events.
        for ctx in [&ctx0, &ctx1] {
            ctx.evtracker
                .get_matching(|ev| matches!(ev, EventType::ImexProgress(1)))
                .await;
            ctx.evtracker
                .get_matching(|ev| matches!(ev, EventType::ImexProgress(1000)))
                .await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_drop_provider() {
        let mut tcm = TestContextManager::new();
        let ctx = tcm.alice().await;

        let provider = BackupProvider::prepare(&ctx).await.unwrap();
        drop(provider);
        ctx.evtracker
            .get_matching(|ev| matches!(ev, EventType::ImexProgress(0)))
            .await;
    }
}
