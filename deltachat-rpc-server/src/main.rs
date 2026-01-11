#![recursion_limit = "256"]
//! Delta Chat core RPC server.
//!
//! It speaks JSON Lines over stdio.
use std::path::PathBuf;
use std::sync::Arc;
use std::{env, ffi::OsStr};

use anyhow::{anyhow, Context as _, Result};
use deltachat::constants::DC_VERSION_STR;
use deltachat_jsonrpc::api::{Accounts, CommandApi};
use futures_lite::stream::StreamExt;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing_subscriber::EnvFilter;
use yerpc::RpcServer as _;

#[cfg(target_family = "unix")]
use tokio::net::UnixListener;
#[cfg(target_family = "unix")]
use tokio::signal::unix as signal_unix;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use yerpc::{RpcClient, RpcSession};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Logs from `log` crate and traces from `tracing` crate
    // are configurable with `RUST_LOG` environment variable
    // and go to stderr to avoid interfering with JSON-RPC using stdout.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let r = main_impl().await;
    // From tokio documentation:
    // "For technical reasons, stdin is implemented by using an ordinary blocking read on a separate
    // thread, and it is impossible to cancel that read. This can make shutdown of the runtime hang
    // until the user presses enter."
    if let Err(error) = &r {
        log::error!("Error: {error:#}.")
    }
    std::process::exit(if r.is_ok() { 0 } else { 1 });
}

async fn main_impl() -> Result<()> {
    let mut args = env::args_os();
    let _program_name = args.next().context("no command line arguments found")?;
    let mut unix_socket = None;
    if let Some(first_arg) = args.next() {
        if first_arg.to_str() == Some("--version") {
            if let Some(arg) = args.next() {
                return Err(anyhow!("Unrecognized argument {arg:?}"));
            }
            eprintln!("{}", &*DC_VERSION_STR);
            return Ok(());
        } else if first_arg.to_str() == Some("--openrpc") {
            if let Some(arg) = args.next() {
                return Err(anyhow!("Unrecognized argument {arg:?}"));
            }
            println!("{}", CommandApi::openrpc_specification()?);
            return Ok(());
        } else if first_arg.to_str() == Some("--unix") {
            let Some(unix_socket_path) = args.next() else {
                return Err(anyhow!("Unix Socket Path is missing"));
            };
            unix_socket = Some(unix_socket_path)
        } else {
            return Err(anyhow!("Unrecognized option {first_arg:?}"));
        }
    }
    if let Some(arg) = args.next() {
        return Err(anyhow!("Unrecognized argument {arg:?}"));
    }

    // Install signal handlers early so that the shutdown is graceful starting from here.
    let _ctrl_c = tokio::signal::ctrl_c();
    #[cfg(target_family = "unix")]
    let mut sigterm = signal_unix::signal(signal_unix::SignalKind::terminate())?;

    let path = std::env::var("DC_ACCOUNTS_PATH").unwrap_or_else(|_| "accounts".to_string());
    log::info!("Starting with accounts directory `{path}`.");
    let writable = true;
    let accounts = Accounts::new(PathBuf::from(&path), writable).await?;

    log::info!("Creating JSON-RPC API.");
    let accounts = Arc::new(RwLock::new(accounts));
    let state = CommandApi::from_arc(accounts.clone()).await;

    let main_cancel = CancellationToken::new();

    let cancel = main_cancel.clone();
    let sigterm_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        #[cfg(target_family = "unix")]
        {
            let _cancel_guard = cancel.clone().drop_guard();
            tokio::select! {
                _ = cancel.cancelled() => (),
                _ = sigterm.recv() => {
                    log::info!("got SIGTERM");
                }
            }
        }
        let _ = cancel;
        Ok(())
    });

    let (send_task, recv_task) = if let Some(unix_socket_path) = unix_socket {
        #[cfg(not(target_family = "unix"))]
        {
            bail!("unix sockets are only supported on unix based operating systems");
        }
        #[cfg(target_family = "unix")]
        unix_socket_impl(&unix_socket_path, state, main_cancel.clone()).await?
    } else {
        stdio_impl(state, main_cancel.clone()).await?
    };

    main_cancel.cancelled().await;
    accounts.read().await.stop_io().await;
    drop(accounts);
    send_task.await??;
    sigterm_task.await??;
    recv_task.await??;

    Ok(())
}

async fn stdio_impl(
    state: CommandApi,
    main_cancel: CancellationToken,
) -> Result<(
    JoinHandle<anyhow::Result<()>>,
    JoinHandle<anyhow::Result<()>>,
)> {
    let (client, mut out_receiver) = RpcClient::new();

    let session = RpcSession::new(client.clone(), state.clone());

    // Send task prints JSON responses to stdout.
    let cancel = main_cancel.clone();
    let send_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let _cancel_guard = cancel.clone().drop_guard();
        loop {
            let message = tokio::select! {
                _ = cancel.cancelled() => break,
                message = out_receiver.next() => match message {
                    None => break,
                    Some(message) => serde_json::to_string(&message)?,
                }
            };
            log::trace!("RPC send {message}");
            println!("{message}");
        }
        Ok(())
    });

    // Receiver task reads JSON requests from stdin.
    let cancel = main_cancel.clone();
    let recv_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let _cancel_guard = cancel.clone().drop_guard();
        let stdin = io::stdin();
        let mut lines = BufReader::new(stdin).lines();

        loop {
            let message = tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::signal::ctrl_c() => {
                    log::info!("got ctrl-c event");
                    break;
                }
                message = lines.next_line() => match message? {
                    None => {
                        log::info!("EOF reached on stdin");
                        break;
                    }
                    Some(message) => message,
                }
            };
            log::trace!("RPC recv {message}");
            let session = session.clone();
            tokio::spawn(async move {
                session.handle_incoming(&message).await;
            });
        }
        Ok(())
    });

    Ok((send_task, recv_task))
}

#[cfg(target_family = "unix")]
async fn unix_socket_impl(
    unix_socket_path: &OsStr,
    state: CommandApi,
    main_cancel: CancellationToken,
) -> Result<(
    JoinHandle<anyhow::Result<()>>,
    JoinHandle<anyhow::Result<()>>,
)> {
    let cancel = main_cancel.clone();

    let listener = UnixListener::bind(unix_socket_path)?;

    let recv_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let _cancel_guard = cancel.clone().drop_guard();
        let cancel = main_cancel.clone();

        loop {
            let connection_result = tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::signal::ctrl_c() => {
                    log::info!("got ctrl-c event");
                    break;
                }
                connection_result = listener.accept() => connection_result
            };
            match connection_result {
                Ok((stream, addr)) => {
                    log::info!("new client {addr:?}");

                    let (client, mut out_receiver) = RpcClient::new();
                    let session = RpcSession::new(client.clone(), state.clone());

                    let (read, mut write) = stream.into_split();
                    let mut read_lines = BufReader::new(read).lines();

                    let cancel = main_cancel.clone();
                    let _receive_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
                        let _cancel_guard = cancel.clone().drop_guard();
                        loop {
                            let message = tokio::select! {
                                _ = cancel.cancelled() => break,
                                _ = tokio::signal::ctrl_c() => {
                                    log::info!("got ctrl-c event");
                                    break;
                                }
                                message =
                                    read_lines.next_line()
                                     => match message? {
                                    None => {
                                        log::info!("EOF reached on stdin");
                                        break;
                                    }
                                    Some(message) => message,
                                }
                            };
                            log::trace!("RPC recv {message}");
                            let session = session.clone();
                            tokio::spawn(async move {
                                session.handle_incoming(&message).await;
                            });
                        }
                        Ok(())
                    });

                    let cancel = main_cancel.clone();
                    let _send_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
                        let _cancel_guard = cancel.clone().drop_guard();
                        loop {
                            use tokio::io::AsyncWriteExt;

                            let message = tokio::select! {
                                _ = cancel.cancelled() => break,
                                message = out_receiver.next() => match message {
                                    None => break,
                                    Some(message) => serde_json::to_string(&message)?,
                                }
                            };
                            log::trace!("RPC send {message}");
                            write.write_all(format!("{message}\n").as_bytes()).await?;
                        }
                        Ok(())
                    });

                    // todo handle shutdown of _send_task and _receive_task
                }
                Err(e) => {
                    log::info!("connection failed {e:#}");
                }
            }
        }
        // todo shutdown all remaining unix streams via their shutdown method

        Ok(())
    });

    Ok((tokio::spawn(async move { Ok(()) }), recv_task))
}
