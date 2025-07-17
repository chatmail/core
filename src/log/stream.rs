//! Stream that logs errors as events.
//!
//! This stream can be used to wrap IMAP,
//! SMTP and HTTP streams so errors
//! that occur are logged before
//! they are processed.

use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::Result;
use pin_project::pin_project;

use crate::events::{Event, EventType, Events};
use crate::net::session::SessionStream;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
struct Metrics {
    /// Total number of bytes read.
    pub total_read: usize,

    /// Total number of bytes written.
    pub total_written: usize,
}

impl Metrics {
    fn new() -> Self {
        Self {
            total_read: 0,
            total_written: 0,
        }
    }
}

/// Stream that logs errors to the event channel.
#[derive(Debug)]
#[pin_project]
pub(crate) struct LoggingStream<S: SessionStream> {
    #[pin]
    inner: S,

    /// Account ID for logging.
    account_id: u32,

    /// Event channel.
    events: Events,

    /// Metrics for this stream.
    metrics: Metrics,
}

impl<S: SessionStream> LoggingStream<S> {
    pub fn new(inner: S, account_id: u32, events: Events) -> Self {
        Self {
            inner,
            account_id,
            events,
            metrics: Metrics::new(),
        }
    }
}

impl<S: SessionStream> AsyncRead for LoggingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let peer_addr = this.inner.peer_addr();
        let old_remaining = buf.remaining();

        let res = this.inner.poll_read(cx, buf);

        if let Poll::Ready(Err(ref err)) = res {
            debug_assert!(
                peer_addr.is_ok(),
                "Logging stream should be created over a bound socket"
            );
            let log_message = match peer_addr {
                Ok(peer_addr) => format!(
                    "Read error on stream {peer_addr:?} after reading {} and writing {} bytes: {err}.",
                    this.metrics.total_read, this.metrics.total_written
                ),
                Err(_) => {
                    format!("Read error on a stream that does not have a peer address: {err}.")
                }
            };
            this.events.emit(Event {
                id: *this.account_id,
                typ: EventType::Warning(log_message),
            });
        }

        let n = old_remaining - buf.remaining();
        this.metrics.total_read = this.metrics.total_read.saturating_add(n);

        res
    }
}

impl<S: SessionStream> AsyncWrite for LoggingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let res = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = res {
            this.metrics.total_written = this.metrics.total_written.saturating_add(n);
        }
        res
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let res = this.inner.poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(n)) = res {
            this.metrics.total_written = this.metrics.total_written.saturating_add(n);
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S: SessionStream> SessionStream for LoggingStream<S> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.inner.set_read_timeout(timeout)
    }

    fn peer_addr(&self) -> Result<SocketAddr> {
        self.inner.peer_addr()
    }
}
