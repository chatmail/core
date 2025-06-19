//! Stream that logs errors as events.
//!
//! This stream can be used to wrap IMAP,
//! SMTP and HTTP streams so errors
//! that occur are logged before
//! they are processed.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use pin_project::pin_project;

use crate::events::{Event, EventType, Events};
use crate::net::session::SessionStream;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Stream that logs errors to the event channel.
#[derive(Debug)]
#[pin_project]
pub(crate) struct LoggingStream<S: SessionStream> {
    #[pin]
    inner: S,

    /// Name of the stream to distinguish log messages produced by it.
    tag: String,

    /// Account ID for logging.
    account_id: u32,

    /// Event channel.
    events: Events,
}

impl<S: SessionStream> LoggingStream<S> {
    pub fn new(inner: S, tag: String, account_id: u32, events: Events) -> Self {
        Self {
            inner,
            tag,
            account_id,
            events,
        }
    }
}

impl<S: SessionStream> AsyncRead for LoggingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let projected = self.project();
        let old_remaining = buf.remaining();

        let res = projected.inner.poll_read(cx, buf);

        let n = old_remaining - buf.remaining();
        let log_message = format!("{}: READING {}", projected.tag, n);
        projected.events.emit(Event {
            id: 0,
            typ: EventType::Info(log_message),
        });


        res
    }
}

impl<S: SessionStream> AsyncWrite for LoggingStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let log_message = format!("{}: WRITING {}", self.tag, buf.len());

        let projected = self.project();
        projected.events.emit(Event {
            id: 0,
            typ: EventType::Info(log_message),
        });

        projected.inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let log_message = format!("{}: FLUSH", self.tag);

        let projected = self.project();
        projected.events.emit(Event {
            id: 0,
            typ: EventType::Info(log_message),
        });

        projected.inner.poll_flush(cx)
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
        self.project().inner.poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<S: SessionStream> SessionStream for LoggingStream<S> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.inner.set_read_timeout(timeout)
    }
}
