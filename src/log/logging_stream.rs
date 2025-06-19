//! Stream that logs errors as events.
//!
//! This stream can be used to wrap IMAP,
//! SMTP and HTTP streams so errors
//! that occur are logged before
//! they are processed.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

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

    /// Total number of bytes read.
    total_read: usize,

    /// Number of bytes read since the last flush.
    span_read: usize,

    /// First timestamp of successful non-zero read.
    ///
    /// Reset on flush.
    first_read_timestamp: Option<Instant>,

    /// Last non-zero read.
    last_read_timestamp: Instant,

    total_duration: Duration,
}

impl<S: SessionStream> LoggingStream<S> {
    pub fn new(inner: S, tag: String, account_id: u32, events: Events) -> Self {
        Self {
            inner,
            tag,
            account_id,
            events,
            total_read: 0,
            span_read: 0,
            first_read_timestamp: None,
            last_read_timestamp: Instant::now(),
            total_duration: Duration::ZERO,
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
        if n > 0 {
            let now = Instant::now();
            if projected.first_read_timestamp.is_none() {
                *projected.first_read_timestamp = Some(now);
            }
            *projected.last_read_timestamp = now;

            *projected.span_read = projected.span_read.saturating_add(n);

            let log_message = format!("{}: READING {}", projected.tag, n);
            projected.events.emit(Event {
                id: 0,
                typ: EventType::Info(log_message),
            });
        }

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
        let projected = self.project();

        if let Some(first_read_timestamp) = projected.first_read_timestamp.take() {
            let duration = projected.last_read_timestamp.duration_since(first_read_timestamp);

            *projected.total_read = projected.total_read.saturating_add(*projected.span_read);
            *projected.span_read = 0;
            *projected.total_duration = projected.total_duration.saturating_add(duration);

            let total_duration_secs = projected.total_duration.as_secs_f64();
            let throughput = if total_duration_secs > 0.0 {
                (*projected.total_read as f64) / total_duration_secs
            } else {
                0.0
            };

            let log_message = format!("{}: FLUSH: read={}, duration={}, {} kbps", projected.tag, *projected.total_read, total_duration_secs, throughput * 8e-3);

            projected.events.emit(Event {
                id: 0,
                typ: EventType::Info(log_message),
            });
        }

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
