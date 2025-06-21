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

#[derive(Debug)]
struct ThroughputStats {
    /// Total number of bytes read.
    pub total_read: usize,

    /// Number of bytes read since the last flush.
    pub span_read: usize,

    /// First timestamp of successful non-zero read.
    ///
    /// Reset on flush.
    pub first_read_timestamp: Option<Instant>,

    /// Last non-zero read.
    pub last_read_timestamp: Instant,

    pub total_duration: Duration,

    /// Whether to collect throughput statistics or not.
    ///
    /// Disabled when read timeout is disabled,
    /// i.e. when we are in IMAP IDLE.
    pub enabled: bool,
}

impl ThroughputStats {
    fn new() -> Self {
        Self {
            total_read: 0,
            span_read: 0,
            first_read_timestamp: None,
            last_read_timestamp: Instant::now(),
            total_duration: Duration::ZERO,
            enabled: false,
        }
    }

    /// Returns throughput in bps.
    pub fn throughput(&self) -> Option<f64> {
        let total_duration_secs = self.total_duration.as_secs_f64();
        if total_duration_secs > 0.0 {
            Some((self.total_read as f64) / total_duration_secs)
        } else {
            None
        }
    }
}

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

    throughput: ThroughputStats,
}

impl<S: SessionStream> LoggingStream<S> {
    pub fn new(inner: S, tag: String, account_id: u32, events: Events) -> Self {
        Self {
            inner,
            tag,
            account_id,
            events,
            throughput: ThroughputStats::new(),
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

        let now = Instant::now();
        let res = projected.inner.poll_read(cx, buf);

        if projected.throughput.enabled {
            let first_read_timestamp =
            if let Some(first_read_timestamp) = projected.throughput.first_read_timestamp {
                first_read_timestamp
            } else {
                projected.throughput.first_read_timestamp = Some(now);
                now
            };

            let n = old_remaining - buf.remaining();
            if n > 0 {
                projected.throughput.last_read_timestamp = now;
                projected.throughput.span_read = projected.throughput.span_read.saturating_add(n);
            }

            let duration = projected
                .throughput
                .last_read_timestamp
                .duration_since(first_read_timestamp);

            let log_message = format!("{}: SPAN: {} {}", projected.tag, duration.as_secs_f64(), projected.throughput.span_read);
            projected.events.emit(Event {
                id: 0,
                typ: EventType::Info(log_message),
            });

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
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let projected = self.project();
        if let Some(first_read_timestamp) = projected.throughput.first_read_timestamp.take() {
            let duration = projected
                .throughput
                .last_read_timestamp
                .duration_since(first_read_timestamp);

            // Only measure when more than about 2 MTU is transferred.
            // We cannot measure throughput on small responses
            // like `A1000 OK`.
            if projected.throughput.span_read > 3000 {
                projected.throughput.total_read = projected
                    .throughput
                    .total_read
                    .saturating_add(projected.throughput.span_read);
                projected.throughput.total_duration =
                    projected.throughput.total_duration.saturating_add(duration);
            }

            projected.throughput.span_read = 0;
        }

        if let Some(throughput) = projected.throughput.throughput() {
            let log_message = format!("{}: FLUSH: {} kbps", projected.tag, throughput * 8e-3);

            projected.events.emit(Event {
                id: 0,
                typ: EventType::Info(log_message),
            });
        } else {
            let log_message = format!("{}: FLUSH: unknown throughput", projected.tag);

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
        self.throughput.enabled = timeout.is_some();

        self.inner.set_read_timeout(timeout)
    }
}
