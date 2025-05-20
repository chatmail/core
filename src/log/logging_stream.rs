//! Stream that logs errors as events.
//!
//! This stream can be used to wrap IMAP,
//! SMTP and HTTP streams so errors
//! that occur are logged before
//! they are processed.

use std::task::{Context, Poll};
use std::pin::Pin;
use std::time::Duration;

use pin_project::pin_project;

use crate::net::session::SessionStream;

use tokio::io::{AsyncWrite, AsyncRead, ReadBuf};

/// Stream that logs errors to the event channel.
#[derive(Debug)]
#[pin_project]
pub struct LoggingStream<S: SessionStream> {
    #[pin]
    inner: S,

    /// Name of the stream to distinguish log messages produced by it.
    name: String
}

impl<S: SessionStream> LoggingStream<S> {
    pub fn new(inner: S, name: String) -> Self {
        Self {
            inner,
            name
        }
    }
}

impl<S: SessionStream> AsyncRead for LoggingStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
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
