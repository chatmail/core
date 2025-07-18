use std::io::IoSlice;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

use pin_project::pin_project;

use crate::net::SessionStream;

/// Stream that remembers the first error
/// and keeps returning it afterwards.
///
/// It is needed to avoid accidentally using
/// the stream after read timeout.
#[derive(Debug)]
#[pin_project]
pub(crate) struct ErrorCapturingStream<T: AsyncRead + AsyncWrite + std::fmt::Debug> {
    #[pin]
    inner: T,

    /// If true, the stream has already returned an error once.
    ///
    /// All read and write operations return error in this case.
    is_broken: bool,
}

impl<T: AsyncRead + AsyncWrite + std::fmt::Debug> ErrorCapturingStream<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            is_broken: false,
        }
    }

    /// Gets a reference to the underlying stream.
    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    /// Gets a pinned mutable reference to the underlying stream.
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut T> {
        self.project().inner
    }
}

impl<T: AsyncRead + AsyncWrite + std::fmt::Debug> AsyncRead for ErrorCapturingStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let this = self.project();
        if *this.is_broken {
            return Poll::Ready(Err(io::Error::other("Broken stream")));
        }
        let res = this.inner.poll_read(cx, buf);
        if let Poll::Ready(Err(_)) = res {
            *this.is_broken = true;
        }
        res
    }
}

impl<T: AsyncRead + AsyncWrite + std::fmt::Debug> AsyncWrite for ErrorCapturingStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        if *this.is_broken {
            return Poll::Ready(Err(io::Error::other("Broken stream")));
        }
        let res = this.inner.poll_write(cx, buf);
        if let Poll::Ready(Err(_)) = res {
            *this.is_broken = true;
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        if *this.is_broken {
            return Poll::Ready(Err(io::Error::other("Broken stream")));
        }
        let res = this.inner.poll_flush(cx);
        if let Poll::Ready(Err(_)) = res {
            *this.is_broken = true;
        }
        res
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.project();
        if *this.is_broken {
            return Poll::Ready(Err(io::Error::other("Broken stream")));
        }
        let res = this.inner.poll_shutdown(cx);
        if let Poll::Ready(Err(_)) = res {
            *this.is_broken = true;
        }
        res
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        if *this.is_broken {
            return Poll::Ready(Err(io::Error::other("Broken stream")));
        }
        let res = this.inner.poll_write_vectored(cx, bufs);
        if let Poll::Ready(Err(_)) = res {
            *this.is_broken = true;
        }
        res
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

impl<T: SessionStream> SessionStream for ErrorCapturingStream<T> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.inner.set_read_timeout(timeout)
    }

    fn peer_addr(&self) -> anyhow::Result<SocketAddr> {
        self.inner.peer_addr()
    }
}
