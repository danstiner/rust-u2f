use std::{
    fmt, io,
    path::Path,
    pin::Pin,
    task::{Context, Poll},
};

use futures::ready;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// Character devices do not support seeking
#[pin_project]
pub struct CharacterDevice(#[pin] tokio::fs::File);

impl CharacterDevice {
    pub async fn open(path: &Path) -> Result<Self, io::Error> {
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .await?;
        Ok(Self(file))
    }
}

impl futures::AsyncRead for CharacterDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut buf = ReadBuf::new(buf);
        ready!(self.project().0.poll_read(cx, &mut buf))?;
        Poll::Ready(Ok(buf.filled().len()))
    }
}

impl futures::AsyncWrite for CharacterDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.project().0.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().0.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.project().0.poll_shutdown(cx)
    }
}

impl fmt::Debug for CharacterDevice {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("CharacterDevice")
            .field("file", &self.0)
            .finish()
    }
}
