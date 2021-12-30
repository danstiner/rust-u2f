use std::{
    cmp, fmt,
    fs::OpenOptions,
    io,
    os::unix::prelude::FileTypeExt,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{ready, FutureExt};
use pin_project::pin_project;
use std::io::{Read, Write};
use tokio::task::{self, JoinHandle};
use tracing::trace;

enum State {
    Ready(Vec<u8>),
    Reading(JoinHandle<io::Result<Vec<u8>>>),
}

/// A reference to a device driver on the system.
///
/// Character devices (also known as raw devices)
///
/// TODO
#[pin_project]
pub struct CharacterDevice {
    file: Arc<std::fs::File>,
    state: State,
}

impl CharacterDevice {
    pub async fn open(path: &Path) -> io::Result<Self> {
        let path = path.to_owned();
        let file = task::spawn_blocking(move || {
            let file = OpenOptions::new().read(true).write(true).open(path)?;
            if !file.metadata()?.file_type().is_char_device() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Not a character device",
                ));
            }
            Ok(file)
        })
        .await??;

        Ok(Self {
            file: Arc::new(file),
            state: State::Ready(vec![]),
        })
    }
}

impl futures::AsyncRead for CharacterDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.project();
        loop {
            match this.state {
                State::Ready(ref mut prev_read) => {
                    if prev_read.len() > 0 {
                        // Return leftover bytes from a previous read
                        let n = cmp::min(prev_read.len(), buf.len());
                        let mut remaining = prev_read.split_off(n);
                        std::mem::swap(prev_read, &mut remaining);
                        buf[..n].copy_from_slice(&remaining);
                        return Poll::Ready(Ok(n));
                    } else {
                        trace!("CharacterDevice::poll_read: Begin new async read");
                        // Spawn a new read on a worker thread
                        // TODO: Consider opening device in async mode instead
                        // TODO: Re-use read buffer instead of allocating every time
                        let file = Arc::clone(this.file);
                        let mut read = vec![0u8; buf.len()];
                        *this.state = State::Reading(task::spawn_blocking(move || {
                            (&*file).read(&mut read)?;
                            Ok(read)
                        }));
                    }
                }
                State::Reading(ref mut handle) => {
                    // Check if read is complete
                    let mut read = ready!(handle.poll_unpin(cx))??;

                    // If it is, copy as many bytes as fit into buf and split off the rest
                    let n = cmp::min(read.len(), buf.len());
                    let remaining = read.split_off(n);
                    buf[..n].copy_from_slice(&read);

                    // Store any remaining bytes that were split off
                    *this.state = State::Ready(remaining);

                    // Return how many bytes were copied into buf
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }
}

impl futures::AsyncWrite for CharacterDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        trace!("CharacterDevice::write; buf.len:{}", buf.len());
        // TODO: Async writes
        let file = Arc::clone(&mut self.project().file);
        Poll::Ready((&*file).write(buf))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // TODO: Async writes
        let file = Arc::clone(self.project().file);
        Poll::Ready((&*file).write_vectored(bufs))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let file = Arc::clone(self.project().file);
        // TODO: Async flush
        Poll::Ready((&*file).flush())
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl fmt::Debug for CharacterDevice {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_struct("CharacterDevice")
            .field("file", &self.file)
            .finish()
    }
}
