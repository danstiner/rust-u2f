use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use mio;

#[derive(Debug)]
pub struct CharacterDevice<F>(F);

impl<F: AsRawFd> CharacterDevice<F> {
    /// Wraps a character device-like object so it can be used with
    /// `tokio_core::reactor::Evented`
    /// ```
    pub fn new(file: F) -> Self {
        CharacterDevice(file)
    }
}

impl<F: AsRawFd> AsRawFd for CharacterDevice<F> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl<F: AsRawFd> mio::Evented for CharacterDevice<F> {
    fn register(
        &self,
        poll: &mio::Poll,
        token: mio::Token,
        interest: mio::Ready,
        opts: mio::PollOpt,
    ) -> io::Result<()> {
        mio::unix::EventedFd(&self.as_raw_fd()).register(poll, token, interest, opts)
    }

    fn reregister(
        &self,
        poll: &mio::Poll,
        token: mio::Token,
        interest: mio::Ready,
        opts: mio::PollOpt,
    ) -> io::Result<()> {
        mio::unix::EventedFd(&self.as_raw_fd()).reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        mio::unix::EventedFd(&self.as_raw_fd()).deregister(poll)
    }
}

impl<F: io::Read> io::Read for CharacterDevice<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<F: io::Write> io::Write for CharacterDevice<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
