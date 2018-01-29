use std::os::unix::io::{AsRawFd, RawFd};
use std::io;

use mio;
use tokio_core::reactor::{Handle, PollEvented};

use poll_evented_read_wrapper::PollEventedRead;

#[derive(Debug)]
pub struct CharacterDeviceFile<F>(F);

impl<F: AsRawFd> CharacterDeviceFile<F> {
    /// Wraps a character device-like object so it can be used with
    /// `tokio_core::reactor::Evented`
    /// ```
    pub fn new(file: F) -> Self {
        CharacterDeviceFile(file)
    }

    /// Converts into a pollable object that supports `tokio_io::AsyncRead`
    /// and `tokio_io::AsyncWrite`, making it suitable for `tokio_io::io::*`.
    ///
    /// ```ignore
    /// fn into_io(File<std::fs::File>, &Handle) -> Result<impl AsyncRead + AsyncWrite>;
    /// fn into_io(File<StdFile<StdinLock>>, &Handle) -> Result<impl AsyncRead + AsyncWrite>;
    /// fn into_io(File<impl AsRawFd + Read>, &Handle) -> Result<impl AsyncRead>;
    /// fn into_io(File<impl AsRawFd + Write>, &Handle) -> Result<impl AsyncWrite>;
    /// ```
    pub fn into_io(self, handle: &Handle) -> io::Result<PollEventedRead<Self>> {
        Ok(PollEventedRead::new(PollEvented::new(self, handle)?))
    }
}

impl<F: AsRawFd + io::Read> CharacterDeviceFile<F> {
    /// Converts into a pollable object that supports `tokio_io::AsyncRead`
    /// and `std::io::BufRead`, making it suitable for `tokio_io::io::read_*`.
    ///
    /// ```ignore
    /// fn into_reader(File<std::fs::File>, &Handle) -> Result<impl AsyncRead + BufRead>;
    /// fn into_reader(File<StdFile<StdinLock>>, &Handle) -> Result<impl AsyncRead + BufRead>;
    /// fn into_reader(File<impl AsRawFd + Read>, &Handle) -> Result<impl AsyncRead + BufRead>;
    /// ```
    pub fn into_reader(self, handle: &Handle) -> io::Result<io::BufReader<PollEventedRead<Self>>> {
        Ok(io::BufReader::new(self.into_io(handle)?))
    }
}

impl<F: AsRawFd> AsRawFd for CharacterDeviceFile<F> {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl<F: AsRawFd> mio::Evented for CharacterDeviceFile<F> {
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

impl<F: io::Read> io::Read for CharacterDeviceFile<F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<F: io::Write> io::Write for CharacterDeviceFile<F> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
