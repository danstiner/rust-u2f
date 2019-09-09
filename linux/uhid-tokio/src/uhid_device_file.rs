use std::io;
use std::os::unix::io::{AsRawFd, RawFd};

use mio;
use mio::Evented;
use tokio::io::{AsyncRead, Read, Write};
use tokio::reactor::{Handle, PollEvented, PollEvented2};

#[derive(Debug)]
pub struct UHIDDeviceFile<E: Evented>(PollEvented2<E>);

impl<E: Evented> UHIDDeviceFile<E> {
    pub fn new(io: PollEvented2<E>) -> Self {
        UHIDDeviceFile(io)
    }
}

impl<E: Evented + Read> Read for UHIDDeviceFile<E> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<E: Evented + Read> AsyncRead for UHIDDeviceFile<E> {}

impl<E: Evented + Write> io::Write for UHIDDeviceFile<E> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.get_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.get_mut().flush()
    }
}
