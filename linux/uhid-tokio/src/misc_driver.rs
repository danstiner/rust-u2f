use std::fs::File;
use std::io;
use std::os::unix::io::FromRawFd;
use std::path::Path;

use nix::{fcntl, libc, sys};
use tokio::prelude::Read;
use tokio::reactor::PollEvented2;
use tokio_io::AsyncRead;

use character_device::CharacterDevice;

pub struct MiscDriver(PollEvented2<CharacterDevice<File>>);

impl MiscDriver {
    pub fn open(path: &Path) -> io::Result<MiscDriver> {
        let fd = fcntl::open(
            path,
            fcntl::OFlag::from_bits(libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK).unwrap(),
            sys::stat::Mode::from_bits(libc::S_IRUSR | libc::S_IWUSR | libc::S_IRGRP | libc::S_IWGRP).unwrap(),
        ).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot open uhid-cdev {:?}: {}", path, err),
            )
        })?;
        let file = unsafe { File::from_raw_fd(fd) };
        let character_device = CharacterDevice::new(file);
        Ok(MiscDriver(PollEvented2::new(character_device)))
    }
}

impl Read for MiscDriver {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl AsyncRead for MiscDriver {}

impl io::Write for MiscDriver {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.get_mut().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.get_mut().flush()
    }
}
