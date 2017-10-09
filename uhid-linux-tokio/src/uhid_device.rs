use std::fs::File;
use std::io::{self, Write};
use std::os::unix::io::FromRawFd;
use std::path::Path;

use futures::{Stream, Poll};
use nix;
use nix::fcntl;
use tokio_core::reactor::Handle;
use tokio_io::AsyncRead;

use poll_evented_read_wrapper::PollEventedRead;
use character_device_file::CharacterDeviceFile;
use character_device::{Encoder, Decoder, CharacterDevice, SyncSink};
use uhid_codec::*;

pub struct UHIDDevice<T> {
    inner: CharacterDevice<T, UHIDCodec, UHIDCodec>,
}

pub struct CreateParams {
    pub name: String,
    pub phys: String,
    pub uniq: String,
    pub bus: Bus,
    pub vendor: u32,
    pub product: u32,
    pub version: u32,
    pub country: u32,
    pub data: Vec<u8>,
}

// ===== impl UHIDDevice =====

impl UHIDDevice<PollEventedRead<CharacterDeviceFile<File>>> {
    pub fn create(
        handle: &Handle,
        params: CreateParams,
    ) -> io::Result<UHIDDevice<PollEventedRead<CharacterDeviceFile<File>>>> {
        Self::create_with_path(Path::new("/dev/uhid"), handle, params)
    }

    pub fn create_with_path(
        path: &Path,
        handle: &Handle,
        params: CreateParams,
    ) -> io::Result<UHIDDevice<PollEventedRead<CharacterDeviceFile<File>>>> {
        let fd = fcntl::open(
            path,
            fcntl::O_RDWR | fcntl::O_CLOEXEC | fcntl::O_NONBLOCK,
            nix::sys::stat::S_IRUSR | nix::sys::stat::S_IWUSR | nix::sys::stat::S_IRGRP |
                nix::sys::stat::S_IWGRP,
        ).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot open uhid-cdev {}: {}", path.to_str().unwrap(), err),
            )
        })?;
        let file: File = unsafe { File::from_raw_fd(fd) };
        let device_file = CharacterDeviceFile::new(file);
        Ok(Self::create_with(device_file.into_io(handle)?, params))
    }
}

impl<T> UHIDDevice<T>
where
    T: AsyncRead + Write,
{
    fn create_with(inner: T, params: CreateParams) -> UHIDDevice<T> {
        let mut device = UHIDDevice { inner: CharacterDevice::new(inner, UHIDCodec, UHIDCodec) };
        device
            .inner
            .send(InputEvent::Create {
                name: params.name,
                phys: params.phys,
                uniq: params.uniq,
                bus: params.bus,
                vendor: params.vendor,
                product: params.product,
                version: params.version,
                country: params.country,
                data: params.data,
            })
            .unwrap();
        device
    }

    pub fn send_input(&mut self, data: &[u8]) -> Result<(), <UHIDCodec as Encoder>::Error> {
        self.inner.send(InputEvent::Input { data: data.to_vec() })
    }

    pub fn destory(mut self) -> Result<(), <UHIDCodec as Encoder>::Error> {
        self.inner.send(InputEvent::Destroy)?;
        self.inner.close()?;
        Ok(())
    }
}

impl<T> Stream for UHIDDevice<T>
where
    T: AsyncRead,
{
    type Item = <UHIDCodec as Decoder>::Item;
    type Error = <UHIDCodec as Decoder>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.inner.poll()
    }
}
