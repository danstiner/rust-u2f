use std::io;
use std::path::Path;
use std::fs::File;
use std::fs::OpenOptions;

use tokio_core::reactor::PollEvented;
use tokio_core;
use tokio_file_unix;
use futures;
use futures::{future, Future};
use futures::{Async, stream, Stream, Sink, IntoFuture, Poll, StartSend};
use tokio_io::{AsyncRead, AsyncWrite};

use uhid_codec::*;
use raw_device::{Encoder, Decoder, RawDevice};

pub struct UHIDDevice<T> {
    inner: RawDevice<T, UHIDCodec, UHIDCodec>,
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

impl UHIDDevice<PollEvented<tokio_file_unix::File<File>>>
{
    pub fn create(params: CreateParams) -> io::Result<UHIDDevice<PollEvented<tokio_file_unix::File<File>>>> {
        Self::create_with_path(Path::new("/dev/uhid"), params)
    }

    pub fn create_with_path(path: &Path, params: CreateParams) -> io::Result<UHIDDevice<PollEvented<tokio_file_unix::File<File>>>> {
        let mut core = tokio_core::reactor::Core::new()?;
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let handle = core.handle();
        let unix_file = tokio_file_unix::File::new_nb(file)?;
        let io = unix_file.into_io(&handle)?;
        Ok(Self::create_with(io, params))
    }
}

impl<T> UHIDDevice<T>
    where T: AsyncRead + AsyncWrite,
{
    fn create_with(inner: T, params: CreateParams) -> UHIDDevice<T> {
        let device = UHIDDevice {
            inner: RawDevice::new(inner, UHIDCodec, UHIDCodec),
        };
        device.send(InputEvent::Create {
            name: params.name,
            phys: params.phys,
            uniq: params.uniq,
            bus: params.bus,
            vendor: params.vendor,
            product: params.product,
            version: params.version,
            country: params.country,
            data: params.data,
        }).wait().unwrap()
    }

    pub fn send_input(self, data: &[u8]) -> futures::sink::Send<Self> {
        self.send(InputEvent::Input { data: data.to_vec() })
    }
}

impl<T> Sink for UHIDDevice<T>
    where T: AsyncWrite,
{
    type SinkItem = <UHIDCodec as Encoder>::Item;
    type SinkError = <UHIDCodec as Encoder>::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        self.inner.start_send(item)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        self.inner.poll_complete()
    }

    fn close(&mut self) -> Poll<(), Self::SinkError> {
        self.send(InputEvent::Destroy).wait()?;
        Ok(try!(self.inner.shutdown()))
    }
}
