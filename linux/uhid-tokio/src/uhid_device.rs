use std::io::{self, Write};
use std::path::Path;

use futures::{Async, AsyncSink, Poll, Sink, StartSend, Stream};
use slog;
use slog::Drain;
use slog_stdlog;
use tokio_io::AsyncRead;

use codec::*;
use misc_driver::MiscDriver;
use transport::{Decoder, Encoder, SyncSink, Transport};

pub struct UHIDDevice<T> {
    inner: Transport<T, Codec, Codec>,
    logger: slog::Logger,
}

/// Parameters used to create UHID devices
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

impl UHIDDevice<MiscDriver> {
    /// Create a UHID device using '/dev/uhid'
    pub fn create<L: Into<Option<slog::Logger>>>(
        params: CreateParams,
        logger: L,
    ) -> io::Result<UHIDDevice<MiscDriver>> {
        Self::create_with_path(Path::new("/dev/uhid"), params, logger)
    }

    /// Create a UHID device using the specified character misc-device file path
    pub fn create_with_path<L: Into<Option<slog::Logger>>>(
        path: &Path,
        params: CreateParams,
        logger: L,
    ) -> io::Result<UHIDDevice<MiscDriver>> {
        Ok(Self::create_with(MiscDriver::open(path)?, params, logger))
    }
}

impl<T> UHIDDevice<T>
where
    T: AsyncRead + Write,
{
    fn create_with<L: Into<Option<slog::Logger>>>(
        inner: T,
        params: CreateParams,
        logger: L,
    ) -> UHIDDevice<T> {
        let logger = logger
            .into()
            .unwrap_or(slog::Logger::root(slog_stdlog::StdLog.fuse(), o!()));
        let logger = logger.new(o!("uhid_device" => params.name.to_string()));
        let mut device = UHIDDevice {
            inner: Transport::new(inner, Codec, Codec, logger.clone()),
            logger: logger.clone(),
        };
        debug!(logger, "Sending create device event");
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
        debug!(logger, "Sent create device event");
        device
    }

    /// Send a HID packet to the UHID device
    pub fn send_input(&mut self, data: &[u8]) -> Result<(), <Codec as Encoder>::Error> {
        debug!(self.logger, "send input");
        self.inner.send(InputEvent::Input {
            data: data.to_vec(),
        })
    }

    /// Send a 'destroy' to the UHID device and close it
    pub fn destroy(mut self) -> Result<(), <Codec as Encoder>::Error> {
        debug!(self.logger, "destroy");
        self.inner.send(InputEvent::Destroy)?;
        self.inner.close()?;
        Ok(())
    }
}

impl<T: AsyncRead> Stream for UHIDDevice<T> {
    type Item = <Codec as Decoder>::Item;
    type Error = <Codec as Decoder>::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        debug!(self.logger, "Stream::poll");
        self.inner.poll()
    }
}

impl<T: Write> Sink for UHIDDevice<T> {
    type SinkItem = <Codec as Encoder>::Item;
    type SinkError = <Codec as Encoder>::Error;

    fn start_send(&mut self, item: Self::SinkItem) -> StartSend<Self::SinkItem, Self::SinkError> {
        debug!(self.logger, "Sink::start_send");
        self.inner.send(item)?;
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), Self::SinkError> {
        debug!(self.logger, "Sink::poll_complete");
        self.inner.flush()?;
        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Result<Async<()>, Self::SinkError> {
        debug!(self.logger, "Sink::close");
        self.inner.close()?;
        Ok(Async::Ready(()))
    }
}
