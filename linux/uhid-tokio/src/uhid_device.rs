use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::{Sink, Stream};
use tokio::io::AsyncWriteExt;
use tracing::{debug, trace};

use crate::codec::*;
use crate::transport::{Decoder, Encoder, SyncSink, Transport};

pub struct UhidDevice {
    file: tokio::fs::File,
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

impl UhidDevice {
    /// Create a UHID device using '/dev/uhid'
    pub fn create<L: Into<Option<slog::Logger>>>(
        params: CreateParams,
        logger: L,
    ) -> io::Result<UHIDDevice<MiscDriver>> {
        Self::create_with_path(Path::new("/dev/uhid"), params)
    }

    /// Create a UHID device using the specified character misc-device file path
    pub fn create_with_path<L: Into<Option<slog::Logger>>>(
        path: &Path,
        params: CreateParams,
        logger: L,
    ) -> io::Result<UHIDDevice<MiscDriver>> {
        Ok(Self::create_with(CharDevice::open(path)?, params))
    }
}

impl UhidDevice {
    fn create_with(inner: T, params: CreateParams) -> Self {
        // let log = log
        //     .into()
        //     .unwrap_or(slog::Logger::root(slog_stdlog::StdLog.fuse(), o!()));
        // let log = log.new(o!("uhid_device" => params.name.to_string()));
        let mut device = UhidDevice {
            inner: Transport::new(inner, Codec, Codec),
        };
        debug!("Sending create device event");
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
        debug!("Sent create device event");
        device
    }

    /// Send a HID packet to the UHID device
    pub fn send_input(&mut self, data: &[u8]) -> Result<(), <Codec as Encoder>::Error> {
        debug!("send input");
        self.inner.send(InputEvent::Input {
            data: data.to_vec(),
        })
    }

    /// Sends a 'destroy' event to the UHID device and then close it
    pub async fn destroy(mut self) -> Result<(), io::Error> {
        debug!("destroy");
        self.file.send(InputEvent::Destroy)?;
        self.file.flush().await?;
        Ok(())
    }
}

impl Stream for UhidDevice {
    type Item = InputEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        trace!("UhidDevice.poll_next");
        self.inner.poll_next(cx)
    }
}

impl Sink<OutputEvent> for UhidDevice {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: OutputEvent) -> Result<(), Self::Error> {
        self.inner.start_send(item)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_close(cx)
    }
}
