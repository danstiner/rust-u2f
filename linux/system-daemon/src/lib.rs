extern crate bincode;
extern crate bytes;
extern crate serde_derive;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const DEFAULT_SOCKET_PATH: &str = "/run/softu2f/softu2f.sock";

#[derive(Serialize, Deserialize)]
pub enum SocketInput {
    CreateDeviceRequest(CreateDeviceRequest),
    Report(Report),
}

#[derive(Serialize, Deserialize)]
pub enum SocketOutput {
    CreateDeviceResponse(Result<DeviceDescription, CreateDeviceError>),
    Report(Report),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateDeviceRequest;

#[derive(Serialize, Deserialize, Debug)]
pub struct DeviceDescription {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug, Error)]
pub enum CreateDeviceError {
    #[error("UHID device experienced an I/O Error")]
    IoError,
    #[error("UHID device already exists")]
    AlreadyExists,
    #[error("UHID device closed")]
    Closed,
    #[error("UHID device failed with unknown error")]
    Unknown,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Report(Vec<u8>);

impl Report {
    pub fn new(bytes: Vec<u8>) -> Report {
        Report(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Report {
        Report::new(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
