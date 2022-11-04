mod app_id;
mod attestation;
mod constants;
mod key_handle;
mod request;
mod response;
mod serde_base64;

use byteorder::{BigEndian, WriteBytesExt};
use std::fmt::Debug;
use thiserror::Error;

use constants::*;
pub use request::Request;
pub use response::Response;

#[derive(Debug)]
pub enum StatusCode {
    NoError,
    TestOfUserPresenceNotSatisfied,
    InvalidKeyHandle,
    UnknownError,
}

impl StatusCode {
    pub fn write<W: WriteBytesExt>(&self, write: &mut W) {
        let value = match self {
            StatusCode::NoError => SW_NO_ERROR,
            StatusCode::TestOfUserPresenceNotSatisfied => SW_CONDITIONS_NOT_SATISFIED,
            StatusCode::InvalidKeyHandle => SW_WRONG_DATA,
            StatusCode::UnknownError => SW_UNKNOWN,
        };
        write.write_u16::<BigEndian>(value).unwrap();
    }
}

#[derive(Debug, Error)]
pub enum SignError {}

pub type Counter = u32;

#[derive(Clone, Debug)]
pub struct Challenge([u8; 32]);

impl AsRef<[u8]> for Challenge {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub trait Signature: AsRef<[u8]> + Debug + Send {}

/// User presence byte [1 byte]. Bit 0 indicates whether user presence was verified.
/// If Bit 0 is is to 1, then user presence was verified. If Bit 0 is set to 0,
/// then user presence was not verified. The values of Bit 1 through 7 shall be 0;
/// different values are reserved for future use.
fn user_presence_byte(user_present: bool) -> u8 {
    let mut byte: u8 = 0b0000_0000;
    if user_present {
        byte |= 0b0000_0001;
    }
    byte
}
