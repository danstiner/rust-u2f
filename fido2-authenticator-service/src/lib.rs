extern crate async_trait;
extern crate base64;
extern crate byteorder;
extern crate futures;
extern crate hex;
extern crate lazy_static;
extern crate openssl;
extern crate pkg_version;
extern crate rand;
extern crate ring;
extern crate serde;
extern crate subtle;
extern crate tokio;
extern crate tower;

#[cfg(test)]
extern crate assert_matches;

mod serde_base64;
mod service;

use std::fmt::Debug;
use std::io;

use byteorder::{BigEndian, WriteBytesExt};
use thiserror::Error;
pub use tower::Service;
use tracing::error;
use u2f_core::{KeyHandle, AttestationCertificate};

pub use crate::service::Authenticator;

const SW_NO_ERROR: u16 = 0x9000; // The command completed successfully without error.
const SW_WRONG_DATA: u16 = 0x6A80; // The request was rejected due to an invalid key handle.
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985; // The request was rejected due to test-of-user-presence being required.
const _SW_COMMAND_NOT_ALLOWED: u16 = 0x6986;
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00; // The Instruction of the request is not supported.
const SW_WRONG_LENGTH: u16 = 0x6700; // The length of the request was invalid.
const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00; // The Class byte of the request is not supported.
const SW_UNKNOWN: u16 = 0x6F00; // Response status : No precise diagnosis

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug)]
pub enum StatusCode {
    NoError,
    TestOfUserPresenceNotSatisfied,
    InvalidKeyHandle,
    RequestLengthInvalid,
    RequestClassNotSupported,
    RequestInstructionNotSuppored,
    UnknownError,
}

impl StatusCode {
    pub fn write<W: WriteBytesExt>(&self, write: &mut W) {
        let value = match self {
            StatusCode::NoError => SW_NO_ERROR,
            StatusCode::TestOfUserPresenceNotSatisfied => SW_CONDITIONS_NOT_SATISFIED,
            StatusCode::InvalidKeyHandle => SW_WRONG_DATA,
            StatusCode::RequestLengthInvalid => SW_WRONG_LENGTH,
            StatusCode::RequestClassNotSupported => SW_CLA_NOT_SUPPORTED,
            StatusCode::RequestInstructionNotSuppored => SW_INS_NOT_SUPPORTED,
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

#[derive(Debug)]
pub struct Registration {
    user_public_key: Vec<u8>,
    key_handle: KeyHandle,
    attestation_certificate: AttestationCertificate,
    signature: Box<dyn Signature>,
}

#[derive(Debug)]
pub struct Authentication {
    counter: Counter,
    signature: Box<dyn Signature>,
    user_present: bool,
}

#[derive(Debug, Error)]
pub enum AuthenticateError {
    #[error("Approval required")]
    ApprovalRequired,

    #[error("Invalid key handle")]
    InvalidKeyHandle,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Signing error: {0}")]
    Signing(#[from] SignError),
}

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("Approval required")]
    ApprovalRequired,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Signing error: {0}")]
    Signing(#[from] SignError),
}

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
