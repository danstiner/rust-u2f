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

#[cfg(test)]
extern crate assert_matches;

mod authenticator;
mod crypto;
mod storage;

use std::fmt::Debug;
use std::io;

use fido2_api::StatusCode;
use thiserror::Error;
use tracing::error;

// TODO hack
pub use crate::crypto::{AttestationSource, PrivateKeyCredentialSource, PrivateKeyDocument};
pub use crate::storage::{CredentialStorage, SoftwareCryptoStore};
pub use ring::error::Unspecified;

pub use crate::authenticator::{
    Authenticator, CredentialHandle, CredentialStore, KeyProtection, UserPresence,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,

    #[error("Invalid parameter")]
    InvalidParameter,

    #[error("Invalid option")]
    InvalidOption,

    #[error("Unspecified")]
    Unspecified,

    #[error("No credentials")]
    NoCredentials,

    #[error("Operation Denined")]
    OperationDenied,

    #[error(transparent)]
    Other(Box<dyn std::error::Error>),
}

impl From<Error> for StatusCode {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(_) => StatusCode::Other,
            Error::UnsupportedAlgorithm => StatusCode::UnsupportedAlgorithm,
            Error::InvalidOption => StatusCode::InvalidOption,
            Error::InvalidParameter => StatusCode::InvalidParameter,
            Error::Unspecified => StatusCode::Other,
            Error::NoCredentials => StatusCode::NoCredentials,
            Error::OperationDenied => StatusCode::OperationDenied,
            Error::Other(_) => StatusCode::Other,
        }
    }
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Error::Unspecified
    }
}

#[derive(Debug, Error)]
pub enum SignError {}

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
