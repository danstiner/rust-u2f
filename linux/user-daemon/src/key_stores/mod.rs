use crate::AAGUID;
use fido2_service::{AttestationSource, CredentialStore, Unspecified};
use thiserror::Error;
use tracing::info;

mod keyring;

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    SecretService(#[from] secret_service::Error),

    #[error("{0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Unspecified")]
    Unspecified,
}

impl From<Error> for fido2_service::Error {
    fn from(error: Error) -> Self {
        fido2_service::Error::Other(Box::new(error))
    }
}

impl From<Unspecified> for Error {
    fn from(_: Unspecified) -> Self {
        Error::Unspecified
    }
}

pub fn build() -> Result<Box<dyn CredentialStore<Error = Error>>, Error> {
    info!("Storing secrets on your default keyring using the D-Bus Secret Service API");
    let rng = ring::rand::SystemRandom::new();
    Ok(Box::new(fido2_service::SoftwareCryptoStore::new(
        keyring::Keyring::new()?,
        AAGUID,
        AttestationSource::generate(&rng)?, // TODO store attestation instead of regenerating
        rng,
    )))
}
