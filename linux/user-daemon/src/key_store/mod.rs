use std::io;

use fido2_service::SecretStore;
use tracing::info;

use self::keyring::KeyRing;
use crate::AAGUID;

mod keyring;

pub fn build() -> io::Result<Box<dyn SecretStore<Error = io::Error>>> {
    info!("Storing secrets on your default keyring using the D-Bus Secret Service API");
    let store = KeyRing::new().map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
    Ok(Box::new(fido2_service::SimpleSecrets::new(store, AAGUID)))
}
