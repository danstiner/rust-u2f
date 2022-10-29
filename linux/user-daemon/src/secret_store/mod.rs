use std::io;

use fido2_authenticator_service::SecretStore;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use u2f_core::{ApplicationKey, Counter};

use crate::config::Config;
use file_store::FileStore;
use file_store_v2::FileStoreV2;
use secret_service_store::SecretServiceStore;

mod file_store;
mod file_store_v2;
mod secret_service_store;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Secret {
    application_key: ApplicationKey,
    counter: Counter,
}

#[derive(Serialize, Deserialize, Copy, Clone)]
pub enum SecretStoreType {
    File,
    SecretService,
}

impl Default for SecretStoreType {
    fn default() -> Self {
        if SecretServiceStore::is_supported() {
            SecretStoreType::SecretService
        } else {
            SecretStoreType::File
        }
    }
}

pub trait MutableSecretStore: SecretStore {
    fn add_secret(&self, secret: Secret) -> io::Result<()>;
}

pub fn build(config: &Config) -> io::Result<Box<dyn SecretStore<Error = io::Error>>> {
    match config.secret_store_type() {
        SecretStoreType::SecretService => {
            info!("Storing secrets in your keychain using the D-Bus Secret Service API");
            let store = SecretServiceStore::new()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
            migrate_legacy_file_store(config, &store)?;
            Ok(Box::new(store))
        }
        SecretStoreType::File => {
            let store = FileStoreV2::new(config.data_local_dir())?;
            warn!(path = %store.path().display(), "Storing secrets in an unencrypted file");
            migrate_legacy_file_store(config, &store)?;
            Ok(Box::new(store))
        }
    }
}

fn migrate_legacy_file_store<S>(config: &Config, store: &S) -> io::Result<()>
where
    S: MutableSecretStore,
{
    let legacy_file_store = FileStore::new(FileStore::default_path(config.home_dir()))?;
    if legacy_file_store.exists() {
        info!("Copying secrets from legacy secret store to newer format");
        for secret in legacy_file_store.iter()? {
            store.add_secret(secret)?;
        }
        info!("Finished copying secrets");
        legacy_file_store.delete()?;
        info!("Deleted legacy secret store");
    }
    Ok(())
}
