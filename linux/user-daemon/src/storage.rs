use std::borrow::Borrow;
use std::io;
use std::path::PathBuf;

use slog::Logger;
use u2f_core::SecretStore;

use crate::config::{Config, ConfigFile, ConfigFilePath, SecretStoreType};
use crate::stores::file_store::FileStore;
use crate::stores::file_store_v2::FileStoreV2;
use crate::stores::secret_service_store::SecretServiceStore;
use crate::stores::UserSecretStore;

pub struct AppDirs {
    pub user_home_dir: PathBuf,
    pub config_dir: PathBuf,
    pub data_local_dir: PathBuf,
}

pub(crate) fn build(dirs: &AppDirs, log: &Logger) -> Result<Box<dyn SecretStore>, failure::Error> {
    let config = determine_config(dirs, log)?;
    let secret_store = build_secret_store(dirs, &config, log)?;
    migrate_legacy_file_store(dirs, secret_store.borrow(), log)?;
    Ok(secret_store.into_u2f_store())
}

fn determine_config(dirs: &AppDirs, log: &Logger) -> io::Result<Config> {
    let config_file_path = ConfigFilePath::from_dir(&dirs.config_dir);
    let config_file = match ConfigFile::load(config_file_path.clone())? {
        Some(config) => {
            info!(log, "Loaded configuration file"; "path" => config_file_path.get().display());
            config
        }
        None => {
            let secret_store_type: SecretStoreType;
            if SecretServiceStore::is_supported() {
                secret_store_type = SecretStoreType::SecretService;
            } else {
                secret_store_type = SecretStoreType::File;
            }
            let config = Config { secret_store_type };
            info!(log, "Creating configuration file"; "path" => config_file_path.get().display());
            ConfigFile::create(config_file_path, config)?
        }
    };
    Ok(config_file.config().clone())
}

fn build_secret_store(
    dirs: &AppDirs,
    config: &Config,
    log: &Logger,
) -> Result<Box<dyn UserSecretStore>, failure::Error> {
    match &config.secret_store_type {
        SecretStoreType::SecretService => {
            info!(
                log,
                "Storing secrets in your keychain using the D-Bus Secret Service API"
            );
            Ok(Box::new(SecretServiceStore::new()?))
        }
        SecretStoreType::File => {
            let store_dir = dirs.data_local_dir.as_path();
            warn!(log, "Storing secrets in an unencrypted file"; "dir" => store_dir.display());
            Ok(Box::new(FileStoreV2::new(store_dir)?))
        }
    }
}

fn migrate_legacy_file_store(
    dirs: &AppDirs,
    secret_store: &dyn UserSecretStore,
    log: &Logger,
) -> io::Result<()> {
    let legacy_file_store = FileStore::new(dirs.user_home_dir.join(".softu2f-secrets.json"))?;
    if legacy_file_store.exists() {
        info!(
            log,
            "copying secrets from legacy secret store to newer format"
        );
        for secret in legacy_file_store.iter()? {
            secret_store.add_secret(secret)?;
        }
        info!(log, "finished copying secrets");
        legacy_file_store.delete()?;
        info!(log, "deleted legacy secret store");
    }
    Ok(())
}
