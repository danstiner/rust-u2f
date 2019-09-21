use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::time::{SystemTime, UNIX_EPOCH};

use failure::Error;
use secret_service::{Collection, EncryptionType, Item, SecretService, SsError};
use serde_json;
use u2f_core::{AppId, ApplicationKey, Counter, KeyHandle, SecretStore, try_reverse_app_id};

use stores::Secret;

#[derive(Debug, Fail)]
pub enum SecretServiceError {
    #[fail(display = "crypto error {}", _0)]
    Crypto(String),
    #[fail(display = "D-Bus error {} {}", _0, _1)]
    DBus(String, String),
    #[fail(display = "object locked")]
    Locked,
    #[fail(display = "no result found")]
    NoResult,
    #[fail(display = "failed to parse D-Bus output")]
    Parse,
    #[fail(display = "prompt dismissed")]
    Prompt,
}

impl From<secret_service::SsError> for SecretServiceError {
    fn from(err: SsError) -> Self {
        match err {
            SsError::Crypto(err) => SecretServiceError::Crypto(err),
            SsError::Dbus(err) => SecretServiceError::DBus(
                err.name().unwrap_or("").into(),
                err.message().unwrap_or("").into()),
            SsError::Locked => SecretServiceError::Locked,
            SsError::NoResult => SecretServiceError::NoResult,
            SsError::Parse => SecretServiceError::Parse,
            SsError::Prompt => SecretServiceError::Prompt,
        }
    }
}

pub struct SecretServiceStore {
    service: SecretService,
}

impl SecretServiceStore {
    pub fn new() -> Result<SecretServiceStore, Error> {
        let service = SecretService::new(EncryptionType::Dh).map_err(|err| SecretServiceError::from(err))?;
        Ok(SecretServiceStore {
            service,
        })
    }

    pub fn add_secret(&self, secret: Secret) -> io::Result<()> {
        let collection = self.service.get_default_collection().map_err(|error| io::Error::new(ErrorKind::Other, "get_default_collection"))?;
        collection.ensure_unlocked().map_err(|error| io::Error::new(ErrorKind::Other, "to_vec"))?;
        let attributes = registration_attributes(&secret.application_key.application, &secret.application_key.handle);
        let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let label = match try_reverse_app_id(&secret.application_key.application) {
            Some(app_id) => format!("Universal 2nd Factor token for {}", app_id),
            None => format!("Universal 2nd Factor token for {}", secret.application_key.application.to_base64()),
        };
        let secret = serde_json::to_string(&Secret {
            application_key: secret.application_key.clone(),
            counter: secret.counter,
        }).map_err(|error| io::Error::new(ErrorKind::Other, error))?;
        let content_type = "application/json";
        let item = collection.create_item(&label, attributes, secret.as_bytes(), false, content_type).map_err(|error| io::Error::new(ErrorKind::Other, "create_item"))?;
        Ok(())
    }
}

impl SecretStore for SecretServiceStore {
    fn add_application_key(
        &self,
        key: &ApplicationKey,
    ) -> io::Result<()> {
        self.add_secret(Secret { application_key: key.clone(), counter: 0 })
    }

    fn get_and_increment_counter(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Counter> {
        let collection = self.service.get_default_collection().map_err(|error| io::Error::new(ErrorKind::Other, "get_default_collection"))?;
        let option = find_item(&collection, application, handle).map_err(|error| io::Error::new(ErrorKind::Other, "find_item"))?;
        if option.is_none() {
            return Err(io::Error::new(ErrorKind::Other, "not found"));
        }
        let item = option.unwrap();
        let secret_bytes = item.get_secret().map_err(|error| io::Error::new(ErrorKind::Other, "get_secret"))?;
        let mut secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|error| io::Error::new(ErrorKind::Other, "from_slice"))?;

        secret.counter += 1;

        let secret_string = serde_json::to_string(&secret).map_err(|error| io::Error::new(ErrorKind::Other, error))?;
        item.set_secret(secret_string.as_bytes(), "application/json").map_err(|error| io::Error::new(ErrorKind::Other, "get_attributes"))?;

        let attributes = item.get_attributes().map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        let mut attributes: HashMap<_, _> = attributes.into_iter().collect();
        attributes.entry("times_used".to_string()).and_modify(|value| {
            let count = value.parse::<u32>().unwrap_or(0);
            *value = (count + 1).to_string();
        }).or_insert(0.to_string());
        let mut attributes: Vec<(&str, &str)> = attributes.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();
        attributes.sort_by_cached_key(|(key, _)| key.to_owned());
        item.set_attributes(attributes).map_err(|error| io::Error::new(ErrorKind::Other, "get_attributes"))?;

        let label = match try_reverse_app_id(application) {
            Some(app_id) => format!("Universal 2nd Factor token for {}", app_id),
            None => format!("Universal 2nd Factor token for {}", application.to_base64()),
        };
        item.set_label(&label).map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;

        Ok(secret.counter)
    }

    fn retrieve_application_key(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Option<ApplicationKey>> {
        let collection = self.service.get_default_collection().map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        let option = find_item(&collection, application, handle).map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        if option.is_none() {
            return Ok(None);
        }
        let item = option.unwrap();
        let secret_bytes = item.get_secret().map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        let secret: Secret = serde_json::from_slice(&secret_bytes).map_err(|error| io::Error::new(ErrorKind::Other, error))?;
        Ok(Some(secret.application_key))
    }
}

fn search_attributes(app_id: &AppId, handle: &KeyHandle) -> Vec<(&'static str, String)> {
    vec![
        ("application", "com.github.danstiner.rust-u2f".to_string()),
        ("u2f_app_id_hash", app_id.to_base64()),
        ("u2f_key_handle", handle.to_base64()),
        ("xdg:schem", "com.github.danstiner.rust-u2f".to_string())
    ]
}

fn registration_attributes(app_id: &AppId, handle: &KeyHandle) -> Vec<(&'static str, String)> {
    let mut attributes = search_attributes(app_id, handle);
    attributes.push(("times_used", 0.to_string()));

    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("time moved backwards");
    attributes.push(("date_registered", since_the_epoch.as_secs().to_string()));

    match try_reverse_app_id(app_id) {
        Some(id) => attributes.push(("u2f_app_id", id)),
        None => {}
    };

    attributes
}

fn find_item<'a>(
    collection: &'a Collection<'a>,
    app_id: &AppId,
    handle: &KeyHandle,
) -> io::Result<Option<Item<'a>>> {
    collection.ensure_unlocked().map_err(|error| io::Error::new(ErrorKind::Other, "ensure_unlocked"))?;
    let attributes = search_attributes(app_id, handle);
    let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let mut result = collection.search_items(attributes).map_err(|error| io::Error::new(ErrorKind::Other, "search_items"))?;
    Ok(result.pop())
}

#[cfg(test)]
mod tests {
    use u2f_core::PrivateKey;

    use super::*;

    #[test]
    fn todo() {}
}
