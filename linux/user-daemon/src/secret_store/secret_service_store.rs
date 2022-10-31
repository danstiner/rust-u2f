use std::io;
use std::io::ErrorKind;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fido2_service::{CredentialHandle, SecretStore};
use secret_service::{Collection, EncryptionType, Error, SecretService};
use serde_json;
use u2f_core::{try_reverse_app_id, AppId, KeyHandle};

use crate::secret_store::{MutableSecretStore, Secret};

pub struct SecretServiceStore<'a> {
    service: SecretService<'a>,
}

impl SecretServiceStore<'_> {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            service: SecretService::new(EncryptionType::Dh)?,
        })
    }

    pub fn is_supported() -> bool {
        SecretServiceStore::new().is_ok()
    }
}

impl<'a> MutableSecretStore for SecretServiceStore<'a> {
    fn add_secret(&self, secret: Secret) -> io::Result<()> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_error| io::Error::new(ErrorKind::Other, "get_default_collection"))?;
        unlock_if_locked(&collection)?;
        let attributes = registration_attributes(
            &secret.application_key.application,
            &secret.application_key.handle,
        );
        let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let label = match try_reverse_app_id(&secret.application_key.application) {
            Some(app_id) => format!("Universal 2nd Factor token for {}", app_id),
            None => format!(
                "Universal 2nd Factor token for {}",
                secret.application_key.application.to_base64()
            ),
        };
        let secret = serde_json::to_string(&Secret {
            application_key: secret.application_key.clone(),
            counter: secret.counter,
        })
        .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
        let content_type = "application/json";
        let _item = collection
            .create_item(&label, attributes, secret.as_bytes(), false, content_type)
            .map_err(|_error| io::Error::new(ErrorKind::Other, "create_item"))?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl<'a> SecretStore for SecretServiceStore<'a> {
    type Error = io::Error;

    async fn make_credential(
        &self,
        _pub_key_cred_params: &fido2_api::PublicKeyCredentialParameters,
        _rp_id: &fido2_api::RelyingPartyIdentifier,
        _user_id: &fido2_api::UserHandle,
    ) -> Result<CredentialHandle, Self::Error> {
        todo!()
    }

    async fn attest(
        &self,
        _rp_id: &fido2_api::RelyingPartyIdentifier,
        _credential_descriptor: &CredentialHandle,
        _client_data_hash: &fido2_api::Sha256,
        _user_present: bool,
        _user_verified: bool,
    ) -> Result<
        (
            fido2_api::AuthenticatorData,
            fido2_api::AttestationStatement,
        ),
        Self::Error,
    > {
        todo!()
    }

    async fn assert(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        credential_handle: &CredentialHandle,
        client_data_hash: &fido2_api::Sha256,
        user_present: bool,
        user_verified: bool,
    ) -> Result<(fido2_api::AuthenticatorData, fido2_api::Signature), Self::Error> {
        todo!()
    }

    async fn list_discoverable_credentials(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        todo!()
    }

    async fn list_specified_credentials(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        allow_list: &[fido2_api::PublicKeyCredentialDescriptor],
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        todo!()
    }

    // fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
    //     self.add_secret(Secret {
    //         application_key: key.clone(),
    //         counter: 0,
    //     })
    // }

    // fn get_and_increment_counter(
    //     &self,
    //     application: &AppId,
    //     handle: &KeyHandle,
    // ) -> io::Result<Counter> {
    //     let collection = self
    //         .service
    //         .get_default_collection()
    //         .map_err(|_error| io::Error::new(ErrorKind::Other, "get_default_collection"))?;
    //     let option = find_item(&collection, application, handle)
    //         .map_err(|_error| io::Error::new(ErrorKind::Other, "find_item"))?;
    //     if option.is_none() {
    //         return Err(io::Error::new(ErrorKind::Other, "not found"));
    //     }
    //     let item = option.unwrap();
    //     let secret_bytes = item
    //         .get_secret()
    //         .map_err(|_error| io::Error::new(ErrorKind::Other, "get_secret"))?;
    //     let mut secret: Secret = serde_json::from_slice(&secret_bytes)
    //         .map_err(|_error| io::Error::new(ErrorKind::Other, "from_slice"))?;

    //     secret.counter += 1;

    //     let secret_string = serde_json::to_string(&secret)
    //         .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
    //     item.set_secret(secret_string.as_bytes(), "application/json")
    //         .map_err(|_error| io::Error::new(ErrorKind::Other, "get_attributes"))?;

    //     let attributes = item
    //         .get_attributes()
    //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
    //     let mut attributes: HashMap<_, _> = attributes.into_iter().collect();
    //     attributes
    //         .entry("times_used".to_string())
    //         .and_modify(|value| {
    //             let count = value.parse::<u64>().unwrap_or(0);
    //             *value = (count + 1).to_string();
    //         })
    //         .or_insert_with(|| 0.to_string());
    //     let attributes = attributes
    //         .iter()
    //         .map(|(key, value)| (key.as_str(), value.as_str()))
    //         .collect();
    //     item.set_attributes(attributes)
    //         .map_err(|_error| io::Error::new(ErrorKind::Other, "set_attributes"))?;

    //     let label = match try_reverse_app_id(application) {
    //         Some(app_id) => format!("Universal 2nd Factor token for {}", app_id),
    //         None => format!("Universal 2nd Factor token for {}", application.to_base64()),
    //     };
    //     item.set_label(&label)
    //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;

    //     Ok(secret.counter)
    // }

    // fn retrieve_application_key(
    //     &self,
    //     application: &AppId,
    //     handle: &KeyHandle,
    // ) -> io::Result<Option<ApplicationKey>> {
    //     let collection = self
    //         .service
    //         .get_default_collection()
    //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
    //     let option = find_item(&collection, application, handle)
    //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
    //     if option.is_none() {
    //         return Ok(None);
    //     }
    //     let item = option.unwrap();
    //     let secret_bytes = item
    //         .get_secret()
    //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
    //     let secret: Secret = serde_json::from_slice(&secret_bytes)
    //         .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
    //     Ok(Some(secret.application_key))
    // }
}

fn search_attributes(app_id: &AppId, handle: &KeyHandle) -> Vec<(&'static str, String)> {
    vec![
        ("application", "com.github.danstiner.rust-u2f".to_string()),
        ("u2f_app_id_hash", app_id.to_base64()),
        ("u2f_key_handle", handle.to_base64()),
    ]
}

fn registration_attributes(app_id: &AppId, handle: &KeyHandle) -> Vec<(&'static str, String)> {
    let mut attributes = search_attributes(app_id, handle);
    attributes.push(("xdg:schema", "com.github.danstiner.rust-u2f".to_string()));
    attributes.push(("times_used", 0.to_string()));

    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("time moved backwards");
    attributes.push(("date_registered", since_the_epoch.as_secs().to_string()));

    match try_reverse_app_id(app_id) {
        Some(id) => attributes.push(("u2f_app_id", id)),
        None => {}
    };

    attributes
}

// fn find_item<'a>(
//     collection: &'a Collection<'a>,
//     app_id: &AppId,
//     handle: &KeyHandle,
// ) -> io::Result<Option<Item<'a>>> {
//     unlock_if_locked(collection)?;
//     let attributes = search_attributes(app_id, handle);
//     let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
//     let mut result = collection
//         .search_items(attributes)
//         .map_err(|_error| io::Error::new(ErrorKind::Other, "search_items"))?;
//     Ok(result.pop())
// }

fn unlock_if_locked(collection: &Collection) -> io::Result<()> {
    if collection
        .is_locked()
        .map_err(|_error| io::Error::new(ErrorKind::Other, "is_locked"))?
    {
        collection
            .unlock()
            .map_err(|_error| io::Error::new(ErrorKind::Other, "unlock"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn todo() {}
}
