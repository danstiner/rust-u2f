use std::collections::HashMap;
use std::io;
use std::io::ErrorKind;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use fido2_api::RelyingPartyIdentifier;
use fido2_service::{
    CredentialHandle, CredentialProtection, PrivateKeyCredentialSource, SecretStore,
};
use secret_service::{Collection, EncryptionType, Error, Item, SecretService};
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
        todo!()
    }
}

#[async_trait(?Send)]
impl<'a> fido2_service::SecretStoreActual for SecretServiceStore<'a> {
    type Error = io::Error;

    fn put_discoverable(
        &mut self,
        credential: fido2_service::PrivateKeyCredentialSource,
    ) -> Result<(), Self::Error> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|_error| io::Error::new(ErrorKind::Other, "get_default_collection"))?;
        unlock_if_locked(&collection)?;
        let attributes = discoverable_credential_attributes(&credential);
        let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let label = format!("FIDO2 credential for {}", credential.rp_id.as_str());
        let secret = serde_json::to_string(&credential)
            .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
        let content_type = "application/json";
        let _item = collection
            .create_item(&label, attributes, secret.as_bytes(), false, content_type)
            .map_err(|_error| io::Error::new(ErrorKind::Other, "create_item"))?;
        Ok(())
    }

    fn get(
        &self,
        credential_handle: &CredentialHandle,
    ) -> Result<Option<fido2_service::PrivateKeyCredentialSource>, Self::Error> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        unlock_if_locked(&collection)?;
        let option = find_item(&collection, credential_handle)
            .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        if option.is_none() {
            return Ok(None);
        }
        let item = option.unwrap();
        let secret_bytes = item
            .get_secret()
            .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        let credential: PrivateKeyCredentialSource = serde_json::from_slice(&secret_bytes)
            .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
        Ok(Some(credential))
    }

    fn list_discoverable(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        let collection = self
            .service
            .get_default_collection()
            .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
        unlock_if_locked(&collection)?;

        let attributes = discoverable_search_attributes(rp_id);
        let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
        collection
            .search_items(attributes)
            .map_err(|_error| io::Error::new(ErrorKind::Other, "search_items"))?
            .into_iter()
            .map(|item| {
                let secret_bytes = item
                    .get_secret()
                    .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
                let credential: PrivateKeyCredentialSource = serde_json::from_slice(&secret_bytes)
                    .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
                Ok(CredentialHandle {
                    descriptor: fido2_api::PublicKeyCredentialDescriptor {
                        type_: credential.type_,
                        id: credential.id,
                    },
                    protection: CredentialProtection {
                        is_user_verification_required: false,
                        is_user_verification_optional_with_credential_id_list: false,
                    },
                    rp_id: credential.rp_id,
                })
            })
            .collect()
    }
}

// #[async_trait(?Send)]
// impl<'a> SecretStore for SecretServiceStore<'a> {
//     type Error = io::Error;

//     // fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
//     //     self.add_secret(Secret {
//     //         application_key: key.clone(),
//     //         counter: 0,
//     //     })
//     // }

//     // fn get_and_increment_counter(
//     //     &self,
//     //     application: &AppId,
//     //     handle: &KeyHandle,
//     // ) -> io::Result<Counter> {
//     //     let collection = self
//     //         .service
//     //         .get_default_collection()
//     //         .map_err(|_error| io::Error::new(ErrorKind::Other, "get_default_collection"))?;
//     //     let option = find_item(&collection, application, handle)
//     //         .map_err(|_error| io::Error::new(ErrorKind::Other, "find_item"))?;
//     //     if option.is_none() {
//     //         return Err(io::Error::new(ErrorKind::Other, "not found"));
//     //     }
//     //     let item = option.unwrap();
//     //     let secret_bytes = item
//     //         .get_secret()
//     //         .map_err(|_error| io::Error::new(ErrorKind::Other, "get_secret"))?;
//     //     let mut secret: Secret = serde_json::from_slice(&secret_bytes)
//     //         .map_err(|_error| io::Error::new(ErrorKind::Other, "from_slice"))?;

//     //     secret.counter += 1;

//     //     let secret_string = serde_json::to_string(&secret)
//     //         .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
//     //     item.set_secret(secret_string.as_bytes(), "application/json")
//     //         .map_err(|_error| io::Error::new(ErrorKind::Other, "get_attributes"))?;

//     //     let attributes = item
//     //         .get_attributes()
//     //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
//     //     let mut attributes: HashMap<_, _> = attributes.into_iter().collect();
//     //     attributes
//     //         .entry("times_used".to_string())
//     //         .and_modify(|value| {
//     //             let count = value.parse::<u64>().unwrap_or(0);
//     //             *value = (count + 1).to_string();
//     //         })
//     //         .or_insert_with(|| 0.to_string());
//     //     let attributes = attributes
//     //         .iter()
//     //         .map(|(key, value)| (key.as_str(), value.as_str()))
//     //         .collect();
//     //     item.set_attributes(attributes)
//     //         .map_err(|_error| io::Error::new(ErrorKind::Other, "set_attributes"))?;

//     //     let label = match try_reverse_app_id(application) {
//     //         Some(app_id) => format!("Universal 2nd Factor token for {}", app_id),
//     //         None => format!("Universal 2nd Factor token for {}", application.to_base64()),
//     //     };
//     //     item.set_label(&label)
//     //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;

//     //     Ok(secret.counter)
//     // }

//     // fn retrieve_application_key(
//     //     &self,
//     //     application: &AppId,
//     //     handle: &KeyHandle,
//     // ) -> io::Result<Option<ApplicationKey>> {
//     //     let collection = self
//     //         .service
//     //         .get_default_collection()
//     //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
//     //     let option = find_item(&collection, application, handle)
//     //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
//     //     if option.is_none() {
//     //         return Ok(None);
//     //     }
//     //     let item = option.unwrap();
//     //     let secret_bytes = item
//     //         .get_secret()
//     //         .map_err(|error| io::Error::new(ErrorKind::Other, error.to_string()))?;
//     //     let secret: Secret = serde_json::from_slice(&secret_bytes)
//     //         .map_err(|error| io::Error::new(ErrorKind::Other, error))?;
//     //     Ok(Some(secret.application_key))
//     // }
// }

fn u2f_search_attributes(app_id: &AppId, handle: &KeyHandle) -> Vec<(&'static str, String)> {
    vec![
        ("application", "com.github.danstiner.rust-u2f".to_string()),
        ("u2f_app_id_hash", app_id.to_base64()),
        ("u2f_key_handle", handle.to_base64()),
    ]
}

fn u2f_registration_attributes(app_id: &AppId, handle: &KeyHandle) -> Vec<(&'static str, String)> {
    let mut attributes = u2f_search_attributes(app_id, handle);
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

fn discoverable_credential_attributes(
    credential: &PrivateKeyCredentialSource,
) -> Vec<(&'static str, String)> {
    let since_the_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moved backwards");
    vec![
        ("application", "com.github.danstiner.rust-fido".to_string()),
        ("rp_id", credential.rp_id.to_string()),
        ("credential_id", base64::encode(credential.id.as_bytes())),
        (
            "user_handle",
            base64::encode(credential.user_handle.as_bytes()),
        ),
        ("xdg:schema", "com.github.danstiner.rust-fido".to_string()),
        ("times_used", 1.to_string()),
        ("created_at", since_the_epoch.as_secs().to_string()),
    ]
}

fn discoverable_search_attributes(rp_id: &RelyingPartyIdentifier) -> Vec<(&'static str, String)> {
    vec![
        ("application", "com.github.danstiner.rust-fido".to_string()),
        ("rp_id", rp_id.to_string()),
    ]
}

fn handle_search_attributes(handle: &CredentialHandle) -> Vec<(&'static str, String)> {
    vec![
        ("application", "com.github.danstiner.rust-fido".to_string()),
        ("rp_id", handle.rp_id.to_string()),
        (
            "credential_id",
            base64::encode(handle.descriptor.id.as_bytes()),
        ),
    ]
}

fn find_item<'a>(
    collection: &'a Collection<'a>,
    handle: &CredentialHandle,
) -> io::Result<Option<Item<'a>>> {
    let attributes = handle_search_attributes(handle);
    let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
    Ok(find_items(collection, attributes)?.into_iter().nth(0))
}

fn find_items<'a>(
    collection: &'a Collection<'a>,
    attributes: HashMap<&str, &str>,
) -> io::Result<Vec<Item<'a>>> {
    collection
        .search_items(attributes)
        .map_err(|_error| io::Error::new(ErrorKind::Other, "search_items"))
}

// fn u2f_find_item<'a>(
//     collection: &'a Collection<'a>,
//     app_id: &AppId,
//     handle: &KeyHandle,
// ) -> io::Result<Option<Item<'a>>> {
//     unlock_if_locked(collection)?;
//     let attributes = u2f_search_attributes(app_id, handle);
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
