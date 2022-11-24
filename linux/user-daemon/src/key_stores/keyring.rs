use super::Error;
use async_trait::async_trait;
use fido2_api::{
    PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
    RelyingPartyIdentifier, Sha256, UserHandle,
};
use fido2_service::{CredentialHandle, PrivateKeyCredentialSource, PrivateKeyDocument};
use p256::pkcs8::EncodePrivateKey;
use secret_service::EncryptionType;
use serde::{Deserialize, Serialize};
use serde_with::base64::Base64;
use serde_with::serde_as;
use std::collections::HashMap;
use std::fmt::Debug;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Store keys to a keyring service running in the user's login session.
///
/// Supports services such as GNOME keyring and KWallet that implement the Secret Service API.
/// Generally keys are encrypted at rest. The service may need to be unlocked by the user in order
/// to decrypt keys, if the service does not automatically unlock at login with the user's password.
pub(crate) struct Keyring<S: SecretService> {
    service: S,
}

impl Keyring<secret_service::SecretService<'_>> {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            service: secret_service::SecretService::new(EncryptionType::Dh)?,
        })
    }
}

impl<S: SecretService> Keyring<S> {
    fn collection(&self) -> Result<<S as SecretService>::Collection<'_>, Error> {
        let collection = self.service.get_default_collection()?;
        if collection.is_locked()? {
            collection.unlock()?;
        }
        Ok(collection)
    }
}

#[allow(clippy::let_and_return)]
#[async_trait(?Send)]
impl<S: SecretService> fido2_service::CredentialStorage for Keyring<S> {
    type Error = Error;

    fn put_discoverable(
        &mut self,
        credential: fido2_service::PrivateKeyCredentialSource,
    ) -> Result<(), Self::Error> {
        let collection = self.collection()?;

        // Delete existing discoverable credentials for this rp and user
        for i in collection.find_items(Attributes::discoverable_user_search(
            &credential.rp.id,
            &credential.user_handle,
        ))? {
            i.delete()?;
        }

        let secret = serde_json::to_string(&credential)?;
        let _item = collection.create_item(
            &format!("FIDO2 credential for {}", credential.rp),
            Attributes::new_discoverable_credential(&credential).get(),
            secret.as_bytes(),
            true,
            "application/json",
        )?;
        Ok(())
    }

    fn put_specific(
        &mut self,
        credential: fido2_service::PrivateKeyCredentialSource,
    ) -> Result<(), Self::Error> {
        let collection = self.collection()?;

        let secret = serde_json::to_vec(&credential)?;
        let _item = collection.create_item(
            &format!("FIDO2 credential for {}", credential.rp),
            Attributes::new_specific_credential(&credential).get(),
            &secret,
            true,
            "application/json",
        )?;
        Ok(())
    }

    fn get_and_increment_sign_count(
        &mut self,
        credential_handle: &CredentialHandle,
    ) -> Result<Option<PrivateKeyCredentialSource>, Self::Error> {
        let collection = self.collection()?;

        // Try to find an item based on the credential handle
        let item = collection.find_item(Attributes::handle_search(credential_handle))?;
        if let Some(item) = item {
            let secret = item.get_secret()?;
            let mut secret: PrivateKeyCredentialSource = serde_json::from_slice(&secret)?;
            secret.sign_count += 1;
            item.set_secret(&serde_json::to_vec(&secret)?, "application/json")?;
            return Ok(Some(secret));
        }

        // Fallback for legacy U2F registrations done with rust-u2f
        let item = collection.find_item(Attributes::u2f_handle_search(credential_handle))?;
        if let Some(item) = item {
            let secret = item.get_secret()?;
            let mut secret: LegacyU2FSecret = serde_json::from_slice(&secret)?;
            secret.counter += 1;
            item.set_secret(&serde_json::to_vec(&secret)?, "application/json")?;
            return Ok(Some(PrivateKeyCredentialSource {
                type_: PublicKeyCredentialType::PublicKey,
                id: secret.application_key.handle.try_into().unwrap(),
                rp: PublicKeyCredentialRpEntity {
                    id: RelyingPartyIdentifier::new("".to_owned()), // todo what to put here, we only have the rp id hash
                    name: "".to_owned(),
                },
                user_handle: UserHandle::new(vec![0]), // todo what to put here, we only have the user's public key
                sign_count: secret.counter,
                private_key_document: decode_sec1_pem_encoded_p256_key(&secret.application_key.key)
                    .unwrap(),
            }));
        }

        Ok(None)
    }

    fn list_discoverable(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        let collection = self.collection()?;
        let mut handles = Vec::new();

        for item in collection.search_items(Attributes::discoverable_search(rp_id).get())? {
            let secret = item.get_secret()?;
            let credential: PrivateKeyCredentialSource = serde_json::from_slice(&secret)?;
            handles.push(credential.handle());
        }

        Ok(handles)
    }

    fn list_specified(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        credential_list: &[PublicKeyCredentialDescriptor],
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        let collection = self.collection()?;
        let mut handles = Vec::new();

        for descriptor in credential_list {
            if let Some(item) =
                collection.find_item(Attributes::specific_search(rp_id, descriptor))?
            {
                let secret = item.get_secret()?;
                let credential: PrivateKeyCredentialSource = serde_json::from_slice(&secret)?;
                handles.push(credential.handle());
            }
        }

        Ok(handles)
    }
}

/// The org.freedesktop.Secret.Service interface for managing collections of secrets.
///
/// Only the subset of methods used in this module are included. This trait is primarily meant
/// to provide an abstraction where we can inject a faked implementation in tests.
pub(crate) trait SecretService {
    type Collection<'a>: Collection
    where
        Self: 'a;

    fn get_default_collection(&self) -> Result<Self::Collection<'_>, secret_service::Error>;
}

impl SecretService for secret_service::SecretService<'_> {
    /// Lifetime models how Collection borrows the D-Bus Session from the SecretService instance.
    type Collection<'a> = secret_service::Collection<'a> where Self: 'a;

    fn get_default_collection(&self) -> Result<Self::Collection<'_>, secret_service::Error> {
        self.get_default_collection()
    }
}

/// The org.freedesktop.Secret.Collection interface for managing secrets in a collection.
///
/// Only the subset of methods used in this module are included. This trait is primarily meant
/// to provide an abstraction where we can inject a faked implementation in tests.
pub(crate) trait Collection {
    type Item<'a>: Item
    where
        Self: 'a;

    fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> Result<Self::Item<'_>, secret_service::Error>;

    fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> Result<Vec<Self::Item<'_>>, secret_service::Error>;

    fn is_locked(&self) -> Result<bool, secret_service::Error>;

    fn unlock(&self) -> Result<(), secret_service::Error>;

    fn find_items(&self, attributes: Attributes) -> Result<Vec<Self::Item<'_>>, Error> {
        Ok(self.search_items(attributes.get())?)
    }

    fn find_item(&self, attributes: Attributes) -> Result<Option<Self::Item<'_>>, Error> {
        Ok(self.search_items(attributes.get())?.into_iter().next())
    }
}

impl Collection for secret_service::Collection<'_> {
    /// Lifetime models how Item borrows the D-Bus Session from the Collection instance.
    type Item<'a> = secret_service::Item<'a> where Self: 'a;

    fn create_item(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> Result<Self::Item<'_>, secret_service::Error> {
        self.create_item(label, attributes, secret, replace, content_type)
    }

    fn search_items(
        &self,
        attributes: HashMap<&str, &str>,
    ) -> Result<Vec<Self::Item<'_>>, secret_service::Error> {
        self.search_items(attributes)
    }

    fn is_locked(&self) -> Result<bool, secret_service::Error> {
        self.is_locked()
    }

    fn unlock(&self) -> Result<(), secret_service::Error> {
        self.unlock()
    }
}

/// The org.freedesktop.Secret.Item interface for managing an item containing a secret value.
///
/// Only the subset of methods used in this module are included. This trait is primarily meant
/// to provide an abstraction where we can inject a faked implementation in tests.
pub(crate) trait Item {
    fn get_secret(&self) -> Result<Vec<u8>, secret_service::Error>;

    fn get_created(&self) -> Result<SystemTime, secret_service::Error>;

    fn set_secret(&self, secret: &[u8], content_type: &str) -> Result<(), secret_service::Error>;

    fn delete(&self) -> Result<(), secret_service::Error>;
}

impl Item for secret_service::Item<'_> {
    fn get_secret(&self) -> Result<Vec<u8>, secret_service::Error> {
        self.get_secret()
    }

    fn get_created(&self) -> Result<SystemTime, secret_service::Error> {
        Ok(UNIX_EPOCH + Duration::from_secs(self.get_created()?))
    }

    fn set_secret(&self, secret: &[u8], content_type: &str) -> Result<(), secret_service::Error> {
        self.set_secret(secret, content_type)
    }

    fn delete(&self) -> Result<(), secret_service::Error> {
        self.delete()
    }
}

pub(crate) struct Attributes(HashMap<&'static str, String>);

impl Attributes {
    fn new() -> Self {
        Attributes(HashMap::new())
    }

    fn insert(&mut self, k: &'static str, v: String) -> Option<String> {
        self.0.insert(k, v)
    }

    fn new_discoverable_credential(credential: &PrivateKeyCredentialSource) -> Self {
        let mut attributes =
            Self::discoverable_user_search(&credential.rp.id, &credential.user_handle);
        attributes.insert(
            "user_handle",
            base64::encode(credential.user_handle.as_ref()),
        );
        attributes.insert("credential_id", base64::encode(credential.id.as_ref()));
        attributes.insert("credential_type", credential.type_.to_string());
        attributes
    }

    fn discoverable_search(rp_id: &RelyingPartyIdentifier) -> Self {
        let mut attributes = Attributes::base();
        attributes.insert("rp_id", rp_id.to_string());
        attributes.insert("discoverable", "true".to_string());
        attributes
    }

    fn discoverable_user_search(rp_id: &RelyingPartyIdentifier, user_handle: &UserHandle) -> Self {
        let mut attributes = Attributes::base();
        attributes.insert("rp_id", rp_id.to_string());
        attributes.insert("user_handle", base64::encode(user_handle.as_ref()));
        attributes.insert("discoverable", "true".to_string());
        attributes
    }

    fn handle_search(handle: &CredentialHandle) -> Self {
        let mut attributes = Attributes::base();
        attributes.insert("rp_id", handle.rp.id.to_string());
        attributes.insert(
            "credential_id",
            base64::encode(handle.descriptor.id.as_ref()),
        );
        attributes.insert("credential_type", handle.descriptor.type_.to_string());
        attributes
    }

    fn new_specific_credential(credential: &PrivateKeyCredentialSource) -> Self {
        let mut attributes = Self::specific_search(&credential.rp.id, &credential.descriptor());
        attributes.insert(
            "user_handle",
            base64::encode(credential.user_handle.as_ref()),
        );
        attributes
    }

    fn specific_search(
        rp_id: &RelyingPartyIdentifier,
        descriptor: &PublicKeyCredentialDescriptor,
    ) -> Self {
        let mut attributes = Attributes::base();
        attributes.insert("rp_id", rp_id.to_string());
        attributes.insert("credential_id", base64::encode(descriptor.id.as_ref()));
        attributes.insert("credential_type", descriptor.type_.to_string());
        attributes.insert("discoverable", "false".to_string());
        attributes
    }

    fn u2f_handle_search(handle: &CredentialHandle) -> Self {
        let mut attributes = Attributes::new();
        attributes.insert("application", "com.github.danstiner.rust-u2f".to_string());
        attributes.insert(
            "u2f_app_id_hash",
            base64::encode(Sha256::digest(handle.rp.id.as_ref()).as_ref()),
        );
        attributes.insert(
            "u2f_key_handle",
            base64::encode(handle.descriptor.id.as_ref()),
        );
        attributes
    }

    fn base() -> Self {
        let mut attributes = Attributes::new();
        attributes.insert("application", "com.github.danstiner.rust-fido".to_string());
        attributes.insert("xdg:schema", "com.github.danstiner.rust-fido".to_string());
        attributes
    }

    fn get(&self) -> HashMap<&str, &str> {
        self.0.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct LegacyU2FSecret {
    application_key: U2FApplicationKey,
    counter: u32,
}

#[serde_as]
#[derive(Clone, Serialize, Deserialize, Debug)]
struct U2FApplicationKey {
    #[serde_as(as = "Base64")]
    pub application: Vec<u8>,
    #[serde_as(as = "Base64")]
    pub handle: Vec<u8>,
    #[serde_as(as = "Base64")]
    key: Vec<u8>,
}

// Decode a Sec1-encoded plaintext private key; as specified in RFC 5915
// U2F keys were generated with openssl EcKey and group X9_62_PRIME256V1 (aka secp256r1, prime256v1, NIST P-256)
fn decode_sec1_pem_encoded_p256_key(value: &[u8]) -> Result<PrivateKeyDocument, ()> {
    let value = std::str::from_utf8(value).unwrap();
    let key = p256::SecretKey::from_sec1_pem(value).unwrap();
    Ok(PrivateKeyDocument::ES256 {
        pkcs8_bytes: key.to_pkcs8_der().unwrap().as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use fido2_api::{
        COSEAlgorithmIdentifier, CredentialId, PublicKeyCredentialDescriptor,
        PublicKeyCredentialParameters, PublicKeyCredentialRpEntity, PublicKeyCredentialType,
        RelyingPartyIdentifier, UserHandle,
    };
    use fido2_service::{CredentialStorage, KeyProtection, PrivateKeyCredentialSource};
    use lazy_static::lazy_static;
    use std::{cell::RefCell, rc::Rc};

    use super::*;

    #[test]
    fn get_with_empty_store_is_none() {
        let mut keyring = keyring();
        let key_handle = CredentialHandle {
            descriptor: PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: CredentialId::new(&[1, 2, 3]),
            },
            protection: KeyProtection {
                is_user_verification_required: false,
                is_user_verification_optional_with_allow_list: false,
            },
            rp: RP.clone(),
        };

        assert!(keyring
            .get_and_increment_sign_count(&key_handle)
            .unwrap()
            .is_none());
    }

    #[test]
    fn list_with_empty_store_is_empty() {
        let keyring = keyring();

        assert!(keyring.list_discoverable(&RP.id).unwrap().is_empty());
    }

    #[test]
    fn put_discoverable_then_list_returns_credential() {
        let mut store = keyring();
        let key = PrivateKeyCredentialSource::generate(
            &PARAMETERS,
            &RP,
            &USER_HANDLE,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();

        store.put_discoverable(key.clone()).unwrap();

        let list = store.list_discoverable(&key.rp.id).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn put_discoverable_should_replace_existing_credential() {
        let mut store = keyring();

        // Put first discoverable key
        let credential1 = PrivateKeyCredentialSource::generate(
            &PARAMETERS,
            &RP,
            &USER_HANDLE,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        store.put_discoverable(credential1.clone()).unwrap();

        // Put second discoverable key, should replace the first
        let key2 = PrivateKeyCredentialSource::generate(
            &PARAMETERS,
            &RP,
            &USER_HANDLE,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        store.put_discoverable(key2.clone()).unwrap();

        let list = store.list_discoverable(&RP.id).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].descriptor.id, key2.id);
    }

    #[test]
    fn put_discoverable_then_get_returns_credential_and_increments() {
        let mut store = keyring();
        let key = PrivateKeyCredentialSource::generate(
            &PARAMETERS,
            &RP,
            &USER_HANDLE,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        let handle = key.handle();

        store.put_discoverable(key.clone()).unwrap();

        // First get
        let result = store
            .get_and_increment_sign_count(&handle)
            .unwrap()
            .unwrap();
        assert_eq!(result.sign_count, 1);

        // Second get
        let result = store
            .get_and_increment_sign_count(&handle)
            .unwrap()
            .unwrap();
        assert_eq!(result.sign_count, 2);
    }

    /// If an authenticator supports both CTAP1/U2F and CTAP2 then a credential created using
    /// CTAP1/U2F MUST be assertable over CTAP2. (Credentials created over CTAP1/U2F MUST NOT be discoverable credentials though.)
    /// Using the CTAP2 authenticatorGetAssertion Command with CTAP1/U2F authenticators, this means
    /// that an authenticator MUST accept, over CTAP2, the credential ID of a credential that was
    /// created using U2F where the application parameter at the time of creation was the
    /// SHA-256 digest of the RP ID that is given at assertion time.
    #[test]
    fn get_with_preexisting_u2f_credential() {
        let mut keyring = keyring();

        let u2f_key_handle_str = "9Fyey17JWZQ9XR6OFgDEpkJ0cDAImCQeyGbDA1CWboo+qeu9wIIlA8ilqSGMDMd+VqmRTkDUqF2+aYJqjahtr2rgNqC8BnCfYbwYk/NtggzOqiShdqmGh8GEq5cnqtcxAcIaEb1wX4uEoYiRHxrvjo3N8B97arLemjnq0Dii/3nFjzuSIkGzTAF5VRzzstop8WMFWxBVc2Vkv+6wdx7AG+QSo8kt3EtIuIr9m5neXNKHJEHdsaCgjvTqkVwpUXo6sGe+pznO8rhviRDQLCuq1LkSTpHMXqa6AwT+E6UDLVIDfeF9uRVGG2epzEAc54xmNSNDNoB6FcgcmXJLl26g";
        let credential_id = base64::decode(u2f_key_handle_str).unwrap();

        let mut attributes = HashMap::new();
        attributes.insert(
            "application".to_string(),
            "com.github.danstiner.rust-u2f".to_string(),
        );
        attributes.insert("u2f_key_handle".to_string(), u2f_key_handle_str.to_string());
        attributes.insert("u2f_app_id".to_string(), "demo.yubico.com".to_string());
        attributes.insert("times_used".to_string(), "1".to_string());
        attributes.insert(
            "u2f_app_id_hash".to_string(),
            "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7c=".to_string(),
        );
        attributes.insert("date_registered".to_string(), "1652250189".to_string());

        keyring.service.add_item(ItemData {
            label: "Universal 2nd Factor token for demo.yubico.com".to_string(),
            secret: b"{\"application_key\":{\"application\":\"xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v+ppaZJdA7c=\",\"handle\":\"9Fyey17JWZQ9XR6OFgDEpkJ0cDAImCQeyGbDA1CWboo+qeu9wIIlA8ilqSGMDMd+VqmRTkDUqF2+aYJqjahtr2rgNqC8BnCfYbwYk/NtggzOqiShdqmGh8GEq5cnqtcxAcIaEb1wX4uEoYiRHxrvjo3N8B97arLemjnq0Dii/3nFjzuSIkGzTAF5VRzzstop8WMFWxBVc2Vkv+6wdx7AG+QSo8kt3EtIuIr9m5neXNKHJEHdsaCgjvTqkVwpUXo6sGe+pznO8rhviRDQLCuq1LkSTpHMXqa6AwT+E6UDLVIDfeF9uRVGG2epzEAc54xmNSNDNoB6FcgcmXJLl26g\",\"key\":\"LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSUZGdlJsTVBIZ04vMU5JWGNzMzNKbDgyTVQxYmxTZ1N4Qk9GNndhaHVsaURvQW9HQ0NxR1NNNDkKQXdFSG9VUURRZ0FFcklxMktvNGRYZmpHWmNpYzJjZ0NnYm9vUWVRWUM0UHJSWEMvQ2duUVhoL1FNUTNKQzcxeQpIVzZYMUNtU0VnbWhWL3NxQUhxN1c5NGVFOHBQUi9mOXBBPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo=\"},\"counter\":1}".to_vec(),
            content_type: "application/json".to_string(),
            attributes,
            created: UNIX_EPOCH + Duration::from_secs(1_000_000_000),
            deleted: false,
        });

        let key_handle = CredentialHandle {
            descriptor: PublicKeyCredentialDescriptor {
                type_: PublicKeyCredentialType::PublicKey,
                id: CredentialId::new(&credential_id),
            },
            protection: KeyProtection {
                is_user_verification_required: false,
                is_user_verification_optional_with_allow_list: false,
            },
            rp: PublicKeyCredentialRpEntity {
                id: RelyingPartyIdentifier::new("demo.yubico.com".to_string()),
                name: "YubicoDemo".to_string(),
            },
        };

        assert!(keyring
            .get_and_increment_sign_count(&key_handle)
            .unwrap()
            .is_some());
    }

    lazy_static! {
        static ref PARAMETERS: PublicKeyCredentialParameters = PublicKeyCredentialParameters {
            alg: COSEAlgorithmIdentifier::ES256,
            type_: PublicKeyCredentialType::PublicKey
        };
        static ref NOW: SystemTime = UNIX_EPOCH + Duration::from_secs(1);
        static ref RP: PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity {
            id: RelyingPartyIdentifier::new("rusty.party".to_string()),
            name: "Party Town".to_string(),
        };
        static ref USER_HANDLE: UserHandle = UserHandle::new(vec![0]);
    }

    fn keyring() -> Keyring<FakeSecretService> {
        Keyring {
            service: FakeSecretService::new(),
        }
    }

    fn borrow_map(m: &HashMap<String, String>) -> HashMap<&str, &str> {
        m.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    struct FakeSecretService(RefCell<Vec<Rc<RefCell<ItemData>>>>);

    impl FakeSecretService {
        fn new() -> Self {
            Self(RefCell::new(vec![]))
        }

        fn add_item(&mut self, item: ItemData) {
            self.0.borrow_mut().push(Rc::new(RefCell::new(item)));
        }
    }

    impl SecretService for FakeSecretService {
        type Collection<'a> = FakeCollection<'a> where Self: 'a;

        fn get_default_collection(&self) -> secret_service::Result<Self::Collection<'_>> {
            Ok(FakeCollection(&self.0))
        }
    }

    struct FakeCollection<'a>(&'a RefCell<Vec<Rc<RefCell<ItemData>>>>);

    impl FakeCollection<'_> {
        fn remove_item(&self, attributes: &HashMap<&str, &str>) {
            self.0
                .borrow_mut()
                .retain(|i| attributes != &borrow_map(&i.borrow().attributes));
        }
    }

    impl Collection for FakeCollection<'_> {
        type Item<'a> = FakeItem where Self: 'a;

        fn create_item(
            &self,
            label: &str,
            attributes: HashMap<&str, &str>,
            secret: &[u8],
            replace: bool,
            content_type: &str,
        ) -> Result<Self::Item<'_>, secret_service::Error> {
            if replace {
                self.remove_item(&attributes);
            }
            self.0.borrow_mut().push(Rc::new(RefCell::new(ItemData {
                created: *NOW,
                secret: secret.to_owned(),
                label: label.to_owned(),
                content_type: content_type.to_owned(),
                attributes: attributes
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
                deleted: false,
            })));
            Ok(FakeItem(Rc::clone(self.0.borrow().last().unwrap())))
        }

        fn search_items(
            &self,
            attributes: HashMap<&str, &str>,
        ) -> Result<Vec<Self::Item<'_>>, secret_service::Error> {
            Ok(self
                .0
                .borrow()
                .iter()
                .filter(|i| {
                    attributes.iter().all(|(k, v)| {
                        i.borrow()
                            .attributes
                            .get(*k)
                            .map(|x| x.as_str() == *v)
                            .unwrap_or_default()
                    }) && !i.borrow().deleted
                })
                .map(|d| FakeItem(Rc::clone(d)))
                .collect())
        }

        fn is_locked(&self) -> Result<bool, secret_service::Error> {
            Ok(true)
        }

        fn unlock(&self) -> Result<(), secret_service::Error> {
            Ok(())
        }
    }

    struct FakeItem(Rc<RefCell<ItemData>>);

    impl Item for FakeItem {
        fn get_secret(&self) -> Result<Vec<u8>, secret_service::Error> {
            Ok(self.0.as_ref().borrow().secret.clone())
        }

        fn get_created(&self) -> Result<SystemTime, secret_service::Error> {
            Ok(self.0.as_ref().borrow().created)
        }

        fn set_secret(
            &self,
            secret: &[u8],
            content_type: &str,
        ) -> Result<(), secret_service::Error> {
            let mut this = self.0.as_ref().borrow_mut();
            this.secret = secret.to_owned();
            this.content_type = content_type.to_owned();
            Ok(())
        }

        fn delete(&self) -> Result<(), secret_service::Error> {
            assert!(!self.0.as_ref().borrow().deleted);
            self.0.as_ref().borrow_mut().deleted = true;
            Ok(())
        }
    }

    #[derive(Debug, PartialEq)]
    struct ItemData {
        label: String,
        secret: Vec<u8>,
        content_type: String,
        attributes: HashMap<String, String>,
        created: SystemTime,
        deleted: bool,
    }

    #[test]
    fn fake_service_create_adds_one_item() -> secret_service::Result<()> {
        let service = FakeSecretService::new();
        let expected = ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([]),
            created: *NOW,
            deleted: false,
        };

        // Create new item
        let item = service.get_default_collection()?.create_item(
            &expected.label,
            borrow_map(&expected.attributes),
            &expected.secret,
            false,
            &expected.content_type,
        )?;
        assert_eq!(item.get_secret()?, expected.secret);

        // Assert one item was created
        let items = service.0.borrow();
        assert_eq!(items.len(), 1);
        let item = items[0].as_ref().borrow();
        assert_eq!(*item, expected);

        Ok(())
    }

    #[test]
    fn fake_service_create_with_replace_adds_one_item() -> secret_service::Result<()> {
        let service = FakeSecretService::new();
        let expected = ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([]),
            created: *NOW,
            deleted: false,
        };

        // First create
        let item = service.get_default_collection()?.create_item(
            &expected.label,
            borrow_map(&expected.attributes),
            &expected.secret,
            true,
            &expected.content_type,
        )?;
        assert_eq!(item.get_secret()?, expected.secret);

        // A second create
        let item = service.get_default_collection()?.create_item(
            &expected.label,
            borrow_map(&expected.attributes),
            &expected.secret,
            true,
            &expected.content_type,
        )?;
        assert_eq!(item.get_secret()?, expected.secret);

        // Assert one item was created
        let items = service.0.borrow();
        assert_eq!(items.len(), 1);
        let item = items[0].as_ref().borrow();
        assert_eq!(*item, expected);

        Ok(())
    }

    #[test]
    fn fake_service_create_without_replace_adds_multiple_items() -> secret_service::Result<()> {
        let service = FakeSecretService::new();
        let expected = ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([]),
            created: *NOW,
            deleted: false,
        };

        // First create
        let item = service.get_default_collection()?.create_item(
            &expected.label,
            borrow_map(&expected.attributes),
            &expected.secret,
            false,
            &expected.content_type,
        )?;
        assert_eq!(item.get_secret()?, expected.secret);

        // A second create
        let item = service.get_default_collection()?.create_item(
            &expected.label,
            borrow_map(&expected.attributes),
            &expected.secret,
            false,
            &expected.content_type,
        )?;
        assert_eq!(item.get_secret()?, expected.secret);

        // Assert two items were created
        let items = service.0.borrow();
        assert_eq!(items.len(), 2);
        let item = items[0].as_ref().borrow();
        assert_eq!(*item, expected);
        let item = items[1].as_ref().borrow();
        assert_eq!(*item, expected);

        Ok(())
    }

    #[test]
    fn fake_service_search_with_exact_attributes_finds_item() -> secret_service::Result<()> {
        let service = FakeSecretService::new();
        service.0.borrow_mut().push(Rc::new(RefCell::new(ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([("attribute".to_owned(), "match".to_owned())]),
            created: *NOW,
            deleted: false,
        })));

        let results = service
            .get_default_collection()?
            .search_items(HashMap::from([("attribute", "match")]))?;

        assert_eq!(results.len(), 1);

        Ok(())
    }

    #[test]
    fn fake_service_search_with_subset_of_attributes_finds_item() -> secret_service::Result<()> {
        let service = FakeSecretService::new();
        service.0.borrow_mut().push(Rc::new(RefCell::new(ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([
                ("attribute".to_owned(), "match".to_owned()),
                ("extra_attribute".to_owned(), "no_match".to_owned()),
            ]),
            created: *NOW,
            deleted: false,
        })));

        let results = service
            .get_default_collection()?
            .search_items(HashMap::from([("attribute", "match")]))?;

        assert_eq!(results.len(), 1);

        Ok(())
    }

    #[test]
    fn fake_service_search_with_non_matching_attributes_finds_nothing() -> secret_service::Result<()>
    {
        let service = FakeSecretService::new();
        service.0.borrow_mut().push(Rc::new(RefCell::new(ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([]),
            created: *NOW,
            deleted: false,
        })));

        let results = service
            .get_default_collection()?
            .search_items(HashMap::from([("no_such_attribute", "wow")]))?;

        assert!(results.is_empty());

        Ok(())
    }

    #[test]
    fn fake_service_search_deleted_item_finds_nothing() -> secret_service::Result<()> {
        let service = FakeSecretService::new();
        service.0.borrow_mut().push(Rc::new(RefCell::new(ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([("attribute".to_owned(), "match".to_owned())]),
            created: *NOW,
            deleted: true,
        })));

        let results = service
            .get_default_collection()?
            .search_items(HashMap::from([("attribute", "match")]))?;

        assert_eq!(results.len(), 0);

        Ok(())
    }
}
