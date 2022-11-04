use super::Error;
use async_trait::async_trait;
use fido2_api::RelyingPartyIdentifier;
use fido2_service::{CredentialHandle, CredentialProtection, PrivateKeyCredentialSource};
use secret_service::EncryptionType;
use std::collections::HashMap;
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

    fn create_item<'a>(
        &'a self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> Result<Self::Item<'a>, secret_service::Error>;

    fn search_items<'a>(
        &'a self,
        attributes: HashMap<&str, &str>,
    ) -> Result<Vec<Self::Item<'a>>, secret_service::Error>;

    fn is_locked(&self) -> Result<bool, secret_service::Error>;

    fn unlock(&self) -> Result<(), secret_service::Error>;
}

impl Collection for secret_service::Collection<'_> {
    /// Lifetime models how Item borrows the D-Bus Session from the Collection instance.
    type Item<'a> = secret_service::Item<'a> where Self: 'a;

    fn create_item<'a>(
        &'a self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> Result<Self::Item<'a>, secret_service::Error> {
        self.create_item(label, attributes, secret, replace, content_type)
    }

    fn search_items<'a>(
        &'a self,
        attributes: HashMap<&str, &str>,
    ) -> Result<Vec<Self::Item<'a>>, secret_service::Error> {
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
}

impl Item for secret_service::Item<'_> {
    fn get_secret(&self) -> Result<Vec<u8>, secret_service::Error> {
        self.get_secret()
    }

    fn get_created(&self) -> Result<SystemTime, secret_service::Error> {
        Ok(UNIX_EPOCH + Duration::from_secs(self.get_created()?))
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
        let collection = self.service.get_default_collection()?;
        unlock_if_locked(&collection)?;
        let attributes = discoverable_credential_attributes(&credential);
        let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let label = format!("FIDO2 credential for {}", credential.rp_id.as_str());
        let secret = serde_json::to_string(&credential)?;
        let content_type = "application/json";
        let _item =
            collection.create_item(&label, attributes, secret.as_bytes(), true, content_type)?;
        Ok(())
    }

    fn get(
        &self,
        credential_handle: &CredentialHandle,
    ) -> Result<Option<fido2_service::PrivateKeyCredentialSource>, Self::Error> {
        let collection = self.service.get_default_collection()?;
        unlock_if_locked(&collection)?;
        let option = find_item(&collection, credential_handle)?;
        if option.is_none() {
            return Ok(None);
        }
        let item = option.unwrap();
        let secret_bytes = item.get_secret()?;
        let credential: PrivateKeyCredentialSource = serde_json::from_slice(&secret_bytes)?;
        Ok(Some(credential))
    }

    fn list_discoverable(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
    ) -> Result<Vec<CredentialHandle>, Self::Error> {
        let collection = self.service.get_default_collection()?;
        unlock_if_locked(&collection)?;

        let attributes = discoverable_search_attributes(rp_id);
        let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let handles = collection
            .search_items(attributes)?
            .into_iter()
            .map(|item| {
                let secret_bytes = item.get_secret()?;
                let credential: PrivateKeyCredentialSource = serde_json::from_slice(&secret_bytes)?;
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
            .collect();
        handles
    }
}

fn discoverable_credential_attributes(
    credential: &PrivateKeyCredentialSource,
) -> Vec<(&'static str, String)> {
    let mut attributes = discoverable_search_attributes(&credential.rp_id);
    attributes.push((
        "user_handle",
        base64::encode(credential.user_handle.as_bytes()),
    ));
    attributes
}

fn discoverable_search_attributes(rp_id: &RelyingPartyIdentifier) -> Vec<(&'static str, String)> {
    vec![
        ("application", "com.github.danstiner.rust-fido".to_string()),
        ("xdg:schema", "com.github.danstiner.rust-fido".to_string()),
        ("rp_id", rp_id.to_string()),
    ]
}

fn handle_search_attributes(handle: &CredentialHandle) -> Vec<(&'static str, String)> {
    vec![
        ("application", "com.github.danstiner.rust-fido".to_string()),
        ("xdg:schema", "com.github.danstiner.rust-fido".to_string()),
        ("rp_id", handle.rp_id.to_string()),
        (
            "credential_id",
            base64::encode(handle.descriptor.id.as_bytes()),
        ),
    ]
}

fn find_item<'a, C: Collection>(
    collection: &'a C,
    handle: &CredentialHandle,
) -> Result<Option<C::Item<'a>>, Error> {
    let attributes = handle_search_attributes(handle);
    let attributes = attributes.iter().map(|(k, v)| (*k, v.as_str())).collect();
    Ok(find_items(collection, attributes)?.into_iter().next())
}

fn find_items<'a, C: Collection>(
    collection: &'a C,
    attributes: HashMap<&str, &str>,
) -> Result<Vec<C::Item<'a>>, Error> {
    Ok(collection.search_items(attributes)?)
}

fn unlock_if_locked<C: Collection>(collection: &C) -> Result<(), Error> {
    if collection.is_locked()? {
        collection.unlock()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use fido2_service::CredentialStorage;

    use super::*;

    fn borrow_map(m: &HashMap<String, String>) -> HashMap<&str, &str> {
        m.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect()
    }

    #[test]
    fn get_none() {
        let store = Keyring {
            service: FakeSecretService::new(),
        };
        let credential_handle = CredentialHandle {
            descriptor: fido2_api::PublicKeyCredentialDescriptor {
                type_: fido2_api::PublicKeyCredentialType::PublicKey,
                id: fido2_api::CredentialId::new(&[]),
            },
            protection: CredentialProtection {
                is_user_verification_required: false,
                is_user_verification_optional_with_credential_id_list: false,
            },
            rp_id: RelyingPartyIdentifier::new("test".to_string()),
        };

        assert!(store.get(&credential_handle).unwrap().is_none());
    }

    #[test]
    fn list_none() {
        let store = Keyring {
            service: FakeSecretService::new(),
        };
        let rp_id = RelyingPartyIdentifier::new("test".to_string());

        assert!(store.list_discoverable(&rp_id).unwrap().is_empty());
    }

    #[test]
    fn put_discoverable_then_list() {
        let mut store = Keyring {
            service: FakeSecretService::new(),
        };
        let key = fido2_service::PrivateKeyCredentialSource::generate(
            &fido2_api::COSEAlgorithmIdentifier::ES256,
            &fido2_api::PublicKeyCredentialType::PublicKey,
            &fido2_api::RelyingPartyIdentifier::new("test".to_string()),
            &fido2_api::UserHandle::new(vec![0]),
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();

        {
            store.put_discoverable(key.clone()).unwrap();
        }

        {
            let list = store.list_discoverable(&key.rp_id).unwrap();
            assert_eq!(list.len(), 1);
        }
    }

    #[test]
    fn put_discoverable_should_replace() {
        let mut store = Keyring {
            service: FakeSecretService::new(),
        };
        let key = fido2_service::PrivateKeyCredentialSource::generate(
            &fido2_api::COSEAlgorithmIdentifier::ES256,
            &fido2_api::PublicKeyCredentialType::PublicKey,
            &fido2_api::RelyingPartyIdentifier::new("test".to_string()),
            &fido2_api::UserHandle::new(vec![0]),
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();

        {
            store.put_discoverable(key.clone()).unwrap();
        }

        {
            store.put_discoverable(key.clone()).unwrap();
        }

        {
            let list = store.list_discoverable(&key.rp_id).unwrap();
            assert_eq!(list.len(), 1);
        }
    }

    struct FakeSecretService(RefCell<Vec<Rc<RefCell<ItemData>>>>);

    impl FakeSecretService {
        fn new() -> Self {
            Self(RefCell::new(vec![]))
        }
    }

    impl SecretService for FakeSecretService {
        type Collection<'a> = FakeCollection<'a> where Self: 'a;

        fn get_default_collection<'a>(&'a self) -> secret_service::Result<Self::Collection<'a>> {
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

        fn create_item<'a>(
            &'a self,
            label: &str,
            attributes: HashMap<&str, &str>,
            secret: &[u8],
            replace: bool,
            content_type: &str,
        ) -> secret_service::Result<Self::Item<'a>> {
            if replace {
                self.remove_item(&attributes);
            }
            self.0.borrow_mut().push(Rc::new(RefCell::new(ItemData {
                created: NOW,
                secret: secret.to_owned(),
                label: label.to_owned(),
                content_type: content_type.to_owned(),
                attributes: attributes
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            })));
            Ok(FakeItem(Rc::clone(self.0.borrow().last().unwrap())))
        }

        fn search_items<'a>(
            &'a self,
            attributes: HashMap<&str, &str>,
        ) -> secret_service::Result<Vec<Self::Item<'a>>> {
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
                    })
                })
                .map(|d| FakeItem(Rc::clone(d)))
                .collect())
        }

        fn is_locked(&self) -> secret_service::Result<bool> {
            Ok(true)
        }

        fn unlock(&self) -> secret_service::Result<()> {
            Ok(())
        }
    }

    struct FakeItem(Rc<RefCell<ItemData>>);

    impl Item for FakeItem {
        fn get_secret(&self) -> secret_service::Result<Vec<u8>> {
            Ok(self.0.as_ref().borrow().secret.clone())
        }

        fn get_created(&self) -> secret_service::Result<SystemTime> {
            Ok(self.0.as_ref().borrow().created)
        }
    }

    #[derive(Debug, PartialEq)]
    struct ItemData {
        label: String,
        secret: Vec<u8>,
        content_type: String,
        attributes: HashMap<String, String>,
        created: SystemTime,
    }

    const NOW: SystemTime = UNIX_EPOCH;

    #[test]
    fn fake_service_create_adds_one_item() -> secret_service::Result<()> {
        let service = FakeSecretService::new();
        let expected = ItemData {
            label: "label".to_owned(),
            secret: "secret".as_bytes().to_owned(),
            content_type: "content_type".to_owned(),
            attributes: HashMap::from([]),
            created: NOW,
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
            created: NOW,
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
            created: NOW,
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
            created: NOW,
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
            created: NOW,
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
            created: NOW,
        })));

        let results = service
            .get_default_collection()?
            .search_items(HashMap::from([("no_such_attribute", "wow")]))?;

        assert!(results.is_empty());

        Ok(())
    }
}
