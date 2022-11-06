use super::Error;
use async_trait::async_trait;
use fido2_api::{PublicKeyCredentialDescriptor, RelyingPartyIdentifier, UserHandle};
use fido2_service::{CredentialHandle, PrivateKeyCredentialSource};
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

impl<S: SecretService> Keyring<S> {
    fn collection(&self) -> Result<<S as SecretService>::Collection<'_>, Error> {
        let collection = self.service.get_default_collection()?;
        unlock_if_locked(&collection)?;
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

        let secret = serde_json::to_string(&credential)?;
        let _item = collection.create_item(
            &format!("FIDO2 credential for {}", credential.rp),
            Attributes::new_specific_credential(&credential).get(),
            secret.as_bytes(),
            true,
            "application/json",
        )?;
        Ok(())
    }

    fn get(
        &self,
        credential_handle: &CredentialHandle,
    ) -> Result<Option<fido2_service::PrivateKeyCredentialSource>, Self::Error> {
        let collection = self.collection()?;
        let item = collection.find_item(Attributes::handle_search(credential_handle))?;
        if let Some(item) = item {
            let secret = item.get_secret()?;
            Ok(Some(serde_json::from_slice(&secret)?))
        } else {
            Ok(None)
        }
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

    fn delete(&self) -> Result<(), secret_service::Error>;
}

impl Item for secret_service::Item<'_> {
    fn get_secret(&self) -> Result<Vec<u8>, secret_service::Error> {
        self.get_secret()
    }

    fn get_created(&self) -> Result<SystemTime, secret_service::Error> {
        Ok(UNIX_EPOCH + Duration::from_secs(self.get_created()?))
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
            base64::encode(credential.user_handle.as_bytes()),
        );
        attributes.insert("credential_id", base64::encode(credential.id.as_bytes()));
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
        attributes.insert("user_handle", base64::encode(user_handle.as_bytes()));
        attributes.insert("discoverable", "true".to_string());
        attributes
    }

    fn handle_search(handle: &CredentialHandle) -> Self {
        let mut attributes = Attributes::base();
        attributes.insert("rp_id", handle.rp.id.to_string());
        attributes.insert(
            "credential_id",
            base64::encode(handle.descriptor.id.as_bytes()),
        );
        attributes.insert("credential_type", handle.descriptor.type_.to_string());
        attributes
    }

    fn new_specific_credential(credential: &PrivateKeyCredentialSource) -> Self {
        let mut attributes = Self::specific_search(&credential.rp.id, &credential.descriptor());
        attributes.insert(
            "user_handle",
            base64::encode(credential.user_handle.as_bytes()),
        );
        attributes
    }

    fn specific_search(
        rp_id: &RelyingPartyIdentifier,
        descriptor: &PublicKeyCredentialDescriptor,
    ) -> Self {
        let mut attributes = Attributes::base();
        attributes.insert("rp_id", rp_id.to_string());
        attributes.insert("credential_id", base64::encode(descriptor.id.as_bytes()));
        attributes.insert("credential_type", descriptor.type_.to_string());
        attributes.insert("discoverable", "false".to_string());
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

fn unlock_if_locked<C: Collection>(collection: &C) -> Result<(), Error> {
    if collection.is_locked()? {
        collection.unlock()?;
    }
    Ok(())
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
        let keyring = keyring();
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

        assert!(keyring.get(&key_handle).unwrap().is_none());
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
    fn put_discoverable_then_get_returns_credential() {
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

        let result = store.get(&handle).unwrap();
        assert!(result.is_some());
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
