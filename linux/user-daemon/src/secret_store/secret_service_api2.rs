#![feature(generic_associated_types)]
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashMap;

pub(crate) trait Item {
    fn get_secret(&self) -> secret_service::Result<Vec<u8>>;

    fn get_created(&self) -> secret_service::Result<DateTime<Utc>>;
}

pub(crate) trait Collection<'b, Item> {
    fn create_item(
        &'b self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> secret_service::Result<Item>;

    // fn search_items(&self, attributes: HashMap<&str, &str>) -> secret_service::Result<Vec<Item>>;
}

struct I<'a> {
    item: secret_service::Item<'a>,
}

struct C<'a> {
    service: secret_service::SecretService<'a>,
}

impl<'a: 'b, 'b> Collection<'b, I<'b>> for C<'a> {
    fn create_item(
        &'b self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        replace: bool,
        content_type: &str,
    ) -> secret_service::Result<I<'b>> {
        let collection = self.service.get_default_collection()?;
        let item = collection.create_item(label, attributes, secret, replace, content_type)?;
        Ok(I { item })
    }
}

// impl Item for secret_service::Item<'_> {
//     fn get_secret(&self) -> secret_service::Result<Vec<u8>> {
//         self.get_secret()
//     }

//     fn get_created(&self) -> secret_service::Result<DateTime<Utc>> {
//         Ok(Utc.timestamp(self.get_created()? as i64, 0))
//     }
// }
// impl<'a> Collection<'a, secret_service::Item<'a>> for secret_service::Collection<'_> {
//     fn create_item(
//         &'a self,
//         label: &str,
//         attributes: HashMap<&str, &str>,
//         secret: &[u8],
//         replace: bool,
//         content_type: &str,
//     ) -> secret_service::Result<secret_service::Item<'a>> {
//         self.create_item(label, attributes, secret, replace, content_type)
//     }

//     fn search_items(
//         &'a self,
//         attributes: HashMap<&str, &str>,
//     ) -> secret_service::Result<Vec<secret_service::Item<'a>>> {
//         self.search_items(attributes)
//     }
// }

// pub(crate) trait SecretService<'a, C> {
//     fn get_default_collection(&'a self) -> secret_service::Result<C>;
// }

// impl<'a> SecretService<'a, secret_service::Collection<'a>> for secret_service::SecretService<'_> {
//     fn get_default_collection(&'a self) -> secret_service::Result<secret_service::Collection<'a>> {
//         self.get_default_collection()
//     }
// }

// struct C<'a> {
//     service: secret_service::SecretService<'a>,
//     // collection: secret_service::Collection<'a>,
// }

// impl<'a> C<'a> {
//     fn new() -> Self {
//         let service =
//             secret_service::SecretService::new(secret_service::EncryptionType::Dh).unwrap();
//         let collection = service.get_default_collection().unwrap();
//         Self {
//             service,
//             // collection,
//         }
//     }
// }

// pub(crate) struct CollectionWrapper<'a> {
//     service: secret_service::SecretService<'a>,
// }

// impl<'a> Collection<secret_service::Item<'a>> for CollectionWrapper<'a> {
//     fn create_item(
//         &self,
//         label: &str,
//         attributes: HashMap<&str, &str>,
//         secret: &[u8],
//         replace: bool,
//         content_type: &str,
//     ) -> secret_service::Result<()> {
//         let collection = self.service.get_default_collection()?;
//         if collection.is_locked()? {
//             collection.unlock()?;
//         }
//         collection.create_item(label, attributes, secret, replace, content_type)?;
//         Ok(())
//     }

//     fn search_items(
//         &self,
//         attributes: HashMap<&str, &str>,
//     ) -> secret_service::Result<Vec<secret_service::Item<'a>>> {
//         let collection: secret_service::Collection<'a> = self.service.get_default_collection()?;
//         if collection.is_locked()? {
//             collection.unlock()?;
//         }
//         collection.search_items(attributes)
//     }
// }

// pub(crate) struct SearchResult<'a> {
//     collection: secret_service::SecretService<'a>,
// }
