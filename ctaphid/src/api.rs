use std::{rc::Rc, sync::Arc};

use async_trait::async_trait;
use fido2_authenticator_api::{AuthenticatorAPI, Command, Service};
use tokio::sync::Mutex;

use crate::message::CapabilityFlags;

#[async_trait]
pub trait CtapHidApi {
    type Error;

    fn version(&self) -> Result<VersionInfo, Self::Error>;
    async fn wink(&self) -> Result<(), Self::Error>;
    async fn msg(&self, msg: &[u8]) -> Result<Vec<u8>, Self::Error>;
    async fn cbor(&self, cbor: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

#[async_trait]
impl<Api: CtapHidApi + Send + Sync> CtapHidApi for Arc<Api> {
    type Error = Api::Error;

    fn version(&self) -> Result<VersionInfo, Self::Error> {
        self.as_ref().version()
    }

    async fn wink(&self) -> Result<(), Self::Error> {
        self.as_ref().wink().await
    }
    async fn msg(&self, msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.as_ref().msg(msg).await
    }
    async fn cbor(&self, cbor: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.as_ref().cbor(cbor).await
    }
}

pub struct VersionInfo {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
    pub capabilities: CapabilityFlags,
}

pub struct Adapter<A>(Arc<Mutex<A>>);

impl<A> Adapter<A>
where
    A: Service<Command> + AuthenticatorAPI,
{
    pub fn new(api: A) -> Self {
        Self(Arc::new(Mutex::new(api)))
    }
}

#[async_trait]
impl<A> CtapHidApi for Adapter<A>
where
    A: Service<Command> + AuthenticatorAPI + Send,
{
    type Error = A::Error;

    fn version(&self) -> Result<VersionInfo, Self::Error> {
        // TODO let info = self.0.blocking_lock().version();
        let info = fido2_authenticator_api::VersionInfo {
            version_major: 1,
            version_minor: 0,
            version_build: 0,
            wink_supported: true,
        };
        let wink_capabitlity = if info.wink_supported {
            CapabilityFlags::WINK
        } else {
            CapabilityFlags::empty()
        };
        Ok(VersionInfo {
            major: info.version_major,
            minor: info.version_minor,
            build: info.version_build,
            capabilities: CapabilityFlags::CBOR | wink_capabitlity,
        })
    }

    async fn wink(&self) -> Result<(), Self::Error> {
        todo!()
    }
    async fn msg(&self, msg: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
    async fn cbor(&self, cbor: &[u8]) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }
}

impl<A> Clone for Adapter<A> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}
