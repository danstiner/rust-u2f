use std::sync::Arc;

use async_trait::async_trait;
use fido2_api::{AuthenticatorAPI, Command, Response};
use tracing::trace;

use crate::{u2f, CapabilityFlags};

#[async_trait(?Send)]
pub trait CtapHidApi {
    type Error;

    fn version(&self) -> Result<VersionInfo, Self::Error>;
    async fn wink(&self) -> Result<(), Self::Error>;
    async fn msg(&self, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error>;
    async fn cbor(&self, cbor: Vec<u8>) -> Result<Vec<u8>, Self::Error>;
}

#[async_trait(?Send)]
impl<Api: CtapHidApi + Send + Sync> CtapHidApi for Arc<Api> {
    type Error = Api::Error;

    fn version(&self) -> Result<VersionInfo, Self::Error> {
        self.as_ref().version()
    }

    async fn wink(&self) -> Result<(), Self::Error> {
        self.as_ref().wink().await
    }
    async fn msg(&self, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        self.as_ref().msg(msg).await
    }
    async fn cbor(&self, cbor: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        self.as_ref().cbor(cbor).await
    }
}

pub struct VersionInfo {
    pub major: u8,
    pub minor: u8,
    pub build: u8,
    pub capabilities: CapabilityFlags,
}

// TODO convert errors to status codes per https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses
pub struct SimpleAdapter<A>(A);

impl<A> SimpleAdapter<A>
where
    A: AuthenticatorAPI,
{
    pub fn new(api: A) -> Self {
        Self(api)
    }
}

#[async_trait(?Send)]
impl<A> CtapHidApi for SimpleAdapter<A>
where
    A: AuthenticatorAPI,
{
    type Error = A::Error;

    fn version(&self) -> Result<VersionInfo, Self::Error> {
        let version = self.0.version();
        let wink_capabitlity = if version.wink_supported {
            CapabilityFlags::WINK
        } else {
            CapabilityFlags::empty()
        };
        Ok(VersionInfo {
            major: version.version_major,
            minor: version.version_minor,
            build: version.version_build,
            capabilities: CapabilityFlags::CBOR | wink_capabitlity,
        })
    }

    async fn wink(&self) -> Result<(), Self::Error> {
        self.0.wink().await
    }
    async fn msg(&self, msg: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        let request = u2f::Request::decode(&msg).unwrap();
        trace!("msg: Request: {:?}", request);

        match request {
            u2f::Request::Register {
                application: _,
                challenge: _,
            } => todo!("map to make_credential"),
            u2f::Request::Authenticate {
                application: _,
                challenge: _,
                control_code: _,
                key_handle: _,
            } => todo!("map to get_assertion"),
            u2f::Request::GetVersion => {
                let version = self.0.version();
                Ok(u2f::Response::Version {
                    u2f_version_string: String::from("U2F_V2"),
                    device_version_major: version.version_major,
                    device_version_minor: version.version_minor,
                    device_version_build: version.version_build,
                }
                .into_bytes())
            }
            u2f::Request::Wink => todo!(),
        }
    }

    async fn cbor(&self, cbor: Vec<u8>) -> Result<Vec<u8>, Self::Error> {
        trace!("cbor: {:?}", cbor);
        let command = Command::decode_cbor(&cbor).unwrap();
        trace!("command: {:?}", command);
        let response = match command {
            Command::MakeCredential(command) => {
                Response::MakeCredential(self.0.make_credential(command).await?)
            }
            Command::GetAssertion(command) => {
                Response::GetAssertion(self.0.get_assertion(command).await?)
            }
            Command::GetInfo => {
                let info = self.0.get_info()?;
                Response::GetInfo(info)
            }
        };
        trace!("response: {:?}", response);
        Ok(response.to_cbor())
    }
}
