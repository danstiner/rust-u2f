use async_trait::async_trait;
use minicbor::{Decode, Encode};
use ring::digest;
use std::fmt::Debug;
use std::result::Result;

use crate::{
    GetAssertionCommand, GetAssertionResponse, GetInfoResponse, MakeCredentialCommand,
    MakeCredentialResponse,
};

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticator-api
#[async_trait(?Send)]
pub trait AuthenticatorAPI {
    type Error;

    fn version(&self) -> VersionInfo;

    /// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
    async fn make_credential(
        &self,
        cmd: MakeCredentialCommand,
    ) -> Result<MakeCredentialResponse, Self::Error>;

    /// If an authenticator supports both CTAP1/U2F and CTAP2 then a credential created using CTAP1/U2F MUST be assertable over CTAP2. (Credentials created over CTAP1/U2F MUST NOT be discoverable credentials though.) From § 10.3 Using the CTAP2 authenticatorGetAssertion Command with CTAP1/U2F authenticators, this means that an authenticator MUST accept, over CTAP2, the credential ID of a credential that was created using U2F where the application parameter at the time of creation was the SHA-256 digest of the RP ID that is given at assertion time.
    /// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetAssertion
    async fn get_assertion(
        &self,
        cmd: GetAssertionCommand,
    ) -> Result<GetAssertionResponse, Self::Error>;

    fn get_info(&self) -> Result<GetInfoResponse, Self::Error>;

    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorClientPIN
    // fn client_pin(
    //     &self,
    //     pin_auth_protocol: u32,
    //     sub_command: PinCommand,
    //     key_agreement: COSE_Key,
    //     pin_uv_auth_param: ByteString,
    //     new_pin_enc: ByteString,
    //     pin_hash_enc: ByteString,
    //     permissions: u32,
    //     rp_id: RpId,
    // ) -> Result<ClientPinResponse, Error>;

    // fn reset(&self) -> Result<ResetResponse, Error>;

    async fn wink(&self) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub struct VersionInfo {
    pub version_major: u8,
    pub version_minor: u8,
    pub version_build: u8,
    pub wink_supported: bool,
}

/// aaguid is a byte string uniquely identifying the authenticator make and model.
///
/// Identical values mean that they refer to the same authenticator model and
/// different values mean they refer to different authenticator models.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct Aaguid(pub uuid::Uuid);

impl<C> Encode<C> for Aaguid {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(self.0.as_bytes())?.ok()
    }
}

impl AsRef<[u8]> for Aaguid {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Sha256([u8; 32]);

impl Sha256 {
    pub fn digest(data: &[u8]) -> Self {
        Self(
            digest::digest(&digest::SHA256, data)
                .as_ref()
                .try_into()
                .expect("SHA256 is 32 bytes"),
        )
    }

    pub fn new(value: [u8; 32]) -> Self {
        Sha256(value)
    }
}

impl<C> Encode<C> for Sha256 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}
impl<'b, C> Decode<'b, C> for Sha256 {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let bytes: minicbor::bytes::ByteArray<32> = Decode::decode(d, ctx)?;
        Ok(Sha256(bytes.into()))
    }
}

impl AsRef<[u8]> for Sha256 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
