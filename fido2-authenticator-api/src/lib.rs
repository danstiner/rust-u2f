mod ctap2;
mod status_code;
mod webauthn;

use minicbor::{Decode, Encode};
use std::fmt::Debug;
use std::result::Result;

pub use ctap2::Response;
pub use ctap2::*;
pub use status_code::StatusCode;
pub use tower::Service;
pub use webauthn::*;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticator-api
pub trait AuthenticatorAPI: Service<Command> {
    fn version(&self) -> VersionInfo;

    fn make_credential(
        &self,
        cmd: MakeCredentialCommand,
    ) -> Result<MakeCredentialResponse, Self::Error>;

    // fn get_assertion(
    //     &self,
    //     rp_id: RpId,
    //     client_data_hash: Hash,
    //     allow_list: [PublicKeyCredentialDescriptor],
    //     extensions: ExtensionMap,
    //     options: GetAssertionOptions,
    //     pin_uv_auth_param: ByteString,
    //     pin_uv_auth_protocol: u32,
    // ) -> Result<GetAssertionResponse, Error>;

    // fn get_next_assertion(&self) -> Result<GetNextAssertionResponse, Error>;

    fn get_info(&self) -> Result<GetInfoResponse, Self::Error>;

    // // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorClientPIN
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

#[derive(Debug)]
pub struct Sha256([u8; 32]);

impl<C> Encode<C> for Sha256 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
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
