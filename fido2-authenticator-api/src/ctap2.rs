use crate::webauthn::PublicKeyCredentialDescriptor;
use crate::webauthn::PublicKeyCredentialParameters;
use crate::webauthn::PublicKeyCredentialRpEntity;
use crate::webauthn::PublicKeyCredentialUserEntity;
use crate::webauthn::RelyingPartyIdentifier;
use crate::Aaguid;
use crate::Sha256;

use minicbor_derive::Encode;
use std::collections::HashMap;
use std::fmt::Debug;

///! CTAP2 protocol
///!
///! Messages are encoded as CTAP2 canonical CBOR: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form

#[derive(Debug)]
pub struct Array<T>(pub Vec<T>);

impl<C, T: minicbor::Encode<C>> minicbor::Encode<C> for Array<T> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.array(self.0.len().try_into().unwrap())?;
        for item in self.0.iter() {
            e.encode_with(item, ctx)?;
        }
        Ok(())
    }
}

impl<'b, C, T> minicbor::Decode<'b, C> for Array<T>
where
    T: minicbor::Decode<'b, ()>,
{
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let mut res = Vec::new();
        for item in d.array_iter()? {
            res.push(item?);
        }
        Ok(Array(res))
    }
}

/// Messages from the host to authenticator, called "commands" in the CTAP2 protocol
#[derive(Debug)]
// #[cbor(map)]
pub enum Command {
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
    // #[n(0x01)]
    MakeCredential(MakeCredentialCommand),
    // #[n(0x02)]
    GetAssertion {
        // #[n(0x01)]
        rp_id: RelyingPartyIdentifier,
        // #[n(0x02)]
        client_data_hash: Sha256,
    },
    // #[n(0x04)]
    GetInfo,
}

#[derive(Debug, Encode)]
pub struct MakeCredentialCommand {
    #[n(0x01)]
    pub client_data_hash: Sha256,
    #[n(0x02)]
    pub rp: PublicKeyCredentialRpEntity,
    #[n(0x03)]
    pub user: PublicKeyCredentialUserEntity,
    #[n(0x04)]
    pub pub_key_cred_params: Array<PublicKeyCredentialParameters>,
    #[n(0x05)]
    pub exclude_list: Option<Array<PublicKeyCredentialDescriptor>>,
    #[n(0x06)]
    pub extensions: Option<Extensions>,
    #[n(0x07)]
    pub options: Option<Options>,
    #[n(0x08)]
    pub pin_uv_auth_param: Option<PinUvAuthParam>,
    #[n(0x09)]
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    #[n(0x0a)]
    pub enterprise_attestation: Option<u8>,
}

#[derive(Debug, Encode)]
pub struct Extensions;

#[derive(Debug, Encode)]
pub struct Options;

#[derive(Debug, Encode)]
pub struct PinUvAuthParam;

#[derive(Debug, Encode)]
pub struct PinUvAuthProtocol;

#[derive(Debug)]
pub enum Response {
    MakeCredential(MakeCredentialResponse),
    GetAssertion {
        credential: PublicKeyCredentialDescriptor,
        auth_data: Vec<u8>,
        signature: Vec<u8>,
    },
    GetInfo(GetInfoResponse),
}

#[derive(Debug)]
pub struct MakeCredentialResponse {
    // #[n(0x01)]
    pub fmt: String,
    // #[n(0x02)]
    pub auth_data: Vec<u8>,
    // #[n(0x03)]
    pub att_stmt: AttestationStatement,
}

#[derive(Debug)]
pub struct GetInfoResponse {
    pub versions: Vec<String>,
    pub extensions: Option<Vec<String>>,
    pub aaguid: Aaguid,
    pub options: Option<HashMap<String, u64>>,
    pub max_msg_size: Option<u64>,
    pub pin_uv_auth_protocols: Option<Vec<u64>>,
    pub max_credential_count_in_list: Option<u64>,
    pub max_credential_id_length: Option<u64>,
    pub transports: Option<Vec<String>>,
    pub algorithms: Option<Vec<PublicKeyCredentialParameters>>,
    pub max_serialized_large_blob_array: Option<u64>,
    pub force_pin_change: Option<bool>,
    pub min_pin_length: Option<u64>,
    pub firmware_version: Option<String>,
    pub max_cred_blob_len: Option<u64>,
    pub max_rp_ids_for_set_min_pin_length: Option<u64>,
    pub preferred_platform_uv_attempts: Option<u64>,
    pub uv_modality: Option<u64>,
    pub certifications: Option<HashMap<String, u64>>,
    pub remaining_discoverable_credentials: Option<u64>,
    pub vendor_prototype_config_commands: Option<Vec<u64>>,
}

#[derive(Debug)]
pub struct AttestationStatement {}
