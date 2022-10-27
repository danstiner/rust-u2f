use crate::webauthn::PublicKeyCredentialDescriptor;
use crate::webauthn::PublicKeyCredentialParameters;
use crate::webauthn::PublicKeyCredentialRpEntity;
use crate::webauthn::PublicKeyCredentialUserEntity;
use crate::webauthn::RelyingPartyIdentifier;
use crate::Aaguid;
use crate::Sha256;

use minicbor_derive::{Decode, Encode};
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
#[derive(Debug, Encode, Decode, PartialEq)]
#[cbor(index_only)]
pub enum Command {
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
    // #[n(0x01)]
    // MakeCredential {
    //     #[n(0x01)]
    //     client_data_hash: Sha256,
    //     #[n(0x02)]
    //     rp: PublicKeyCredentialRpEntity,
    //     #[n(0x03)]
    //     user: PublicKeyCredentialUserEntity,
    //     #[n(0x04)]
    //     pub_key_cred_params: Array<PublicKeyCredentialParameters>,
    //     #[n(0x05)]
    //     exclude_list: Option<Array<PublicKeyCredentialDescriptor>>,
    //     #[n(0x06)]
    //     extensions: Option<Extensions>,
    //     #[n(0x07)]
    //     options: Option<Options>,
    //     #[n(0x08)]
    //     pin_uv_auth_param: Option<PinUvAuthParam>,
    //     #[n(0x09)]
    //     pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    //     #[n(0x0a)]
    //     enterprise_attestation: Option<u8>,
    // },
    // #[n(0x02)]
    // GetAssertion {
    //     #[n(0x01)]
    //     rp_id: RelyingPartyIdentifier,
    //     #[n(0x02)]
    //     client_data_hash: Sha256,
    // },
    #[n(0x04)]
    GetInfo,
}

impl Command {
    pub fn decode_cbor(data: &[u8]) -> Result<Self, minicbor::decode::Error> {
        minicbor::decode(data)
    }
}

// TODO dedupe with MakeCredential command type
#[derive(Debug, Encode, Decode)]
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

#[derive(Debug, Encode, Decode, PartialEq)]
pub struct Extensions;

#[derive(Debug, Encode, Decode, PartialEq)]
pub struct Options;

#[derive(Debug, Encode, Decode, PartialEq)]
pub struct PinUvAuthParam;

#[derive(Debug, Encode, Decode, PartialEq)]
pub struct PinUvAuthProtocol;

/// Messages from authenticator to the host, called a "response" in the CTAP2 protocol
#[derive(Debug, PartialEq)]
pub enum Response {
    // MakeCredential(MakeCredentialResponse),
    // GetAssertion {
    //     credential: PublicKeyCredentialDescriptor,
    //     auth_data: Vec<u8>,
    //     signature: Vec<u8>,
    // },
    GetInfo(GetInfoResponse),
}

impl<C> minicbor::Encode<C> for Response {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Response::GetInfo(info) => e.encode(info)?,
        };
        Ok(())
    }
}

impl Response {
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        minicbor::encode(self, &mut buffer).unwrap();
        buffer
    }
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

#[derive(Debug, PartialEq)]
// #[cbor(map)]
pub struct GetInfoResponse {
    // #[n(0x01)]
    pub versions: Vec<String>,
    // #[n(0x02)]
    pub extensions: Option<Vec<String>>,
    // #[n(0x03)]
    pub aaguid: Aaguid,
    // #[n(0x04)]
    pub options: Option<HashMap<String, u64>>,
    // #[n(0x05)]
    pub max_msg_size: Option<u64>,
    // #[n(0x06)]
    pub pin_uv_auth_protocols: Option<Vec<u64>>,
    // #[n(0x07)]
    pub max_credential_count_in_list: Option<u64>,
    // #[n(0x08)]
    pub max_credential_id_length: Option<u64>,
    // #[n(0x09)]
    pub transports: Option<Vec<String>>,
    // #[n(0x0A)]
    pub algorithms: Option<Vec<PublicKeyCredentialParameters>>,
    // #[n(0x0B)]
    pub max_serialized_large_blob_array: Option<u64>,
    // #[n(0x0C)]
    pub force_pin_change: Option<bool>,
    // #[n(0x0D)]
    pub min_pin_length: Option<u64>,
    // #[n(0x0E)]
    pub firmware_version: Option<String>,
    // #[n(0x0F)]
    pub max_cred_blob_len: Option<u64>,
    // #[n(0x10)]
    pub max_rp_ids_for_set_min_pin_length: Option<u64>,
    // #[n(0x11)]
    pub preferred_platform_uv_attempts: Option<u64>,
    // #[n(0x12)]
    pub uv_modality: Option<u64>,
    // #[n(0x13)]
    pub certifications: Option<HashMap<String, u64>>,
    // #[n(0x14)]
    pub remaining_discoverable_credentials: Option<u64>,
    // #[n(0x15)]
    pub vendor_prototype_config_commands: Option<Vec<u64>>,
}

impl<C> minicbor::Encode<C> for GetInfoResponse {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut len = 2;
        if self.algorithms.is_some() {
            len += 1;
        }
        e.map(len)?;

        e.u8(0x01)?;
        e.encode(&self.versions)?;

        e.u8(0x03)?;
        e.encode(&self.aaguid)?;

        if let Some(ref algorithms) = self.algorithms {
            e.u8(0x0A)?;
            e.encode(algorithms)?;
        }

        Ok(())
    }
}

#[derive(Debug, Encode, Decode)]
pub struct AttestationStatement {}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::uuid;

    #[test]
    fn decode_getinfo_command() {
        assert_eq!(Command::decode_cbor(&[4]).unwrap(), Command::GetInfo);
    }

    #[test]
    fn encode_getinfo_response() {
        assert_eq!(
            Response::GetInfo(GetInfoResponse {
                versions: vec![],
                extensions: None,
                aaguid: Aaguid(uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8")),
                options: None,
                max_msg_size: None,
                pin_uv_auth_protocols: None,
                max_credential_count_in_list: None,
                max_credential_id_length: None,
                transports: None,
                algorithms: None,
                max_serialized_large_blob_array: None,
                force_pin_change: None,
                min_pin_length: None,
                firmware_version: None,
                max_cred_blob_len: None,
                max_rp_ids_for_set_min_pin_length: None,
                preferred_platform_uv_attempts: None,
                uv_modality: None,
                certifications: None,
                remaining_discoverable_credentials: None,
                vendor_prototype_config_commands: None
            })
            .to_cbor(),
            vec![
                162, 1, 128, 3, 80, 103, 229, 80, 68, 16, 177, 66, 111, 146, 71, 187, 104, 14, 95,
                224, 200
            ]
        );
    }

    // Test basic data types follow the CTAP2 canonical CBOR encoding form as defined in section 6 of
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form
    #[test]
    fn encode_basic_cbor_types() {
        assert_eq!(encode(Vec::<String>::new()), [0x80]);
        assert_eq!(encode(vec![1, 2, 3]), [0x83, 0x01, 0x02, 0x03]);
        assert_eq!(encode("IETF"), [0x64, 0x49, 0x45, 0x54, 0x46]);
        assert_eq!(encode(0), [0x00]);
        assert_eq!(encode(65535), [0x19, 0xff, 0xff]);
        assert_eq!(encode(-24), [0x37]);
    }

    fn encode<T: minicbor::Encode<()>>(x: T) -> Vec<u8> {
        let mut buffer = Vec::new();
        minicbor::encode(x, &mut buffer).unwrap();
        buffer
    }
}
