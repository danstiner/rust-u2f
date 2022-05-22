use crate::webauthn::PublicKeyCredentialDescriptor;
use crate::webauthn::PublicKeyCredentialParameters;
use crate::webauthn::PublicKeyCredentialRpEntity;
use crate::webauthn::PublicKeyCredentialUserEntity;
use crate::webauthn::RelyingPartyIdentifier;
use crate::Aaguid;
use crate::Sha256;
use async_trait::async_trait;
use futures::Future;
use minicbor_derive::Decode;
use minicbor_derive::Encode;
use std::collections::HashMap;
use std::fmt::Debug;
use thiserror::Error;
use tracing::{debug, error, info, trace};

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
#[derive(Debug, Encode)]
// #[cbor(map)]
pub enum Command {
    // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
    #[n(0x01)]
    MakeCredential {
        #[n(0x01)]
        client_data_hash: Sha256,
        #[n(0x02)]
        rp: PublicKeyCredentialRpEntity,
        #[n(0x03)]
        user: PublicKeyCredentialUserEntity,
        #[n(0x04)]
        pub_key_cred_params: Array<PublicKeyCredentialParameters>,
        #[n(0x05)]
        exclude_list: Option<Array<PublicKeyCredentialDescriptor>>,
    },
    #[n(0x02)]
    GetAssertion {
        #[n(0x01)]
        rp_id: RelyingPartyIdentifier,
        #[n(0x02)]
        client_data_hash: Sha256,
    },
    #[n(4)]
    GetInfo,
}

#[derive(Debug)]
pub enum Response {
    MakeCredential {
        fmt: String,
        auth_data: Vec<u8>,
        att_stmt: AttestationStatement,
    },
    GetAssertion {
        credential: PublicKeyCredentialDescriptor,
        auth_data: Vec<u8>,
        signature: Vec<u8>,
    },
    GetInfo {
        versions: Vec<String>,
        extensions: Option<Vec<String>>,
        aaguid: Aaguid,
        options: Option<HashMap<String, u64>>,
        max_msg_size: Option<u64>,
        pin_uv_auth_protocols: Option<Vec<u64>>,
        max_credential_count_in_list: Option<u64>,
        max_credential_id_length: Option<u64>,
        transports: Option<Vec<String>>,
        algorithms: Option<Vec<PublicKeyCredentialParameters>>,
        max_serialized_large_blob_array: Option<u64>,
        force_pin_change: Option<bool>,
        min_pin_length: Option<u64>,
        firmware_version: Option<String>,
        max_cred_blob_len: Option<u64>,
        max_rp_ids_for_set_min_pin_length: Option<u64>,
        preferred_platform_uv_attempts: Option<u64>,
        uv_modality: Option<u64>,
        certifications: Option<HashMap<String, u64>>,
        remaining_discoverable_credentials: Option<u64>,
        vendor_prototype_config_commands: Option<Vec<u64>>,
    },
}

#[derive(Debug)]
pub struct AttestationStatement {}
