mod webauthn;

use std::collections::HashMap;
use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::result::Result;
use std::task::Context;
use std::task::Poll;

use async_trait::async_trait;
use byteorder::{BigEndian, WriteBytesExt};
use futures::Future;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;
use tracing::{debug, error, info, trace};
use webauthn::PublicKeyCredentialParameters;

pub use tower::Service;

// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticator-api
pub trait AuthenticatorAPI {
    fn version(&self) -> VersionInfo;
    // fn make_credential(
    //     &self,
    //     client_data_hash: Hash,
    //     rp: PublicKeyCredentialRpEntity,
    //     user: PublicKeyCredentialUserEntity,
    //     pub_key_cred_params: [PublicKeyCredentialParameters],
    //     exclude_list: [PublicKeyCredentialDescriptor],
    //     extensions: u32,
    //     options: MakeCredentialOptions,
    //     pin_uv_auth_param: ByteString,
    //     pin_uv_auth_protocol: u32,
    //     enterprise_attestation: u32,
    // ) -> Result<MakeCredentialResponse, Error>;

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

    // fn get_info(&self) -> Result<GetInfoResponse, Error>;

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

#[derive(Debug)]
pub enum Request {
    GetInfo,
}

#[derive(Debug)]
pub enum Response {
    GetInfo {
        versions: Vec<String>,
        extensions: Vec<String>,
        aaguid: [u8; 16],
        options: u64,
        max_msg_size: u64,
        pin_uv_auth_protocols: Vec<u64>,
        max_credential_count_in_list: u64,
        max_credential_id_length: u64,
        transports: Vec<String>,
        algorithms: Vec<PublicKeyCredentialParameters>,
        max_serialized_large_blob_array: u64,
        force_pin_change: bool,
        min_pin_length: u64,
        firmware_version: String,
        max_cred_blob_len: u64,
        max_rp_ids_for_set_min_pin_length: u64,
        preferred_platform_uv_attempts: u64,
        uv_modality: u64,
        certifications: HashMap<String, u64>,
        remaining_discoverable_credentials: u64,
        vendor_prototype_config_commands: Vec<u64>,
    },
}

#[derive(Debug)]
enum Error {}
