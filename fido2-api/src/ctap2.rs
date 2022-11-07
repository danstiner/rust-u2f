use crate::api::Aaguid;
use crate::api::Sha256;
use crate::webauthn::AuthenticatorData;
use crate::webauthn::PublicKeyCredentialDescriptor;
use crate::webauthn::PublicKeyCredentialParameters;
use crate::webauthn::PublicKeyCredentialRpEntity;
use crate::webauthn::PublicKeyCredentialUserEntity;
use crate::AttestationStatement;
use crate::RelyingPartyIdentifier;
use crate::Signature;

use minicbor_derive::{Decode, Encode};
use std::collections::HashMap;
use std::fmt::Debug;

///! CTAP2 protocol
///!
///! Messages are encoded as CTAP2 canonical CBOR: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#ctap2-canonical-cbor-encoding-form

/// Messages from the host to authenticator, called "commands" in the CTAP2 protocol.
/// Command parameters are encoded using a CBOR map (CBOR major type 5). The CBOR map MUST be encoded using the definite length variant.
/// Some commands have optional parameters. Therefore, the length of the parameter map for these commands may vary.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    MakeCredential(MakeCredentialCommand),
    GetAssertion(GetAssertionCommand),
    GetInfo,
    Unrecognized(u8),
}

impl<'b, C> minicbor::Decode<'b, C> for Command {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        match d.u8()? {
            0x01 => Ok(Command::MakeCredential(d.decode()?)),
            0x02 => Ok(Command::GetAssertion(d.decode()?)),
            0x04 => Ok(Command::GetInfo),
            type_ => Ok(Command::Unrecognized(type_)),
        }
    }
}

impl Command {
    pub fn decode_cbor(data: &[u8]) -> Result<Self, minicbor::decode::Error> {
        minicbor::decode(data)
    }
}

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorMakeCredential
#[derive(Debug, Encode, Decode, PartialEq, Eq)]
#[cbor(map)]
pub struct MakeCredentialCommand {
    #[n(0x01)]
    pub client_data_hash: Sha256,
    #[n(0x02)]
    pub rp: PublicKeyCredentialRpEntity,
    #[n(0x03)]
    pub user: PublicKeyCredentialUserEntity,
    #[n(0x04)]
    pub pub_key_cred_params: Vec<PublicKeyCredentialParameters>,
    #[n(0x05)]
    pub exclude_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    #[n(0x06)]
    pub extensions: Option<Extensions>,
    #[n(0x07)]
    pub options: Option<MakeCredentialOptions>,
    #[n(0x08)]
    pub pin_uv_auth_param: Option<PinUvAuthParam>,
    #[n(0x09)]
    pub pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
    #[n(0x0a)]
    pub enterprise_attestation: Option<u8>,
}

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct Extensions;

#[derive(Debug, PartialEq, Eq)]
pub struct MakeCredentialOptions {
    /// rk option key - Specifies whether this credential is to be discoverable or not.
    pub discoverable: bool,

    /// up option key - Is user consent required to complete the operation. MUST be true if present.
    /// The value false will cause a CTAP2_ERR_INVALID_OPTION response regardless of authenticator version.
    pub require_user_presence: bool,

    /// up option key - If true, user-verifying gesterued such as a fingerprint scan is required.
    /// Deprecated as of CTAP2.1
    pub require_user_verification: bool,
}

impl Default for MakeCredentialOptions {
    fn default() -> Self {
        Self {
            discoverable: false,
            require_user_presence: true,
            require_user_verification: false,
        }
    }
}

impl<'b, C> minicbor::Decode<'b, C> for MakeCredentialOptions {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let mut options = MakeCredentialOptions::default();

        let map_len = d
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("Expected sized map"))?;

        for _ in 0..map_len {
            let key = d.str()?;
            match key {
                "rk" => options.discoverable = d.decode()?,
                "up" => {
                    if !d.decode()? {
                        todo!("CTAP2_ERR_INVALID_OPTION");
                    }
                }
                "uv" => options.require_user_verification = d.decode()?,
                other => {
                    return Err(minicbor::decode::Error::message(format!(
                        "Unexpected map key \"{}\"",
                        other
                    )))
                }
            }
        }

        Ok(options)
    }
}

impl<C> minicbor::Encode<C> for MakeCredentialOptions {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let mut map_len = 2;
        if self.require_user_presence {
            map_len += 1;
        }
        e.map(map_len)?;

        e.str("rk")?.bool(self.discoverable)?;

        if self.require_user_presence {
            e.str("up")?.bool(true)?;
        }

        e.str("uv")?.bool(self.require_user_verification)?;

        Ok(())
    }
}

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct PinUvAuthParam;

#[derive(Debug, Encode, Decode, PartialEq, Eq)]
pub struct PinUvAuthProtocol;

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetAssertion
#[derive(Debug, Encode, Decode, PartialEq, Eq)]
#[cbor(map)]
pub struct GetAssertionCommand {
    #[n(0x01)]
    pub rp_id: RelyingPartyIdentifier,
    #[n(0x02)]
    pub client_data_hash: Sha256,

    /// An array of allowed credentials. The authenticator MUST only generate an assertion for one
    /// of the listed credentials, if the list is present. The list MUST NOT be empty, if the list
    /// would be empty the platform MUST omit the field.
    #[n(0x03)]
    pub allow_list: Option<Vec<PublicKeyCredentialDescriptor>>,
    //     extensions: Option<ExtensionMap>,
    //     options: Option<GetAssertionOptions>,
    //     pin_uv_auth_param: Option<PinUvAuthParam>,
    //     pin_uv_auth_protocol: Option<PinUvAuthProtocol>,
}

/// Messages from authenticator to the host, called a "response" in the CTAP2 protocol
#[allow(clippy::large_enum_variant)]
#[derive(Debug, PartialEq, Eq)]
pub enum Response {
    MakeCredential(MakeCredentialResponse),
    GetAssertion(GetAssertionResponse),
    GetInfo(GetInfoResponse),
}

impl<C> minicbor::Encode<C> for Response {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Response::MakeCredential(response) => {
                e.u8(0)?; // status, TODO encode this in a better place
                e.encode(response)?
            }
            Response::GetAssertion(response) => {
                e.u8(0)?; // status, TODO encode this in a better place
                e.encode(response)?
            }
            Response::GetInfo(info) => {
                e.u8(0)?; // status, TODO encode this in a better place
                e.encode(info)?
            }
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

#[derive(Debug, PartialEq, Eq)]
pub struct MakeCredentialResponse {
    pub auth_data: AuthenticatorData,
    pub att_stmt: AttestationStatement,
}

impl<C> minicbor::Encode<C> for MakeCredentialResponse {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(3)?;

        e.u8(0x01)?;
        e.encode(self.att_stmt.format())?;

        e.u8(0x02)?;
        e.encode(&self.auth_data)?;

        e.u8(0x03)?;
        e.encode(&self.att_stmt)?;

        Ok(())
    }
}

#[derive(Debug, minicbor_derive::Encode, PartialEq, Eq)]
#[cbor(map)]
pub struct GetAssertionResponse {
    #[n(0x01)]
    pub credential: PublicKeyCredentialDescriptor,
    #[n(0x02)]
    pub auth_data: AuthenticatorData,
    #[n(0x03)]
    pub signature: Signature,
    // todo optional fields
}

#[derive(Debug, PartialEq, Eq)]
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
        e.encode(self.aaguid)?;

        if let Some(ref algorithms) = self.algorithms {
            e.u8(0x0A)?;
            e.encode(algorithms)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::{Aaguid, RelyingPartyIdentifier};
    use crate::{COSEAlgorithmIdentifier, PublicKeyCredentialType, UserHandle};

    use super::*;
    use uuid::uuid;

    #[test]
    fn decode_make_credential_command() {
        // 1
        // {
        //    1: h'0F0476E70816EBD0405FCB705C1D06D29EBC1324BC8F21F34D627FB143F63081',
        //    2: {"id": "example.com", "name": "Example RP"},
        //    3: {"id": h'757365725F6964', "name": "A. User"},
        //    4: [{"alg": -7, "type": "public-key"}, {"alg": -8, "type": "public-key"}, {"alg": -37, "type": "public-key"}, {"alg": -257, "type": "public-key"}]
        // }
        assert_eq!(
            Command::decode_cbor(&[
                1, 164, 1, 88, 32, 15, 4, 118, 231, 8, 22, 235, 208, 64, 95, 203, 112, 92, 29, 6,
                210, 158, 188, 19, 36, 188, 143, 33, 243, 77, 98, 127, 177, 67, 246, 48, 129, 2,
                162, 98, 105, 100, 107, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 100,
                110, 97, 109, 101, 106, 69, 120, 97, 109, 112, 108, 101, 32, 82, 80, 3, 162, 98,
                105, 100, 71, 117, 115, 101, 114, 95, 105, 100, 100, 110, 97, 109, 101, 103, 65,
                46, 32, 85, 115, 101, 114, 4, 132, 162, 99, 97, 108, 103, 38, 100, 116, 121, 112,
                101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162, 99, 97, 108, 103, 39,
                100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99, 45, 107, 101, 121, 162,
                99, 97, 108, 103, 56, 36, 100, 116, 121, 112, 101, 106, 112, 117, 98, 108, 105, 99,
                45, 107, 101, 121, 162, 99, 97, 108, 103, 57, 1, 0, 100, 116, 121, 112, 101, 106,
                112, 117, 98, 108, 105, 99, 45, 107, 101, 121
            ])
            .unwrap(),
            Command::MakeCredential(MakeCredentialCommand {
                client_data_hash: Sha256::new([
                    15, 4, 118, 231, 8, 22, 235, 208, 64, 95, 203, 112, 92, 29, 6, 210, 158, 188,
                    19, 36, 188, 143, 33, 243, 77, 98, 127, 177, 67, 246, 48, 129,
                ]),
                rp: PublicKeyCredentialRpEntity {
                    id: RelyingPartyIdentifier::new(String::from("example.com")),
                    name: String::from("Example RP")
                },
                user: PublicKeyCredentialUserEntity {
                    id: UserHandle::new(vec![0x75, 0x73, 0x65, 0x72, 0x5F, 0x69, 0x64]),
                    display_name: String::from(""),
                    name: String::from("A. User")
                },
                pub_key_cred_params: vec![
                    PublicKeyCredentialParameters {
                        alg: COSEAlgorithmIdentifier::ES256,
                        type_: PublicKeyCredentialType::PublicKey,
                    },
                    PublicKeyCredentialParameters {
                        alg: COSEAlgorithmIdentifier::EdDSA,
                        type_: PublicKeyCredentialType::PublicKey,
                    },
                    PublicKeyCredentialParameters {
                        alg: COSEAlgorithmIdentifier::PS256,
                        type_: PublicKeyCredentialType::PublicKey,
                    },
                    PublicKeyCredentialParameters {
                        alg: COSEAlgorithmIdentifier::RS256,
                        type_: PublicKeyCredentialType::PublicKey,
                    }
                ],
                exclude_list: None,
                extensions: None,
                options: None,
                pin_uv_auth_param: None,
                pin_uv_auth_protocol: None,
                enterprise_attestation: None
            })
        );
    }

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
                0, 162, 1, 128, 3, 80, 103, 229, 80, 68, 16, 177, 66, 111, 146, 71, 187, 104, 14,
                95, 224, 200
            ]
        );
    }

    #[test]
    fn encode_make_credential_options_defaults() {
        assert_eq!(
            encode(MakeCredentialOptions::default()),
            vec![163, 98, 114, 107, 244, 98, 117, 112, 245, 98, 117, 118, 244]
        );
    }

    #[test]
    fn encode_make_credential_options_with_false_user_presence_option_should_not_include_up_key() {
        assert_eq!(
            encode(MakeCredentialOptions::default()),
            vec![163, 98, 114, 107, 244, 98, 117, 112, 245, 98, 117, 118, 244]
        );
        assert_eq!(
            encode(MakeCredentialOptions {
                discoverable: false,
                require_user_presence: false,
                require_user_verification: false,
            }),
            vec![162, 98, 114, 107, 244, 98, 117, 118, 244]
        );
    }

    #[test]
    fn decode_make_credential_options_defaults() {
        assert_eq!(
            decode::<MakeCredentialOptions>(&[
                163, 98, 114, 107, 244, 98, 117, 112, 245, 98, 117, 118, 244
            ]),
            MakeCredentialOptions::default()
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

    fn decode<'b, T: minicbor::Decode<'b, ()>>(data: &'b [u8]) -> T {
        minicbor::decode(data).unwrap()
    }
}
