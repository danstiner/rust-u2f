use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};

use crate::Sha256;

/// See https://www.w3.org/TR/2019/PR-webauthn-20190117/#typedefdef-cosealgorithmidentifier
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum COSEAlgorithmIdentifier {
    ES256 = -7, // ECDSA w/ SHA-256, first default option
    EdDSA = -8,
    ES384 = -35,
    ES512 = -36,
    PS256 = -37,
    RS256 = -257,
}

impl<C> Encode<C> for COSEAlgorithmIdentifier {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.i16(*self as i16)?.ok()
    }
}
impl<'b, C> Decode<'b, C> for COSEAlgorithmIdentifier {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let type_ = d.i16()?;
        match type_ {
            _ if type_ == COSEAlgorithmIdentifier::ES256 as i16 => {
                Ok(COSEAlgorithmIdentifier::ES256)
            }
            _ if type_ == COSEAlgorithmIdentifier::EdDSA as i16 => {
                Ok(COSEAlgorithmIdentifier::EdDSA)
            }
            _ if type_ == COSEAlgorithmIdentifier::ES512 as i16 => {
                Ok(COSEAlgorithmIdentifier::ES512)
            }
            _ if type_ == COSEAlgorithmIdentifier::PS256 as i16 => {
                Ok(COSEAlgorithmIdentifier::PS256)
            }
            _ if type_ == COSEAlgorithmIdentifier::RS256 as i16 => {
                Ok(COSEAlgorithmIdentifier::RS256)
            }
            _ => Err(minicbor::decode::Error::message(
                "Unrecognized algorithm identifier",
            )),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct PublicKeyCredentialDescriptor {
    type_: String,
    id: CredentialId,
    //TODO optional transports: Vec<String>,
}

impl<C> Encode<C> for PublicKeyCredentialDescriptor {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?
            .str("id")?
            .encode(&self.id)?
            .str("type")?
            .str(&self.type_)?
            .ok()
    }
}
impl<'b, C> Decode<'b, C> for PublicKeyCredentialDescriptor {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let map_len = d
            .map()?
            .ok_or(minicbor::decode::Error::message("Expected sized map"))?;
        if map_len != 2 {
            return Err(minicbor::decode::Error::message(
                "Expected map of exactly size 2",
            ));
        }

        if d.str()? != "id" {
            return Err(minicbor::decode::Error::message("Expected map key \"id\""));
        }
        let id = Decode::decode(d, ctx)?;

        if d.str()? != "type" {
            return Err(minicbor::decode::Error::message(
                "Expected map key \"type\"",
            ));
        }
        let type_: &'b str = d.str()?;

        Ok(PublicKeyCredentialDescriptor {
            id: id,
            type_: type_.to_string(),
        })
    }
}

/// Parameters for Credential Generation from WebAuthn spec
/// https://www.w3.org/TR/webauthn-2/#dictionary-credential-params
#[derive(Debug, PartialEq)]
pub struct PublicKeyCredentialParameters {
    pub alg: COSEAlgorithmIdentifier,
    pub type_: PublicKeyCredentialType,
}

impl PublicKeyCredentialParameters {
    pub fn es256() -> Self {
        Self {
            alg: COSEAlgorithmIdentifier::ES256,
            type_: PublicKeyCredentialType::PublicKey,
        }
    }
}

impl<C> Encode<C> for PublicKeyCredentialParameters {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?
            .str("alg")?
            .encode(&self.alg)?
            .str("type")?
            .encode(&self.type_)?
            .ok()
    }
}

// TODO update this validation
// If the element is missing required members, including members that are mandatory only for the specific type, then return an error, for example CTAP2_ERR_INVALID_CBOR.
// If the values of any known members have the wrong type then return an error, for example CTAP2_ERR_CBOR_UNEXPECTED_TYPE.
// Note: This means always iterating over every element of pubKeyCredParams to validate them.
impl<'b, C> Decode<'b, C> for PublicKeyCredentialParameters {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let map_len = d
            .map()?
            .ok_or(minicbor::decode::Error::message("Expected sized map"))?;
        if map_len != 2 {
            return Err(minicbor::decode::Error::message(
                "Expected map of exactly size 2",
            ));
        }

        if d.str()? != "alg" {
            return Err(minicbor::decode::Error::message("Expected map key \"alg\""));
        }
        let alg = Decode::decode(d, ctx)?;

        if d.str()? != "type" {
            return Err(minicbor::decode::Error::message(
                "Expected map key \"type\"",
            ));
        }
        let type_ = Decode::decode(d, ctx)?;

        Ok(PublicKeyCredentialParameters { alg, type_ })
    }
}

/// https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub enum PublicKeyCredentialType {
    PublicKey,
    Unknown(String),
}

impl<C> Encode<C> for PublicKeyCredentialType {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            PublicKeyCredentialType::PublicKey => e.str("public-key")?,
            PublicKeyCredentialType::Unknown(s) => e.str(s)?,
        };
        Ok(())
    }
}

impl<'b, C> Decode<'b, C> for PublicKeyCredentialType {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        match d.str()? {
            "public-key" => Ok(PublicKeyCredentialType::PublicKey),
            type_ => Ok(PublicKeyCredentialType::Unknown(type_.to_owned())),
        }
    }
}

/// Relying Party attribute map, used when creating a new credential
#[derive(Debug, PartialEq)]
pub struct PublicKeyCredentialRpEntity {
    // A unique identifier for the Relying Party entity, used as the RP ID
    pub id: RelyingPartyIdentifier,

    // A human-palatable name for the Relying Party, intended only for display
    pub name: String,
}

impl<C> Encode<C> for PublicKeyCredentialRpEntity {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?
            .str("id")?
            .str(&self.id.0)?
            .str("name")?
            .str(&self.name)?
            .ok()
    }
}
impl<'b, C> Decode<'b, C> for PublicKeyCredentialRpEntity {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let map_len = d.map()?.ok_or(
            minicbor::decode::Error::message("Expected sized map for PublicKeyCredentialRpEntity")
                .at(d.position()),
        )?;
        if map_len != 2 {
            return Err(minicbor::decode::Error::message(
                "Expected map of exactly size 2 for PublicKeyCredentialRpEntity",
            )
            .at(d.position()));
        }

        let key = d.str()?;
        if key != "id" {
            return Err(minicbor::decode::Error::message(format!(
                "Expected map key \"id\" for PublicKeyCredentialRpEntity, got \"{}\"",
                key
            ))
            .at(d.position()));
        }
        let id = d.str()?;

        let key = d.str()?;
        if key != "name" {
            return Err(minicbor::decode::Error::message(format!(
                "Expected map key \"name\" for PublicKeyCredentialRpEntity, got \"{}\"",
                key
            ))
            .at(d.position()));
        }
        let name: &'b str = Decode::decode(d, ctx)?;

        Ok(PublicKeyCredentialRpEntity {
            id: RelyingPartyIdentifier(id.to_string()),
            name: name.to_string(),
        })
    }
}

// Additional user account attribute map used when creating a new credential
#[derive(Debug, PartialEq)]
pub struct PublicKeyCredentialUserEntity {
    /// The user handle of the user account. Authentication and authorization
    /// decisions MUST be made on the basis of this member, not displayName or name
    pub id: UserHandle,

    pub display_name: String,

    /// Human-palatable identifier for a user account, intended only for display.
    /// May be used to help the user differentiate accounts with similar display names.
    /// Fox example "alexm", "alex.mueller@example.com" or "+14255551234".
    pub name: String,
}

impl<C> Encode<C> for PublicKeyCredentialUserEntity {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(3)?
            .str("id")?
            .encode(&self.id)?
            .str("name")?
            .str(&self.name)?
            .str("displayName")?
            .str(&self.display_name)?
            .ok()
    }
}
impl<'b, C> Decode<'b, C> for PublicKeyCredentialUserEntity {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        let map_len = d.map()?.ok_or(
            minicbor::decode::Error::message(
                "Expected sized map for PublicKeyCredentialUserEntity",
            )
            .at(d.position()),
        )?;
        if map_len > 3 {
            return Err(minicbor::decode::Error::message(
                "Expected map of size 3 or less for PublicKeyCredentialUserEntity",
            )
            .at(d.position()));
        }

        let mut id = None;
        let mut display_name = None;
        let mut name = None;

        for _ in 0..map_len {
            let key = d.str()?;
            match key {
                "id" => {
                    id = Some(Decode::decode(d, ctx)?);
                }
                "displayName" => {
                    display_name = Some(Decode::decode(d, ctx)?);
                }
                "name" => {
                    name = Some(Decode::decode(d, ctx)?);
                }
                _ => {
                    return Err(minicbor::decode::Error::message(format!(
                        "Unexpected map key '{}' when decoding PublicKeyCredentialUserEntity",
                        key
                    ))
                    .at(d.position()))
                }
            }
        }

        Ok(PublicKeyCredentialUserEntity {
            id: id.ok_or_else(|| {
                minicbor::decode::Error::message(
                    "Required key id not present decoding PublicKeyCredentialUserEntity",
                )
                .at(d.position())
            })?,
            name: name.unwrap_or_default(),
            display_name: display_name.unwrap_or_default(),
        })
    }
}

/// Opaque byte sequence with a maximum size of 64 bytes. Not meant for display
/// to the user. MUST NOT contain personally identifying information and
/// MUST NOT be empty.
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct UserHandle(Vec<u8>);

impl UserHandle {
    pub fn new(id: Vec<u8>) -> Self {
        assert!(id.len() > 0);
        assert!(id.len() <= 64);
        UserHandle(id)
    }
}

impl<C> Encode<C> for UserHandle {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}
impl<'b, C> Decode<'b, C> for UserHandle {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(d.bytes()?.to_vec()))
    }
}

#[derive(Debug, PartialEq)]
pub struct CredentialId(Vec<u8>);

impl<C> Encode<C> for CredentialId {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}
impl<'b, C> Decode<'b, C> for CredentialId {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(d.bytes()?.to_vec()))
    }
}

/// A valid domain string identifying on whose behalf a registration or
/// autentication ceremony is being performed. A credential may only be used
/// for authentication with the same identifier it was registered with.
///
/// aka RP ID
///
/// For WebAuthn it will be the origin's effective domain or a suffix thereof.
/// https://www.w3.org/TR/webauthn-2/#relying-party-identifier
#[derive(
    Debug,
    Serialize,
    Deserialize,
    minicbor_derive::Encode,
    minicbor_derive::Decode,
    PartialEq,
    Clone,
)]
#[cbor(transparent)]
pub struct RelyingPartyIdentifier(#[n(0)] String);

impl RelyingPartyIdentifier {
    pub fn new(id: String) -> Self {
        Self(id)
    }
}

/// https://www.w3.org/TR/webauthn-2/#authenticator-data
struct AuthenticatorData {
    /// SHA-256 hash of the RP ID the credential is scoped to.
    rp_id_hash: Sha256,

    // flags

    // Signature counter, 32-bit unsigned big-endian integer.
    sign_count: u32,
}
