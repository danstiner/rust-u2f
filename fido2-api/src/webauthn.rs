use bitflags::bitflags;
use byteorder::{BigEndian, WriteBytesExt};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

use crate::{Aaguid, Sha256};

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

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct PublicKeyCredentialDescriptor {
    pub type_: PublicKeyCredentialType,
    pub id: CredentialId,
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
            .encode(&self.type_)?
            .ok()
    }
}

impl<'b, C> Decode<'b, C> for PublicKeyCredentialDescriptor {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let map_len = d
            .map()?
            .ok_or_else(|| minicbor::decode::Error::message("Expected sized map"))?;
        if map_len != 2 {
            return Err(minicbor::decode::Error::message(
                "Expected map of exactly size 2",
            ));
        }

        if d.str()? != "id" {
            return Err(minicbor::decode::Error::message("Expected map key \"id\""));
        }
        let id = d.decode()?;

        if d.str()? != "type" {
            return Err(minicbor::decode::Error::message(
                "Expected map key \"type\"",
            ));
        }
        let type_ = d.decode()?;

        Ok(PublicKeyCredentialDescriptor { id, type_ })
    }
}

/// Parameters for Credential Generation from WebAuthn spec
/// https://www.w3.org/TR/webauthn-2/#dictionary-credential-params
#[derive(Debug, PartialEq, Eq)]
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
            .encode(self.alg)?
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
            .ok_or_else(|| minicbor::decode::Error::message("Expected sized map"))?;
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
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub enum PublicKeyCredentialType {
    #[serde(rename = "public-key")]
    PublicKey,
    #[serde(skip)]
    Unknown(String),
}

impl fmt::Display for PublicKeyCredentialType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PublicKeyCredentialType::PublicKey => write!(f, "public-key"),
            PublicKeyCredentialType::Unknown(type_) => write!(f, "{}", type_),
        }
    }
}

impl FromStr for PublicKeyCredentialType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "public-key" => Ok(PublicKeyCredentialType::PublicKey),
            s => Ok(PublicKeyCredentialType::Unknown(s.to_owned())),
        }
    }
}

impl<C> Encode<C> for PublicKeyCredentialType {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.str(&self.to_string())?.ok()
    }
}

impl<'b, C> Decode<'b, C> for PublicKeyCredentialType {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        if let Ok(r) = Self::from_str(d.str()?) {
            Ok(r)
        } else {
            Err(todo!())
        }
    }
}

/// Relying Party attribute map, used when creating a new credential
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct PublicKeyCredentialRpEntity {
    // A unique identifier for the Relying Party entity, used as the RP ID
    pub id: RelyingPartyIdentifier,

    // A human-palatable name for the Relying Party, intended only for display
    pub name: String,
}

impl fmt::Display for PublicKeyCredentialRpEntity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({})", self.id, self.name)
    }
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
        let map_len = d.map()?.ok_or_else(|| {
            minicbor::decode::Error::message("Expected sized map for PublicKeyCredentialRpEntity")
                .at(d.position())
        })?;
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
#[derive(Debug, PartialEq, Eq)]
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
        let map_len = d.map()?.ok_or_else(|| {
            minicbor::decode::Error::message("Expected sized map for PublicKeyCredentialUserEntity")
                .at(d.position())
        })?;
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
#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, Clone)]
pub struct UserHandle(Vec<u8>);

impl UserHandle {
    pub fn new(id: Vec<u8>) -> Self {
        assert!(!id.is_empty());
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
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(d.bytes()?.to_vec()))
    }
}

impl AsRef<[u8]> for UserHandle {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<Vec<u8>> for UserHandle {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(UserHandle::new(value))
    }
}

/// A probabilistically-unique byte sequence identifying a public key credential source and its authentication assertions.
/// Must be at least 16 bytes and include at least 100 bits of entropy.
#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, Clone)]
pub struct CredentialId(Vec<u8>);

impl CredentialId {
    pub fn new(value: &[u8]) -> Self {
        CredentialId(value.to_vec())
    }
}

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
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(d.bytes()?.to_vec()))
    }
}

impl AsRef<[u8]> for CredentialId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl TryFrom<Vec<u8>> for CredentialId {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(CredentialId(value))
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
    Hash,
    PartialEq,
    Eq,
    Clone,
)]
#[cbor(transparent)]
pub struct RelyingPartyIdentifier(#[n(0)] String);

impl RelyingPartyIdentifier {
    pub fn new(id: String) -> Self {
        Self(id)
    }
}

impl fmt::Display for RelyingPartyIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<[u8]> for RelyingPartyIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// The authenticator data structure is a byte array of 37 bytes or more that
/// encodes contextual bindings made by the authenticator.
/// https://www.w3.org/TR/webauthn-2/#authenticator-data
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AuthenticatorData {
    /// SHA-256 hash of the RP ID the credential is scoped to.
    pub rp_id_hash: Sha256,

    // flags
    pub user_present: bool,
    pub user_verified: bool,

    /// Signature counter, 32-bit unsigned big-endian integer.
    pub sign_count: u32,

    /// Attested credential data (if present)
    pub attested_credential_data: Option<Vec<AttestedCredentialData>>,
}

impl AuthenticatorData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut flags = AuthenticatorDataFlags::empty();
        if self.user_present {
            flags |= AuthenticatorDataFlags::UP;
        }
        if self.user_verified {
            flags |= AuthenticatorDataFlags::UV;
        }
        if self.attested_credential_data.is_some() {
            flags |= AuthenticatorDataFlags::AT;
        }

        let mut buf = Vec::with_capacity(37);
        buf.extend_from_slice(self.rp_id_hash.as_ref());
        buf.push(flags.bits);
        buf.write_u32::<BigEndian>(self.sign_count).unwrap();
        if let Some(ref attested_credential_data) = self.attested_credential_data {
            for attested in attested_credential_data {
                buf.extend_from_slice(attested.aaguid.as_ref());
                buf.write_u16::<BigEndian>(
                    attested.credential_id.as_ref().len().try_into().unwrap(),
                )
                .unwrap();
                buf.extend_from_slice(attested.credential_id.as_ref());
                minicbor::encode(&attested.credential_public_key, &mut buf).unwrap();
            }
        }
        buf
    }
}

impl<C> minicbor::Encode<C> for AuthenticatorData {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.to_bytes())?;
        Ok(())
    }
}

bitflags! {
    pub struct AuthenticatorDataFlags: u8 {
        const UP = 0b0000_0001; // Indicates the user is present
        const UV = 0b0000_0100; // Indicates the user is verified
        const AT = 0b0100_0000; // Indicates the authenticator added attested credential data
        const ED = 0b1000_0000; // Indicates the authenticator data has extensions
    }
}

/// https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AttestedCredentialData {
    pub aaguid: Aaguid,
    pub credential_id: CredentialId,
    pub credential_public_key: CredentialPublicKey,
}

/// A credential public key is the public key portion of a credential key pair.
/// The credential public key is returned to the Relying Party during a registration ceremony.
///
/// A credential key pair is a pair of asymmetric cryptographic keys generated by an authenticator
/// and scoped to a specific WebAuthn Relying Party. It is the central part of a public key credential.
///
/// The credential public key encoded in COSE_Key format, as defined in Section 7 of [RFC8152],
/// using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded credential public key
/// MUST contain the "alg" parameter and MUST NOT contain any other OPTIONAL parameters.
/// The "alg" parameter MUST contain a COSEAlgorithmIdentifier value. The encoded credential
/// public key MUST also contain any additional REQUIRED parameters stipulated by the relevant key
/// type specification, i.e., REQUIRED for the key type "kty" and algorithm "alg" (see Section 8 of [RFC8152]).
///
/// Note: The credential public key is referred to as the user public key in FIDO UAF and U2F.
/// https://www.w3.org/TR/webauthn-2/#credential-public-key
#[derive(Debug, PartialEq, Eq, Clone)]
// #[cbor(map)]
pub struct CredentialPublicKey {
    // #[n(0x01)]
    pub kty: KeyType,
    // #[n(0x03)]
    pub alg: COSEAlgorithmIdentifier,
    // #[n(0x20)]
    pub crv: EllipticCurve,
    // #[n(0x21)]
    pub x: [u8; 32],
    // #[n(0x22)]
    pub y: [u8; 32],
}

impl<C> Encode<C> for CredentialPublicKey {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(5)?
            .i8(1)?
            .encode(self.kty)?
            .i8(3)?
            .encode(self.alg)?
            .i8(-1)?
            .encode(self.crv)?
            .i8(-2)?
            .bytes(&self.x)?
            .i8(-3)?
            .bytes(&self.y)?
            .ok()
    }
}

/// Key types define a format for transmitting pblic and private keys.
/// https://www.rfc-editor.org/rfc/rfc8152#section-13
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum KeyType {
    /// This value is reserved
    Reserved = 0,
    /// Octet Key Pair
    OKP = 1,
    /// Elliptic Curve Keys w/ x- and y-coordinate pair    
    EC2 = 2,
    /// Symmetric Keys
    Symmetric = 4,
}

impl<C> Encode<C> for KeyType {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u8(*self as u8)?.ok()
    }
}

/// https://www.rfc-editor.org/rfc/rfc8152#section-13.1
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EllipticCurve {
    /// NIST P-256 also known as secp256r1, uses KeyType::EC2
    P256 = 1,
}

impl<C> Encode<C> for EllipticCurve {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u8(*self as u8)?.ok()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AttestationStatement {
    /// https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
    Packed(PackedAttestationStatement),

    /// https://www.w3.org/TR/webauthn-2/#sctn-none-attestation
    None,
}

impl AttestationStatement {
    pub fn format(&self) -> &str {
        match self {
            AttestationStatement::Packed(_) => "packed",
            AttestationStatement::None => "none",
        }
    }
}

impl<C> Encode<C> for AttestationStatement {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            AttestationStatement::Packed(statement) => e.encode(statement)?.ok(),
            AttestationStatement::None => e.map(0)?.ok(),
        }
    }
}

/// https://www.w3.org/TR/webauthn-2/#sctn-packed-attestation
#[derive(Debug, PartialEq, Eq)]
pub struct PackedAttestationStatement {
    pub alg: COSEAlgorithmIdentifier,
    pub sig: Signature,
    pub x5c: Option<AttestationCertificate>,
}

impl<C> Encode<C> for PackedAttestationStatement {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?
            .str("alg")?
            .encode(self.alg)?
            .str("sig")?
            .bytes(self.sig.as_ref())?
            .ok()
    }
}

/// An attestation certificate and its certificate chain (if any), each encoded in X.509 format
#[derive(Debug, PartialEq, Eq)]
pub struct AttestationCertificate {
    pub attestation_certificate: Vec<u8>,
    pub ca_certificate_chain: Vec<Vec<u8>>,
}

/// A WebAuthn signature is the result of signing authenticator data and the client data hash.
/// It can be an attestation signature or assertion signature.
/// https://www.w3.org/TR/webauthn-2/#webauthn-signature
#[derive(Debug, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    pub fn new(value: &[u8]) -> Signature {
        Signature(value.to_vec())
    }
}

impl<C> Encode<C> for Signature {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.bytes(&self.0)?.ok()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
