use minicbor::{Decode, Encode};

#[allow(dead_code)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum COSEAlgorithmIdentifier {
    ES256 = -7,
    ES384 = -35,
    ES512 = -36,
    EdDSA = -8,
}

impl<C> Encode<C> for COSEAlgorithmIdentifier {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.i8(*self as i8)?.ok()
    }
}
impl<'b, C> Decode<'b, C> for COSEAlgorithmIdentifier {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        match d.i8()? {
            -7 => Ok(COSEAlgorithmIdentifier::ES256),
            _ => Err(minicbor::decode::Error::message(
                "Unrecognized algorithm identifier",
            )),
        }
    }
}

#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
pub struct PublicKeyCredentialRpEntity {
    // A unique identifier for the Relying Party entity, used as the RP ID
    id: String,

    // A human-palatable name for the Relying Party, intended only for display
    name: String,
}

impl<C> Encode<C> for PublicKeyCredentialRpEntity {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?
            .str("id")?
            .str(&self.id)?
            .str("name")?
            .str(&self.name)?
            .ok()
    }
}
impl<'b, C> Decode<'b, C> for PublicKeyCredentialRpEntity {
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
        let id = d.str()?;

        if d.str()? != "name" {
            return Err(minicbor::decode::Error::message(
                "Expected map key \"name\"",
            ));
        }
        let name: &'b str = Decode::decode(d, ctx)?;

        Ok(PublicKeyCredentialRpEntity {
            id: id.to_string(),
            name: name.to_string(),
        })
    }
}

// Additional user account attribute map used when creating a new credential
#[derive(Debug)]
pub struct PublicKeyCredentialUserEntity {
    /// The user handle of the user account. Authentication and authorization
    /// decisions MUST be made on the basis of this member, not displayName or name
    id: UserHandle,

    display_name: String,

    /// Human-palatable identifier for a user account, intended only for display.
    /// May be used to help the user differentiate accounts with similar display names.
    /// Fox example "alexm", "alex.mueller@example.com" or "+14255551234".
    name: String,
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
        let map_len = d
            .map()?
            .ok_or(minicbor::decode::Error::message("Expected sized map"))?;
        if map_len != 3 {
            return Err(minicbor::decode::Error::message(
                "Expected map of exactly size 3",
            ));
        }

        let id_key: &'b str = Decode::decode(d, ctx)?;
        if id_key != "id" {
            return Err(minicbor::decode::Error::message("Expected map key \"id\""));
        }
        let id: UserHandle = Decode::decode(d, ctx)?;

        let name_key: &'b str = Decode::decode(d, ctx)?;
        if name_key != "name" {
            return Err(minicbor::decode::Error::message(
                "Expected map key \"name\"",
            ));
        }
        let name: &'b str = Decode::decode(d, ctx)?;

        let display_name_key: &'b str = Decode::decode(d, ctx)?;
        if display_name_key != "displayName" {
            return Err(minicbor::decode::Error::message(
                "Expected map key \"displayName\"",
            ));
        }
        let display_name: &'b str = Decode::decode(d, ctx)?;

        Ok(PublicKeyCredentialUserEntity {
            id: id,
            name: name.to_string(),
            display_name: display_name.to_string(),
        })
    }
}

/// Opaque byte sequence with a maximum size of 64 bytes. Not meant for display
/// to the user. MUST NOT contain personally identifying information and
/// MUST NOT be empty.
#[derive(Debug)]
pub struct UserHandle(Vec<u8>);

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

#[derive(Debug)]
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
#[derive(Debug)]
pub struct RelyingPartyIdentifier(String);

impl<C> Encode<C> for RelyingPartyIdentifier {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.str(&self.0)?.ok()
    }
}
impl<'b, C> Decode<'b, C> for RelyingPartyIdentifier {
    fn decode(d: &mut minicbor::Decoder<'b>, ctx: &mut C) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(d.str()?.to_string()))
    }
}
