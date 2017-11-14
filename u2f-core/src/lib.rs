#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate slog;
#[macro_use]
extern crate quick_error;

extern crate base64;
extern crate byteorder;
extern crate crypto;
extern crate futures;
extern crate openssl;
extern crate rand;
extern crate serde;
extern crate slog_stdlog;
extern crate subtle;
extern crate tokio_service;
extern crate u2f_header;

mod known_facets;
mod self_signed_attestation;

use std::fmt::{self, Debug};
use std::io::{self, Cursor};
use std::io::Read;
use std::rc::Rc;
use std::result::Result;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use futures::Future;
use futures::future;
use openssl::bn::BigNumContext;
use openssl::bn::BigNumContextRef;
use openssl::ec::{self, EcGroup, EcKey, EcPoint, EcGroupRef, EcPointRef};
use openssl::hash::MessageDigest;
use openssl::nid;
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::x509::X509;
use rand::OsRng;
use rand::Rand;
use rand::Rng;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use slog::Drain;

use self_signed_attestation::{SELF_SIGNED_ATTESTATION_KEY_PEM,
                              SELF_SIGNED_ATTESTATION_CERTIFICATE_PEM};

const REGISTER_COMMAND_CODE: u8 = 0x01;
const AUTHENTICATE_COMMAND_CODE: u8 = 0x02;
const VERSION_COMMAND_CODE: u8 = 0x03;
const VENDOR_FIRST_COMMAND_CODE: u8 = 0x40;
const VENDOR_LAST_COMMAND_CODE: u8 = 0xbf;

const SW_NO_ERROR: u16 = 0x9000; // The command completed successfully without error.
const SW_WRONG_DATA: u16 = 0x6A80; // The request was rejected due to an invalid key handle.
const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985; // The request was rejected due to test-of-user-presence being required.
const SW_COMMAND_NOT_ALLOWED: u16 = 0x6986;
const SW_INS_NOT_SUPPORTED: u16 = 0x6D00; // The Instruction of the request is not supported.
const SW_WRONG_LENGTH: u16 = 0x6700; // The length of the request was invalid.
const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00; // The Class byte of the request is not supported.
const SW_UNKNOWN: u16 = 0x6F00; // Response status : No precise diagnosis

const AUTH_ENFORCE: u8 = 0x03; // Enforce user presence and sign
const AUTH_CHECK_ONLY: u8 = 0x07; // Check only
const AUTH_FLAG_TUP: u8 = 0x01; // Test of user presence set

pub use known_facets::try_reverse_application_id;

#[derive(Debug)]
pub enum StatusCode {
    NoError,
    TestOfUserPresenceNotSatisfied,
    InvalidKeyHandle,
    RequestLengthInvalid,
    RequestClassNotSupported,
    RequestInstructionNotSuppored,
    UnknownError,
}

impl StatusCode {
    pub fn write<W: WriteBytesExt>(&self, write: &mut W) {
        let value = match self {
            &StatusCode::NoError => SW_NO_ERROR,
            &StatusCode::TestOfUserPresenceNotSatisfied => SW_CONDITIONS_NOT_SATISFIED,
            &StatusCode::InvalidKeyHandle => SW_WRONG_DATA,
            &StatusCode::RequestLengthInvalid => SW_WRONG_LENGTH,
            &StatusCode::RequestClassNotSupported => SW_CLA_NOT_SUPPORTED,
            &StatusCode::RequestInstructionNotSuppored => SW_INS_NOT_SUPPORTED,
            &StatusCode::UnknownError => SW_UNKNOWN,
        };
        write.write_u16::<BigEndian>(value).unwrap();
    }
}

#[derive(Debug)]
pub enum AuthenticateControlCode {
    CheckOnly,
    EnforceUserPresenceAndSign,
    DontEnforceUserPresenceAndSign,
}

#[derive(Debug)]
pub enum Request {
    Register {
        application: ApplicationParameter,
        challenge: ChallengeParameter,
    },
    Authenticate {
        application: ApplicationParameter,
        challenge: ChallengeParameter,
        control_code: AuthenticateControlCode,
        key_handle: KeyHandle,
    },
    GetVersion,
    Wink,
}

impl Request {
    /// Only supports Extended Length Encoding
    pub fn decode(data: &[u8]) -> Result<Request, ()> {
        let mut reader = Cursor::new(data);

        // CLA: Reserved to be used by the underlying transport protocol
        let class_byte = reader.read_u8().unwrap();
        // TODO check or error with RequestClassNotSupported

        // INS: U2F command code
        let command_code = reader.read_u8().unwrap();
        // TODO check or error with RequestInstructionNotSuppored

        // P1, P2: Parameter 1 and 2, defined by each command.
        let parameter1 = reader.read_u8().unwrap();
        let parameter2 = reader.read_u8().unwrap();

        // Lc: The length of the request-data.
        // If there are no request data bytes, Lc is omitted.
        let remaining_len = data.len() - reader.position() as usize;
        let request_data_len = match remaining_len {
            3 => {
                // Lc is omitted because there are no request data bytes
                0
            }
            _ => {
                let zero_byte = reader.read_u8().unwrap();
                assert_eq!(zero_byte, 0);
                let mut value = reader.read_u16::<BigEndian>().unwrap() as usize;
                if value == 0 {
                    // Maximum length of request-data is 65 535 bytes.
                    // The MSB is lost when encoding to two bytes, but
                    // since Lc is omitted when there are no request data
                    // bytes, we can unambigously assume 0 to mean 65 535
                    value = 65535;
                }
                value
            }
        };

        // Request-data
        let mut request_data = vec![0u8; request_data_len];
        reader.read_exact(&mut request_data[..]).unwrap();

        // Le: The maximum expected length of the response data.
        // If no response data are expected, Le may be omitted.
        let remaining_len = data.len() - reader.position() as usize;
        let max_response_data_len = match remaining_len {
            0 => {
                // Instruction is not expected to yield any response bytes, Le omitted
                0
            }
            2 => {
                // When Lc is present, i.e. Nc > 0, Le is encoded as: Le1 Le2
                // When N e = 65 536, let Le1 = 0 and Le2 = 0.
                let mut value = reader.read_u16::<BigEndian>().unwrap() as usize;
                if value == 0 {
                    // Maximum length of request-data is 65 535 bytes.
                    // The MSB is lost when encoding to two bytes, but
                    // since Lc is omitted when there are no request data
                    // bytes, we can unambigously assume 0 to mean 65 535
                    value = 65535;
                }
                value
            }
            3 => {
                // When L c is absent, i.e. if Nc = 0,
                // Le is encoded as: 0 Le1 Le2
                // In other words, Le has a single-byte prefix of 0 when Lc is absent.
                let zero_byte = reader.read_u8().unwrap();
                assert_eq!(zero_byte, 0);
                let mut value = reader.read_u16::<BigEndian>().unwrap() as usize;
                if value == 0 {
                    // Maximum length of request-data is 65 535 bytes.
                    // The MSB is lost when encoding to two bytes, but
                    // since Lc is omitted when there are no request data
                    // bytes, we can unambigously assume 0 to mean 65 535
                    value = 65535;
                }
                value
            }
            _ => return Err(()),
        };

        // TODO If the instruction is not expected to yield any response bytes, L e may be omitted. O
        let mut reader = Cursor::new(request_data);
        let request = match command_code {
            REGISTER_COMMAND_CODE => {
                // The challenge parameter [32 bytes].
                let mut challenge_parameter = [0u8; 32];
                reader.read_exact(&mut challenge_parameter[..]).unwrap();

                // The application parameter [32 bytes].
                let mut application_parameter = [0u8; 32];
                reader.read_exact(&mut application_parameter[..]).unwrap();

                assert_eq!(reader.position() as usize, request_data_len);
                Request::Register {
                    application: ApplicationParameter(application_parameter),
                    challenge: ChallengeParameter(challenge_parameter),
                }
            }
            AUTHENTICATE_COMMAND_CODE => {
                assert_eq!(parameter2, 0);

                // Control byte (P1).
                let control_code = match parameter1 {
                    AUTH_CHECK_ONLY => AuthenticateControlCode::CheckOnly,
                    AUTH_ENFORCE => AuthenticateControlCode::EnforceUserPresenceAndSign,
                    AUTH_ENFORCE | AUTH_FLAG_TUP => {
                        AuthenticateControlCode::DontEnforceUserPresenceAndSign
                    }
                    _ => panic!("Unknown control code"),
                };

                // The challenge parameter [32 bytes].
                let mut challenge_parameter = [0u8; 32];
                reader.read_exact(&mut challenge_parameter[..]).unwrap();

                // The application parameter [32 bytes].
                let mut application_parameter = [0u8; 32];
                reader.read_exact(&mut application_parameter[..]).unwrap();

                // key handle length byte [1 byte]
                let key_handle_len = reader.read_u8().unwrap();

                // key handle [length specified in previous field]
                let mut key_handle_bytes = vec![0u8; key_handle_len as usize];
                reader.read_exact(&mut key_handle_bytes[..]).unwrap();

                Request::Authenticate {
                    application: ApplicationParameter(application_parameter),
                    challenge: ChallengeParameter(challenge_parameter),
                    control_code: control_code,
                    key_handle: KeyHandle::from(&key_handle_bytes),
                }
            }
            VERSION_COMMAND_CODE => {
                assert_eq!(parameter1, 0);
                assert_eq!(parameter2, 0);
                assert_eq!(request_data_len, 0);
                Request::GetVersion
            }
            _ => panic!("Not implemented"),
        };
        Ok(request)
    }
}

pub enum Response {
    Registration {
        user_public_key: Vec<u8>,
        key_handle: KeyHandle,
        attestation_certificate: AttestationCertificate,
        signature: Box<Signature>,
    },
    Authentication {
        counter: Counter,
        signature: Box<Signature>,
        user_present: bool,
    },
    Version { version_string: String },
    DidWink,
    TestOfUserPresenceNotSatisfied,
    InvalidKeyHandle,
    UnknownError,
}

impl Response {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Response::Registration {
                user_public_key,
                key_handle,
                attestation_certificate,
                signature,
            } => {
                // reserved byte [1 byte], which for legacy reasons has the value 0x05.
                bytes.push(0x05);

                // user public key [65 bytes]. This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
                bytes.extend_from_slice(&user_public_key);

                // key handle length byte [1 byte], which specifies the length of the key handle (see below). The value is unsigned (range 0-255).
                let key_handle_bytes = key_handle.as_ref();
                bytes.push(key_handle_bytes.len() as u8);

                // A key handle [length specified in previous field].
                bytes.extend_from_slice(key_handle_bytes);

                // An attestation certificate [variable length]. This is a certificate in X.509 DER format
                bytes.extend_from_slice(&attestation_certificate.to_der());

                // A signature [variable length, 71-73 bytes]
                let signature_bytes = signature.as_ref().as_ref();
                bytes.extend_from_slice(signature_bytes);

                // Status word: The command completed successfully without error.
                StatusCode::NoError.write(&mut bytes);
            }
            Response::Authentication {
                counter,
                signature,
                user_present,
            } => {
                let user_presence_byte = user_presence_byte(user_present);

                // A user presence byte [1 byte].
                bytes.push(user_presence_byte);

                // A counter [4 bytes].
                bytes.write_u32::<BigEndian>(counter).unwrap();

                // A signature [variable length, 71-73 bytes]
                bytes.extend_from_slice(signature.as_ref().as_ref());

                // Status word: The command completed successfully without error.
                StatusCode::NoError.write(&mut bytes);
            }
            Response::Version { version_string } => {
                // The response message's raw representation is the
                // ASCII representation of the string 'U2F_V2'
                // (without quotes, and without any NUL terminator).
                bytes.extend_from_slice(version_string.as_bytes());

                // Status word: The command completed successfully without error.
                StatusCode::NoError.write(&mut bytes);
            }
            Response::DidWink => {
                // Status word: The command completed successfully without error.
                StatusCode::NoError.write(&mut bytes);
            }
            Response::TestOfUserPresenceNotSatisfied => {
                // Status word: The command completed successfully without error.
                StatusCode::TestOfUserPresenceNotSatisfied.write(&mut bytes);
            }
            Response::InvalidKeyHandle => {
                // Status word: The command completed successfully without error.
                StatusCode::InvalidKeyHandle.write(&mut bytes);
            }
            Response::UnknownError => {
                // Status word: The command completed successfully without error.
                StatusCode::UnknownError.write(&mut bytes);
            }
        }
        bytes
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ResponseError {
        Io(err: io::Error) {
            from()
        }
        Signing(err: SignError) {
            from()
        }
    }
}

impl Into<io::Error> for ResponseError {
    fn into(self: Self) -> io::Error {
        match self {
            ResponseError::Io(err) => err,
            ResponseError::Signing(_) => io::Error::new(io::ErrorKind::Other, "Signing error"),
        }
    }
}

pub type Counter = u32;
type SHA256Hash = [u8; 32];

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ApplicationParameter(SHA256Hash);

impl ApplicationParameter {
    fn from_str(input: &str) -> ApplicationParameter {
        let mut hasher = Sha256::new();
        hasher.input_str(input);
        let mut bytes = [0u8; 32];
        assert_eq!(hasher.output_bytes(), bytes.len());
        hasher.result(&mut bytes);
        ApplicationParameter(bytes)
    }
}

impl AsRef<[u8]> for ApplicationParameter {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Serialize for ApplicationParameter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        as_base64(&self, serializer)
    }
}

impl<'de> Deserialize<'de> for ApplicationParameter {
    fn deserialize<D>(deserializer: D) -> Result<ApplicationParameter, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&from_base64(deserializer)?);
        Ok(ApplicationParameter(bytes))
    }
}

fn as_base64<T, S>(buffer: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&base64::encode(buffer.as_ref()))
}

fn from_base64<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| {
        base64::decode(&string).map_err(|err| Error::custom(err.to_string()))
    })
}

impl slog::Value for ApplicationParameter {
    fn serialize(
        &self,
        record: &slog::Record,
        key: slog::Key,
        serializer: &mut slog::Serializer,
    ) -> slog::Result {
        slog::Value::serialize(&format!("{:?}", self.0), record, key, serializer)
    }
}

#[derive(Clone, Debug)]
pub struct ChallengeParameter(SHA256Hash);

impl AsRef<[u8]> for ChallengeParameter {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

const MAX_KEY_HANDLE_LEN: usize = u2f_header::U2F_MAX_KH_SIZE as usize;

#[derive(Clone)]
pub struct KeyHandle(Vec<u8>);

impl KeyHandle {
    fn from(bytes: &[u8]) -> KeyHandle {
        assert!(bytes.len() <= MAX_KEY_HANDLE_LEN);
        KeyHandle(bytes.to_vec())
    }

    pub fn eq_consttime(&self, other: &KeyHandle) -> bool {
        self.0.len() == other.0.len() && subtle::slices_equal(&self.0, &other.0) == 1
    }
}

impl AsRef<[u8]> for KeyHandle {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Rand for KeyHandle {
    #[inline]
    fn rand<R: Rng>(rng: &mut R) -> KeyHandle {
        let mut bytes = Vec::with_capacity(MAX_KEY_HANDLE_LEN);
        for _ in 0..MAX_KEY_HANDLE_LEN {
            bytes.push(rng.gen::<u8>());
        }
        KeyHandle(bytes)
    }
}

impl Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyHandle")
    }
}

impl Serialize for KeyHandle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        as_base64(&self, serializer)
    }
}

impl<'de> Deserialize<'de> for KeyHandle {
    fn deserialize<D>(deserializer: D) -> Result<KeyHandle, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(KeyHandle(from_base64(deserializer)?))
    }
}

pub struct Key(EcKey);

impl Key {
    fn from_pem(pem: &str) -> Key {
        Key(EcKey::private_key_from_pem(pem.as_bytes()).unwrap())
    }
}

impl Clone for Key {
    fn clone(&self) -> Key {
        Key(self.0.to_owned().unwrap())
    }
}

impl Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Key")
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        PrivateKeyAsPEM::from_key(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Key, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(PrivateKeyAsPEM::deserialize(deserializer)?.as_key())
    }
}

struct PrivateKeyAsPEM(Vec<u8>);

impl PrivateKeyAsPEM {
    fn as_key(&self) -> Key {
        Key(EcKey::private_key_from_pem(&self.0).unwrap())
    }

    fn from_key(key: &Key) -> PrivateKeyAsPEM {
        PrivateKeyAsPEM(key.0.private_key_to_pem().unwrap())
    }
}

impl Serialize for PrivateKeyAsPEM {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        as_base64(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for PrivateKeyAsPEM {
    fn deserialize<D>(deserializer: D) -> Result<PrivateKeyAsPEM, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(PrivateKeyAsPEM(from_base64(deserializer)?))
    }
}

pub struct PublicKey {
    group: EcGroup,
    point: EcPoint,
}

fn copy_ec_point(point: &EcPointRef, group: &EcGroupRef, ctx: &mut BigNumContextRef) -> EcPoint {
    let form = ec::POINT_CONVERSION_UNCOMPRESSED;
    let bytes = point.to_bytes(&group, form, ctx).unwrap();
    EcPoint::from_bytes(&group, &bytes, ctx).unwrap()
}

impl PublicKey {
    fn from_key(key: &Key, ctx: &mut BigNumContextRef) -> PublicKey {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let point = copy_ec_point(key.0.public_key().unwrap(), &group, ctx);
        PublicKey {
            group: group,
            point: point,
        }
    }

    /// Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
    /// I.e. [0x04, X (32 bytes), Y (32 bytes)] . Where the byte 0x04 denotes the
    /// uncompressed point compression method.
    fn from_bytes(bytes: &[u8], ctx: &mut BigNumContext) -> Result<PublicKey, String> {
        if bytes.len() != 65 {
            return Err(String::from(
                format!("Expected 65 bytes, found {}", bytes.len()),
            ));
        }
        if bytes[0] != u2f_header::U2F_POINT_UNCOMPRESSED as u8 {
            return Err(String::from("Expected uncompressed point"));
        }
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let point = EcPoint::from_bytes(&group, bytes, ctx).unwrap();
        Ok(PublicKey {
            group: group,
            point: point,
        })
    }

    fn to_ec_key(&self) -> EcKey {
        EcKey::from_public_key(&self.group, &self.point).unwrap()
    }

    /// Raw ANSI X9.62 formatted Elliptic Curve public key [SEC1].
    /// I.e. [0x04, X (32 bytes), Y (32 bytes)] . Where the byte 0x04 denotes the
    /// uncompressed point compression method.
    fn to_raw(&self, ctx: &mut BigNumContext) -> Vec<u8> {
        let form = ec::POINT_CONVERSION_UNCOMPRESSED;
        self.point.to_bytes(&self.group, form, ctx).unwrap()
    }
}

pub trait Signature: AsRef<[u8]> + Debug + Send {}

#[derive(Clone, Serialize, Deserialize)]
pub struct ApplicationKey {
    pub application: ApplicationParameter,
    pub handle: KeyHandle,
    key: Key,
}

#[derive(Clone)]
pub struct Attestation {
    certificate: AttestationCertificate,
    key: Key,
}

#[derive(Clone)]
pub struct AttestationCertificate(X509);

impl AttestationCertificate {
    fn from_pem(pem: &str) -> AttestationCertificate {
        AttestationCertificate(X509::from_pem(pem.as_bytes()).unwrap())
    }
    fn to_der(&self) -> Vec<u8> {
        self.0.to_der().unwrap()
    }
}

impl Debug for AttestationCertificate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "AttestationCertificate")
    }
}

#[derive(Debug)]
pub enum SignError {}

pub trait UserPresence {
    fn approve_registration(
        &self,
        application: &ApplicationParameter,
    ) -> Box<Future<Item = bool, Error = io::Error>>;
    fn approve_authentication(
        &self,
        application: &ApplicationParameter,
    ) -> Box<Future<Item = bool, Error = io::Error>>;
    fn wink(&self) -> Box<Future<Item = (), Error = io::Error>>;
}

pub trait CryptoOperations {
    fn attest(&self, data: &[u8]) -> Result<Box<Signature>, SignError>;
    fn generate_application_key(
        &self,
        application: &ApplicationParameter,
    ) -> io::Result<ApplicationKey>;
    fn get_attestation_certificate(&self) -> AttestationCertificate;
    fn sign(&self, key: &Key, data: &[u8]) -> Result<Box<Signature>, SignError>;
}

pub trait SecretStore {
    fn add_application_key(
        &self,
        key: &ApplicationKey,
    ) -> Box<Future<Item = (), Error = io::Error>>;
    fn get_and_increment_counter(
        &self,
        application: &ApplicationParameter,
    ) -> Box<Future<Item = Counter, Error = io::Error>>;
    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> Box<Future<Item = Option<ApplicationKey>, Error = io::Error>>;
}

#[derive(Debug)]
pub struct Registration {
    user_public_key: Vec<u8>,
    key_handle: KeyHandle,
    attestation_certificate: AttestationCertificate,
    signature: Box<Signature>,
}

#[derive(Debug)]
pub struct Authentication {
    counter: Counter,
    signature: Box<Signature>,
    user_present: bool,
}

quick_error! {
    #[derive(Debug)]
    pub enum AuthenticateError {
        ApprovalRequired
        InvalidKeyHandle
        Io(err: io::Error) {
            from()
        }
        Signing(err: SignError) {
            from()
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum RegisterError {
        ApprovalRequired
        Io(err: io::Error) {
            from()
        }
        Signing(err: SignError) {
            from()
        }
    }
}

pub struct U2F(Rc<U2FInner>);

struct U2FInner {
    approval: Box<UserPresence>,
    logger: slog::Logger,
    operations: Box<CryptoOperations>,
    storage: Box<SecretStore>,
}

impl U2F {
    pub fn new<L: Into<Option<slog::Logger>>>(
        approval: Box<UserPresence>,
        operations: Box<CryptoOperations>,
        storage: Box<SecretStore>,
        logger: L,
    ) -> io::Result<Self> {
        let logger = logger.into().unwrap_or(slog::Logger::root(
            slog_stdlog::StdLog.fuse(),
            o!(),
        ));
        let inner = U2FInner {
            approval: approval,
            logger: logger,
            operations: operations,
            storage: storage,
        };
        Ok(U2F(Rc::new(inner)))
    }

    pub fn authenticate(
        &self,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
        key_handle: KeyHandle,
    ) -> Box<Future<Item = Authentication, Error = AuthenticateError>> {
        trace!(self.0.logger, "authenticate");
        Self::_authenticate_step1(self.0.clone(), application, challenge, key_handle)
    }

    fn _authenticate_step1(
        self_rc: Rc<U2FInner>,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
        key_handle: KeyHandle,
    ) -> Box<Future<Item = Authentication, Error = AuthenticateError>> {
        let application_key_future = {
            self_rc
                .storage
                .retrieve_application_key(&application, &key_handle)
                .from_err()
        };

        Box::new(application_key_future.and_then(
            move |application_key_option| {
                match application_key_option {
                    Some(application_key) => {
                        Self::_authenticate_step2(self_rc, application, challenge, application_key)
                    }
                    None => Box::new(future::err(AuthenticateError::InvalidKeyHandle)),
                }
            },
        ))
    }

    fn _authenticate_step2(
        self_rc: Rc<U2FInner>,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
        application_key: ApplicationKey,
    ) -> Box<Future<Item = Authentication, Error = AuthenticateError>> {
        Box::new(
            self_rc
                .approval
                .approve_authentication(&application)
                .from_err()
                .and_then(move |user_present| {
                    Self::_authenticate_step3(
                        self_rc,
                        application,
                        challenge,
                        application_key,
                        user_present,
                    )
                }),
        )
    }

    fn _authenticate_step3(
        self_rc: Rc<U2FInner>,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
        application_key: ApplicationKey,
        user_present: bool,
    ) -> Box<Future<Item = Authentication, Error = AuthenticateError>> {
        if !user_present {
            return Box::new(future::err(AuthenticateError::ApprovalRequired));
        }

        Box::new(
            self_rc
                .storage
                .get_and_increment_counter(&application)
                .from_err()
                .and_then(move |counter| {
                    Self::_authenticate_step4(
                        self_rc,
                        application,
                        challenge,
                        application_key,
                        user_present,
                        counter,
                    )
                }),
        )
    }

    fn _authenticate_step4(
        self_rc: Rc<U2FInner>,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
        application_key: ApplicationKey,
        user_present: bool,
        counter: Counter,
    ) -> Result<Authentication, AuthenticateError> {
        let user_presence_byte = user_presence_byte(user_present);

        let signature = self_rc.operations.sign(
            &application_key.key,
            &message_to_sign_for_authenticate(
                &application,
                &challenge,
                user_presence_byte,
                counter,
            ),
        )?;

        Ok(Authentication {
            counter: counter,
            signature: signature,
            user_present: user_present,
        })
    }

    pub fn get_version_string(&self) -> String {
        String::from("U2F_V2")
    }

    pub fn is_valid_key_handle(
        &self,
        key_handle: &KeyHandle,
        application: &ApplicationParameter,
    ) -> Box<Future<Item = bool, Error = io::Error>> {
        trace!(self.0.logger, "is_valid_key_handle");
        Box::new(
            self.0
                .storage
                .retrieve_application_key(application, key_handle)
                .map(|res| match res {
                    Some(_) => true,
                    None => false,
                }),
        )
    }

    pub fn register(
        &self,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
    ) -> Box<Future<Item = Registration, Error = RegisterError>> {
        trace!(self.0.logger, "register");
        Self::_register_step1(self.0.clone(), application, challenge)
    }

    fn _register_step1(
        self_rc: Rc<U2FInner>,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
    ) -> Box<Future<Item = Registration, Error = RegisterError>> {
        Box::new(
            self_rc
                .approval
                .approve_registration(&application)
                .from_err()
                .and_then(move |user_present| {
                    Self::_register_step2(self_rc, application, challenge, user_present)
                }),
        )
    }

    fn _register_step2(
        self_rc: Rc<U2FInner>,
        application: ApplicationParameter,
        challenge: ChallengeParameter,
        user_present: bool,
    ) -> Box<Future<Item = Registration, Error = RegisterError>> {
        if !user_present {
            return Box::new(future::err(RegisterError::ApprovalRequired));
        }

        let application_key = match self_rc.operations.generate_application_key(&application) {
            Ok(application_key) => application_key,
            Err(err) => return Box::new(future::err(err).from_err()),
        };

        Box::new(
            self_rc
                .storage
                .add_application_key(&application_key)
                .from_err()
                .and_then(move |_| {
                    Self::_register_step3(self_rc, challenge, application_key)
                }),
        )
    }

    fn _register_step3(
        self_rc: Rc<U2FInner>,
        challenge: ChallengeParameter,
        application_key: ApplicationKey,
    ) -> Result<Registration, RegisterError> {
        let mut ctx = BigNumContext::new().unwrap();
        let public_key = PublicKey::from_key(&application_key.key, &mut ctx);
        let public_key_bytes: Vec<u8> = public_key.to_raw(&mut ctx);
        let signature = self_rc.operations.attest(&message_to_sign_for_register(
            &application_key.application,
            &challenge,
            &public_key_bytes,
            &application_key.handle,
        ))?;
        let attestation_certificate = self_rc.operations.get_attestation_certificate();

        Ok(Registration {
            user_public_key: public_key_bytes,
            key_handle: application_key.handle,
            attestation_certificate: attestation_certificate,
            signature: signature,
        })
    }

    fn wink(&self) -> Box<Future<Item = (), Error = io::Error>> {
        self.0.approval.wink()
    }
}

pub trait Service {
    /// Requests handled by the service.
    type Request;

    /// Responses given by the service.
    type Response;

    /// Errors produced by the service.
    type Error;

    /// The future response value.
    type Future: Future<Item = Self::Response, Error = Self::Error>;

    /// Process the request and return the response asynchronously.
    fn call(&self, req: Self::Request) -> Self::Future;
}

impl Service for U2F {
    type Request = Request;
    type Response = Response;
    type Error = io::Error;
    type Future = Box<Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        let logger = self.0.logger.clone();
        trace!(logger, "call U2F service");
        match req {
            Request::Register {
                challenge,
                application,
            } => {
                let logger_clone = self.0.logger.clone();
                debug!(logger, "Request::Register"; "app_id" => application);
                Box::new(
                    self.register(application, challenge)
                        .map(move |registration| {
                            info!(logger, "registered");
                            debug!(logger, "Request::Register => Ok");
                            Response::Registration {
                                user_public_key: registration.user_public_key,
                                key_handle: registration.key_handle,
                                attestation_certificate: registration.attestation_certificate,
                                signature: registration.signature,
                            }
                        })
                        .or_else(move |err| match err {
                            RegisterError::ApprovalRequired => {
                                debug!(logger_clone, "Request::Register => ApprovalRequired");
                                Ok(Response::TestOfUserPresenceNotSatisfied)
                            }
                            RegisterError::Io(err) => {
                                debug!(logger_clone, "Request::Register => IoError"; "error" => format!("{:?}", err));
                                Err(err.into())
                            }
                            RegisterError::Signing(err) => {
                                debug!(logger_clone, "Request::Register => SigningError"; "error" => format!("{:?}", err));
                                Err(io::Error::new(io::ErrorKind::Other, "Signing error").into())
                            }
                        }),
                )
            }
            Request::Authenticate {
                control_code,
                challenge,
                application,
                key_handle,
            } => {
                debug!(self.0.logger, "Request::Authenticate"; "app_id" => application);
                match control_code {
                    AuthenticateControlCode::CheckOnly => {
                        Box::new(self.is_valid_key_handle(&key_handle, &application).map(
                            |is_valid| match is_valid {
                                true => Response::TestOfUserPresenceNotSatisfied,
                                false => Response::InvalidKeyHandle,
                            },
                        ))
                    }
                    AuthenticateControlCode::EnforceUserPresenceAndSign => {
                        let logger_map = self.0.logger.clone();
                        let logger_map_err = self.0.logger.clone();
                        Box::new(self.authenticate(application, challenge, key_handle).map(move |authentication| {
                            info!(logger_map, "authenticated"; "counter" => &authentication.counter, "user_present" => &authentication.user_present);
                            Response::Authentication {
                                counter: authentication.counter,
                                signature: authentication.signature,
                                user_present: authentication.user_present,
                            }
                        }).or_else(move |err| match err {
                            AuthenticateError::ApprovalRequired => {
                                info!(logger_map_err, "TestOfUserPresenceNotSatisfied");
                                Ok(Response::TestOfUserPresenceNotSatisfied)
                            }
                            AuthenticateError::InvalidKeyHandle => {
                                info!(logger_map_err, "InvalidKeyHandle");
                                Ok(Response::InvalidKeyHandle)
                            }
                            AuthenticateError::Io(err) => {
                                info!(logger_map_err, "I/O error"; "error" => format!("{:?}", err));
                                Ok(Response::UnknownError)
                            }
                            AuthenticateError::Signing(err) => {
                                info!(logger_map_err, "Signing error"; "error" => format!("{:?}", err));
                                Ok(Response::UnknownError)
                            }
                        }))
                    }
                    AuthenticateControlCode::DontEnforceUserPresenceAndSign => {
                        // TODO Implement
                        Box::new(futures::finished(Response::TestOfUserPresenceNotSatisfied))
                    }
                }
            }
            Request::GetVersion => {
                trace!(logger, "Request::GetVersion");
                let response = Response::Version { version_string: self.get_version_string() };
                Box::new(future::ok(response))
            }
            Request::Wink => {
                Box::new(self.wink().map(|_| Response::DidWink).or_else(move |err| {
                    info!(logger, "I/O error"; "error" => format!("{:?}", err));
                    Ok(Response::UnknownError)
                }))
            }
        }
    }
}

/// User presence byte [1 byte]. Bit 0 indicates whether user presence was verified.
/// If Bit 0 is is to 1, then user presence was verified. If Bit 0 is set to 0,
/// then user presence was not verified. The values of Bit 1 through 7 shall be 0;
/// different values are reserved for future use.
fn user_presence_byte(user_present: bool) -> u8 {
    let mut byte: u8 = 0b0000_0000;
    if user_present {
        byte |= 0b0000_0001;
    }
    byte
}

fn message_to_sign_for_authenticate(
    application: &ApplicationParameter,
    challenge: &ChallengeParameter,
    user_presence: u8,
    counter: Counter,
) -> Vec<u8> {
    let mut message: Vec<u8> = Vec::new();

    // The application parameter [32 bytes] from the authentication request message.
    message.extend_from_slice(application.as_ref());

    // The user presence byte [1 byte].
    message.push(user_presence);

    // The counter [4 bytes].
    message.write_u32::<BigEndian>(counter).unwrap();

    // The challenge parameter [32 bytes] from the authentication request message.
    message.extend_from_slice(challenge.as_ref());

    message
}

fn message_to_sign_for_register(
    application: &ApplicationParameter,
    challenge: &ChallengeParameter,
    key_bytes: &[u8],
    key_handle: &KeyHandle,
) -> Vec<u8> {
    let mut message: Vec<u8> = Vec::new();

    // A byte reserved for future use [1 byte] with the value 0x00.
    message.push(0u8);

    // The application parameter [32 bytes] from the registration request message.
    message.extend_from_slice(application.as_ref());

    // The challenge parameter [32 bytes] from the registration request message.
    message.extend_from_slice(challenge.as_ref());

    // The key handle [variable length].
    message.extend_from_slice(key_handle.as_ref());

    // The user public key [65 bytes].
    message.extend_from_slice(key_bytes);

    message
}

pub struct SecureCryptoOperations {
    attestation: Attestation,
}

impl SecureCryptoOperations {
    pub fn new(attestation: Attestation) -> SecureCryptoOperations {
        SecureCryptoOperations { attestation: attestation }
    }

    fn generate_key() -> Key {
        let group = EcGroup::from_curve_name(nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        Key(ec_key)
    }

    fn generate_key_handle() -> io::Result<KeyHandle> {
        Ok(OsRng::new()?.gen())
    }
}

impl CryptoOperations for SecureCryptoOperations {
    fn attest(&self, data: &[u8]) -> Result<Box<Signature>, SignError> {
        self.sign(&self.attestation.key, data)
    }

    fn generate_application_key(
        &self,
        application: &ApplicationParameter,
    ) -> io::Result<ApplicationKey> {
        let key = Self::generate_key();
        let handle = Self::generate_key_handle()?;
        Ok(ApplicationKey {
            application: *application,
            handle: handle,
            key: key,
        })
    }

    fn get_attestation_certificate(&self) -> AttestationCertificate {
        self.attestation.certificate.clone()
    }

    fn sign(&self, key: &Key, data: &[u8]) -> Result<Box<Signature>, SignError> {
        let ec_key = key.0.to_owned().unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).unwrap();
        signer.update(data).unwrap();
        let signature = signer.finish().unwrap();
        Ok(Box::new(RawSignature(signature)))
    }
}

#[derive(Debug)]
struct RawSignature(Vec<u8>);

impl Signature for RawSignature {}

impl AsRef<[u8]> for RawSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub fn self_signed_attestation() -> Attestation {
    Attestation {
        certificate: AttestationCertificate::from_pem(SELF_SIGNED_ATTESTATION_CERTIFICATE_PEM),
        key: Key::from_pem(SELF_SIGNED_ATTESTATION_KEY_PEM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openssl::sign::Verifier;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const ALL_ZERO_HASH: [u8; 32] = [0u8; 32];
    fn all_zero_key_handle() -> KeyHandle {
        KeyHandle(vec![0u8; 128])
    }

    struct FakeUserPresence {
        pub should_approve_authentication: bool,
        pub should_approve_registration: bool,
    }

    impl FakeUserPresence {
        fn always_approve() -> FakeUserPresence {
            FakeUserPresence {
                should_approve_authentication: true,
                should_approve_registration: true,
            }
        }
    }

    impl UserPresence for FakeUserPresence {
        fn approve_authentication(
            &self,
            _: &ApplicationParameter,
        ) -> Box<Future<Item = bool, Error = io::Error>> {
            Box::new(future::ok(self.should_approve_authentication))
        }
        fn approve_registration(
            &self,
            _: &ApplicationParameter,
        ) -> Box<Future<Item = bool, Error = io::Error>> {
            Box::new(future::ok(self.should_approve_registration))
        }
        fn wink(&self) -> Box<Future<Item = (), Error = io::Error>> {
            Box::new(future::ok(()))
        }
    }

    struct InMemoryStorage(RefCell<InMemoryStorageInner>);

    struct InMemoryStorageInner {
        application_keys: HashMap<ApplicationParameter, ApplicationKey>,
        counters: HashMap<ApplicationParameter, Counter>,
    }

    impl InMemoryStorage {
        fn new() -> InMemoryStorage {
            InMemoryStorage(RefCell::new(InMemoryStorageInner {
                application_keys: HashMap::new(),
                counters: HashMap::new(),
            }))
        }
    }

    impl SecretStore for InMemoryStorage {
        fn add_application_key(
            &self,
            key: &ApplicationKey,
        ) -> Box<Future<Item = (), Error = io::Error>> {
            self.0.borrow_mut().application_keys.insert(
                key.application,
                key.clone(),
            );
            Box::new(future::ok(()))
        }

        fn get_and_increment_counter(
            &self,
            application: &ApplicationParameter,
        ) -> Box<Future<Item = Counter, Error = io::Error>> {
            let mut borrow = self.0.borrow_mut();
            if let Some(counter) = borrow.counters.get_mut(application) {
                let counter_value = *counter;
                *counter += 1;
                return Box::new(future::ok(counter_value));
            }

            let initial_counter = 0;
            borrow.counters.insert(*application, initial_counter);
            Box::new(future::ok(initial_counter))
        }

        fn retrieve_application_key(
            &self,
            application: &ApplicationParameter,
            handle: &KeyHandle,
        ) -> Box<Future<Item = Option<ApplicationKey>, Error = io::Error>> {
            Box::new(future::ok(
                match self.0.borrow().application_keys.get(application) {
                    Some(key) => {
                        if key.handle.eq_consttime(handle) {
                            Some(key.clone())
                        } else {
                            None
                        }
                    }
                    None => None,
                },
            ))
        }
    }

    fn get_test_attestation() -> Attestation {
        Attestation {
            certificate: AttestationCertificate::from_pem(
                "-----BEGIN CERTIFICATE-----
MIIBfzCCASagAwIBAgIJAJaMtBXq9XVHMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMM
EFNvZnQgVTJGIFRlc3RpbmcwHhcNMTcxMDIwMjE1NzAzWhcNMjcxMDIwMjE1NzAz
WjAbMRkwFwYDVQQDDBBTb2Z0IFUyRiBUZXN0aW5nMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEryDZdIOGjRKLLyG6Mkc4oSVUDBndagZDDbdwLcUdNLzFlHx/yqYl
30rPR35HvZI/zKWELnhl5BG3hZIrBEjpSqNTMFEwHQYDVR0OBBYEFHjWu2kQGzvn
KfCIKULVtb4WZnAEMB8GA1UdIwQYMBaAFHjWu2kQGzvnKfCIKULVtb4WZnAEMA8G
A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgaiIS0Rb+Hw8WSO9fcsln
ERLGHDWaV+MS0kr5HgmvAjQCIEU0qjr86VDcpLvuGnTkt2djzapR9iO9PPZ5aErv
3GCT
-----END CERTIFICATE-----
",
            ),
            key: Key::from_pem(
                "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEijhKU+RGVbusHs9jNSUs9ZycXRSvtz0wrBJKozKuh1oAoGCCqGSM49
AwEHoUQDQgAEryDZdIOGjRKLLyG6Mkc4oSVUDBndagZDDbdwLcUdNLzFlHx/yqYl
30rPR35HvZI/zKWELnhl5BG3hZIrBEjpSg==
-----END EC PRIVATE KEY-----
",
            ),
        }
    }

    #[test]
    fn is_valid_key_handle_with_invalid_handle_is_false() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let key_handle = all_zero_key_handle();

        assert_matches!(
            u2f.is_valid_key_handle(&key_handle, &application).wait(),
            Ok(false)
        );
    }

    #[test]
    fn is_valid_key_handle_with_valid_handle_is_true() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let mut u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = u2f.register(application.clone(), challenge).wait().unwrap();

        assert_matches!(
            u2f.is_valid_key_handle(&registration.key_handle, &application)
                .wait(),
            Ok(true)
        );
    }

    #[test]
    fn authenticate_with_invalid_handle_errors() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let mut u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let key_handle = all_zero_key_handle();

        assert_matches!(
            u2f.authenticate(application, challenge, key_handle).wait(),
            Err(AuthenticateError::InvalidKeyHandle)
        );
    }

    #[test]
    fn authenticate_with_valid_handle_succeeds() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let mut u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = u2f.register(application.clone(), challenge.clone())
            .wait()
            .unwrap();

        u2f.authenticate(application, challenge, registration.key_handle)
            .wait()
            .unwrap();
    }

    #[test]
    fn authenticate_with_rejected_approval_errors() {
        let approval = Box::new(FakeUserPresence {
            should_approve_authentication: false,
            should_approve_registration: true,
        });
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let mut u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = u2f.register(application.clone(), challenge.clone())
            .wait()
            .unwrap();

        assert_matches!(
            u2f.authenticate(application, challenge, registration.key_handle)
                .wait(),
            Err(AuthenticateError::ApprovalRequired)
        );
    }

    #[test]
    fn register_with_rejected_approval_errors() {
        let approval = Box::new(FakeUserPresence {
            should_approve_authentication: true,
            should_approve_registration: false,
        });
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let mut u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);

        assert_matches!(
            u2f.register(application, challenge).wait(),
            Err(RegisterError::ApprovalRequired)
        );
    }

    #[test]
    fn authenticate_signature() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let mut u2f = U2F::new(approval, operations, storage, None).unwrap();

        let mut os_rng = OsRng::new().unwrap();
        let application = ApplicationParameter(os_rng.gen());
        let register_challenge = ChallengeParameter(os_rng.gen());
        let mut ctx = BigNumContext::new().unwrap();

        let registration = u2f.register(application.clone(), register_challenge.clone())
            .wait()
            .unwrap();

        let authentication_challenge = ChallengeParameter(os_rng.gen());
        let authentication = u2f.authenticate(
            application.clone(),
            authentication_challenge.clone(),
            registration.key_handle.clone(),
        ).wait()
            .unwrap();

        let user_presence_byte = user_presence_byte(true);
        let user_public_key = PublicKey::from_bytes(&registration.user_public_key, &mut ctx)
            .unwrap();
        let user_pkey = PKey::from_ec_key(user_public_key.to_ec_key()).unwrap();
        let signed_data = message_to_sign_for_authenticate(
            &application,
            &authentication_challenge,
            user_presence_byte,
            authentication.counter,
        );
        verify_signature(
            authentication.signature.as_ref(),
            signed_data.as_ref(),
            &user_pkey,
        );
    }

    #[test]
    fn register_signature() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let mut storage = Box::new(InMemoryStorage::new());
        let mut u2f = U2F::new(approval, operations, storage, None).unwrap();

        let mut os_rng = OsRng::new().unwrap();
        let application = ApplicationParameter(os_rng.gen());
        let challenge = ChallengeParameter(os_rng.gen());
        let mut ctx = BigNumContext::new().unwrap();

        let registration = u2f.register(application.clone(), challenge.clone())
            .wait()
            .unwrap();

        let public_key = registration.attestation_certificate.0.public_key().unwrap();
        let signed_data = message_to_sign_for_register(
            &application,
            &challenge,
            &registration.user_public_key,
            &registration.key_handle,
        );
        verify_signature(
            registration.signature.as_ref(),
            signed_data.as_ref(),
            &public_key,
        );
    }

    fn verify_signature(signature: &Signature, data: &[u8], public_key: &PKey) {
        let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
        verifier.update(data).unwrap();
        assert!(verifier.finish(signature.as_ref()).unwrap());
    }
}
