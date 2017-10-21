#[macro_use]
extern crate assert_matches;
#[macro_use]
extern crate quick_error;
extern crate openssl;
extern crate rand;
extern crate byteorder;
extern crate u2f_header;
extern crate subtle;

use std::collections::HashMap;
use std::fmt::{self, Debug};
use std::io;
use std::result::Result;

use byteorder::{BigEndian, WriteBytesExt};
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

type Counter = u32;
type SHA256Hash = [u8; 32];

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct ApplicationParameter(SHA256Hash);

impl AsRef<[u8]> for ApplicationParameter {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

struct ChallengeParameter(SHA256Hash);

impl AsRef<[u8]> for ChallengeParameter {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

const MaxKeyHandleSize: usize = u2f_header::U2F_MAX_KH_SIZE as usize;

#[derive(Copy)]
struct KeyHandle([u8; MaxKeyHandleSize]);

impl AsRef<[u8]> for KeyHandle {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Clone for KeyHandle {
    fn clone(&self) -> KeyHandle {
        KeyHandle(self.0)
    }
}

impl Rand for KeyHandle {
    #[inline]
    fn rand<R: Rng>(rng: &mut R) -> KeyHandle {
        let mut bytes = [0u8; MaxKeyHandleSize];
        for byte in bytes.iter_mut() {
            *byte = rng.gen::<u8>();
        }
        KeyHandle(bytes)
    }
}

impl Debug for KeyHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KeyHandle")
    }
}

struct Key(EcKey);

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

struct PublicKey {
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
    fn from_raw(bytes: &[u8], ctx: &mut BigNumContext) -> Result<PublicKey, String> {
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

trait Signature: AsRef<[u8]> + Debug {}

#[derive(Clone)]
struct ApplicationKey {
    application: ApplicationParameter,
    handle: KeyHandle,
    key: Key,
}

#[derive(Clone)]
struct Attestation {
    certificate: AttestationCertificate,
    key: Key,
}

#[derive(Clone)]
struct AttestationCertificate(X509);

impl AttestationCertificate {
    fn from_pem(pem: &str) -> AttestationCertificate {
        AttestationCertificate(X509::from_pem(pem.as_bytes()).unwrap())
    }
    fn to_der(&self) -> Vec<u8> {
        self.0.to_der().unwrap()
    }
}

#[derive(Debug)]
pub enum SignError {}

trait ApprovalService {
    fn approve_registration(&self, application: &ApplicationParameter) -> io::Result<bool>;
    fn approve_authentication(&self, application: &ApplicationParameter) -> io::Result<bool>;
}

trait CryptoOperations {
    fn attest(&self, data: &[u8]) -> Result<Box<Signature>, SignError>;
    fn generate_application_key(
        &self,
        application: &ApplicationParameter,
    ) -> io::Result<ApplicationKey>;
    fn get_attestation_certificate(&self) -> AttestationCertificate;
    fn sign(&self, key: &Key, data: &[u8]) -> Result<Box<Signature>, SignError>;
}

trait SecretStore {
    fn add_application_key(&mut self, key: &ApplicationKey) -> io::Result<()>;
    fn get_then_increment_counter(
        &mut self,
        application: &ApplicationParameter,
    ) -> io::Result<Counter>;
    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> io::Result<Option<&ApplicationKey>>;
}

#[derive(Debug)]
struct Registration {
    user_public_key: Vec<u8>,
    key_handle: KeyHandle,
    attestation_certificate: Vec<u8>,
    signature: Box<Signature>,
}

#[derive(Debug)]
struct Authentication {
    counter: Counter,
    signature: Box<Signature>,
}

quick_error! {
    #[derive(Debug)]
    pub enum AuthenticateError {
        ApprovalRequired
        BadKeyHandle
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

struct U2F<'a> {
    approval: &'a ApprovalService,
    operations: &'a CryptoOperations,
    storage: &'a mut SecretStore,
}

impl<'a> U2F<'a> {
    pub fn new(
        approval: &'a ApprovalService,
        operations: &'a CryptoOperations,
        storage: &'a mut SecretStore,
    ) -> io::Result<U2F<'a>> {
        Ok(U2F {
            approval: approval,
            operations: operations,
            storage: storage,
        })
    }

    pub fn authenticate(
        &mut self,
        application: &ApplicationParameter,
        challenge: &ChallengeParameter,
        key_handle: &KeyHandle,
    ) -> Result<Authentication, AuthenticateError> {
        if !self.approval.approve_authentication(application)? {
            return Err(AuthenticateError::ApprovalRequired);
        }

        let application_key = match self.storage.retrieve_application_key(
            application,
            key_handle,
        )? {
            Some(key) => key.clone(),
            None => return Err(AuthenticateError::BadKeyHandle),
        };
        let counter = self.storage.get_then_increment_counter(application)?;
        let user_presence_byte = user_presence_byte(true);

        let signature = self.operations.sign(
            &application_key.key,
            &message_to_sign_for_authenticate(
                application,
                challenge,
                user_presence_byte,
                counter,
            ),
        )?;

        Ok(Authentication {
            counter: counter,
            signature: signature,
        })
    }

    pub fn get_version_string() -> String {
        String::from("U2F_V2")
    }

    pub fn is_valid_key_handle(
        &self,
        key_handle: &KeyHandle,
        application: &ApplicationParameter,
    ) -> io::Result<bool> {
        match self.storage.retrieve_application_key(
            application,
            key_handle,
        )? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    pub fn register(
        &mut self,
        application: &ApplicationParameter,
        challenge: &ChallengeParameter,
    ) -> Result<Registration, RegisterError> {
        if !self.approval.approve_registration(application)? {
            return Err(RegisterError::ApprovalRequired);
        }

        let mut ctx = BigNumContext::new().unwrap();
        let application_key = self.operations.generate_application_key(application)?;
        self.storage.add_application_key(&application_key)?;

        let public_key = PublicKey::from_key(&application_key.key, &mut ctx);
        let public_key_bytes: Vec<u8> = public_key.to_raw(&mut ctx);
        let signature = self.operations.attest(&message_to_sign_for_register(
            &application_key.application,
            challenge,
            &public_key_bytes,
            &application_key.handle,
        ))?;
        let attestation_certificate = self.operations.get_attestation_certificate();

        Ok(Registration {
            user_public_key: public_key_bytes,
            key_handle: application_key.handle,
            attestation_certificate: attestation_certificate.to_der(),
            signature: signature,
        })
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

struct SecureCryptoOperations {
    attestation: Attestation,
}

impl SecureCryptoOperations {
    fn new(attestation: Attestation) -> SecureCryptoOperations {
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

struct FakeApprovalService {
    pub should_approve_authentication: bool,
    pub should_approve_registration: bool,
}

impl FakeApprovalService {
    fn always_approve() -> FakeApprovalService {
        FakeApprovalService {
            should_approve_authentication: true,
            should_approve_registration: true,
        }
    }
}

impl ApprovalService for FakeApprovalService {
    fn approve_authentication(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Ok(self.should_approve_authentication)
    }
    fn approve_registration(&self, application: &ApplicationParameter) -> io::Result<bool> {
        Ok(self.should_approve_registration)
    }
}

struct InMemoryStorage {
    application_keys: HashMap<ApplicationParameter, ApplicationKey>,
    counters: HashMap<ApplicationParameter, Counter>,
}

impl InMemoryStorage {
    pub fn new() -> InMemoryStorage {
        InMemoryStorage {
            application_keys: HashMap::new(),
            counters: HashMap::new(),
        }
    }
}

impl SecretStore for InMemoryStorage {
    fn add_application_key(&mut self, key: &ApplicationKey) -> io::Result<()> {
        self.application_keys.insert(key.application, key.clone());
        Ok(())
    }

    fn get_then_increment_counter(
        &mut self,
        application: &ApplicationParameter,
    ) -> io::Result<Counter> {
        if let Some(counter) = self.counters.get_mut(application) {
            let counter_value = *counter;
            *counter += 1;
            return Ok(counter_value);
        }

        let initial_counter = 0;
        self.counters.insert(*application, initial_counter);
        Ok(initial_counter)
    }

    fn retrieve_application_key(
        &self,
        application: &ApplicationParameter,
        handle: &KeyHandle,
    ) -> io::Result<Option<&ApplicationKey>> {
        match self.application_keys.get(application) {
            Some(key) => {
                if key_handles_eq_consttime(&key.handle, handle) {
                    Ok(Some(key))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }
}

fn key_handles_eq_consttime(key_handle1: &KeyHandle, key_handle2: &KeyHandle) -> bool {
    subtle::slices_equal(&key_handle1.0, &key_handle2.0) == 1
}

// struct TestContext<'a> {
//     u2f: U2F<'a>,
//     approval: AlwaysApproveService,
//     operations: FakeOperations,
//     storage: InMemoryStorage,
// }

#[cfg(test)]
mod tests {
    use super::*;

    use openssl::sign::Verifier;

    const ALL_ZERO_HASH: [u8; 32] = [0; 32];
    const ALL_ZERO_KEY_HANDLE: KeyHandle = KeyHandle([0; 128]);

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

    // fn new_test_context<'a>() -> TestContext<'a> {
    //     let approval = AlwaysApproveService;
    //     let operations = FakeOperations;
    //     let mut storage: InMemoryStorage = InMemoryStorage::new();
    //     TestContext {
    //         u2f: U2F::new(&approval, &operations, &mut storage).unwrap(),
    //         approval: approval,
    //         operations: operations,
    //         storage: storage,
    //     }
    // }

    #[test]
    fn is_valid_key_handle_with_invalid_handle_is_false() {
        let approval = FakeApprovalService::always_approve();
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let key_handle = ALL_ZERO_KEY_HANDLE;

        assert_matches!(
            u2f.is_valid_key_handle(&key_handle, &application),
            Ok(false)
        );
    }

    #[test]
    fn is_valid_key_handle_with_valid_handle_is_true() {
        let approval = FakeApprovalService::always_approve();
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let mut u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = u2f.register(&application, &challenge).unwrap();

        assert_matches!(
            u2f.is_valid_key_handle(&registration.key_handle, &application),
            Ok(true)
        );
    }

    #[test]
    fn authenticate_with_invalid_handle_errors() {
        let approval = FakeApprovalService::always_approve();
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let mut u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let key_handle = ALL_ZERO_KEY_HANDLE;

        assert_matches!(
            u2f.authenticate(&application, &challenge, &key_handle),
            Err(AuthenticateError::BadKeyHandle)
        );
    }

    #[test]
    fn authenticate_with_valid_handle_succeeds() {
        let approval = FakeApprovalService::always_approve();
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let mut u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = u2f.register(&application, &challenge).unwrap();

        u2f.authenticate(&application, &challenge, &registration.key_handle)
            .unwrap();
    }

    #[test]
    fn authenticate_with_rejected_approval_errors() {
        let approval = FakeApprovalService {
            should_approve_authentication: false,
            should_approve_registration: true,
        };
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let mut u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);
        let registration = u2f.register(&application, &challenge).unwrap();

        assert_matches!(
            u2f.authenticate(&application, &challenge, &registration.key_handle),
            Err(AuthenticateError::ApprovalRequired)
        );
    }

    #[test]
    fn register_with_rejected_approval_errors() {
        let approval = FakeApprovalService {
            should_approve_authentication: true,
            should_approve_registration: false,
        };
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let mut u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let application = ApplicationParameter(ALL_ZERO_HASH);
        let challenge = ChallengeParameter(ALL_ZERO_HASH);

        assert_matches!(
            u2f.register(&application, &challenge),
            Err(RegisterError::ApprovalRequired)
        );
    }

    #[test]
    fn authenticate_signature() {
        let approval = FakeApprovalService::always_approve();
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let mut u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let mut os_rng = OsRng::new().unwrap();
        let application = ApplicationParameter(os_rng.gen());
        let register_challenge = ChallengeParameter(os_rng.gen());
        let mut ctx = BigNumContext::new().unwrap();

        let registration = u2f.register(&application, &register_challenge).unwrap();

        let authenticate_challenge = ChallengeParameter(os_rng.gen());
        let authentication = u2f.authenticate(
            &application,
            &authenticate_challenge,
            &registration.key_handle,
        ).unwrap();

        let user_presence_byte = user_presence_byte(true);
        let user_public_key = PublicKey::from_raw(&registration.user_public_key, &mut ctx).unwrap();
        let user_pkey = PKey::from_ec_key(user_public_key.to_ec_key()).unwrap();
        let signed_data = message_to_sign_for_authenticate(
            &application,
            &authenticate_challenge,
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
        let approval = FakeApprovalService::always_approve();
        let operations = SecureCryptoOperations::new(get_test_attestation());
        let mut storage = InMemoryStorage::new();
        let mut u2f = U2F::new(&approval, &operations, &mut storage).unwrap();

        let mut os_rng = OsRng::new().unwrap();
        let application = ApplicationParameter(os_rng.gen());
        let challenge = ChallengeParameter(os_rng.gen());
        let mut ctx = BigNumContext::new().unwrap();

        let registration = u2f.register(&application, &challenge).unwrap();

        let attestation_certificate = X509::from_der(&registration.attestation_certificate)
            .unwrap();
        let public_key = attestation_certificate.public_key().unwrap();
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
