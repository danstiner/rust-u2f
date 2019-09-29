#[cfg(test)]
#[macro_use]
extern crate assert_matches;
extern crate base64;
extern crate byteorder;
extern crate futures;
extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate openssl;
#[macro_use]
extern crate quick_error;
extern crate rand;
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate slog;
extern crate slog_stdlog;
extern crate subtle;
extern crate tokio_service;

use std::fmt::Debug;
use std::io;
use std::rc::Rc;
use std::result::Result;

pub use app_id::AppId;
pub use application_key::ApplicationKey;
use attestation::AttestationCertificate;
use byteorder::{BigEndian, WriteBytesExt};
use constants::*;
use futures::future;
use futures::Future;
use futures::IntoFuture;
pub use key_handle::KeyHandle;
pub use known_app_ids::try_reverse_app_id;
use known_app_ids::BOGUS_APP_ID_HASH;
pub use openssl_crypto::OpenSSLCryptoOperations as SecureCryptoOperations;
pub use private_key::PrivateKey;
use public_key::PublicKey;
pub use request::{AuthenticateControlCode, Request};
pub use response::Response;
pub use self_signed_attestation::self_signed_attestation;
use slog::Drain;
pub use tokio_service::Service;

mod app_id;
mod application_key;
mod attestation;
mod constants;
mod key_handle;
mod known_app_ids;
mod openssl_crypto;
mod private_key;
mod public_key;
mod request;
mod response;
mod self_signed_attestation;
mod serde_base64;

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
            StatusCode::NoError => SW_NO_ERROR,
            StatusCode::TestOfUserPresenceNotSatisfied => SW_CONDITIONS_NOT_SATISFIED,
            StatusCode::InvalidKeyHandle => SW_WRONG_DATA,
            StatusCode::RequestLengthInvalid => SW_WRONG_LENGTH,
            StatusCode::RequestClassNotSupported => SW_CLA_NOT_SUPPORTED,
            StatusCode::RequestInstructionNotSuppored => SW_INS_NOT_SUPPORTED,
            StatusCode::UnknownError => SW_UNKNOWN,
        };
        write.write_u16::<BigEndian>(value).unwrap();
    }
}

#[derive(Debug)]
pub enum SignError {}

pub type Counter = u32;

#[derive(Clone, Debug)]
pub struct Challenge([u8; 32]);

impl AsRef<[u8]> for Challenge {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub trait Signature: AsRef<[u8]> + Debug + Send {}

pub trait UserPresence {
    fn approve_registration(
        &self,
        application: &AppId,
    ) -> Box<dyn Future<Item = bool, Error = io::Error>>;
    fn approve_authentication(
        &self,
        application: &AppId,
    ) -> Box<dyn Future<Item = bool, Error = io::Error>>;
    fn wink(&self) -> Box<dyn Future<Item = (), Error = io::Error>>;
}

pub trait CryptoOperations {
    fn attest(&self, data: &[u8]) -> Result<Box<dyn Signature>, SignError>;
    fn generate_application_key(&self, application: &AppId) -> io::Result<ApplicationKey>;
    fn get_attestation_certificate(&self) -> AttestationCertificate;
    fn sign(&self, key: &PrivateKey, data: &[u8]) -> Result<Box<dyn Signature>, SignError>;
}

pub trait SecretStore {
    fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()>;
    fn get_and_increment_counter(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Counter>;
    fn retrieve_application_key(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Option<ApplicationKey>>;
}

#[derive(Debug)]
pub struct Registration {
    user_public_key: Vec<u8>,
    key_handle: KeyHandle,
    attestation_certificate: AttestationCertificate,
    signature: Box<dyn Signature>,
}

#[derive(Debug)]
pub struct Authentication {
    counter: Counter,
    signature: Box<dyn Signature>,
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
    approval: Box<dyn UserPresence>,
    logger: slog::Logger,
    operations: Box<dyn CryptoOperations>,
    storage: Box<dyn SecretStore>,
}

impl U2F {
    pub fn new<L: Into<Option<slog::Logger>>>(
        approval: Box<dyn UserPresence>,
        operations: Box<dyn CryptoOperations>,
        storage: Box<dyn SecretStore>,
        logger: L,
    ) -> io::Result<Self> {
        let logger = logger
            .into()
            .unwrap_or_else(|| slog::Logger::root(slog_stdlog::StdLog.fuse(), o!()));
        let inner = U2FInner {
            approval,
            logger,
            operations,
            storage,
        };
        Ok(U2F(Rc::new(inner)))
    }

    pub fn authenticate(
        &self,
        application: AppId,
        challenge: Challenge,
        key_handle: KeyHandle,
    ) -> Box<dyn Future<Item = Authentication, Error = AuthenticateError>> {
        debug!(self.0.logger, "authenticate");
        Self::_authenticate_step1(self.0.clone(), application, challenge, key_handle)
    }

    fn _authenticate_step1(
        self_rc: Rc<U2FInner>,
        application: AppId,
        challenge: Challenge,
        key_handle: KeyHandle,
    ) -> Box<dyn Future<Item = Authentication, Error = AuthenticateError>> {
        let application_key = self_rc
            .storage
            .retrieve_application_key(&application, &key_handle);

        Box::new(
            application_key
                .into_future()
                .from_err()
                .and_then(move |application_key_option| match application_key_option {
                    Some(application_key) => {
                        Self::_authenticate_step2(self_rc, challenge, application_key)
                    }
                    None => Box::new(future::err(AuthenticateError::InvalidKeyHandle)),
                }),
        )
    }

    fn _authenticate_step2(
        self_rc: Rc<U2FInner>,
        challenge: Challenge,
        application_key: ApplicationKey,
    ) -> Box<dyn Future<Item = Authentication, Error = AuthenticateError>> {
        Box::new(
            self_rc
                .approval
                .approve_authentication(&application_key.application)
                .from_err()
                .and_then(move |user_present| {
                    Self::_authenticate_step3(self_rc, challenge, application_key, user_present)
                }),
        )
    }

    fn _authenticate_step3(
        self_rc: Rc<U2FInner>,
        challenge: Challenge,
        application_key: ApplicationKey,
        user_present: bool,
    ) -> Box<dyn Future<Item = Authentication, Error = AuthenticateError>> {
        if !user_present {
            return Box::new(future::err(AuthenticateError::ApprovalRequired));
        }

        Box::new(
            self_rc
                .storage
                .get_and_increment_counter(&application_key.application, &application_key.handle)
                .into_future()
                .from_err()
                .and_then(move |counter| {
                    Self::_authenticate_step4(
                        self_rc,
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
        challenge: Challenge,
        application_key: ApplicationKey,
        user_present: bool,
        counter: Counter,
    ) -> Result<Authentication, AuthenticateError> {
        let user_presence_byte = user_presence_byte(user_present);

        let signature = self_rc.operations.sign(
            application_key.key(),
            &message_to_sign_for_authenticate(
                &application_key.application,
                &challenge,
                user_presence_byte,
                counter,
            ),
        )?;

        Ok(Authentication {
            counter,
            signature,
            user_present,
        })
    }

    pub fn get_version_string(&self) -> String {
        String::from("U2F_V2")
    }

    pub fn is_valid_key_handle(
        &self,
        key_handle: &KeyHandle,
        application: &AppId,
    ) -> io::Result<bool> {
        debug!(self.0.logger, "is_valid_key_handle");
        Ok(self
            .0
            .storage
            .retrieve_application_key(application, key_handle)?
            .is_some())
    }

    pub fn register(
        &self,
        application: AppId,
        challenge: Challenge,
    ) -> Box<dyn Future<Item = Registration, Error = RegisterError>> {
        debug!(self.0.logger, "register");
        Self::_register_step1(self.0.clone(), application, challenge)
    }

    fn _register_step1(
        self_rc: Rc<U2FInner>,
        application: AppId,
        challenge: Challenge,
    ) -> Box<dyn Future<Item = Registration, Error = RegisterError>> {
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
        application: AppId,
        challenge: Challenge,
        user_present: bool,
    ) -> Box<dyn Future<Item = Registration, Error = RegisterError>> {
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
                .into_future()
                .from_err()
                .and_then(move |_| Self::_register_step3(self_rc, challenge, application_key)),
        )
    }

    fn _register_step3(
        self_rc: Rc<U2FInner>,
        challenge: Challenge,
        application_key: ApplicationKey,
    ) -> Result<Registration, RegisterError> {
        let public_key = PublicKey::from_key(application_key.key());
        let public_key_bytes: Vec<u8> = public_key.to_raw();
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
            attestation_certificate,
            signature,
        })
    }

    fn wink(&self) -> Box<dyn Future<Item = (), Error = io::Error>> {
        self.0.approval.wink()
    }
}

impl Service for U2F {
    type Request = Request;
    type Response = Response;
    type Error = io::Error;
    type Future = Box<dyn Future<Item = Self::Response, Error = Self::Error>>;

    fn call(&self, req: Self::Request) -> Self::Future {
        let logger = self.0.logger.clone();
        debug!(logger, "call U2F service");
        match req {
            Request::Register {
                challenge,
                application,
            } => {
                let logger_clone = self.0.logger.clone();
                debug!(logger, "Request::Register"; "app_id" => application);

                if application == BOGUS_APP_ID_HASH {
                    return Box::new(future::ok(Response::TestOfUserPresenceNotSatisfied));
                }

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
                                debug!(
                                    logger_clone,
                                    "Request::Register => TestOfUserPresenceNotSatisfied"
                                );
                                Ok(Response::TestOfUserPresenceNotSatisfied)
                            }
                            RegisterError::Io(err) => {
                                debug!(logger_clone, "Request::Register => IoError"; "error" => ?err);
                                Err(err)
                            }
                            RegisterError::Signing(err) => {
                                debug!(logger_clone, "Request::Register => SigningError"; "error" => ?err);
                                Err(io::Error::new(io::ErrorKind::Other, "Signing error"))
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
                let logger = self
                    .0
                    .logger
                    .new(o!("request" => "authenticate", "app_id" => application));
                match control_code {
                    AuthenticateControlCode::CheckOnly => {
                        debug!(logger, "ControlCode::CheckOnly");
                        Box::new(self.is_valid_key_handle(&key_handle, &application).into_future().map(
                            move |is_valid| {
                                info!(logger, "ControlCode::CheckOnly"; "is_valid_key_handle" => is_valid);
                                if is_valid {
                                    Response::TestOfUserPresenceNotSatisfied
                                } else {
                                    Response::InvalidKeyHandle
                                }
                            },
                        ))
                    }
                    AuthenticateControlCode::EnforceUserPresenceAndSign => {
                        debug!(logger, "ControlCode::EnforceUserPresenceAndSign");
                        let logger_clone = logger.clone();
                        Box::new(
                            self.authenticate(application, challenge, key_handle)
                                .map(move |authentication| {
                                    info!(logger, "authenticated"; "counter" => &authentication.counter, "user_present" => &authentication.user_present);
                                    Response::Authentication {
                                        counter: authentication.counter,
                                        signature: authentication.signature,
                                        user_present: authentication.user_present,
                                    }
                                })
                                .or_else(move |err| match err {
                                    AuthenticateError::ApprovalRequired => {
                                        info!(logger_clone, "TestOfUserPresenceNotSatisfied");
                                        Ok(Response::TestOfUserPresenceNotSatisfied)
                                    }
                                    AuthenticateError::InvalidKeyHandle => {
                                        info!(logger_clone, "InvalidKeyHandle");
                                        Ok(Response::InvalidKeyHandle)
                                    }
                                    AuthenticateError::Io(err) => {
                                        info!(logger_clone, "I/O error"; "error" => ?err);
                                        Ok(Response::UnknownError)
                                    }
                                    AuthenticateError::Signing(err) => {
                                        info!(logger_clone, "Signing error"; "error" => ?err);
                                        Ok(Response::UnknownError)
                                    }
                                }),
                        )
                    }
                    AuthenticateControlCode::DontEnforceUserPresenceAndSign => {
                        debug!(
                            logger,
                            "Request::Authenticate::DontEnforceUserPresenceAndSign"
                        );
                        info!(logger, "Request::Authenticate::DontEnforceUserPresenceAndSign => TestOfUserPresenceNotSatisfied (Not implemented)");
                        // TODO Implement
                        Box::new(futures::finished(Response::TestOfUserPresenceNotSatisfied))
                    }
                }
            }
            Request::GetVersion => {
                debug!(logger, "Request::GetVersion");
                let response = Response::Version {
                    version_string: self.get_version_string(),
                };
                Box::new(future::ok(response))
            }
            Request::Wink => Box::new(self.wink().map(|_| Response::DidWink).or_else(move |err| {
                info!(logger, "I/O error"; "error" => format!("{:?}", err));
                Ok(Response::UnknownError)
            })),
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
    application: &AppId,
    challenge: &Challenge,
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
    application: &AppId,
    challenge: &Challenge,
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashMap;

    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Verifier;
    use rand::os::OsRng;
    use rand::Rng;

    use super::attestation::Attestation;
    use super::*;

    fn fake_app_id() -> AppId {
        AppId([0u8; 32])
    }

    fn fake_challenge() -> Challenge {
        Challenge([0u8; 32])
    }

    fn fake_key_handle() -> KeyHandle {
        KeyHandle::from(&vec![0u8; 128])
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
        fn approve_registration(&self, _: &AppId) -> Box<Future<Item = bool, Error = io::Error>> {
            Box::new(future::ok(self.should_approve_registration))
        }
        fn approve_authentication(&self, _: &AppId) -> Box<Future<Item = bool, Error = io::Error>> {
            Box::new(future::ok(self.should_approve_authentication))
        }
        fn wink(&self) -> Box<Future<Item = (), Error = io::Error>> {
            Box::new(future::ok(()))
        }
    }

    struct InMemoryStorage(RefCell<InMemoryStorageInner>);

    struct InMemoryStorageInner {
        application_keys: HashMap<AppId, ApplicationKey>,
        counters: HashMap<AppId, Counter>,
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
            self.0
                .borrow_mut()
                .application_keys
                .insert(key.application, key.clone());
            Box::new(future::ok(()))
        }

        fn get_and_increment_counter(
            &self,
            application: &AppId,
            handle: &KeyHandle,
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
            application: &AppId,
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
-----END CERTIFICATE-----",
            ),
            key: Key::from_pem(
                "-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEijhKU+RGVbusHs9jNSUs9ZycXRSvtz0wrBJKozKuh1oAoGCCqGSM49
AwEHoUQDQgAEryDZdIOGjRKLLyG6Mkc4oSVUDBndagZDDbdwLcUdNLzFlHx/yqYl
30rPR35HvZI/zKWELnhl5BG3hZIrBEjpSg==
-----END EC PRIVATE KEY-----",
            ),
        }
    }

    #[test]
    fn is_valid_key_handle_with_invalid_handle_is_false() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = fake_app_id();
        let key_handle = fake_key_handle();

        assert_matches!(
            u2f.is_valid_key_handle(&key_handle, &application).wait(),
            Ok(false)
        );
    }

    #[test]
    fn is_valid_key_handle_with_valid_handle_is_true() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = fake_app_id();
        let challenge = fake_challenge();
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
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = fake_app_id();
        let challenge = fake_challenge();
        let key_handle = fake_key_handle();

        assert_matches!(
            u2f.authenticate(application, challenge, key_handle).wait(),
            Err(AuthenticateError::InvalidKeyHandle)
        );
    }

    #[test]
    fn authenticate_with_valid_handle_succeeds() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = fake_app_id();
        let challenge = fake_challenge();
        let registration = u2f
            .register(application.clone(), challenge.clone())
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
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = fake_app_id();
        let challenge = fake_challenge();
        let registration = u2f
            .register(application.clone(), challenge.clone())
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
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let application = fake_app_id();
        let challenge = fake_challenge();

        assert_matches!(
            u2f.register(application, challenge).wait(),
            Err(RegisterError::ApprovalRequired)
        );
    }

    #[test]
    fn authenticate_signature() {
        let approval = Box::new(FakeUserPresence::always_approve());
        let operations = Box::new(SecureCryptoOperations::new(get_test_attestation()));
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let mut rng = OsRng::new().unwrap();
        let application = AppId(rng.gen());
        let register_challenge = Challenge(rng.gen());

        let registration = u2f
            .register(application.clone(), register_challenge.clone())
            .wait()
            .unwrap();

        let authentication_challenge = Challenge(rng.gen());
        let authentication = u2f
            .authenticate(
                application.clone(),
                authentication_challenge.clone(),
                registration.key_handle.clone(),
            )
            .wait()
            .unwrap();

        let user_presence_byte = user_presence_byte(true);
        let user_public_key = PublicKey::from_bytes(&registration.user_public_key).unwrap();
        let user_pkey = PKey::from_ec_key(user_public_key.as_ec_key()).unwrap();
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
        let storage = Box::new(InMemoryStorage::new());
        let u2f = U2F::new(approval, operations, storage, None).unwrap();

        let mut rng = OsRng::new().unwrap();
        let application = AppId(rng.gen());
        let challenge = Challenge(rng.gen());

        let registration = u2f
            .register(application.clone(), challenge.clone())
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

    fn verify_signature(signature: &Signature, data: &[u8], public_key: &PKey<PublicKey>) {
        let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
        verifier.update(data).unwrap();
        assert!(verifier.verify(signature.as_ref()).unwrap());
    }
}
