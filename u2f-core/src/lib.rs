#[cfg(test)]
#[macro_use]
extern crate assert_matches;
extern crate async_trait;
extern crate base64;
extern crate byteorder;
extern crate futures;
extern crate hex;
#[macro_use]
extern crate lazy_static;
extern crate openssl;
extern crate rand;
extern crate ring;
extern crate serde;
extern crate serde_derive;
extern crate subtle;
extern crate tokio;
extern crate tower;

use std::fmt::Debug;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::result::Result;
use std::task::Context;
use std::task::Poll;

use async_trait::async_trait;
use byteorder::{BigEndian, WriteBytesExt};
use futures::future;
use futures::Future;
use thiserror::Error;
pub use tower::Service;
use tracing::{debug, error, info, trace};

pub use crate::app_id::AppId;
pub use crate::application_key::ApplicationKey;
use crate::attestation::AttestationCertificate;
use crate::constants::*;
pub use crate::key_handle::KeyHandle;
pub use crate::known_app_ids::try_reverse_app_id;
use crate::known_app_ids::{BOGUS_APP_ID_HASH_CHROME, BOGUS_APP_ID_HASH_FIREFOX};
pub use crate::openssl_crypto::OpenSSLCryptoOperations;
pub use crate::private_key::PrivateKey;
use crate::public_key::PublicKey;
pub use crate::request::{AuthenticateControlCode, Request};
pub use crate::response::Response;
pub use crate::self_signed_attestation::self_signed_attestation;

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

#[derive(Debug, Error)]
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

#[async_trait]
pub trait UserPresence {
    async fn approve_registration(&self, application: &AppId) -> Result<bool, io::Error>;
    async fn approve_authentication(&self, application: &AppId) -> Result<bool, io::Error>;
    async fn wink(&self) -> Result<(), io::Error>;
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

impl SecretStore for Box<dyn SecretStore> {
    fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
        Box::as_ref(self).add_application_key(key)
    }

    fn get_and_increment_counter(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Counter> {
        Box::as_ref(self).get_and_increment_counter(application, handle)
    }

    fn retrieve_application_key(
        &self,
        application: &AppId,
        handle: &KeyHandle,
    ) -> io::Result<Option<ApplicationKey>> {
       Box::as_ref(self).retrieve_application_key(application, handle)
    }
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

#[derive(Debug, Error)]
pub enum AuthenticateError {
    #[error("Approval required")]
    ApprovalRequired,

    #[error("Invalid key handle")]
    InvalidKeyHandle,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Signing error: {0}")]
    Signing(#[from] SignError),
}

#[derive(Debug, Error)]
pub enum RegisterError {
    #[error("Approval required")]
    ApprovalRequired,

    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Signing error: {0}")]
    Signing(#[from] SignError),
}

pub struct U2F<Approval, Crypto, Secrets> {
    inner: Rc<U2FInner<Approval, Crypto, Secrets>>,
}

impl<Approval, Crypto, Secrets> U2F<Approval, Crypto, Secrets>
where
    Approval: UserPresence,
    Crypto: CryptoOperations,
    Secrets: SecretStore,
{
    pub fn new(user_presence: Approval, crypto: Crypto, secrets: Secrets) -> Self {
        U2F {
            inner: Rc::new(U2FInner::new(user_presence, crypto, secrets)),
        }
    }

    pub fn version_string(&self) -> String {
        String::from("U2F_V2")
    }
}

impl<Approval, Crypto, Secrets> Service<Request> for U2F<Approval, Crypto, Secrets>
where
    Approval: UserPresence + 'static,
    Crypto: CryptoOperations + 'static,
    Secrets: SecretStore + 'static,
{
    type Response = Response;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let inner = Rc::clone(&self.inner);
        trace!("calling U2F service");
        match req {
            Request::Register {
                challenge,
                application,
            } => Box::pin(inner.register_request(application, challenge)),
            Request::Authenticate {
                control_code,
                challenge,
                application,
                key_handle,
            } => Box::pin(inner.authenticate_request(
                control_code,
                challenge,
                application,
                key_handle,
            )),
            Request::GetVersion => {
                debug!("Get version request");
                let response = Response::Version {
                    version_string: self.version_string(),
                };
                Box::pin(future::ok(response))
            }
            Request::Wink => Box::pin(inner.wink_request()),
        }
    }
}

pub struct U2FInner<Approval, Crypto, Secrets> {
    approval: Approval,
    operations: Crypto,
    storage: Secrets,
}

impl<Approval, Crypto, Secrets> U2FInner<Approval, Crypto, Secrets>
where
    Approval: UserPresence,
    Crypto: CryptoOperations,
    Secrets: SecretStore,
{
    pub fn new(approval: Approval, crypto: Crypto, secrets: Secrets) -> Self {
        U2FInner {
            approval,
            operations: crypto,
            storage: secrets,
        }
    }

    async fn authenticate_request(
        self: Rc<Self>,
        control_code: AuthenticateControlCode,
        challenge: Challenge,
        application: AppId,
        key_handle: KeyHandle,
    ) -> Result<Response, io::Error> {
        // let log = self.log.new(o!(
        //     "app" => try_reverse_app_id(&application).unwrap_or(application.to_base64()),
        //     "control_code" => format!("{:?}", control_code),
        // ));
        debug!("Authenticate request");

        match control_code {
            AuthenticateControlCode::CheckOnly => {
                let is_valid = self.is_valid_key_handle(&key_handle, &application)?;
                debug!(is_valid_key_handle = is_valid, "ControlCode::CheckOnly");
                if is_valid {
                    info!("Valid key handle");
                    Ok(Response::TestOfUserPresenceNotSatisfied)
                } else {
                    Ok(Response::InvalidKeyHandle)
                }
            }
            AuthenticateControlCode::EnforceUserPresenceAndSign => {
                match self.authenticate(application, challenge, key_handle).await {
                    Ok(authentication) => {
                        info!(user_present = authentication.user_present, "Authenticated");
                        Ok(Response::Authentication {
                            counter: authentication.counter,
                            signature: authentication.signature,
                            user_present: authentication.user_present,
                        })
                    }
                    Err(err) => match err {
                        AuthenticateError::ApprovalRequired => {
                            info!("TestOfUserPresenceNotSatisfied");
                            Ok(Response::TestOfUserPresenceNotSatisfied)
                        }
                        AuthenticateError::InvalidKeyHandle => {
                            info!("InvalidKeyHandle");
                            Ok(Response::InvalidKeyHandle)
                        }
                        AuthenticateError::Io(err) => {
                            error!(error = ?err, "I/O error");
                            Ok(Response::UnknownError)
                        }
                        AuthenticateError::Signing(err) => {
                            error!(error = ?err, "Signing error");
                            Ok(Response::UnknownError)
                        }
                    },
                }
            }
            AuthenticateControlCode::DontEnforceUserPresenceAndSign => {
                info!("DontEnforceUserPresenceAndSign");
                // TODO Implement
                Ok(Response::TestOfUserPresenceNotSatisfied)
            }
        }
    }

    async fn register_request(
        self: Rc<Self>,
        application: AppId,
        challenge: Challenge,
    ) -> Result<Response, io::Error> {
        // let log = self
        //     .log
        //     .new(o!("app" => try_reverse_app_id(&application).unwrap_or(application.to_base64())));
        debug!("Registration request");

        if application == BOGUS_APP_ID_HASH_CHROME {
            debug!("Rejecting bogus registration request from Chrome");
            return Ok(Response::Bogus);
        }

        if application == BOGUS_APP_ID_HASH_FIREFOX {
            debug!("Rejecting bogus registration request from Firefox");
            return Ok(Response::Bogus);
        }

        match self.register(application, challenge).await {
            Ok(Registration {
                user_public_key,
                key_handle,
                attestation_certificate,
                signature,
            }) => {
                info!("Registered");
                Ok(Response::Registration {
                    user_public_key,
                    key_handle,
                    attestation_certificate,
                    signature,
                })
            }
            Err(err) => match err {
                RegisterError::ApprovalRequired => {
                    info!("Registration was not approved by user");
                    Ok(Response::TestOfUserPresenceNotSatisfied)
                }
                RegisterError::Io(err) => Err(err),
                RegisterError::Signing(err) => {
                    Err(io::Error::new(io::ErrorKind::Other, "Signing error"))
                }
            },
        }
    }

    pub async fn wink_request(self: Rc<Self>) -> Result<Response, io::Error> {
        debug!("Wink");

        self.approval
            .wink()
            .await
            .map(|_| Response::DidWink)
            .or_else(move |err| {
                error!(error = ?err, "I/O error");
                Ok(Response::UnknownError)
            })
    }

    pub fn is_valid_key_handle(
        &self,
        key_handle: &KeyHandle,
        application: &AppId,
    ) -> io::Result<bool> {
        debug!("is_valid_key_handle");
        self.storage
            .retrieve_application_key(application, key_handle)
            .map(|key| key.is_some())
    }

    pub async fn authenticate(
        &self,
        application: AppId,
        challenge: Challenge,
        key_handle: KeyHandle,
    ) -> Result<Authentication, AuthenticateError> {
        debug!(appid = ?application, "authenticate");

        let application_key = self
            .storage
            .retrieve_application_key(&application, &key_handle)?
            .ok_or(AuthenticateError::InvalidKeyHandle)?;

        let user_present = self
            .approval
            .approve_authentication(&application_key.application)
            .await?;

        if !user_present {
            return Err(AuthenticateError::ApprovalRequired);
        }

        let counter = self
            .storage
            .get_and_increment_counter(&application_key.application, &application_key.handle)?;

        let user_presence_byte = user_presence_byte(user_present);

        let signature = self.operations.sign(
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

    pub async fn register(
        &self,
        application: AppId,
        challenge: Challenge,
    ) -> Result<Registration, RegisterError> {
        debug!("register");

        let user_present = self.approval.approve_registration(&application).await?;

        if !user_present {
            return Err(RegisterError::ApprovalRequired);
        }

        let application_key = match self.operations.generate_application_key(&application) {
            Ok(application_key) => application_key,
            Err(err) => return Err(RegisterError::Io(err)),
        };

        self.storage.add_application_key(&application_key)?;

        let public_key = PublicKey::from_key(application_key.key());
        let public_key_bytes: Vec<u8> = public_key.to_raw();
        let signature = self.operations.attest(&message_to_sign_for_register(
            &application_key.application,
            &challenge,
            &public_key_bytes,
            &application_key.handle,
        ))?;
        let attestation_certificate = self.operations.get_attestation_certificate();

        Ok(Registration {
            user_public_key: public_key_bytes,
            key_handle: application_key.handle,
            attestation_certificate,
            signature,
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
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{HasPublic, PKey, PKeyRef};
    use openssl::sign::Verifier;

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

    #[async_trait]
    impl UserPresence for FakeUserPresence {
        async fn approve_registration(&self, _: &AppId) -> Result<bool, io::Error> {
            Ok(self.should_approve_registration)
        }
        async fn approve_authentication(&self, _: &AppId) -> Result<bool, io::Error> {
            Ok(self.should_approve_authentication)
        }
        async fn wink(&self) -> Result<(), io::Error> {
            Ok(())
        }
    }

    struct InMemoryStorage(Mutex<InMemoryStorageInner>);

    struct InMemoryStorageInner {
        application_keys: HashMap<AppId, ApplicationKey>,
        counters: HashMap<AppId, Counter>,
    }

    impl InMemoryStorage {
        fn new() -> InMemoryStorage {
            InMemoryStorage(Mutex::new(InMemoryStorageInner {
                application_keys: HashMap::new(),
                counters: HashMap::new(),
            }))
        }
    }

    #[async_trait]
    impl SecretStore for InMemoryStorage {
        fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
            self.0
                .lock()
                .unwrap()
                .application_keys
                .insert(key.application, key.clone());
            Ok(())
        }

        fn get_and_increment_counter(
            &self,
            application: &AppId,
            handle: &KeyHandle,
        ) -> Result<Counter, io::Error> {
            let mut borrow = self.0.lock().unwrap();
            if let Some(counter) = borrow.counters.get_mut(application) {
                let counter_value = *counter;
                *counter += 1;
                return Ok(counter_value);
            }

            let initial_counter = 0;
            borrow.counters.insert(*application, initial_counter);
            Ok(initial_counter)
        }

        fn retrieve_application_key(
            &self,
            application: &AppId,
            handle: &KeyHandle,
        ) -> Result<Option<ApplicationKey>, io::Error> {
            let borrow = self.0.lock().unwrap();
            let key = borrow.application_keys.get(application);
            match key {
                Some(key) if key.handle.eq_consttime(handle) => Ok(Some(key.clone())),
                _ => Ok(None),
            }
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
            key: PrivateKey::from_pem(
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
        let approval = FakeUserPresence::always_approve();
        let operations = OpenSSLCryptoOperations::new(get_test_attestation());
        let storage = InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = fake_app_id();
        let key_handle = fake_key_handle();

        assert_matches!(
            u2f.is_valid_key_handle(&key_handle, &application),
            Ok(false)
        );
    }

    #[tokio::test]
    async fn is_valid_key_handle_with_valid_handle_is_true() {
        let approval = FakeUserPresence::always_approve();
        let operations = OpenSSLCryptoOperations::new(get_test_attestation());
        let storage = InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = fake_app_id();
        let challenge = fake_challenge();
        let registration = u2f.register(application.clone(), challenge).await.unwrap();

        assert_matches!(
            u2f.is_valid_key_handle(&registration.key_handle, &application),
            Ok(true)
        );
    }

    #[tokio::test]
    async fn authenticate_with_invalid_handle_errors() {
        let approval =FakeUserPresence::always_approve();
        let operations =OpenSSLCryptoOperations::new(get_test_attestation());
        let storage =InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = fake_app_id();
        let challenge = fake_challenge();
        let key_handle = fake_key_handle();

        assert_matches!(
            u2f.authenticate(application, challenge, key_handle).await,
            Err(AuthenticateError::InvalidKeyHandle)
        );
    }

    #[tokio::test]
    async fn authenticate_with_valid_handle_succeeds() {
        let approval = FakeUserPresence::always_approve();
        let operations = OpenSSLCryptoOperations::new(get_test_attestation());
        let storage = InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = fake_app_id();
        let challenge = fake_challenge();
        let registration = u2f
            .register(application.clone(), challenge.clone())
            .await
            .unwrap();

        u2f.authenticate(application, challenge, registration.key_handle)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn authenticate_with_rejected_approval_errors() {
        let approval = FakeUserPresence {
            should_approve_authentication: false,
            should_approve_registration: true,
        };
        let operations = OpenSSLCryptoOperations::new(get_test_attestation());
        let storage = InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = fake_app_id();
        let challenge = fake_challenge();
        let registration = u2f
            .register(application.clone(), challenge.clone())
            .await
            .unwrap();

        assert_matches!(
            u2f.authenticate(application, challenge, registration.key_handle)
                .await,
            Err(AuthenticateError::ApprovalRequired)
        );
    }

    #[tokio::test]
    async fn register_with_rejected_approval_errors() {
        let approval = FakeUserPresence {
            should_approve_authentication: true,
            should_approve_registration: false,
        };
        let operations = OpenSSLCryptoOperations::new(get_test_attestation());
        let storage = InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = fake_app_id();
        let challenge = fake_challenge();

        assert_matches!(
            u2f.register(application, challenge).await,
            Err(RegisterError::ApprovalRequired)
        );
    }

    #[tokio::test]
    async fn authenticate_signature() {
        let approval =FakeUserPresence::always_approve();
        let operations =OpenSSLCryptoOperations::new(get_test_attestation());
        let storage =InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = AppId(rand::random());
        let register_challenge = Challenge(rand::random());

        let registration = u2f
            .register(application.clone(), register_challenge.clone())
            .await
            .unwrap();

        let authentication_challenge = Challenge(rand::random());
        let authentication = u2f
            .authenticate(
                application.clone(),
                authentication_challenge.clone(),
                registration.key_handle.clone(),
            )
            .await
            .unwrap();

        let user_presence_byte = user_presence_byte(true);
        let user_public_key = PublicKey::from_bytes(&registration.user_public_key).unwrap();
        let user_public_key = PKey::from_ec_key(user_public_key.into()).unwrap();
        let signed_data = message_to_sign_for_authenticate(
            &application,
            &authentication_challenge,
            user_presence_byte,
            authentication.counter,
        );
        verify_signature(
            authentication.signature.as_ref(),
            signed_data.as_ref(),
            &user_public_key,
        );
    }

    #[tokio::test]
    async fn register_signature() {
        let approval = FakeUserPresence::always_approve();
        let operations = OpenSSLCryptoOperations::new(get_test_attestation());
        let storage = InMemoryStorage::new();
        let u2f = U2F::new(approval, operations, storage).inner;

        let application = AppId(rand::random());
        let challenge = Challenge(rand::random());

        let registration = u2f
            .register(application.clone(), challenge.clone())
            .await
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

    fn verify_signature<T>(signature: &dyn Signature, data: &[u8], public_key: &PKeyRef<T>)
    where
        T: HasPublic,
    {
        let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
        verifier.update(data).unwrap();
        assert!(verifier.verify(signature.as_ref()).unwrap());
    }
}
