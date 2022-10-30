use std::result::Result;

use async_trait::async_trait;
use fido2_authenticator_api::Aaguid;
use fido2_authenticator_api::AttestationCertificate;
use fido2_authenticator_api::AttestationStatement;
use fido2_authenticator_api::AuthenticatorAPI;
use fido2_authenticator_api::AuthenticatorData;
use fido2_authenticator_api::COSEAlgorithmIdentifier;
use fido2_authenticator_api::GetAssertionCommand;
use fido2_authenticator_api::GetAssertionResponse;
use fido2_authenticator_api::GetInfoResponse;
use fido2_authenticator_api::MakeCredentialCommand;
use fido2_authenticator_api::MakeCredentialResponse;
use fido2_authenticator_api::PackedAttestationStatement;
use fido2_authenticator_api::PublicKeyCredentialDescriptor;
use fido2_authenticator_api::PublicKeyCredentialParameters;
use fido2_authenticator_api::RelyingPartyIdentifier;
use fido2_authenticator_api::Sha256;
use fido2_authenticator_api::Signature;
use fido2_authenticator_api::UserHandle;
use tracing::debug;

use crate::Error;

#[async_trait(?Send)]
pub trait UserPresence {
    type Error;
    async fn approve_make_credential(&self, name: &str) -> Result<bool, Self::Error>;
    async fn wink(&self) -> Result<(), Self::Error>;
}

#[async_trait(?Send)]
pub trait SecretStore {
    type Error;

    async fn make_credential(
        &self,
        pub_key_cred_params: &PublicKeyCredentialParameters,
        rp_id: &RelyingPartyIdentifier,
        user_handle: &UserHandle,
    ) -> Result<PublicKeyCredentialDescriptor, Self::Error>;

    async fn attest(
        &self,
        rp_id: &RelyingPartyIdentifier,
        credential: &PublicKeyCredentialDescriptor,
        auth_data: &AuthenticatorData,
        client_data_hash: &Sha256,
    ) -> Result<AttestationStatement, Self::Error>;
}

#[async_trait(?Send)]
impl<W: SecretStore + ?Sized> SecretStore for Box<W> {
    type Error = W::Error;

    async fn make_credential(
        &self,
        pub_key_cred_params: &PublicKeyCredentialParameters,
        rp_id: &RelyingPartyIdentifier,
        user_handle: &UserHandle,
    ) -> Result<PublicKeyCredentialDescriptor, Self::Error> {
        (**self)
            .make_credential(pub_key_cred_params, rp_id, user_handle)
            .await
    }

    async fn attest(
        &self,
        rp_id: &RelyingPartyIdentifier,
        credential_descriptor: &PublicKeyCredentialDescriptor,
        auth_data: &AuthenticatorData,
        client_data_hash: &Sha256,
    ) -> Result<AttestationStatement, Self::Error> {
        (**self)
            .attest(rp_id, credential_descriptor, auth_data, client_data_hash)
            .await
    }
}

/// Service implementing the FIDO authenticator API.
///
/// Methods are defined by the FIDO specification and implemented in terms of pluggable dependencies
/// that perform the actual cryptographic operations, secret storage, and user interaction.
///
/// See https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticator-api
pub struct Authenticator<Secrets, Presence>
where
    Secrets: SecretStore,
    Presence: UserPresence,
{
    pub(crate) secrets: Secrets,
    pub(crate) presence: Presence,
    pub(crate) aaguid: Aaguid,
}

impl<Secrets, Presence> Authenticator<Secrets, Presence>
where
    Secrets: SecretStore,
    Presence: UserPresence,
{
    pub fn new(secrets: Secrets, presence: Presence, aaguid: Aaguid) -> Self {
        Self {
            secrets,
            presence,
            aaguid,
        }
    }

    fn get_info_internal(&self) -> GetInfoResponse {
        GetInfoResponse {
            versions: vec![String::from("FIDO_2_1"), String::from("U2F_V2")],
            extensions: None,
            aaguid: self.aaguid,
            options: None,
            max_msg_size: None,
            pin_uv_auth_protocols: None,
            max_credential_count_in_list: None,
            max_credential_id_length: None,
            transports: None,
            algorithms: Some(vec![PublicKeyCredentialParameters::es256()]),
            max_serialized_large_blob_array: None,
            force_pin_change: None,
            min_pin_length: None,
            firmware_version: None,
            max_cred_blob_len: None,
            max_rp_ids_for_set_min_pin_length: None,
            preferred_platform_uv_attempts: None,
            uv_modality: None,
            certifications: None,
            remaining_discoverable_credentials: Some(0),
            vendor_prototype_config_commands: None,
        }
    }
}

#[async_trait(?Send)]
impl<Secrets, Presence> AuthenticatorAPI for Authenticator<Secrets, Presence>
where
    Secrets: SecretStore + 'static,
    Presence: UserPresence + 'static,
    super::Error: From<Secrets::Error>,
    super::Error: From<Presence::Error>,
{
    type Error = super::Error;

    fn version(&self) -> fido2_authenticator_api::VersionInfo {
        fido2_authenticator_api::VersionInfo {
            version_major: pkg_version::pkg_version_major!(),
            version_minor: pkg_version::pkg_version_minor!(),
            version_build: pkg_version::pkg_version_patch!(),
            wink_supported: true,
        }
    }

    async fn make_credential(
        &self,
        cmd: MakeCredentialCommand,
    ) -> Result<MakeCredentialResponse, Error> {
        let MakeCredentialCommand {
            client_data_hash,
            rp,
            user,
            pub_key_cred_params,
            exclude_list,
            extensions: _,
            options,
            pin_uv_auth_param,
            pin_uv_auth_protocol: _,
            enterprise_attestation,
        } = cmd;
        debug!(rp = ?rp, user = ?user, "make_credential");

        // Number steps follow the authenticatorMakeCredential algorithm from the fido specification:
        // https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-makeCred-authnr-alg

        // 1. This authenticator does not support pinUvAuthToken or clientPin features
        // 2. This authenticator does not support pinUvAuthParam or pinUvAuthProtocol features
        if pin_uv_auth_param.is_some() {
            return Err(Error::InvalidParameter);
        }

        // 3. Select the first supported algorithm in pubKeyCredParams
        let pk_parameters = pub_key_cred_params
            .iter()
            .filter(|param| param.alg == COSEAlgorithmIdentifier::ES256) // TODO filter other algorithm types
            .next()
            .ok_or(Error::UnsupportedAlgorithm)?;

        // 4. Initialize both "uv" and "up" as false.
        let mut uv = false;
        let mut up = false;

        // 5. Process options parameter if present, treat any option keys that are not understood as absent.
        if let Some(options) = options {
            // Note: As the specification defines normative behaviours for the "rk", "up", and "uv" option keys, they MUST be understood by all authenticators.
            // TODO
        }

        // 9. If the enterpriseAttestation parameter is present:
        if enterprise_attestation.is_some() {
            // If the authenticator is not enterprise attestation capable,
            // or the authenticator is enterprise attestation capable but enterprise attestation is disabled,
            // then end the operation by returning CTAP1_ERR_INVALID_PARAMETER.
            return Err(Error::InvalidParameter);
        }

        // 10. If the following statements are all true:
        //   Note: This step allows the authenticator to create a non-discoverable credential without requiring some form of user verification under the below specific criteria.
        //   "rk" and "uv" options are both set to false or omitted.
        //   the makeCredUvNotRqd option ID in authenticatorGetInfo's response is present with the value true.
        //   the pinUvAuthParam parameter is not present.
        //   Then go to Step 12.
        //   Note: Step 4 has already ensured that the "uv" bit is false in the response.
        // TODO

        // 11. If the authenticator is protected by some form of user verification, then:
        // 11.1. If pinUvAuthParam parameter is present (implying the "uv" option is false (see Step 5)):
        if pin_uv_auth_param.is_some() {
            assert_eq!(uv, false);
            // If the authenticator is not protected by pinUvAuthToken,
            // or the authenticator is protected by pinUvAuthToken but pinUvAuthToken is disabled,
            // then end the operation by returning CTAP1_ERR_INVALID_PARAMETER.
            return Err(Error::InvalidParameter);
        }

        // 12. If the excludeList parameter is present and contains a credential ID created by this authenticator, that is bound to the specified rp.id:

        if exclude_list.is_some() {
            // TODO not supported
            return Err(Error::InvalidParameter);
        }

        // 13. If evidence of user interaction was provided as part of Step 11 (i.e., by invoking performBuiltInUv()):
        // TODO evidence of user interaction
        // Set the "up" bit to true in the response.
        let present = self.presence.approve_make_credential(&rp.name).await?;
        up = true;
        // Go to Step 15
        // TODO

        // 14. If the "up" option is set to true:

        // 15. If the extensions parameter is present:
        // TODO

        // 16. Generate a new credential key pair for the algorithm chosen in step 3
        // TODO

        // 17. If the "rk" option is set to true:
        // TODO

        // 18. Otherwise, if the "rk" option is false: the authenticator MUST create a non-discoverable credential.
        // TODO

        let credential = self
            .secrets
            .make_credential(pk_parameters, &rp.id, &user.id)
            .await?;

        // 19. Generate an attestation statement for the newly-created credential using clientDataHash, taking into account the value of the enterpriseAttestation parameter, if present, as described above in Step 9.
        let auth_data = AuthenticatorData {
            rp_id_hash: Sha256::digest(rp.id.as_bytes()),
            user_present: up,
            user_verified: uv,
            sign_count: 1,
        };
        let att_stmt = self
            .secrets
            .attest(&rp.id, &credential, &auth_data, &client_data_hash)
            .await?;

        // On success, the authenticator returns the following authenticatorMakeCredential response structure which contains an attestation object plus additional information.
        Ok(MakeCredentialResponse {
            auth_data,
            att_stmt,
        })
    }

    async fn get_assertion(
        &self,
        cmd: GetAssertionCommand,
    ) -> Result<GetAssertionResponse, Self::Error> {
        let GetAssertionCommand {
            rp_id,
            client_data_hash,
        } = cmd;

        let credential: PublicKeyCredentialDescriptor = todo!();
        let auth_data: AuthenticatorData = todo!();
        let attestation_statement = self
            .secrets
            .attest(&rp_id, &credential, &auth_data, &client_data_hash)
            .await?;

        Ok(GetAssertionResponse {
            credential,
            auth_data,
            signature: todo!(),
        })
    }

    fn get_info(&self) -> Result<GetInfoResponse, Error> {
        Ok(self.get_info_internal())
    }

    async fn wink(&self) -> Result<(), Self::Error> {
        self.presence.wink().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use fido2_authenticator_api::{
        AttestationStatement, AuthenticatorData, CredentialId, PublicKeyCredentialRpEntity,
        PublicKeyCredentialType, PublicKeyCredentialUserEntity, RelyingPartyIdentifier, Sha256,
        UserHandle,
    };
    use std::collections::HashMap;
    use std::io;
    use std::sync::Mutex;
    use uuid::Uuid;

    use super::*;
    use crate::crypto::{PrivateKeyCredentialSource, PublicKeyCredentialSource};

    #[test]
    fn version() {
        let authenticator = fake_authenticator();

        let version = authenticator.version();

        assert_eq!(version.version_major, pkg_version::pkg_version_major!());
        assert_eq!(version.version_minor, pkg_version::pkg_version_minor!());
        assert_eq!(version.version_build, pkg_version::pkg_version_patch!());
        assert_eq!(version.wink_supported, true);
    }

    #[tokio::test]
    async fn get_info() {
        let authenticator = fake_authenticator();

        let info = authenticator.get_info().unwrap();

        assert_eq!(info.aaguid, Aaguid(Uuid::default()));
    }

    #[tokio::test]
    async fn make_credential_success() {
        let authenticator = fake_authenticator();
        let client_data_hash = Sha256::digest(b"client data");

        let result = authenticator
            .make_credential(MakeCredentialCommand {
                client_data_hash: client_data_hash.clone(),
                rp: PublicKeyCredentialRpEntity {
                    id: RelyingPartyIdentifier::new("example.com".into()),
                    name: "Example RP".into(),
                },
                user: PublicKeyCredentialUserEntity {
                    id: UserHandle::new(vec![0x01]),
                    name: "user@example.com".into(),
                    display_name: "Test User".into(),
                },
                pub_key_cred_params: vec![PublicKeyCredentialParameters {
                    alg: COSEAlgorithmIdentifier::ES256,
                    type_: PublicKeyCredentialType::PublicKey,
                }],
                exclude_list: None,
                extensions: None,
                options: None,
                pin_uv_auth_param: None,
                pin_uv_auth_protocol: None,
                enterprise_attestation: None,
            })
            .await
            .unwrap();

        assert_eq!(
            result.auth_data,
            AuthenticatorData {
                rp_id_hash: Sha256::digest("example.com".as_bytes()),
                user_present: true,
                user_verified: false,
                sign_count: 1,
            }
        );

        match result.att_stmt {
            AttestationStatement::Packed(statement) => {
                assert_eq!(statement.alg, COSEAlgorithmIdentifier::ES256);

                // Verify signature
                let attestation_certificate = statement.x5c.unwrap();
                let peer_public_key = ring::signature::UnparsedPublicKey::new(
                    &ring::signature::ECDSA_P256_SHA256_FIXED,
                    &attestation_certificate.attestnCert,
                );
                let mut message = result.auth_data.to_bytes();
                message.extend_from_slice(client_data_hash.as_ref());
                peer_public_key
                    .verify(&message, statement.sig.as_ref())
                    .unwrap();
            }
        };
    }

    #[tokio::test]
    async fn make_credential_fails_no_algorithm() {
        let authenticator = fake_authenticator();

        let result = authenticator
            .make_credential(MakeCredentialCommand {
                client_data_hash: Sha256::digest(b"client data"),
                rp: PublicKeyCredentialRpEntity {
                    id: RelyingPartyIdentifier::new("example.com".into()),
                    name: "Example RP".into(),
                },
                user: PublicKeyCredentialUserEntity {
                    id: UserHandle::new(vec![0x01]),
                    name: "user@example.com".into(),
                    display_name: "Test User".into(),
                },
                pub_key_cred_params: vec![],
                exclude_list: None,
                extensions: None,
                options: None,
                pin_uv_auth_param: None,
                pin_uv_auth_protocol: None,
                enterprise_attestation: None,
            })
            .await;

        match result {
            Err(Error::UnsupportedAlgorithm) => {}
            r => panic!("expected Error::UnsupportedAlgorithm, got {:?}", r),
        }
    }

    #[tokio::test]
    async fn make_credential_denies_enterprise_attestation() {
        let authenticator = fake_authenticator();

        let result = authenticator
            .make_credential(MakeCredentialCommand {
                client_data_hash: Sha256::digest(b"client data"),
                rp: PublicKeyCredentialRpEntity {
                    id: RelyingPartyIdentifier::new("example.com".into()),
                    name: "Example RP".into(),
                },
                user: PublicKeyCredentialUserEntity {
                    id: UserHandle::new(vec![0x01]),
                    name: "user@example.com".into(),
                    display_name: "Test User".into(),
                },
                pub_key_cred_params: vec![PublicKeyCredentialParameters {
                    alg: COSEAlgorithmIdentifier::ES256,
                    type_: PublicKeyCredentialType::PublicKey,
                }],
                exclude_list: None,
                extensions: None,
                options: None,
                pin_uv_auth_param: None,
                pin_uv_auth_protocol: None,
                enterprise_attestation: Some(1),
            })
            .await;

        match result {
            Err(Error::InvalidParameter) => {}
            r => panic!("expected Error::InvalidParameter, got {:?}", r),
        }
    }

    fn fake_authenticator() -> Authenticator<InMemorySecretStore, FakeUserPresence> {
        Authenticator::new(
            InMemorySecretStore::new(),
            FakeUserPresence::always_approve(),
            Aaguid(Uuid::default()),
        )
    }

    struct FakeUserPresence {
        pub should_make_credential: bool,
    }

    impl FakeUserPresence {
        fn always_approve() -> FakeUserPresence {
            FakeUserPresence {
                should_make_credential: true,
            }
        }
    }

    #[async_trait(?Send)]
    impl UserPresence for FakeUserPresence {
        type Error = io::Error;

        async fn approve_make_credential(&self, _: &str) -> Result<bool, Self::Error> {
            Ok(self.should_make_credential)
        }

        async fn wink(&self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct InMemorySecretStore(Mutex<InMemorySecretStoreInner>);

    struct InMemorySecretStoreInner {
        rng: ring::rand::SystemRandom,
        id_lookup: HashMap<RelyingPartyIdentifier, HashMap<UserHandle, CredentialId>>,
        keys: HashMap<CredentialId, PrivateKeyCredentialSource>,
    }

    impl InMemorySecretStore {
        fn new() -> InMemorySecretStore {
            InMemorySecretStore(Mutex::new(InMemorySecretStoreInner {
                rng: ring::rand::SystemRandom::new(),
                id_lookup: HashMap::new(),
                keys: HashMap::new(),
            }))
        }
    }

    #[async_trait(?Send)]
    impl SecretStore for InMemorySecretStore {
        type Error = io::Error;

        async fn make_credential(
            &self,
            pub_key_cred_params: &PublicKeyCredentialParameters,
            rp_id: &RelyingPartyIdentifier,
            user_handle: &UserHandle,
        ) -> Result<PublicKeyCredentialDescriptor, Self::Error> {
            let mut lock = self.0.lock().unwrap();
            let key = PrivateKeyCredentialSource::generate(
                &pub_key_cred_params.alg,
                &pub_key_cred_params.type_,
                rp_id,
                user_handle,
                &lock.rng,
            )
            .unwrap();
            let descriptor = PublicKeyCredentialDescriptor {
                type_: key.type_.clone(),
                id: key.id.clone(),
            };
            lock.keys.insert(key.id.clone(), key);
            lock.id_lookup
                .entry(rp_id.clone())
                .or_default()
                .insert(user_handle.clone(), descriptor.id.clone());
            Ok(descriptor)
        }

        async fn attest(
            &self,
            _rp_id: &RelyingPartyIdentifier,
            credential_descriptor: &PublicKeyCredentialDescriptor,
            auth_data: &AuthenticatorData,
            client_data_hash: &Sha256,
        ) -> Result<AttestationStatement, Self::Error> {
            let lock = self.0.lock().unwrap();
            if let Some(key) = lock.keys.get(&credential_descriptor.id) {
                let key: PublicKeyCredentialSource = key.clone().try_into().unwrap();
                // TODO increment use counter
                let signature = key.sign(auth_data, client_data_hash, &lock.rng).unwrap();
                Ok(AttestationStatement::Packed(PackedAttestationStatement {
                    alg: key.alg(),
                    sig: signature,
                    x5c: Some(AttestationCertificate {
                        attestnCert: key.public_key_document().as_ref().to_vec(),
                        caCerts: vec![],
                    }),
                }))
            } else {
                todo!("error")
            }
        }

        // fn add_application_key(&self, key: &ApplicationKey) -> io::Result<()> {
        //     self.0
        //         .lock()
        //         .unwrap()
        //         .application_keys
        //         .insert(key.application, key.clone());
        //     Ok(())
        // }

        // fn get_and_increment_counter(
        //     &self,
        //     application: &AppId,
        //     handle: &KeyHandle,
        // ) -> Result<Counter, io::Error> {
        //     let mut borrow = self.0.lock().unwrap();
        //     if let Some(counter) = borrow.counters.get_mut(application) {
        //         let counter_value = *counter;
        //         *counter += 1;
        //         return Ok(counter_value);
        //     }

        //     let initial_counter = 0;
        //     borrow.counters.insert(*application, initial_counter);
        //     Ok(initial_counter)
        // }

        // fn retrieve_application_key(
        //     &self,
        //     application: &AppId,
        //     handle: &KeyHandle,
        // ) -> Result<Option<ApplicationKey>, io::Error> {
        //     let borrow = self.0.lock().unwrap();
        //     let key = borrow.application_keys.get(application);
        //     match key {
        //         Some(key) if key.handle.eq_consttime(handle) => Ok(Some(key.clone())),
        //         _ => Ok(None),
        //     }
        // }
    }

    //     fn fake_attestation() -> Attestation {
    //         Attestation {
    //             certificate: AttestationCertificate::from_pem(
    //                 "-----BEGIN CERTIFICATE-----
    // MIIBfzCCASagAwIBAgIJAJaMtBXq9XVHMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMM
    // EFNvZnQgVTJGIFRlc3RpbmcwHhcNMTcxMDIwMjE1NzAzWhcNMjcxMDIwMjE1NzAz
    // WjAbMRkwFwYDVQQDDBBTb2Z0IFUyRiBUZXN0aW5nMFkwEwYHKoZIzj0CAQYIKoZI
    // zj0DAQcDQgAEryDZdIOGjRKLLyG6Mkc4oSVUDBndagZDDbdwLcUdNLzFlHx/yqYl
    // 30rPR35HvZI/zKWELnhl5BG3hZIrBEjpSqNTMFEwHQYDVR0OBBYEFHjWu2kQGzvn
    // KfCIKULVtb4WZnAEMB8GA1UdIwQYMBaAFHjWu2kQGzvnKfCIKULVtb4WZnAEMA8G
    // A1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgaiIS0Rb+Hw8WSO9fcsln
    // ERLGHDWaV+MS0kr5HgmvAjQCIEU0qjr86VDcpLvuGnTkt2djzapR9iO9PPZ5aErv
    // 3GCT
    // -----END CERTIFICATE-----",
    //             ),
    //             key: PrivateKey::from_pem(
    //                 "-----BEGIN EC PRIVATE KEY-----
    // MHcCAQEEIEijhKU+RGVbusHs9jNSUs9ZycXRSvtz0wrBJKozKuh1oAoGCCqGSM49
    // AwEHoUQDQgAEryDZdIOGjRKLLyG6Mkc4oSVUDBndagZDDbdwLcUdNLzFlHx/yqYl
    // 30rPR35HvZI/zKWELnhl5BG3hZIrBEjpSg==
    // -----END EC PRIVATE KEY-----",
    //             ),
    //         }
    //     }

    // fn verify_signature<T>(signature: &dyn Signature, data: &[u8], public_key: &PKeyRef<T>)
    // where
    //     T: HasPublic,
    // {
    //     let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).unwrap();
    //     verifier.update(data).unwrap();
    //     assert!(verifier.verify(signature.as_ref()).unwrap());
    // }
}
