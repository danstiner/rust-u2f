use std::sync::Mutex;

use async_trait::async_trait;
use fido2_api::{
    Aaguid, AttestationCertificate, AttestationStatement, AttestedCredentialData,
    AuthenticatorData, CredentialId, PackedAttestationStatement, PublicKeyCredentialDescriptor,
    Sha256,
};

use crate::{
    crypto::{PrivateKeyCredentialSource, PublicKeyCredentialSource},
    SecretStore,
};

pub(crate) trait SecretStoreActual {
    type Error;

    fn put(&mut self, credential: PrivateKeyCredentialSource) -> Result<(), Self::Error>;

    fn get(
        &self,
        credential_id: &CredentialId,
    ) -> Result<Option<PrivateKeyCredentialSource>, Self::Error>;
}

pub(crate) struct SimpleSecrets<S>(Mutex<SimpleSecretsData<S>>);

impl<S> SimpleSecrets<S> {
    pub fn new(store: S, aaguid: Aaguid) -> Self {
        Self(Mutex::new(SimpleSecretsData {
            aaguid,
            rng: ring::rand::SystemRandom::new(),
            store,
        }))
    }
}

pub(crate) struct SimpleSecretsData<S> {
    aaguid: Aaguid,
    rng: ring::rand::SystemRandom,
    store: S,
}

#[async_trait(?Send)]
impl<S: SecretStoreActual> SecretStore for SimpleSecrets<S> {
    type Error = S::Error;

    async fn make_credential(
        &self,
        pub_key_cred_params: &fido2_api::PublicKeyCredentialParameters,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        user_handle: &fido2_api::UserHandle,
    ) -> Result<fido2_api::PublicKeyCredentialDescriptor, Self::Error> {
        let mut data = self.0.lock().unwrap();
        let key = PrivateKeyCredentialSource::generate(
            &pub_key_cred_params.alg,
            &pub_key_cred_params.type_,
            rp_id,
            user_handle,
            &data.rng,
        )
        .unwrap();
        let descriptor = PublicKeyCredentialDescriptor {
            type_: key.type_.clone(),
            id: key.id.clone(),
        };
        data.store.put(key)?;
        Ok(descriptor)
    }

    async fn attest(
        &self,
        rp_id: &fido2_api::RelyingPartyIdentifier,
        credential: &fido2_api::PublicKeyCredentialDescriptor,
        client_data_hash: &fido2_api::Sha256,
        user_present: bool,
        user_verified: bool,
    ) -> Result<(AuthenticatorData, AttestationStatement), Self::Error> {
        let data = self.0.lock().unwrap();
        if let Some(key) = data.store.get(&credential.id)? {
            let key: PublicKeyCredentialSource = key.clone().try_into().unwrap();
            let auth_data = AuthenticatorData {
                rp_id_hash: Sha256::digest(rp_id.as_bytes()),
                user_present,
                user_verified,
                sign_count: 1,
                attested_credential_data: Some(vec![AttestedCredentialData {
                    aaguid: data.aaguid,
                    credential_id: credential.id.clone(),
                    credential_public_key: key.credential_public_key(),
                }]),
            };
            // TODO increment use counter
            let signature = key.sign(&auth_data, client_data_hash, &data.rng).unwrap();
            Ok((
                auth_data,
                AttestationStatement::Packed(PackedAttestationStatement {
                    alg: key.alg(),
                    sig: signature,
                    x5c: Some(AttestationCertificate {
                        attestnCert: key.public_key_document().as_ref().to_vec(), // TODO this should be the authenticator's certificate
                        caCerts: vec![],
                    }),
                }),
            ))
        } else {
            todo!("error")
        }
    }
}
