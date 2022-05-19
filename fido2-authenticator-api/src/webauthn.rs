use serde::{Deserialize, Serialize};

enum COSEAlgorithmIdentifier {
    ES256 = -7,
    ES384 = -35,
    ES512 = -36,
    EdDSA = -8,
}

#[derive(Debug)]
pub struct PublicKeyCredentialParameters {
    alg: u64, // todo use COSEAlgorithmIdentifier
    type_: String,
}
