const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP1_ERR_OTHER: u8 = 0x7f;

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses
#[derive(Debug)]
pub enum StatusCode {
    UnsupportedAlgorithm,
    InvalidParameter,
    Other,
}

impl StatusCode {
    pub fn to_u8(&self) -> u8 {
        match self {
            StatusCode::UnsupportedAlgorithm => CTAP2_ERR_UNSUPPORTED_ALGORITHM,
            StatusCode::InvalidParameter => CTAP1_ERR_INVALID_PARAMETER,
            StatusCode::Other => CTAP1_ERR_OTHER,
        }
    }
}
