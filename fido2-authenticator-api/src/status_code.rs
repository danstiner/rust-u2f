const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;
const CTAP2_ERR_INVALID_CBOR: u8 = 0x12;
const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
const CTAP1_ERR_OTHER: u8 = 0x7f;

/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses
#[derive(Debug)]
pub enum StatusCode {
    /// The command included an invalid parameter.
    InvalidCommandParameter,
    /// Error when parsing CBOR
    InvalidCbor,
    /// Missing non-optional parameter
    MissingParameter,
    /// Authenticator does not support requested algorithm.
    UnsupportedAlgorithm,
    /// Other unspecified error
    Other,
}

impl StatusCode {
    pub fn to_u8(&self) -> u8 {
        match self {
            StatusCode::InvalidCommandParameter => CTAP1_ERR_INVALID_PARAMETER,
            StatusCode::InvalidCbor => CTAP2_ERR_INVALID_CBOR,
            StatusCode::MissingParameter => CTAP2_ERR_MISSING_PARAMETER,
            StatusCode::UnsupportedAlgorithm => CTAP2_ERR_UNSUPPORTED_ALGORITHM,
            StatusCode::Other => CTAP1_ERR_OTHER,
        }
    }
}
