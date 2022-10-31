/// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#error-responses
#[derive(Debug)]
pub enum StatusCode {
    /// CTAP1_ERR_SUCCESS, CTAP2_OK: Indicates successful response.
    Ok = 0x00,
    /// The command is not a valid CTAP command.
    InvalidCommand = 0x01,
    /// The command included an invalid parameter.
    InvalidParameter = 0x02,
    /// Invalid message or item length.
    InvalidLength = 0x03,
    /// Error when parsing CBOR
    InvalidCbor = 0x12,
    /// Missing non-optional parameter
    MissingParameter = 0x14,
    /// Authenticator does not support requested algorithm.
    UnsupportedAlgorithm = 0x26,
    /// Other unspecified error
    Other = 0x7f,
    /// No valid credentials provided.
    NoCredentials = 0x2e,
}

impl StatusCode {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
