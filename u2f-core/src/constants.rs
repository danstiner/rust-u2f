pub(crate) const REGISTER_COMMAND_CODE: u8 = 0x01;
pub(crate) const AUTHENTICATE_COMMAND_CODE: u8 = 0x02;
pub(crate) const VERSION_COMMAND_CODE: u8 = 0x03;
pub(crate) const VENDOR_FIRST_COMMAND_CODE: u8 = 0x40;
pub(crate) const VENDOR_LAST_COMMAND_CODE: u8 = 0xbf;

pub(crate) const SW_NO_ERROR: u16 = 0x9000; // The command completed successfully without error.
pub(crate) const SW_WRONG_DATA: u16 = 0x6A80; // The request was rejected due to an invalid key handle.
pub(crate) const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985; // The request was rejected due to test-of-user-presence being required.
pub(crate) const SW_COMMAND_NOT_ALLOWED: u16 = 0x6986;
pub(crate) const SW_INS_NOT_SUPPORTED: u16 = 0x6D00; // The Instruction of the request is not supported.
pub(crate) const SW_WRONG_LENGTH: u16 = 0x6700; // The length of the request was invalid.
pub(crate) const SW_CLA_NOT_SUPPORTED: u16 = 0x6E00; // The Class byte of the request is not supported.
pub(crate) const SW_UNKNOWN: u16 = 0x6F00; // Response status : No precise diagnosis

pub(crate) const AUTH_ENFORCE: u8 = 0x03; // Enforce user presence and sign
pub(crate) const AUTH_CHECK_ONLY: u8 = 0x07; // Check only
pub(crate) const AUTH_FLAG_TUP: u8 = 0x01; // Test of user presence set

/// Spec says 255 is max length, but the provided .C header says 128
/// Chose the smaller, it is still sufficient entropy to avoid collisions
pub(crate) const MAX_KEY_HANDLE_LEN: usize = 128;

pub(crate) const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0x04;
