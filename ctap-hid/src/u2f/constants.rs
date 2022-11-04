pub(crate) const REGISTER_COMMAND_CODE: u8 = 0x01;
pub(crate) const AUTHENTICATE_COMMAND_CODE: u8 = 0x02;
pub(crate) const VERSION_COMMAND_CODE: u8 = 0x03;
pub(crate) const _VENDOR_FIRST_COMMAND_CODE: u8 = 0x40;
pub(crate) const _VENDOR_LAST_COMMAND_CODE: u8 = 0xbf;

pub(crate) const SW_NO_ERROR: u16 = 0x9000; // The command completed successfully without error.
pub(crate) const SW_WRONG_DATA: u16 = 0x6A80; // The request was rejected due to an invalid key handle.
pub(crate) const SW_CONDITIONS_NOT_SATISFIED: u16 = 0x6985; // The request was rejected due to test-of-user-presence being required.
pub(crate) const _SW_COMMAND_NOT_ALLOWED: u16 = 0x6986;
pub(crate) const SW_UNKNOWN: u16 = 0x6F00; // Response status : No precise diagnosis

pub(crate) const AUTH_ENFORCE: u8 = 0x03; // Enforce user presence and sign
pub(crate) const AUTH_CHECK_ONLY: u8 = 0x07; // Check only
pub(crate) const AUTH_DONT_ENFORCE: u8 = 0x08; // Don't enforce user presence and sign

pub(crate) const DEFAULT_KEY_HANDLE_LEN: usize = 255;
pub(crate) const MAX_KEY_HANDLE_LEN: usize = 255;
