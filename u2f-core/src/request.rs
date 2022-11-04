use std::io;
use std::io::Cursor;
use std::io::Read;
use std::result::Result;

use crate::app_id::AppId;
use crate::key_handle::KeyHandle;
use byteorder::{BigEndian, ReadBytesExt};

use super::Challenge;

const AUTH_CONTROL_CODE_ENFORCE: u8 = 0x03; // Enforce user presence and sign
const AUTH_CONTROL_CODE_CHECK_ONLY: u8 = 0x07; // Check only
const AUTH_CONTROL_CODE_DONT_ENFORCE: u8 = 0x08; // Don't enforce user presence and sign

const REGISTER_COMMAND_CODE: u8 = 0x01;
const AUTHENTICATE_COMMAND_CODE: u8 = 0x02;
const VERSION_COMMAND_CODE: u8 = 0x03;

#[derive(Debug)]
pub enum AuthenticateControlCode {
    CheckOnly,
    EnforceUserPresenceAndSign,
    DontEnforceUserPresenceAndSign,
}

#[derive(Debug)]
pub enum Request {
    Register {
        application: AppId,
        challenge: Challenge,
    },
    Authenticate {
        application: AppId,
        challenge: Challenge,
        control_code: AuthenticateControlCode,
        key_handle: KeyHandle,
    },
    GetVersion,
    Wink,
}

impl Request {
    /// Only supports Extended Length Encoding
    pub fn decode(data: &[u8]) -> Result<Request, io::Error> {
        let mut reader = Cursor::new(data);

        // CLA: Reserved to be used by the underlying transport protocol
        let _class_byte = reader.read_u8()?;
        // TODO check or error with RequestClassNotSupported

        // INS: U2F command code
        let command_code = reader.read_u8()?;
        // TODO check or error with RequestInstructionNotSuppored

        // P1, P2: Parameter 1 and 2, defined by each command.
        let parameter1 = reader.read_u8()?;
        let parameter2 = reader.read_u8()?;

        // Extended Length Encoding
        // Always begins with a byte of value 0
        let zero_byte = reader.read_u8()?;
        assert_eq!(zero_byte, 0);

        // Nc: Length of the request-data, range 0..65 535
        // Lc: Encoding of Nc as two bytes
        // If Nc is 0, Lc is omitted (Caveat: Not all implementations respect this)
        let remaining_len = data.len() - reader.position() as usize;
        let request_data_len = match remaining_len {
            2 => {
                // Lc was omitted, there is no request data
                0
            }
            _ => {
                // Lc in big-endian order
                reader.read_u16::<BigEndian>()? as usize
            }
        };

        // Request-data
        let mut request_data = vec![0u8; request_data_len];
        reader.read_exact(&mut request_data[..])?;

        // Ne: Maximum length of the response data, range 0..65 536
        // Le: Encoding of Ne as two bytes
        // If no response data are expected, Le may be omitted.
        let remaining_len = data.len() - reader.position() as usize;
        let _max_response_data_len = match remaining_len {
            0 => {
                // Lc was omitted, instruction is not expected to yield any response bytes
                0
            }
            2 => {
                // Encoded as: Le1 Le2
                let mut value = reader.read_u16::<BigEndian>()? as usize;
                // When Ne = 65 536, let Le1 = 0 and Le2 = 0.
                if value == 0 {
                    // The MSB is lost when encoding to two bytes, but
                    // since Le can be omitted when there are no request data
                    // bytes, we can unambigously assume 0 to mean 65 535
                    value = 65535;
                }
                value
            }
            _ => todo!("return Error"),
        };

        // TODO If the instruction is not expected to yield any response bytes, L e may be omitted. O
        let mut reader = Cursor::new(request_data);
        let request = match command_code {
            REGISTER_COMMAND_CODE => {
                // TODO this isn't matching the constant, it's defining a variable
                // The challenge parameter [32 bytes].
                let mut challenge_parameter = [0u8; 32];
                reader.read_exact(&mut challenge_parameter[..])?;

                // The application parameter [32 bytes].
                let mut application_parameter = [0u8; 32];
                reader.read_exact(&mut application_parameter[..])?;

                assert_eq!(reader.position() as usize, request_data_len);
                Request::Register {
                    application: AppId(application_parameter),
                    challenge: Challenge(challenge_parameter),
                }
            }
            AUTHENTICATE_COMMAND_CODE => {
                assert_eq!(parameter2, 0);

                // Control byte (P1).
                let control_code = match parameter1 {
                    AUTH_CONTROL_CODE_CHECK_ONLY => AuthenticateControlCode::CheckOnly,
                    AUTH_CONTROL_CODE_ENFORCE => {
                        AuthenticateControlCode::EnforceUserPresenceAndSign
                    }
                    AUTH_CONTROL_CODE_DONT_ENFORCE => {
                        AuthenticateControlCode::DontEnforceUserPresenceAndSign
                    }
                    _ => panic!("Unknown control code"),
                };

                // The challenge parameter [32 bytes].
                let mut challenge_parameter = [0u8; 32];
                reader.read_exact(&mut challenge_parameter[..])?;

                // The application parameter [32 bytes].
                let mut application_parameter = [0u8; 32];
                reader.read_exact(&mut application_parameter[..])?;

                // key handle length byte [1 byte]
                let key_handle_len = reader.read_u8()?;

                // key handle [length specified in previous field]
                let mut key_handle_bytes = vec![0u8; key_handle_len as usize];
                reader.read_exact(&mut key_handle_bytes[..])?;

                Request::Authenticate {
                    application: AppId(application_parameter),
                    challenge: Challenge(challenge_parameter),
                    control_code,
                    key_handle: KeyHandle::from(&key_handle_bytes),
                }
            }
            VERSION_COMMAND_CODE => {
                assert_eq!(parameter1, 0);
                assert_eq!(parameter2, 0);
                assert_eq!(request_data_len, 0);
                Request::GetVersion
            }
            _ => panic!("Command not implemented"),
        };
        Ok(request)
    }
}
