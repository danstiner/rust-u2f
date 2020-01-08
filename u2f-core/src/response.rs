use std::io;

use attestation::AttestationCertificate;
use byteorder::{BigEndian, WriteBytesExt};
use key_handle::KeyHandle;

use super::user_presence_byte;
use super::Counter;
use super::SignError;
use super::Signature;
use super::StatusCode;

pub enum Response {
    Registration {
        user_public_key: Vec<u8>,
        key_handle: KeyHandle,
        attestation_certificate: AttestationCertificate,
        signature: Box<dyn Signature>,
    },
    Authentication {
        counter: Counter,
        signature: Box<dyn Signature>,
        user_present: bool,
    },
    Version {
        version_string: String,
    },
    DidWink,
    TestOfUserPresenceNotSatisfied,
    InvalidKeyHandle,
    UnknownError,
}

impl Response {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Response::Registration {
                user_public_key,
                key_handle,
                attestation_certificate,
                signature,
            } => {
                // reserved byte [1 byte], which for legacy reasons has the value 0x05.
                bytes.push(0x05);

                // user public key [65 bytes]. This is the (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve.
                bytes.extend_from_slice(&user_public_key);

                // key handle length byte [1 byte], which specifies the length of the key handle (see below). The value is unsigned (range 0-255).
                let key_handle_bytes = key_handle.as_ref();
                bytes.push(key_handle_bytes.len() as u8);

                // A key handle [length specified in previous field].
                bytes.extend_from_slice(key_handle_bytes);

                // An attestation certificate [variable length]. This is a certificate in X.509 DER format
                bytes.extend_from_slice(&attestation_certificate.to_der());

                // A signature [variable length, 71-73 bytes]
                let signature_bytes = signature.as_ref().as_ref();
                bytes.extend_from_slice(signature_bytes);

                // Status word [2 bytes]
                StatusCode::NoError.write(&mut bytes);
            }
            Response::Authentication {
                counter,
                signature,
                user_present,
            } => {
                let user_presence_byte = user_presence_byte(user_present);

                // A user presence byte [1 byte].
                bytes.push(user_presence_byte);

                // A counter [4 bytes].
                bytes.write_u32::<BigEndian>(counter).unwrap();

                // A signature [variable length, 71-73 bytes]
                bytes.extend_from_slice(signature.as_ref().as_ref());

                // Status word [2 bytes]
                StatusCode::NoError.write(&mut bytes);
            }
            Response::Version { version_string } => {
                // The response message's raw representation is the
                // ASCII representation of the string 'U2F_V2'
                // (without quotes, and without any NUL terminator).
                bytes.extend_from_slice(version_string.as_bytes());

                // Status word [2 bytes]
                StatusCode::NoError.write(&mut bytes);
            }
            Response::DidWink => {
                // Status word [2 bytes]
                StatusCode::NoError.write(&mut bytes);
            }
            Response::TestOfUserPresenceNotSatisfied => {
                // Status word [2 bytes]
                StatusCode::TestOfUserPresenceNotSatisfied.write(&mut bytes);
            }
            Response::InvalidKeyHandle => {
                // Status word [2 bytes]
                StatusCode::InvalidKeyHandle.write(&mut bytes);
            }
            Response::UnknownError => {
                // Status word [2 bytes]
                StatusCode::UnknownError.write(&mut bytes);
            }
        }
        bytes
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum ResponseError {
        Io(err: io::Error) {
            from()
        }
        Signing(err: SignError) {
            from()
        }
    }
}

impl Into<io::Error> for ResponseError {
    fn into(self: Self) -> io::Error {
        match self {
            ResponseError::Io(err) => err,
            ResponseError::Signing(_) => io::Error::new(io::ErrorKind::Other, "Signing error"),
        }
    }
}
