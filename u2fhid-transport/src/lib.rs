enum StatusCode {
    NoError,
    TestOfUserPresenceNotSatisfied,
    InvalidKeyHandle,
    RequestLengthInvalid,
    RequestClassNotSupported,
    RequestInstructionNotSuppored,
}

enum AuthenticateControlCode {
    CheckOnly,
    EnforceUserPresenceAndSign,
    DontEnforceUserPresenceAndSign,
}

enum RequestMessage {
    Register {
        challenge_parameter: [u8; 32],
        application_parameter: [u8; 32],
    },
    Authenticate {
        control_code: AuthenticateControlCode,
        challenge_parameter: [u8; 32],
        application_parameter: [u8; 32],
        key_handle: Vec<u8>,
    },
    GetVersion,
}

enum ResponseMessage {
    RegisterSuccess {
        user_public_key: [u8; 65],
        key_handle: Vec<u8>,
        attestation_certificate: Vec<u8>,
        signature: Vec<u8>,
    },
    AuthenticateSuccess {
        user_present: bool,
        counter: u32,
        signature: Vec<u8>,
    },
    Version { version_string: String },
}
