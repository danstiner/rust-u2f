#[macro_use]
extern crate serde_derive;

extern crate serde;

pub const CHANNEL_ENV_VAR: &str = "IPC_CHANNEL";

#[derive(Serialize, Deserialize)]
pub struct UserPresenceTestParameters {
    pub message: String,
}
