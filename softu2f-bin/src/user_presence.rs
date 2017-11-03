use std::ascii::AsciiExt;
use std::io;
use std::thread;
use std::time;

use rprompt;
use u2f_core::{ApplicationParameter, UserPresence};

pub struct CommandPromptUserPresence;

impl CommandPromptUserPresence {
    fn approve(prompt: &str) -> io::Result<bool> {
        loop {
            let reply = rprompt::prompt_reply_stdout(prompt)?;
            if reply.eq_ignore_ascii_case("y") {
                let approve_delay = time::Duration::from_secs(3);
                println!(
                    "Waiting {} seconds. Switch back to your browser or operation will fail.",
                    approve_delay.as_secs()
                );
                thread::sleep(approve_delay);
                return Ok(true);
            } else if reply.eq_ignore_ascii_case("n") {
                return Ok(false);
            }
        }
    }
}

impl UserPresence for CommandPromptUserPresence {
    fn approve_registration(&self, _: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve registration [y/n]: ")
    }

    fn approve_authentication(&self, _: &ApplicationParameter) -> io::Result<bool> {
        Self::approve("Approve authentication [y/n]: ")
    }

    fn wink(&self) -> io::Result<()> {
        println!(";)");
        Ok(())
    }
}
