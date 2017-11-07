use std::ascii::AsciiExt;
use std::io::{self, Write};
use std::time::Duration;

use futures::{Future, Stream};
use futures::future;
use tokio_core::reactor::{Handle, Timeout};
use u2f_core::{ApplicationParameter, UserPresence};

use stdin_stream::stdin_stream;

fn approve_delay() -> Duration {
    Duration::from_secs(3)
}

pub struct CommandPromptUserPresence {
    handle: Handle,
}

impl CommandPromptUserPresence {
    pub fn new(handle: Handle) -> CommandPromptUserPresence {
        CommandPromptUserPresence { handle: handle }
    }

    fn test_user_presence(&self, prompt: &str) -> Box<Future<Item = bool, Error = io::Error>> {
        let handle = self.handle.clone();
        let prompt = String::from(prompt);
        print_prompt(&prompt);
        let replies_stream =
            stdin_stream().filter_map(move |line| if line.eq_ignore_ascii_case("y") {
                Some(true)
            } else if line.eq_ignore_ascii_case("n") {
                Some(false)
            } else {
                print_prompt(&prompt);
                None
            });
        let reply = replies_stream.into_future().map_err(|(err, _)| err).map(
            |(maybe_reply, _)| maybe_reply.unwrap_or(false),
        );
        let reply_after_delay = reply.and_then(move |res| {
            let delay = approve_delay();
            println!(
                "Waiting {} seconds before approving. Switch back to your browser or approval will fail.",
                delay.as_secs()
            );
            Timeout::new(delay, &handle).unwrap().map(move |_| {
                println!("Approved.");
                res
            })
        });
        Box::new(reply_after_delay)
    }
}

impl UserPresence for CommandPromptUserPresence {
    fn approve_registration(
        &self,
        _: &ApplicationParameter,
    ) -> Box<Future<Item = bool, Error = io::Error>> {
        self.test_user_presence("Approve registration [y/n]: ")
    }

    fn approve_authentication(
        &self,
        _: &ApplicationParameter,
    ) -> Box<Future<Item = bool, Error = io::Error>> {
        self.test_user_presence("Approve authentication [y/n]: ")
    }

    fn wink(&self) -> Box<Future<Item = (), Error = io::Error>> {
        println!(";)");
        Box::new(future::ok(()))
    }
}

fn print_prompt(prompt: &str) {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
}
