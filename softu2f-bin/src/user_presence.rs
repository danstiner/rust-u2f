use std::env;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use sandbox_ipc;
use futures::{Future, Sink, Stream};
use futures::future;
use serde_json;
use tokio_core::reactor::Handle;

use super::{DBUS_SESSION_BUS_ADDRESS_VAR, PreSudoEnvironment};
use u2f_core::{ApplicationParameter, UserPresence, try_reverse_application_id};
use softu2f_test_user_presence::{CHANNEL_ENV_VAR, UserPresenceTestParameters};

pub struct NotificationUserPresence {
    handle: Handle,
    pre_sudo_env: PreSudoEnvironment,
}

impl NotificationUserPresence {
    pub fn new(handle: Handle, pre_sudo_env: PreSudoEnvironment) -> NotificationUserPresence {
        NotificationUserPresence {
            handle: handle,
            pre_sudo_env: pre_sudo_env,
        }
    }

    fn test_user_presence(&self, message: &str) -> Box<Future<Item = bool, Error = io::Error>> {
        let mut child_command = match test_command() {
            Ok(command) => command,
            Err(err) => return Box::new(future::err(err)),
        };

        let (channel, mut child) =
            sandbox_ipc::MessageChannel::<UserPresenceTestParameters, bool>::establish_with_child(
                &mut child_command,
                8192,
                &self.handle,
                |command, child_channel| {
                    command
                        .uid(self.pre_sudo_env.security_ids.uid)
                        .gid(self.pre_sudo_env.security_ids.gid)
                        .env_clear()
                        .current_dir("/")
                        .stdin(Stdio::null())
                        .env(DBUS_SESSION_BUS_ADDRESS_VAR, &self.pre_sudo_env.dbus_session_bus_address)
                        // .env("PATH", "/bin:/usr/bin")
                        // .env("IFS", " \t\n")
                        .env(
                            CHANNEL_ENV_VAR,
                            serde_json::to_string(child_channel).unwrap(),
                        )
                        .spawn()
                },
            ).unwrap();

        Box::new(
            channel
                .send(UserPresenceTestParameters {
                    message: String::from(message),
                })
                .and_then(|channel| {
                    channel
                        .into_future()
                        .map(|(response_option, _)| response_option.unwrap_or(false))
                        .map_err(|(err, _)| err)
                }).then(move |res| {
                    child.kill().ok(); // TODO Only allow certain failures
                    res
                })
        )
    }
}

fn test_command() -> io::Result<Command> {
    let mut path = env::current_exe()?;
    path.set_file_name("softu2f-test-user-presence");
    path.set_extension("");
    Ok(Command::new(&path))
}

impl UserPresence for NotificationUserPresence {
    fn approve_registration(
        &self,
        application: &ApplicationParameter,
    ) -> Box<Future<Item = bool, Error = io::Error>> {
        let site_name = try_reverse_application_id(application).unwrap_or(String::from("site"));
        let message = format!("Register with {}", site_name);
        self.test_user_presence(&message)
    }

    fn approve_authentication(
        &self,
        application: &ApplicationParameter,
    ) -> Box<Future<Item = bool, Error = io::Error>> {
        let site_name = try_reverse_application_id(application).unwrap_or(String::from("site"));
        let message = format!("Authenticate with {}", site_name);
        self.test_user_presence(&message)
    }

    fn wink(&self) -> Box<Future<Item = (), Error = io::Error>> {
        println!(";)");
        Box::new(future::ok(()))
    }
}
