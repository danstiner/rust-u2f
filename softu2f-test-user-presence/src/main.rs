#[macro_use]
extern crate lazy_static;

extern crate futures;
extern crate notify_rust;
extern crate sandbox_ipc as ipc;
extern crate serde_json as json;
extern crate softu2f_test_user_presence;
extern crate time;
extern crate tokio_core;

use std::env;
use std::io;

use futures::prelude::*;
use notify_rust::{Notification, NotificationHint, NotificationUrgency};
use time::Duration;
use tokio_core::reactor::Core;

use softu2f_test_user_presence::{UserPresenceTestParameters, CHANNEL_ENV_VAR};

// TODO this hardcoded keyword should be in the notifcation library
const NOTIFICATION_CLOSE_ACTION: &str = "__closed";

lazy_static! {
    static ref NOTIFICATION_TIMEOUT: Duration = Duration::seconds(10);
}

fn notify(parameters: UserPresenceTestParameters) -> io::Result<bool> {
    let mut res = false;

    let handle = Notification::new()
        .summary("Security Key Request")
        .body(&parameters.message)
        .action("deny", "Deny")
        .action("approve", "Approve")
        .icon("security-high-symbolic")
        .hint(NotificationHint::Category(String::from("device")))
        .hint(NotificationHint::Transient(true))
        .hint(NotificationHint::Urgency(NotificationUrgency::Critical))
        .urgency(NotificationUrgency::Critical)
        .timeout(NOTIFICATION_TIMEOUT.num_milliseconds() as i32)
        .show()
        .unwrap();

    handle.wait_for_action({
        |action| match action {
            "approve" => res = true,
            "deny" => res = false,
            "default" => res = false,
            NOTIFICATION_CLOSE_ACTION => {
                println!("the notification was closed");
                res = false;
            }
            _ => unreachable!("Unknown action taken on notification"),
        }
    });

    Ok(res)
}

fn main() {
    let mut core = Core::new().unwrap();
    let handle = core.handle();

    let channel: ipc::ChildMessageChannel =
        json::from_str(&env::var(CHANNEL_ENV_VAR).unwrap()).unwrap();
    let channel = channel
        .into_channel::<bool, UserPresenceTestParameters>(&handle)
        .unwrap();

    let (parameters, channel) = core.run(channel.into_future())
        .map_err(|(err, _)| err)
        .unwrap();

    let res = notify(parameters.unwrap()).unwrap();

    let _channel = core.run(channel.send(res)).unwrap();
}
