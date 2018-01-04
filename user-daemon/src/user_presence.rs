use std::io;

use futures_cpupool::CpuPool;
use futures::future;
use futures::prelude::*;
use notify_rust::{Notification, NotificationHint, NotificationUrgency};
use slog::Logger;
use time::Duration;
use tokio_core::reactor::Handle;
use u2f_core::{ApplicationParameter, UserPresence, try_reverse_application_id};

// TODO this hardcoded keyword should be in the notifcation library
const NOTIFICATION_CLOSE_ACTION: &str = "__closed";

const MAX_CONCURRENT_NOTIFICATIONS: usize = 1;

lazy_static! {
    static ref NOTIFICATION_TIMEOUT: Duration = Duration::seconds(10);
}

pub struct NotificationUserPresence {
    executor: CpuPool,
    logger: Logger,
}

impl NotificationUserPresence {
    pub fn new(_handle: &Handle, logger: Logger) -> NotificationUserPresence {
        NotificationUserPresence {
            executor: CpuPool::new(MAX_CONCURRENT_NOTIFICATIONS),
            logger: logger,
        }
    }

    fn test_user_presence(&self, message: &str) -> Box<Future<Item = bool, Error = io::Error>> {
        info!(self.logger, "test_user_presence"; "message" => message);

        let body = message.to_owned();
        let logger_clone = self.logger.clone();

        Box::new(self.executor.spawn_fn(move || {
            let mut res = false;

            let handle = Notification::new()
                .summary("Security Key Request")
                .body(&body)
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

            let logger_clone_close = logger_clone.clone();
            handle.wait_for_action(|action| match action {
                    "approve" => res = true,
                    "deny" => res = false,
                    "default" => res = false,
                    NOTIFICATION_CLOSE_ACTION => {
                        info!(logger_clone_close, "The notification was closed");
                        res = false;
                    }
                    _ => unreachable!("Unknown action taken on notification"),
                });

            info!(logger_clone, "test_user_presence"; "result" => res);

            future::ok(res)
        }))
    }
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
