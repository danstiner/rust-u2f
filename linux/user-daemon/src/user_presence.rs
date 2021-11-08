use std::collections::HashMap;
use std::io;

use futures::future;
use futures::prelude::*;
use futures_cpupool::CpuPool;
use notify_rust::Timeout;
use notify_rust::{self, Notification, Hint, Urgency};
use slog::Logger;
use tokio_core::reactor::Handle;
use u2f_core::{try_reverse_app_id, AppId, UserPresence};

const APPNAME: &str = "SoftU2F";
const HINT_CATEGORY: &str = "device";
const ICON: &str = "security-high-symbolic";
const MAX_CONCURRENT_NOTIFICATIONS: usize = 1;
const NOTIFICATION_CLOSE_ACTION: &str = "__closed";
const SUMMARY: &str = "Security Key Request";
const URGENCY: Urgency = Urgency::Critical;

lazy_static! {
    static ref TIMEOUT: Timeout = Timeout::Milliseconds(10_000);
    static ref WORKAROUND_SERVERS: HashMap<&'static str, &'static str> = {
        let mut ws = HashMap::new();
        // See https://github.com/danstiner/softu2f-linux/issues/12
        ws.insert("notify-osd", "1.0");
        ws.insert("mako", "0.0.0");
        ws
    };
}

pub struct NotificationUserPresence {
    executor: CpuPool,
    logger: Logger,
}

impl NotificationUserPresence {
    pub fn new(_handle: &Handle, logger: Logger) -> NotificationUserPresence {
        NotificationUserPresence {
            executor: CpuPool::new(MAX_CONCURRENT_NOTIFICATIONS),
            logger,
        }
    }

    fn test_user_presence(&self, message: &str) -> Box<dyn Future<Item = bool, Error = io::Error>> {
        debug!(self.logger, "test_user_presence"; "message" => message);

        let body = message.to_owned();
        let logger = self.logger.clone();

        Box::new(self.executor.spawn_fn(move || {
            let mut notification = Notification::new();
            notification
                .appname(APPNAME)
                .summary(SUMMARY)
                .body(&body)
                .icon(ICON)
                .hint(Hint::Category(String::from(HINT_CATEGORY)))
                .hint(Hint::Transient(true))
                .hint(Hint::Urgency(URGENCY))
                .urgency(URGENCY)
                .timeout(TIMEOUT.clone());

            let mut apply_workaround = false;
            let server_info = notify_rust::get_server_information().unwrap();
            if let Some(version) = WORKAROUND_SERVERS.get(server_info.name.as_str()) {
                if version == &server_info.version {
                    debug!(logger, "Detected server that require workaround, applying"; "server_info" => ?server_info);
                    apply_workaround = true;
                }
            }

            let mut default_means_user_present = false;
            if apply_workaround {
                notification.action("default", "");
                default_means_user_present = true;
            } else {
                notification.action("approve", "Approve");
                notification.action("deny", "Deny");
            }

            let notify_handle = notification.show().unwrap();

            let mut action = String::new();
            notify_handle.wait_for_action(|a| action = a.to_owned());

            let user_present = match action.as_str() {
                "approve" => true,
                "deny" => false,
                "default" => default_means_user_present,
                NOTIFICATION_CLOSE_ACTION => false,
                _ => unreachable!("Unknown action taken on notification"),
            };

            debug!(logger, "test_user_presence"; "action" => action, "user_present" => user_present);

            Ok(user_present)
        }))
    }
}

impl UserPresence for NotificationUserPresence {
    fn approve_registration(
        &self,
        application: &AppId,
    ) -> Box<dyn Future<Item = bool, Error = io::Error>> {
        let site_name = try_reverse_app_id(application).unwrap_or(String::from("site"));
        let message = format!("Register with {}", site_name);
        self.test_user_presence(&message)
    }

    fn approve_authentication(
        &self,
        application: &AppId,
    ) -> Box<dyn Future<Item = bool, Error = io::Error>> {
        let site_name = try_reverse_app_id(application).unwrap_or(String::from("site"));
        let message = format!("Authenticate with {}", site_name);
        self.test_user_presence(&message)
    }

    fn wink(&self) -> Box<dyn Future<Item = (), Error = io::Error>> {
        let message = String::from("Ready to authenticate");
        Notification::new()
            .appname(APPNAME)
            .summary(SUMMARY)
            .body(&message)
            .icon(ICON)
            .hint(Hint::Category(String::from(HINT_CATEGORY)))
            .hint(Hint::Transient(true))
            .hint(Hint::Urgency(URGENCY))
            .urgency(URGENCY)
            .timeout(TIMEOUT.clone());
        Box::new(future::ok(()))
    }
}
