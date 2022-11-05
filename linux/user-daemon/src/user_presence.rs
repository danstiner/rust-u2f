use std::collections::HashMap;
use std::io;

use async_trait::async_trait;
use fido2_api::PublicKeyCredentialRpEntity;
use fido2_service::UserPresence;
use lazy_static::lazy_static;
use notify_rust::Timeout;
use notify_rust::{self, Hint, Notification, Urgency};
use tracing::debug;

const APPNAME: &str = "SoftU2F";
const HINT_CATEGORY: &str = "device";
const ICON: &str = "security-high-symbolic";
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

pub struct NotificationUserPresence;

impl NotificationUserPresence {
    pub fn new() -> Self {
        NotificationUserPresence
    }

    async fn test_user_presence(&self, message: String) -> Result<bool, io::Error> {
        debug!(%message, "test_user_presence");

        let mut notification = Notification::new();
        notification
            .appname(APPNAME)
            .summary(SUMMARY)
            .body(&message)
            .icon(ICON)
            .hint(Hint::Category(String::from(HINT_CATEGORY)))
            .hint(Hint::Transient(true))
            .hint(Hint::Urgency(URGENCY))
            .urgency(URGENCY)
            .timeout(*TIMEOUT);

        let mut apply_workaround = false;
        let server_info = notify_rust::get_server_information().unwrap();
        if let Some(version) = WORKAROUND_SERVERS.get(server_info.name.as_str()) {
            if version == &server_info.version {
                debug!(
                    ?server_info,
                    "Detected server that require workaround, applying"
                );
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
            "__closed" => false,
            _ => unreachable!("Unknown action taken on notification"),
        };

        debug!(%action, user_present, "test_user_presence");

        Ok(user_present)
    }
}

#[async_trait(?Send)]
impl UserPresence for NotificationUserPresence {
    type Error = io::Error;

    async fn approve_make_credential(
        &self,
        rp: &PublicKeyCredentialRpEntity,
    ) -> Result<bool, Self::Error> {
        let message = format!("Register with {}", rp);
        self.test_user_presence(message).await
    }

    async fn wink(&self) -> Result<(), Self::Error> {
        let message = String::from("Ready to authenticate ;)");
        Notification::new()
            .appname(APPNAME)
            .summary(SUMMARY)
            .body(&message)
            .icon(ICON)
            .hint(Hint::Category(String::from(HINT_CATEGORY)))
            .hint(Hint::Transient(true))
            .hint(Hint::Urgency(URGENCY))
            .urgency(URGENCY)
            .timeout(*TIMEOUT)
            .show()
            .unwrap();
        Ok(())
    }
}
