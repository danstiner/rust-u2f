use std::collections::HashMap;

use super::AppId;

pub fn try_reverse_app_id(app_id: &AppId) -> Option<String> {
    KNOWN_APP_IDS.get(app_id).map(|s| String::from(*s))
}

/// Should be kept in sync with https://github.com/github/SoftU2F/blob/master/SoftU2FTool/KnownFacets.swift
lazy_static! {
    static ref KNOWN_APP_IDS: HashMap<AppId, &'static str> = {
        let mut map = HashMap::new();
        map.insert(AppId::from_url("https://github.com/u2f/trusted_facets"), "https://github.com");
        map.insert(AppId::from_url("https://demo.yubico.com"), "https://demo.yubico.com");
        map.insert(AppId::from_url("https://www.dropbox.com/u2f-app-id.json"), "https://dropbox.com");
        map.insert(AppId::from_url("https://www.gstatic.com/securitykey/origins.json"), "https://google.com");
        map.insert(AppId::from_url("https://vault.bitwarden.com/app-id.json"), "https://vault.bitwarden.com");
        map.insert(AppId::from_url("https://keepersecurity.com"), "https://keepersecurity.com");
        map.insert(AppId::from_url("https://api-9dcf9b83.duosecurity.com"), "https://api-9dcf9b83.duosecurity.com");
        map.insert(AppId::from_url("https://dashboard.stripe.com"), "https://dashboard.stripe.com");
        map.insert(AppId::from_url("https://id.fedoraproject.org/u2f-origins.json"), "https://id.fedoraproject.org");
        map.insert(AppId::from_url("https://gitlab.com"), "https://gitlab.com");
        map
    };
}
