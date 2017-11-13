use std::collections::HashMap;

use super::ApplicationParameter;

pub fn try_reverse_application_id(application: &ApplicationParameter) -> Option<String> {
    KNOWN_FACETS.get(application).map(|s| String::from(*s))
}

fn app_id(url: &str) -> ApplicationParameter {
    ApplicationParameter::from_str(url)
}

/// Should be kept in sync with https://github.com/github/SoftU2F/blob/master/SoftU2FTool/KnownFacets.swift
lazy_static! {
    static ref KNOWN_FACETS: HashMap<ApplicationParameter, &'static str> = {
        let mut facets = HashMap::new();
        facets.insert(app_id("https://github.com/u2f/trusted_facets"), "https://github.com");
        facets.insert(app_id("https://demo.yubico.com"), "https://demo.yubico.com");
        facets.insert(app_id("https://www.dropbox.com/u2f-app-id.json"), "https://dropbox.com");
        facets.insert(app_id("https://www.gstatic.com/securitykey/origins.json"), "https://google.com");
        facets.insert(app_id("https://vault.bitwarden.com/app-id.json"), "https://vault.bitwarden.com");
        facets.insert(app_id("https://keepersecurity.com"), "https://keepersecurity.com");
        facets.insert(app_id("https://api-9dcf9b83.duosecurity.com"), "https://api-9dcf9b83.duosecurity.com");
        facets.insert(app_id("https://dashboard.stripe.com"), "https://dashboard.stripe.com");
        facets.insert(ApplicationParameter([178, 69, 252, 77, 230, 119, 249, 186, 244, 183, 217, 253, 44, 8, 33, 181, 43, 115, 217, 237, 112, 141, 5, 247, 174, 17, 120, 196, 131, 70, 225, 105]), "https://www.facebook.com");
        facets
    };
}
