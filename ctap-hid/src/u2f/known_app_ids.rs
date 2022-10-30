use std::collections::HashMap;

use super::app_id::AppId;
use lazy_static::lazy_static;
use ring::digest;

// Known bogus app id hashes, Browsers do a bogus register command after certain authentication failures,
// this "force[s] the user to tap the [key] before revealing [the authentication state to the site]".
//
// In the future we should perhaps display a notification to the user about the authentication failure.
//
// See https://github.com/google/u2f-ref-code/blob/b11e47c5bca093c93d802286bead3db78a4b0b9f/u2f-chrome-extension/usbsignhandler.js#L118

lazy_static! {
    static ref KNOWN_APP_IDS: HashMap<AppId, &'static str> = {
        let mut map = HashMap::new();

        // Sourced from https://github.com/github/SoftU2F/blob/master/SoftU2FTool/KnownFacets.swift
        map.insert(from_url("https://github.com/u2f/trusted_facets"), "github.com");
        map.insert(from_url("https://demo.yubico.com"), "demo.yubico.com");
        map.insert(from_url("https://www.dropbox.com/u2f-app-id.json"), "dropbox.com");
        map.insert(from_url("https://www.gstatic.com/securitykey/origins.json"), "google.com");
        map.insert(from_url("https://vault.bitwarden.com/app-id.json"), "vault.bitwarden.com");
        map.insert(from_url("https://keepersecurity.com"), "keepersecurity.com");
        map.insert(from_url("https://api-9dcf9b83.duosecurity.com"), "duosecurity.com");
        map.insert(from_url("https://dashboard.stripe.com"), "dashboard.stripe.com");
        map.insert(from_url("https://id.fedoraproject.org/u2f-origins.json"), "id.fedoraproject.org");
        map.insert(from_url("https://lastpass.com"), "lastpass.com");
        map.insert(from_url("https://u2f.aws.amazon.com/app-id.json"), "aws.amazon.com");

        // Additional known app IDs
        map.insert(from_url("bin.coffee"), "bin.coffee");
        map.insert(from_url("coinbase.com"), "coinbase.com");
        map.insert(from_url("demo.yubico.com"), "demo.yubico.com");
        map.insert(from_url("https://gitlab.com"), "gitlab.com");
        map.insert(from_url("https://mdp.github.io"), "mdp.github.io");
        map.insert(from_url("https://u2f.bin.coffee"), "u2f.bin.coffee");
        map.insert(from_url("https://www.fastmail.com"), "www.fastmail.com");
        map.insert(from_url("webauthn.bin.coffee"), "webauthn.bin.coffee");
        map.insert(from_url("webauthn.io"), "webauthn.io");
        map.insert(from_url("ssh:"), "ssh key");

        map
    };
}

fn from_url(url: &str) -> AppId {
    AppId::from_bytes(digest::digest(&digest::SHA256, url.as_bytes()).as_ref())
}
