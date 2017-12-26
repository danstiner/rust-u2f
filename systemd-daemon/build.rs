extern crate protoc_rust;

use std::env;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    protoc_rust::run(protoc_rust::Args {
        out_dir: &out_dir,
        input: &["protos/socket.proto"],
        includes: &["protos"],
    }).expect("protoc");
}
