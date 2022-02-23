extern crate protoc_rust;

use protoc_rust::Customize;
use std::path::Path;

fn main() {
    //println!("cargo:rerun-if-changed=src/config/geosite.rs");
    //println!("cargo:rerun-if-changed=src/config/geoip.rs");
    let p1 = Path::new("src/config/geoip.rs");
    let p2 = Path::new("src/config/geosite.rs");
    if p1.exists() && p2.exists() {
        return;
    }
    protoc_rust::Codegen::new()
        .out_dir("src/")
        .customize(Customize {
            expose_oneof: None,
            expose_fields: None,
            generate_accessors: None,
            carllerche_bytes_for_bytes: Some(true),
            carllerche_bytes_for_string: None,
            serde_derive: None,
            serde_derive_cfg: None,
            serde_rename_all: None,
            lite_runtime: None,
            gen_mod_rs: None,
            inside_protobuf: None,
            _future_options: (),
        })
        .inputs(&["src/config/geoip.proto", "src/config/geosite.proto"])
        .include(".")
        .out_dir("src/config/")
        .run()
        .expect("protoc");
}
