use protobuf_codegen::Customize;

fn main() {
    println!("cargo:rerun-if-changed=src/config/geosite.proto");
    println!("cargo:rerun-if-changed=src/config/geoip.proto");
    println!("cargo:rerun-if-changed=src/api/api.proto");
    tonic_build::configure()
        .build_client(false)
        .compile(&["src/api/api.proto"], &["src/api/"])
        .unwrap();
    //tonic_build::compile_protos("src/api/api.proto").unwrap();
    let customize = Customize::default()
        .gen_mod_rs(false)
        .tokio_bytes(true)
        .generate_getter(true);
    protobuf_codegen::Codegen::new()
        .out_dir("src/")
        .customize(customize)
        .inputs(&["src/config/geoip.proto", "src/config/geosite.proto"])
        .include(".")
        .out_dir("src/config/")
        .run()
        .expect("protoc");
}
