//! Generates Rust protobuf/gRPC bindings for `agentic.v1`.
//!
//! Uses the vendored `protoc` binary so builds work in the Docker image without
//! a system protobuf compiler.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path()?;
        // Safe: build scripts are single-threaded before compilation starts.
        std::env::set_var("PROTOC", protoc);
    }

    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../proto");
    let cognitive_proto = proto_root.join("agentic/v1/cognitive.proto");
    let task_proto = proto_root.join("agentic/v1/task_service.proto");

    println!("cargo:rerun-if-changed={}", cognitive_proto.display());
    println!("cargo:rerun-if-changed={}", task_proto.display());

    let includes = [proto_root, protoc_bin_vendored::include_path()?];

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&[cognitive_proto, task_proto], &includes)?;

    Ok(())
}
