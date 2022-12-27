fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .compile_protos(&["proto/cve_api.proto"], &["proto/"])
        .unwrap();
    Ok(())
}
