use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=DOCS_RS");
    if env::var_os("DOCS_RS").is_some() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("manifest dir"));
    let capi_dir = manifest_dir.join("capi");

    println!("cargo:rerun-if-env-changed=BICYCL_SOURCE_DIR");
    let bicycl_source_dir = env::var("BICYCL_SOURCE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("vendor").join("bicycl"));

    println!("cargo:rerun-if-changed={}", capi_dir.display());
    println!("cargo:rerun-if-changed={}", bicycl_source_dir.display());

    let dst = cmake::Config::new(&capi_dir)
        .profile("Release")
        .define("BICYCL_SOURCE_DIR", &bicycl_source_dir)
        .build();

    println!(
        "cargo:rustc-link-search=native={}",
        dst.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=bicycl_capi");

    // C++ runtime
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    match (target_os.as_str(), target_env.as_str()) {
        ("macos", _) => println!("cargo:rustc-link-lib=dylib=c++"),
        ("windows", "gnu") => println!("cargo:rustc-link-lib=dylib=stdc++"),
        ("windows", _) => {}
        _ => println!("cargo:rustc-link-lib=dylib=stdc++"),
    }

    println!("cargo:rustc-link-lib=dylib=gmpxx");
    println!("cargo:rustc-link-lib=dylib=gmp");
    println!("cargo:rustc-link-lib=dylib=crypto");
}
