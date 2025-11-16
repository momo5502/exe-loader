use std::env;
use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_dir = out_dir.ancestors().nth(3).unwrap();

    let tls_lib = target_dir.join("tls_lib.dll");
    println!("cargo:rustc-env=TLS_LIB_FILE={}", tls_lib.display());
}
