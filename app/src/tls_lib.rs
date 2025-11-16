use std::{io::Write, path::PathBuf};
use tempfile::NamedTempFile;

const TLS_DLL: &[u8] = include_bytes!(concat!(env!("TLS_LIB_FILE")));

pub fn create_tls_lib() -> PathBuf {
    let mut file = NamedTempFile::new().unwrap();
    let path = file.path().to_path_buf();
    file.write_all(TLS_DLL).unwrap();
    file.persist(&path).unwrap();

    return path;
}
