use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let target_path = out_path.join("../../..");
    let target_triple = env::var("TARGET").unwrap();

    // macOS or iOS, inherited from rpgp
    let libs_priv = if target_triple.contains("apple") || target_triple.contains("darwin") {
        // needed for OsRng
        "-framework Security -framework Foundation"
    } else {
        ""
    };

    let pkg_config = format!(
        include_str!("deltachat.pc.in"),
        name = "deltachat",
        description = env::var("CARGO_PKG_DESCRIPTION").unwrap(),
        url = env::var("CARGO_PKG_HOMEPAGE").unwrap_or_else(|_| "".to_string()),
        version = env::var("CARGO_PKG_VERSION").unwrap(),
        libs_priv = libs_priv,
        prefix = option_env!("PREFIX").unwrap_or_else(|| "/usr/local"),
        libdir = option_env!("LIBDIR").unwrap_or_else(|| "/usr/local/lib"),
        includedir = option_env!("INCLUDEDIR").unwrap_or_else(|| "/usr/local/include"),
    );

    fs::create_dir_all(target_path.join("pkgconfig")).unwrap();
    fs::write(
        target_path.join("pkgconfig").join("deltachat.pc"),
        pkg_config.as_bytes(),
    )
    .unwrap();
}
