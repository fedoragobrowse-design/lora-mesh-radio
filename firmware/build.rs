//! This build script copies `memory.x` into the linker search path and
//! passes the RP235x secure-ARM link arguments (matches the official
//! embassy-rp rp235x example structure, not RP2040 boot2).
//!
//! The firmware FLASH region is capped at the sequential-storage start
//! (top 64 KiB retained); cortex-m-rt supplies `link.x`/vector table.
//! embassy-rp supplies the default secure-executable ImageDef in
//! `.start_block`, so a single core runs in secure ARM state.

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    // Put `memory.x` in our output directory and ensure it's
    // on the linker search path.
    let out = &PathBuf::from(env::var_os("OUT_DIR").unwrap());
    File::create(out.join("memory.x"))
        .unwrap()
        .write_all(include_bytes!("memory.x"))
        .unwrap();
    println!("cargo:rustc-link-search={}", out.display());

    // By default, Cargo will re-run a build script whenever
    // any file in the project changes. By specifying `memory.x`
    // here, we ensure the build script is only re-run when
    // `memory.x` is changed.
    println!("cargo:rerun-if-changed=memory.x");

    println!("cargo:rustc-link-arg-bins=--nmagic");
    println!("cargo:rustc-link-arg-bins=-Tlink.x");
}
