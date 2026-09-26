//! Stage the libFuzzer seed corpus before the fuzz target builds.
//!
//! Copies `tests/fixtures/*.bin` into `fuzz/corpus/decode_program/`,
//! `fuzz/corpus/verify_pipeline/`, and `fuzz/corpus/ssa_pipeline/` so
//! the corpus is always fresh without being committed (the corpus dir is
//! gitignored). Re-runs only when the fixtures change, via
//! `rerun-if-changed` — the same pattern as protobuf codegen in
//! `build.rs`.
//!
//! Only `*.bin` copies are refreshed; fuzzer-discovered inputs in the
//! corpus dir are never deleted.

use std::path::PathBuf;

fn sync_dir(src: &std::path::Path, dst: &PathBuf) {
    if let Err(e) = std::fs::create_dir_all(dst) {
        println!("cargo:warning=sync-corpus: cannot create {}: {e}", dst.display());
        return;
    }

    let mut wanted = std::collections::HashSet::new();
    let entries = match std::fs::read_dir(src) {
        Ok(entries) => entries,
        Err(e) => {
            println!(
                "cargo:warning=sync-corpus: cannot read {}: {e}; fuzzing unseeded",
                src.display()
            );
            return;
        }
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "bin") {
            let name = path.file_name().expect("fixture has a file name");
            wanted.insert(name.to_os_string());
            if let Err(e) = std::fs::copy(&path, dst.join(name)) {
                println!("cargo:warning=sync-corpus: cannot copy {}: {e}", path.display());
            }
        }
    }
    // Drop stale copies (renamed/deleted fixtures); leave fuzzer-found inputs.
    if let Ok(dst_entries) = std::fs::read_dir(dst) {
        for entry in dst_entries.flatten() {
            let path = entry.path();
            let stale = path.extension().is_some_and(|e| e == "bin")
                && path.file_name().is_some_and(|n| !wanted.contains(n));
            if stale {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

fn main() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let src = manifest.join("../tests/fixtures");

    // Re-run when fixtures change: per-file directives catch content edits,
    // the directory directive catches added/removed fixtures.
    println!("cargo:rerun-if-changed={}", src.display());
    for target in ["decode_program", "verify_pipeline", "ssa_pipeline"] {
        sync_dir(&src, &manifest.join("corpus").join(target));
    }
}
