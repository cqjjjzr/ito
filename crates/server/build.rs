//! Embeds the built frontend assets from `web/dist` into the server binary.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn main() {
    let dist = Path::new("../../web/dist");
    // Ensure `web/dist` exists so `cargo::rerun-if-changed` does not force a rebuild on every
    // invocation when the frontend has not been built.
    fs::create_dir_all(dist).expect("web/dist is creatable");
    println!("cargo::rerun-if-changed=../../web/dist");
    let mut files = Vec::new();
    collect_files(dist, &mut files);
    let entries: String = files
        .iter()
        .map(|path| {
            let name = path.strip_prefix(dist).ok().and_then(Path::to_str);
            let name = name.expect("UTF-8 path inside dist");
            let full = fs::canonicalize(path).expect("readable file");
            format!("({name:?}, include_bytes!({full:?})),\n")
        })
        .collect();
    let out = Path::new(&env::var("OUT_DIR").expect("set by cargo")).join("web_files.rs");
    fs::write(out, format!("&[{entries}]")).expect("writable OUT_DIR");
}

fn collect_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable directory") {
        let path = entry.expect("readable entry").path();
        if path.is_dir() {
            collect_files(&path, files);
        } else {
            files.push(path);
        }
    }
}
