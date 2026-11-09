use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

fn collect_files(directory: &Path, root: &Path, files: &mut BTreeSet<String>) {
    for entry in fs::read_dir(directory).expect("read vendor directory") {
        let entry = entry.expect("read vendor directory entry");
        let path = entry.path();
        if path.is_dir() {
            collect_files(&path, root, files);
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("vendor file is beneath crate root")
                .to_str()
                .expect("vendor file path is UTF-8")
                .replace('\\', "/");
            files.insert(relative);
        }
    }
}

#[test]
fn vendored_files_match_the_sha256_manifest() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest_path = root.join("vendor/SHA256SUMS");
    let manifest = fs::read_to_string(&manifest_path).expect("read vendor checksum manifest");
    let mut expected = BTreeMap::new();

    for line in manifest.lines() {
        let (digest, relative_path) = line
            .split_once("  ")
            .expect("checksum line has two-space separator");
        assert_eq!(
            digest.len(),
            64,
            "invalid SHA-256 digest for {relative_path}"
        );

        let relative_path = Path::new(relative_path);
        assert!(
            relative_path
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "manifest path must be relative and traversal-free: {relative_path:?}"
        );
        assert!(
            relative_path.starts_with("vendor"),
            "manifest path must be beneath vendor/: {relative_path:?}"
        );

        let full_path = root.join(relative_path);
        let actual = format!(
            "{:x}",
            Sha256::digest(fs::read(&full_path).expect("read vendored file"))
        );
        assert_eq!(
            actual,
            digest,
            "checksum mismatch for {}",
            relative_path.display()
        );
        assert!(
            expected
                .insert(relative_path.to_string_lossy().replace('\\', "/"), digest)
                .is_none(),
            "duplicate manifest entry: {}",
            relative_path.display()
        );
    }

    let vendor_root = root.join("vendor");
    let mut actual = BTreeSet::new();
    collect_files(&vendor_root, &root, &mut actual);
    actual.remove("vendor/SHA256SUMS");

    assert_eq!(
        expected.keys().cloned().collect::<BTreeSet<_>>(),
        actual,
        "manifest must cover every vendored file except itself"
    );
}
