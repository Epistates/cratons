//! Integration tests for the malicious-archive attack surface in
//! [`cratons_installer::PackageExtractor`].
//!
//! These tests are the regression suite for the Phase 2 fixes in the
//! security hardening plan (H-2 hard-link validation/materialization,
//! L-1 deeply-nested-path containment, the symlink-then-hardlink
//! cross-entry attack). They build tarballs in-memory (no on-disk
//! fixtures) so the test corpus is readable in the same file that
//! documents the attacks.
//!
//! Each test drives the real public API —
//! `PackageExtractor::new().extract(&archive_path, ecosystem, &store)` —
//! so the assertions cover the whole extraction pipeline, not just the
//! validator helpers in isolation.

use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

use cratons_core::Ecosystem;
use cratons_installer::PackageExtractor;
use cratons_store::Store;
use flate2::Compression;
use flate2::write::GzEncoder;
use tar::{Builder, EntryType, Header};
use tempfile::TempDir;

/// Convenience: build an npm-style tarball (`package/...` prefix) from an
/// ordered list of entries and write it to `path`. Entry ordering matches
/// extraction order, which matters for hard-link tests (the target must
/// appear before any link that references it).
fn write_tarball(path: &Path, entries: &[Entry]) {
    let file = File::create(path).expect("create tarball file");
    let gz = GzEncoder::new(file, Compression::default());
    let mut builder = Builder::new(gz);
    builder.mode(tar::HeaderMode::Deterministic);

    for entry in entries {
        match entry {
            Entry::File { name, data } => {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Regular);
                header.set_size(data.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_data(&mut header, name, Cursor::new(data.clone()))
                    .expect("append file");
            }
            Entry::Symlink { name, target } => {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Symlink);
                header.set_size(0);
                header.set_mode(0o777);
                header.set_cksum();
                builder
                    .append_link(&mut header, name, target)
                    .expect("append symlink");
            }
            Entry::HardLink { name, target } => {
                let mut header = Header::new_gnu();
                header.set_entry_type(EntryType::Link);
                header.set_size(0);
                header.set_mode(0o644);
                header.set_cksum();
                builder
                    .append_link(&mut header, name, target)
                    .expect("append hardlink");
            }
        }
    }

    let gz = builder.into_inner().expect("finish tar");
    let mut file = gz.finish().expect("finish gz");
    file.flush().expect("flush");
}

/// In-memory description of a tarball entry. Paths are relative (no
/// `package/` prefix required — callers include it when building npm
/// fixtures).
enum Entry {
    File { name: String, data: Vec<u8> },
    Symlink { name: String, target: String },
    HardLink { name: String, target: String },
}

impl Entry {
    fn file(name: &str, data: &[u8]) -> Self {
        Self::File {
            name: name.to_string(),
            data: data.to_vec(),
        }
    }
    fn symlink(name: &str, target: &str) -> Self {
        Self::Symlink {
            name: name.to_string(),
            target: target.to_string(),
        }
    }
    fn hard_link(name: &str, target: &str) -> Self {
        Self::HardLink {
            name: name.to_string(),
            target: target.to_string(),
        }
    }
}

/// Build a fresh Store rooted in a temp dir and return both the store and
/// the TempDir (keep the TempDir alive for the lifetime of the test).
fn fresh_store() -> (TempDir, Store) {
    let dir = TempDir::new().expect("tempdir");
    let store = Store::open(dir.path()).expect("open store");
    (dir, store)
}

/// Write an npm-flavored tarball into a temp file and return its path.
/// All entries are prefixed with `package/` to match npm tarball layout.
fn write_npm_tarball(entries: &[Entry]) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("pkg.tgz");

    // `name` gets the archive prefix; `target` is written verbatim. Hard-link
    // targets in this test suite are expressed relative to the extracted
    // root (i.e. after the prefix has been stripped by the extractor), which
    // matches how `validate_hard_link_target_ctx` resolves them.
    let mut prefixed: Vec<Entry> = Vec::with_capacity(entries.len());
    for e in entries {
        match e {
            Entry::File { name, data } => prefixed.push(Entry::File {
                name: format!("package/{}", name),
                data: data.clone(),
            }),
            Entry::Symlink { name, target } => prefixed.push(Entry::Symlink {
                name: format!("package/{}", name),
                target: target.clone(),
            }),
            Entry::HardLink { name, target } => prefixed.push(Entry::HardLink {
                name: format!("package/{}", name),
                target: target.clone(),
            }),
        }
    }
    write_tarball(&path, &prefixed);
    (dir, path)
}

/// Write a Rust .crate tarball (top-level `{name}-{version}/` prefix).
fn write_crate_tarball(entries: &[Entry]) -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("pkg.crate");

    let mut prefixed: Vec<Entry> = Vec::with_capacity(entries.len());
    for e in entries {
        match e {
            Entry::File { name, data } => prefixed.push(Entry::File {
                name: format!("pkg-0.1.0/{}", name),
                data: data.clone(),
            }),
            Entry::Symlink { name, target } => prefixed.push(Entry::Symlink {
                name: format!("pkg-0.1.0/{}", name),
                target: target.clone(),
            }),
            Entry::HardLink { name, target } => prefixed.push(Entry::HardLink {
                name: format!("pkg-0.1.0/{}", name),
                target: target.clone(),
            }),
        }
    }
    write_tarball(&path, &prefixed);
    (dir, path)
}

// --- H-2: hard link escape rejection (npm) ----------------------------------

#[test]
fn hard_link_traversal_rejected_npm() {
    let (_src, tarball) = write_npm_tarball(&[
        Entry::file("legit.txt", b"legit"),
        // Absolute target — must be rejected outright.
        Entry::hard_link("evil.txt", "/etc/passwd"),
    ]);
    let (_store_dir, store) = fresh_store();
    let err = PackageExtractor::new()
        .extract(&tarball, Ecosystem::Npm, &store)
        .expect_err("malicious hardlink must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("Hard link")
            || msg.contains("hard link")
            || msg.contains("Absolute"),
        "expected hard-link rejection, got: {msg}"
    );
}

#[test]
fn hard_link_parent_dir_rejected_npm() {
    let (_src, tarball) = write_npm_tarball(&[
        Entry::file("legit.txt", b"legit"),
        // `..` would walk out of canonical_dest.
        Entry::hard_link("evil.txt", "../../../../../../etc/passwd"),
    ]);
    let (_store_dir, store) = fresh_store();
    let err = PackageExtractor::new()
        .extract(&tarball, Ecosystem::Npm, &store)
        .expect_err("`..` in hardlink target must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("'..'") || msg.contains("escapes"),
        "expected parent-dir rejection, got: {msg}"
    );
}

#[test]
fn hard_link_to_nonexistent_rejected_npm() {
    // Link references a sibling entry that was never included in the archive.
    // POSIX ustar guarantees source-before-link order for valid archives; a
    // dangling link indicates malformed input or a malicious construct.
    let (_src, tarball) = write_npm_tarball(&[
        // Note: the hard link appears before its (missing) target.
        Entry::hard_link("evil.txt", "nonexistent.txt"),
    ]);
    let (_store_dir, store) = fresh_store();
    let err = PackageExtractor::new()
        .extract(&tarball, Ecosystem::Npm, &store)
        .expect_err("hardlink to nonexistent entry must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("does not exist") || msg.contains("Hard link"),
        "expected nonexistent-target rejection, got: {msg}"
    );
}

#[cfg(unix)]
#[test]
fn hard_link_created_when_valid_npm() {
    use std::os::unix::fs::MetadataExt;

    // Legitimate case: file A, then a hard link B pointing at A. The
    // extractor must *actually materialize* the link (not silently drop it
    // like the pre-Phase-2 code).
    let (_src, tarball) = write_npm_tarball(&[
        Entry::file("a.txt", b"payload"),
        Entry::hard_link("b.txt", "a.txt"),
    ]);
    let (_store_dir, store) = fresh_store();
    let extracted = PackageExtractor::new()
        .extract(&tarball, Ecosystem::Npm, &store)
        .expect("legitimate hardlink must succeed");

    let a = extracted.join("a.txt");
    let b = extracted.join("b.txt");
    assert!(a.exists(), "target file not extracted");
    assert!(b.exists(), "hard link was silently dropped");

    let md_a = fs::metadata(&a).unwrap();
    let md_b = fs::metadata(&b).unwrap();
    assert_eq!(
        md_a.ino(),
        md_b.ino(),
        "hard link does not share an inode with its target (was it materialized as a copy?)"
    );
    assert!(
        md_a.nlink() >= 2,
        "nlink < 2 for target after hardlink materialization"
    );
    assert_eq!(fs::read(&b).unwrap(), b"payload");
}

// --- H-2 extended to .crate archives ----------------------------------------

#[test]
fn hard_link_traversal_rejected_crate() {
    let (_src, tarball) = write_crate_tarball(&[
        Entry::file("src/lib.rs", b"// legit"),
        Entry::hard_link("src/evil.rs", "/etc/passwd"),
    ]);
    let (_store_dir, store) = fresh_store();
    let err = PackageExtractor::new()
        .extract(&tarball, Ecosystem::Crates, &store)
        .expect_err("crate hardlink traversal must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("Hard link") || msg.contains("Absolute"),
        "expected hard-link rejection for .crate, got: {msg}"
    );
}

// --- Cross-entry attack: symlink then hardlink ------------------------------

#[cfg(unix)]
#[test]
fn absolute_symlink_rejected_before_hardlink_runs() {
    // A malicious tarball that tries to plant an absolute symlink as a
    // first step (`escape -> /tmp`) must fail fast at the symlink validator
    // — before any subsequent entry can attempt to walk through it. This
    // is the first line of defense in the symlink-then-hardlink class of
    // attacks. The canonical_dest-based containment of hard links is the
    // second line; see `hard_link_parent_dir_rejected_npm` for that.
    let (_src, tarball) = write_npm_tarball(&[
        Entry::symlink("escape", "/tmp"),
        Entry::file("a.txt", b"legit"),
        Entry::hard_link("victim", "escape/whatever"),
    ]);
    let (_store_dir, store) = fresh_store();
    let err = PackageExtractor::new()
        .extract(&tarball, Ecosystem::Npm, &store)
        .expect_err("absolute symlink target must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("Absolute symlink")
            || msg.contains("symlink")
            || msg.contains("escapes"),
        "expected symlink rejection, got: {msg}"
    );
}

// --- L-1: deeply nested new paths ------------------------------------------

#[test]
fn deeply_nested_new_path_accepted_when_contained() {
    // A legitimate deep path with many new intermediate directories must
    // still extract. The pre-Phase-2 code had a non-canonical fallback for
    // this case; we retain the legitimate-path behavior while closing the
    // containment hole.
    let (_src, tarball) = write_npm_tarball(&[Entry::file("a/b/c/d/e/f/g/file.txt", b"ok")]);
    let (_store_dir, store) = fresh_store();
    let extracted = PackageExtractor::new()
        .extract(&tarball, Ecosystem::Npm, &store)
        .expect("deeply-nested legitimate path must extract");
    assert!(extracted.join("a/b/c/d/e/f/g/file.txt").exists());
}
