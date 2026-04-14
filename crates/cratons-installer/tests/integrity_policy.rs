//! End-to-end integration tests for `IntegrityPolicy` enforcement.
//!
//! These exercise the Phase 4 `enforce_integrity_policy` path through the
//! real `Installer::install` API: we construct a tiny in-memory lockfile
//! with one package whose `integrity` field is empty, open a fresh store
//! in a temp directory, and assert the installer's behavior under every
//! policy × ecosystem combination that matters.
//!
//! We never actually hit the network: `install_ecosystem` runs its
//! `enforce_integrity_policy` gate before touching `download_and_extract`,
//! so an empty-integrity package either errors synchronously (Required) or
//! succeeds with a warning (allowlisted) before any I/O attempt.

use std::path::PathBuf;

use cratons_core::{ContentHash, Ecosystem};
use cratons_installer::{Installer, InstallerConfig, IntegrityPolicy};
use cratons_lockfile::{DependencyRef, LockedPackage, Lockfile};
use cratons_store::Store;
use tempfile::TempDir;

/// Build a one-package lockfile where the only package has empty integrity.
/// `ecosystem` controls which ecosystem the package belongs to.
fn lockfile_with_empty_integrity(ecosystem: Ecosystem) -> Lockfile {
    let manifest_hash = ContentHash::blake3("test-manifest-hash".to_string());
    let mut lockfile = Lockfile::new(manifest_hash);

    let pkg = LockedPackage {
        name: "test-package".to_string(),
        version: "1.0.0".to_string(),
        ecosystem,
        source: "https://example.invalid/test-package-1.0.0.tgz".to_string(),
        // Intentionally empty — this is the condition under test.
        integrity: String::new(),
        resolved_hash: ContentHash::blake3(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        direct: true,
        features: Vec::new(),
        dependencies: Vec::<DependencyRef>::new(),
    };
    lockfile.packages.push(pkg);
    lockfile
}

/// Convenience: build an Installer with the given integrity policy. Sandbox
/// policy is forced to `Disabled` so we never try to invoke a real sandbox
/// backend during tests (which might not exist on the CI host).
fn installer_config(integrity_policy: IntegrityPolicy) -> InstallerConfig {
    InstallerConfig {
        integrity_policy,
        sandbox_policy: cratons_installer::SandboxPolicy::Disabled,
        run_scripts: false,
        ..InstallerConfig::default()
    }
}

fn fresh_store() -> (TempDir, Store) {
    let dir = TempDir::new().expect("tempdir");
    let store = Store::open(dir.path()).expect("open store");
    (dir, store)
}

#[tokio::test]
async fn required_policy_rejects_empty_integrity_for_npm() {
    let lockfile = lockfile_with_empty_integrity(Ecosystem::Npm);
    let (_store_dir, store) = fresh_store();
    let project = TempDir::new().unwrap();

    let installer = Installer::with_config(&store, installer_config(IntegrityPolicy::Required));
    let err = installer
        .install(&lockfile, project.path())
        .await
        .expect_err("Required + empty integrity must abort the install");

    let msg = err.to_string();
    assert!(
        msg.contains("test-package")
            && (msg.contains("Checksum mismatch") || msg.contains("checksum") || msg.contains("integrity")),
        "expected checksum-mismatch-style error, got: {msg}"
    );
}

#[tokio::test]
async fn required_policy_rejects_empty_integrity_for_go() {
    // `Required` overrides the default Go allowlist: even Go must have
    // integrity when the operator opts into strict mode.
    let lockfile = lockfile_with_empty_integrity(Ecosystem::Go);
    let (_store_dir, store) = fresh_store();
    let project = TempDir::new().unwrap();

    let installer = Installer::with_config(&store, installer_config(IntegrityPolicy::Required));
    let err = installer
        .install(&lockfile, project.path())
        .await
        .expect_err("Required + Go + empty integrity must abort");

    assert!(err.to_string().contains("test-package"));
}

#[tokio::test]
async fn default_policy_rejects_empty_integrity_for_every_ecosystem() {
    // Post-F-final: the default is `Required`, which rejects empty
    // integrity for ALL ecosystems including Go and Maven (both of
    // which now deliver real integrity via F-1 sum.golang.org and F-2
    // Maven PGP verification).
    for ecosystem in [
        Ecosystem::Npm,
        Ecosystem::PyPi,
        Ecosystem::Crates,
        Ecosystem::Go,
        Ecosystem::Maven,
    ] {
        let lockfile = lockfile_with_empty_integrity(ecosystem);
        let (_store_dir, store) = fresh_store();
        let project = TempDir::new().unwrap();
        let installer =
            Installer::with_config(&store, installer_config(IntegrityPolicy::default()));
        let err = installer.install(&lockfile, project.path()).await;
        assert!(
            err.is_err(),
            "default policy must reject empty integrity for {:?}",
            ecosystem
        );
    }
}

#[tokio::test]
async fn skip_policy_tolerates_empty_integrity_but_then_errors_on_missing_source() {
    // Skip policy means the integrity gate lets the package through. The
    // install will then fail at network-fetch time (because our fixture URL
    // is invalid), but the failure mode must NOT be an integrity error —
    // it must be a network/source error. This proves Skip reaches the
    // downloader.
    let lockfile = lockfile_with_empty_integrity(Ecosystem::Npm);
    let (_store_dir, store) = fresh_store();
    let project = TempDir::new().unwrap();

    let installer = Installer::with_config(&store, installer_config(IntegrityPolicy::Skip));
    let result = installer.install(&lockfile, project.path()).await;

    match result {
        Err(e) => {
            let msg = e.to_string();
            // Must NOT be a checksum/integrity error — the integrity gate
            // was bypassed. Any other failure (Network, HTTP, resolver) is
            // acceptable because the test fixture URL is intentionally
            // unreachable.
            assert!(
                !msg.contains("integrity") && !msg.contains("Checksum mismatch"),
                "Skip policy still produced an integrity error: {msg}"
            );
        }
        Ok(_) => {
            // If it somehow succeeded (e.g. stubbed network), that's fine —
            // it just means the gate didn't stop it.
        }
    }
}

#[test]
fn integrity_policy_default_is_strict_for_every_ecosystem() {
    // Regression guard: the default is `Required` for every ecosystem
    // post-F-final. Any change (such as a future allowlist reinstatement)
    // must be a deliberate security decision documented in CHANGELOG and
    // `docs/security-followups.md`.
    let default = IntegrityPolicy::default();
    for eco in [
        Ecosystem::Npm,
        Ecosystem::PyPi,
        Ecosystem::Crates,
        Ecosystem::Go,
        Ecosystem::Maven,
        Ecosystem::Url,
    ] {
        assert!(
            !default.allows_empty_integrity(eco),
            "default policy must not allowlist {:?}",
            eco
        );
    }

    // `Url` dependencies are handled entirely outside `install_ecosystem`
    // today, but keep the assertion for future-proofing.
    let _unused_dir = PathBuf::from("/");
}
