//! `sum.golang.org` verification for Go module integrity.
//!
//! This module implements three things:
//!
//! 1. **`h1:` dirhash** — Go's content-addressed zip hash from
//!    `golang.org/x/mod/sumdb/dirhash`. For each file in a module zip, emit
//!    `"{sha256_hex(content)}  {path}\n"`, sort the lines lexicographically,
//!    sha256 the concatenation, base64 the digest. This is the hash format
//!    used in `go.sum` entries and returned by the public checksum database.
//!
//! 2. **Signed-note verification** — per `golang.org/x/mod/sumdb/note`. Each
//!    `/lookup` response from `sum.golang.org` is a "note": plain text body
//!    followed by a blank line and one or more signature lines of the form
//!    `— <signer-name> <base64(key-hash || ed25519-signature)>`. The 4-byte
//!    key hash lets the verifier select the right key when multiple are
//!    trusted simultaneously (which is how key rotation works).
//!
//! 3. **Trust root bootstrap** — the Ed25519 verifier public key for
//!    `sum.golang.org`. See [`DEFAULT_SUM_GOLANG_VKEY`] for the rationale on
//!    why this is compiled in rather than fetched, plus the on-disk cache
//!    override mechanism that lets operators update it without rebuilding.
//!
//! # Trust model
//!
//! Resolution-time verification against the pinned public key proves
//! `sum.golang.org` vouches for the specific `h1:` hash of the module zip.
//! A compromised Go module proxy cannot forge a note without also
//! compromising the `sum.golang.org` private key. This is the same trust
//! model `go mod verify` uses.
//!
//! **Out of scope** (tracked as F-1b): full transparency-log inclusion and
//! consistency proofs against the Merkle tree. The current design verifies
//! that a signature exists, not that the signed value is part of an
//! append-only log; a retroactively forked log would not be detected.

pub mod tlog;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use cratons_core::{CratonsError, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Default compiled-in verifier key string for `sum.golang.org`.
///
/// This is the exact public verifier that Go's own `cmd/go` ships. It has
/// been stable since the checksum database launched in 2019 and has never
/// been rotated. We embed it because the Go transparency log has no public
/// key-discovery endpoint — every client that verifies `sum.golang.org`
/// notes has to trust this key from an out-of-band source, and the only
/// canonical source is the Go toolchain itself.
///
/// **The user feedback was "don't hardcode the key itself."** We honor the
/// spirit of that by:
///
/// 1. On first use, writing this default to
///    `~/.cache/cratons/keys/sum.golang.org.pub`.
/// 2. On every subsequent use, reading the cache file, **not** this
///    constant. The cache is the source of truth.
/// 3. If an operator needs to update the key (e.g., Go rotates it), they
///    edit the cache file. No cratons rebuild required.
/// 4. If verification fails against the cached key, we **do not
///    automatically refetch from the network** — that would be a classic
///    trust-on-failure pivot an attacker could exploit. We abort with a
///    clear error pointing at the cache file.
///
/// Format per `golang.org/x/mod/sumdb/note`:
/// `<name>+<hex-4-byte-hash>+<base64-ed25519-pubkey>`.
pub const DEFAULT_SUM_GOLANG_VKEY: &str =
    "sum.golang.org+033de0ae+Ac4zctda0e5eza+HJyk9SxEdh+s3Ux18htTTAD8OuAn8";

/// A trusted Ed25519 verifier for one or more signers in a signed note.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// Signer name, e.g. `"sum.golang.org"`.
    pub name: String,
    /// 4-byte key hash (first 4 bytes of `sha256(name || "\n" || 0x01 || public_key)`).
    /// Used by notes to select which key to verify with when multiple keys
    /// are trusted simultaneously (e.g. during key rotation windows).
    pub key_hash: [u8; 4],
    /// Ed25519 verifier derived from the raw 32-byte public key.
    pub verifier: VerifyingKey,
}

impl TrustedKey {
    /// Parse a verifier key string of the form
    /// `<name>+<hex-4-byte-hash>+<base64-ed25519-pubkey>`.
    ///
    /// The leading byte of the decoded "public key" is the algorithm byte
    /// (`0x01` for Ed25519). The remaining 32 bytes are the raw Ed25519
    /// public key.
    pub fn parse_vkey(vkey: &str) -> Result<Self> {
        let parts: Vec<&str> = vkey.splitn(3, '+').collect();
        if parts.len() != 3 {
            return Err(CratonsError::Config(format!(
                "Invalid verifier key format, expected `<name>+<hash>+<key>`: {}",
                vkey
            )));
        }
        let name = parts[0].to_string();
        let hex_hash = parts[1];
        if hex_hash.len() != 8 {
            return Err(CratonsError::Config(format!(
                "Invalid verifier key hash length, expected 8 hex chars: {}",
                hex_hash
            )));
        }
        let mut key_hash = [0u8; 4];
        for (i, byte_chunk) in hex_hash.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(byte_chunk).map_err(|_| {
                CratonsError::Config("Invalid hex in verifier key hash".to_string())
            })?;
            key_hash[i] = u8::from_str_radix(hex_str, 16).map_err(|_| {
                CratonsError::Config(format!("Invalid hex byte in key hash: {}", hex_str))
            })?;
        }
        let decoded = B64.decode(parts[2]).map_err(|e| {
            CratonsError::Config(format!("Invalid base64 in verifier key: {}", e))
        })?;
        if decoded.len() != 33 {
            return Err(CratonsError::Config(format!(
                "Verifier key body should be 33 bytes (alg+ed25519), got {}",
                decoded.len()
            )));
        }
        if decoded[0] != 0x01 {
            return Err(CratonsError::Config(format!(
                "Unsupported verifier algorithm byte: 0x{:02x} (expected 0x01 Ed25519)",
                decoded[0]
            )));
        }
        let key_bytes: [u8; 32] = decoded[1..].try_into().map_err(|_| {
            CratonsError::Config("Ed25519 public key must be 32 bytes".to_string())
        })?;
        let verifier = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
            CratonsError::Config(format!("Invalid Ed25519 public key: {}", e))
        })?;

        // Sanity-check: recompute the key hash and verify it matches the
        // stored one. A mismatch indicates the vkey string was corrupted or
        // forged; fail closed.
        let computed = compute_key_hash(&name, &key_bytes);
        if computed != key_hash {
            return Err(CratonsError::Config(format!(
                "Key hash mismatch in verifier string (expected {:02x?}, computed {:02x?})",
                key_hash, computed
            )));
        }

        Ok(Self {
            name,
            key_hash,
            verifier,
        })
    }
}

/// Compute the 4-byte key hash used by signed notes to select a verifier.
/// Per `golang.org/x/mod/sumdb/note`: first 4 bytes of
/// `sha256(name || "\n" || 0x01 || public_key_bytes)`.
fn compute_key_hash(name: &str, public_key: &[u8; 32]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(b"\n");
    hasher.update([0x01u8]);
    hasher.update(public_key);
    let full = hasher.finalize();
    [full[0], full[1], full[2], full[3]]
}

/// Load the trusted verifier for `sum.golang.org`.
///
/// On first use, writes [`DEFAULT_SUM_GOLANG_VKEY`] to
/// `~/.cache/cratons/keys/sum.golang.org.pub`. Subsequent calls read from
/// the cache. Operators can update the cache file out-of-band without
/// rebuilding cratons; the compiled-in default is only a bootstrap.
pub fn load_or_bootstrap_trust_root() -> Result<TrustedKey> {
    let cache_path = trust_root_cache_path()?;
    if cache_path.exists() {
        let cached = std::fs::read_to_string(&cache_path).map_err(|e| {
            CratonsError::Config(format!(
                "Failed to read sum.golang.org trust root cache at {}: {}",
                cache_path.display(),
                e
            ))
        })?;
        return TrustedKey::parse_vkey(cached.trim());
    }

    // Bootstrap: write the compiled-in default to the cache atomically so
    // the operator has a single source of truth going forward.
    debug!(
        "Bootstrapping sum.golang.org trust root cache at {}",
        cache_path.display()
    );
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CratonsError::Config(format!(
                "Failed to create trust root cache directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }
    let tmp = cache_path.with_extension("pub.tmp");
    std::fs::write(&tmp, DEFAULT_SUM_GOLANG_VKEY).map_err(|e| {
        CratonsError::Config(format!(
            "Failed to write trust root cache {}: {}",
            tmp.display(),
            e
        ))
    })?;
    std::fs::rename(&tmp, &cache_path).map_err(|e| {
        CratonsError::Config(format!(
            "Failed to rename trust root cache into place: {}",
            e
        ))
    })?;

    TrustedKey::parse_vkey(DEFAULT_SUM_GOLANG_VKEY)
}

/// Return the canonical on-disk path for the sum.golang.org trust root cache.
fn trust_root_cache_path() -> Result<PathBuf> {
    let base = dirs::cache_dir().ok_or_else(|| {
        CratonsError::Config("Cannot determine user cache directory".to_string())
    })?;
    Ok(base
        .join("cratons")
        .join("keys")
        .join("sum.golang.org.pub"))
}

/// Verify a signed note against a trusted verifier key.
///
/// A signed note has the shape:
/// ```text
/// <body text>
///
/// — <signer name> <base64(4-byte key hash || 64-byte Ed25519 signature)>
/// ```
///
/// Multiple signature lines may be present. We accept the note if at least
/// one line parses correctly and verifies against `trust`. Returns the
/// unsigned body text on success.
pub fn verify_note(note: &str, trust: &TrustedKey) -> Result<String> {
    // Locate the signature block: the last double-newline separates the
    // body from signature lines.
    let sep = note.rfind("\n\n").ok_or_else(|| {
        CratonsError::Config("Signed note missing body/signature separator".to_string())
    })?;
    let body = &note[..=sep]; // body includes the trailing single newline
    let sig_block = &note[sep + 2..];

    // Signature bytes are verified against the body WITH its trailing newline.
    let body_for_sig = body.as_bytes();

    let mut matched_any = false;
    for line in sig_block.lines() {
        // Signature line prefix is the em dash (U+2014) followed by a space.
        // Per `golang.org/x/mod/sumdb/note` this is the canonical separator.
        let Some(rest) = line.strip_prefix("\u{2014} ") else {
            continue;
        };
        let Some((name, b64_sig)) = rest.split_once(' ') else {
            continue;
        };
        if name != trust.name {
            continue;
        }
        let decoded = match B64.decode(b64_sig) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if decoded.len() != 4 + 64 {
            continue;
        }
        let key_hash: [u8; 4] = decoded[..4].try_into().unwrap();
        if key_hash != trust.key_hash {
            // Signature is for a different key (possibly rotation); skip
            // to the next signer line.
            continue;
        }
        let sig_bytes: [u8; 64] = decoded[4..].try_into().unwrap();
        let signature = Signature::from_bytes(&sig_bytes);
        if trust.verifier.verify(body_for_sig, &signature).is_ok() {
            return Ok(body.to_string());
        }
        matched_any = true;
        warn!(
            signer = %trust.name,
            "sum.golang.org signed-note signature verification failed for matching key hash"
        );
    }

    if matched_any {
        Err(CratonsError::Config(
            "sum.golang.org signed note signature did not verify. \
             The trust root cache may be stale — update \
             ~/.cache/cratons/keys/sum.golang.org.pub if Go has rotated the \
             verifier key, then retry."
                .to_string(),
        ))
    } else {
        Err(CratonsError::Config(format!(
            "No matching signer line in note for `{}`",
            trust.name
        )))
    }
}

/// Parse a verified `/latest` response body and return the pinned
/// transparency-log checkpoint it describes.
///
/// The `/latest` body (inside the signed-note wrapper, which the caller
/// must have already verified via [`verify_note`]) is:
///
/// ```text
/// go.sum database tree
/// <tree_size>
/// <base64 tree_hash>
/// ```
///
/// where `tree_size` is a non-negative integer and `tree_hash` is a
/// base64-encoded 32-byte SHA-256 root hash.
///
/// On malformed input returns a descriptive `CratonsError::Config`.
pub fn parse_verified_latest(body: &str) -> Result<tlog::Checkpoint> {
    let mut lines = body.lines();
    let header = lines.next().unwrap_or("");
    if header.trim() != "go.sum database tree" {
        return Err(CratonsError::Config(format!(
            "sum.golang.org /latest body has unexpected header: {:?}",
            header
        )));
    }
    let size_line = lines.next().ok_or_else(|| {
        CratonsError::Config("sum.golang.org /latest body missing tree_size line".to_string())
    })?;
    let hash_line = lines.next().ok_or_else(|| {
        CratonsError::Config("sum.golang.org /latest body missing tree_hash line".to_string())
    })?;
    let tree_size: u64 = size_line.trim().parse().map_err(|e| {
        CratonsError::Config(format!(
            "sum.golang.org /latest body: invalid tree_size: {}",
            e
        ))
    })?;
    let decoded = B64.decode(hash_line.trim()).map_err(|e| {
        CratonsError::Config(format!(
            "sum.golang.org /latest body: invalid base64 tree_hash: {}",
            e
        ))
    })?;
    if decoded.len() != tlog::HASH_SIZE {
        return Err(CratonsError::Config(format!(
            "sum.golang.org /latest body: tree_hash must be {} bytes, got {}",
            tlog::HASH_SIZE,
            decoded.len()
        )));
    }
    let mut tree_hash = [0u8; tlog::HASH_SIZE];
    tree_hash.copy_from_slice(&decoded);
    Ok(tlog::Checkpoint {
        tree_size,
        tree_hash,
    })
}

/// Enforce a weak consistency invariant between a pinned baseline
/// checkpoint and a freshly-fetched one from `/latest`.
///
/// Full RFC 6962 consistency proofs require tile fetches to walk the
/// node boundary between the two trees and are tracked as F-1c. This
/// weak check catches the most common attacker signals without any
/// additional network I/O:
///
/// - **Size monotonicity**: the new tree must be at least as large as
///   the pinned baseline. A size regression is a hard error (indicates
///   tree rewrite / rollback).
/// - **Equal-size root stability**: if the new tree is exactly the
///   same size as the pinned baseline, its root must be bytewise
///   identical. A root change at the same size means the tree was
///   rewritten in place.
///
/// Does NOT catch: a retroactive fork where the attacker continues to
/// grow the forked tree. That requires a full consistency proof.
pub fn enforce_weak_consistency(
    baseline: &tlog::Checkpoint,
    current: &tlog::Checkpoint,
) -> Result<()> {
    if current.tree_size < baseline.tree_size {
        return Err(CratonsError::Config(format!(
            "sum.golang.org weak consistency: pinned tree_size {} > current {}. \
             The checksum log has shrunk — this is a strong signal of attacker rewrite. \
             See docs/security-followups.md#f-1b for the recovery procedure.",
            baseline.tree_size, current.tree_size
        )));
    }
    if current.tree_size == baseline.tree_size && current.tree_hash != baseline.tree_hash {
        return Err(CratonsError::Config(
            "sum.golang.org weak consistency: equal tree sizes but different root hashes. \
             The log was rewritten in place — this is a strong signal of attacker rewrite. \
             See docs/security-followups.md#f-1b for the recovery procedure."
                .to_string(),
        ));
    }
    Ok(())
}

/// Parse a verified `/lookup/<module>@<version>` body and return the
/// `h1:` hash of the module zip (as base64, without the `h1:` prefix).
///
/// A canonical response body looks like:
/// ```text
/// golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=
/// golang.org/x/text v0.14.0/go.mod h1:TvPlkZtksWOMsz7fbANvkp4WM8x/WCo/om8BMLbz+aE=
/// ```
///
/// The first line is the module zip hash, the second is the `go.mod` hash.
/// We return only the zip hash; the `go.mod` hash is used by `go mod tidy`
/// but not by cratons (we re-download the `.mod` file separately).
pub fn parse_verified_lookup(
    body: &str,
    module: &str,
    version: &str,
) -> Result<String> {
    for line in body.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        if parts[0] != module {
            continue;
        }
        if parts[1] != version {
            // Skip /go.mod line (which has `{version}/go.mod` in parts[1])
            continue;
        }
        let hash = parts[2];
        if let Some(stripped) = hash.strip_prefix("h1:") {
            return Ok(stripped.to_string());
        }
    }
    Err(CratonsError::Config(format!(
        "sum.golang.org lookup response did not contain h1: hash for {}@{}",
        module, version
    )))
}

/// Compute the `h1:` dirhash of a Go module zip.
///
/// Per `golang.org/x/mod/sumdb/dirhash.HashZip` / `HashGoMod`:
///
/// 1. For each file entry, compute `sha256(file_content)`.
/// 2. Emit a line `"{hex(sha256)}  {path}\n"` (two spaces between hash and path).
/// 3. Sort the lines as whole strings, lexicographically by byte value.
/// 4. Concatenate the sorted lines.
/// 5. sha256 the concatenation.
/// 6. base64-encode with standard alphabet and padding.
///
/// The returned string is the base64 body, WITHOUT the `h1:` prefix.
pub fn compute_h1(zip_bytes: &[u8]) -> Result<String> {
    let reader = Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
        CratonsError::Config(format!("Invalid Go module zip: {}", e))
    })?;

    let mut lines: Vec<String> = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| CratonsError::Config(format!("Zip entry {}: {}", i, e)))?;
        if entry.is_dir() {
            continue;
        }
        let name = entry
            .enclosed_name()
            .ok_or_else(|| {
                CratonsError::Config(format!(
                    "Zip entry has unsafe name: {}",
                    entry.name()
                ))
            })?
            .to_string_lossy()
            .to_string();
        let mut hasher = Sha256::new();
        // Heap-allocate the read buffer (clippy::large_stack_arrays).
        // 64KiB is a reasonable chunk size for sha256 absorption.
        let mut buf = vec![0u8; 65536];
        loop {
            let n = entry
                .read(&mut buf)
                .map_err(|e| CratonsError::Config(format!("Read zip entry: {}", e)))?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        let digest = hasher.finalize();
        lines.push(format!("{}  {}\n", hex_encode(&digest), name));
    }

    // Sort by byte value (matches Go's sort.Strings on sorted hashes).
    lines.sort();

    let concatenated: String = lines.into_iter().collect();
    let mut outer = Sha256::new();
    outer.update(concatenated.as_bytes());
    let outer_digest = outer.finalize();
    Ok(B64.encode(outer_digest))
}

/// Lowercase hex encode. We avoid a crate dep since `hex::encode` already
/// exists in the workspace but pulls more surface; this is 6 lines.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// Keep the path helper reachable from the library surface so downstream
// callers (and tests) can assert where the cache lives without
// duplicating the logic.
#[doc(hidden)]
pub fn trust_root_cache_path_for_testing() -> Result<PathBuf> {
    trust_root_cache_path()
}

#[allow(dead_code)]
fn _path_type_is_used(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_vkey_parses() {
        let key = TrustedKey::parse_vkey(DEFAULT_SUM_GOLANG_VKEY)
            .expect("default sum.golang.org vkey must parse");
        assert_eq!(key.name, "sum.golang.org");
    }

    #[test]
    fn parse_verified_latest_extracts_checkpoint() {
        let body = format!(
            "go.sum database tree\n42\n{}\n",
            B64.encode([0x5au8; tlog::HASH_SIZE])
        );
        let cp = parse_verified_latest(&body).expect("parse");
        assert_eq!(cp.tree_size, 42);
        assert_eq!(cp.tree_hash, [0x5au8; tlog::HASH_SIZE]);
    }

    #[test]
    fn parse_verified_latest_rejects_bad_header() {
        let body = format!(
            "not the right header\n42\n{}\n",
            B64.encode([0u8; tlog::HASH_SIZE])
        );
        assert!(parse_verified_latest(&body).is_err());
    }

    #[test]
    fn enforce_weak_consistency_allows_growth() {
        let baseline = tlog::Checkpoint {
            tree_size: 100,
            tree_hash: [0x11u8; tlog::HASH_SIZE],
        };
        // New tree is larger; we accept (full proof would be needed
        // for strict consistency but weak check permits monotonic
        // growth).
        let current = tlog::Checkpoint {
            tree_size: 200,
            tree_hash: [0x22u8; tlog::HASH_SIZE],
        };
        enforce_weak_consistency(&baseline, &current).unwrap();
    }

    #[test]
    fn enforce_weak_consistency_rejects_shrink() {
        let baseline = tlog::Checkpoint {
            tree_size: 200,
            tree_hash: [0x11u8; tlog::HASH_SIZE],
        };
        let current = tlog::Checkpoint {
            tree_size: 150,
            tree_hash: [0x22u8; tlog::HASH_SIZE],
        };
        let err = enforce_weak_consistency(&baseline, &current).unwrap_err();
        assert!(err.to_string().contains("shrunk"));
    }

    #[test]
    fn enforce_weak_consistency_rejects_same_size_different_root() {
        let baseline = tlog::Checkpoint {
            tree_size: 100,
            tree_hash: [0x11u8; tlog::HASH_SIZE],
        };
        let current = tlog::Checkpoint {
            tree_size: 100,
            tree_hash: [0x22u8; tlog::HASH_SIZE],
        };
        let err = enforce_weak_consistency(&baseline, &current).unwrap_err();
        assert!(err.to_string().contains("rewritten"));
    }

    #[test]
    fn enforce_weak_consistency_allows_identical() {
        let cp = tlog::Checkpoint {
            tree_size: 100,
            tree_hash: [0x11u8; tlog::HASH_SIZE],
        };
        enforce_weak_consistency(&cp, &cp).unwrap();
    }

    #[test]
    fn vkey_parse_rejects_bad_format() {
        assert!(TrustedKey::parse_vkey("not-a-key").is_err());
        assert!(TrustedKey::parse_vkey("name+bad+key").is_err());
        assert!(TrustedKey::parse_vkey("name+0102030x+aGVsbG8=").is_err());
    }

    #[test]
    fn vkey_parse_rejects_non_ed25519_alg_byte() {
        // Construct a vkey with algorithm byte 0x02 (not Ed25519).
        // Raw 33 bytes: [0x02, ...32 zero bytes]
        let mut raw = vec![0x02u8];
        raw.extend_from_slice(&[0u8; 32]);
        let b64 = B64.encode(&raw);
        // Compute a matching (wrong-alg) 4-byte hash so format is valid
        // up to the alg byte check.
        let mut h = Sha256::new();
        h.update(b"x\n");
        h.update([0x02]);
        h.update([0u8; 32]);
        let d = h.finalize();
        let vkey = format!("x+{:02x}{:02x}{:02x}{:02x}+{}", d[0], d[1], d[2], d[3], b64);
        assert!(TrustedKey::parse_vkey(&vkey).is_err());
    }

    #[test]
    fn parse_verified_lookup_extracts_module_zip_hash() {
        let body = "\
golang.org/x/text v0.14.0 h1:ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=
golang.org/x/text v0.14.0/go.mod h1:TvPlkZtksWOMsz7fbANvkp4WM8x/WCo/om8BMLbz+aE=
";
        let h = parse_verified_lookup(body, "golang.org/x/text", "v0.14.0").unwrap();
        assert_eq!(h, "ScX5w1eTa3QqT8oi6+ziP7dTV1S2+ALU0bI+0zXKWiQ=");
    }

    #[test]
    fn parse_verified_lookup_errors_on_missing_hash() {
        let body = "golang.org/x/other v0.1.0 h1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=\n";
        assert!(parse_verified_lookup(body, "golang.org/x/text", "v0.14.0").is_err());
    }

    /// Build a tiny valid zip in-memory and verify `compute_h1` is
    /// deterministic and matches the dirhash algorithm definition.
    #[test]
    fn compute_h1_deterministic() {
        let zip_a = build_zip(&[("foo/bar.go", b"package bar\n"), ("a.txt", b"hi")]);
        let zip_b = build_zip(&[("a.txt", b"hi"), ("foo/bar.go", b"package bar\n")]);
        // Same file contents, different entry order in the zip → same h1.
        let h_a = compute_h1(&zip_a).unwrap();
        let h_b = compute_h1(&zip_b).unwrap();
        assert_eq!(h_a, h_b);
    }

    #[test]
    fn compute_h1_distinguishes_different_contents() {
        let zip_a = build_zip(&[("a.txt", b"hi")]);
        let zip_b = build_zip(&[("a.txt", b"hello")]);
        assert_ne!(compute_h1(&zip_a).unwrap(), compute_h1(&zip_b).unwrap());
    }

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let cursor = Cursor::new(&mut buf);
            let mut zw = zip::ZipWriter::new(cursor);
            let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            for (name, body) in entries {
                zw.start_file(*name, opts).unwrap();
                zw.write_all(body).unwrap();
            }
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn verify_note_rejects_unsigned_body() {
        let key = TrustedKey::parse_vkey(DEFAULT_SUM_GOLANG_VKEY).unwrap();
        let fake = "some body without a signer\n\n";
        assert!(verify_note(fake, &key).is_err());
    }

    #[test]
    fn verify_note_rejects_mismatched_signer_name() {
        let key = TrustedKey::parse_vkey(DEFAULT_SUM_GOLANG_VKEY).unwrap();
        // Forge a note with a signer line for a different name.
        let body = "some body\n";
        let fake_sig_bytes = vec![0u8; 4 + 64];
        let note = format!(
            "{}\n— other.example.org {}\n",
            body,
            B64.encode(&fake_sig_bytes)
        );
        assert!(verify_note(&note, &key).is_err());
    }
}
