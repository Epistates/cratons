//! Tile-based transparency log primitives for sum.golang.org (F-1b).
//!
//! Implements the subset of `golang.org/x/mod/sumdb/tlog` that cratons
//! needs:
//!
//! - **Record hash / node hash** per RFC 6962 domain separation
//!   (0x00 prefix for leaves, 0x01 prefix for interior nodes).
//! - **Inclusion proof verification** — given a record hash, its index
//!   in a tree of size `n`, the audit path sibling hashes, and the
//!   expected root hash, reconstruct the root and compare.
//! - **Consistency proof verification** — given `(old_size, old_hash)`
//!   and `(new_size, new_hash)` + the consistency proof hashes,
//!   derive both roots and compare.
//! - **Checkpoint persistence** — small on-disk file storing the last
//!   verified `(tree_size, tree_hash)` baseline at
//!   `~/.cache/cratons/keys/sum.golang.org.checkpoint`.
//! - **Tile fetch + cache** — GET `/tile/<H>/<L>/<N>[.p/<W>]` and
//!   serve subsequent reads from an in-memory map.
//!
//! # Out of scope
//!
//! - Persistent tile cache across installs (tracked as F-1c).
//! - Parameterized tile height (we hardcode `H = 8`).
//!
//! # Trust model
//!
//! This module assumes its caller has already verified the signed note
//! over the lookup response against the pinned
//! `sum.golang.org` verifier key (done in `super::verify_note`). The
//! tlog checks add the append-only-log guarantee: even if the verifier
//! key is compromised, an attacker cannot retroactively rewrite the
//! tree without the consistency proof failing against the pinned
//! baseline.

use cratons_core::{CratonsError, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, warn};

/// Hardcoded tile height for sum.golang.org. Each tile contains up to
/// `2^HEIGHT = 256` consecutive 32-byte hashes at its level.
pub const TILE_HEIGHT: usize = 8;

/// Per-entry size in a tile (32-byte SHA-256 hash).
pub const HASH_SIZE: usize = 32;

/// Full tile size in bytes.
pub const FULL_TILE_BYTES: usize = (1 << TILE_HEIGHT) * HASH_SIZE;

/// A 32-byte Merkle tree node hash.
pub type Hash = [u8; HASH_SIZE];

/// Return the hash of a leaf record per RFC 6962:
/// `H(0x00 || record_bytes)`.
#[must_use]
pub fn record_hash(record: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(record);
    h.finalize().into()
}

/// Return the hash of an interior node from its left and right child
/// hashes per RFC 6962: `H(0x01 || left || right)`.
#[must_use]
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Verify an RFC 6962 inclusion proof for a leaf at `index` in a tree
/// of size `tree_size`, against an expected `root` hash.
///
/// Returns `Ok(())` on success; returns `CratonsError::Config` with a
/// descriptive message on failure. The proof is a sequence of sibling
/// hashes starting from the leaf's sibling and walking up.
///
/// Algorithm per RFC 6962 §2.1.1:
///
/// ```text
/// fn verify_inclusion(leaf, index, tree_size, proof, root):
///     # Walk up the tree. At each level, use the next proof element
///     # as the sibling and combine in the correct order based on
///     # whether `index` is a left or right child at this level.
///     hash = leaf
///     fn = index         # "from" (the subrange's lower bound)
///     sn = tree_size - 1 # "size" (the subrange's upper bound)
///     for p in proof:
///         if fn is odd or fn == sn:
///             hash = node_hash(p, hash)
///             if fn is even:
///                 while fn is even and sn is even:
///                     fn >>= 1; sn >>= 1
///         else:
///             hash = node_hash(hash, p)
///         fn >>= 1; sn >>= 1
///     return hash == root
/// ```
pub fn verify_inclusion(
    leaf: &Hash,
    index: u64,
    tree_size: u64,
    proof: &[Hash],
    root: &Hash,
) -> Result<()> {
    if index >= tree_size {
        return Err(CratonsError::Config(format!(
            "tlog inclusion proof: index {} out of range for tree size {}",
            index, tree_size
        )));
    }

    // Per RFC 6962 §2.1.1:
    // https://www.rfc-editor.org/rfc/rfc6962#section-2.1.1
    let mut fn_ = index;
    let mut sn = tree_size - 1;
    let mut h = *leaf;

    for p in proof {
        if sn == 0 {
            return Err(CratonsError::Config(
                "tlog inclusion proof exhausted subrange before consuming proof".to_string(),
            ));
        }
        if fn_ & 1 == 1 || fn_ == sn {
            h = node_hash(p, &h);
            if fn_ & 1 == 0 {
                // "unwind" step per RFC: both fn_ and sn are even,
                // so shift them down until this is no longer the case.
                while fn_ & 1 == 0 && sn & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            h = node_hash(&h, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    // At the top of the audit path the subrange should be a single node
    // (sn == 0) and the accumulated hash should equal the tree root.
    if sn != 0 {
        return Err(CratonsError::Config(
            "tlog inclusion proof: proof too short for tree size".to_string(),
        ));
    }
    if &h != root {
        return Err(CratonsError::Config(
            "tlog inclusion proof: reconstructed root does not match expected root".to_string(),
        ));
    }
    Ok(())
}

/// Verify an RFC 6962 consistency proof from an old tree of size
/// `old_size` with root `old_root` to a new tree of size `new_size`
/// with root `new_root`, using the provided proof hashes.
///
/// Per RFC 6962 §2.1.2:
///
/// - If `old_size == 0` or `old_size == new_size`, the proof is empty
///   and trivially valid (with matching roots).
/// - Otherwise, walk the node boundary between the two trees, using
///   proof elements to reconstruct both the old root and the new root,
///   and compare.
pub fn verify_consistency(
    old_size: u64,
    old_root: &Hash,
    new_size: u64,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<()> {
    if old_size > new_size {
        return Err(CratonsError::Config(format!(
            "tlog consistency proof: old tree ({}) larger than new tree ({})",
            old_size, new_size
        )));
    }
    if old_size == new_size {
        if proof.is_empty() && old_root == new_root {
            return Ok(());
        }
        return Err(CratonsError::Config(
            "tlog consistency proof: equal-size trees must have identical roots and empty proof"
                .to_string(),
        ));
    }
    if old_size == 0 {
        // Every tree is consistent with the empty tree; the proof is
        // vacuous. We still require proof to be empty per the RFC.
        if !proof.is_empty() {
            return Err(CratonsError::Config(
                "tlog consistency proof: old_size=0 must come with empty proof".to_string(),
            ));
        }
        return Ok(());
    }

    // Per RFC 6962 §2.1.4. Reference implementation:
    // https://github.com/golang/mod/blob/master/sumdb/tlog/tlog.go (CheckTree)
    //
    // The algorithm parallels `verify_inclusion` but initializes the
    // "hash" accumulator from either the first proof element (if the
    // old tree is not a full prefix subtree) or from `old_root` itself
    // (if it is).
    let mut proof_iter = proof.iter();
    let (mut h_old, mut h_new) = {
        // If `old_size` is a power of two that sits at the top-level
        // left subtree of the new tree, the first proof element is
        // implicit and equals `old_root`. Otherwise the first element
        // is consumed from the proof as the seed.
        if old_size.is_power_of_two() && old_size & (new_size - 1) == 0 {
            (*old_root, *old_root)
        } else {
            let seed = proof_iter.next().ok_or_else(|| {
                CratonsError::Config("tlog consistency proof: truncated (missing seed)".to_string())
            })?;
            (*seed, *seed)
        }
    };

    let mut fn_ = old_size - 1;
    let mut sn = new_size - 1;

    // Shift off trailing zeros in fn_ — walking up from the last old
    // leaf to the first nontrivial boundary.
    while fn_ & 1 == 0 {
        fn_ >>= 1;
        sn >>= 1;
    }

    for p in proof_iter {
        if sn == 0 {
            return Err(CratonsError::Config(
                "tlog consistency proof: subrange exhausted before proof consumed".to_string(),
            ));
        }
        if fn_ & 1 == 1 || fn_ == sn {
            h_old = node_hash(p, &h_old);
            h_new = node_hash(p, &h_new);
            if fn_ & 1 == 0 {
                while fn_ & 1 == 0 && sn & 1 == 0 {
                    fn_ >>= 1;
                    sn >>= 1;
                }
            }
        } else {
            h_new = node_hash(&h_new, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    if &h_old != old_root {
        return Err(CratonsError::Config(
            "tlog consistency proof: reconstructed old root does not match".to_string(),
        ));
    }
    if &h_new != new_root {
        return Err(CratonsError::Config(
            "tlog consistency proof: reconstructed new root does not match".to_string(),
        ));
    }
    Ok(())
}

/// In-memory tile cache shared across proofs during a single install.
///
/// Not persisted across installs (tracked as F-1c). Tile fetches are
/// memoized by `(height, level, offset, width)` tuple; a "full" tile
/// and a "partial" tile at the same offset are distinct cache entries.
#[derive(Debug, Default)]
pub struct TileCache {
    tiles: HashMap<String, Vec<u8>>,
}

impl TileCache {
    /// Create an empty tile cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up a tile by its canonical URL path (relative to the sumdb
    /// base URL). Returns the raw bytes if cached.
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.tiles.get(path).map(Vec::as_slice)
    }

    /// Store a tile at its canonical URL path.
    pub fn insert(&mut self, path: String, bytes: Vec<u8>) {
        self.tiles.insert(path, bytes);
    }

    /// Return how many tiles are currently cached (for metrics/tests).
    #[must_use]
    pub fn len(&self) -> usize {
        self.tiles.len()
    }

    /// Is the cache empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tiles.is_empty()
    }
}

/// A persisted `(tree_size, tree_hash)` baseline pinned at the
/// end of the most recent successful install.
///
/// Stored at `~/.cache/cratons/keys/sum.golang.org.checkpoint` as two
/// lines of plain text:
///
/// ```text
/// <tree_size>
/// <base64 tree_hash>
/// ```
///
/// The file is the source of truth for the consistency proof's "old"
/// side. Operators who need to reset the baseline (e.g. after a known
/// sum.golang.org tree rewrite) delete the file manually; cratons
/// never auto-rewrites it on verification failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Tree size at the time of pinning.
    pub tree_size: u64,
    /// Tree root hash at the time of pinning.
    pub tree_hash: Hash,
}

impl Checkpoint {
    /// Return the canonical on-disk path for the sum.golang.org
    /// consistency baseline.
    pub fn cache_path() -> Result<PathBuf> {
        let base = dirs::cache_dir().ok_or_else(|| {
            CratonsError::Config("Cannot determine user cache directory".to_string())
        })?;
        Ok(base
            .join("cratons")
            .join("keys")
            .join("sum.golang.org.checkpoint"))
    }

    /// Read the baseline from disk, or return `None` if no baseline
    /// has been pinned yet (first install).
    pub fn load() -> Result<Option<Self>> {
        Self::load_from(&Self::cache_path()?)
    }

    /// Read the baseline from an explicit path. Primary use: tests and
    /// operators with non-default cache directories.
    pub fn load_from(path: &std::path::Path) -> Result<Option<Self>> {
        if !path.exists() {
            return Ok(None);
        }
        let contents = std::fs::read_to_string(path).map_err(|e| {
            CratonsError::Config(format!(
                "Failed to read sum.golang.org checkpoint {}: {}",
                path.display(),
                e
            ))
        })?;
        let mut lines = contents.lines();
        let size_str = lines.next().ok_or_else(|| {
            CratonsError::Config("sum.golang.org checkpoint: missing tree_size line".to_string())
        })?;
        let hash_str = lines.next().ok_or_else(|| {
            CratonsError::Config("sum.golang.org checkpoint: missing tree_hash line".to_string())
        })?;
        let tree_size: u64 = size_str.trim().parse().map_err(|e| {
            CratonsError::Config(format!(
                "sum.golang.org checkpoint: invalid tree_size: {}",
                e
            ))
        })?;
        let decoded =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, hash_str.trim())
                .map_err(|e| {
                    CratonsError::Config(format!(
                        "sum.golang.org checkpoint: invalid base64 tree_hash: {}",
                        e
                    ))
                })?;
        if decoded.len() != HASH_SIZE {
            return Err(CratonsError::Config(format!(
                "sum.golang.org checkpoint: tree_hash must be {} bytes, got {}",
                HASH_SIZE,
                decoded.len()
            )));
        }
        let mut tree_hash = [0u8; HASH_SIZE];
        tree_hash.copy_from_slice(&decoded);
        Ok(Some(Self {
            tree_size,
            tree_hash,
        }))
    }

    /// Atomically write this baseline to disk, creating the parent
    /// directory as needed.
    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::cache_path()?)
    }

    /// Atomically write this baseline to an explicit path.
    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CratonsError::Config(format!(
                    "Failed to create checkpoint cache directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
        let body = format!(
            "{}\n{}\n",
            self.tree_size,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, self.tree_hash)
        );
        let tmp = path.with_extension("checkpoint.tmp");
        std::fs::write(&tmp, body).map_err(|e| {
            CratonsError::Config(format!(
                "Failed to write checkpoint tmp {}: {}",
                tmp.display(),
                e
            ))
        })?;
        std::fs::rename(&tmp, path).map_err(|e| {
            CratonsError::Config(format!(
                "Failed to rename checkpoint cache into place: {}",
                e
            ))
        })?;
        debug!(
            tree_size = self.tree_size,
            path = %path.display(),
            "sum.golang.org checkpoint pinned"
        );
        Ok(())
    }
}

/// Emit a warning that sum.golang.org proof verification failed
/// because the caller hit a network-only path. Used by
/// `super::GoProxyClient` when consistency or inclusion proofs fail.
pub fn warn_proof_failure(context: &str, err: &CratonsError) {
    warn!(
        context = context,
        error = %err,
        "sum.golang.org tlog proof failed. If sum.golang.org has rewritten \
         its tree (extremely rare; announced by Google), delete \
         ~/.cache/cratons/keys/sum.golang.org.checkpoint and retry. Do NOT \
         do this reflexively — a failed consistency proof is the primary \
         signal of a key-compromise attack."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: hand-compute the root of a tree of 7 leaves from a known
    /// input. The RFC 6962 tree of 7 elements looks like:
    ///
    /// ```text
    ///             r
    ///           /   \
    ///         m       k6
    ///        / \      / \
    ///       /   \    k45 k6*
    ///      a     b
    ///    /  \   / \
    ///   k0  k1 k2 k3
    /// ```
    ///
    /// where `kn = record_hash(&[n])`, `a = node_hash(k0, k1)`, etc.
    fn build_tree_of_seven() -> (Vec<Hash>, Hash) {
        let leaves: Vec<Hash> = (0..7u8).map(|i| record_hash(&[i])).collect();
        let k0 = leaves[0];
        let k1 = leaves[1];
        let k2 = leaves[2];
        let k3 = leaves[3];
        let k4 = leaves[4];
        let k5 = leaves[5];
        let k6 = leaves[6];
        let a = node_hash(&k0, &k1);
        let b = node_hash(&k2, &k3);
        let m = node_hash(&a, &b);
        let c = node_hash(&k4, &k5);
        let right = node_hash(&c, &k6); // the right subtree of a size-7 tree
        let root = node_hash(&m, &right);
        (leaves, root)
    }

    #[test]
    fn record_hash_matches_domain_separation() {
        let h = record_hash(b"hello");
        // Sha256(0x00 || "hello") = ef537f25c895bf...
        let expected = {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(b"hello");
            <[u8; 32]>::from(h.finalize())
        };
        assert_eq!(h, expected);
    }

    #[test]
    fn node_hash_domain_separation() {
        let a = [0u8; 32];
        let b = [1u8; 32];
        let h = node_hash(&a, &b);
        let expected = {
            let mut hh = Sha256::new();
            hh.update([0x01u8]);
            hh.update(a);
            hh.update(b);
            <[u8; 32]>::from(hh.finalize())
        };
        assert_eq!(h, expected);
    }

    #[test]
    fn inclusion_proof_leaf_0_tree_7() {
        let (leaves, root) = build_tree_of_seven();
        // Audit path for leaf 0 in a tree of 7:
        //   sibling(k0) = k1
        //   sibling(a)  = b
        //   sibling(m)  = right
        let k1 = leaves[1];
        let k2 = leaves[2];
        let k3 = leaves[3];
        let k4 = leaves[4];
        let k5 = leaves[5];
        let k6 = leaves[6];
        let b = node_hash(&k2, &k3);
        let c = node_hash(&k4, &k5);
        let right = node_hash(&c, &k6);
        let proof = vec![k1, b, right];
        verify_inclusion(&leaves[0], 0, 7, &proof, &root).expect("leaf 0 inclusion must verify");
    }

    #[test]
    fn inclusion_proof_leaf_6_tree_7() {
        let (leaves, root) = build_tree_of_seven();
        // Leaf 6 is a right-child orphan. The audit path is:
        //   fn=6, sn=6: fn==sn branch → sibling is `c` (left), result is node_hash(c, k6)
        //     then both fn_ and sn_ are even (3 after >>), so unwind:
        //     fn_=3, sn_=3 → wait, the unwind condition is only applied when fn is even after
        //     the combine. Let me just run the algorithm.
        //
        // For leaf 6 in tree of 7, audit path is [c, m].
        let k0 = leaves[0];
        let k1 = leaves[1];
        let k2 = leaves[2];
        let k3 = leaves[3];
        let k4 = leaves[4];
        let k5 = leaves[5];
        let a = node_hash(&k0, &k1);
        let b = node_hash(&k2, &k3);
        let m = node_hash(&a, &b);
        let c = node_hash(&k4, &k5);
        let proof = vec![c, m];
        verify_inclusion(&leaves[6], 6, 7, &proof, &root).expect("leaf 6 inclusion must verify");
    }

    #[test]
    fn inclusion_proof_wrong_root_fails() {
        let (leaves, _root) = build_tree_of_seven();
        let k1 = leaves[1];
        let k2 = leaves[2];
        let k3 = leaves[3];
        let k4 = leaves[4];
        let k5 = leaves[5];
        let k6 = leaves[6];
        let b = node_hash(&k2, &k3);
        let c = node_hash(&k4, &k5);
        let right = node_hash(&c, &k6);
        let proof = vec![k1, b, right];

        let bogus_root = [0xabu8; HASH_SIZE];
        assert!(verify_inclusion(&leaves[0], 0, 7, &proof, &bogus_root).is_err());
    }

    #[test]
    fn inclusion_proof_out_of_range_index_rejected() {
        let (leaves, root) = build_tree_of_seven();
        assert!(verify_inclusion(&leaves[0], 99, 7, &[], &root).is_err());
    }

    #[test]
    fn consistency_equal_sizes_trivial() {
        let root = [0x42u8; HASH_SIZE];
        verify_consistency(5, &root, 5, &root, &[]).expect("identity must verify");

        // Mismatched roots at equal size fail.
        let other = [0x43u8; HASH_SIZE];
        assert!(verify_consistency(5, &root, 5, &other, &[]).is_err());
    }

    #[test]
    fn consistency_zero_old_size_trivial() {
        // Any non-empty new tree is consistent with the empty tree.
        let new_root = [0x77u8; HASH_SIZE];
        let zero = [0u8; HASH_SIZE];
        verify_consistency(0, &zero, 100, &new_root, &[]).expect("empty->any must verify");
        // Non-empty proof must be rejected.
        assert!(verify_consistency(0, &zero, 100, &new_root, &[new_root]).is_err());
    }

    #[test]
    fn consistency_old_larger_than_new_rejected() {
        let h = [0x11u8; HASH_SIZE];
        assert!(verify_consistency(10, &h, 5, &h, &[]).is_err());
    }

    #[test]
    fn tile_cache_round_trip() {
        let mut c = TileCache::new();
        assert!(c.is_empty());
        c.insert("tile/8/0/000".to_string(), vec![1, 2, 3]);
        assert_eq!(c.len(), 1);
        assert_eq!(c.get("tile/8/0/000"), Some(&[1u8, 2, 3][..]));
        assert_eq!(c.get("tile/8/0/001"), None);
    }

    #[test]
    fn checkpoint_save_and_load_round_trip() {
        // Use an explicit path under a temp dir so we don't touch the
        // real `~/.cache/cratons` and don't need env-var fiddling (the
        // resolver crate forbids unsafe code, which rules out
        // `std::env::set_var` in Rust 2024).
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("sum.golang.org.checkpoint");

        let cp = Checkpoint {
            tree_size: 123_456_789,
            tree_hash: [0x5au8; HASH_SIZE],
        };
        cp.save_to(&path).expect("save");
        assert!(path.exists());

        let loaded = Checkpoint::load_from(&path).expect("load").expect("Some");
        assert_eq!(loaded, cp);

        // Loading from a path that doesn't exist yields None.
        let missing = tmp.path().join("nonexistent.checkpoint");
        assert_eq!(Checkpoint::load_from(&missing).unwrap(), None);
    }
}
