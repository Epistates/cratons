# Security Follow-ups Registry

This file is the canonical registry of every security follow-up item
identified during the cratons Phase 1–5 hardening plan and its Phase 2
continuation (F‑1..F‑6). Every item is listed with its current status
(landed, deferred, or dropped), the reasoning, and the trigger that
would make us reconsider it.

**Read this file before adding new `deny.toml` ignore entries or reverting
any security-critical default.** If a reviewer or auditor wants to know
"why didn't cratons do X", this is where the answer lives.

---

## Status legend

- **Landed**: shipped in the codebase. Verified by tests in the listed
  location.
- **Deferred**: the work is in scope, but intentionally out of the
  current delivery window. Tracked for a future phase.
- **Dropped**: the work is not planned. The reasoning explains why
  (infeasible, unnecessary, or superseded).

---

## F‑1 — Go `sum.golang.org` signed-note verified `h1:` integrity

**Status**: Landed.

**Where**:
- Core library: `crates/cratons-resolver/src/registry/gosum.rs`
- Wired in: `crates/cratons-resolver/src/registry/go.rs`
  (`GoProxyClient::fetch_sum_h1`)
- Install-time check: `crates/cratons-installer/src/download.rs`
  (`h1-` branch in `verify_download_integrity`)
- Tests: `cargo test -p cratons-resolver registry::gosum`

**What it does**: every `/lookup` response from `sum.golang.org` is
verified against an Ed25519 public key pinned on first use to
`~/.cache/cratons/keys/sum.golang.org.pub`. The `h1:` hash extracted
from the verified body is the cryptographic dirhash over the module
zip's contents. At install time, `verify_download_integrity` recomputes
the dirhash locally from the downloaded bytes and compares.

**F‑1b status**: partially landed. The module
`crates/cratons-resolver/src/registry/gosum/tlog.rs` implements RFC
6962 primitives — record hashing, node hashing, inclusion proof
verification, consistency proof verification, tile cache, and
checkpoint persistence — verified against hand-constructed tree
vectors in unit tests. The `GoProxyClient` now also fetches
`/latest` on first use per install, pins a `(tree_size, tree_hash)`
baseline at `~/.cache/cratons/keys/sum.golang.org.checkpoint`, and
enforces **weak consistency** against the baseline on every
subsequent run: size-monotonic (no log shrinking) and stable-root-
at-same-size (no in-place rewrite).

**Deferred to F‑1c**: full tile-fetching path. Weak consistency
catches the most obvious attacker signals (rollback, in-place
rewrite) but cannot detect a retroactive fork where the attacker
continues to grow the forked tree. Full detection requires
fetching `/tile/<H>/<L>/<N>` paths and running
`tlog::verify_inclusion` + `tlog::verify_consistency` against real
proof data. The primitives are ready; only the HTTP tile fetcher
needs to be wired.

**Revisit F‑1c when**: `cratons install` latency becomes a
complaint, or when `sum.golang.org` rotates its verifier key (which
would exercise the full proof path and surface any remaining wiring
gaps).

---

## F‑2 — Maven PGP detached-signature verification with keyserver cache

**Status**: Landed (F‑2a core, F‑2b wiring).

**Where**:
- Core library: `crates/cratons-security/src/keyring.rs`
  (`MavenTrustConfig`, `KeyStore`, `fetch_key`)
- Install-time verification: `crates/cratons-installer/src/download.rs`
  (`verify_maven_pgp`)
- Tests: `cargo test -p cratons-security keyring`

**What it does**: for every Maven package, at install time, the
installer:

1. Fetches `{jar_url}.asc` from Maven Central (same HTTPS).
2. Resolves trusted fingerprints for the package's groupId via the
   configured `MavenTrustConfig` (project and/or user keyring).
3. On a match, fetches the public key by fingerprint from a hardcoded
   trusted keyserver list (`keys.openpgp.org` primary,
   `keyserver.ubuntu.com` fallback), validating that the returned key's
   actual fingerprint matches the requested one (prevents keyserver
   substitution attacks). Keys are cached at
   `~/.cache/cratons/keys/pgp/<fingerprint>.asc`.
4. Verifies the detached signature against the downloaded JAR bytes
   using `ToolchainVerifier::verify_gpg`.
5. When no explicit fingerprint is configured, the fallback extracts
   the issuer fingerprint subpacket from the signature and verifies
   against a keyserver-fetched key. This proves "bytes are consistent
   with SOME key's signature" but not identity.

**F‑2c status**: landed.

- Project-level `[security.maven]` section in `cratons.toml` parses into
  `cratons_manifest::SecurityConfig`. `InstallerConfig::from_manifest`
  overlays this onto the default user-level config; precedence is
  project > user > TOFU.
- Lockfile `[pgp-trust]` TOFU table serializes as a `BTreeMap<String,
  String>` (deterministic ordering, omitted when empty).
- `first-install` policy is wired in `download.rs::verify_maven_pgp`
  with `deny`/`warn`/`allow` and `CRATONS_CI=1` promoting `warn` →
  `deny` for non-interactive automation.
- TOFU pins flow up through
  `InstallResult::pgp_trust_updates`; the CLI (`cratons install`)
  merges them into the lockfile on disk after a successful install.
  Failed installs never corrupt the on-disk lockfile.
- The F‑2b "permissive fallback" that soft-passed unverified
  signatures is gone. Every Maven package now goes through the strict
  trust ladder: project/user config → lockfile TOFU → first-install
  policy → error (under `Deny`).

**Deferred to F‑2d**:

- Sigstore `.sigstore.json` verification for Maven Central publishers
  who've adopted it (2026 update). `sigstore` is already a workspace
  dep (used by toolchain verification). A future phase could prefer
  Sigstore when the `.sigstore.json` sidecar exists and fall back to
  PGP otherwise.
- Keyserver rotation detection. Cached PGP keys are re-validated
  against their own self-signature on every use, but there's no TTL
  or revocation-check path. A compromised key that gets revoked on
  `keys.openpgp.org` would continue to verify locally until the
  operator manually clears
  `~/.cache/cratons/keys/pgp/<fingerprint>.asc`.

---

## F‑3 — Cross-mirror Maven SHA‑1 verification

**Status**: Dropped.

**Why**: SHA‑1 is cryptographically broken (SHAttered, 2017) and Maven
Central no longer serves stronger hashes as individual files. Any
cross-mirror attestation against SHA‑1 would still be defeated by a
chosen-prefix collision attack from a sufficiently motivated adversary.
F‑2 supersedes this entirely by moving to real PGP signature
verification, which provides the cryptographic binding F‑3 could not.

**Revisit when**: never. The underlying primitive is dead.

---

## F‑4 — `rand` 0.8 → 0.9 / 0.10 upgrade

**Status**: Dropped.

**Why not reachable**: `RUSTSEC-2026-0097` affects `rand::rng()` and
`rand::thread_rng()` used inside a custom tracing logger that re-enters
during emit. Cratons' direct `rand` uses are:

- `crates/cratons-lockfile/src/lib.rs:694` — `rand::rngs::OsRng`
  (bypass the thread-local PRNG entirely; not affected)
- `crates/cratons-credentials/src/store.rs:330-340` — `rand::rngs::OsRng`
  (same)
- `crates/cratons-benchmarks/src/lib.rs:207` — `rand::thread_rng()`
  (only reachable in benchmark runs; no custom logger is active)

No code path exists where `rand::rng()` is called re-entrantly from
inside a logger's `emit` method. The existing `deny.toml`
RUSTSEC-2026-0097 ignore is load-bearing and documents this.

**Why the upgrade is blocked**: `argon2 0.5`, `aes-gcm 0.10`, and `rsa
0.9` all pin `rand_core 0.6`. Bumping cratons to `rand 0.9` (which uses
`rand_core 0.9`) would fragment the CryptoRng/CryptoRngCore traits at
linker time. These crates have only RC releases for `rand_core 0.9` as
of 2026‑04.

**Revisit when**: the RustCrypto ecosystem ships coordinated stable
releases of `argon2`, `aes-gcm`, and `rsa` on `rand_core 0.9` — and the
advisory is re-evaluated against the new API surface.

---

## F‑5 — Coordinated crypto stack bump (`sha1`/`sha2`/`hmac`/`digest` 0.10 → 0.11)

**Status**: Dropped as an action item; ecosystem-blocked.

**Why**: `sha2 0.11` / `digest 0.11` are stable, but the downstream
crates that cratons depends on do not have stable releases yet on the
`digest 0.11` trait tree:

- `argon2 0.6.0-rc.8` — release candidate only
- `aes-gcm 0.11.0-rc.3` — release candidate only
- `rsa` — no `digest 0.11` release on crates.io
- `sigstore 0.13` — pinned to `digest 0.10`
- `pgp 0.18` — pinned to `digest 0.10`

Attempting the bump unilaterally would produce a dependency graph with
both `digest 0.10` and `digest 0.11` resolved simultaneously, and the
two trait hierarchies are incompatible at the type level.

**Revisit**: quarterly via `cargo outdated`. When all five downstream
crates ship stable releases on `digest 0.11`, cratons can land the
coordinated bump.

---

## F‑6 — Benchmarks `criterion::black_box` hygiene

**Status**: Landed.

**Where**: `crates/cratons-benchmarks/benches/{lockfile,manifest,resolver,store}.rs`

All `criterion::black_box` call sites now use `std::hint::black_box`
via a module-level `use std::hint::black_box;` import.

---

## F‑final — `IntegrityPolicy::default()` flipped to `Required`

**Status**: Landed.

**Where**: `crates/cratons-installer/src/lib.rs` (`impl Default for IntegrityPolicy`)

The previous default was
`RequiredWithEcosystemAllowlist(vec![Ecosystem::Go, Ecosystem::Maven])`
because neither ecosystem had a credible cross-origin integrity source.
F‑1 and F‑2 added those sources. Flipping the default from "allowlisted"
to `Required` is the moment M‑2 is fully closed.

**User-visible behavior change**: any package with an empty registry
integrity string now aborts the install. This is a breaking change;
documented in `CHANGELOG.md` under the Unreleased section.

---

## Cross-reference from `deny.toml`

The `RUSTSEC-2026-0097` entry in `deny.toml` points at this document
(`#f-4`) for the reachability analysis that justifies the ignore.
Every other ignore entry should similarly cross-reference the item
here rather than duplicating rationale inline.
