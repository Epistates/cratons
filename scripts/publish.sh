#!/usr/bin/env bash
set -euo pipefail

# Publish all cratons crates to crates.io in dependency order.
# Crates.io index needs time to propagate between publishes.
#
# Usage:
#   ./scripts/publish.sh          # dry-run (default)
#   ./scripts/publish.sh --execute # actually publish

DRY_RUN="--dry-run"
if [[ "${1:-}" == "--execute" ]]; then
    DRY_RUN=""
    echo "=== PUBLISHING FOR REAL ==="
else
    echo "=== DRY RUN (pass --execute to publish) ==="
fi

WAIT_SECS=30

publish() {
    local crate=$1
    echo ""
    echo "--- Publishing $crate ---"
    cargo publish $DRY_RUN -p "$crate"
    if [[ -z "$DRY_RUN" ]]; then
        echo "Waiting ${WAIT_SECS}s for crates.io index propagation..."
        sleep "$WAIT_SECS"
    fi
}

# Tier 1: No internal dependencies
publish cratons-core
publish cratons-credentials

# Tier 2: Depends on core only
publish cratons-manifest
publish cratons-lockfile
publish cratons-sandbox

# Tier 3: Depends on tiers 1-2
publish cratons-store
publish cratons-workspace
publish cratons-security
publish cratons-resolver

# Tier 4: Depends on tiers 1-3
publish cratons-builder
publish cratons-environment

# Tier 5: Depends on most crates
publish cratons-installer

# Tier 6: CLI binary (depends on everything)
publish cratons

echo ""
echo "=== Done ==="
