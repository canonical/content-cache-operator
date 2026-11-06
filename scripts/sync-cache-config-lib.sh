#!/bin/bash
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.
set -euo pipefail

# Vendor the cache-config interface library into every in-repo charm that speaks it.
#
# libs/charms/content_cache/v0/cache_config.py is the single source of truth; each charm
# keeps an identical, committed copy at lib/charms/content_cache/v0/cache_config.py (the
# same approach the vault-k8s-operator monorepo uses for shared charm libs - see
# https://discourse.charmhub.io/t/code-sharing-in-charm-monorepos/18347).
#
# Run this after any change to the canonical file and commit the result. Pass --check to
# verify the vendored copies are in sync instead of updating them (used in CI).

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_file="$repo_root/libs/charms/content_cache/v0/cache_config.py"

consumers=(
  "$repo_root/content-cache/lib/charms/content_cache/v0/cache_config.py"
  "$repo_root/content-cache-backends-config/lib/charms/content_cache/v0/cache_config.py"
)

mode="${1:-sync}"

if [[ "$mode" == "--check" ]]; then
  status=0
  for dest in "${consumers[@]}"; do
    if ! diff -u "$source_file" "$dest" > /dev/null 2>&1; then
      echo "out of sync: $dest"
      diff -u "$dest" "$source_file" || true
      status=1
    fi
  done
  if [[ "$status" -ne 0 ]]; then
    echo "Run scripts/sync-cache-config-lib.sh and commit the result." >&2
  fi
  exit "$status"
fi

for dest in "${consumers[@]}"; do
  mkdir -p "$(dirname "$dest")"
  cp "$source_file" "$dest"
  echo "synced $source_file -> $dest"
done
