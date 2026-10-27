#!/usr/bin/env bash
# The static checks CI's `checks` job runs; the suite stays outside (run targeted: uv run pytest <files>).
set -euo pipefail
cd "$(dirname "$0")/.."

step() {
  printf '\n== %s ==\n' "$1"
  shift
  "$@"
}

step "Ruff" uv run --locked ruff check src tests
step "Import boundaries" uv run --locked lint-imports
step "Declared dependencies" uv run --locked deptry src
step "Pyright" uv run --locked --group dev --group e2e pyright --stats
step "Public types are fully annotated" uv run --locked --group dev pyright --verifytypes webauth --ignoreexternal
step "The typing hosts type-check against the built wheel" tests/typing/check_against_wheel.sh
