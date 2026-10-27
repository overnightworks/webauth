#!/usr/bin/env bash
# Verifies a published release: checksums and build-provenance attestations of the wheel and sdist.
# Usage: scripts/verify_release.sh TAG
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/verify_release.sh TAG" >&2
  exit 2
fi

repository="overnightworks/webauth"
download="$(mktemp -d)"
trap 'rm -rf "$download"' EXIT

gh release download "$1" -R "$repository" --dir "$download"
cd "$download"
sha256sum -c --ignore-missing SHA256SUMS
for artifact in *.whl *.tar.gz; do
  gh attestation verify "$artifact" -R "$repository"
done
