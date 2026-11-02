#!/usr/bin/env bash
# Verifies a release as PyPI serves it: the digest of each file, its build-provenance attestation
# and its PEP 740 publisher (GitHub, this repository, release.yml, environment pypi).
# Usage: scripts/verify_release.sh TAG
# PYPI_URL points at another index, for tests against canned answers; it defaults to PyPI.
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: scripts/verify_release.sh TAG" >&2
  exit 2
fi

repository="overnightworks/webauth"
project="overnightworks-webauth"
version="${1#v}"
pypi="${PYPI_URL:-https://pypi.org}"
download="$(mktemp -d)"
trap 'rm -rf "$download"' EXIT

curl -fsS "$pypi/pypi/$project/$version/json" > "$download/release.json"
mapfile -t files < <(jq -r '.urls[].filename' "$download/release.json")
if [[ ${#files[@]} -eq 0 ]]; then
  echo "PyPI serves no files for $project $version" >&2
  exit 1
fi

for file in "${files[@]}"; do
  expected="$(jq -r --arg file "$file" '.urls[] | select(.filename == $file) | .digests.sha256' "$download/release.json")"
  url="$(jq -r --arg file "$file" '.urls[] | select(.filename == $file) | .url' "$download/release.json")"
  curl -fsS "$url" -o "$download/$file"
  actual="$(sha256sum "$download/$file" | cut -d' ' -f1)"
  if [[ "$actual" != "$expected" ]]; then
    echo "$file: sha256 is $actual, PyPI lists $expected" >&2
    exit 1
  fi

  gh attestation verify "$download/$file" -R "$repository"

  curl -fsS -H "Accept: application/vnd.pypi.integrity.v1+json" \
    "$pypi/integrity/$project/$version/$file/provenance" > "$download/provenance.json"
  if ! jq -e --arg repository "$repository" '
    (.attestation_bundles | length) > 0
    and all(.attestation_bundles[].publisher;
      .kind == "GitHub" and .repository == $repository
      and .workflow == "release.yml" and .environment == "pypi")' "$download/provenance.json" > /dev/null; then
    echo "$file: the provenance names a publisher other than $repository, release.yml, environment pypi" >&2
    exit 1
  fi
  echo "$file: digest, attestation and publisher verified"
done
