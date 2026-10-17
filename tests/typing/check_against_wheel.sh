#!/usr/bin/env bash
# Type-checks the OIDC-only host the way a host's own pyright sees webauth: from a
# directory without src, against the built wheel installed at the locked versions,
# so pyright applies py.typed export rules (reportPrivateImportUsage).
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
host="$(mktemp -d)"
trap 'rm -rf "$host"' EXIT
uv build "$repo" --wheel --out-dir "$host/dist" \
  --build-constraint "$repo/.github/requirements-build.txt" --require-hashes --quiet
uv export --project "$repo" --locked --no-emit-project --no-hashes --extra jwt \
  --quiet --output-file "$host/constraints.txt"
uv venv --quiet --python 3.12 "$host/.venv"
wheels=("$host"/dist/*.whl)
uv pip install --quiet --python "$host/.venv/bin/python" --constraints "$host/constraints.txt" \
  "overnightworks-webauth[jwt] @ file://${wheels[0]}"
# Without py.typed pyright reads webauth as untyped and checks no export at all.
site="$("$host/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
[[ -f "$site/webauth/py.typed" ]]
cp "$repo/tests/typing/oidc_host.py" "$host/"
cd "$host"
uvx --no-build pyright@1.1.414 --pythonpath .venv/bin/python oidc_host.py
