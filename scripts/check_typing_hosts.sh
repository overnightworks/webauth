#!/usr/bin/env bash
# Type-checks the typing hosts in tests/fixtures/typing_hosts the way a host's own pyright sees webauth: from a
# directory without src, against the built wheel installed at the locked versions,
# so pyright applies py.typed export rules (reportPrivateImportUsage). The host lives under the user's cache
# directory because no dependency install belongs in /tmp.
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
hosts="${XDG_CACHE_HOME:-$HOME/.cache}/webauth-typing-hosts"
mkdir -p "$hosts"
host="$(mktemp -d "$hosts/host.XXXXXX")"
trap 'rm -rf "$host"' EXIT
uv build "$repo" --out-dir "$host/dist" \
  --build-constraint "$repo/.github/requirements-build.txt" --require-hashes --quiet
uv export --project "$repo" --locked --no-emit-project --no-hashes \
  --quiet --output-file "$host/constraints.txt"
uv venv --quiet --python 3.14 "$host/.venv"
wheels=("$host"/dist/*.whl)
uv pip install --quiet --python "$host/.venv/bin/python" --constraints "$host/constraints.txt" \
  "overnightworks-webauth @ file://${wheels[0]}"
# Without py.typed pyright reads webauth as untyped and checks no export at all.
site="$("$host/.venv/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
[[ -f "$site/webauth/py.typed" ]] || { echo "the built wheel installs no webauth/py.typed" >&2; exit 1; }
cp "$repo"/tests/fixtures/typing_hosts/*.py "$host/"
cd "$host"
uv run --project "$repo" --locked --group dev pyright --stats --pythonpath .venv/bin/python *.py
