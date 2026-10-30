#!/usr/bin/env bash
# Regenerates .github/requirements-build.txt, the hash-pinned build constraints both CI and the
# release build install, from the setuptools floor in pyproject.toml's [build-system].
set -euo pipefail
cd "$(dirname "$0")/.."

floor="$(python3 -c '
import tomllib
with open("pyproject.toml", "rb") as manifest:
    requirements = tomllib.load(manifest)["build-system"]["requires"]
print(next(requirement for requirement in requirements if requirement.startswith("setuptools")))
')"

echo "$floor" | uv pip compile - --generate-hashes --python-version 3.14 --no-annotate \
  --custom-compile-command 'See AGENTS.md "Releasing"' \
  --output-file .github/requirements-build.txt
