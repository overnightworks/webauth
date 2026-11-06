#!/usr/bin/env bash
# Publishes a release: checks the checkout, waits for the CI run of main's commit, tags that commit,
# pushes only the tag, waits for the release run and verifies the release.
# Usage: scripts/publish_release.sh vMAJOR.MINOR.PATCH
set -euo pipefail

refuse() {
  echo "publish_release: $1" >&2
  exit 1
}

# Runs a command with its output hidden; a failing command's output is printed with the refusal.
run_hidden() {
  local output
  if ! output="$("$@" 2>&1)"; then
    refuse "$* failed: ${output}"
  fi
}

# Waits for the newest push run of a workflow on a commit; sets run_id, run_conclusion and run_url.
wait_for_run() {
  local workflow="$1" sha="$2" answer status
  shift 2
  while true; do
    if ! answer="$(gh run list --workflow "$workflow" --commit "$sha" --event push "$@" --limit 1 \
      --json databaseId,status,conclusion,url \
      --jq '.[0] // empty | "\(.databaseId) \(.status) \((.conclusion | select(. != null and . != "")) // "-") \(.url)"' 2>&1)"; then
      refuse "gh run list failed: ${answer}"
    fi
    if [[ -n "$answer" ]]; then
      if [[ ! "$answer" =~ ^[0-9]+\ (queued|requested|waiting|pending|in_progress|completed)\ [^[:space:]]+\ [^[:space:]]+$ ]]; then
        refuse "cannot read the answer of gh run list: ${answer//$'\n'/\\n}"
      fi
      read -r run_id status run_conclusion run_url <<<"$answer"
      [[ "$status" == "completed" ]] && return 0
    fi
    echo "waiting for ${workflow} on ${sha:0:7}"
    sleep 60
  done
}

[[ $# -eq 1 ]] || refuse "usage: scripts/publish_release.sh vMAJOR.MINOR.PATCH"
tag="$1"
cd "$(dirname "$0")/.."

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || refuse "'${tag}' is not vMAJOR.MINOR.PATCH"
version="$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' src/webauth/__init__.py 2>/dev/null)" ||
  refuse "cannot read src/webauth/__init__.py"
[[ "$tag" == "v${version}" ]] || refuse "${tag} differs from v${version}, the webauth.__version__ of this checkout"
[[ "$(git symbolic-ref --short -q HEAD || true)" == "main" ]] || refuse "the checkout is not on main"
[[ -z "$(git status --porcelain)" ]] || refuse "the tree is not clean"
run_hidden git fetch --no-tags origin
sha="$(git rev-parse refs/heads/main 2>/dev/null)" || refuse "main does not exist locally"
origin_sha="$(git rev-parse refs/remotes/origin/main 2>/dev/null)" || refuse "origin has no main"
[[ "$sha" == "$origin_sha" ]] || refuse "local main differs from origin/main"
if ! remote_tag="$(git ls-remote --tags origin "refs/tags/${tag}" 2>&1)"; then
  refuse "git ls-remote failed: ${remote_tag}"
fi
[[ -z "$remote_tag" ]] || refuse "${tag} exists on origin"
if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
  refuse "${tag} exists locally only; delete it with: git tag -d ${tag}"
fi
command -v gh >/dev/null || refuse "gh is not installed"
run_hidden gh auth status
echo "releasing ${tag} from main at ${sha:0:7}"

wait_for_run ci.yml "$sha" --branch main
case "$run_conclusion" in
  success) ;;
  cancelled) refuse "the CI run was cancelled: ${run_url}; run: gh run rerun ${run_id}" ;;
  *) refuse "the CI run ended with ${run_conclusion}: ${run_url}" ;;
esac

if ! output="$(git tag -a "$tag" -m "webauth ${version}" "$sha" 2>&1)"; then
  refuse "git tag failed: ${output}"
fi
if ! output="$(git push --no-follow-tags origin "refs/tags/${tag}:refs/tags/${tag}" 2>&1)"; then
  git tag -d "$tag" >/dev/null || refuse "git push failed: ${output}; the local tag ${tag} is left behind, delete it with: git tag -d ${tag}"
  refuse "git push failed: ${output}"
fi
echo "pushed ${tag}"

wait_for_run release.yml "$sha" --branch "$tag"
[[ "$run_conclusion" == "success" ]] || refuse "the release run ended with ${run_conclusion}: ${run_url}"
run_hidden scripts/verify_release.sh "$tag"
echo "verified"
