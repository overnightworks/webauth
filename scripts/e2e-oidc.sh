#!/usr/bin/env bash
# The terminal steps of the real-browser proofs in e2e/oidc/ (see its README).
set -euo pipefail
shopt -s inherit_errexit

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_lock=/tmp/probe-stack.lock
suite_host=conformance.example.test
compose_project_label=com.docker.compose.project

# The cap is a whole-run limit. --kill-after must exceed the worst case of a
# run's cleanup, or timeout's SIGKILL would cut it short and leave the stack
# behind. prove.py: browser worker 15 s, host SIGTERM 15 s, host SIGKILL 15 s,
# stack 180 s, together 225 s. conformance.py: worker join 15 s, host stop
# 30 s, first teardown 90 s, backstop teardown 90 s, together 225 s. A full
# prove run measured 134 s, so 900 s leaves a factor of about 6.
run_cap_seconds=900
kill_after_seconds=240

usage() {
  cat >&2 <<'USAGE'
usage: scripts/e2e-oidc.sh VERB [ARGS]

  prepare            install the pinned Chromium and pull the relay and suite images
  prove ARGS         run e2e/oidc/prove.py (ARGS: --edge DIR --scratch EMPTY_DIR)
  conformance ARGS   run e2e/oidc/conformance.py (ARGS: --scratch EMPTY_DIR)
  cleanup SCRATCH    remove what a killed run left behind (SCRATCH: the run's --scratch)
USAGE
  exit 2
}

refuse_while_loaded() {
  local load cores
  load="$(cut -d' ' -f1 /proc/loadavg)"
  cores="$(nproc)"
  if awk -v load="$load" -v cores="$cores" 'BEGIN { exit !(load > 1.5 * cores) }'; then
    echo "1-minute load $load is above 1.5 x $cores cores; wait and retry" >&2
    exit 1
  fi
}

# timeout runs in its own process group so its limit reaches every descendant;
# Ctrl-C reaches only flock. Stop a run with SIGTERM to timeout or the python process.
# The load is read again once the lock is held, because the wait for it can be long.
run_under_lock() {
  local driver="$1"
  shift
  refuse_while_loaded
  flock -o "$probe_lock" bash -c "$(declare -f refuse_while_loaded)"'
refuse_while_loaded && exec "$@"' _ \
    timeout --kill-after="$kill_after_seconds" "$run_cap_seconds" \
    uv run --locked --project "$root" --group dev --group e2e python "$root/e2e/oidc/$driver" "$@"
}

# A constant the harness defines, read from its module so no copy can drift.
harness_constant() {
  uv run --locked --project "$root" --group e2e python -I -c \
    'import importlib, sys; sys.path.insert(0, sys.argv[1]); print(getattr(importlib.import_module(sys.argv[2]), sys.argv[3]))' \
    "$root/e2e/oidc" "$1" "$2"
}

prepare() {
  uv run --locked --project "$root" --group e2e playwright install chromium
  docker pull "$(harness_constant shim RELAY_IMAGE)"
  SUITE_HOST="$suite_host" docker compose -f "$root/e2e/oidc/suite-compose.yaml" pull
}

# The command line harness.py:start_host builds for this checkout's host app:
# the interpreter, then this checkout's host_app.py.
host_app_pattern() {
  local escaped
  escaped="$(printf '%s' "$root/e2e/oidc/host_app.py" | sed 's/[][\.*^$+?(){}|]/\\&/g')"
  printf '^[^ ]+ %s ' "$escaped"
}

# Succeeds for the compose project of the probe stack (stack.py) and for a suite
# project (suite.py: d2-suite- and eight lowercase hex digits), by whole-string match.
is_probe_project() {
  [[ "$2" == "$1" || "$2" =~ ^d2-suite-[0-9a-f]{8}$ ]]
}

# Prints "KIND NAME" for each docker object a probe run makes: containers, networks and
# volumes labelled with a probe project, and the relay containers (shim.py) by name prefix.
probe_objects() {
  local probe_project relay_prefix listing kind id project name
  probe_project="$(harness_constant stack PROBE_PROJECT)"
  relay_prefix="$(harness_constant shim RELAY_NAME_PREFIX)"
  listing="$(docker ps -a --format '{{.ID}}|{{.Label "'"$compose_project_label"'"}}|{{.Names}}')"
  while IFS='|' read -r id project name; do
    [[ -n "$id" ]] || continue
    if is_probe_project "$probe_project" "$project" || [[ "$name" == "$relay_prefix"* ]]; then
      echo "container $id"
    fi
  done <<<"$listing"
  for kind in network volume; do
    listing="$(docker "$kind" ls --format '{{.Name}}|{{.Label "'"$compose_project_label"'"}}')"
    while IFS='|' read -r name project; do
      [[ -n "$name" ]] || continue
      if is_probe_project "$probe_project" "$project"; then
        echo "$kind $name"
      fi
    done <<<"$listing"
  done
}

# A directory a run leaves behind holds runtime, evidence and export, and nothing else.
holds_only_run_leftovers() {
  local scratch="$1" entry found=0
  [[ -n "$scratch" && -d "$scratch" ]] || return 1
  for entry in "$scratch"/* "$scratch"/.[!.]* "$scratch"/..?*; do
    [[ -e "$entry" || -L "$entry" ]] || continue
    case "${entry##*/}" in
      runtime | evidence | export) found=1 ;;
      *) return 1 ;;
    esac
  done
  [[ $found -eq 1 ]]
}

# Prints the processes of this checkout's host app; pgrep status 1 means none.
running_host_apps() {
  local status=0
  pgrep -af -- "$(host_app_pattern)" || status=$?
  [[ $status -le 1 ]] || exit "$status"
}

remove_probe_objects() {
  local objects kind name
  objects="$(probe_objects)"
  while read -r kind name; do
    [[ -n "$kind" ]] || continue
    case "$kind" in
      container) docker rm -f -v "$name" >/dev/null ;;
      *) docker "$kind" rm "$name" >/dev/null ;;
    esac
  done <<<"$objects"
}

cleanup_under_lock() {
  local scratch="$1" status=0 leftovers
  pkill -f -- "$(host_app_pattern)" || status=$?
  [[ $status -le 1 ]] || exit "$status"
  remove_probe_objects
  rm -rf -- "$scratch/runtime"
  leftovers="$(
    probe_objects
    running_host_apps
    if [[ -e "$scratch/runtime" ]]; then echo "$scratch/runtime"; fi
  )"
  if [[ -n "$leftovers" ]]; then
    echo "still present after cleanup:" >&2
    echo "$leftovers" >&2
    exit 1
  fi
}

# The scratch directory is checked before the wait, and the work waits for the lock
# so that no proof runs while it acts. The lock descriptor is not passed on.
cleanup() {
  local scratch="$1"
  if ! holds_only_run_leftovers "$scratch"; then
    echo "refusing: '$scratch' is not a directory holding only runtime, evidence and export" >&2
    exit 2
  fi
  (
    flock 9
    cleanup_under_lock "$scratch" 9>&-
  ) 9>"$probe_lock"
}

verb="${1:-}"
[[ -n "$verb" ]] || usage
shift
case "$verb" in
  prepare)
    [[ $# -eq 0 ]] || usage
    prepare
    ;;
  prove) run_under_lock prove.py "$@" ;;
  conformance) run_under_lock conformance.py "$@" ;;
  cleanup)
    [[ $# -eq 1 ]] || usage
    cleanup "$1"
    ;;
  *) usage ;;
esac
