#!/usr/bin/env bash
# The terminal steps of the real-browser proofs in e2e/oidc/ (see its README).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_lock=/tmp/probe-stack.lock
suite_host=conformance.example.test

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
  cleanup SCRATCH    remove what a SIGKILLed run left behind
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
run_under_lock() {
    local driver="$1"
    shift
    refuse_while_loaded
    flock -o "$probe_lock" \
        timeout --kill-after="$kill_after_seconds" "$run_cap_seconds" \
        uv run --project "$root" --group dev --group e2e python "$root/e2e/oidc/$driver" "$@"
}

relay_image() {
    uv run --project "$root" --group e2e python -I -c \
        'import sys; sys.path.insert(0, sys.argv[1]); import shim; print(shim.RELAY_IMAGE)' \
        "$root/e2e/oidc"
}

prepare() {
    uv run --project "$root" --group e2e playwright install chromium
    docker pull "$(relay_image)"
    SUITE_HOST="$suite_host" docker compose -f "$root/e2e/oidc/suite-compose.yaml" pull
}

remove_compose_projects_named() {
    local name_filter="$1" project
    docker ps -a --filter "name=$name_filter" \
        --format '{{.Label "com.docker.compose.project"}}' | sort -u | while read -r project; do
        [[ -n "$project" ]] || continue
        SUITE_HOST="$suite_host" docker compose -p "$project" down -v --remove-orphans
    done
}

cleanup() {
    local scratch="$1"
    rm -rf -- "$scratch/runtime"
    remove_compose_projects_named edge-kc-probe
    remove_compose_projects_named d2-suite
    # The host app dies with its parent, so this rarely finds anything.
    pkill -f e2e/oidc/host_app.py || true
    docker ps -a --filter name=edge-kc-probe --filter name=d2-suite
}

verb="${1:-}"
[[ -n "$verb" ]] || usage
shift
case "$verb" in
    prepare) prepare ;;
    prove) run_under_lock prove.py "$@" ;;
    conformance) run_under_lock conformance.py "$@" ;;
    cleanup)
        [[ $# -eq 1 ]] || usage
        cleanup "$1"
        ;;
    *) usage ;;
esac
