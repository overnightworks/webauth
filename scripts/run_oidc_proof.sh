#!/usr/bin/env bash
# The terminal steps of the real-browser proofs in tests/e2e/oidc/ (see its README).
set -euo pipefail
shopt -s inherit_errexit

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
probe_lock=/tmp/probe-stack.lock
suite_host=conformance.example.test
compose_project_label=com.docker.compose.project
state_root="${XDG_STATE_HOME:-$HOME/.local/state}/webauth-e2e-oidc"

# The cap is a whole-run limit. --kill-after must exceed the worst case of a
# run's cleanup: timeout exits at cap plus kill-after and flock frees the lock
# then, so a shorter kill-after would free it while the stack is still being
# torn down. (This host's uutils timeout sends its KILL only to its direct
# child, uv, so the KILL does not cut the driver's cleanup short.) prove.py:
# browser worker 15 s, host SIGTERM 15 s, host SIGKILL 15 s, stack 180 s,
# together 225 s. conformance.py: worker join 15 s, host stop 30 s, first
# teardown 90 s, backstop teardown 90 s, together 225 s. A full prove run
# measured 134 s, so 900 s leaves a factor of about 6. CAP + K <= 1830 is the
# fleet's bound for a lock holder (marketplace#291).
run_cap_seconds=900
kill_after_seconds=240
# cleanup has no teardown on SIGTERM (bash -c and the docker CLI die, the daemon
# finishes a started rm); K is a margin. CAP: about 30 docker calls (list, inspect,
# one rm per object of a probe stack and a suite stack) and seven `uv run` calls
# (checkout_interpreter, plus harness_constant three times in each of the two
# probe_objects passes) at a generous 10 s each.
cleanup_cap_seconds=300
cleanup_kill_after_seconds=30
lock_wait_seconds=1200
lock_wait_timeout_status=75
setpriv_unavailable_status=69

usage() {
  cat >&2 <<'USAGE'
usage: scripts/run_oidc_proof.sh VERB [ARGS]

  prepare            install Chromium, Firefox and WebKit and pull the relay and suite images
  prove --hal DIR    run tests/e2e/oidc/prove.py against the hal checkout DIR
  conformance        run tests/e2e/oidc/conformance.py
  cleanup            remove what a killed run left behind

A run's directory is made under the state root and printed when the run starts.
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

# Every run directory lives below the state root, which cleanup trusts only as a real directory.
refuse_unsafe_state_root() {
  if [[ -L "$state_root" || ( -e "$state_root" && ! -d "$state_root" ) ]]; then
    echo "refusing: '$state_root' is not a real directory" >&2
    exit 1
  fi
}

# Takes the probe lock for at most lock_wait_seconds, then runs "$@" (an executable, because
# timeout cannot run a shell function) under timeout with the given kill-after and cap.
# The lock is not passed on: flock -o closes it for the command. setpriv makes timeout
# receive SIGTERM when flock dies. The lock is free from that moment, so while the driver's
# SIGTERM teardown runs a new proof can take it; that window is bounded by the driver's own
# teardown budget (225 s, under kill-after 240 s for a run; cleanup has 30 s).
# flock exits with the status 69 when setpriv cannot run; it is never left out.
run_locked() {
  local kill_after="$1" cap="$2" status=0
  shift 2
  flock -o -w "$lock_wait_seconds" -E "$lock_wait_timeout_status" "$probe_lock" \
    setpriv --pdeathsig TERM timeout --kill-after="$kill_after" "$cap" "$@" || status=$?
  if [[ "$status" -eq "$lock_wait_timeout_status" ]]; then
    echo "gave up waiting for $probe_lock after $lock_wait_seconds s" >&2
  elif [[ "$status" -eq "$setpriv_unavailable_status" ]]; then
    echo "setpriv could not run; the lock would not outlive the command, so nothing ran" >&2
  fi
  return "$status"
}

# Ctrl-C reaches flock, which holds the lock for the run: setpriv then sends timeout
# SIGTERM, timeout passes it to the driver, and the run ends through its own cleanup.
# timeout's KILL reaches only its direct child, uv, not the driver (see the README's "Stop a
# run"). Stop a run with SIGTERM to timeout or the python process.
# The load is read again once the lock is held, because the wait for it can be long.
# The run directory is made under the lock and handed to the driver as --scratch.
run_under_lock() {
  local driver="$1"
  shift
  refuse_while_loaded
  mkdir -p -- "$state_root"
  refuse_unsafe_state_root
  run_locked "$kill_after_seconds" "$run_cap_seconds" bash -c "$(declare -f refuse_while_loaded)"'
refuse_while_loaded
run_directory="$(mktemp -d "$1/$2-XXXXXX")" || exit
echo "run directory: $run_directory"
shift 2
exec "$@" --scratch "$run_directory"' _ "$state_root" "${driver%.py}" \
    uv run --locked --project "$root" --group dev --group e2e python "$root/tests/e2e/oidc/$driver" "$@"
}

# A constant the harness defines, read from its module so no copy can drift.
harness_constant() {
  uv run --locked --project "$root" --group e2e python -I -c \
    'import importlib, sys; sys.path.insert(0, sys.argv[1]); print(getattr(importlib.import_module(sys.argv[2]), sys.argv[3]))' \
    "$root/tests/e2e/oidc" "$1" "$2"
}

prepare() {
  uv run --locked --project "$root" --group e2e playwright install chromium firefox webkit
  docker pull "$(harness_constant shim RELAY_IMAGE)"
  SUITE_HOST="$suite_host" docker compose -f "$root/tests/e2e/oidc/suite-compose.yaml" pull
}

# The compose project names are reserved for the probe: the harness's own teardown
# removes them (stack.py PROBE_PROJECT, suite.py d2-suite- and eight lowercase hex
# digits) and cleanup replays that teardown. The live hal stack's project is `edge`.
is_probe_project() {
  [[ "$2" == "$1" || "$2" =~ ^d2-suite-[0-9a-f]{8}$ ]]
}

# A relay container (shim.py: docker run --rm) has the relay name prefix and image
# and no compose project label.
is_relay_container() {
  local relay_prefix="$1" relay_image="$2" project="$3" name="$4" image="$5"
  [[ -z "$project" && "$name" == "$relay_prefix"* && "$image" == "$relay_image" ]]
}

# Runs a listing command and prints its output. A command that fails ends cleanup with the
# command named, so a failed listing is never read as an empty one.
listing_of() {
  local output
  output="$("$@")" || {
    echo "cleanup failed: '$*' exited $?" >&2
    exit 1
  }
  printf '%s\n' "$output"
}

# Prints "ID|PROJECT|NAME|IMAGE" for every container, the image as it was named when the
# container was created (docker ps drops a digest).
docker_container_identities() {
  local listing
  local -a ids
  listing="$(listing_of docker ps -a --no-trunc --quiet)"
  mapfile -t ids <<<"$listing"
  [[ -n "${ids[0]}" ]] || return 0
  docker inspect --format '{{.Id}}|{{with index .Config.Labels "'"$compose_project_label"'"}}{{.}}{{end}}|{{.Name}}|{{.Config.Image}}' "${ids[@]}"
}

# Prints "KIND NAME" for each docker object a probe run makes: containers, networks and
# volumes labelled with a probe project, and the relay containers (shim.py).
probe_objects() {
  local probe_project relay_prefix relay_image listing kind id project name image
  probe_project="$(harness_constant stack PROBE_PROJECT)"
  relay_prefix="$(harness_constant shim RELAY_NAME_PREFIX)"
  relay_image="$(harness_constant shim RELAY_IMAGE)"
  listing="$(docker_container_identities)"
  while IFS='|' read -r id project name image; do
    [[ -n "$id" ]] || continue
    name="${name#/}"
    if is_probe_project "$probe_project" "$project" \
      || is_relay_container "$relay_prefix" "$relay_image" "$project" "$name" "$image"; then
      echo "container $id"
    fi
  done <<<"$listing"
  for kind in network volume; do
    listing="$(listing_of docker "$kind" ls --format '{{.Name}}|{{.Label "'"$compose_project_label"'"}}')"
    while IFS='|' read -r name project; do
      [[ -n "$name" ]] || continue
      if is_probe_project "$probe_project" "$project"; then
        echo "$kind $name"
      fi
    done <<<"$listing"
  done
}

# The interpreter of this checkout's environment, as the harness sees it in sys.executable.
checkout_interpreter() {
  local interpreter
  interpreter="$(listing_of uv run --locked --project "$root" --group e2e python -c 'import sys; print(sys.executable)')"
  realpath -m -s -- "$interpreter"
}

# Prints the pid of each host app this checkout's probe starts. Its argv is exactly the six
# fields harness.py:start_host builds: this checkout's interpreter, this checkout's
# host_app.py, --settings, a settings file inside the state root, --parent-pid and a pid.
# /proc/PID/cmdline keeps the arguments apart. host_interpreter is read once per cleanup;
# its symlinks are kept, so another environment sharing a base Python is not taken for this one.
host_app_pids() {
  local host_app state_real cmdline pid
  local -a argv
  host_app="$(realpath -m -- "$root/tests/e2e/oidc/host_app.py")"
  state_real="$(realpath -m -- "$state_root")"
  for cmdline in /proc/[0-9]*/cmdline; do
    pid="${cmdline#/proc/}"
    pid="${pid%/cmdline}"
    mapfile -d "" argv 2>/dev/null <"$cmdline" || continue
    [[ ${#argv[@]} -eq 6 && "${argv[2]}" == --settings && "${argv[4]}" == --parent-pid ]] || continue
    [[ "${argv[5]}" =~ ^[0-9]+$ ]] || continue
    [[ "$(realpath -m -s -- "${argv[0]}")" == "$host_interpreter" ]] || continue
    [[ "$(realpath -m -- "${argv[1]}")" == "$host_app" ]] || continue
    [[ "$(realpath -m -- "${argv[3]}")" == "$state_real"/* ]] || continue
    echo "$pid"
  done
}

# The runtime directories exactly one level below the run directories of the state root,
# found without following a symlink, each followed by a NUL so no path name can split.
run_runtime_directories() {
  [[ -d "$state_root" ]] || return 0
  find -P "$state_root" -mindepth 2 -maxdepth 2 -type d -name runtime -print0
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
  local pids pid directory leftovers
  host_interpreter="$(checkout_interpreter)"
  pids="$(host_app_pids)"
  for pid in $pids; do
    kill -KILL "$pid" 2>/dev/null || true
  done
  sleep 1
  remove_probe_objects
  # A process that can swap a directory under the state root runs as this user and already
  # holds every right this removal has, so the path is not re-checked between find and rm.
  while IFS= read -r -d '' directory; do
    rm -rf -- "$directory"
  done < <(run_runtime_directories)
  leftovers="$(
    probe_objects
    host_app_pids
    run_runtime_directories | tr '\0' '\n'
  )"
  if [[ -n "$leftovers" ]]; then
    echo "still present after cleanup:" >&2
    echo "$leftovers" >&2
    exit 1
  fi
}

# The work waits for the lock so that no proof runs while it acts, and is capped like a run.
cleanup() {
  refuse_unsafe_state_root
  run_locked "$cleanup_kill_after_seconds" "$cleanup_cap_seconds" bash -c "$(declare -p root state_root compose_project_label)
$(declare -f cleanup_under_lock checkout_interpreter listing_of harness_constant host_app_pids \
    run_runtime_directories remove_probe_objects probe_objects docker_container_identities \
    is_probe_project is_relay_container)"'
set -euo pipefail
shopt -s inherit_errexit
cleanup_under_lock'
}

verb="${1:-}"
[[ -n "$verb" ]] || usage
shift
case "$verb" in
  prepare)
    [[ $# -eq 0 ]] || usage
    prepare
    ;;
  prove)
    [[ $# -eq 2 && "$1" == --hal && -d "$2" ]] || usage
    run_under_lock prove.py "$@"
    ;;
  conformance)
    [[ $# -eq 0 ]] || usage
    run_under_lock conformance.py
    ;;
  cleanup)
    [[ $# -eq 0 ]] || usage
    cleanup
    ;;
  *) usage ;;
esac
