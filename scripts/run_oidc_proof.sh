#!/usr/bin/env bash
# The terminal steps of the real-browser proofs in tests/e2e/oidc/ (see docs/runbooks/).
set -euo pipefail
shopt -s inherit_errexit

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
suite_host=conformance.example.test
compose_project_label=com.docker.compose.project
state_root="${XDG_STATE_HOME:-$HOME/.local/state}/webauth-e2e-oidc"
driver_record_suffix=.driver

# probe-run waits for room on the machine, then runs the command under timeout with this
# kill-after and cap. The cap is a whole-run limit. --kill-after must exceed the worst case
# of a run's cleanup: timeout sends KILL at cap plus kill-after. (This host's uutils timeout
# sends its KILL only to its direct child, uv, so the KILL does not cut the driver's cleanup
# short.) prove.py: browser worker 15 s, host SIGTERM 15 s, host SIGKILL 15 s, stack 180 s,
# together 225 s. conformance.py: worker join 15 s, host stop 30 s, first teardown 90 s,
# backstop teardown 90 s, together 225 s. A full prove run measured 134 s, so 900 s leaves a
# factor of about 6. CAP + K <= 1830 is the fleet's bound for a probe stack.
run_cap_seconds=900
kill_after_seconds=240
# cleanup has no teardown on SIGTERM (bash -c and the docker CLI die, the daemon
# finishes a started rm); K is a margin. CAP: about 30 docker calls (listings and one rm
# per object of the dead runs' hold and suite stacks) and one `uv run` (checkout_interpreter)
# at a generous 10 s each.
cleanup_cap_seconds=300
cleanup_kill_after_seconds=30

usage() {
  cat >&2 <<'USAGE'
usage: scripts/run_oidc_proof.sh VERB [ARGS]

  prepare            install Chromium, Firefox and WebKit and pull the relay and suite images
  prove --platform DIR
                     run tests/e2e/oidc/prove.py against the platform checkout DIR
  conformance        run tests/e2e/oidc/conformance.py
  cleanup            remove what runs that no longer live left behind

A run's directory is made under the state root and printed when the run starts.
USAGE
  exit 2
}

# Every run directory lives below the state root, which cleanup trusts only as a real directory.
refuse_unsafe_state_root() {
  if [[ -L "$state_root" || ( -e "$state_root" && ! -d "$state_root" ) ]]; then
    echo "refusing: '$state_root' is not a real directory" >&2
    exit 1
  fi
}

# The process that makes a run's directory records its pid and start time in a file beside it,
# because the directory must stay empty for the driver. The pid alone could be reused by another
# process after the run died. Start time is field 22 of
# /proc/PID/stat, the 20th after the command name, which may hold spaces but ends at the
# last ") ".
process_start_time() {
  local stat
  { read -r stat <"/proc/$1/stat"; } 2>/dev/null || return 1
  cut -d' ' -f20 <<<"${stat##*) }"
}

record_driver() {
  echo "$$ $(process_start_time "$$")" >"$1$driver_record_suffix"
}

# A run lives while the process recorded beside its directory (the directory itself stays
# empty for the driver) is the one that started then. The directory exists a moment before the
# record; a cleanup in that moment finds nothing of the run to remove.
run_is_live() {
  local pid start
  [[ -f "$1$driver_record_suffix" ]] || return 1
  read -r pid start <"$1$driver_record_suffix" || return 1
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [[ "$(process_start_time "$pid")" == "$start" ]]
}

# Ctrl-C reaches every process of the foreground group; timeout passes it on to the driver,
# whose first SIGTERM or SIGINT ends the run through an uninterruptible cleanup (further
# signals are ignored). SIGTERM sent to timeout or to the python process ends the run the
# same way.
# timeout's KILL reaches only its direct child, uv: bash -c execs uv run, which starts
# python as its own child (measured on uutils coreutils 0.10.0: a child that ignores TERM
# is killed, its grandchild survives). So an overrunning teardown is not cut short and
# the driver then runs on, while its record already names a process that is gone.
# The processes that can outlive a run are listed in docs/runbooks/stop-a-run.md.
# The run directory is made inside the capped command and handed to the driver as --scratch.
run_driver() {
  local driver="$1"
  shift
  mkdir -p -- "$state_root"
  refuse_unsafe_state_root
  probe-run -k "$kill_after_seconds" "$run_cap_seconds" bash -c "$(declare -p driver_record_suffix)
$(declare -f process_start_time record_driver)"'
set -euo pipefail
shopt -s inherit_errexit
run_directory="$(mktemp -d "$1/$2-XXXXXX")" || exit
echo "run directory: $run_directory"
record_driver "$run_directory"
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

# Prints "KIND NAME" for each line of a listing.
print_objects() {
  local kind="$1" name
  while read -r name; do
    [[ -z "$name" ]] || echo "$kind $name"
  done <<<"$2"
}

# Prints "KIND NAME" for each docker object of the projects given one per line: containers,
# networks and volumes labelled with the project, and the containers on its networks, which
# are the relay containers (shim.py: docker run --rm), whose name the project prefixes but
# which carry no project label.
project_objects() {
  local project networks network
  while read -r project; do
    [[ -n "$project" ]] || continue
    networks="$(listing_of docker network ls --filter "label=$compose_project_label=$project" --format '{{.Name}}')"
    print_objects container "$(listing_of docker ps -a --no-trunc --quiet --filter "label=$compose_project_label=$project")"
    while read -r network; do
      [[ -z "$network" ]] || print_objects container "$(listing_of docker ps -a --no-trunc --quiet --filter "network=$network")"
    done <<<"$networks"
    print_objects network "$networks"
    print_objects volume "$(listing_of docker volume ls --filter "label=$compose_project_label=$project" --format '{{.Name}}')"
  done <<<"$1"
}

# The run directories whose recorded process no longer lives, one per line. A run directory
# is exactly one level below the state root, which is a real directory (refuse_unsafe_state_root).
dead_run_directories() {
  local directory
  [[ -d "$state_root" ]] || return 0
  while IFS= read -r -d '' directory; do
    run_is_live "$directory" || echo "$directory"
  done < <(find -P "$(realpath -m -- "$state_root")" -mindepth 1 -maxdepth 1 -type d -print0)
}

# The compose projects of the dead runs, one per line: the held Keycloak writes its name into
# its scratch directory (stack.py HOLD_SCRATCH_NAME) before it creates anything, and the
# conformance run records the suite's (suite.py PROJECT_RECORD).
dead_run_projects() {
  local directory file project
  while read -r directory; do
    [[ -n "$directory" ]] || continue
    for file in "$directory/runtime/$hold_scratch_name/project" "$directory/$suite_project_record"; do
      [[ -f "$file" && ! -L "$file" ]] || continue
      project=""
      read -r project <"$file" || true
      [[ -n "$project" ]] || continue
      if [[ ! "$project" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
        echo "cleanup failed: '$file' does not hold a compose project name" >&2
        exit 1
      fi
      echo "$project"
    done
  done <<<"$dead_runs"
}

# The interpreter of this checkout's environment, as the harness sees it in sys.executable.
checkout_interpreter() {
  local interpreter
  interpreter="$(listing_of uv run --locked --project "$root" --group e2e python -c 'import sys; print(sys.executable)')"
  realpath -m -s -- "$interpreter"
}

# Prints the pid of each host app a dead run of this checkout started. Its argv is exactly
# the six fields harness.py:start_host builds: this checkout's interpreter, this checkout's
# host_app.py, --settings, a settings file inside a dead run's directory, --parent-pid and a
# pid. /proc/PID/cmdline keeps the arguments apart. host_interpreter is read once per cleanup;
# its symlinks are kept, so another environment sharing a base Python is not taken for this one.
host_app_pids() {
  local host_app state_real cmdline pid settings run
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
    settings="$(realpath -m -- "${argv[3]}")"
    [[ "$settings" == "$state_real"/* ]] || continue
    run="${settings#"$state_real"/}"
    grep -qxF -- "$state_real/${run%%/*}" <<<"$dead_runs" || continue
    echo "$pid"
  done
}

# The runtime directories of the dead runs, found without following a symlink, each
# followed by a NUL so no path name can split.
run_runtime_directories() {
  local directory
  while read -r directory; do
    [[ -z "$directory" ]] || find -P "$directory" -mindepth 1 -maxdepth 1 -type d -name runtime -print0
  done <<<"$dead_runs"
}

# A removal that fails is not fatal: the held Keycloak removes its own project when its driver
# is gone, so an object may vanish between the listing and the removal, and the check after
# the removal reports what truly remains.
remove_project_objects() {
  local kind name
  while read -r kind name; do
    [[ -n "$kind" ]] || continue
    case "$kind" in
      container) docker rm -f -v "$name" >/dev/null || true ;;
      *) docker "$kind" rm "$name" >/dev/null || true ;;
    esac
  done <<<"$1"
}

# Removes what the runs that no longer live left behind and leaves a live run untouched:
# dead_runs, the host_interpreter and the projects below only ever name a dead run's objects.
cleanup_dead_runs() {
  local projects pids pid directory leftovers
  host_interpreter="$(checkout_interpreter)"
  dead_runs="$(dead_run_directories)"
  projects="$(dead_run_projects)"
  pids="$(host_app_pids)"
  for pid in $pids; do
    kill -KILL "$pid" 2>/dev/null || true
  done
  sleep 1
  remove_project_objects "$(project_objects "$projects" | sort -u)"
  # A process that can swap a directory under the state root runs as this user and already
  # holds every right this removal has, so the path is not re-checked between find and rm.
  while IFS= read -r -d '' directory; do
    rm -rf -- "$directory"
  done < <(run_runtime_directories)
  leftovers="$(
    project_objects "$projects"
    host_app_pids
    run_runtime_directories | tr '\0' '\n'
  )"
  if [[ -n "$leftovers" ]]; then
    echo "still present after cleanup:" >&2
    echo "$leftovers" >&2
    exit 1
  fi
}

# The work is capped like a run and waits for room on the machine like one.
cleanup() {
  local hold_scratch_name suite_project_record
  refuse_unsafe_state_root
  hold_scratch_name="$(harness_constant stack HOLD_SCRATCH_NAME)"
  suite_project_record="$(harness_constant suite PROJECT_RECORD)"
  probe-run -k "$cleanup_kill_after_seconds" "$cleanup_cap_seconds" bash -c "$(declare -p root state_root compose_project_label driver_record_suffix hold_scratch_name suite_project_record)
$(declare -f cleanup_dead_runs checkout_interpreter listing_of host_app_pids run_runtime_directories \
    remove_project_objects project_objects print_objects dead_run_directories dead_run_projects \
    run_is_live process_start_time)"'
set -euo pipefail
shopt -s inherit_errexit
cleanup_dead_runs'
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
    [[ $# -eq 2 && "$1" == --platform && -d "$2" ]] || usage
    run_driver prove.py "$@"
    ;;
  conformance)
    [[ $# -eq 0 ]] || usage
    run_driver conformance.py
    ;;
  cleanup)
    [[ $# -eq 0 ]] || usage
    cleanup
    ;;
  *) usage ;;
esac
